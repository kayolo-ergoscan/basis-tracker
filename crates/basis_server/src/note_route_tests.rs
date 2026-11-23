//! `POST /notes` with a real tracker state: the reserve requirement and the note caps
//! (round 4, C3), and the C10 fixes of the read routes that sit on the same state.

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use basis_store::{DenomKey, IouNote, PubKey, TrackerStateManager};

use crate::api::create_note;
use crate::models::CreateNoteRequest;
use crate::{AppState, TrackerCommand};

pub(crate) const TRACKER_NFT: [u8; 32] = [0x5a; 32];
const OTHER_NFT: [u8; 32] = [0x5b; 32];

static STORAGE_INIT_LOCK: Mutex<()> = Mutex::new(());

/// The caps of a test state.
#[derive(Clone, Copy)]
pub(crate) struct Caps {
    require_reserve: bool,
    recipients: u32,
    updates: u32,
    new_edges: u32,
    new_edges_per_issuer: u32,
}

pub(crate) const DEFAULT_CAPS: Caps = Caps {
    require_reserve: true,
    recipients: 50,
    updates: 120,
    new_edges: 1000,
    new_edges_per_issuer: 10,
};

/// A tracker thread holding a real `TrackerStateManager`, answering what `POST /notes` sends.
fn spawn_tracker_thread() -> tokio::sync::mpsc::Sender<TrackerCommand> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TrackerCommand>(100);
    std::thread::spawn(move || {
        let mut tracker = TrackerStateManager::new_with_temp_storage();
        while let Some(cmd) = rx.blocking_recv() {
            match cmd {
                TrackerCommand::AddNote {
                    issuer_pubkey,
                    note,
                    response_tx,
                } => {
                    let _ = response_tx.send(tracker.add_note(&issuer_pubkey, &note));
                }
                TrackerCommand::GetNotesByIssuer {
                    issuer_pubkey,
                    response_tx,
                } => {
                    let _ = response_tx.send(tracker.get_issuer_notes(&issuer_pubkey));
                }
                TrackerCommand::GetNotes { response_tx } => {
                    let _ = response_tx.send(tracker.get_all_notes_with_issuer());
                }
                TrackerCommand::Shutdown => break,
                _ => {}
            }
        }
    });
    tx
}

pub(crate) fn state(caps: Caps) -> AppState {
    let data_dir = tempfile::tempdir().unwrap().keep();
    let (scanner, tracker_storage, policy_storage) = {
        let _guard = STORAGE_INIT_LOCK.lock().unwrap();
        std::fs::create_dir_all(data_dir.join("tracker_storage")).unwrap();
        std::fs::create_dir_all(data_dir.join("policies")).unwrap();
        (
            basis_store::ergo_scanner::ServerState::new(
                basis_store::ergo_scanner::NodeConfig {
                    node_url: "http://127.0.0.1:1".to_string(),
                    ..Default::default()
                },
                &data_dir,
            )
            .unwrap(),
            basis_store::persistence::TrackerStorage::open(data_dir.join("tracker_storage"))
                .unwrap(),
            basis_store::persistence::AcceptancePolicyStorage::open(data_dir.join("policies"))
                .unwrap(),
        )
    };
    let config = crate::config::AppConfig {
        server: crate::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3048,
            data_dir: Some(data_dir.to_string_lossy().to_string()),
            database_url: None,
            tls_cert_path: None,
            tls_key_path: None,
            auth: crate::config::AuthConfig::default(),
            reserve_creation_max_erg_nano: 10_000_000_000,
            reserve_creation_max_token_amount: 1_000_000_000,
            redemption_build_max_per_pair_per_hour: 12,
            redemption_build_max_per_recipient_per_hour: 30,
            redemption_build_max_per_issuer_per_hour: 6,
            redemption_build_max_per_hour: 30,
            notes_require_reserve: caps.require_reserve,
            notes_max_recipients_per_issuer: caps.recipients,
            notes_max_updates_per_issuer_per_hour: caps.updates,
            notes_max_new_edges_per_hour: caps.new_edges,
            notes_max_new_edges_per_issuer_per_hour: caps.new_edges_per_issuer,
        },
        ergo: crate::config::ErgoConfig {
            scanner: basis_store::ergo_scanner::NodeConfig::default(),
            wallet: Default::default(),
            basis_reserve_contract_p2s: "test".to_string(),
            basis_token_reserve_contract_p2s: "test_token".to_string(),
            tracker_nft_id: Some(hex::encode(TRACKER_NFT)),
            reserve_tokens: [(
                hex::encode([0x7c; 32]),
                crate::config::ReserveTokenConfig {
                    symbol: "TKN".to_string(),
                    decimals: 0,
                    min_collateralization_ratio: None,
                },
            )]
            .into_iter()
            .collect(),
            tracker_public_key: None,
            tracker_secret_key: None,
        },
        transaction: crate::config::TransactionConfig {
            fee: 1_000_000,
            change_address: None,
            heartbeat_blocks: 720,
            commit_reserve_nano: 100_000_000,
        },
        acceptance: crate::acceptance::config::AcceptanceConfig::empty(),
        redemption: crate::config::RedemptionConfig::default(),
        confirmation: crate::config::ConfirmationConfig::default(),
    };
    AppState {
        tx: spawn_tracker_thread(),
        event_store: Arc::new(crate::store::EventStore::new_in_memory()),
        ergo_scanner: Arc::new(tokio::sync::Mutex::new(scanner)),
        reserve_tracker: Arc::new(tokio::sync::Mutex::new(basis_store::ReserveTracker::new())),
        config: Arc::new(config),
        shared_tracker_state: Arc::new(tokio::sync::Mutex::new(
            crate::tracker_box_updater::SharedTrackerState::new(),
        )),
        tracker_storage,
        acceptance_predicate: None,
        policy_storage,
        pending_redemptions: Arc::new(crate::redemption_build::PendingRedemptionRegistry::new()),
        redemption_build_rate: Arc::new(crate::redemption_build::BuildRateLimiter::new()),
        note_limits: Arc::new(crate::note_limits::NoteLimiter::new()),
    }
}

/// A reserve of `owner` (ERG, or the token `token`), bound to `nft`, in refund since
/// `refund_height` (0: none).
pub(crate) fn reserve_info(
    owner: &PubKey,
    box_id: &str,
    token: Option<[u8; 32]>,
    nft: [u8; 32],
    refund_height: u64,
) -> basis_store::reserve_tracker::ExtendedReserveInfo {
    basis_store::reserve_tracker::ExtendedReserveInfo {
        base_info: basis_store::ReserveInfo {
            collateral_amount: 1_000_000_000,
            last_updated_height: 1,
            contract_address: String::new(),
            tracker_nft_id: hex::encode(nft),
            refund_initiation_height: refund_height,
            reserve_token_id: token.map(hex::encode).unwrap_or_default(),
        },
        total_debt: 0,
        box_id: box_id.to_string(),
        owner_pubkey: hex::encode(owner),
        last_updated_timestamp: 0,
    }
}

/// Track a reserve (see [`reserve_info`]).
pub(crate) async fn add_reserve(
    state: &AppState,
    owner: &PubKey,
    box_id: &str,
    token: Option<[u8; 32]>,
    nft: [u8; 32],
    refund_height: u64,
) {
    state
        .reserve_tracker
        .lock()
        .await
        .update_reserve(reserve_info(owner, box_id, token, nft, refund_height))
        .unwrap();
}

struct Issuer {
    secret: [u8; 32],
    key: PubKey,
}

fn issuer() -> Issuer {
    let (secret, key) = basis_store::schnorr::generate_keypair();
    Issuer { secret, key }
}

fn recipient() -> PubKey {
    basis_store::schnorr::generate_keypair().1
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// A note of `issuer` to `to` for a cumulative `amount`, signed at `timestamp`.
fn note_request(
    issuer: &Issuer,
    to: &PubKey,
    amount: u64,
    timestamp: u64,
    denomination: DenomKey,
) -> CreateNoteRequest {
    let note = IouNote::create_and_sign(
        *to,
        amount,
        timestamp,
        &issuer.secret,
        &TRACKER_NFT,
        denomination,
    )
    .unwrap();
    CreateNoteRequest {
        recipient_pubkey: hex::encode(to),
        amount,
        timestamp,
        signature: hex::encode(note.signature),
        issuer_pubkey: hex::encode(issuer.key),
        tracker_nft_id: hex::encode(TRACKER_NFT),
        denomination: denomination.denomination_id(),
    }
}

async fn post(state: &AppState, request: CreateNoteRequest) -> (StatusCode, String) {
    let (status, body) =
        create_note(axum::extract::State(state.clone()), axum::Json(request)).await;
    (status, body.0.error.unwrap_or_default())
}

async fn stored_notes(state: &AppState, issuer: &Issuer) -> usize {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .tx
        .send(TrackerCommand::GetNotesByIssuer {
            issuer_pubkey: issuer.key,
            response_tx: tx,
        })
        .await
        .unwrap();
    rx.await.unwrap().unwrap().len()
}

/// A note is accepted only when its issuer has an active reserve under this tracker in the
/// note's denomination; nothing is stored otherwise.
#[tokio::test]
async fn a_note_needs_the_issuers_active_reserve_here() {
    let state = state(DEFAULT_CAPS);
    let ts = now_ms() - 10_000;
    let to = recipient();

    // No reserve at all.
    let a = issuer();
    let (status, error) = post(&state, note_request(&a, &to, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert!(error.contains("no reserve under this tracker"), "{error}");
    assert_eq!(stored_notes(&state, &a).await, 0);

    // With one: accepted.
    add_reserve(&state, &a.key, "box-a", None, TRACKER_NFT, 0).await;
    let (status, error) = post(&state, note_request(&a, &to, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CREATED, "{error}");
    assert_eq!(stored_notes(&state, &a).await, 1);

    // An ERG reserve does not back a token note.
    let token = DenomKey::Token([0x7c; 32]);
    let (status, error) = post(&state, note_request(&a, &to, 5, ts + 1, token)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert!(error.contains("token:"), "{error}");

    // In refund.
    let b = issuer();
    add_reserve(&state, &b.key, "box-b", None, TRACKER_NFT, 1_234).await;
    let (status, error) = post(&state, note_request(&b, &to, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert!(error.contains("in refund (since height 1234)"), "{error}");

    // Two reserves in the denomination: the note would redeem against each.
    let c = issuer();
    add_reserve(&state, &c.key, "box-c1", None, TRACKER_NFT, 0).await;
    add_reserve(&state, &c.key, "box-c2", None, TRACKER_NFT, 0).await;
    let (status, error) = post(&state, note_request(&c, &to, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert!(error.contains("2 tracked reserves"), "{error}");

    // Bound to another tracker (the scanner does not track such reserves; checked anyway).
    let d = issuer();
    add_reserve(&state, &d.key, "box-d", None, OTHER_NFT, 0).await;
    let (status, error) = post(&state, note_request(&d, &to, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert!(error.contains("not this tracker's"), "{error}");

    for issuer in [&b, &c, &d] {
        assert_eq!(stored_notes(&state, issuer).await, 0);
    }
}

/// `notes_require_reserve = false` accepts credit without a reserve.
#[tokio::test]
async fn credit_without_a_reserve_can_be_allowed() {
    let state = state(Caps {
        require_reserve: false,
        ..DEFAULT_CAPS
    });
    let a = issuer();
    let (status, error) = post(
        &state,
        note_request(&a, &recipient(), 1_000, now_ms() - 10_000, DenomKey::Erg),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{error}");
}

/// Distinct recipients per issuer are capped (429); notes to existing recipients still pass.
#[tokio::test]
async fn recipients_per_issuer_are_capped() {
    let state = state(Caps {
        recipients: 2,
        ..DEFAULT_CAPS
    });
    let a = issuer();
    add_reserve(&state, &a.key, "box-a", None, TRACKER_NFT, 0).await;
    let ts = now_ms() - 10_000;
    let (r1, r2, r3) = (recipient(), recipient(), recipient());
    for to in [&r1, &r2] {
        let (status, error) = post(&state, note_request(&a, to, 1_000, ts, DenomKey::Erg)).await;
        assert_eq!(status, StatusCode::CREATED, "{error}");
    }
    let (status, error) = post(&state, note_request(&a, &r3, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{error}");
    assert!(error.contains("notes_max_recipients_per_issuer"), "{error}");
    // Raising an existing recipient's debt is fine.
    let (status, error) = post(&state, note_request(&a, &r1, 2_000, ts + 1, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CREATED, "{error}");
    assert_eq!(stored_notes(&state, &a).await, 2);
}

/// Accepted notes per issuer and hour are capped (429); a note the tracker refuses does not
/// count.
#[tokio::test]
async fn notes_per_issuer_and_hour_are_capped_and_refusals_do_not_count() {
    let state = state(Caps {
        updates: 2,
        ..DEFAULT_CAPS
    });
    let a = issuer();
    add_reserve(&state, &a.key, "box-a", None, TRACKER_NFT, 0).await;
    let ts = now_ms() - 10_000;
    let to = recipient();

    // A note with a bad signature: refused by the tracker, gives its slot back.
    let mut forged = note_request(&a, &to, 1_000, ts, DenomKey::Erg);
    forged.amount = 999;
    let (status, error) = post(&state, forged).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");

    for (amount, t) in [(1_000, ts), (2_000, ts + 1)] {
        let (status, error) = post(&state, note_request(&a, &to, amount, t, DenomKey::Erg)).await;
        assert_eq!(status, StatusCode::CREATED, "{error}");
    }
    let (status, error) = post(&state, note_request(&a, &to, 3_000, ts + 2, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{error}");
    assert!(error.contains("notes_max_updates_per_issuer_per_hour"), "{error}");
}

/// New edges per hour, all issuers together, are capped (429); raising an edge is not new.
#[tokio::test]
async fn new_edges_per_hour_are_capped_for_all_issuers() {
    let state = state(Caps {
        new_edges: 2,
        ..DEFAULT_CAPS
    });
    let (a, b) = (issuer(), issuer());
    add_reserve(&state, &a.key, "box-a", None, TRACKER_NFT, 0).await;
    add_reserve(&state, &b.key, "box-b", None, TRACKER_NFT, 0).await;
    let ts = now_ms() - 10_000;
    let (r1, r2) = (recipient(), recipient());

    let (status, error) = post(&state, note_request(&a, &r1, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CREATED, "{error}");
    let (status, error) = post(&state, note_request(&b, &r1, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CREATED, "{error}");
    let (status, error) = post(&state, note_request(&a, &r2, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{error}");
    assert!(error.contains("notes_max_new_edges_per_hour"), "{error}");
    let (status, error) = post(&state, note_request(&a, &r1, 2_000, ts + 1, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CREATED, "{error}");
}

/// Round 5, item 6: new edges of one issuer per hour are capped (429) below the total, so one
/// issuer cannot use up the total; other issuers and raised edges are not affected.
#[tokio::test]
async fn new_edges_per_issuer_and_hour_are_capped() {
    let state = state(Caps {
        new_edges_per_issuer: 2,
        ..DEFAULT_CAPS
    });
    let (a, b) = (issuer(), issuer());
    add_reserve(&state, &a.key, "box-a", None, TRACKER_NFT, 0).await;
    add_reserve(&state, &b.key, "box-b", None, TRACKER_NFT, 0).await;
    let ts = now_ms() - 10_000;
    let (r1, r2, r3) = (recipient(), recipient(), recipient());

    for to in [&r1, &r2] {
        let (status, error) = post(&state, note_request(&a, to, 1_000, ts, DenomKey::Erg)).await;
        assert_eq!(status, StatusCode::CREATED, "{error}");
    }
    let (status, error) = post(&state, note_request(&a, &r3, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{error}");
    assert!(error.contains("notes_max_new_edges_per_issuer_per_hour"), "{error}");
    // Raising an edge of A is not a new edge; B has its own budget.
    let (status, error) = post(&state, note_request(&a, &r1, 2_000, ts + 1, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CREATED, "{error}");
    let (status, error) = post(&state, note_request(&b, &r3, 1_000, ts, DenomKey::Erg)).await;
    assert_eq!(status, StatusCode::CREATED, "{error}");
    assert_eq!(stored_notes(&state, &a).await, 2);
}

/// Concurrent notes cannot overshoot a cap: admission is serialized.
#[tokio::test]
async fn concurrent_notes_do_not_overshoot_a_cap() {
    let state = state(Caps {
        recipients: 3,
        ..DEFAULT_CAPS
    });
    let a = Arc::new(issuer());
    add_reserve(&state, &a.key, "box-a", None, TRACKER_NFT, 0).await;
    let ts = now_ms() - 10_000;
    let mut handles = Vec::new();
    for _ in 0..8 {
        let (state, a) = (state.clone(), a.clone());
        handles.push(tokio::spawn(async move {
            post(&state, note_request(&a, &recipient(), 1_000, ts, DenomKey::Erg))
                .await
                .0
        }));
    }
    let mut created = 0;
    for handle in handles {
        if handle.await.unwrap() == StatusCode::CREATED {
            created += 1;
        }
    }
    assert_eq!(created, 3);
    assert_eq!(stored_notes(&state, &a).await, 3);
}

/// Round 4 (C10): the debt sum of `/key-status` is checked. Three notes of 2^63 - 1 (the most a
/// note may carry) pass u64::MAX together: the plain `sum()` panicked (release builds check
/// overflow too, `[profile.release] overflow-checks = true`), so the route never answered for
/// that issuer. Now the total saturates and the ratio reads as undercollateralized.
#[tokio::test]
async fn key_status_saturates_a_debt_sum_past_u64() {
    assert_eq!(crate::api::checked_debt_sum([1, 2, 3]), Some(6));
    assert_eq!(crate::api::checked_debt_sum([u64::MAX, 1]), None);

    let state = state(DEFAULT_CAPS);
    let a = issuer();
    add_reserve(&state, &a.key, "box-a", None, TRACKER_NFT, 0).await;
    let ts = now_ms() - 10_000;
    let max_note = i64::MAX as u64;
    for _ in 0..3 {
        let (status, error) =
            post(&state, note_request(&a, &recipient(), max_note, ts, DenomKey::Erg)).await;
        assert_eq!(status, StatusCode::CREATED, "{error}");
    }

    let (status, body) = crate::api::get_key_status(
        axum::extract::State(state.clone()),
        axum::extract::Path(hex::encode(a.key)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.0.error);
    let data = body.0.data.unwrap();
    assert_eq!(data.note_count, 3);
    let erg = &data.denominations[0];
    assert_eq!(erg.denomination, "erg");
    assert_eq!(erg.total_debt, u64::MAX);
    assert!(erg.collateralization_ratio < 1e-9, "{}", erg.collateralization_ratio);
}

/// Round 4 (C10): `/reserves/issuer/{pubkey}` compares normalized keys, so an upper-case or
/// 07-prefixed key finds the issuer's reserves.
#[tokio::test]
async fn reserves_by_issuer_matches_normalized_keys() {
    let state = state(DEFAULT_CAPS);
    let owner = issuer().key;
    state
        .ergo_scanner
        .lock()
        .await
        .reserve_storage()
        .store_reserve(&reserve_info(&owner, "box-n", None, TRACKER_NFT, 0))
        .unwrap();

    let lower = hex::encode(owner);
    for path in [
        lower.clone(),
        lower.to_ascii_uppercase(),
        format!("07{lower}"),
    ] {
        let (status, body) = crate::reserve_api::get_reserves_by_issuer(
            axum::extract::State(state.clone()),
            axum::extract::Path(path.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}");
        let reserves = body.0.data.unwrap();
        assert_eq!(reserves.len(), 1, "{path}");
        assert_eq!(reserves[0].box_id, "box-n");
    }
}

/// Round 5, item 5: `/reserves`, `/reserves/issuer/{pubkey}` and `/reserves/{box_id}` report
/// each reserve's outstanding debt from the notes this tracker holds, in the reserve's
/// denomination, and the ratio collateral / debt, `null` when nothing is owed. Round 5b (F11):
/// `/reserves` reads the notes of the reserves' owners through the issuer index, never every
/// note (no `GetNotes`, no notes of an issuer without a reserve).
#[tokio::test]
async fn reserves_report_the_notes_outstanding_debt_and_ratio() {
    let mut state = state(DEFAULT_CAPS);
    // Count what the handlers ask the tracker thread.
    let full_scans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let issuers_read: Arc<Mutex<Vec<PubKey>>> = Arc::default();
    {
        let (counted_tx, mut counted_rx) = tokio::sync::mpsc::channel::<TrackerCommand>(100);
        let inner = state.tx.clone();
        let (scans, read) = (full_scans.clone(), issuers_read.clone());
        tokio::spawn(async move {
            while let Some(cmd) = counted_rx.recv().await {
                match &cmd {
                    TrackerCommand::GetNotes { .. } => {
                        scans.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    TrackerCommand::GetNotesByIssuer { issuer_pubkey, .. } => {
                        read.lock().unwrap().push(*issuer_pubkey);
                    }
                    _ => {}
                }
                if inner.send(cmd).await.is_err() {
                    break;
                }
            }
        });
        state.tx = counted_tx;
    }
    let token = [0x7c; 32];
    let (a, b) = (issuer(), issuer());
    for (owner, box_id, denomination) in [
        (&a.key, "box-a-erg", None),
        (&a.key, "box-a-token", Some(token)),
        (&b.key, "box-b-erg", None),
    ] {
        add_reserve(&state, owner, box_id, denomination, TRACKER_NFT, 0).await;
        state
            .ergo_scanner
            .lock()
            .await
            .reserve_storage()
            .store_reserve(&reserve_info(owner, box_id, denomination, TRACKER_NFT, 0))
            .unwrap();
    }
    let ts = now_ms() - 10_000;
    for (to, amount, denomination) in [
        (recipient(), 300_000_000, DenomKey::Erg),
        (recipient(), 200_000_000, DenomKey::Erg),
        (recipient(), 250, DenomKey::Token(token)),
    ] {
        let (status, error) = post(&state, note_request(&a, &to, amount, ts, denomination)).await;
        assert_eq!(status, StatusCode::CREATED, "{error}");
    }

    issuers_read.lock().unwrap().clear();
    let (status, body) = crate::reserve_api::get_all_reserves(axum::extract::State(state.clone())).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.0.error);
    assert_eq!(
        full_scans.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no scan of every note"
    );
    let mut read = issuers_read.lock().unwrap().clone();
    read.sort();
    let mut owners = vec![a.key, b.key];
    owners.sort();
    assert_eq!(read, owners, "each owner once, nobody else");
    let all = serde_json::to_value(body.0.data.unwrap()).unwrap();
    let by_box = |id: &str| {
        all.as_array()
            .unwrap()
            .iter()
            .find(|r| r["box_id"] == id)
            .cloned()
            .unwrap()
    };
    // 1 ERG of collateral against 0.5 ERG owed: ratio 2.
    assert_eq!(by_box("box-a-erg")["total_debt"], 500_000_000u64);
    assert_eq!(by_box("box-a-erg")["collateralization_ratio"], 2.0);
    // 1e9 token units against 250.
    assert_eq!(by_box("box-a-token")["total_debt"], 250);
    assert_eq!(by_box("box-a-token")["collateralization_ratio"], 4_000_000.0);
    // Nothing owed: ratio null.
    assert_eq!(by_box("box-b-erg")["total_debt"], 0);
    assert!(by_box("box-b-erg")["collateralization_ratio"].is_null());

    let (status, body) = crate::reserve_api::get_reserves_by_issuer(
        axum::extract::State(state.clone()),
        axum::extract::Path(hex::encode(a.key)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.0.error);
    let mine = body.0.data.unwrap();
    assert_eq!(mine.len(), 2);
    for reserve in &mine {
        let expected = if reserve.box_id == "box-a-erg" { 500_000_000 } else { 250 };
        assert_eq!(reserve.total_debt, expected, "{}", reserve.box_id);
    }

    let (status, body) = crate::reserve_api::get_reserve_by_box_id(
        axum::extract::State(state.clone()),
        axum::extract::Path("box-a-erg".to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let one = body.0.data.unwrap().unwrap();
    assert_eq!(one.total_debt, 500_000_000);
    assert_eq!(one.collateralization_ratio, Some(2.0));
    assert_eq!(one.pending_redemption_amount, 0);

    // Round 5b (F11): a redemption of A's ERG reserve waiting for the chain is noted on that
    // reserve, and the debt still includes it; B's marked entry is applied already.
    let waiting = basis_store::persistence::JournaledRedemption {
        tx_id: "ab".repeat(32),
        reserve_box_id: "cd".repeat(32),
        issuer_pubkey: hex::encode(a.key),
        recipient_pubkey: hex::encode(recipient()),
        denomination: DenomKey::Erg.denomination_id(),
        redeemed_amount: 100_000_000,
        new_already_redeemed: 100_000_000,
        ..Default::default()
    };
    state.tracker_storage.journal_redemption(&waiting).unwrap();
    state
        .tracker_storage
        .journal_redemption(&basis_store::persistence::JournaledRedemption {
            tx_id: "ef".repeat(32),
            issuer_pubkey: hex::encode(b.key),
            digest_mismatch: Some("applied, out of step".to_string()),
            ..waiting.clone()
        })
        .unwrap();
    let (status, body) = crate::reserve_api::get_all_reserves(axum::extract::State(state.clone())).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.0.error);
    let all = serde_json::to_value(body.0.data.unwrap()).unwrap();
    let field = |id: &str, name: &str| {
        all.as_array()
            .unwrap()
            .iter()
            .find(|r| r["box_id"] == id)
            .unwrap()[name]
            .clone()
    };
    assert_eq!(field("box-a-erg", "pending_redemption_amount"), 100_000_000u64);
    assert_eq!(field("box-a-erg", "total_debt"), 500_000_000u64);
    assert_eq!(field("box-a-token", "pending_redemption_amount"), 0);
    assert_eq!(field("box-b-erg", "pending_redemption_amount"), 0);
    let (_, body) = crate::reserve_api::get_reserves_by_issuer(
        axum::extract::State(state.clone()),
        axum::extract::Path(hex::encode(a.key)),
    )
    .await;
    for reserve in body.0.data.unwrap() {
        let expected = if reserve.box_id == "box-a-erg" { 100_000_000 } else { 0 };
        assert_eq!(reserve.pending_redemption_amount, expected, "{}", reserve.box_id);
    }
    let (_, body) = crate::reserve_api::get_reserve_by_box_id(
        axum::extract::State(state.clone()),
        axum::extract::Path("box-a-erg".to_string()),
    )
    .await;
    let one = body.0.data.unwrap().unwrap();
    assert_eq!((one.total_debt, one.pending_redemption_amount), (500_000_000, 100_000_000));
}
