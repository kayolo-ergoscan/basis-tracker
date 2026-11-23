//! `POST /redemption/tree/repair` and `GET /redemption/tree/repairs` (round 6, risk 1) with a
//! real tracker state and a mock node on 127.0.0.1 that holds the reserve box.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Json, State};
use axum::http::StatusCode;
use basis_store::persistence::JournaledRedemption;
use basis_store::{DenomKey, IouNote, PubKey, RedemptionManager, ReserveTreeRepairOutcome};

use crate::note_route_tests::{add_reserve, state, DEFAULT_CAPS, TRACKER_NFT};
use crate::reserve_repair::{list_tree_repairs, repair_reserve_tree, TreeRepairRequest};
use crate::{AppState, TrackerCommand};

const BUILT_AT: u64 = 1_700_000_000_000;
const RE_SIGNED_AT: u64 = 1_700_000_060_000;

fn reserve_box() -> String {
    "ab".repeat(32)
}

/// A tracker thread with a real `RedemptionManager`, answering what the repair route, the
/// confirmer's apply and these tests send.
fn spawn_tracker_thread() -> tokio::sync::mpsc::Sender<TrackerCommand> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TrackerCommand>(100);
    std::thread::spawn(move || {
        let mut m =
            RedemptionManager::new(basis_store::TrackerStateManager::new_with_temp_storage());
        while let Some(cmd) = rx.blocking_recv() {
            match cmd {
                TrackerCommand::AddNote {
                    issuer_pubkey,
                    note,
                    response_tx,
                } => {
                    let _ = response_tx.send(m.tracker.add_note(&issuer_pubkey, &note));
                }
                TrackerCommand::GetNotesByIssuer {
                    issuer_pubkey,
                    response_tx,
                } => {
                    let _ = response_tx.send(m.tracker.get_issuer_notes(&issuer_pubkey));
                }
                TrackerCommand::GetNoteByIssuerAndRecipient {
                    issuer_pubkey,
                    recipient_pubkey,
                    denomination,
                    response_tx,
                } => {
                    let _ = response_tx.send(m.tracker.get_note_optional(
                        &issuer_pubkey,
                        &recipient_pubkey,
                        &denomination,
                    ));
                }
                TrackerCommand::CompleteRedemption {
                    issuer_pubkey,
                    recipient_pubkey,
                    denomination,
                    redeemed_amount,
                    new_already_redeemed,
                    reserve_tree_timestamp,
                    response_tx,
                } => {
                    let _ = response_tx.send(m.complete_redemption_at(
                        &issuer_pubkey,
                        &recipient_pubkey,
                        &denomination,
                        redeemed_amount,
                        new_already_redeemed,
                        reserve_tree_timestamp,
                    ));
                }
                TrackerCommand::RepairReserveTreeValue {
                    issuer_pubkey,
                    recipient_pubkey,
                    denomination,
                    value,
                    chain_digest,
                    dry_run,
                    response_tx,
                } => {
                    let _ = response_tx.send(m.tracker.repair_reserve_tree_value(
                        &issuer_pubkey,
                        &recipient_pubkey,
                        &denomination,
                        value,
                        &chain_digest,
                        dry_run,
                    ));
                }
                TrackerCommand::GetReserveStateDigest {
                    issuer_pubkey,
                    denomination,
                    response_tx,
                } => {
                    let _ = response_tx.send(
                        m.tracker
                            .reserve_state_digest(&issuer_pubkey, &denomination),
                    );
                }
                TrackerCommand::GetReserveInsertProof {
                    issuer_pubkey,
                    recipient_pubkey,
                    denomination,
                    timestamp,
                    new_already_redeemed,
                    response_tx,
                } => {
                    let _ = response_tx.send(m.tracker.generate_reserve_insert_proof(
                        &issuer_pubkey,
                        &recipient_pubkey,
                        &denomination,
                        timestamp,
                        new_already_redeemed,
                    ));
                }
                TrackerCommand::Shutdown => break,
                _ => {}
            }
        }
    });
    tx
}

struct Fixture {
    state: AppState,
    /// The node's UTXO set: box id -> R5 (serialized, hex).
    utxo: Arc<Mutex<HashMap<String, String>>>,
    issuer_secret: [u8; 32],
    issuer: PubKey,
    recipient: PubKey,
}

async fn fixture() -> Fixture {
    let utxo: Arc<Mutex<HashMap<String, String>>> = Arc::default();
    let node_utxo = utxo.clone();
    let (url, _) = crate::local_wallet::tests::mock_node(move |method, target, _| {
        match target.strip_prefix("/utxo/byId/") {
            Some(id) if method == "GET" => match node_utxo.lock().unwrap().get(id) {
                Some(r5) => (
                    200,
                    serde_json::json!({ "boxId": id, "value": 1_000_000_000u64,
                        "additionalRegisters": { "R5": r5 } })
                    .to_string(),
                ),
                None => (404, r#"{"error":404}"#.to_string()),
            },
            _ => (404, r#"{"error":404}"#.to_string()),
        }
    })
    .await;
    let mut state = state(DEFAULT_CAPS);
    state.tx = spawn_tracker_thread();
    let mut config = (*state.config).clone();
    config.ergo.scanner.node_url = url;
    state.config = Arc::new(config);

    let (issuer_secret, issuer) = basis_store::schnorr::generate_keypair();
    let recipient = basis_store::schnorr::generate_keypair().1;
    add_reserve(&state, &issuer, &reserve_box(), None, TRACKER_NFT, 0).await;
    let fx = Fixture {
        state,
        utxo,
        issuer_secret,
        issuer,
        recipient,
    };
    fx.add_note(BUILT_AT).await;
    fx
}

impl Fixture {
    async fn ask<T>(
        &self,
        make: impl FnOnce(tokio::sync::oneshot::Sender<T>) -> TrackerCommand,
    ) -> T {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.state.tx.send(make(tx)).await.unwrap();
        rx.await.unwrap()
    }

    /// The note of 1000 from the issuer to the recipient, signed at `timestamp`.
    async fn add_note(&self, timestamp: u64) {
        let note = IouNote::create_and_sign(
            self.recipient,
            1_000,
            timestamp,
            &self.issuer_secret,
            &TRACKER_NFT,
            DenomKey::Erg,
        )
        .unwrap();
        let issuer = self.issuer;
        self.ask(|response_tx| TrackerCommand::AddNote {
            issuer_pubkey: issuer,
            note,
            response_tx,
        })
        .await
        .unwrap();
    }

    /// The reserve tree digest with the edge at `timestamp ‖ already`, as a build proves it.
    async fn digest_with(&self, timestamp: u64, already: u64) -> String {
        let (issuer, recipient) = (self.issuer, self.recipient);
        hex::encode(
            self.ask(|response_tx| TrackerCommand::GetReserveInsertProof {
                issuer_pubkey: issuer,
                recipient_pubkey: recipient,
                denomination: DenomKey::Erg,
                timestamp,
                new_already_redeemed: already,
                response_tx,
            })
            .await
            .unwrap()
            .1,
        )
    }

    async fn tracker_digest(&self) -> String {
        let issuer = self.issuer;
        hex::encode(
            self.ask(|response_tx| TrackerCommand::GetReserveStateDigest {
                issuer_pubkey: issuer,
                denomination: DenomKey::Erg,
                response_tx,
            })
            .await,
        )
    }

    async fn note_redeemed(&self) -> u64 {
        let (issuer, recipient) = (self.issuer, self.recipient);
        self.ask(|response_tx| TrackerCommand::GetNoteByIssuerAndRecipient {
            issuer_pubkey: issuer,
            recipient_pubkey: recipient,
            denomination: DenomKey::Erg,
            response_tx,
        })
        .await
        .unwrap()
        .unwrap()
        .amount_redeemed
    }

    /// The reserve box on chain, its R5 holding `digest`.
    fn chain_holds(&self, digest: &str) {
        self.utxo
            .lock()
            .unwrap()
            .insert(reserve_box(), format!("64{digest}072000"));
    }

    /// A redemption of 300 (cumulative 300) built at [`BUILT_AT`], as `/redemption/submit`
    /// journals it.
    fn entry(&self, tx_id: &str, chain: &str) -> JournaledRedemption {
        JournaledRedemption {
            tx_id: tx_id.to_string(),
            reserve_box_id: reserve_box(),
            issuer_pubkey: hex::encode(self.issuer),
            recipient_pubkey: hex::encode(self.recipient),
            denomination: DenomKey::Erg.denomination_id(),
            redeemed_amount: 300,
            new_already_redeemed: 300,
            data_input_ids: vec!["cd".repeat(32)],
            submitted_at_ms: 1,
            reserve_tree_timestamp: Some(BUILT_AT),
            reserve_r5_digest: Some(chain.to_string()),
            ..Default::default()
        }
    }

    fn explicit(&self, timestamp: u64, already_redeemed: u64) -> TreeRepairRequest {
        TreeRepairRequest {
            issuer_pubkey: Some(hex::encode(self.issuer)),
            recipient_pubkey: Some(hex::encode(self.recipient)),
            timestamp: Some(timestamp),
            already_redeemed: Some(already_redeemed),
            ..Default::default()
        }
    }

    async fn repair(
        &self,
        request: TreeRepairRequest,
    ) -> (
        StatusCode,
        crate::models::ApiResponse<basis_store::persistence::ReserveTreeRepairRecord>,
    ) {
        let (status, Json(body)) =
            repair_reserve_tree(State(self.state.clone()), Json(request)).await;
        (status, body)
    }

    async fn repairs(&self) -> Vec<basis_store::persistence::ReserveTreeRepairRecord> {
        let (status, Json(body)) = list_tree_repairs(State(self.state.clone())).await;
        assert_eq!(status, StatusCode::OK);
        body.data.unwrap()
    }
}

/// The risk itself: a redemption applied with the note's timestamp after a re-sign (the legacy
/// apply) leaves the reserve tree with the right amount and another timestamp; the confirmer's
/// apply of the journaled redemption is refused, so its reserve stays blocked. The repair from
/// the journal entry (`tx_id`) is checked against R5 of the reserve box on chain: a dry run
/// changes nothing, a value that would not hash to R5 is refused (409) and changes nothing, the
/// repair brings the tree to R5 and is recorded; then the confirmer's apply finds the redemption
/// applied and the journal entry leaves. A repeat changes nothing and records nothing.
#[tokio::test]
async fn a_tree_value_with_another_timestamp_is_repaired_from_its_journal_entry() {
    let fx = fixture().await;
    let chain = fx.digest_with(BUILT_AT, 300).await;
    fx.chain_holds(&chain);
    fx.add_note(RE_SIGNED_AT).await;
    let (issuer, recipient) = (fx.issuer, fx.recipient);
    fx.ask(|response_tx| TrackerCommand::CompleteRedemption {
        issuer_pubkey: issuer,
        recipient_pubkey: recipient,
        denomination: DenomKey::Erg,
        redeemed_amount: 300,
        new_already_redeemed: Some(300),
        reserve_tree_timestamp: None,
        response_tx,
    })
    .await
    .unwrap();
    let out_of_step = fx.tracker_digest().await;
    assert_ne!(out_of_step, chain);

    let tx_id = "7a".repeat(32);
    let entry = fx.entry(&tx_id, &chain);
    fx.state.tracker_storage.journal_redemption(&entry).unwrap();
    let shared = fx.state.shared_tracker_state.lock().await.clone();
    let apply = crate::redemption_confirmer::apply_journaled(
        &fx.state.tracker_storage,
        &shared,
        &fx.state.tx,
        &entry,
    )
    .await;
    assert!(apply.unwrap_err().contains("another timestamp"));

    let by_entry = || TreeRepairRequest {
        tx_id: Some(tx_id.to_ascii_uppercase()),
        ..Default::default()
    };
    let (status, body) = fx
        .repair(TreeRepairRequest {
            dry_run: true,
            ..by_entry()
        })
        .await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    let dry = body.data.unwrap();
    assert_eq!(dry.repair.outcome, ReserveTreeRepairOutcome::WouldRepair);
    assert_eq!(dry.repair.digest_after, chain);
    assert_eq!(fx.tracker_digest().await, out_of_step);

    let (status, body) = fx.repair(fx.explicit(RE_SIGNED_AT + 5, 300)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let refusal = body.error.unwrap();
    assert!(
        refusal.contains(&chain) && refusal.contains("nothing changed"),
        "{refusal}"
    );
    assert_eq!(fx.tracker_digest().await, out_of_step);
    assert!(fx.repairs().await.is_empty());

    let (status, body) = fx.repair(by_entry()).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    let record = body.data.unwrap();
    assert_eq!(record.repair.outcome, ReserveTreeRepairOutcome::Repaired);
    assert_eq!(record.tx_id.as_deref(), Some(tx_id.as_str()));
    assert_eq!(record.reserve_box_id, reserve_box());
    assert_eq!(
        record.repair.before.map(|v| v.timestamp),
        Some(RE_SIGNED_AT)
    );
    assert_eq!(fx.tracker_digest().await, chain);
    assert_eq!(fx.repairs().await, vec![record]);

    crate::redemption_confirmer::apply_journaled(
        &fx.state.tracker_storage,
        &shared,
        &fx.state.tx,
        &entry,
    )
    .await
    .expect("the confirmer finds it applied now");
    assert!(fx
        .state
        .tracker_storage
        .journaled_redemptions()
        .unwrap()
        .is_empty());
    assert_eq!(fx.note_redeemed().await, 300);

    let (status, body) = fx.repair(fx.explicit(BUILT_AT, 300)).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    assert_eq!(
        body.data.unwrap().repair.outcome,
        ReserveTreeRepairOutcome::Unchanged
    );
    assert_eq!(fx.repairs().await.len(), 1, "a repeat records nothing");
}

/// A redemption the tracker never applied (broadcast elsewhere, or dropped from the journal and
/// mined): the reserve's entry marked out of step blocks it. The repair from the chain's value
/// brings the tree and the note in step and removes the reserve's marked entries (not another
/// reserve's), so the reserve builds again.
#[tokio::test]
async fn a_repair_clears_the_reserves_marked_entries() {
    let fx = fixture().await;
    let chain = fx.digest_with(BUILT_AT, 400).await;
    fx.chain_holds(&chain);
    let marked = JournaledRedemption {
        digest_mismatch: Some("tracker reserve tree digest x, R5 of the reserve output y".into()),
        ..fx.entry(&"5e".repeat(32), &chain)
    };
    let others = JournaledRedemption {
        tx_id: "6f".repeat(32),
        issuer_pubkey: hex::encode([0x02; 33]),
        ..marked.clone()
    };
    for entry in [&marked, &others] {
        fx.state.tracker_storage.journal_redemption(entry).unwrap();
    }
    assert!(crate::redemption_confirmer::waiting_redemption(
        &fx.state.tracker_storage,
        &hex::encode(fx.issuer),
        &DenomKey::Erg
    )
    .unwrap()
    .is_some());

    let (status, body) = fx.repair(fx.explicit(BUILT_AT, 400)).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    let record = body.data.unwrap();
    assert_eq!(record.repair.outcome, ReserveTreeRepairOutcome::Repaired);
    assert_eq!(
        (record.repair.before, record.repair.note_redeemed_before),
        (None, 0)
    );
    assert_eq!(record.cleared_marked, vec![marked.tx_id.clone()]);
    assert_eq!(fx.note_redeemed().await, 400);
    assert_eq!(fx.tracker_digest().await, chain);
    let left: Vec<String> = fx
        .state
        .tracker_storage
        .journaled_redemptions()
        .unwrap()
        .into_iter()
        .map(|e| e.tx_id)
        .collect();
    assert_eq!(left, vec![others.tx_id]);
    assert!(crate::redemption_confirmer::waiting_redemption(
        &fx.state.tracker_storage,
        &hex::encode(fx.issuer),
        &DenomKey::Erg
    )
    .unwrap()
    .is_none());
}

/// What the route refuses before it changes anything.
#[tokio::test]
async fn the_repair_route_refuses_what_it_cannot_check() {
    let fx = fixture().await;
    let chain = fx.digest_with(BUILT_AT, 300).await;

    // The reserve box is not in the node's UTXO set.
    let (status, body) = fx.repair(fx.explicit(BUILT_AT, 300)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{:?}", body.error);
    assert!(body.error.unwrap().contains("UTXO set"));
    fx.chain_holds(&chain);

    // An unknown journal entry; both forms; a missing field; a malformed key.
    let (status, _) = fx
        .repair(TreeRepairRequest {
            tx_id: Some("9c".repeat(32)),
            ..Default::default()
        })
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = fx
        .repair(TreeRepairRequest {
            tx_id: Some("9c".repeat(32)),
            ..fx.explicit(BUILT_AT, 300)
        })
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = fx
        .repair(TreeRepairRequest {
            timestamp: None,
            ..fx.explicit(BUILT_AT, 300)
        })
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = fx
        .repair(TreeRepairRequest {
            issuer_pubkey: Some("02".to_string()),
            ..fx.explicit(BUILT_AT, 300)
        })
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A note the tracker does not hold.
    let (status, _) = fx
        .repair(TreeRepairRequest {
            recipient_pubkey: Some(hex::encode(basis_store::schnorr::generate_keypair().1)),
            ..fx.explicit(BUILT_AT, 300)
        })
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // An issuer without a tracked reserve.
    let stranger = basis_store::schnorr::generate_keypair().1;
    let (status, body) = fx
        .repair(TreeRepairRequest {
            issuer_pubkey: Some(hex::encode(stranger)),
            ..fx.explicit(BUILT_AT, 300)
        })
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.error.unwrap().contains("no tracked reserve"));

    assert_eq!(fx.note_redeemed().await, 0);
    assert!(fx.repairs().await.is_empty());
}
