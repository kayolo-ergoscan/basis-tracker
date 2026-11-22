//! End-to-end tests of `POST /redemption/build` (round 4, C2) against a mock node on 127.0.0.1.
//!
//! The tracker state is real (notes, committed digest, reserve tree and their proofs), the
//! reserve box is locked by the real ERG reserve contract (`contract/basis.es`, as compiled into
//! `basis_store::contract_compiler`), and the recipient finishes the transaction as a client
//! does. The built ERG redemption pays the miner fee out of the payout, spends only the reserve,
//! and passes a full local validation (`TransactionContext::validate`: value and token
//! preservation, minimum values, heights and every input's script).

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::Transaction;
use ergo_lib::ergo_chain_types::{Header, PreHeader};
use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox;
use ergo_lib::ergotree_ir::ergo_tree::ErgoTree;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use ergo_lib::wallet::secret_key::SecretKey;
use ergo_lib::wallet::signing::TransactionContext;
use serde_json::json;

use basis_offchain::ergo_tx::build_savl_tree_from_digest;
use basis_offchain::signing::add_input_proof;
use basis_store::{DenomKey, IouNote, PubKey, TrackerStateManager};

use crate::local_wallet::tests::{mock_node, utxo_box, Seen, LAST_HEADERS_JSON};
use crate::redemption_build::{
    build_redemption, RedemptionBuildRequest, BUILD_REQUEST_MAX_SKEW_MS, FEE_PAID_BY_RECIPIENT,
};
use crate::{AppState, TrackerCommand};

const TRACKER_NFT: [u8; 32] = [0x5a; 32];
const RESERVE_NFT: [u8; 32] = [0x6b; 32];
/// 1 ERG of collateral.
const RESERVE_VALUE: u64 = 1_000_000_000;
/// The note's committed total debt: 0.05 ERG.
const NOTE_DEBT: u64 = 50_000_000;
const FEE: u64 = 1_000_000;
/// Creation heights of the fixture boxes: below the fixture headers (123405..=123414).
const RESERVE_HEIGHT: u32 = 123_000;
const TRACKER_BOX_HEIGHT: u32 = 123_100;

static STORAGE_INIT_LOCK: Mutex<()> = Mutex::new(());

/// What the mock node answers.
#[derive(Clone, Copy, PartialEq)]
enum Node {
    Healthy,
    /// `/blocks/lastHeaders/10` fails with a body that must never reach a client.
    LeakyFailure,
}

const LEAKY_BODY: &str = "node-internal-detail-7f3a";

struct Harness {
    state: AppState,
    /// How many times the tracker built its committed tree (see [`TrackerSetup`]).
    committed_tree_builds: Arc<std::sync::atomic::AtomicU64>,
    issuer_pk: PubKey,
    recipient_secret: [u8; 32],
    recipient_pk: PubKey,
    note_signature: [u8; 65],
    reserve: ErgoBox,
    tracker_box: ErgoBox,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn register_hex_long(v: i64) -> String {
    basis_offchain::ergo_tx::serialize_ergo_long(v)
}

/// The node's JSON for a box (the fields `/redemption/build` reads).
fn node_box_json(b: &ErgoBox, registers: &[(&str, String)]) -> serde_json::Value {
    let assets: Vec<serde_json::Value> = b
        .tokens
        .as_ref()
        .map(|tokens| {
            tokens
                .iter()
                .map(|t| json!({ "tokenId": String::from(t.token_id), "amount": *t.amount.as_u64() }))
                .collect()
        })
        .unwrap_or_default();
    let registers: serde_json::Map<String, serde_json::Value> = registers
        .iter()
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect();
    json!({
        "boxId": String::from(b.box_id()),
        "value": *b.value.as_u64(),
        "ergoTree": hex::encode(b.ergo_tree.sigma_serialize_bytes().unwrap()),
        "assets": assets,
        "additionalRegisters": registers,
        "creationHeight": b.creation_height,
    })
}

/// Digests of the tracker state a [`spawn_tracker_thread`] set up.
struct TrackerSetup {
    /// The tracker tree digest, committed: the tracker box's R5.
    committed_digest: [u8; 33],
    /// The issuer's (empty) reserve tree digest: the reserve box's R5.
    reserve_digest: Vec<u8>,
    /// How many times the tracker built its committed tree, after each committed proof.
    committed_tree_builds: Arc<std::sync::atomic::AtomicU64>,
}

/// A tracker thread holding `note` of `issuer`, committed, that serves the commands
/// `/redemption/build` sends with the real tracker state (the state is not `Send`, so it is
/// created on its thread, as in `main`).
fn spawn_tracker_thread(
    issuer: PubKey,
    note: IouNote,
) -> (tokio::sync::mpsc::Sender<TrackerCommand>, TrackerSetup) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TrackerCommand>(100);
    let (setup_tx, setup_rx) = std::sync::mpsc::channel();
    let committed_tree_builds = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let builds = committed_tree_builds.clone();
    std::thread::spawn(move || {
        let mut tracker = TrackerStateManager::new_with_temp_storage();
        tracker.add_note(&issuer, &note).unwrap();
        let committed_digest = tracker.get_state().avl_root_digest;
        tracker
            .reconcile_with_confirmed_digest(&committed_digest, "tracker-box", 1)
            .unwrap();
        let reserve_digest = tracker.reserve_state_digest(&issuer, &DenomKey::Erg);
        setup_tx
            .send(TrackerSetup {
                committed_digest,
                reserve_digest,
                committed_tree_builds,
            })
            .unwrap();
        while let Some(cmd) = rx.blocking_recv() {
            match cmd {
                TrackerCommand::GetNoteByIssuerAndRecipient {
                    issuer_pubkey,
                    recipient_pubkey,
                    denomination,
                    response_tx,
                } => {
                    let _ = response_tx.send(tracker.get_note_optional(
                        &issuer_pubkey,
                        &recipient_pubkey,
                        &denomination,
                    ));
                }
                TrackerCommand::GetNotesByIssuer {
                    issuer_pubkey,
                    response_tx,
                } => {
                    let _ = response_tx.send(tracker.get_issuer_notes(&issuer_pubkey));
                }
                TrackerCommand::GetCommittedTrackerLookupProof {
                    issuer_pubkey,
                    recipient_pubkey,
                    denomination,
                    response_tx,
                } => {
                    let proof = tracker.generate_committed_tracker_lookup_proof(
                        &issuer_pubkey,
                        &recipient_pubkey,
                        &denomination,
                    );
                    builds.store(
                        tracker.committed_tree_rebuild_count(),
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    let _ = response_tx.send(proof);
                }
                TrackerCommand::GetReserveLookupProof {
                    issuer_pubkey,
                    recipient_pubkey,
                    denomination,
                    response_tx,
                } => {
                    let _ = response_tx.send(tracker.generate_reserve_lookup_proof(
                        &issuer_pubkey,
                        &recipient_pubkey,
                        &denomination,
                    ));
                }
                TrackerCommand::GetReserveInsertProof {
                    issuer_pubkey,
                    recipient_pubkey,
                    denomination,
                    timestamp,
                    new_already_redeemed,
                    response_tx,
                } => {
                    let _ = response_tx.send(tracker.generate_reserve_insert_proof(
                        &issuer_pubkey,
                        &recipient_pubkey,
                        &denomination,
                        timestamp,
                        new_already_redeemed,
                    ));
                }
                TrackerCommand::GetReserveStateDigest {
                    issuer_pubkey,
                    denomination,
                    response_tx,
                } => {
                    let _ = response_tx
                        .send(tracker.reserve_state_digest(&issuer_pubkey, &denomination));
                }
                TrackerCommand::Shutdown => break,
                // Nothing else is sent by a build; an unanswered command fails the build.
                _ => {}
            }
        }
    });
    (tx, setup_rx.recv().unwrap())
}

async fn harness(node: Node, max_builds_per_pair: u32) -> Harness {
    let (tracker_secret, tracker_pk) = basis_store::schnorr::generate_keypair();
    let (issuer_secret, issuer_pk) = basis_store::schnorr::generate_keypair();
    let (recipient_secret, recipient_pk) = basis_store::schnorr::generate_keypair();

    // The note, committed: the tracker box's R5 holds the tracker's digest.
    let note_timestamp = crate::redemption_build::now_unix_ms() - 60_000;
    let note = IouNote::create_and_sign(
        recipient_pk,
        NOTE_DEBT,
        note_timestamp,
        &issuer_secret,
        &TRACKER_NFT,
        DenomKey::Erg,
    )
    .unwrap();
    let (tracker_tx, setup) = spawn_tracker_thread(issuer_pk, note.clone());
    let TrackerSetup {
        committed_digest,
        reserve_digest,
        committed_tree_builds,
    } = setup;

    // The issuer's reserve under the real ERG reserve contract, and the tracker box.
    let reserve_tree = ErgoTree::sigma_parse_bytes(
        &hex::decode(basis_store::contract_compiler::get_basis_reserve_ergo_tree_hex().unwrap())
            .unwrap(),
    )
    .unwrap();
    let reserve_r4 = format!("07{}", hex::encode(issuer_pk));
    let reserve_r5 = hex::encode(build_savl_tree_from_digest(&hex::encode(reserve_digest)));
    let reserve_r6 = format!("0e20{}", hex::encode(TRACKER_NFT));
    let reserve_r7 = register_hex_long(0);
    let reserve = utxo_box(
        &reserve_tree,
        RESERVE_VALUE,
        &[(RESERVE_NFT, 1)],
        &[&reserve_r4, &reserve_r5, &reserve_r6, &reserve_r7],
        RESERVE_HEIGHT,
        0,
    );
    let tracker_tree = crate::local_wallet::tests::tree_of(&tracker_pk);
    let tracker_r4 = format!("07{}", hex::encode(tracker_pk));
    let tracker_r5 = hex::encode(build_savl_tree_from_digest(&hex::encode(committed_digest)));
    let tracker_box = utxo_box(
        &tracker_tree,
        1_000_000,
        &[(TRACKER_NFT, 1)],
        &[&tracker_r4, &tracker_r5],
        TRACKER_BOX_HEIGHT,
        1,
    );

    let reserve_id = String::from(reserve.box_id());
    let tracker_id = String::from(tracker_box.box_id());
    let reserve_json = node_box_json(
        &reserve,
        &[
            ("R4", reserve_r4.clone()),
            ("R5", reserve_r5.clone()),
            ("R6", reserve_r6.clone()),
            ("R7", reserve_r7.clone()),
        ],
    )
    .to_string();
    let reserve_bytes = hex::encode(reserve.sigma_serialize_bytes().unwrap());
    let tracker_bytes = hex::encode(tracker_box.sigma_serialize_bytes().unwrap());
    let (node_url, seen) = {
        let reserve_id = reserve_id.clone();
        let tracker_id = tracker_id.clone();
        mock_node(move |method, target, _| {
            if method != "GET" {
                return (404, "{}".to_string());
            }
            if target == "/blocks/lastHeaders/10" {
                return match node {
                    Node::Healthy => (200, LAST_HEADERS_JSON.to_string()),
                    Node::LeakyFailure => (500, format!("{{\"reason\":\"{LEAKY_BODY}\"}}")),
                };
            }
            if target == format!("/utxo/byId/{reserve_id}") {
                return (200, reserve_json.clone());
            }
            if target == format!("/utxo/byIdBinary/{reserve_id}") {
                return (
                    200,
                    json!({ "boxId": reserve_id, "bytes": reserve_bytes }).to_string(),
                );
            }
            if target == format!("/utxo/byIdBinary/{tracker_id}") {
                return (
                    200,
                    json!({ "boxId": tracker_id, "bytes": tracker_bytes }).to_string(),
                );
            }
            (404, "{}".to_string())
        })
        .await
    };

    let data_dir = tempfile::tempdir().unwrap().keep();
    let scanner = {
        let _guard = STORAGE_INIT_LOCK.lock().unwrap();
        basis_store::ergo_scanner::ServerState::new(
            basis_store::ergo_scanner::NodeConfig {
                node_url: node_url.clone(),
                ..Default::default()
            },
            &data_dir,
        )
        .unwrap()
    };
    let reserve_info = basis_store::reserve_tracker::ExtendedReserveInfo {
        base_info: basis_store::ReserveInfo {
            collateral_amount: RESERVE_VALUE,
            last_updated_height: RESERVE_HEIGHT as u64,
            contract_address: basis_store::contract_compiler::get_basis_reserve_contract_p2s()
                .unwrap(),
            tracker_nft_id: hex::encode(TRACKER_NFT),
            refund_initiation_height: 0,
            reserve_token_id: String::new(),
        },
        total_debt: NOTE_DEBT,
        box_id: reserve_id.clone(),
        owner_pubkey: hex::encode(issuer_pk),
        last_updated_timestamp: 0,
    };
    scanner
        .reserve_storage()
        .store_reserve(&reserve_info)
        .unwrap();
    let reserve_tracker = basis_store::ReserveTracker::new();
    reserve_tracker.update_reserve(reserve_info).unwrap();

    let shared = crate::tracker_box_updater::SharedTrackerState::new();
    shared.set_confirmed(committed_digest, tracker_id.clone(), TRACKER_BOX_HEIGHT as u64);
    shared.set_tracker_box_id(tracker_id);

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
            redemption_build_max_per_pair_per_hour: max_builds_per_pair,
            redemption_build_max_per_recipient_per_hour: 30,
            notes_require_reserve: false,
            notes_max_recipients_per_issuer: 50,
            notes_max_updates_per_issuer_per_hour: 120,
            notes_max_new_edges_per_hour: 1000,
            notes_max_new_edges_per_issuer_per_hour: 10,
            redemption_build_max_per_issuer_per_hour: 6,
            redemption_build_max_per_hour: 30,
        },
        ergo: crate::config::ErgoConfig {
            scanner: basis_store::ergo_scanner::NodeConfig {
                node_url,
                ..Default::default()
            },
            wallet: Default::default(),
            basis_reserve_contract_p2s:
                basis_store::contract_compiler::get_basis_reserve_contract_p2s().unwrap(),
            basis_token_reserve_contract_p2s:
                basis_store::contract_compiler::get_basis_token_reserve_contract_p2s().unwrap(),
            tracker_nft_id: Some(hex::encode(TRACKER_NFT)),
            reserve_tokens: Default::default(),
            tracker_public_key: Some(hex::encode(tracker_pk)),
            tracker_secret_key: Some(hex::encode(tracker_secret)),
        },
        transaction: crate::config::TransactionConfig {
            fee: FEE,
            change_address: None,
            heartbeat_blocks: 720,
            commit_reserve_nano: 100_000_000,
        },
        acceptance: crate::acceptance::config::AcceptanceConfig::empty(),
        redemption: crate::config::RedemptionConfig {
            enforce_acceptance_policy: true,
        },
        confirmation: crate::config::ConfirmationConfig::default(),
    };

    let (tracker_storage, policy_storage) = {
        let _guard = STORAGE_INIT_LOCK.lock().unwrap();
        std::fs::create_dir_all(data_dir.join("tracker_storage")).unwrap();
        std::fs::create_dir_all(data_dir.join("policies")).unwrap();
        (
            basis_store::persistence::TrackerStorage::open(data_dir.join("tracker_storage"))
                .unwrap(),
            basis_store::persistence::AcceptancePolicyStorage::open(data_dir.join("policies"))
                .unwrap(),
        )
    };
    let state = AppState {
        tx: tracker_tx,
        event_store: Arc::new(crate::store::EventStore::new_in_memory()),
        ergo_scanner: Arc::new(tokio::sync::Mutex::new(scanner)),
        reserve_tracker: Arc::new(tokio::sync::Mutex::new(reserve_tracker)),
        config: Arc::new(config),
        shared_tracker_state: Arc::new(tokio::sync::Mutex::new(shared)),
        tracker_storage,
        acceptance_predicate: None,
        policy_storage,
        pending_redemptions: Arc::new(crate::redemption_build::PendingRedemptionRegistry::new()),
        redemption_build_rate: Arc::new(crate::redemption_build::BuildRateLimiter::new()),
        note_limits: Arc::new(crate::note_limits::NoteLimiter::new()),
    };

    Harness {
        state,
        committed_tree_builds,
        issuer_pk,
        recipient_secret,
        recipient_pk,
        note_signature: note.signature,
        reserve,
        tracker_box,
        seen,
    }
}

impl Harness {
    /// A build request for `amount`, signed by the recipient at `request_timestamp`.
    fn request_at(&self, amount: u64, request_timestamp: u64) -> RedemptionBuildRequest {
        let message = basis_store::schnorr::build_request_message(
            &TRACKER_NFT,
            &self.issuer_pk,
            &self.recipient_pk,
            &DenomKey::Erg,
            amount,
            request_timestamp,
        );
        let signature =
            basis_store::schnorr::schnorr_sign(&message, &self.recipient_secret, &self.recipient_pk)
                .unwrap();
        RedemptionBuildRequest {
            issuer_pubkey: hex::encode(self.issuer_pk),
            recipient_pubkey: hex::encode(self.recipient_pk),
            amount,
            timestamp: 0,
            issuer_signature: hex::encode(self.note_signature),
            emergency: false,
            tracker_box_id: None,
            change_address: None,
            denomination: "erg".to_string(),
            request_timestamp,
            receiver_signature: hex::encode(signature),
        }
    }

    fn request(&self, amount: u64) -> RedemptionBuildRequest {
        // Strictly rising per recipient: one millisecond per call is enough.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let bump = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.request_at(amount, crate::redemption_build::now_unix_ms() + bump)
    }

    async fn build(
        &self,
        request: RedemptionBuildRequest,
    ) -> (
        StatusCode,
        crate::models::ApiResponse<crate::redemption_build::RedemptionBuildResponse>,
    ) {
        let (status, body) =
            build_redemption(axum::extract::State(self.state.clone()), axum::Json(request)).await;
        (status, body.0)
    }

    fn node_requests(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| format!("{} {}", s.method, s.target))
            .collect()
    }
}

/// The recipient finishes the build as a client does: checks it, proves the reserve input.
fn client_sign(
    h: &Harness,
    build: &crate::redemption_build::RedemptionBuildResponse,
) -> (Transaction, Vec<ErgoBox>, Vec<ErgoBox>) {
    let unsigned: UnsignedTransaction = serde_json::from_value(build.unsigned_tx.clone()).unwrap();
    let partial: Transaction = serde_json::from_value(build.partial_tx.clone()).unwrap();
    let parse = |h: &String| ErgoBox::sigma_parse_bytes(&hex::decode(h).unwrap()).unwrap();
    let inputs: Vec<ErgoBox> = build.input_box_binaries.iter().map(parse).collect();
    let data: Vec<ErgoBox> = build.data_box_binaries.iter().map(parse).collect();
    let headers: [Header; 10] = build.headers[..10].to_vec().try_into().unwrap();
    let pre_header = PreHeader::from(headers[0].clone());
    let receiver_sk = SecretKey::dlog_from_bytes(&h.recipient_secret).unwrap();
    let signed = add_input_proof(
        &unsigned,
        Some(&partial),
        &inputs,
        &data,
        &pre_header,
        &headers,
        0,
        &receiver_sk,
    )
    .unwrap();
    (signed, inputs, data)
}

/// The ERG redemption the tracker builds pays the fee out of the payout, spends only the
/// reserve (the tracker signs and spends nothing), and is valid under the real contract.
#[tokio::test]
async fn erg_redemption_pays_the_fee_from_the_payout_and_validates_against_the_contract() {
    let h = harness(Node::Healthy, 12).await;
    let amount = 20_000_000;
    let (status, body) = h.build(h.request(amount)).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    let build = body.data.unwrap();

    assert_eq!(build.fee_paid_by, FEE_PAID_BY_RECIPIENT);
    assert_eq!(build.fee, FEE);
    assert_eq!(build.recipient_output_value, amount - FEE);
    assert_eq!(build.reserve_output_value, RESERVE_VALUE - amount);
    assert_eq!(build.change_amount, 0);
    assert_eq!(build.change_address, "");
    assert_eq!(build.total_debt, NOTE_DEBT);
    assert!(build.is_first_redemption);
    assert_eq!(build.new_already_redeemed, amount);
    assert_eq!(build.input_box_binaries.len(), 1, "only the reserve is spent");
    assert_eq!(build.tracker_box_id, String::from(h.tracker_box.box_id()));
    // No fee box scan, nothing but the boxes the build reads and the headers.
    let requests = h.node_requests();
    assert!(
        requests.iter().all(|r| !r.contains("byAddress")),
        "{requests:?}"
    );

    let (signed, inputs, data) = client_sign(&h, &build);
    assert_eq!(signed.inputs.len(), 1);
    assert_eq!(inputs[0].box_id(), h.reserve.box_id());
    let outputs = signed.outputs.as_vec();
    assert_eq!(outputs.len(), 3, "reserve, recipient, miner fee");
    assert_eq!(*outputs[1].value.as_u64(), amount - FEE);
    assert_eq!(*outputs[2].value.as_u64(), FEE);
    // What the basis CLI and TUI check before they sign (`verify_redemption_tx` with a fee
    // allowance): the reserve releases exactly `amount`, the recipient's P2PK gets the rest.
    assert_eq!(*inputs[0].value.as_u64() - *outputs[0].value.as_u64(), amount);
    assert_eq!(
        outputs[1].ergo_tree,
        crate::local_wallet::tests::tree_of(&h.recipient_pk)
    );

    // Full validation: value and token preservation, minimum values, heights, and the reserve
    // contract's redeem path with the recipient's proof.
    let state_context = crate::local_wallet::tests::fixture_state();
    TransactionContext::new(signed.clone(), inputs.clone(), data.clone())
        .unwrap()
        .validate(&state_context)
        .unwrap();

    // The contract refuses the same transaction without the recipient's proof.
    let unproven = Transaction::from_unsigned_tx(
        serde_json::from_value(build.unsigned_tx.clone()).unwrap(),
        vec![ergo_lib::ergotree_interpreter::sigma_protocol::prover::ProofBytes::Empty],
    )
    .unwrap();
    assert!(TransactionContext::new(unproven, inputs, data)
        .unwrap()
        .validate(&state_context)
        .is_err());
}

/// Requests that fail the signature or clock checks never reach the node and never use a build
/// budget. A signed request for a note the tracker holds uses one unit of its own budget (round
/// 5: counted before the committed proof), also when a cheap check refuses it; it still never
/// reaches the node.
#[tokio::test]
async fn invalid_requests_cost_no_node_request_and_only_signed_ones_use_the_budget() {
    // Three refused signed requests and one build fit; the next is over the budget.
    let h = harness(Node::Healthy, 4).await;
    let amount = 20_000_000;

    // No signature at all.
    let mut unsigned = h.request(amount);
    unsigned.receiver_signature = String::new();
    let (status, body) = h.build(unsigned).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.error.unwrap().contains("receiver_signature"));

    // Signed by someone else.
    let mut forged = h.request(amount);
    let (other_secret, other_pk) = basis_store::schnorr::generate_keypair();
    let message = basis_store::schnorr::build_request_message(
        &TRACKER_NFT,
        &h.issuer_pk,
        &h.recipient_pk,
        &DenomKey::Erg,
        amount,
        forged.request_timestamp,
    );
    forged.receiver_signature = hex::encode(
        basis_store::schnorr::schnorr_sign(&message, &other_secret, &other_pk).unwrap(),
    );
    let (status, body) = h.build(forged).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.error.unwrap().contains("does not verify"));

    // Signed for another amount.
    let mut other_amount = h.request(amount);
    other_amount.amount = amount + 1;
    let (status, _) = h.build(other_amount).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Outside the clock window.
    let stale = h.request_at(
        amount,
        crate::redemption_build::now_unix_ms() - BUILD_REQUEST_MAX_SKEW_MS - 5_000,
    );
    let (status, body) = h.build(stale).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.error.unwrap().contains("tracker's clock"));
    assert_eq!(
        h.committed_tree_builds.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing before the signature verifies reaches the committed tree"
    );

    // Signed requests the cheap checks refuse: each uses one unit of the pair's budget.
    // More than the committed outstanding debt.
    let (status, body) = h.build(h.request(NOTE_DEBT + 1)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.error.unwrap().contains("outstanding"), "too much");

    // Not even the miner fee.
    let (status, body) = h.build(h.request(FEE)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.error.unwrap().contains("miner fee"));

    // A wrong issuer signature.
    let mut bad_issuer_sig = h.request(amount);
    bad_issuer_sig.issuer_signature = "01".repeat(65);
    let (status, body) = h.build(bad_issuer_sig).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.error.unwrap().contains("issuer_signature"));

    assert!(
        h.node_requests().is_empty(),
        "no node request for a refused build: {:?}",
        h.node_requests()
    );

    // One unit is left (4 per hour here): a valid request builds.
    let (status, body) = h.build(h.request(amount)).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    // And the next one is over budget, before the committed proof and any node request.
    let before = h.node_requests().len();
    let (status, body) = h.build(h.request(amount)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{:?}", body.error);
    assert_eq!(h.node_requests().len(), before);
}

/// Round 5, item 1: N builds of a committed note make the tracker build its committed tree
/// once, not once per build.
#[tokio::test]
async fn many_builds_make_one_committed_tree() {
    let h = harness(Node::Healthy, 12).await;
    for _ in 0..10 {
        let (status, body) = h.build(h.request(20_000_000)).await;
        assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    }
    assert_eq!(
        h.committed_tree_builds
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

/// Round 5, item 2: a request signed by a key that holds no note is refused at the note lookup
/// and leaves nothing in the request-timestamp table, so throwaway keys cannot fill it. A
/// replay is still refused before the note lookup.
#[tokio::test]
async fn keys_without_a_note_leave_no_request_timestamp() {
    let h = harness(Node::Healthy, 12).await;
    for _ in 0..20 {
        let (secret, pk) = basis_store::schnorr::generate_keypair();
        let request_timestamp = crate::redemption_build::now_unix_ms();
        let message = basis_store::schnorr::build_request_message(
            &TRACKER_NFT,
            &h.issuer_pk,
            &pk,
            &DenomKey::Erg,
            20_000_000,
            request_timestamp,
        );
        let mut request = h.request_at(20_000_000, request_timestamp);
        request.recipient_pubkey = hex::encode(pk);
        request.receiver_signature =
            hex::encode(basis_store::schnorr::schnorr_sign(&message, &secret, &pk).unwrap());
        let (status, body) = h.build(request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{:?}", body.error);
        assert!(body.error.unwrap().contains("note not found"));
    }
    assert_eq!(h.state.redemption_build_rate.tracked_request_timestamps(), 0);

    // The recipient of the note is recorded, and its replay stops at the timestamp check.
    let request_timestamp = crate::redemption_build::now_unix_ms();
    let (status, body) = h.build(h.request_at(20_000_000, request_timestamp)).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    assert_eq!(h.state.redemption_build_rate.tracked_request_timestamps(), 1);
    let (status, body) = h.build(h.request_at(20_000_000, request_timestamp)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.error.unwrap().contains("not greater"));
}

/// A captured request cannot be replayed: request timestamps must rise per recipient.
#[tokio::test]
async fn a_build_request_cannot_be_replayed() {
    let h = harness(Node::Healthy, 12).await;
    let request_timestamp = crate::redemption_build::now_unix_ms();
    let (status, body) = h.build(h.request_at(20_000_000, request_timestamp)).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);

    let (status, body) = h.build(h.request_at(20_000_000, request_timestamp)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.error.unwrap().contains("not greater"));
    let (status, _) = h
        .build(h.request_at(20_000_000, request_timestamp - 1))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body) = h
        .build(h.request_at(20_000_000, request_timestamp + 1))
        .await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
}

/// A caller's `tracker_box_id` never reaches the node unless it is a tracker box the tracker
/// knows; a known one is used.
#[tokio::test]
async fn an_unknown_tracker_box_id_is_ignored() {
    let h = harness(Node::Healthy, 12).await;
    let mut request = h.request(20_000_000);
    request.tracker_box_id = Some("../../wallet/status?x=".to_string());
    let (status, body) = h.build(request).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    let build = body.data.unwrap();
    assert_eq!(build.tracker_box_id, String::from(h.tracker_box.box_id()));
    let requests = h.node_requests();
    assert!(
        requests.iter().all(|r| !r.contains("wallet") && !r.contains("..")),
        "{requests:?}"
    );

    let mut request = h.request(20_000_000);
    request.tracker_box_id = Some(String::from(h.tracker_box.box_id()).to_uppercase());
    let (status, body) = h.build(request).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    assert_eq!(
        body.data.unwrap().tracker_box_id,
        String::from(h.tracker_box.box_id())
    );
}

/// A failing node request answers the client without the node's URL or body.
#[tokio::test]
async fn node_errors_reach_the_client_without_url_or_body() {
    let h = harness(Node::LeakyFailure, 12).await;
    let (status, body) = h.build(h.request(20_000_000)).await;
    assert_ne!(status, StatusCode::OK);
    let error = body.error.unwrap();
    assert!(!error.contains(LEAKY_BODY), "{error}");
    assert!(!error.contains("127.0.0.1"), "{error}");
    assert!(!error.contains("http"), "{error}");
}

/// A build that is never submitted (the canary's dry run, a lost response) does not block the
/// next build of the same note: builds only read tracker state, and the newer build replaces the
/// older pending entry, so only the newer one can be submitted. Each signed build of the note
/// still uses one unit of the pair's hourly budget.
#[tokio::test]
async fn a_build_that_is_never_submitted_does_not_block_the_next_one() {
    let h = harness(Node::Healthy, 2).await;
    let amount = 20_000_000;

    let (status, body) = h.build(h.request(amount)).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    let dry_run = body.data.unwrap();
    assert_eq!(h.state.pending_redemptions.len(), 1);

    // The real build, right after: the same redemption, valid on its own.
    let (status, body) = h.build(h.request(amount)).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
    let real = body.data.unwrap();
    assert_eq!(real.reserve_box_id, dry_run.reserve_box_id);
    assert_eq!(real.new_already_redeemed, dry_run.new_already_redeemed);
    assert!(real.is_first_redemption, "the dry run changed no tracker state");
    assert_eq!(real.recipient_output_value, amount - FEE);

    // Only the newest build is pending: the dry run is refused like an expired build.
    assert_eq!(h.state.pending_redemptions.len(), 1, "replaced, not added");
    let (dry_signed, _, _) = client_sign(&h, &dry_run);
    let dry_fp =
        crate::redemption_build::unsigned_tx_fingerprint(&dry_run.unsigned_tx).unwrap();
    let err = h
        .state
        .pending_redemptions
        .validate_and_consume(&dry_fp, &serde_json::to_value(&dry_signed).unwrap())
        .unwrap_err();
    assert_eq!(err.0, StatusCode::CONFLICT);

    let (real_signed, inputs, data) = client_sign(&h, &real);
    TransactionContext::new(real_signed.clone(), inputs, data)
        .unwrap()
        .validate(&crate::local_wallet::tests::fixture_state())
        .unwrap();
    let real_fp = crate::redemption_build::unsigned_tx_fingerprint(&real.unsigned_tx).unwrap();
    let entry = h
        .state
        .pending_redemptions
        .validate_and_consume(&real_fp, &serde_json::to_value(&real_signed).unwrap())
        .unwrap();
    assert_eq!(entry.redeemed_amount, amount);
    assert_eq!(entry.issuer_pubkey, hex::encode(h.issuer_pk));
    assert_eq!(entry.recipient_pubkey, hex::encode(h.recipient_pk));

    // Both builds used the pair's budget (2 per hour here).
    let (status, _) = h.build(h.request(amount)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

/// Round 5 (C8): while a redemption of the reserve waits for the chain (it is journaled), a
/// build of that reserve is refused with 409 naming it; one of another issuer or denomination
/// does not block. Once it is applied or dropped (no longer journaled), builds work again.
#[tokio::test]
async fn a_reserve_with_a_journaled_redemption_builds_nothing() {
    let h = harness(Node::Healthy, 12).await;
    let waiting = basis_store::persistence::JournaledRedemption {
        tx_id: "5e".repeat(32),
        reserve_box_id: String::from(h.reserve.box_id()),
        issuer_pubkey: hex::encode(h.issuer_pk),
        recipient_pubkey: hex::encode(h.recipient_pk),
        denomination: DenomKey::Erg.denomination_id(),
        redeemed_amount: 10_000_000,
        new_already_redeemed: 10_000_000,
        data_input_ids: vec![String::from(h.tracker_box.box_id())],
        submitted_at_ms: 1,
        ..Default::default()
    };
    let others = [
        basis_store::persistence::JournaledRedemption {
            tx_id: "6f".repeat(32),
            issuer_pubkey: hex::encode([0x02; 33]),
            ..waiting.clone()
        },
        basis_store::persistence::JournaledRedemption {
            tx_id: "7a".repeat(32),
            denomination: DenomKey::Token([0x7c; 32]).denomination_id(),
            ..waiting.clone()
        },
    ];
    for other in &others {
        h.state.tracker_storage.journal_redemption(other).unwrap();
    }
    let (status, body) = h.build(h.request(20_000_000)).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);

    h.state.tracker_storage.journal_redemption(&waiting).unwrap();
    let (status, body) = h.build(h.request(20_000_000)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let error = body.error.unwrap();
    assert!(error.contains(&waiting.tx_id), "{error}");
    assert!(error.contains("waiting for the chain"), "{error}");

    h.state
        .tracker_storage
        .remove_journaled_redemption(&waiting.tx_id)
        .unwrap();
    let (status, body) = h.build(h.request(20_000_000)).await;
    assert_eq!(status, StatusCode::OK, "{:?}", body.error);
}
