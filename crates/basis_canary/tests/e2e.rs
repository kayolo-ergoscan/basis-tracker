//! End to end: the canary against the tracker's own HTTP handlers, auth layers and redemption
//! builder, and a mock Ergo node on 127.0.0.1 that keeps a UTXO set, validates every submitted
//! transaction in full and applies it.
//!
//! The test plays the tracker's two background services: after a transaction is applied it
//! admits the reserve box (or its successor) to the tracker's reserve stores, as the scanner
//! does, and `commit` writes a tracker box holding the tracker's live digest and confirms the
//! notes, as the tracker box updater does once its commit is in a block.
//!
//! Keys are generated fresh for every run; nothing leaves 127.0.0.1.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use basis_canary::keys::{ApiKey, FileKey};
use basis_canary::note::fetch_note;
use basis_canary::redeem::{check_redemption, node_boxes, BuildResponse, Expectation};
use basis_canary::{tx, Cli, Context, Report};
use basis_server::config::{
    AppConfig, AuthConfig, AuthMode, ConfirmationConfig, ErgoConfig, RedemptionConfig,
    ServerConfig, TransactionConfig, WalletNodeConfig,
};
use basis_server::local_wallet;
use basis_server::tracker_box_updater::SharedTrackerState;
use basis_server::{AppState, TrackerCommand};
use clap::{CommandFactory, Parser};
use ergo_lib::chain::ergo_state_context::ErgoStateContext;
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::{Transaction, TxId};
use ergo_lib::ergotree_ir::chain::address::{Address, AddressEncoder, NetworkPrefix};
use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
use ergo_lib::ergotree_ir::chain::ergo_box::{BoxTokens, ErgoBox, NonMandatoryRegisters};
use ergo_lib::ergotree_ir::chain::token::{Token, TokenAmount};
use ergo_lib::ergotree_ir::ergo_tree::ErgoTree;
use ergo_lib::ergotree_ir::mir::constant::Constant;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use serde_json::{json, Value};
use tokio::sync::mpsc;

const LAST_HEADERS_JSON: &str = include_str!(
    "../../../scala/src/test/resources/mockwebserver/node_responses/response_LastHeaders.json"
);
/// Height of the newest fixture header.
const TIP: u32 = 123_414;
const ERG: u64 = 1_000_000_000;
const API_KEY: &str = "canary-test-write-key-5f1c9e04";
const ADMIN_KEY: &str = "canary-test-admin-key-0b7d42aa";

/// Fjall keyspaces race when several are opened at once in one process.
static STORAGE_LOCK: Mutex<()> = Mutex::new(());

// ----- mock node -----

/// One HTTP request as a server received it.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn new(method: &Method, uri: &Uri, headers: &HeaderMap, body: &[u8]) -> Self {
        Self {
            method: method.to_string(),
            target: uri.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).to_string(),
                    )
                })
                .collect(),
            body: String::from_utf8_lossy(body).to_string(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn raw(&self) -> String {
        let headers: Vec<String> = self
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        format!(
            "{} {}\n{}\n\n{}",
            self.method,
            self.target,
            headers.join("\n"),
            self.body
        )
    }
}

/// A node with a UTXO set. `POST /transactions` validates a transaction in full against the
/// fixture headers and applies it; `/wallet/transactions` is the tracker's broadcast node,
/// which refuses everything while `wallet_rejects` is set.
struct MockNode {
    utxo: Mutex<BTreeMap<String, ErgoBox>>,
    applied: Mutex<Vec<Transaction>>,
    seen: Mutex<Vec<Seen>>,
    wallet_rejects: AtomicBool,
    state: ErgoStateContext,
}

impl MockNode {
    fn add(&self, b: ErgoBox) {
        self.utxo
            .lock()
            .unwrap()
            .insert(String::from(b.box_id()), b);
    }

    fn applied(&self) -> Vec<Transaction> {
        self.applied.lock().unwrap().clone()
    }

    fn answer(&self, method: &str, path: &str, query: &str, body: &str) -> (u16, String) {
        let not_found = (
            404,
            json!({"error": 404, "reason": "not-found"}).to_string(),
        );
        match (method, path) {
            ("GET", "/blocks/lastHeaders/10") => (200, LAST_HEADERS_JSON.to_string()),
            ("POST", "/blockchain/box/unspent/byAddress") => {
                let address: String = serde_json::from_str(body).unwrap();
                let tree = tx::address_tree(&address).unwrap();
                let first_page = query.split('&').any(|kv| kv == "offset=0");
                let boxes: Vec<Value> = if first_page {
                    self.utxo
                        .lock()
                        .unwrap()
                        .values()
                        .filter(|b| b.ergo_tree == tree)
                        .map(box_json)
                        .collect()
                } else {
                    Vec::new()
                };
                (200, Value::Array(boxes).to_string())
            }
            ("POST", "/transactions") => self.submit(body),
            ("POST", "/wallet/transactions") => {
                if self.wallet_rejects.load(Ordering::SeqCst) {
                    (
                        503,
                        json!({"error": 503, "reason": "broadcast node unavailable"}).to_string(),
                    )
                } else {
                    self.submit(body)
                }
            }
            ("GET", p) => {
                if let Some(id) = p.strip_prefix("/utxo/byIdBinary/") {
                    match self.utxo.lock().unwrap().get(id) {
                        Some(b) => (
                            200,
                            json!({
                                "boxId": id,
                                "bytes": hex::encode(b.sigma_serialize_bytes().unwrap()),
                            })
                            .to_string(),
                        ),
                        None => not_found,
                    }
                } else if let Some(id) = p.strip_prefix("/utxo/byId/") {
                    match self.utxo.lock().unwrap().get(id) {
                        Some(b) => (200, box_json(b).to_string()),
                        None => not_found,
                    }
                } else {
                    not_found
                }
            }
            _ => not_found,
        }
    }

    fn submit(&self, body: &str) -> (u16, String) {
        let refuse = |reason: String| (400, json!({"error": 400, "reason": reason}).to_string());
        let signed: Transaction = match serde_json::from_str(body) {
            Ok(t) => t,
            Err(e) => return refuse(format!("not a transaction: {e}")),
        };
        let mut utxo = self.utxo.lock().unwrap();
        let find = |id: String| utxo.get(&id).cloned().ok_or(id);
        let inputs: Result<Vec<ErgoBox>, String> = signed
            .inputs
            .iter()
            .map(|i| find(String::from(i.box_id)))
            .collect();
        let data_inputs: Result<Vec<ErgoBox>, String> = signed
            .data_inputs
            .iter()
            .flat_map(|d| d.iter())
            .map(|d| find(String::from(d.box_id)))
            .collect();
        let (inputs, data_inputs) = match (inputs, data_inputs) {
            (Ok(i), Ok(d)) => (i, d),
            (Err(id), _) | (_, Err(id)) => return refuse(format!("box {id} is not unspent")),
        };
        if let Err(e) = tx::validate(&signed, &inputs, &data_inputs, &self.state) {
            return refuse(e);
        }
        for input in signed.inputs.iter() {
            utxo.remove(&String::from(input.box_id));
        }
        for output in signed.outputs.iter() {
            utxo.insert(String::from(output.box_id()), output.clone());
        }
        drop(utxo);
        let id = String::from(signed.id());
        self.applied.lock().unwrap().push(signed);
        (200, Value::String(id).to_string())
    }
}

async fn node_handler(
    State(node): State<Arc<MockNode>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    node.seen
        .lock()
        .unwrap()
        .push(Seen::new(&method, &uri, &headers, &body));
    let (status, payload) = node.answer(
        method.as_str(),
        uri.path(),
        uri.query().unwrap_or(""),
        &String::from_utf8_lossy(&body),
    );
    (
        StatusCode::from_u16(status).unwrap(),
        [(header::CONTENT_TYPE, "application/json")],
        payload,
    )
        .into_response()
}

/// The `IndexedErgoBox` JSON the node returns for `b`.
fn box_json(b: &ErgoBox) -> Value {
    let registers: serde_json::Map<String, Value> = tx::REGISTER_IDS
        .iter()
        .filter_map(|r| {
            let c = tx::register(b, *r)?;
            Some((
                format!("{r:?}"),
                Value::String(tx::constant_hex(&c).unwrap()),
            ))
        })
        .collect();
    json!({
        "boxId": String::from(b.box_id()),
        "value": b.value.as_u64(),
        "ergoTree": tx::tree_hex(&b.ergo_tree).unwrap(),
        "assets": tx::box_tokens(b)
            .into_iter()
            .map(|(t, a)| json!({ "tokenId": t, "amount": a }))
            .collect::<Vec<_>>(),
        "additionalRegisters": registers,
        "creationHeight": b.creation_height,
        "transactionId": String::from(b.transaction_id),
        "index": b.index,
    })
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

// ----- the tracker -----

/// Records every request the tracker receives, then passes it on.
async fn record(
    State(seen): State<Arc<Mutex<Vec<Seen>>>>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20)
        .await
        .unwrap_or_default();
    seen.lock()
        .unwrap()
        .push(Seen::new(&parts.method, &parts.uri, &parts.headers, &bytes));
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// The tracker thread of `basis_server`'s main, for the commands these flows use: the real
/// note store, real proofs, and the live digest kept in `shared`.
fn tracker_thread(mut rx: mpsc::Receiver<TrackerCommand>, shared: SharedTrackerState) {
    use basis_store::{RedemptionManager, TrackerStateManager};
    let tracker = TrackerStateManager::new_with_temp_storage();
    shared.set_avl_root_digest(tracker.get_state().avl_root_digest);
    let mut m = RedemptionManager::new(tracker);
    while let Some(cmd) = rx.blocking_recv() {
        match cmd {
            TrackerCommand::AddNote {
                issuer_pubkey,
                note,
                response_tx,
            } => {
                let result = m.tracker.add_note(&issuer_pubkey, &note);
                if result.is_ok() {
                    shared.set_avl_root_digest(m.tracker.get_state().avl_root_digest);
                }
                let _ = response_tx.send(result);
            }
            TrackerCommand::GetNotesByIssuer {
                issuer_pubkey,
                response_tx,
            } => {
                let _ = response_tx.send(m.tracker.get_issuer_notes(&issuer_pubkey));
            }
            TrackerCommand::GetNotesByRecipient {
                recipient_pubkey,
                response_tx,
            } => {
                let _ = response_tx.send(m.tracker.get_recipient_notes(&recipient_pubkey));
            }
            TrackerCommand::GetNotesByRecipientWithIssuer {
                recipient_pubkey,
                response_tx,
            } => {
                let _ =
                    response_tx.send(m.tracker.get_recipient_notes_with_issuer(&recipient_pubkey));
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
                response_tx,
            } => {
                let result = m.complete_redemption(
                    &issuer_pubkey,
                    &recipient_pubkey,
                    &denomination,
                    redeemed_amount,
                    new_already_redeemed,
                );
                if result.is_ok() {
                    shared.set_avl_root_digest(m.tracker.get_state().avl_root_digest);
                }
                let _ = response_tx.send(result);
            }
            TrackerCommand::GetNotes { response_tx } => {
                let _ = response_tx.send(m.tracker.get_all_notes_with_issuer());
            }
            TrackerCommand::GenerateProof {
                issuer_pubkey,
                recipient_pubkey,
                denomination,
                response_tx,
            } => {
                let _ = response_tx.send(m.tracker.generate_proof(
                    &issuer_pubkey,
                    &recipient_pubkey,
                    &denomination,
                ));
            }
            TrackerCommand::GetTrackerLookupProof {
                issuer_pubkey,
                recipient_pubkey,
                denomination,
                response_tx,
            } => {
                let _ = response_tx.send(m.tracker.generate_tracker_lookup_proof(
                    &issuer_pubkey,
                    &recipient_pubkey,
                    &denomination,
                ));
            }
            TrackerCommand::GetCommittedTrackerLookupProof {
                issuer_pubkey,
                recipient_pubkey,
                denomination,
                response_tx,
            } => {
                let _ = response_tx.send(m.tracker.generate_committed_tracker_lookup_proof(
                    &issuer_pubkey,
                    &recipient_pubkey,
                    &denomination,
                ));
            }
            TrackerCommand::GetReserveLookupProof {
                issuer_pubkey,
                recipient_pubkey,
                denomination,
                response_tx,
            } => {
                let _ = response_tx.send(m.tracker.generate_reserve_lookup_proof(
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
                let _ = response_tx.send(m.tracker.generate_reserve_insert_proof(
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
                let _ = response_tx.send(
                    m.tracker
                        .reserve_state_digest(&issuer_pubkey, &denomination),
                );
            }
            TrackerCommand::GetConfirmation {
                issuer_pubkey,
                recipient_pubkey,
                denomination,
                response_tx,
            } => {
                let _ = response_tx.send(Ok(m.tracker.get_confirmation(
                    &issuer_pubkey,
                    &recipient_pubkey,
                    &denomination,
                )));
            }
            TrackerCommand::GetAllConfirmations { response_tx } => {
                let _ = response_tx.send(m.tracker.all_confirmations());
            }
            TrackerCommand::MarkNotesPending {
                digest,
                tx_id,
                submitted_height,
                response_tx,
            } => {
                let _ = response_tx.send(m.tracker.mark_notes_pending(
                    digest,
                    &tx_id,
                    submitted_height,
                ));
            }
            TrackerCommand::ConfirmPendingNotes {
                digest,
                box_id,
                height,
                response_tx,
            } => {
                let _ = response_tx.send(m.tracker.confirm_pending_notes(digest, &box_id, height));
            }
            TrackerCommand::RevertPendingNotes { response_tx } => {
                let _ = response_tx.send(m.tracker.revert_pending_notes());
            }
            TrackerCommand::ReconcileWithConfirmedDigest {
                digest,
                box_id,
                height,
                response_tx,
            } => {
                let _ = response_tx.send(
                    m.tracker
                        .reconcile_with_confirmed_digest(&digest, &box_id, height),
                );
            }
            TrackerCommand::Shutdown => break,
            // Exchanges and the retired redemption flow: not used here. Dropping the command
            // drops its response sender, so a caller would see "tracker unavailable".
            _ => {}
        }
    }
}

/// Mainnet P2S address of the ERG reserve contract compiled into this build.
fn reserve_p2s() -> String {
    let address = Address::recreate_from_ergo_tree(&tx::reserve_tree().unwrap()).unwrap();
    AddressEncoder::new(NetworkPrefix::Mainnet).address_to_str(&address)
}

/// The tracker's routes the canary uses (and the Admin repair route), with the production auth
/// layers in production order, in `api_key` mode with a separate Admin key.
async fn start_tracker(
    node_url: &str,
    tracker: &Party,
    nft: &[u8; 32],
    data_dir: &Path,
) -> (String, AppState, Arc<Mutex<Vec<Seen>>>) {
    std::fs::create_dir_all(data_dir).unwrap();
    let config = AppConfig {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3048,
            data_dir: Some(data_dir.display().to_string()),
            database_url: Some("sqlite::memory:".to_string()),
            tls_cert_path: None,
            tls_key_path: None,
            auth: AuthConfig {
                mode: AuthMode::ApiKey,
                api_key: Some(API_KEY.to_string()),
                admin_api_key: Some(ADMIN_KEY.to_string()),
                ..AuthConfig::default()
            },
            reserve_creation_max_erg_nano: 10 * ERG,
            reserve_creation_max_token_amount: 1_000_000_000,
            redemption_build_max_per_pair_per_hour: 60,
            redemption_build_max_per_issuer_per_hour: 20,
            redemption_build_max_per_hour: 30,
        },
        ergo: ErgoConfig {
            scanner: basis_store::ergo_scanner::NodeConfig {
                node_url: node_url.to_string(),
                ..Default::default()
            },
            wallet: WalletNodeConfig {
                node_url: format!("{node_url}/wallet"),
                api_key: None,
            },
            basis_reserve_contract_p2s: reserve_p2s(),
            basis_token_reserve_contract_p2s: "test_token".to_string(),
            tracker_nft_id: Some(hex::encode(nft)),
            reserve_tokens: Default::default(),
            tracker_public_key: Some(hex::encode(tracker.pk)),
            tracker_secret_key: Some(hex::encode(tracker.secret)),
        },
        transaction: TransactionConfig {
            fee: 1_000_000,
            change_address: None,
            heartbeat_blocks: 720,
            commit_reserve_nano: 100_000_000,
        },
        acceptance: basis_server::acceptance::config::AcceptanceConfig::empty(),
        redemption: RedemptionConfig {
            enforce_acceptance_policy: false,
        },
        confirmation: ConfirmationConfig::default(),
    };

    let (tx, rx) = mpsc::channel(100);
    let shared = SharedTrackerState::new_with_tracker_key(tracker.pk);
    let thread_shared = shared.clone();
    tokio::task::spawn_blocking(move || tracker_thread(rx, thread_shared));

    let (ergo_scanner, tracker_storage, policy_storage) = {
        let _guard = STORAGE_LOCK.lock().unwrap();
        let scanner = basis_store::ergo_scanner::ServerState::new(
            config.ergo.scanner.clone(),
            data_dir.join("scanner"),
        )
        .unwrap();
        let tracker_storage =
            basis_store::persistence::TrackerStorage::open(data_dir.join("tracker")).unwrap();
        let policy_storage =
            basis_store::persistence::AcceptancePolicyStorage::open(data_dir.join("policies"))
                .unwrap();
        (scanner, tracker_storage, policy_storage)
    };
    let auth_state = Arc::new(basis_server::auth_middleware::AuthState::new(
        config.server.auth.clone(),
    ));
    let state = AppState {
        tx,
        event_store: Arc::new(basis_server::store::EventStore::new().await.unwrap()),
        ergo_scanner: Arc::new(tokio::sync::Mutex::new(ergo_scanner)),
        reserve_tracker: Arc::new(tokio::sync::Mutex::new(basis_store::ReserveTracker::new())),
        config: Arc::new(config),
        shared_tracker_state: Arc::new(tokio::sync::Mutex::new(shared)),
        tracker_storage,
        acceptance_predicate: None,
        policy_storage,
        pending_redemptions: Arc::new(
            basis_server::redemption_build::PendingRedemptionRegistry::new(),
        ),
        redemption_build_rate: Arc::new(basis_server::redemption_build::BuildRateLimiter::new()),
    };

    use basis_server::api::*;
    use basis_server::redemption_build::{build_redemption, submit_redemption};
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let app = Router::new()
        .route("/notes", post(create_note))
        .route(
            "/notes/issuer/{issuer_pubkey}/recipient/{recipient_pubkey}",
            get(get_note_by_issuer_and_recipient),
        )
        .route("/notes/issuer/{pubkey}", get(get_notes_by_issuer))
        .route("/notes/recipient/{pubkey}", get(get_notes_by_recipient))
        .route("/key-status/{pubkey}", get(get_key_status))
        .route("/tracker/state", get(get_tracker_state))
        .route(
            "/reserves/issuer/{pubkey}",
            get(basis_server::reserve_api::get_reserves_by_issuer),
        )
        .route("/reserves/create", post(create_reserve_payload))
        .route("/tracker/signature", post(request_tracker_signature))
        .route("/redemption/build", post(build_redemption))
        .route("/redemption/submit", post(submit_redemption))
        .route("/redeem/complete", post(complete_redemption))
        .with_state(state.clone())
        .layer(from_fn(
            basis_server::authorization::authorization_middleware,
        ))
        .layer(from_fn_with_state(
            auth_state,
            basis_server::auth_middleware::auth_middleware,
        ))
        .layer(from_fn_with_state(seen.clone(), record));
    (serve(app).await, state, seen)
}

// ----- the world -----

struct Party {
    secret: [u8; 32],
    pk: [u8; 33],
    file: PathBuf,
}

impl Party {
    fn new(dir: &Path, name: &str) -> Self {
        let (secret, pk) = basis_store::schnorr::generate_keypair();
        let file = dir.join(format!("{name}.key"));
        std::fs::write(&file, format!("{}\n", hex::encode(secret))).unwrap();
        Self { secret, pk, file }
    }

    fn file(&self) -> String {
        self.file.display().to_string()
    }

    fn tree(&self) -> ErgoTree {
        tx::p2pk_tree(&self.pk).unwrap()
    }
}

fn utxo_box(
    tree: ErgoTree,
    value: u64,
    tokens: &[([u8; 32], u64)],
    registers: Vec<Constant>,
    creation_height: u32,
    index: u16,
) -> ErgoBox {
    let tokens = (!tokens.is_empty()).then(|| {
        BoxTokens::from_vec(
            tokens
                .iter()
                .map(|(id, amount)| Token {
                    token_id: tx::token_id(id).unwrap(),
                    amount: TokenAmount::try_from(*amount).unwrap(),
                })
                .collect(),
        )
        .unwrap()
    });
    ErgoBox::new(
        BoxValue::try_from(value).unwrap(),
        tree,
        tokens,
        NonMandatoryRegisters::try_from(registers).unwrap(),
        creation_height,
        TxId::zero(),
        index,
    )
    .unwrap()
}

fn fixture_state() -> ErgoStateContext {
    local_wallet::state_context_from_headers(serde_json::from_str(LAST_HEADERS_JSON).unwrap())
        .unwrap()
}

/// A, the issuer and reserve owner (1.1 ERG); B, the recipient (no ERG); T, the tracker (one
/// 1 ERG fee box and the tracker box).
struct World {
    _dir: tempfile::TempDir,
    a: Party,
    b: Party,
    t: Party,
    nft: [u8; 32],
    api_key_file: PathBuf,
    admin_key_file: PathBuf,
    node: Arc<MockNode>,
    node_url: String,
    tracker_url: String,
    tracker_seen: Arc<Mutex<Vec<Seen>>>,
    state: AppState,
    tracker_box_id: Mutex<Option<String>>,
    reserve_box_id: Mutex<Option<String>>,
    next_index: AtomicU16,
    /// Everything the canary printed, and its errors.
    outputs: Mutex<Vec<String>>,
}

impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, t) = (
            Party::new(dir.path(), "a"),
            Party::new(dir.path(), "b"),
            Party::new(dir.path(), "t"),
        );
        let api_key_file = dir.path().join("api.key");
        std::fs::write(&api_key_file, format!("{API_KEY}\n")).unwrap();
        let admin_key_file = dir.path().join("admin.key");
        std::fs::write(&admin_key_file, ADMIN_KEY).unwrap();
        let mut nft = [0u8; 32];
        nft.copy_from_slice(&t.pk[1..]);

        let node = Arc::new(MockNode {
            utxo: Mutex::default(),
            applied: Mutex::default(),
            seen: Mutex::default(),
            wallet_rejects: AtomicBool::new(false),
            state: fixture_state(),
        });
        node.add(utxo_box(a.tree(), 1_100_000_000, &[], vec![], 123_000, 1));
        node.add(utxo_box(t.tree(), ERG, &[], vec![], 123_000, 2));
        let node_url = serve(
            Router::new()
                .fallback(node_handler)
                .with_state(node.clone()),
        )
        .await;
        let (tracker_url, state, tracker_seen) =
            start_tracker(&node_url, &t, &nft, &dir.path().join("tracker")).await;

        let world = Self {
            _dir: dir,
            a,
            b,
            t,
            nft,
            api_key_file,
            admin_key_file,
            node,
            node_url,
            tracker_url,
            tracker_seen,
            state,
            tracker_box_id: Mutex::default(),
            reserve_box_id: Mutex::default(),
            next_index: AtomicU16::new(10),
            outputs: Mutex::default(),
        };
        // The tracker box as the init transaction left it: the empty tree.
        world.commit().await;
        world
    }

    async fn ask<T>(
        &self,
        command: impl FnOnce(tokio::sync::oneshot::Sender<T>) -> TrackerCommand,
    ) -> T {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.state.tx.send(command(tx)).await.unwrap();
        rx.await.unwrap()
    }

    /// What the tracker box updater does when its commit is in a block: a new tracker box holds
    /// the live digest (R4 tracker key, R5 the tree, R6 the NFT id), the notes it covers are
    /// confirmed, and the shared state points at the box.
    async fn commit(&self) {
        let digest = self
            .state
            .shared_tracker_state
            .lock()
            .await
            .get_avl_root_digest();
        let tree = basis_offchain::ergo_tx::build_savl_tree_from_digest(&hex::encode(digest));
        let tracker_box = utxo_box(
            self.t.tree(),
            10_000_000,
            &[(self.nft, 1)],
            vec![
                Constant::from(tx::point(&self.t.pk).unwrap()),
                Constant::sigma_parse_bytes(&tree).unwrap(),
                tx::coll_bytes(&self.nft),
            ],
            TIP,
            self.next_index.fetch_add(1, Ordering::SeqCst),
        );
        let box_id = String::from(tracker_box.box_id());
        if let Some(old) = self.tracker_box_id.lock().unwrap().replace(box_id.clone()) {
            self.node.utxo.lock().unwrap().remove(&old);
        }
        self.node.add(tracker_box);
        let height = u64::from(TIP);
        self.ask(|response_tx| TrackerCommand::MarkNotesPending {
            digest,
            tx_id: "11".repeat(32),
            submitted_height: height,
            response_tx,
        })
        .await
        .unwrap();
        self.ask(|response_tx| TrackerCommand::ConfirmPendingNotes {
            digest,
            box_id: box_id.clone(),
            height,
            response_tx,
        })
        .await
        .unwrap();
        let shared = self.state.shared_tracker_state.lock().await;
        shared.set_tracker_box_id(box_id.clone());
        shared.set_confirmed(digest, box_id, height);
    }

    /// What the scanner does when a reserve box of A is in a block: it replaces the reserve
    /// it succeeds in both reserve stores.
    async fn admit_reserve(&self, reserve: &ErgoBox) {
        let id = String::from(reserve.box_id());
        let mut info = basis_store::ExtendedReserveInfo::new(
            &hex::decode(&id).unwrap(),
            &self.a.pk,
            *reserve.value.as_u64(),
            Some(&self.nft),
            u64::from(reserve.creation_height),
            0,
            None,
        );
        info.set_contract_address(reserve_p2s());
        let previous = self.reserve_box_id.lock().unwrap().replace(id);
        {
            let scanner = self.state.ergo_scanner.lock().await;
            if let Some(old) = &previous {
                let _ = scanner.reserve_storage().remove_reserve(old);
            }
            scanner.reserve_storage().store_reserve(&info).unwrap();
        }
        let tracker = self.state.reserve_tracker.lock().await;
        if let Some(old) = &previous {
            let _ = tracker.remove_reserve(old);
        }
        tracker.update_reserve(info).unwrap();
    }

    fn context(&self) -> Context {
        Context::new(
            &self.tracker_url,
            &self.node_url,
            Some(&self.api_key_file),
            &hex::encode(self.nft),
        )
        .unwrap()
    }

    /// Run the canary as the binary would, with `--tracker-nft-id nft`.
    async fn run_for(&self, nft: &str, args: &[&str]) -> Result<String, String> {
        let api_key_file = self.api_key_file.display().to_string();
        let mut argv = vec![
            "basis_canary",
            "--tracker-url",
            &self.tracker_url,
            "--node-url",
            &self.node_url,
            "--api-key-file",
            &api_key_file,
            "--tracker-nft-id",
            nft,
        ];
        argv.extend_from_slice(args);
        for secret in self.secrets() {
            assert!(
                !argv.iter().any(|a| a.contains(&secret)),
                "a secret in argv"
            );
        }
        let cli = Cli::try_parse_from(&argv).map_err(|e| e.to_string())?;
        let mut report = Report::new(false);
        let result = basis_canary::run(cli, &mut report).await;
        let mut output = report.text().to_string();
        if let Err(e) = &result {
            output.push_str(&format!("error: {e}\n"));
        }
        self.outputs.lock().unwrap().push(output);
        result.map(|()| report.text().to_string())
    }

    /// The canary's output; panics with it when the command fails.
    async fn ok(&self, args: &[&str]) -> String {
        match self.run_for(&hex::encode(self.nft), args).await {
            Ok(out) => out,
            Err(e) => panic!(
                "{args:?} failed: {e}\n--- output ---\n{}",
                self.last_output()
            ),
        }
    }

    /// The canary's error; panics when the command succeeds.
    async fn err(&self, args: &[&str]) -> String {
        match self.run_for(&hex::encode(self.nft), args).await {
            Ok(out) => panic!("{args:?} succeeded:\n{out}"),
            Err(e) => e,
        }
    }

    fn last_output(&self) -> String {
        self.outputs
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }

    fn last_applied(&self) -> Transaction {
        self.node.applied().last().cloned().unwrap()
    }

    /// Requests the tracker received for `path`.
    fn tracker_requests(&self, path: &str) -> usize {
        self.tracker_seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.target.split('?').next() == Some(path))
            .count()
    }

    /// Every secret, in both hex cases, and both API keys.
    fn secrets(&self) -> Vec<String> {
        let mut all: Vec<String> = [self.a.secret, self.b.secret, self.t.secret]
            .iter()
            .flat_map(|s| [hex::encode(s), hex::encode_upper(s)])
            .collect();
        all.extend([API_KEY.to_string(), ADMIN_KEY.to_string()]);
        all
    }

    /// The secrets went nowhere: no secret key and no API key reached the node, nothing the
    /// canary printed holds one, and the tracker saw API keys only as the `X-API-Key` header
    /// (the Admin key only on the repair this test sends itself).
    fn assert_no_secret_leaks(&self) {
        let secrets = self.secrets();
        let public_paths = [
            "/blocks/lastHeaders/10",
            "/blockchain/box/unspent/byAddress",
            "/utxo/byId",
            "/transactions",
            "/wallet/transactions",
        ];
        let node_seen = self.node.seen.lock().unwrap();
        assert!(!node_seen.is_empty());
        for s in node_seen.iter() {
            assert!(
                public_paths.iter().any(|p| s.target.starts_with(p)),
                "unexpected node endpoint {} {}",
                s.method,
                s.target
            );
            for secret in &secrets {
                assert!(
                    !s.raw().contains(secret.as_str()),
                    "a secret reached the node"
                );
            }
            for name in ["x-api-key", "api_key", "authorization"] {
                assert!(s.header(name).is_none(), "{name} header sent to the node");
            }
        }
        let tracker_seen = self.tracker_seen.lock().unwrap();
        let mut admin_requests = 0;
        for s in tracker_seen.iter() {
            for secret in &secrets[..6] {
                assert!(
                    !s.raw().contains(secret.as_str()),
                    "a secret key reached the tracker"
                );
            }
            for key in [API_KEY, ADMIN_KEY] {
                assert!(!s.target.contains(key) && !s.body.contains(key));
            }
            match s.header("x-api-key") {
                Some(API_KEY) => {}
                Some(ADMIN_KEY) => {
                    assert_eq!(s.target, "/redeem/complete");
                    admin_requests += 1;
                }
                other => panic!("tracker request {} with X-API-Key {other:?}", s.target),
            }
        }
        assert_eq!(admin_requests, 1);
        for output in self.outputs.lock().unwrap().iter() {
            for secret in &secrets {
                assert!(!output.contains(secret.as_str()), "a secret in the output");
            }
        }
    }
}

/// Context-extension keys of input 0 in the order the summary prints them.
fn extension_order(output: &str) -> Vec<u8> {
    output
        .lines()
        .skip_while(|l| !l.starts_with("context extension of input 0"))
        .skip(1)
        .take_while(|l| l.trim_start().starts_with('#'))
        .map(|l| {
            l.trim_start()[1..]
                .split(' ')
                .next()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect()
}

fn registers_hex(b: &ErgoBox) -> Vec<(String, String)> {
    tx::REGISTER_IDS
        .iter()
        .filter_map(|r| {
            Some((
                format!("{r:?}"),
                tx::constant_hex(&tx::register(b, *r)?).unwrap(),
            ))
        })
        .collect()
}

fn output(tx: &Transaction, index: usize) -> ErgoBox {
    tx.outputs.as_vec()[index].clone()
}

// ----- tests -----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_canary_runs_the_whole_flow_against_the_tracker() {
    let w = World::new().await;
    let (a_file, b_file) = (w.a.file(), w.b.file());
    let (a_pk, b_pk) = (hex::encode(w.a.pk), hex::encode(w.b.pk));
    let nft = hex::encode(w.nft);
    let empty_tree = basis_store::ergo_scanner::empty_reserve_tree_register();

    // key-info: the public key and address, no network.
    let out = w.ok(&["key-info", "--secret-file", &a_file]).await;
    assert!(out.contains(&format!("public key: {a_pk}")), "{out}");
    assert!(out.contains(&local_wallet::p2pk_address(&w.a.pk).unwrap()));
    assert!(w.node.seen.lock().unwrap().is_empty());
    assert_eq!(w.tracker_seen.lock().unwrap().len(), 0);

    // status before anything: every read answers.
    let out = w.ok(&["status", "--pubkey", &a_pk]).await;
    assert_eq!(out.matches(": HTTP ").count(), 5, "{out}");

    // A reserve bound to another tracker is refused before anything is signed.
    let other = hex::encode([0x77u8; 32]);
    let create_dry: [&str; 6] = [
        "reserve-create",
        "--secret-file",
        &a_file,
        "--erg-nano",
        "1000000000",
        "--dry-run",
    ];
    let e = w.run_for(&other, &create_dry).await.unwrap_err();
    assert!(
        e.contains("refusing to create a reserve bound to another tracker"),
        "{e}"
    );

    // reserve-create --dry-run: the transaction and the exact registers, nothing submitted.
    let out = w.ok(&create_dry).await;
    for expected in [
        format!("R4 = 07{a_pk}"),
        format!("R5 = {empty_tree}"),
        format!("R6 = 0e20{nft}"),
        "R7 = 0500".to_string(),
        "warning: payload R7 is 05000000000000000000".to_string(),
        "checks before signing: OK".to_string(),
        "unsigned transaction (node JSON):".to_string(),
        "signed locally with the owner key and validated in full".to_string(),
        "dry run: nothing submitted".to_string(),
    ] {
        assert!(out.contains(&expected), "missing {expected:?} in\n{out}");
    }
    assert!(w.node.applied().is_empty());

    // reserve-create: signed with A's key, valid, applied.
    let out = w
        .ok(&[
            "reserve-create",
            "--secret-file",
            &a_file,
            "--erg-nano",
            "1000000000",
        ])
        .await;
    let create = w.last_applied();
    assert_eq!(w.node.applied().len(), 1);
    assert!(out.contains(&format!(
        "submitted transaction {}",
        String::from(create.id())
    )));
    let reserve = output(&create, 0);
    let reserve_nft = String::from(create.inputs.as_vec()[0].box_id);
    assert_eq!(reserve.ergo_tree, tx::reserve_tree().unwrap());
    assert_eq!(*reserve.value.as_u64(), ERG);
    assert_eq!(tx::box_tokens(&reserve), vec![(reserve_nft, 1)]);
    assert_eq!(
        registers_hex(&reserve),
        vec![
            ("R4".to_string(), format!("07{a_pk}")),
            ("R5".to_string(), empty_tree.clone()),
            ("R6".to_string(), format!("0e20{nft}")),
            ("R7".to_string(), "0500".to_string()),
        ]
    );
    let fee = output(&create, 1);
    let change = output(&create, 2);
    assert_eq!(fee.ergo_tree, tx::fee_tree().unwrap());
    assert_eq!(*fee.value.as_u64(), 1_000_000);
    assert_eq!(
        (change.ergo_tree.clone(), *change.value.as_u64()),
        (w.a.tree(), 99_000_000)
    );
    assert_eq!(create.outputs.len(), 3);
    w.admit_reserve(&reserve).await;

    // note: A owes B 0.3 ERG in total.
    let out = w
        .ok(&[
            "note",
            "--secret-file",
            &a_file,
            "--recipient-pubkey",
            &b_pk,
            "--total",
            "300000000",
        ])
        .await;
    assert!(out.contains("HTTP 201"), "{out}");
    assert!(out.contains("tracker co-signature: none"), "{out}");
    // A note states the whole debt so far: a lower total is refused before it is signed.
    let e = w
        .err(&[
            "note",
            "--secret-file",
            &a_file,
            "--recipient-pubkey",
            &b_pk,
            "--total",
            "200000000",
            "--dry-run",
        ])
        .await;
    assert!(
        e.contains("below the current cumulative debt 300000000"),
        "{e}"
    );

    // Not committed on chain yet: refused before any build.
    let redeem = |amount: &'static str, dry_run: bool| {
        let mut args = vec![
            "redeem".to_string(),
            "--secret-file".to_string(),
            b_file.clone(),
            "--issuer-pubkey".to_string(),
            a_pk.clone(),
            "--amount".to_string(),
            amount.to_string(),
        ];
        if dry_run {
            args.push("--dry-run".to_string());
        }
        args
    };
    let args = redeem("100000000", false);
    let e = w
        .err(&args.iter().map(String::as_str).collect::<Vec<_>>())
        .await;
    assert!(e.contains("is not committed on chain yet"), "{e}");
    assert_eq!(w.tracker_requests("/redemption/build"), 0);

    w.commit().await;

    // redeem --dry-run: built by the tracker, proved and validated locally, nothing submitted.
    let args = redeem("100000000", true);
    let out = w
        .ok(&args.iter().map(String::as_str).collect::<Vec<_>>())
        .await;
    for expected in [
        "first redemption: true",
        "checks before signing: OK",
        "unsigned transaction (exactly as the tracker built it):",
        "proved the reserve input with the recipient key and validated the transaction in full",
        "payout once submitted: output 1",
        "dry run: nothing submitted",
    ] {
        assert!(out.contains(expected), "missing {expected:?} in\n{out}");
    }
    assert_eq!(extension_order(&out), vec![0, 5, 1, 6, 2, 3, 8, 4]);
    assert_eq!(w.node.applied().len(), 1);
    assert_eq!(w.tracker_requests("/redemption/submit"), 0);

    // The checks refuse a build that is not what was asked for.
    tampered_builds_are_refused(&w).await;

    // redeem: B gets 0.1 ERG; the tracker paid the fee and submitted it.
    let args = redeem("100000000", false);
    let out = w
        .ok(&args.iter().map(String::as_str).collect::<Vec<_>>())
        .await;
    assert!(
        out.contains("submitted through the tracker (POST /redemption/submit)"),
        "{out}"
    );
    let first = w.last_applied();
    assert_eq!(w.node.applied().len(), 2);
    let payout = output(&first, 1);
    assert_eq!(
        (payout.ergo_tree.clone(), *payout.value.as_u64()),
        (w.b.tree(), 100_000_000)
    );
    assert!(payout.tokens.is_none());
    assert!(out.contains(&format!(
        "payout: output 1, box {}",
        String::from(payout.box_id())
    )));
    assert_eq!(*output(&first, 0).value.as_u64(), 900_000_000);
    // The fee and the change are the tracker's.
    assert_eq!(output(&first, 2).ergo_tree, tx::fee_tree().unwrap());
    assert_eq!(output(&first, 3).ergo_tree, w.t.tree());
    assert_eq!(first.outputs.len(), 4);
    let note = fetch_note(&w.context(), &w.a.pk, &w.b.pk)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (note.amount_collected, note.amount_redeemed),
        (300_000_000, 100_000_000)
    );
    w.admit_reserve(&output(&first, 0)).await;

    // A second note and a second redemption for the same pair: the reserve tree has the note
    // now, so the extension carries #7.
    w.ok(&[
        "note",
        "--secret-file",
        &a_file,
        "--recipient-pubkey",
        &b_pk,
        "--total",
        "500000000",
    ])
    .await;
    let args = redeem("250000000", false);
    let e = w
        .err(&args.iter().map(String::as_str).collect::<Vec<_>>())
        .await;
    assert!(e.contains("is not committed on chain yet"), "{e}");
    w.commit().await;
    let out = w
        .ok(&args.iter().map(String::as_str).collect::<Vec<_>>())
        .await;
    assert!(out.contains("first redemption: false"), "{out}");
    assert!(out.contains("submitted through the tracker"), "{out}");
    let all_keys: Vec<u8> = (0..=8).collect();
    assert_eq!(
        extension_order(&out),
        basis_offchain::ergo_tx::scala_context_extension_order(&all_keys)
    );
    let second = w.last_applied();
    assert_eq!(*output(&second, 0).value.as_u64(), 650_000_000);
    assert_eq!(
        (
            output(&second, 1).ergo_tree,
            *output(&second, 1).value.as_u64()
        ),
        (w.b.tree(), 250_000_000)
    );
    let note = fetch_note(&w.context(), &w.a.pk, &w.b.pk)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (note.amount_collected, note.amount_redeemed),
        (500_000_000, 350_000_000)
    );
    w.admit_reserve(&output(&second, 0)).await;

    // More than is redeemable is refused before any build.
    let builds = w.tracker_requests("/redemption/build");
    let args = redeem("150000001", true);
    let e = w
        .err(&args.iter().map(String::as_str).collect::<Vec<_>>())
        .await;
    assert!(e.contains("above what is redeemable now: 150000000"), "{e}");
    assert_eq!(w.tracker_requests("/redemption/build"), builds);

    // The tracker's broadcast node refuses: the canary submits through its own node and says
    // that the tracker has not recorded the redemption.
    w.node.wallet_rejects.store(true, Ordering::SeqCst);
    let args = redeem("100000000", false);
    let out = w
        .ok(&args.iter().map(String::as_str).collect::<Vec<_>>())
        .await;
    w.node.wallet_rejects.store(false, Ordering::SeqCst);
    for expected in [
        "the tracker did not submit it: POST /redemption/submit: HTTP 500",
        "submitted through the node (POST /transactions)",
        "warning: the tracker has not recorded this redemption",
    ] {
        assert!(out.contains(expected), "missing {expected:?} in\n{out}");
    }
    let third = w.last_applied();
    assert_eq!(w.node.applied().len(), 4);
    assert_eq!(*output(&third, 0).value.as_u64(), 550_000_000);
    w.admit_reserve(&output(&third, 0)).await;
    let note = fetch_note(&w.context(), &w.a.pk, &w.b.pk)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(note.amount_redeemed, 350_000_000);

    // Until it is recorded the tracker's reserve tree is behind the chain, and it builds
    // nothing from this reserve.
    let args = redeem("10000000", true);
    let e = w
        .err(&args.iter().map(String::as_str).collect::<Vec<_>>())
        .await;
    assert!(e.contains("a reserve tree matching the tracker"), "{e}");

    // The repair the canary printed, sent with the Admin key, records it.
    let repair: Value = out
        .lines()
        .skip_while(|l| !l.ends_with("and the body:"))
        .nth(1)
        .map(|l| serde_json::from_str(l).unwrap())
        .unwrap();
    assert_eq!(repair["redemption_id"], json!(String::from(third.id())));
    assert_eq!(repair["new_already_redeemed"], json!(450_000_000u64));
    let admin = basis_canary::TrackerClient::new(
        &w.tracker_url,
        Some(ApiKey::read(&w.admin_key_file).unwrap()),
    )
    .unwrap();
    let response = admin.post("/redeem/complete", &repair).await.unwrap();
    assert_eq!(response.status, 200, "{}", response.body);
    let out = w
        .ok(&args.iter().map(String::as_str).collect::<Vec<_>>())
        .await;
    assert!(out.contains("dry run: nothing submitted"), "{out}");
    let note = fetch_note(&w.context(), &w.a.pk, &w.b.pk)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(note.amount_redeemed, 450_000_000);

    // status after the flow.
    let out = w.ok(&["status", "--pubkey", &a_pk]).await;
    assert!(out.contains("\"amount_redeemed\": 450000000"), "{out}");

    w.assert_no_secret_leaks();

    // `cargo test -- --nocapture` shows what each command printed.
    for output in w.outputs.lock().unwrap().iter() {
        println!("{output}----");
    }
}

/// A real build passes the checks run before signing; each tampered copy is refused for the
/// reason that matters.
async fn tampered_builds_are_refused(w: &World) {
    let context = w.context();
    let note = fetch_note(&context, &w.a.pk, &w.b.pk)
        .await
        .unwrap()
        .unwrap();
    let response = context
        .tracker
        .post(
            "/redemption/build",
            &json!({
                "issuer_pubkey": hex::encode(w.a.pk),
                "recipient_pubkey": hex::encode(w.b.pk),
                "amount": 100_000_000u64,
                "timestamp": note.timestamp,
                "issuer_signature": note.signature,
                "emergency": false,
                "denomination": "erg",
            }),
        )
        .await
        .unwrap();
    let build: BuildResponse =
        serde_json::from_value(response.data("POST /redemption/build", 200).unwrap()).unwrap();
    let unsigned: UnsignedTransaction = serde_json::from_value(build.unsigned_tx.clone()).unwrap();
    let partial: Transaction = serde_json::from_value(build.partial_tx.clone()).unwrap();
    let (inputs, data_inputs) = node_boxes(&context.node, &unsigned, &build).await.unwrap();
    let expect = Expectation {
        issuer: w.a.pk,
        recipient: w.b.pk,
        amount: 100_000_000,
        total_debt: 300_000_000,
        timestamp: note.timestamp,
        issuer_signature: hex::decode(&note.signature).unwrap().try_into().unwrap(),
        tracker_nft: w.nft,
        tracker_pubkey: w.t.pk,
    };
    assert_eq!(
        check_redemption(&unsigned, &partial, &inputs, &data_inputs, &build, &expect),
        Ok(1)
    );

    let check = |edit: &dyn Fn(&mut Value), expect: &Expectation| {
        let mut unsigned_json = build.unsigned_tx.clone();
        edit(&mut unsigned_json);
        let unsigned: UnsignedTransaction = serde_json::from_value(unsigned_json.clone()).unwrap();
        let tampered = BuildResponse {
            unsigned_tx: unsigned_json,
            ..build.clone()
        };
        check_redemption(
            &unsigned,
            &partial,
            &inputs,
            &data_inputs,
            &tampered,
            expect,
        )
        .unwrap_err()
    };
    let ascending = |v: &mut Value| {
        let extension = v["inputs"][0]["extension"].as_object().unwrap().clone();
        let mut keys: Vec<String> = extension.keys().cloned().collect();
        keys.sort_by_key(|k| k.parse::<u8>().unwrap());
        v["inputs"][0]["extension"] = Value::Object(
            keys.into_iter()
                .map(|k| (k.clone(), extension[&k].clone()))
                .collect(),
        );
    };
    let e = check(&ascending, &expect);
    assert!(e.contains("not Scala's"), "{e}");

    let issuer_tree = tx::tree_hex(&w.a.tree()).unwrap();
    let to_issuer = |v: &mut Value| v["outputs"][1]["ergoTree"] = json!(issuer_tree);
    let e = check(&to_issuer, &expect);
    assert!(e.contains("output 1 goes to an unexpected script"), "{e}");

    let not_the_tracker = |v: &mut Value| {
        v["inputs"][0]["extension"]["6"] = v["inputs"][0]["extension"]["2"].clone();
    };
    let e = check(&not_the_tracker, &expect);
    assert!(
        e.contains("context var #6 is not the tracker's signature"),
        "{e}"
    );

    let unchanged = |_: &mut Value| {};
    let less = Expectation {
        amount: 90_000_000,
        ..expect.clone()
    };
    let e = check(&unchanged, &less);
    assert!(
        e.contains("does not keep the reserve minus 90000000"),
        "{e}"
    );

    let stale = Expectation {
        total_debt: 250_000_000,
        ..expect.clone()
    };
    let e = check(&unchanged, &stale);
    assert!(e.contains("the note's committed total is 250000000"), "{e}");

    let other_tracker = Expectation {
        tracker_pubkey: w.a.pk,
        ..expect.clone()
    };
    let e = check(&unchanged, &other_tracker);
    assert!(e.contains("is not the key"), "{e}");
}

#[test]
fn secrets_come_from_files_only() {
    // Every option naming a secret takes a file.
    let command = Cli::command();
    let mut checked = 0;
    for arg in command
        .get_arguments()
        .chain(command.get_subcommands().flat_map(|s| s.get_arguments()))
    {
        let id = arg.get_id().as_str();
        if id.contains("secret") || id.contains("api_key") {
            assert!(id.ends_with("_file"), "option {id} takes a secret value");
            checked += 1;
        }
    }
    assert!(checked >= 4);

    // The binary reads the key from the file and prints only its public part.
    let dir = tempfile::tempdir().unwrap();
    let (secret, pk) = basis_store::schnorr::generate_keypair();
    let file = dir.path().join("key");
    std::fs::write(&file, format!("{}\n", hex::encode(secret))).unwrap();
    let run = |file: &Path| {
        Process::new(env!("CARGO_BIN_EXE_basis_canary"))
            .args([
                "--node-url",
                "http://127.0.0.1:9",
                "--tracker-url",
                "http://127.0.0.1:9",
            ])
            .arg("key-info")
            .arg("--secret-file")
            .arg(file)
            .output()
            .unwrap()
    };
    let out = run(&file);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains(&format!("public key: {}", hex::encode(pk))),
        "{stdout}"
    );
    assert!(stdout.contains(&local_wallet::p2pk_address(&pk).unwrap()));
    assert!(!stdout.contains(&hex::encode(secret)));

    // A file that is not a key: the error names the file and what is wrong, never the content.
    let wrong = dir.path().join("wrong");
    let content = format!("{}zz", &hex::encode(secret)[..62]);
    std::fs::write(&wrong, &content).unwrap();
    let out = run(&wrong);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("the key is not hex"), "{stderr}");
    assert!(!stderr.contains(&content[..16]), "{stderr}");
    assert!(out.stdout.is_empty());
}

#[test]
fn debug_output_and_urls_hold_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    let (secret, _) = basis_store::schnorr::generate_keypair();
    let key = FileKey::from_secret(secret).unwrap();
    assert!(!format!("{key:?}").contains(&hex::encode(secret)));

    let api_key_file = dir.path().join("api");
    std::fs::write(&api_key_file, API_KEY).unwrap();
    let api_key = ApiKey::read(&api_key_file).unwrap();
    assert!(!format!("{api_key:?}").contains(API_KEY));
    let nft = hex::encode([1u8; 32]);
    let context = Context::new(
        "http://127.0.0.1:9",
        "http://127.0.0.1:9",
        Some(&api_key_file),
        &nft,
    )
    .unwrap();
    assert!(!format!("{context:?}").contains(API_KEY));

    // A URL with credentials is refused, and the refusal does not repeat them.
    for (tracker, node) in [
        ("http://canary:hunter2@127.0.0.1:9", "http://127.0.0.1:9"),
        ("http://127.0.0.1:9", "https://canary:hunter2@node.example"),
    ] {
        let e = Context::new(tracker, node, None, &nft).unwrap_err();
        assert!(e.contains("holds credentials"), "{e}");
        assert!(!e.contains("hunter2"), "{e}");
    }
}
