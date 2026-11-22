//! Tracker Box Updater Service
//!
//! This module implements a background service that periodically updates the R4 and R5 register values
//! of the tracker box every 10 minutes. The update transaction is built and signed in this process
//! with `ergo.tracker_secret_key` and submitted through the node's public `POST /transactions`;
//! no node wallet endpoint is used.

use basis_store::redact;
use std::sync::{Arc, RwLock};
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

/// Create a default tracker public key that looks realistic (compressed format with proper prefix)
fn create_default_tracker_pubkey() -> [u8; 33] {
    [
        0x02, 0xda, 0xda, 0x81, 0x1a, 0x88, 0x8c, 0xd0, 0xdc, 0x7a, 0x0a, 0x41, 0x73, 0x9a, 0x3a,
        0xd9, 0xb0, 0xf4, 0x27, 0x74, 0x1f, 0xe6, 0xca, 0x19, 0x70, 0x0c, 0xf1, 0xa5, 0x12, 0x00,
        0xc9, 0x6b, 0xf7,
    ]
}

/// Snapshot of the tracker box commitment state, as observed on-chain.
#[derive(Debug, Clone, Default)]
pub struct ConfirmedState {
    /// Confirmed on-chain AVL root digest (R5). `None` until observed.
    pub digest: Option<[u8; 33]>,
    /// Box ID of the confirmed tracker box.
    pub box_id: Option<String>,
    /// Height at which the confirmed box was observed.
    pub height: Option<u64>,
}

/// Snapshot of an in-flight tracker box update transaction.
#[derive(Debug, Clone, Default)]
pub struct PendingState {
    /// Digest that the pending update will commit.
    pub digest: Option<[u8; 33]>,
    /// Transaction ID of the in-flight update.
    pub tx_id: Option<String>,
    /// Height at which the update was submitted.
    pub submitted_height: Option<u64>,
}

/// A redemption broadcast through `/redemption/submit` that the updater has not seen leave the
/// mempool yet (round 5, item 3). A commit spends the tracker box such a redemption reads as a
/// data input, which would invalidate it, so the updater holds the commit back for a while.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedRedemption {
    /// Id of the broadcast redemption transaction.
    pub tx_id: String,
    /// The boxes the redemption reads as data inputs (the tracker box).
    pub data_input_ids: Vec<String>,
    /// When `/redemption/submit` broadcast it.
    pub submitted_at: std::time::Instant,
}

/// Most submitted redemptions [`SharedTrackerState`] keeps for the commit deferral; the oldest
/// make room. Each needed a build within its budgets, and a redemption defers a commit for at
/// most [`MAX_COMMIT_DEFERRAL`] anyway.
pub const MAX_SUBMITTED_REDEMPTIONS: usize = 1024;

/// Shared state for the tracker box updater
#[derive(Debug, Clone)]
pub struct SharedTrackerState {
    pub avl_root_digest: Arc<RwLock<[u8; 33]>>,
    pub tracker_pubkey: Arc<RwLock<[u8; 33]>>,
    pub tracker_box_id: Arc<RwLock<Option<String>>>,
    pub tracker_nft_id: Arc<RwLock<Option<String>>>,
    pub confirmed: Arc<RwLock<ConfirmedState>>,
    pub pending: Arc<RwLock<PendingState>>,
    /// Redemptions submitted through `/redemption/submit` and not yet seen out of the mempool
    /// (see [`SubmittedRedemption`]).
    pub submitted_redemptions: Arc<RwLock<Vec<SubmittedRedemption>>>,
}

impl Default for SharedTrackerState {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedTrackerState {
    /// Creates a new SharedTrackerState with a default tracker public key for testing.
    /// This should only be used in tests - production code should use new_with_tracker_key.
    pub fn new() -> Self {
        Self {
            avl_root_digest: Arc::new(RwLock::new([0u8; 33])),
            tracker_pubkey: Arc::new(RwLock::new(create_default_tracker_pubkey())),
            tracker_box_id: Arc::new(RwLock::new(None)),
            tracker_nft_id: Arc::new(RwLock::new(None)),
            confirmed: Arc::new(RwLock::new(ConfirmedState::default())),
            pending: Arc::new(RwLock::new(PendingState::default())),
            submitted_redemptions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn new_with_tracker_key(tracker_pubkey: [u8; 33]) -> Self {
        Self {
            avl_root_digest: Arc::new(RwLock::new([0u8; 33])),
            tracker_pubkey: Arc::new(RwLock::new(tracker_pubkey)),
            tracker_box_id: Arc::new(RwLock::new(None)),
            tracker_nft_id: Arc::new(RwLock::new(None)),
            confirmed: Arc::new(RwLock::new(ConfirmedState::default())),
            pending: Arc::new(RwLock::new(PendingState::default())),
            submitted_redemptions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn set_avl_root_digest(&self, digest: [u8; 33]) {
        if let Ok(mut root_lock) = self.avl_root_digest.write() {
            *root_lock = digest;
        }
    }

    pub fn set_tracker_pubkey(&self, pubkey: [u8; 33]) {
        if let Ok(mut pubkey_lock) = self.tracker_pubkey.write() {
            *pubkey_lock = pubkey;
        }
    }

    pub fn set_tracker_box_id(&self, box_id: String) {
        if let Ok(mut id_lock) = self.tracker_box_id.write() {
            *id_lock = Some(box_id);
        }
    }

    pub fn set_tracker_nft_id(&self, nft_id: String) {
        if let Ok(mut id_lock) = self.tracker_nft_id.write() {
            *id_lock = Some(nft_id);
        }
    }

    pub fn get_avl_root_digest(&self) -> [u8; 33] {
        if let Ok(root_lock) = self.avl_root_digest.read() {
            *root_lock
        } else {
            [0u8; 33]
        }
    }

    pub fn get_tracker_pubkey(&self) -> [u8; 33] {
        if let Ok(pubkey_lock) = self.tracker_pubkey.read() {
            *pubkey_lock
        } else {
            [0u8; 33]
        }
    }

    pub fn get_tracker_box_id(&self) -> Option<String> {
        if let Ok(id_lock) = self.tracker_box_id.read() {
            id_lock.clone()
        } else {
            None
        }
    }

    pub fn get_tracker_nft_id(&self) -> Option<String> {
        if let Ok(id_lock) = self.tracker_nft_id.read() {
            id_lock.clone()
        } else {
            None
        }
    }

    /// Record an in-flight update transaction.
    pub fn set_pending(&self, digest: [u8; 33], tx_id: String, submitted_height: u64) {
        if let Ok(mut pending) = self.pending.write() {
            pending.digest = Some(digest);
            pending.tx_id = Some(tx_id);
            pending.submitted_height = Some(submitted_height);
        }
    }

    /// Clear the pending state (after confirmation or revert).
    pub fn clear_pending(&self) {
        if let Ok(mut pending) = self.pending.write() {
            *pending = PendingState::default();
        }
    }

    /// Record the confirmed on-chain state.
    pub fn set_confirmed(&self, digest: [u8; 33], box_id: String, height: u64) {
        if let Ok(mut confirmed) = self.confirmed.write() {
            confirmed.digest = Some(digest);
            confirmed.box_id = Some(box_id);
            confirmed.height = Some(height);
        }
    }

    /// Snapshot the pending state.
    pub fn get_pending(&self) -> PendingState {
        self.pending.read().map(|p| p.clone()).unwrap_or_default()
    }

    /// Snapshot the confirmed state.
    pub fn get_confirmed(&self) -> ConfirmedState {
        self.confirmed.read().map(|c| c.clone()).unwrap_or_default()
    }

    /// Remember a redemption `/redemption/submit` just broadcast (round 5, item 3), so the
    /// updater does not spend the tracker box it reads while it waits in the mempool.
    pub fn record_submitted_redemption(&self, tx_id: String, data_input_ids: Vec<String>) {
        self.record_submitted_redemption_at(tx_id, data_input_ids, std::time::Instant::now());
    }

    /// [`Self::record_submitted_redemption`] for a redemption submitted at `submitted_at`: the
    /// redemption journal at startup (round 5, C8), so a restart does not restart the
    /// deferral limit.
    pub fn record_submitted_redemption_at(
        &self,
        tx_id: String,
        data_input_ids: Vec<String>,
        submitted_at: std::time::Instant,
    ) {
        // Round 5b (F10): ids are kept in lower case, as the node writes them.
        let tx_id = tx_id.to_ascii_lowercase();
        let data_input_ids = data_input_ids
            .iter()
            .map(|id| id.to_ascii_lowercase())
            .collect();
        let mut submitted = self
            .submitted_redemptions
            .write()
            .unwrap_or_else(|e| e.into_inner());
        submitted.retain(|r| !r.tx_id.eq_ignore_ascii_case(&tx_id));
        submitted.push(SubmittedRedemption {
            tx_id,
            data_input_ids,
            submitted_at,
        });
        let excess = submitted.len().saturating_sub(MAX_SUBMITTED_REDEMPTIONS);
        submitted.drain(..excess);
    }

    /// Snapshot the submitted redemptions, oldest first.
    pub fn get_submitted_redemptions(&self) -> Vec<SubmittedRedemption> {
        self.submitted_redemptions
            .read()
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// Forget the submitted redemptions with these ids.
    pub fn forget_submitted_redemptions(&self, tx_ids: &[String]) {
        if tx_ids.is_empty() {
            return;
        }
        let mut submitted = self
            .submitted_redemptions
            .write()
            .unwrap_or_else(|e| e.into_inner());
        submitted.retain(|r| !tx_ids.iter().any(|id| id.eq_ignore_ascii_case(&r.tx_id)));
    }
}

/// Configuration for the tracker box updater. `Debug` redacts the tracker secret key.
#[derive(Clone)]
pub struct TrackerBoxUpdateConfig {
    /// Node that receives the signed update transaction (`POST /transactions`).
    /// No wallet endpoint is called on it.
    pub wallet_node_url: String,
    pub wallet_api_key: Option<String>,
    /// Node used for chain reads (`/blockchain/*`, `/utxo/*`, `/blocks/lastHeaders`,
    /// `/info`) and fee-box discovery (`POST /blockchain/box/unspent/byAddress`); needs
    /// `extraIndex = true`.
    pub scanner_node_url: String,
    pub scanner_api_key: Option<String>,
    pub update_interval_seconds: u64,
    pub fee: u64,
    pub change_address: Option<String>,
    pub tracker_secret_key: Option<[u8; 32]>,
    /// Minimum on-chain depth (including the inclusion block) before a
    /// tracker box update is treated as confirmed and pending notes are
    /// promoted to `Confirmed`.
    pub min_confirmation_depth: u64,
    /// Reserve contract addresses (P2S) to exclude when searching for the
    /// tracker box. Token-backed reserves store the tracker NFT in R6, so
    /// they are returned by `byTokenId` queries and must be filtered out.
    pub reserve_contract_addresses: Vec<String>,
    /// Recommit the unchanged digest once the tracker box is this many blocks old and nothing
    /// else is pending, so the box never reaches the 2160-block emergency window. 0 disables.
    pub heartbeat_blocks: u64,
    /// Round 5, item 4: how often a submitted commit is looked for on chain between cycles
    /// (one `GET /blockchain/transaction/byId/{id}` per poll while a commit is pending).
    /// [`PENDING_COMMIT_POLL_INTERVAL`] by default; the cycles keep `update_interval_seconds`.
    pub pending_poll_interval: Duration,
    /// Round 5, item 3: how long one redemption submitted through `/redemption/submit` may hold
    /// back a commit while it waits in the mempool ([`MAX_COMMIT_DEFERRAL`] by default). Round
    /// 5b (F3): also the most commits are held back in total from the first deferral since the
    /// last commit, whichever redemptions hold them back. A due heartbeat is never held back.
    pub max_commit_deferral: Duration,
}

/// Default [`TrackerBoxUpdateConfig::pending_poll_interval`]: a minute.
pub const PENDING_COMMIT_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Default [`TrackerBoxUpdateConfig::max_commit_deferral`]: 20 minutes, about ten blocks.
pub const MAX_COMMIT_DEFERRAL: Duration = Duration::from_secs(20 * 60);

/// No commit is held back for a redemption once the tracker box is within this many blocks of
/// the emergency window ([`crate::config::TRACKER_EMERGENCY_WINDOW_BLOCKS`]).
pub const COMMIT_DEFERRAL_EMERGENCY_MARGIN_BLOCKS: u64 = 200;

impl std::fmt::Debug for TrackerBoxUpdateConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let TrackerBoxUpdateConfig {
            wallet_node_url,
            wallet_api_key,
            scanner_node_url,
            scanner_api_key,
            update_interval_seconds,
            fee,
            change_address,
            tracker_secret_key,
            min_confirmation_depth,
            reserve_contract_addresses,
            heartbeat_blocks,
            pending_poll_interval,
            max_commit_deferral,
        } = self;
        f.debug_struct("TrackerBoxUpdateConfig")
            .field("wallet_node_url", &redact::Url(wallet_node_url))
            .field("wallet_api_key", &redact::Secret(wallet_api_key))
            .field("scanner_node_url", &redact::Url(scanner_node_url))
            .field("scanner_api_key", &redact::Secret(scanner_api_key))
            .field("update_interval_seconds", update_interval_seconds)
            .field("fee", fee)
            .field("change_address", change_address)
            .field("tracker_secret_key", &redact::Secret(tracker_secret_key))
            .field("min_confirmation_depth", min_confirmation_depth)
            .field("reserve_contract_addresses", reserve_contract_addresses)
            .field("heartbeat_blocks", heartbeat_blocks)
            .field("pending_poll_interval", pending_poll_interval)
            .field("max_commit_deferral", max_commit_deferral)
            .finish()
    }
}

impl Default for TrackerBoxUpdateConfig {
    fn default() -> Self {
        Self {
            wallet_node_url: "http://localhost:9053".to_string(),
            wallet_api_key: None,
            scanner_node_url: "http://localhost:9053".to_string(),
            scanner_api_key: None,
            update_interval_seconds: 600,
            fee: 1_000_000,
            change_address: None,
            tracker_secret_key: None,
            min_confirmation_depth: 2,
            reserve_contract_addresses: Vec::new(),
            heartbeat_blocks: 720,
            pending_poll_interval: PENDING_COMMIT_POLL_INTERVAL,
            max_commit_deferral: MAX_COMMIT_DEFERRAL,
        }
    }
}

/// Error type for tracker box updater operations
#[derive(Debug, thiserror::Error)]
pub enum TrackerBoxUpdaterError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),
    #[error("No tracker NFT ID configured")]
    NoTrackerNftId,
    #[error("No tracker box found on chain")]
    NoTrackerBoxFound,
    #[error("Transaction not found on chain: {0}")]
    TransactionNotFound(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("No token-free boxes at the tracker address to pay the transaction fee")]
    NoFeeInputs,
    #[error("Insufficient token-free funds at the tracker address to pay the fee: {available} < {required}")]
    InsufficientFeeInputs { available: u64, required: u64 },
    #[error("Failed to sign transaction: {0}")]
    SigningFailed(String),
    #[error("Failed to broadcast transaction: {0}")]
    BroadcastFailed(String),
}

/// Ergo box as returned by the blockchain API
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErgoBoxApi {
    pub box_id: String,
    pub value: u64,
    pub ergo_tree: String,
    pub assets: Vec<AssetApi>,
    pub additional_registers: std::collections::HashMap<String, String>,
    pub creation_height: u32,
    /// Box address (P2PK or P2S). Present on `/blockchain/box/unspent/byTokenId`
    /// responses; optional because other box sources omit it.
    pub address: Option<String>,
}

/// Asset in an Ergo box
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetApi {
    pub token_id: String,
    pub amount: u64,
}

/// Encode an unsigned integer using Ergo's VLQ encoding.
fn vlq_encode(mut value: usize) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut bytes = Vec::new();
    while value > 0 {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
    }
    bytes
}

/// Compute the on-chain confirmation depth of a transaction included at
/// `inclusion_height` given the current chain tip `current_height`. Both heights
/// are inclusive, so a transaction in the current tip has depth 1. A height of 0
/// means the inclusion height is unknown and depth is reported as 0.
pub fn confirmation_depth(current_height: u64, inclusion_height: u64) -> u64 {
    if inclusion_height == 0 {
        0
    } else {
        current_height.saturating_sub(inclusion_height) + 1
    }
}

/// A commit transaction as the blockchain index reports it
/// (`GET /blockchain/transaction/byId/{id}`, an `IndexedErgoTransaction`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfirmingTx {
    /// The new tracker box: the first output (the tx id when the response has no outputs).
    box_id: String,
    /// Creation height of that box (0 when unknown), recorded as the confirmation height.
    height: u64,
    /// Height of the block that included the transaction (`inclusionHeight`, 0 when unknown).
    /// Confirmation depth counts from here, never from the creation height: a transaction
    /// that waited in the mempool was built many blocks before it was included.
    inclusion_height: u64,
    /// The first output's R5 register (serialized, hex), when it has one: for a redemption,
    /// the reserve tree digest the reserve output carries (round 5b, F1).
    first_output_r5: Option<String>,
}

impl ConfirmingTx {
    fn from_indexed_tx(body: &serde_json::Value, tx_id: &str) -> Self {
        let first = body
            .get("outputs")
            .and_then(|o| o.as_array())
            .and_then(|outputs| outputs.first());
        Self {
            box_id: first
                .and_then(|b| b.get("boxId"))
                .and_then(|b| b.as_str())
                .unwrap_or(tx_id)
                .to_string(),
            height: first
                .and_then(|b| b.get("creationHeight"))
                .and_then(|h| h.as_u64())
                .unwrap_or(0),
            inclusion_height: body
                .get("inclusionHeight")
                .and_then(|h| h.as_u64())
                .unwrap_or(0),
            first_output_r5: first
                .and_then(|b| b.get("additionalRegisters"))
                .and_then(|r| r.get("R5"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
        }
    }
}

/// Tracker box updater service
pub struct TrackerBoxUpdater;

/// Number of consecutive update cycles in which a submitted update transaction
/// may be missing from the node (mempool and blockchain) before it is treated
/// as dropped/rejected and the pending notes are reverted. With the default
/// 600s update interval this bounds the stall to roughly 30 minutes.
const MAX_PENDING_MISSING_CYCLES: u32 = 3;

/// Where a submitted transaction is, as the nodes report it
/// ([`TrackerBoxUpdater::check_transaction_confirmation`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    /// In a block.
    OnChain,
    /// In a node's mempool, waiting for a block: pending, not dropped. Never resubmitted.
    InMempool,
    /// Neither in a mempool nor in a block. Only a transaction missing for
    /// `MAX_PENDING_MISSING_CYCLES` consecutive cycles is treated as dropped and rebuilt.
    Missing,
}

/// Update interval of the tracker box updater when `BASIS_TRACKER_UPDATE_INTERVAL_SECONDS` is
/// not set, in seconds.
pub const DEFAULT_UPDATE_INTERVAL_SECONDS: u64 = 600;

/// Intervals below this many seconds work, but the server warns: every cycle reads the node,
/// and `MAX_PENDING_MISSING_CYCLES` cycles of it decide that a commit was dropped.
pub const SHORT_UPDATE_INTERVAL_SECONDS: u64 = 30;

/// The update interval from `BASIS_TRACKER_UPDATE_INTERVAL_SECONDS`, given as `raw` (`None`
/// when unset). Unset or empty gives [`DEFAULT_UPDATE_INTERVAL_SECONDS`]. `0` is refused
/// (an interval of zero is no interval: the timer cannot run), and so is anything that is not
/// a whole number of seconds, which used to fall back to the default silently.
pub fn update_interval_from_env(raw: Option<&str>) -> Result<u64, String> {
    let raw = raw.map(str::trim).unwrap_or_default();
    if raw.is_empty() {
        return Ok(DEFAULT_UPDATE_INTERVAL_SECONDS);
    }
    match raw.parse::<u64>() {
        Ok(0) => Err(
            "BASIS_TRACKER_UPDATE_INTERVAL_SECONDS is 0; set a number of seconds, at least 1 \
             (default 600)"
                .to_string(),
        ),
        Ok(seconds) => Ok(seconds),
        Err(_) => Err(format!(
            "BASIS_TRACKER_UPDATE_INTERVAL_SECONDS must be a whole number of seconds (default \
             600), got {raw:?}"
        )),
    }
}

/// Whether a pending update transaction that the node has not seen for
/// `missing_cycles` consecutive cycles should be treated as dropped/rejected
/// (and the pending notes reverted so a fresh update can be submitted).
/// Round 4: after a (re)start, a cycle that ends before it could record the tracker box (the
/// AVL digest is not initialized yet, or the tracker box was not found) is retried after
/// `STARTUP_RETRY_DELAY` instead of a full interval, for up to `STARTUP_RETRY_WINDOW` after
/// the start. `/reserves/create` answers 503 until the tracker box is recorded, so a skipped
/// first cycle kept it unavailable for a whole interval (600 s by default) after every restart.
pub const STARTUP_RETRY_DELAY: Duration = Duration::from_secs(5);
/// See [`STARTUP_RETRY_DELAY`].
pub const STARTUP_RETRY_WINDOW: Duration = Duration::from_secs(60);

/// Whether a cycle that ended early `since_start` after the start is retried after
/// [`STARTUP_RETRY_DELAY`]: only until the tracker box was first recorded, and only while
/// the retry still falls within [`STARTUP_RETRY_WINDOW`].
fn startup_retry_due(since_start: Duration, tracker_box_recorded: bool) -> bool {
    !tracker_box_recorded && since_start + STARTUP_RETRY_DELAY <= STARTUP_RETRY_WINDOW
}

fn pending_tx_is_dropped(missing_cycles: u32) -> bool {
    missing_cycles >= MAX_PENDING_MISSING_CYCLES
}

/// Whether a heartbeat commit is due: heartbeats are enabled (`heartbeat_blocks > 0`) and the
/// tracker box, created at `box_creation_height`, is at least `heartbeat_blocks` old at
/// `current_height`.
fn heartbeat_due(heartbeat_blocks: u64, current_height: u64, box_creation_height: u64) -> bool {
    heartbeat_blocks > 0 && current_height.saturating_sub(box_creation_height) >= heartbeat_blocks
}

/// Round 5, item 3: whether a commit may still be held back for a redemption: the tracker box,
/// created at `box_creation_height`, is more than [`COMMIT_DEFERRAL_EMERGENCY_MARGIN_BLOCKS`]
/// blocks short of the emergency window at `current_height`.
fn commit_may_wait(current_height: u64, box_creation_height: u64) -> bool {
    let age = current_height.saturating_sub(box_creation_height);
    age + COMMIT_DEFERRAL_EMERGENCY_MARGIN_BLOCKS < crate::config::TRACKER_EMERGENCY_WINDOW_BLOCKS
}

/// Whether the tracker can spend `box_ergo_tree_hex`: it must be exactly `P2PK(tracker_pubkey)`.
/// A tracker box under any other script would be committed to with a transaction the tracker
/// key cannot sign, or by spending a box the operator does not control.
fn tracker_box_is_p2pk_of(box_ergo_tree_hex: &str, tracker_pubkey: &[u8; 33]) -> bool {
    box_ergo_tree_hex.eq_ignore_ascii_case(&crate::local_wallet::p2pk_tree_hex(tracker_pubkey))
}

/// Whether the previously confirmed tracker box has disappeared from the chain
/// (the box now carrying the tracker NFT has a different id), indicating a reorg
/// of the confirming update (issue #15 S6).
fn confirmed_box_orphaned(confirmed_box_id: Option<&str>, current_box_id: &str) -> bool {
    match confirmed_box_id {
        Some(confirmed) => confirmed != current_box_id,
        None => false,
    }
}

impl TrackerBoxUpdater {
    /// Start the tracker box updater service as an async background task
    pub async fn start(
        config: TrackerBoxUpdateConfig,
        shared_state: SharedTrackerState,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        cmd_tx: Option<tokio::sync::mpsc::Sender<crate::TrackerCommand>>,
    ) -> Result<(), TrackerBoxUpdaterError> {
        // `interval` panics on a zero period; the server refuses 0 at startup, and a config built
        // in code with 0 runs every second instead.
        let mut ticker = interval(Duration::from_secs(config.update_interval_seconds.max(1)));

        let mut last_submitted_digest: Option<[u8; 33]> = None;
        let mut pending_tx: Option<(String, [u8; 33])> = None;
        // Consecutive cycles in which the pending update tx was not found on the
        // node (neither mempool nor blockchain). A dropped/rejected tx would
        // otherwise stay `pending` forever and block all future updates
        // (issue #15 S6).
        let mut pending_missing_cycles: u32 = 0;
        // Round 4: the startup retry (see `STARTUP_RETRY_DELAY`).
        let started = tokio::time::Instant::now();
        let mut tracker_box_recorded = false;
        let mut retry_soon = false;
        // Round 5b (F3): when the first commit since the last one was held back for a
        // redemption. Commits are held back for at most `max_commit_deferral` in total from
        // here, whichever redemptions hold them back and however the digest changes meanwhile.
        let mut deferring_since: Option<std::time::Instant> = None;
        // Round 5, item 4: between cycles, a pending commit is looked for on chain every
        // `pending_poll_interval` (one node request per poll), so a confirmed commit is noticed
        // within a minute instead of at the next cycle. The cycles keep their interval.
        let poll_period = config.pending_poll_interval.max(Duration::from_millis(10));
        let mut pending_poll =
            tokio::time::interval_at(tokio::time::Instant::now() + poll_period, poll_period);
        pending_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        info!(
            "Tracker box updater started with {}s interval",
            config.update_interval_seconds
        );

        loop {
            // `biased`: a shutdown that arrived during a cycle wins over a missed tick, so the
            // updater never starts another cycle once it was asked to stop.
            let poll_only = tokio::select! {
                biased;
                _ = shutdown_rx.recv() => {
                    info!("Tracker box updater received shutdown signal, stopping");
                    return Ok(());
                }
                _ = tokio::time::sleep(STARTUP_RETRY_DELAY), if retry_soon => {
                    // The regular schedule restarts from this cycle: no burst of missed ticks.
                    ticker.reset();
                    false
                }
                _ = ticker.tick(), if !retry_soon => false,
                _ = pending_poll.tick(), if pending_tx.is_some() && !retry_soon => true,
            };

            if poll_only {
                let Some((tx_id, expected_digest)) = pending_tx.clone() else {
                    continue;
                };
                match Self::poll_pending_commit(&config, &tx_id).await {
                    Ok(Some(confirming)) => {
                        Self::commit_confirmed(
                            &config,
                            &shared_state,
                            &cmd_tx,
                            &tx_id,
                            expected_digest,
                            confirming,
                        )
                        .await;
                        last_submitted_digest = Some(expected_digest);
                        pending_missing_cycles = 0;
                        pending_tx = None;
                    }
                    Ok(None) => {}
                    Err(e) => warn!("Pending commit {} could not be looked up: {}", tx_id, e),
                }
                continue;
            }
            retry_soon = false;

            if let Some((tx_id, expected_digest)) = pending_tx.clone() {
                match Self::check_transaction_confirmation(&config, &tx_id).await {
                    Ok(TxStatus::OnChain) => {
                        // Look up the confirming box to record its height/id, and the block
                        // height the transaction was included at.
                        let confirming = match Self::fetch_tracker_box_summary(&config, &tx_id)
                            .await
                        {
                            Ok(summary) => summary,
                            Err(e) => {
                                error!(
                                    "Failed to fetch confirming box for {}: {}. Will retry.",
                                    tx_id, e
                                );
                                continue;
                            }
                        };
                        match Self::deep_enough(&config, &tx_id, &confirming).await {
                            Ok(true) => {}
                            Ok(false) => continue,
                            Err(e) => {
                                error!(
                                    "Failed to fetch node height for depth check of {}: {}. Will retry.",
                                    tx_id, e
                                );
                                continue;
                            }
                        }
                        Self::commit_confirmed(
                            &config,
                            &shared_state,
                            &cmd_tx,
                            &tx_id,
                            expected_digest,
                            confirming,
                        )
                        .await;
                        last_submitted_digest = Some(expected_digest);
                        pending_missing_cycles = 0;
                        pending_tx = None;
                    }
                    Ok(TxStatus::InMempool) => {
                        // Waiting for a block: still pending, never rebuilt or resubmitted.
                        // Only consecutive missing cycles count towards a drop.
                        pending_missing_cycles = 0;
                        info!(
                            "Transaction {} is in the mempool, waiting for a block...",
                            tx_id
                        );
                        continue;
                    }
                    Ok(TxStatus::Missing) => {
                        pending_missing_cycles += 1;
                        if pending_tx_is_dropped(pending_missing_cycles) {
                            // The tx has been missing from both mempool and
                            // blockchain for several cycles: it was dropped or
                            // rejected. Keeping it `pending` would block every
                            // future update, so revert the pending notes, clear
                            // the pending state, and let a fresh update be built
                            // and submitted on the next cycle (issue #15 S6).
                            error!(
                                "Transaction {} not found for {} consecutive cycles; assuming it was dropped/rejected. Reverting pending notes and re-submitting.",
                                tx_id, pending_missing_cycles
                            );
                            shared_state.clear_pending();
                            pending_tx = None;
                            last_submitted_digest = None;
                            pending_missing_cycles = 0;

                            if let Some(ref tx) = cmd_tx {
                                let (rtx, rrx) = tokio::sync::oneshot::channel();
                                let _ = tx
                                    .send(crate::TrackerCommand::RevertPendingNotes {
                                        response_tx: rtx,
                                    })
                                    .await;
                                let _ = rrx.await;
                            }
                        } else {
                            info!(
                                "Transaction {} is neither in the mempool nor on chain ({}/{} cycles), waiting for next cycle...",
                                tx_id, pending_missing_cycles, MAX_PENDING_MISSING_CYCLES
                            );
                        }
                        continue;
                    }
                    Err(e) => {
                        error!(
                            "Failed to check transaction {} status: {}. Will retry.",
                            tx_id, e
                        );
                        continue;
                    }
                }
            }

            let tracker_nft_id = match shared_state.get_tracker_nft_id() {
                Some(id) => id,
                None => {
                    warn!("No tracker NFT ID configured, skipping update cycle");
                    continue;
                }
            };

            // The digest to commit comes from the tracker thread, which rebuilds the live tree
            // once if notes arrived since the last rebuild (round 4, C3: notes no longer rebuild
            // it one by one, so the shared digest is only as fresh as its last refresh).
            let current_digest = Self::refreshed_digest(&shared_state, &cmd_tx).await;
            let tracker_pubkey = shared_state.get_tracker_pubkey();

            if current_digest == [0u8; 33] {
                retry_soon = startup_retry_due(started.elapsed(), tracker_box_recorded);
                if retry_soon {
                    info!(
                        "AVL root digest not initialized yet, retrying in {}s",
                        STARTUP_RETRY_DELAY.as_secs()
                    );
                } else {
                    info!("AVL root digest not initialized yet, skipping update");
                }
                continue;
            }

            let tracker_box = match Self::find_tracker_box(&config, &tracker_nft_id).await {
                Ok(box_data) => box_data,
                Err(e) => {
                    retry_soon = startup_retry_due(started.elapsed(), tracker_box_recorded);
                    if retry_soon {
                        error!(
                            "Failed to find tracker box: {}; retrying in {}s",
                            e,
                            STARTUP_RETRY_DELAY.as_secs()
                        );
                    } else {
                        error!("Failed to find tracker box: {}", e);
                    }
                    continue;
                }
            };
            tracker_box_recorded = true;

            // Refresh the confirmed box id in shared state from the live node.
            shared_state.set_tracker_box_id(tracker_box.box_id.clone());

            // The tracker box must be locked by P2PK(tracker pk); otherwise the tracker key
            // cannot spend it. Reads and reconciliation below still run; committing does not.
            let tracker_box_spendable =
                tracker_box_is_p2pk_of(&tracker_box.ergo_tree, &tracker_pubkey);
            if !tracker_box_spendable {
                error!(
                    "Tracker box {} is not locked by P2PK(tracker public key {}): its ErgoTree is {}. \
                     Refusing to commit until ergo.tracker_public_key / tracker_nft_id match the tracker box.",
                    tracker_box.box_id,
                    hex::encode(tracker_pubkey),
                    tracker_box.ergo_tree
                );
            }

            // Reorg re-validation: if the box previously treated as confirmed is no
            // longer the one carrying the tracker NFT, the confirming update was
            // orphaned (or the chain was reorganized). Revert any pending notes so
            // a fresh update can be built; the reconcile step below re-aligns
            // per-note confirmations with the newly observed box (issue #15 S6).
            if confirmed_box_orphaned(
                shared_state.get_confirmed().box_id.as_deref(),
                &tracker_box.box_id,
            ) {
                warn!(
                    "Previously confirmed tracker box {} is no longer on-chain (found {} instead); possible reorg. Re-syncing confirmation state.",
                    shared_state.get_confirmed().box_id.unwrap_or_default(),
                    tracker_box.box_id
                );
                if let Some(ref tx) = cmd_tx {
                    let (rtx, rrx) = tokio::sync::oneshot::channel();
                    let _ = tx
                        .send(crate::TrackerCommand::RevertPendingNotes { response_tx: rtx })
                        .await;
                    let _ = rrx.await;
                }
            }

            // Set when this cycle has no new digest to commit (the reason is logged).
            let mut nothing_to_commit: Option<&str> = None;
            if let Some(r5_value) = tracker_box.additional_registers.get("R5") {
                if let Ok(r5_bytes) = hex::decode(r5_value) {
                    if r5_bytes.len() >= 34 {
                        let onchain_digest = &r5_bytes[1..34];
                        let mut onchain_digest_arr = [0u8; 33];
                        onchain_digest_arr.copy_from_slice(onchain_digest);

                        // Always record the currently-confirmed on-chain state so
                        // clients can read it via /tracker/state.
                        shared_state.set_confirmed(
                            onchain_digest_arr,
                            tracker_box.box_id.clone(),
                            tracker_box.creation_height as u64,
                        );

                        // Reconcile per-note confirmation records with the
                        // observed on-chain digest (handles restarts where the
                        // local tree already matches the on-chain commitment).
                        if let Some(ref tx) = cmd_tx {
                            let (rtx, rrx) = tokio::sync::oneshot::channel();
                            let _ = tx
                                .send(crate::TrackerCommand::ReconcileWithConfirmedDigest {
                                    digest: onchain_digest_arr,
                                    box_id: tracker_box.box_id.clone(),
                                    height: tracker_box.creation_height as u64,
                                    response_tx: rtx,
                                })
                                .await;
                            let _ = rrx.await;
                        }

                        // Issue #17 phase 2: reconcile may have promoted the
                        // from-edge decrease to Confirmed (e.g. after a
                        // restart); evaluate staged exchanges now.
                        Self::process_pending_exchanges(&config, &cmd_tx).await;

                        if onchain_digest == current_digest.as_slice() {
                            last_submitted_digest = Some(current_digest);
                            nothing_to_commit =
                                Some("On-chain tracker box already has current AVL root digest");
                        }
                    }
                }
            }

            // If a previous submission for a different digest is still pending
            // and never confirmed, skip submitting a new one (the confirmation
            // check at the top of the loop handles the in-flight tx).
            if nothing_to_commit.is_none() && last_submitted_digest == Some(current_digest) {
                nothing_to_commit = Some("AVL root digest unchanged, skipping redundant update");
            }

            // With nothing to commit, a due heartbeat recommits the unchanged digest anyway
            // so the tracker box never ages into the emergency window.
            let mut heartbeat = false;
            if let Some(reason) = nothing_to_commit {
                if !Self::heartbeat_now(&config, &tracker_box).await {
                    info!("{}", reason);
                    // Nothing waits to be committed: no deferral runs (round 5b, F3).
                    deferring_since = None;
                    continue;
                }
                heartbeat = true;
            }

            if !tracker_box_spendable {
                continue;
            }

            // Round 5, item 3: a commit spends the tracker box that a redemption waiting in the
            // mempool reads as its data input, which would invalidate the redemption. Round 5b
            // (F3): a due heartbeat is never held back, and commits are held back for at most
            // `max_commit_deferral` in total from the first deferral since the last commit, so
            // redemptions submitted one after another cannot hold them back for longer.
            if heartbeat {
                let waiting = shared_state.get_submitted_redemptions().len();
                if waiting > 0 {
                    warn!(
                        "Heartbeat commit not held back for {} submitted redemption(s): a due heartbeat never waits. A redemption that reads tracker box {} and is not in a block yet fails and must be built again.",
                        waiting, tracker_box.box_id
                    );
                }
            } else if let Some(waiting) =
                Self::redemption_holding_commit(&config, &shared_state, &tracker_box).await
            {
                let since = *deferring_since.get_or_insert_with(std::time::Instant::now);
                if since.elapsed() < config.max_commit_deferral {
                    info!(
                        "Commit deferred: redemption {} reads tracker box {} and is still in the mempool (submitted {}s ago; commits held back for {}s, at most {}s in total)",
                        waiting.tx_id,
                        tracker_box.box_id,
                        waiting.submitted_at.elapsed().as_secs(),
                        since.elapsed().as_secs(),
                        config.max_commit_deferral.as_secs()
                    );
                    continue;
                }
                warn!(
                    "Committing although redemption {} reads tracker box {} and may still be in the mempool: commits have been held back for {}s since the first deferral, at most {}s in total. If it is not in a block yet, it fails and must be built again.",
                    waiting.tx_id,
                    tracker_box.box_id,
                    since.elapsed().as_secs(),
                    config.max_commit_deferral.as_secs()
                );
            }

            match Self::submit_tracker_update(
                &tracker_nft_id,
                &config,
                &tracker_box,
                &tracker_pubkey,
                &current_digest,
            )
            .await
            {
                Ok(tx_id) => {
                    info!(
                        "Tracker box update submitted. Transaction ID: {}, Box ID: {}. Waiting for confirmation...",
                        tx_id, tracker_box.box_id
                    );
                    deferring_since = None;

                    let submitted_height = Self::get_node_height(&config).await.unwrap_or(0) as u64;
                    shared_state.set_pending(current_digest, tx_id.clone(), submitted_height);
                    pending_tx = Some((tx_id.clone(), current_digest));

                    if let Some(ref tx) = cmd_tx {
                        let (rtx, rrx) = tokio::sync::oneshot::channel();
                        let _ = tx
                            .send(crate::TrackerCommand::MarkNotesPending {
                                digest: current_digest,
                                tx_id,
                                submitted_height,
                                response_tx: rtx,
                            })
                            .await;
                        let _ = rrx.await;
                    }
                }
                Err(e) => {
                    error!("Failed to submit tracker box update: {}", e);
                }
            }
        }
    }

    /// The live digest to commit: asked from the tracker thread (`RefreshDigest`, which also
    /// refreshes the shared digest), or the shared digest when there is no tracker thread to ask
    /// (tests) or it does not answer.
    async fn refreshed_digest(
        shared_state: &SharedTrackerState,
        cmd_tx: &Option<tokio::sync::mpsc::Sender<crate::TrackerCommand>>,
    ) -> [u8; 33] {
        if let Some(tx) = cmd_tx {
            let (rtx, rrx) = tokio::sync::oneshot::channel();
            if tx
                .send(crate::TrackerCommand::RefreshDigest { response_tx: rtx })
                .await
                .is_ok()
            {
                if let Ok(digest) = rrx.await {
                    return digest;
                }
            }
            warn!("The tracker thread did not answer RefreshDigest; using the shared digest");
        }
        shared_state.get_avl_root_digest()
    }

    /// Round 5, item 4: one look at the chain for the pending commit `tx_id`
    /// (`GET /blockchain/transaction/byId/{tx_id}` on the scanner node): `Some` once it is in a
    /// block and at least `min_confirmation_depth` deep (the depth costs one `/info` read, only
    /// once the commit is in a block), `None` while it is not.
    async fn poll_pending_commit(
        config: &TrackerBoxUpdateConfig,
        tx_id: &str,
    ) -> Result<Option<ConfirmingTx>, TrackerBoxUpdaterError> {
        let client = basis_store::http::bounded_client();
        let path = format!("/blockchain/transaction/byId/{tx_id}");
        let mut request = client.get(format!(
            "{}{path}",
            config.scanner_node_url.trim_end_matches('/')
        ));
        if let Some(ref api_key) = config.scanner_api_key {
            request = request.header("api_key", api_key);
        }
        let response = request
            .send()
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(e.to_string()))?;
        match response.status().as_u16() {
            200 => {}
            404 => return Ok(None),
            status => {
                let body = basis_store::http::read_body_capped(response)
                    .await
                    .unwrap_or_default();
                return Err(TrackerBoxUpdaterError::HttpError(format!(
                    "HTTP {status} from {path}: {body}"
                )));
            }
        }
        let body = basis_store::http::read_json_capped(response)
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(format!("JSON parse error: {}", e)))?;
        let confirming = ConfirmingTx::from_indexed_tx(&body, tx_id);
        if Self::deep_enough(config, tx_id, &confirming).await? {
            Ok(Some(confirming))
        } else {
            Ok(None)
        }
    }

    /// Round 5 (C8): whether `tx_id` is in a block at least `min_confirmation_depth` deep: one
    /// chain lookup on the scanner node, plus one `/info` read once it is in a block.
    pub async fn confirmed_deep_enough(
        config: &TrackerBoxUpdateConfig,
        tx_id: &str,
    ) -> Result<bool, TrackerBoxUpdaterError> {
        Ok(Self::poll_pending_commit(config, tx_id).await?.is_some())
    }

    /// Round 5b (F1): [`Self::confirmed_deep_enough`] that also returns the first output's R5
    /// register (serialized, hex) as the blockchain index reports it: `Some(r5)` once `tx_id`
    /// is in a block deep enough (`r5` is `None` when the output has no R5), `None` while it is
    /// not.
    pub async fn confirmed_first_output_r5(
        config: &TrackerBoxUpdateConfig,
        tx_id: &str,
    ) -> Result<Option<Option<String>>, TrackerBoxUpdaterError> {
        Ok(Self::poll_pending_commit(config, tx_id)
            .await?
            .map(|confirming| confirming.first_output_r5))
    }

    /// Round 5b (F4): whether `box_id` is in the scanner node's UTXO set
    /// (`GET /utxo/byId/{box_id}`, which follows the chain without index lag).
    pub async fn box_is_unspent(
        config: &TrackerBoxUpdateConfig,
        box_id: &str,
    ) -> Result<bool, TrackerBoxUpdaterError> {
        Self::node_knows(
            config.scanner_node_url.trim_end_matches('/'),
            config.scanner_api_key.as_deref(),
            &format!("/utxo/byId/{box_id}"),
        )
        .await
    }

    /// Round 5b (F4): the transaction that spent `box_id`, as the scanner node's blockchain
    /// index names it (`spentTransactionId` of `GET /blockchain/box/byId/{box_id}`). `None`
    /// when the index does not name one: the box is unspent, or the index has not reached the
    /// block that spent it.
    pub async fn box_spent_by(
        config: &TrackerBoxUpdateConfig,
        box_id: &str,
    ) -> Result<Option<String>, TrackerBoxUpdaterError> {
        let client = basis_store::http::bounded_client();
        let path = format!("/blockchain/box/byId/{box_id}");
        let mut request = client.get(format!(
            "{}{path}",
            config.scanner_node_url.trim_end_matches('/')
        ));
        if let Some(ref api_key) = config.scanner_api_key {
            request = request.header("api_key", api_key);
        }
        let response = request
            .send()
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(e.to_string()))?;
        match response.status().as_u16() {
            200 => {}
            404 => return Ok(None),
            status => {
                let body = basis_store::http::read_body_capped(response)
                    .await
                    .unwrap_or_default();
                return Err(TrackerBoxUpdaterError::HttpError(format!(
                    "HTTP {status} from {path}: {body}"
                )));
            }
        }
        let body = basis_store::http::read_json_capped(response)
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(format!("JSON parse error: {}", e)))?;
        Ok(body
            .get("spentTransactionId")
            .and_then(|v| v.as_str())
            .filter(|id| !id.is_empty())
            .map(str::to_string))
    }

    /// Whether the commit `tx_id`, in a block at `confirming.inclusion_height`, is at least
    /// `min_confirmation_depth` deep. Presence in a block alone is not confirmation, and the
    /// depth counts from the block that included the transaction: its outputs' creation height
    /// is when it was built, which can be many blocks earlier for a transaction that waited in
    /// the mempool.
    async fn deep_enough(
        config: &TrackerBoxUpdateConfig,
        tx_id: &str,
        confirming: &ConfirmingTx,
    ) -> Result<bool, TrackerBoxUpdaterError> {
        if config.min_confirmation_depth <= 1 {
            return Ok(true);
        }
        let current = Self::get_node_height(config).await?;
        let depth = confirmation_depth(current as u64, confirming.inclusion_height);
        if depth < config.min_confirmation_depth {
            info!(
                "Transaction {} included at height {} (depth {}/{}), waiting for more confirmations...",
                tx_id, confirming.inclusion_height, depth, config.min_confirmation_depth
            );
            return Ok(false);
        }
        Ok(true)
    }

    /// The pending commit `tx_id` is confirmed: record the new tracker box and the committed
    /// digest, promote the pending notes, and evaluate staged exchanges (issue #17 phase 2).
    /// The caller clears its own pending state.
    async fn commit_confirmed(
        config: &TrackerBoxUpdateConfig,
        shared_state: &SharedTrackerState,
        cmd_tx: &Option<tokio::sync::mpsc::Sender<crate::TrackerCommand>>,
        tx_id: &str,
        expected_digest: [u8; 33],
        confirming: ConfirmingTx,
    ) {
        info!("Transaction {} confirmed on chain. Update complete.", tx_id);
        let ConfirmingTx { box_id, height, .. } = confirming;
        shared_state.set_confirmed(expected_digest, box_id.clone(), height);
        // The commit's first output is the new tracker box, which builds read as their data
        // input from now on (round 5, item 4: a poll between cycles finds it first). Without
        // outputs in the answer the id is the transaction's, which is no box: left to the
        // cycle's own lookup.
        if box_id != tx_id {
            shared_state.set_tracker_box_id(box_id.clone());
        }
        shared_state.clear_pending();

        if let Some(ref tx) = cmd_tx {
            let (rtx, rrx) = tokio::sync::oneshot::channel();
            let _ = tx
                .send(crate::TrackerCommand::ConfirmPendingNotes {
                    digest: expected_digest,
                    box_id,
                    height,
                    response_tx: rtx,
                })
                .await;
            let _ = rrx.await;
        }

        // Issue #17 phase 2: with the from-edge decrease now confirmed, evaluate staged
        // exchanges (apply the to-edge increase or cancel if the reserve changed).
        Self::process_pending_exchanges(config, cmd_tx).await;
    }

    /// Round 5, item 3: the redemption submitted through `/redemption/submit` that holds back a
    /// commit of `tracker_box`, if one does: it reads `tracker_box` as a data input, was
    /// submitted less than `max_commit_deferral` ago, and is still in a mempool (or its status
    /// cannot be read). Redemptions in a block or gone from the mempools, and those that read
    /// another box, are forgotten; one held back for `max_commit_deferral` is committed over
    /// with a warning. Nothing is held back once the tracker box is within
    /// [`COMMIT_DEFERRAL_EMERGENCY_MARGIN_BLOCKS`] of the emergency window, once it is due for
    /// its heartbeat (round 5b, F3), or when the node height cannot be read. The loop caps the
    /// deferral in total (round 5b, F3).
    async fn redemption_holding_commit(
        config: &TrackerBoxUpdateConfig,
        shared_state: &SharedTrackerState,
        tracker_box: &ErgoBoxApi,
    ) -> Option<SubmittedRedemption> {
        let submitted = shared_state.get_submitted_redemptions();
        if submitted.is_empty() {
            return None;
        }
        let mut forget = Vec::new();
        let mut waiting = Vec::new();
        for redemption in submitted {
            if !redemption
                .data_input_ids
                .iter()
                .any(|id| id.eq_ignore_ascii_case(&tracker_box.box_id))
            {
                // It read an older tracker box, already spent: in a block already, or invalid.
                forget.push(redemption.tx_id);
            } else if redemption.submitted_at.elapsed() >= config.max_commit_deferral {
                warn!(
                    "Committing although redemption {} (submitted {}s ago) may still be in the mempool: a redemption holds back a commit for at most {}s. If it is not in a block yet, it fails and must be built again.",
                    redemption.tx_id,
                    redemption.submitted_at.elapsed().as_secs(),
                    config.max_commit_deferral.as_secs()
                );
                forget.push(redemption.tx_id);
            } else {
                waiting.push(redemption);
            }
        }
        shared_state.forget_submitted_redemptions(&forget);
        if waiting.is_empty() {
            return None;
        }

        match Self::get_node_height(config).await {
            Ok(height) => {
                let creation_height = tracker_box.creation_height as u64;
                // Round 5b (F3): a commit that is due as a heartbeat is never held back.
                if heartbeat_due(config.heartbeat_blocks, height as u64, creation_height) {
                    warn!(
                        "Committing although {} submitted redemption(s) may still be in the mempool: tracker box {} is {} blocks old, due for its heartbeat ({} blocks), and a due heartbeat never waits",
                        waiting.len(),
                        tracker_box.box_id,
                        (height as u64).saturating_sub(creation_height),
                        config.heartbeat_blocks
                    );
                    return None;
                }
                if !commit_may_wait(height as u64, creation_height) {
                    warn!(
                        "Committing although {} submitted redemption(s) may still be in the mempool: tracker box {} is {} blocks old, within {} blocks of the {}-block emergency window",
                        waiting.len(),
                        tracker_box.box_id,
                        (height as u64).saturating_sub(creation_height),
                        COMMIT_DEFERRAL_EMERGENCY_MARGIN_BLOCKS,
                        crate::config::TRACKER_EMERGENCY_WINDOW_BLOCKS
                    );
                    return None;
                }
            }
            Err(e) => {
                warn!(
                    "Committing without waiting for {} submitted redemption(s): the node height (tracker box age) cannot be read: {}",
                    waiting.len(),
                    e
                );
                return None;
            }
        }

        let mut done = Vec::new();
        let mut holding = None;
        for redemption in waiting {
            match Self::check_transaction_confirmation(config, &redemption.tx_id).await {
                Ok(TxStatus::InMempool) => {
                    holding = Some(redemption);
                    break;
                }
                Ok(TxStatus::OnChain) | Ok(TxStatus::Missing) => done.push(redemption.tx_id),
                Err(e) => {
                    warn!(
                        "Status of redemption {} cannot be read ({}); holding the commit back",
                        redemption.tx_id, e
                    );
                    holding = Some(redemption);
                    break;
                }
            }
        }
        shared_state.forget_submitted_redemptions(&done);
        holding
    }

    /// Whether this cycle should recommit an unchanged digest (heartbeat): enabled, and the
    /// tracker box is at least `heartbeat_blocks` old at the node's current height. Only called
    /// when nothing is pending. A node error skips the heartbeat for this cycle.
    async fn heartbeat_now(config: &TrackerBoxUpdateConfig, tracker_box: &ErgoBoxApi) -> bool {
        if config.heartbeat_blocks == 0 {
            return false;
        }
        let current_height = match Self::get_node_height(config).await {
            Ok(h) => h as u64,
            Err(e) => {
                warn!(
                    "Heartbeat check skipped: cannot read the node height: {}",
                    e
                );
                return false;
            }
        };
        let creation_height = tracker_box.creation_height as u64;
        if !heartbeat_due(config.heartbeat_blocks, current_height, creation_height) {
            return false;
        }
        info!(
            "Heartbeat: tracker box {} is {} blocks old (created at {}, height {}, heartbeat_blocks {}); recommitting the current digest",
            tracker_box.box_id,
            current_height.saturating_sub(creation_height),
            creation_height,
            current_height,
            config.heartbeat_blocks
        );
        true
    }

    /// What the loop records about a commit found on chain
    /// (`GET /blockchain/transaction/byId/{tx_id}`): see [`ConfirmingTx`].
    async fn fetch_tracker_box_summary(
        config: &TrackerBoxUpdateConfig,
        tx_id: &str,
    ) -> Result<ConfirmingTx, TrackerBoxUpdaterError> {
        let client = basis_store::http::bounded_client();
        let url = format!(
            "{}/blockchain/transaction/byId/{}",
            config.scanner_node_url.trim_end_matches('/'),
            tx_id
        );

        let mut request = client.get(&url);
        if let Some(ref api_key) = config.scanner_api_key {
            request = request.header("api_key", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(TrackerBoxUpdaterError::HttpError(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let body: serde_json::Value = basis_store::http::read_json_capped(response)
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(format!("JSON parse error: {}", e)))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|e| {
                    TrackerBoxUpdaterError::HttpError(format!("JSON parse error: {}", e))
                })
            })?;
        Ok(ConfirmingTx::from_indexed_tx(&body, tx_id))
    }

    /// Fetch a reserve box's on-chain R5 digest from the node's UTXO set.
    ///
    /// Returns `Ok(None)` when the box is no longer unspent — a redemption,
    /// top-up, or refund completion spends the reserve box, so for the staged
    /// exchange integrity check (issue #17) a missing box is conclusive.
    /// Transport/parse errors return `Err` so the caller can distinguish
    /// "node unavailable" from "box spent" and skip rather than cancel.
    async fn fetch_reserve_box_r5(
        config: &TrackerBoxUpdateConfig,
        box_id: &str,
    ) -> Result<Option<[u8; 33]>, TrackerBoxUpdaterError> {
        let client = basis_store::http::bounded_client();
        let url = format!(
            "{}/utxo/byId/{}",
            config.scanner_node_url.trim_end_matches('/'),
            box_id
        );

        let mut request = client.get(&url);
        if let Some(ref api_key) = config.scanner_api_key {
            request = request.header("api_key", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(e.to_string()))?;

        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(TrackerBoxUpdaterError::HttpError(format!(
                "HTTP {} fetching reserve box {}",
                response.status(),
                box_id
            )));
        }

        let body: serde_json::Value = basis_store::http::read_json_capped(response)
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(format!("JSON parse error: {}", e)))?;

        // The R5 register holds the serialized AVL tree: one type byte followed
        // by the 33-byte root digest (same layout as the tracker box R5).
        let r5_hex = body
            .get("additionalRegisters")
            .and_then(|r| r.get("R5"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TrackerBoxUpdaterError::SerializationError(format!(
                    "reserve box {} has no R5 register",
                    box_id
                ))
            })?;
        let r5_bytes = hex::decode(r5_hex).map_err(|e| {
            TrackerBoxUpdaterError::SerializationError(format!(
                "reserve box {} has malformed R5 register: {}",
                box_id, e
            ))
        })?;
        if r5_bytes.len() < 34 {
            return Err(TrackerBoxUpdaterError::SerializationError(format!(
                "reserve box {} has truncated R5 register",
                box_id
            )));
        }
        let mut digest = [0u8; 33];
        digest.copy_from_slice(&r5_bytes[1..34]);
        Ok(Some(digest))
    }

    /// Issue #17 phase 2: apply or cancel staged exchanges now that tracker
    /// state has been confirmed on-chain.
    ///
    /// Lists the staged exchanges, observes each one's from-denomination
    /// reserve box on the node, and hands the observations to the tracker
    /// thread, which applies the to-edge increase only when the from-edge
    /// decrease is confirmed and the reserve is verified unchanged. A node
    /// error observing one reserve skips that exchange for this cycle (wait);
    /// it is retried on a later confirmation pass.
    async fn process_pending_exchanges(
        config: &TrackerBoxUpdateConfig,
        cmd_tx: &Option<tokio::sync::mpsc::Sender<crate::TrackerCommand>>,
    ) {
        let Some(tx) = cmd_tx else { return };

        let (rtx, rrx) = tokio::sync::oneshot::channel();
        if tx
            .send(crate::TrackerCommand::ListStagedExchanges { response_tx: rtx })
            .await
            .is_err()
        {
            return;
        }
        let staged = match rrx.await {
            Ok(Ok(staged)) => staged,
            Ok(Err(e)) => {
                error!("Failed to list staged exchanges: {:?}", e);
                return;
            }
            Err(_) => return,
        };
        if staged.is_empty() {
            return;
        }

        let mut observations = Vec::new();
        for exchange in &staged {
            match Self::fetch_reserve_box_r5(config, &exchange.reserve_box_id).await {
                Ok(digest) => observations.push(basis_store::ExchangeObservation {
                    key: exchange.key,
                    reserve_r5_digest: digest,
                }),
                Err(e) => {
                    // Leave this exchange staged; it is retried next cycle.
                    error!(
                        "Failed to observe reserve box {} for staged exchange {}: {}. Will retry.",
                        exchange.reserve_box_id,
                        hex::encode(exchange.key),
                        e
                    );
                }
            }
        }
        if observations.is_empty() {
            return;
        }

        let (rtx, rrx) = tokio::sync::oneshot::channel();
        let _ = tx
            .send(crate::TrackerCommand::ProcessStagedExchanges {
                observations,
                response_tx: rtx,
            })
            .await;
        match rrx.await {
            Ok(Ok(processed)) => {
                if processed.applied > 0 || processed.cancelled > 0 {
                    info!(
                        "Processed staged exchanges: {} applied, {} cancelled",
                        processed.applied, processed.cancelled
                    );
                }
            }
            Ok(Err(e)) => error!("Failed to process staged exchanges: {:?}", e),
            Err(_) => {}
        }
    }

    /// Find the tracker box on chain using the tracker NFT ID.
    ///
    /// Boxes whose `address` matches a configured reserve contract are skipped,
    /// because reserves store the tracker NFT in R6 and therefore appear in the
    /// `byTokenId` results.
    async fn find_tracker_box(
        config: &TrackerBoxUpdateConfig,
        tracker_nft_id: &str,
    ) -> Result<ErgoBoxApi, TrackerBoxUpdaterError> {
        let client = basis_store::http::bounded_client();
        let url = format!(
            "{}/blockchain/box/unspent/byTokenId/{}?limit=20",
            config.scanner_node_url.trim_end_matches('/'),
            tracker_nft_id
        );

        let mut request = client.get(&url);
        if let Some(ref api_key) = config.scanner_api_key {
            request = request.header("api_key", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(TrackerBoxUpdaterError::HttpError(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        let boxes: Vec<ErgoBoxApi> = basis_store::http::read_json_capped(response)
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(format!("JSON parse error: {}", e)))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|e| {
                    TrackerBoxUpdaterError::HttpError(format!("JSON parse error: {}", e))
                })
            })?;

        let excluded: std::collections::HashSet<&str> = config
            .reserve_contract_addresses
            .iter()
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .collect();

        let candidates: Vec<ErgoBoxApi> = boxes
            .into_iter()
            .filter(|b| {
                let addr = b.address.as_deref().unwrap_or("");
                !excluded.contains(addr)
            })
            .collect();

        if candidates.is_empty() {
            return Err(TrackerBoxUpdaterError::NoTrackerBoxFound);
        }

        // NFT singleton sanity check (issue #15 C4): the tracker NFT must be a
        // singleton (amount == 1) held by the tracker box. A non-singleton NFT or
        // a box not actually holding it is a setup error that breaks the
        // singleton guarantees the reserve contract relies on.
        for candidate in &candidates {
            match candidate
                .assets
                .iter()
                .find(|a| a.token_id == tracker_nft_id)
            {
                Some(asset) if asset.amount != 1 => {
                    error!(
                        "Tracker NFT {} has amount {} in box {} — expected a singleton (amount 1). \
                         This is a setup error: the tracker NFT must not be divisible.",
                        tracker_nft_id, asset.amount, candidate.box_id
                    );
                }
                None => {
                    warn!(
                        "Tracker box candidate {} does not hold tracker NFT {} in its assets",
                        candidate.box_id, tracker_nft_id
                    );
                }
                _ => {}
            }
        }

        if candidates.len() > 1 {
            warn!(
                "Found {} non-reserve tracker boxes for NFT {} - expected at most 1. \
                 Using the first box (box_id={}).",
                candidates.len(),
                tracker_nft_id,
                candidates[0].box_id
            );
        }

        Ok(candidates.into_iter().next().unwrap())
    }

    /// Token-free boxes at the tracker's own P2PK address, found through the public
    /// `POST /blockchain/box/unspent/byAddress` on the scanner node (no node wallet, no API
    /// key). Boxes already spent by a mempool transaction are skipped. Token-bearing boxes are
    /// never returned: the tracker box (with the tracker NFT) lives at the same address and
    /// must never be spent as a fee input.
    async fn find_fee_boxes(
        config: &TrackerBoxUpdateConfig,
        tracker_pubkey: &[u8; 33],
        tracker_box_id: &str,
        enough: u64,
    ) -> Result<Vec<crate::local_wallet::UnspentBox>, TrackerBoxUpdaterError> {
        use crate::local_wallet;

        let address = local_wallet::p2pk_address(tracker_pubkey)
            .map_err(TrackerBoxUpdaterError::SerializationError)?;
        let tree = local_wallet::p2pk_tree_hex(tracker_pubkey);
        let node = local_wallet::NodeEndpoint::new(
            &config.scanner_node_url,
            config.scanner_api_key.clone(),
        );
        let scan = local_wallet::scan_fee_boxes(&node, &address, &tree, &[tracker_box_id], enough)
            .await
            .map_err(TrackerBoxUpdaterError::HttpError)?;
        if scan.skipped_with_tokens > 1 {
            info!(
                "Fee box scan skipped {} token-bearing boxes at the tracker address (the tracker box is one of them)",
                scan.skipped_with_tokens
            );
        }
        if scan.truncated {
            warn!(
                "Fee box scan of the tracker address stopped after {} pages",
                local_wallet::BY_ADDRESS_MAX_PAGES
            );
        }
        Ok(scan.boxes)
    }

    /// Get the current blockchain height from the Ergo node.
    async fn get_node_height(
        config: &TrackerBoxUpdateConfig,
    ) -> Result<u32, TrackerBoxUpdaterError> {
        let client = basis_store::http::bounded_client();
        let url = format!("{}/info", config.scanner_node_url.trim_end_matches('/'));

        let mut request = client.get(&url);
        if let Some(ref api_key) = config.scanner_api_key {
            request = request.header("api_key", api_key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(TrackerBoxUpdaterError::HttpError(format!(
                "HTTP {} fetching node height: {}",
                status, body
            )));
        }

        let body: serde_json::Value = basis_store::http::read_json_capped(response)
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(format!("JSON parse error: {}", e)))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|e| {
                    TrackerBoxUpdaterError::HttpError(format!("JSON parse error: {}", e))
                })
            })?;

        body["fullHeight"]
            .as_u64()
            .map(|h| h as u32)
            .ok_or_else(|| TrackerBoxUpdaterError::HttpError("Missing fullHeight".to_string()))
    }

    /// Build, sign (locally, with `ergo.tracker_secret_key`) and broadcast the transaction that
    /// commits `avl_root_digest` to the tracker box. See [`build_tracker_commit_tx`] for its shape.
    ///
    /// Public node endpoints only: `/blocks/lastHeaders/10`, `/blockchain/box/unspent/byAddress`
    /// and `/utxo/byIdBinary/{id}` on the scanner node, `POST /transactions` on the broadcast node.
    async fn submit_tracker_update(
        tracker_nft_id: &str,
        config: &TrackerBoxUpdateConfig,
        tracker_box: &ErgoBoxApi,
        tracker_pubkey: &[u8; 33],
        avl_root_digest: &[u8; 33],
    ) -> Result<String, TrackerBoxUpdaterError> {
        use crate::local_wallet::{self, NodeEndpoint, TrackerKey};

        let secret = config.tracker_secret_key.as_ref().ok_or_else(|| {
            TrackerBoxUpdaterError::SigningFailed(
                "ergo.tracker_secret_key is not configured".to_string(),
            )
        })?;
        let key =
            TrackerKey::from_secret_bytes(secret).map_err(TrackerBoxUpdaterError::SigningFailed)?;
        if key.public_key() != *tracker_pubkey {
            return Err(TrackerBoxUpdaterError::SigningFailed(
                "ergo.tracker_secret_key does not belong to the tracker public key".to_string(),
            ));
        }

        let chain = NodeEndpoint::new(&config.scanner_node_url, config.scanner_api_key.clone());
        let state = local_wallet::fetch_state_context(&chain)
            .await
            .map_err(TrackerBoxUpdaterError::HttpError)?;
        let height = state.pre_header.height;

        let fee_boxes =
            Self::find_fee_boxes(config, tracker_pubkey, &tracker_box.box_id, config.fee).await?;
        let (fee_inputs, _) = match local_wallet::select_fee_boxes(&fee_boxes, config.fee) {
            Some(selected) => selected,
            None if fee_boxes.is_empty() => return Err(TrackerBoxUpdaterError::NoFeeInputs),
            None => {
                return Err(TrackerBoxUpdaterError::InsufficientFeeInputs {
                    available: fee_boxes
                        .iter()
                        .fold(0u64, |a, b| a.saturating_add(b.value)),
                    required: config.fee,
                })
            }
        };

        // Spend exactly what the UTXO set holds: the boxes are parsed from their bytes.
        let tracker_input = local_wallet::fetch_box(&chain, &tracker_box.box_id)
            .await
            .map_err(TrackerBoxUpdaterError::HttpError)?;
        let mut fee_input_boxes = Vec::with_capacity(fee_inputs.len());
        for fee_box in &fee_inputs {
            fee_input_boxes.push(
                local_wallet::fetch_box(&chain, &fee_box.box_id)
                    .await
                    .map_err(TrackerBoxUpdaterError::HttpError)?,
            );
        }

        let change_address = match &config.change_address {
            Some(addr) if !addr.is_empty() => addr.clone(),
            _ => derive_change_address(tracker_pubkey)?,
        };
        let change_tree = address_to_tree(&change_address)?;

        let commit = build_tracker_commit_tx(
            &tracker_input,
            &fee_input_boxes,
            tracker_nft_id,
            tracker_pubkey,
            avl_root_digest,
            config.fee,
            &change_tree,
            height,
        )?;

        let mut inputs = vec![tracker_input];
        inputs.extend(fee_input_boxes);
        check_commit_tx(&commit.unsigned, &inputs, tracker_nft_id)?;
        let signed = key
            .sign(commit.unsigned, inputs, Vec::new(), &state)
            .map_err(TrackerBoxUpdaterError::SigningFailed)?;
        info!(
            "Tracker update {} signed locally: {} inputs, {} outputs, fee {} nanoERG, change {} nanoERG, height {}",
            String::from(signed.id()),
            signed.inputs.len(),
            signed.outputs.len(),
            commit.fee,
            commit.change,
            height
        );

        let broadcast_node =
            NodeEndpoint::new(&config.wallet_node_url, config.wallet_api_key.clone());
        local_wallet::broadcast(&broadcast_node, &signed)
            .await
            .map_err(TrackerBoxUpdaterError::BroadcastFailed)
    }

    /// Where `tx_id` is. Mempools are read first (public
    /// `GET /transactions/unconfirmed/byTransactionId/{id}`): the node the transaction was
    /// broadcast to and, when that is another node, the scanner node. Then the chain
    /// (`GET /blockchain/transaction/byId/{id}` on the scanner node). In this order a
    /// transaction that moves from the mempool into a block between two reads is still found.
    /// Any answer other than 200 or 404 is an error: the status is unknown, not `Missing`.
    pub async fn check_transaction_confirmation(
        config: &TrackerBoxUpdateConfig,
        tx_id: &str,
    ) -> Result<TxStatus, TrackerBoxUpdaterError> {
        let scanner = (
            config.scanner_node_url.trim_end_matches('/'),
            config.scanner_api_key.as_deref(),
        );
        let broadcast = (
            config.wallet_node_url.trim_end_matches('/'),
            config.wallet_api_key.as_deref(),
        );
        let mut mempools = vec![scanner];
        if !broadcast.0.is_empty() && broadcast.0 != scanner.0 {
            mempools.insert(0, broadcast);
        }

        let in_mempool = format!("/transactions/unconfirmed/byTransactionId/{tx_id}");
        for (node, api_key) in mempools {
            if Self::node_knows(node, api_key, &in_mempool).await? {
                return Ok(TxStatus::InMempool);
            }
        }
        let on_chain = format!("/blockchain/transaction/byId/{tx_id}");
        if Self::node_knows(scanner.0, scanner.1, &on_chain).await? {
            return Ok(TxStatus::OnChain);
        }
        Ok(TxStatus::Missing)
    }

    /// `GET {node}{path}`: true on 200, false on 404, an error on anything else.
    async fn node_knows(
        node: &str,
        api_key: Option<&str>,
        path: &str,
    ) -> Result<bool, TrackerBoxUpdaterError> {
        let client = basis_store::http::bounded_client();
        let mut request = client.get(format!("{node}{path}"));
        if let Some(api_key) = api_key {
            request = request.header("api_key", api_key);
        }
        let response = request
            .send()
            .await
            .map_err(|e| TrackerBoxUpdaterError::HttpError(e.to_string()))?;
        match response.status().as_u16() {
            200 => Ok(true),
            404 => Ok(false),
            status => {
                let body = basis_store::http::read_body_capped(response)
                    .await
                    .unwrap_or_default();
                Err(TrackerBoxUpdaterError::HttpError(format!(
                    "HTTP {status} from {path}: {body}"
                )))
            }
        }
    }
}

/// Derive a P2PK change address from a compressed tracker public key.
fn derive_change_address(tracker_pubkey: &[u8; 33]) -> Result<String, TrackerBoxUpdaterError> {
    use ergo_lib::ergo_chain_types::EcPoint;
    use ergo_lib::ergotree_ir::chain::address::{Address, NetworkPrefix};
    use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
    use ergo_lib::ergotree_ir::sigma_protocol::sigma_boolean::ProveDlog;

    let ec_point = EcPoint::sigma_parse_bytes(tracker_pubkey).map_err(|e| {
        TrackerBoxUpdaterError::SerializationError(format!("Invalid tracker pubkey: {}", e))
    })?;
    let prove_dlog = ProveDlog::new(ec_point);
    let address = Address::P2Pk(prove_dlog);
    let encoder =
        ergo_lib::ergotree_ir::chain::address::AddressEncoder::new(NetworkPrefix::Mainnet);
    Ok(encoder.address_to_str(&address))
}

/// Convert a P2PK or P2S address string to its hex-encoded ergoTree bytes.
fn change_address_to_ergo_tree(address_str: &str) -> Result<String, TrackerBoxUpdaterError> {
    use ergo_lib::ergotree_ir::chain::address::{AddressEncoder, NetworkPrefix};
    use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

    let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
    let address = encoder.parse_address_from_str(address_str).map_err(|e| {
        TrackerBoxUpdaterError::SerializationError(format!(
            "Invalid address '{}': {}",
            address_str, e
        ))
    })?;
    let tree = address.script().map_err(|e| {
        TrackerBoxUpdaterError::SerializationError(format!(
            "Failed to get script for address '{}': {}",
            address_str, e
        ))
    })?;
    Ok(hex::encode(tree.sigma_serialize_bytes().map_err(|e| {
        TrackerBoxUpdaterError::SerializationError(format!("Failed to serialize ergoTree: {:?}", e))
    })?))
}

/// Parse a P2PK or P2S address into its ErgoTree.
fn address_to_tree(
    address_str: &str,
) -> Result<ergo_lib::ergotree_ir::ergo_tree::ErgoTree, TrackerBoxUpdaterError> {
    use ergo_lib::ergotree_ir::ergo_tree::ErgoTree;
    use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

    let tree_hex = change_address_to_ergo_tree(address_str)?;
    let bytes = hex::decode(&tree_hex)
        .map_err(|e| TrackerBoxUpdaterError::SerializationError(e.to_string()))?;
    ErgoTree::sigma_parse_bytes(&bytes).map_err(|e| {
        TrackerBoxUpdaterError::SerializationError(format!(
            "ErgoTree of address '{}': {}",
            address_str, e
        ))
    })
}

/// The unsigned transaction that commits a new AVL root digest, before signing.
pub(crate) struct CommitTx {
    pub unsigned: ergo_lib::chain::transaction::unsigned::UnsignedTransaction,
    /// Miner fee paid by the transaction.
    pub fee: u64,
    /// Value of the change output; 0 when there is none.
    pub change: u64,
}

/// R4 of the tracker box: `GroupElement(tracker pk)`, `07 ‖ pk33`.
pub(crate) fn tracker_r4_bytes(tracker_pubkey: &[u8; 33]) -> Vec<u8> {
    let mut bytes = vec![0x07u8];
    bytes.extend_from_slice(tracker_pubkey);
    bytes
}

/// R5 of the tracker box: `SAvlTree` with the given digest, insert + update allowed, 32-byte
/// keys, no fixed value length: `64 ‖ digest33 ‖ 03 ‖ 20 ‖ 00`.
pub(crate) fn tracker_r5_bytes(avl_root_digest: &[u8; 33]) -> Vec<u8> {
    let mut bytes = vec![0x64u8];
    bytes.extend_from_slice(avl_root_digest);
    bytes.push(0x03u8); // insert + update allowed (insertOrUpdate contract)
    bytes.extend_from_slice(&vlq_encode(32));
    bytes.extend_from_slice(&vlq_encode(0));
    bytes
}

/// R6 of the tracker box: the tracker NFT id as `Coll[Byte]`, `0e 20 ‖ id32`, so the tracker
/// scanner can identify the box.
pub(crate) fn tracker_r6_bytes(tracker_nft_id: &[u8; 32]) -> Vec<u8> {
    let mut bytes = vec![0x0eu8, 0x20u8];
    bytes.extend_from_slice(tracker_nft_id);
    bytes
}

/// Pre-signing assertions on a commit transaction: no token is burned, minted or changed
/// (every input token reaches the outputs with its full amount), and the tracker NFT appears
/// exactly once, first in output 0, with amount 1.
pub(crate) fn check_commit_tx(
    unsigned: &ergo_lib::chain::transaction::unsigned::UnsignedTransaction,
    inputs: &[ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox],
    tracker_nft_id: &str,
) -> Result<(), TrackerBoxUpdaterError> {
    let outputs = unsigned.output_candidates.as_vec();
    crate::local_wallet::check_tokens_preserved(inputs, outputs, None)
        .and_then(|()| crate::local_wallet::check_nft_only_in_output0(outputs, tracker_nft_id))
        .map_err(|e| {
            TrackerBoxUpdaterError::SigningFailed(format!("refusing to sign the commit: {e}"))
        })
}

/// Build the transaction that commits `avl_root_digest` to the tracker box.
///
/// - inputs: `[tracker box, fee boxes...]`, empty context extensions, no data inputs;
/// - output 0: the new tracker box: same value and script as the old one, created at
///   `height`, tracker NFT first and then the old box's other tokens, R4 = tracker pk,
///   R5 = AVL tree with `avl_root_digest`, R6 = tracker NFT id, any R7+ copied;
/// - output 1: the miner fee;
/// - output 2: change (fee inputs minus the fee) to `change_tree`, without tokens, whenever
///   value is left. A leftover below the minimum value of that change box (360 nanoERG per
///   serialized byte) cannot form a box; it is added to the miner fee instead.
///
/// Fee boxes must hold no token.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_tracker_commit_tx(
    tracker_box: &ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox,
    fee_boxes: &[ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox],
    tracker_nft_id: &str,
    tracker_pubkey: &[u8; 33],
    avl_root_digest: &[u8; 33],
    fee: u64,
    change_tree: &ergo_lib::ergotree_ir::ergo_tree::ErgoTree,
    height: u32,
) -> Result<CommitTx, TrackerBoxUpdaterError> {
    use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
    use ergo_lib::chain::transaction::UnsignedInput;
    use ergo_lib::ergotree_ir::chain::context_extension::ContextExtension;
    use ergo_lib::ergotree_ir::chain::ergo_box::{
        BoxTokens, ErgoBoxCandidate, NonMandatoryRegisterId, NonMandatoryRegisters,
    };
    use ergo_lib::ergotree_ir::chain::token::{Token, TokenId};
    use ergo_lib::ergotree_ir::mir::constant::Constant;
    use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
    use std::str::FromStr;

    let ser = |what: &str, e: String| {
        TrackerBoxUpdaterError::SerializationError(format!("commit tx {what}: {e}"))
    };

    let nft_bytes: [u8; 32] = hex::decode(tracker_nft_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            ser(
                "tracker NFT id",
                format!("not a 32-byte hex id: {tracker_nft_id}"),
            )
        })?;
    let nft =
        TokenId::from_str(tracker_nft_id).map_err(|e| ser("tracker NFT id", e.to_string()))?;

    // Registers: R4..R6 rewritten, anything above copied unchanged.
    let constant = |what: &str, bytes: Vec<u8>| {
        Constant::sigma_parse_bytes(&bytes).map_err(|e| ser(what, e.to_string()))
    };
    let mut registers = vec![
        constant("R4", tracker_r4_bytes(tracker_pubkey))?,
        constant("R5", tracker_r5_bytes(avl_root_digest))?,
        constant("R6", tracker_r6_bytes(&nft_bytes))?,
    ];
    for id in [
        NonMandatoryRegisterId::R7,
        NonMandatoryRegisterId::R8,
        NonMandatoryRegisterId::R9,
    ] {
        match tracker_box.additional_registers.get_constant(id) {
            Ok(Some(c)) => registers.push(c),
            Ok(None) => break,
            Err(e) => return Err(ser("tracker box register", format!("{id:?}: {e}"))),
        }
    }
    let registers =
        NonMandatoryRegisters::try_from(registers).map_err(|e| ser("registers", e.to_string()))?;

    // Tokens: the tracker NFT first, then the old tracker box's other tokens in order.
    let old_tokens: Vec<Token> = tracker_box
        .tokens
        .as_ref()
        .map(|t| t.as_vec().clone())
        .unwrap_or_default();
    let (nft_tokens, other_tokens): (Vec<Token>, Vec<Token>) =
        old_tokens.into_iter().partition(|t| t.token_id == nft);
    if nft_tokens.len() != 1 || u64::from(nft_tokens[0].amount) != 1 {
        return Err(ser(
            "tracker box",
            format!(
                "box {} must hold tracker NFT {} exactly once with amount 1",
                String::from(tracker_box.box_id()),
                tracker_nft_id
            ),
        ));
    }
    let mut new_tokens = nft_tokens;
    new_tokens.extend(other_tokens);
    let new_tokens = BoxTokens::from_vec(new_tokens).map_err(|e| ser("tokens", e.to_string()))?;

    if let Some(with_tokens) = fee_boxes.iter().find(|b| b.tokens.is_some()) {
        return Err(ser(
            "fee inputs",
            format!(
                "fee box {} holds tokens; fee boxes must be token-free",
                String::from(with_tokens.box_id())
            ),
        ));
    }
    let fee_total = fee_boxes
        .iter()
        .try_fold(0u64, |acc, b| acc.checked_add(*b.value.as_u64()))
        .ok_or_else(|| ser("fee inputs", "value overflow".to_string()))?;
    if fee_total < fee {
        return Err(TrackerBoxUpdaterError::InsufficientFeeInputs {
            available: fee_total,
            required: fee,
        });
    }
    let leftover = fee_total - fee;

    // Change whenever value is left; only dust that cannot form a box goes to the miner.
    let change_output = crate::local_wallet::change_output(leftover, change_tree, height)
        .map_err(|e| ser("change", e))?;
    let (fee, change) = match change_output {
        Some(_) => (fee, leftover),
        None => (fee + leftover, 0),
    };

    let mut outputs = vec![
        ErgoBoxCandidate {
            value: tracker_box.value,
            ergo_tree: tracker_box.ergo_tree.clone(),
            tokens: Some(new_tokens),
            additional_registers: registers,
            creation_height: height,
        },
        crate::local_wallet::miner_fee_output(fee, height).map_err(|e| ser("fee", e))?,
    ];
    outputs.extend(change_output);

    let mut inputs = vec![UnsignedInput::new(
        tracker_box.box_id(),
        ContextExtension::empty(),
    )];
    for fee_box in fee_boxes {
        inputs.push(UnsignedInput::new(
            fee_box.box_id(),
            ContextExtension::empty(),
        ));
    }
    let unsigned = UnsignedTransaction::new_from_vec(inputs, Vec::new(), outputs)
        .map_err(|e| ser("transaction", e.to_string()))?;
    Ok(CommitTx {
        unsigned,
        fee,
        change,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confirmation_depth_current_tip() {
        // Transaction in the current tip has depth 1.
        assert_eq!(confirmation_depth(100, 100), 1);
    }

    #[test]
    fn test_confirmation_depth_one_block_back() {
        assert_eq!(confirmation_depth(101, 100), 2);
    }

    #[test]
    fn test_confirmation_depth_unknown_height() {
        // An inclusion height of 0 is treated as unknown.
        assert_eq!(confirmation_depth(100, 0), 0);
    }

    #[test]
    fn test_confirmation_depth_does_not_underflow() {
        // If current height somehow lags inclusion height, depth is at least 1.
        assert_eq!(confirmation_depth(100, 200), 1);
    }

    #[test]
    fn test_tracker_box_update_config_default_depth() {
        let config = TrackerBoxUpdateConfig::default();
        assert_eq!(config.min_confirmation_depth, 2);
    }

    /// Issue #15 S6: a dropped/rejected update transaction must not block future
    /// updates forever — after a bounded number of consecutive missing cycles the
    /// pending state is reverted.
    #[test]
    fn test_pending_tx_drop_detection_is_bounded() {
        assert!(!pending_tx_is_dropped(0));
        assert!(!pending_tx_is_dropped(1));
        assert!(!pending_tx_is_dropped(MAX_PENDING_MISSING_CYCLES - 1));
        assert!(pending_tx_is_dropped(MAX_PENDING_MISSING_CYCLES));
        assert!(pending_tx_is_dropped(MAX_PENDING_MISSING_CYCLES + 10));
    }

    /// Issue #15 S6: a confirmed tracker box that disappears from the NFT scan is
    /// treated as orphaned (reorg) and triggers re-sync; the same box id or no
    /// prior confirmation does not.
    #[test]
    fn test_confirmed_box_orphaned_detection() {
        assert!(!confirmed_box_orphaned(None, "box_a"));
        assert!(!confirmed_box_orphaned(Some("box_a"), "box_a"));
        assert!(confirmed_box_orphaned(Some("box_a"), "box_b"));
    }

    /// Fee boxes come from the public byAddress index on the scanner node, never from the
    /// wallet node, and the tracker box (token-bearing) is never offered as a fee input.
    #[tokio::test]
    async fn fee_boxes_come_from_by_address_and_skip_the_tracker_box() {
        use crate::local_wallet::tests::{mock_node, PK};
        let tree = crate::local_wallet::p2pk_tree_hex(&PK);
        let tree_for_node = tree.clone();
        let tracker_box_id = "ab".repeat(32);
        let tracker_box_for_node = tracker_box_id.clone();
        let (url, seen) = mock_node(move |_, target, _| {
            if target.contains("offset=0") {
                let page = serde_json::json!([
                    {
                        "boxId": tracker_box_for_node,
                        "value": 1_000_000u64,
                        "ergoTree": tree_for_node,
                        "assets": [{ "tokenId": "11".repeat(32), "amount": 1 }],
                        "additionalRegisters": {},
                        "creationHeight": 10
                    },
                    {
                        "boxId": "cd".repeat(32),
                        "value": 3_000_000u64,
                        "ergoTree": tree_for_node,
                        "assets": [],
                        "additionalRegisters": {},
                        "creationHeight": 11
                    }
                ]);
                (200, page.to_string())
            } else {
                (200, "[]".to_string())
            }
        })
        .await;

        let config = TrackerBoxUpdateConfig {
            // Unreachable: any wallet-node call would fail the test.
            wallet_node_url: "http://127.0.0.1:1".to_string(),
            scanner_node_url: url,
            ..Default::default()
        };
        let boxes = TrackerBoxUpdater::find_fee_boxes(&config, &PK, &tracker_box_id, 1_000_000)
            .await
            .unwrap();
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes[0].box_id, "cd".repeat(32));
        assert!(boxes.iter().all(|b| b.assets.is_empty()));

        let seen = seen.lock().unwrap().clone();
        assert!(seen
            .iter()
            .all(|r| r.method == "POST"
                && r.target.starts_with("/blockchain/box/unspent/byAddress?")));
        let expected_address = crate::local_wallet::p2pk_address(&PK).unwrap();
        assert_eq!(seen[0].body, format!("\"{expected_address}\""));
    }

    /// Round 4: the startup retry stops once the tracker box was recorded, and after the
    /// window.
    #[test]
    fn startup_retries_stop_after_the_window_or_once_the_box_is_recorded() {
        assert!(startup_retry_due(Duration::ZERO, false));
        assert!(startup_retry_due(
            STARTUP_RETRY_WINDOW - STARTUP_RETRY_DELAY,
            false
        ));
        assert!(!startup_retry_due(
            STARTUP_RETRY_WINDOW - STARTUP_RETRY_DELAY + Duration::from_millis(1),
            false
        ));
        assert!(!startup_retry_due(Duration::ZERO, true));
    }

    /// Round 4: after a start, a cycle that ends because the AVL digest is not initialized yet
    /// (the tracker thread still loading the tree) is retried after 5 s, not after the full
    /// 600 s interval, so the tracker box that `/reserves/create` waits for is recorded within
    /// seconds of a restart.
    #[tokio::test]
    async fn a_skipped_first_cycle_is_retried_within_seconds() {
        use crate::local_wallet::tests::{mock_node, PK};
        let nft = "5a".repeat(32);
        let box_id = "ab".repeat(32);
        let digest = [0x01u8; 33];
        // R5: AvlTree type, digest, flags, key length.
        let r5 = format!("64{}0720", hex::encode(digest));
        let tree = crate::local_wallet::p2pk_tree_hex(&PK);
        let (nft_node, box_node) = (nft.clone(), box_id.clone());
        let (url, seen) = mock_node(move |_, target, _| {
            if target.starts_with(&format!("/blockchain/box/unspent/byTokenId/{nft_node}")) {
                let page = serde_json::json!([{
                    "boxId": box_node,
                    "value": 1_000_000u64,
                    "ergoTree": tree,
                    "assets": [{ "tokenId": nft_node, "amount": 1 }],
                    "additionalRegisters": { "R5": r5 },
                    "creationHeight": 10
                }]);
                (200, page.to_string())
            } else {
                (404, "{}".to_string())
            }
        })
        .await;
        let config = TrackerBoxUpdateConfig {
            wallet_node_url: "http://127.0.0.1:1".to_string(),
            scanner_node_url: url,
            update_interval_seconds: 600,
            heartbeat_blocks: 0,
            ..Default::default()
        };
        let shared = SharedTrackerState::new();
        shared.set_tracker_nft_id(nft);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let updater = tokio::spawn(TrackerBoxUpdater::start(
            config,
            shared.clone(),
            shutdown_rx,
            None,
        ));

        // The first cycle runs at once and finds no digest.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(shared.get_confirmed().box_id.is_none());
        shared.set_avl_root_digest(digest);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while shared.get_confirmed().box_id.is_none() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the skipped first cycle was not retried within 10 s"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(shared.get_confirmed().box_id.as_deref(), Some(box_id.as_str()));
        assert_eq!(shared.get_confirmed().digest, Some(digest));

        let _ = shutdown_tx.send(());
        updater.await.unwrap().unwrap();
        // One lookup: the first cycle stopped before it, the retry made it, and the next
        // regular cycle is a full interval away.
        let lookups = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.target.contains("byTokenId"))
            .count();
        assert_eq!(lookups, 1);
    }

    /// Fixture for the commit transaction: a tracker box at P2PK(fresh key) holding the NFT, as
    /// `init-box` creates it, plus its API view.
    pub(crate) struct CommitFixture {
        pub secret: [u8; 32],
        pub pubkey: [u8; 33],
        pub nft: [u8; 32],
        pub tracker_box: ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox,
        pub tracker_api: ErgoBoxApi,
    }

    pub(crate) fn commit_fixture(extra_tokens: &[([u8; 32], u64)]) -> CommitFixture {
        use crate::local_wallet::tests::{fresh_key, tree_of, utxo_box};
        use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

        let (secret, key) = fresh_key();
        let pubkey = key.public_key();
        let nft = [0x11u8; 32];
        let mut tokens = vec![(nft, 1u64)];
        tokens.extend_from_slice(extra_tokens);
        let r4 = hex::encode(tracker_r4_bytes(&pubkey));
        let r5 = basis_store::ergo_scanner::empty_reserve_tree_register();
        let r6 = hex::encode(tracker_r6_bytes(&nft));
        let tracker_box = utxo_box(
            &tree_of(&pubkey),
            1_000_000,
            &tokens,
            &[&r4, &r5, &r6],
            123_000,
            0,
        );
        let tracker_api = ErgoBoxApi {
            box_id: String::from(tracker_box.box_id()),
            value: 1_000_000,
            ergo_tree: crate::local_wallet::p2pk_tree_hex(&pubkey),
            assets: tokens
                .iter()
                .map(|(id, amount)| AssetApi {
                    token_id: hex::encode(id),
                    amount: *amount,
                })
                .collect(),
            additional_registers: [("R4", r4), ("R5", r5), ("R6", r6)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            creation_height: 123_000,
            address: None,
        };
        let _ = tracker_box.sigma_serialize_bytes().unwrap();
        CommitFixture {
            secret,
            pubkey,
            nft,
            tracker_box,
            tracker_api,
        }
    }

    /// The whole commit path against a mock node: headers, byAddress, byIdBinary and
    /// POST /transactions only; the transaction is signed in-process and valid.
    #[tokio::test]
    async fn commit_is_signed_locally_and_uses_public_endpoints_only() {
        use crate::local_wallet::tests::{mock_node, tree_of, utxo_box, LAST_HEADERS_JSON};
        use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

        let fx = commit_fixture(&[]);
        let tree = tree_of(&fx.pubkey);
        let fee_box = utxo_box(&tree, 5_000_000, &[], &[], 123_100, 1);
        let fee_box_id = String::from(fee_box.box_id());
        let tracker_box_id = fx.tracker_api.box_id.clone();

        let binaries: std::collections::HashMap<String, String> = [
            (
                tracker_box_id.clone(),
                hex::encode(fx.tracker_box.sigma_serialize_bytes().unwrap()),
            ),
            (
                fee_box_id.clone(),
                hex::encode(fee_box.sigma_serialize_bytes().unwrap()),
            ),
        ]
        .into_iter()
        .collect();
        let tree_hex = crate::local_wallet::p2pk_tree_hex(&fx.pubkey);
        let page = serde_json::json!([
            {
                "boxId": tracker_box_id,
                "value": 1_000_000u64,
                "ergoTree": tree_hex,
                "assets": [{ "tokenId": hex::encode(fx.nft), "amount": 1 }],
                "additionalRegisters": {},
                "creationHeight": 123_000
            },
            {
                "boxId": fee_box_id,
                "value": 5_000_000u64,
                "ergoTree": tree_hex,
                "assets": [],
                "additionalRegisters": {},
                "creationHeight": 123_100
            }
        ])
        .to_string();

        let (url, seen) = mock_node(move |method, target, body| {
            let path = target.split('?').next().unwrap_or_default();
            match (method, path) {
                ("GET", "/blocks/lastHeaders/10") => (200, LAST_HEADERS_JSON.to_string()),
                ("POST", "/blockchain/box/unspent/byAddress") => {
                    if target.contains("offset=0&") {
                        (200, page.clone())
                    } else {
                        (200, "[]".to_string())
                    }
                }
                ("GET", p) if p.starts_with("/utxo/byIdBinary/") => {
                    let id = p.trim_start_matches("/utxo/byIdBinary/");
                    match binaries.get(id) {
                        Some(bytes) => (
                            200,
                            serde_json::json!({ "boxId": id, "bytes": bytes }).to_string(),
                        ),
                        None => (404, "{}".to_string()),
                    }
                }
                ("POST", "/transactions") => {
                    let v: serde_json::Value = serde_json::from_str(body).unwrap();
                    (
                        200,
                        serde_json::Value::String(v["id"].as_str().unwrap().to_string())
                            .to_string(),
                    )
                }
                _ => (500, format!("unexpected {method} {target}")),
            }
        })
        .await;

        let config = TrackerBoxUpdateConfig {
            wallet_node_url: url.clone(),
            scanner_node_url: url,
            tracker_secret_key: Some(fx.secret),
            fee: 1_000_000,
            ..Default::default()
        };
        let new_digest = [0x42u8; 33];
        let tx_id = TrackerBoxUpdater::submit_tracker_update(
            &hex::encode(fx.nft),
            &config,
            &fx.tracker_api,
            &fx.pubkey,
            &new_digest,
        )
        .await
        .unwrap();

        let seen = seen.lock().unwrap().clone();
        for request in &seen {
            assert!(
                !request.target.starts_with("/wallet") && !request.target.starts_with("/utils"),
                "non-public endpoint used: {}",
                request.target
            );
            assert!(
                !request.body.contains(&hex::encode(fx.secret)),
                "secret left the process"
            );
            assert!(!request.headers.to_ascii_lowercase().contains("api_key"));
        }
        let posted = seen
            .iter()
            .find(|r| r.target == "/transactions")
            .expect("transaction broadcast");
        let tx: serde_json::Value = serde_json::from_str(&posted.body).unwrap();
        assert_eq!(tx["id"].as_str().unwrap(), tx_id);

        // Inputs: tracker box first, then the fee box, each with a proof.
        let inputs = tx["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0]["boxId"], tracker_box_id);
        assert_eq!(inputs[1]["boxId"], fee_box_id);
        for input in inputs {
            assert!(!input["spendingProof"]["proofBytes"]
                .as_str()
                .unwrap()
                .is_empty());
        }
        assert!(tx["dataInputs"].as_array().unwrap().is_empty());

        // Output 0: the new tracker box.
        let outputs = tx["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 3);
        let out0 = &outputs[0];
        assert_eq!(out0["value"], 1_000_000u64);
        assert_eq!(out0["ergoTree"], tree_hex);
        assert_eq!(out0["creationHeight"], 123_414);
        assert_eq!(out0["assets"][0]["tokenId"], hex::encode(fx.nft));
        assert_eq!(out0["assets"][0]["amount"], 1);
        assert_eq!(out0["assets"].as_array().unwrap().len(), 1);
        let regs = &out0["additionalRegisters"];
        assert_eq!(regs["R4"], format!("07{}", hex::encode(fx.pubkey)));
        assert_eq!(regs["R5"], format!("64{}032000", hex::encode(new_digest)));
        assert_eq!(regs["R6"], format!("0e20{}", hex::encode(fx.nft)));

        // Output 1: the miner fee; output 2: change back to the tracker address.
        assert_eq!(outputs[1]["value"], 1_000_000u64);
        assert_eq!(
            outputs[1]["ergoTree"],
            ergo_lib::wallet::miner_fee::MINERS_FEE_BASE16_BYTES
        );
        assert_eq!(outputs[2]["value"], 4_000_000u64);
        assert_eq!(outputs[2]["ergoTree"], tree_hex);
        assert!(outputs[2]["assets"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn commit_without_secret_key_fails_before_any_request() {
        let fx = commit_fixture(&[]);
        let config = TrackerBoxUpdateConfig {
            wallet_node_url: "http://127.0.0.1:1".to_string(),
            scanner_node_url: "http://127.0.0.1:1".to_string(),
            tracker_secret_key: None,
            ..Default::default()
        };
        let err = TrackerBoxUpdater::submit_tracker_update(
            &hex::encode(fx.nft),
            &config,
            &fx.tracker_api,
            &fx.pubkey,
            &[0x42u8; 33],
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("tracker_secret_key"), "{err}");

        // A key that is not the tracker's is refused too.
        let (other_secret, _) = basis_store::schnorr::generate_keypair();
        let config = TrackerBoxUpdateConfig {
            tracker_secret_key: Some(other_secret),
            ..config
        };
        let err = TrackerBoxUpdater::submit_tracker_update(
            &hex::encode(fx.nft),
            &config,
            &fx.tracker_api,
            &fx.pubkey,
            &[0x42u8; 33],
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("does not belong"), "{err}");
    }

    #[test]
    fn tracker_box_must_be_p2pk_of_the_tracker_key() {
        let (_, pubkey) = basis_store::schnorr::generate_keypair();
        let (_, other) = basis_store::schnorr::generate_keypair();
        let own = crate::local_wallet::p2pk_tree_hex(&pubkey);
        assert!(tracker_box_is_p2pk_of(&own, &pubkey));
        assert!(tracker_box_is_p2pk_of(&own.to_uppercase(), &pubkey));
        assert!(!tracker_box_is_p2pk_of(
            &crate::local_wallet::p2pk_tree_hex(&other),
            &pubkey
        ));
        // A script that merely contains the key is not P2PK of it.
        assert!(!tracker_box_is_p2pk_of(&format!("{own}00"), &pubkey));
        assert!(!tracker_box_is_p2pk_of(
            ergo_lib::wallet::miner_fee::MINERS_FEE_BASE16_BYTES,
            &pubkey
        ));
    }

    #[test]
    fn updater_config_debug_redacts_the_secret() {
        let secret = [0x5cu8; 32];
        let config = TrackerBoxUpdateConfig {
            tracker_secret_key: Some(secret),
            wallet_api_key: Some("wallet-key".to_string()),
            scanner_node_url: "http://op:url-password@scanner.example:9053".to_string(),
            ..Default::default()
        };
        let printed = format!("{config:?}");
        assert!(!printed.contains(&hex::encode(secret)));
        assert!(!printed.contains("92, 92, 92"), "{printed}");
        assert!(!printed.contains("wallet-key"));
        assert!(!printed.contains("url-password"), "{printed}");
        assert!(
            printed.contains("tracker_secret_key: <redacted>"),
            "{printed}"
        );
        assert!(printed.contains("wallet_api_key: <redacted>"), "{printed}");
        assert!(printed.contains("scanner_api_key: None"), "{printed}");
        assert!(
            printed.contains("<redacted>@scanner.example:9053"),
            "{printed}"
        );
    }

    #[test]
    fn heartbeat_is_due_at_heartbeat_blocks_and_disabled_by_zero() {
        assert!(!heartbeat_due(720, 1_000 + 719, 1_000));
        assert!(heartbeat_due(720, 1_000 + 720, 1_000));
        assert!(heartbeat_due(720, 1_000 + 2_000, 1_000));
        // 0 disables, whatever the age.
        assert!(!heartbeat_due(0, 1_000_000, 1_000));
        // A box newer than the node's tip (node behind) is never due.
        assert!(!heartbeat_due(720, 900, 1_000));
        assert_eq!(TrackerBoxUpdateConfig::default().heartbeat_blocks, 720);
    }

    /// The heartbeat asks the node for its height (public `/info`) and fires only when the
    /// box is old enough; heartbeat_blocks = 0 never calls the node.
    #[tokio::test]
    async fn heartbeat_now_reads_the_node_height() {
        use crate::local_wallet::tests::mock_node;
        let (url, seen) =
            mock_node(|_, _, _| (200, serde_json::json!({ "fullHeight": 1_720 }).to_string()))
                .await;
        let fx = commit_fixture(&[]);
        let mut tracker_box = fx.tracker_api;
        tracker_box.creation_height = 1_000;

        let config = TrackerBoxUpdateConfig {
            scanner_node_url: url,
            heartbeat_blocks: 720,
            ..Default::default()
        };
        assert!(TrackerBoxUpdater::heartbeat_now(&config, &tracker_box).await);
        let config = TrackerBoxUpdateConfig {
            heartbeat_blocks: 721,
            ..config
        };
        assert!(!TrackerBoxUpdater::heartbeat_now(&config, &tracker_box).await);
        assert_eq!(seen.lock().unwrap().len(), 2);
        assert!(seen.lock().unwrap().iter().all(|r| r.target == "/info"));

        let config = TrackerBoxUpdateConfig {
            heartbeat_blocks: 0,
            ..config
        };
        assert!(!TrackerBoxUpdater::heartbeat_now(&config, &tracker_box).await);
        assert_eq!(
            seen.lock().unwrap().len(),
            2,
            "disabled heartbeat must not call the node"
        );
    }

    fn build_for_test(
        fx: &CommitFixture,
        fee_values: &[u64],
        fee: u64,
    ) -> (
        CommitTx,
        Vec<ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox>,
    ) {
        use crate::local_wallet::tests::{tree_of, utxo_box};
        let tree = tree_of(&fx.pubkey);
        let fee_boxes: Vec<_> = fee_values
            .iter()
            .enumerate()
            .map(|(i, v)| utxo_box(&tree, *v, &[], &[], 123_100, 1 + i as u16))
            .collect();
        let commit = build_tracker_commit_tx(
            &fx.tracker_box,
            &fee_boxes,
            &hex::encode(fx.nft),
            &fx.pubkey,
            &[0x42u8; 33],
            fee,
            &tree,
            123_414,
        )
        .unwrap();
        let mut inputs = vec![fx.tracker_box.clone()];
        inputs.extend(fee_boxes);
        (commit, inputs)
    }

    fn output_values(commit: &CommitTx) -> Vec<u64> {
        commit
            .unsigned
            .output_candidates
            .iter()
            .map(|o| *o.value.as_u64())
            .collect()
    }

    #[test]
    fn commit_keeps_change_and_folds_only_dust() {
        let fx = commit_fixture(&[]);
        let fee = 1_000_000;

        // Plenty left: a change output with all of it.
        let (commit, _) = build_for_test(&fx, &[5_000_000], fee);
        assert_eq!(output_values(&commit), vec![1_000_000, fee, 4_000_000]);
        assert_eq!((commit.fee, commit.change), (fee, 4_000_000));

        // Exactly the fee: no change, no folding.
        let (commit, _) = build_for_test(&fx, &[fee], fee);
        assert_eq!(output_values(&commit), vec![1_000_000, fee]);
        assert_eq!((commit.fee, commit.change), (fee, 0));

        // The smallest change box the node accepts is still created.
        let change_box = |v: u64| {
            use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
            use ergo_lib::ergotree_ir::chain::ergo_box::{ErgoBoxCandidate, NonMandatoryRegisters};
            ErgoBoxCandidate {
                value: BoxValue::try_from(v).unwrap(),
                ergo_tree: crate::local_wallet::tests::tree_of(&fx.pubkey),
                tokens: None,
                additional_registers: NonMandatoryRegisters::empty(),
                creation_height: 123_414,
            }
        };
        let min = crate::local_wallet::min_box_value(&change_box(20_000)).unwrap();
        assert!(
            min > 10_000 && min < 30_000,
            "P2PK change box minimum {min}"
        );
        let (commit, _) = build_for_test(&fx, &[fee + min], fee);
        assert_eq!(output_values(&commit), vec![1_000_000, fee, min]);

        // Dust below the minimum goes to the miner; ERG is conserved either way.
        let (commit, _) = build_for_test(&fx, &[fee + min - 1], fee);
        assert_eq!(output_values(&commit), vec![1_000_000, fee + min - 1]);
        assert_eq!((commit.fee, commit.change), (fee + min - 1, 0));
        let (commit, _) = build_for_test(&fx, &[fee + 5], fee);
        assert_eq!(output_values(&commit), vec![1_000_000, fee + 5]);

        // Both shapes sign and pass full validation (no dust output, ERG preserved).
        let key = crate::local_wallet::TrackerKey::from_secret_bytes(&fx.secret).unwrap();
        let state = crate::local_wallet::tests::fixture_state();
        for fee_inputs in [vec![fee + min], vec![fee + min - 1], vec![600_000, 400_005]] {
            let (commit, inputs) = build_for_test(&fx, &fee_inputs, fee);
            key.sign(commit.unsigned, inputs, vec![], &state).unwrap();
        }
    }

    #[test]
    fn commit_refuses_token_fee_boxes_and_insufficient_fees() {
        use crate::local_wallet::tests::{tree_of, utxo_box};
        let fx = commit_fixture(&[]);
        let tree = tree_of(&fx.pubkey);
        let token_box = utxo_box(&tree, 5_000_000, &[([0x77; 32], 10)], &[], 123_100, 1);
        let err = build_tracker_commit_tx(
            &fx.tracker_box,
            &[token_box],
            &hex::encode(fx.nft),
            &fx.pubkey,
            &[0x42u8; 33],
            1_000_000,
            &tree,
            123_414,
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("token-free"), "{err}");

        let small = utxo_box(&tree, 500_000, &[], &[], 123_100, 1);
        let err = build_tracker_commit_tx(
            &fx.tracker_box,
            &[small],
            &hex::encode(fx.nft),
            &fx.pubkey,
            &[0x42u8; 33],
            1_000_000,
            &tree,
            123_414,
        )
        .err()
        .unwrap();
        assert!(matches!(
            err,
            TrackerBoxUpdaterError::InsufficientFeeInputs { .. }
        ));
    }

    #[test]
    fn commit_keeps_every_tracker_box_token_and_puts_the_nft_first() {
        // The tracker box also holds another token, listed before the NFT.
        let other = [0x33u8; 32];
        let mut fx = commit_fixture(&[(other, 5)]);
        {
            use crate::local_wallet::tests::{tree_of, utxo_box};
            let r4 = hex::encode(tracker_r4_bytes(&fx.pubkey));
            let r5 = basis_store::ergo_scanner::empty_reserve_tree_register();
            let r6 = hex::encode(tracker_r6_bytes(&fx.nft));
            fx.tracker_box = utxo_box(
                &tree_of(&fx.pubkey),
                1_000_000,
                &[(other, 5), (fx.nft, 1)],
                &[&r4, &r5, &r6],
                123_000,
                0,
            );
        }
        let (commit, inputs) = build_for_test(&fx, &[5_000_000], 1_000_000);
        let out0 = &commit.unsigned.output_candidates.as_vec()[0];
        let tokens: Vec<(String, u64)> = out0
            .tokens
            .as_ref()
            .unwrap()
            .iter()
            .map(|t| (String::from(t.token_id), u64::from(t.amount)))
            .collect();
        assert_eq!(
            tokens,
            vec![(hex::encode(fx.nft), 1), (hex::encode(other), 5)]
        );
        check_commit_tx(&commit.unsigned, &inputs, &hex::encode(fx.nft)).unwrap();
    }

    #[test]
    fn pre_signing_check_rejects_burns_mints_and_misplaced_nfts() {
        use crate::local_wallet::tests::{tree_of, utxo_box};
        use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
        use ergo_lib::ergotree_ir::chain::ergo_box::{BoxTokens, ErgoBoxCandidate};
        use ergo_lib::ergotree_ir::chain::token::{Token, TokenAmount, TokenId};
        use std::str::FromStr;

        let other = [0x33u8; 32];
        let fx = commit_fixture(&[(other, 5)]);
        let nft_hex = hex::encode(fx.nft);
        let (commit, inputs) = build_for_test(&fx, &[5_000_000], 1_000_000);
        check_commit_tx(&commit.unsigned, &inputs, &nft_hex).unwrap();

        let token = |id: [u8; 32], amount: u64| Token {
            token_id: TokenId::from_str(&hex::encode(id)).unwrap(),
            amount: TokenAmount::try_from(amount).unwrap(),
        };
        let with_outputs = |edit: &dyn Fn(&mut Vec<ErgoBoxCandidate>)| {
            let mut outputs = commit.unsigned.output_candidates.as_vec().clone();
            edit(&mut outputs);
            UnsignedTransaction::new_from_vec(
                commit.unsigned.inputs.as_vec().clone(),
                vec![],
                outputs,
            )
            .unwrap()
        };
        let rejects = |tx: UnsignedTransaction, needle: &str| {
            let err = check_commit_tx(&tx, &inputs, &nft_hex)
                .unwrap_err()
                .to_string();
            assert!(err.contains(needle), "expected '{needle}' in: {err}");
        };

        // Burning the other token (output 0 keeps only the NFT).
        rejects(
            with_outputs(&|o| {
                o[0].tokens = Some(BoxTokens::from_vec(vec![token(fx.nft, 1)]).unwrap())
            }),
            "would be burned",
        );
        // Burning the NFT.
        rejects(
            with_outputs(&|o| {
                o[0].tokens = Some(BoxTokens::from_vec(vec![token(other, 5)]).unwrap())
            }),
            "would be burned",
        );
        // NFT moved to the change output.
        rejects(
            with_outputs(&|o| {
                o[0].tokens = Some(BoxTokens::from_vec(vec![token(other, 5)]).unwrap());
                o[2].tokens = Some(BoxTokens::from_vec(vec![token(fx.nft, 1)]).unwrap());
            }),
            "must appear once",
        );
        // NFT not first in output 0.
        rejects(
            with_outputs(&|o| {
                o[0].tokens =
                    Some(BoxTokens::from_vec(vec![token(other, 5), token(fx.nft, 1)]).unwrap())
            }),
            "must appear once",
        );
        // A token that no input holds.
        rejects(
            with_outputs(&|o| {
                o[2].tokens = Some(BoxTokens::from_vec(vec![token([0x99; 32], 1)]).unwrap())
            }),
            "in no input",
        );

        // An input token missing from the outputs because a token-bearing box was added as
        // an input: refused before signing.
        let mut more_inputs = inputs.clone();
        more_inputs.push(utxo_box(
            &tree_of(&fx.pubkey),
            1_000_000,
            &[([0x55; 32], 7)],
            &[],
            123_100,
            9,
        ));
        let err = check_commit_tx(&commit.unsigned, &more_inputs, &nft_hex)
            .unwrap_err()
            .to_string();
        assert!(err.contains("would be burned"), "{err}");
    }

    const MEMPOOL_LOOKUP: &str = "/transactions/unconfirmed/byTransactionId/";
    const CHAIN_LOOKUP: &str = "/blockchain/transaction/byId/";

    /// Two nodes that know a transaction id by name: `pool-<node>` (or `pool-both`) is in that
    /// node's mempool, `chain` is in a block, `broken` makes the mempool lookup fail.
    #[tokio::test]
    async fn transaction_status_reads_the_mempools_before_the_chain() {
        use crate::local_wallet::tests::mock_node;

        let node = |name: &'static str| {
            mock_node(move |_, target, _| {
                let id = target.rsplit('/').next().unwrap_or_default();
                if target.starts_with(MEMPOOL_LOOKUP) {
                    match id {
                        "broken" => (503, "busy".to_string()),
                        _ if id == format!("pool-{name}") || id == "pool-both" => {
                            (200, "{}".to_string())
                        }
                        _ => (404, "{}".to_string()),
                    }
                } else if target.starts_with(CHAIN_LOOKUP) && id == "chain" {
                    (200, "{}".to_string())
                } else if target.starts_with(CHAIN_LOOKUP) {
                    (404, "{}".to_string())
                } else {
                    (500, format!("unexpected {target}"))
                }
            })
        };
        let (scanner_url, scanner_seen) = node("scanner").await;
        let (broadcast_url, broadcast_seen) = node("broadcast").await;
        let config = TrackerBoxUpdateConfig {
            scanner_node_url: scanner_url.clone(),
            wallet_node_url: broadcast_url,
            ..Default::default()
        };
        let status = |id: &'static str| {
            let config = config.clone();
            async move { TrackerBoxUpdater::check_transaction_confirmation(&config, id).await }
        };

        assert_eq!(status("pool-broadcast").await.unwrap(), TxStatus::InMempool);
        assert_eq!(status("pool-scanner").await.unwrap(), TxStatus::InMempool);
        assert_eq!(status("chain").await.unwrap(), TxStatus::OnChain);
        assert_eq!(status("gone").await.unwrap(), TxStatus::Missing);
        // An unknown status is an error, so it never counts as a missing cycle.
        assert!(status("broken").await.is_err());

        let targets = |seen: &Arc<std::sync::Mutex<Vec<crate::local_wallet::tests::Seen>>>| {
            seen.lock()
                .unwrap()
                .iter()
                .map(|r| r.target.clone())
                .collect::<Vec<_>>()
        };
        let mempool = |id: &str| format!("{MEMPOOL_LOOKUP}{id}");
        let chain = |id: &str| format!("{CHAIN_LOOKUP}{id}");
        // The broadcast node's mempool is asked first, about everything; nothing else.
        assert_eq!(
            targets(&broadcast_seen),
            ["pool-broadcast", "pool-scanner", "chain", "gone", "broken"].map(mempool)
        );
        // The scanner node: its mempool once the broadcast node said no, then the chain.
        assert_eq!(
            targets(&scanner_seen),
            [
                mempool("pool-scanner"),
                mempool("chain"),
                chain("chain"),
                mempool("gone"),
                chain("gone"),
            ]
        );

        // One node for both roles: one mempool lookup, then the chain.
        let config = TrackerBoxUpdateConfig {
            scanner_node_url: scanner_url.clone(),
            wallet_node_url: format!("{scanner_url}/"),
            ..Default::default()
        };
        scanner_seen.lock().unwrap().clear();
        let found = TrackerBoxUpdater::check_transaction_confirmation(&config, "gone").await;
        assert_eq!(found.unwrap(), TxStatus::Missing);
        assert_eq!(targets(&scanner_seen), [mempool("gone"), chain("gone")]);
    }

    /// The updater loop against a mock node: it commits, and from then on the node reports the
    /// transaction in its mempool (`in_mempool`) or nowhere. Runs until `done` holds for the
    /// requests seen so far, then stops the loop and returns them.
    async fn run_updater_until(
        in_mempool: bool,
        done: impl FnMut(&[crate::local_wallet::tests::Seen]) -> bool,
    ) -> Vec<crate::local_wallet::tests::Seen> {
        let lookup = move |path: &str| {
            if in_mempool && path.starts_with(MEMPOOL_LOOKUP) {
                (200, "{}".to_string())
            } else {
                (404, "{}".to_string())
            }
        };
        let height = Arc::new(std::sync::atomic::AtomicU64::new(123_500));
        run_updater(lookup, height, done).await
    }

    /// [`run_updater_until`] with the mempool and chain lookups of the commit answered by
    /// `lookup(path)` and the node height (`/info`) read from `height`.
    async fn run_updater(
        lookup: impl Fn(&str) -> (u16, String) + Send + Sync + 'static,
        height: Arc<std::sync::atomic::AtomicU64>,
        done: impl FnMut(&[crate::local_wallet::tests::Seen]) -> bool,
    ) -> Vec<crate::local_wallet::tests::Seen> {
        run_updater_with(lookup, height, |_, _, _| {}, done).await.0
    }

    /// [`run_updater`] with the config and the shared state adjusted by `setup` before the
    /// updater starts (the fixture gives the tracker box). Returns the requests and the shared
    /// state after the updater stopped.
    async fn run_updater_with(
        lookup: impl Fn(&str) -> (u16, String) + Send + Sync + 'static,
        height: Arc<std::sync::atomic::AtomicU64>,
        setup: impl FnOnce(&mut TrackerBoxUpdateConfig, &SharedTrackerState, &CommitFixture),
        mut done: impl FnMut(&[crate::local_wallet::tests::Seen]) -> bool,
    ) -> (Vec<crate::local_wallet::tests::Seen>, SharedTrackerState) {
        use crate::local_wallet::tests::{mock_node, tree_of, utxo_box, LAST_HEADERS_JSON};
        use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

        let fx = commit_fixture(&[]);
        let fee_box = utxo_box(&tree_of(&fx.pubkey), 5_000_000, &[], &[], 123_100, 1);
        let fee_box_id = String::from(fee_box.box_id());
        let binaries: std::collections::HashMap<String, String> = [
            (
                fx.tracker_api.box_id.clone(),
                hex::encode(fx.tracker_box.sigma_serialize_bytes().unwrap()),
            ),
            (
                fee_box_id.clone(),
                hex::encode(fee_box.sigma_serialize_bytes().unwrap()),
            ),
        ]
        .into_iter()
        .collect();
        let tree_hex = crate::local_wallet::p2pk_tree_hex(&fx.pubkey);
        let fee_page = serde_json::json!([{
            "boxId": fee_box_id,
            "value": 5_000_000u64,
            "ergoTree": tree_hex,
            "assets": [],
            "additionalRegisters": {},
            "creationHeight": 123_100
        }])
        .to_string();
        let tracker_boxes = serde_json::to_string(&[&fx.tracker_api]).unwrap();
        let by_token = format!("/blockchain/box/unspent/byTokenId/{}", hex::encode(fx.nft));

        let (url, seen) = mock_node(move |method, target, body| {
            let path = target.split('?').next().unwrap_or_default();
            match (method, path) {
                ("GET", "/info") => {
                    let full_height = height.load(std::sync::atomic::Ordering::SeqCst);
                    (
                        200,
                        serde_json::json!({ "fullHeight": full_height }).to_string(),
                    )
                }
                ("GET", p) if p == by_token => (200, tracker_boxes.clone()),
                ("GET", "/blocks/lastHeaders/10") => (200, LAST_HEADERS_JSON.to_string()),
                ("POST", "/blockchain/box/unspent/byAddress") if target.contains("offset=0&") => {
                    (200, fee_page.clone())
                }
                ("POST", "/blockchain/box/unspent/byAddress") => (200, "[]".to_string()),
                ("GET", p) if p.starts_with("/utxo/byIdBinary/") => {
                    let id = p.trim_start_matches("/utxo/byIdBinary/");
                    let bytes = &binaries[id];
                    (
                        200,
                        serde_json::json!({ "boxId": id, "bytes": bytes }).to_string(),
                    )
                }
                ("POST", "/transactions") => {
                    let tx: serde_json::Value = serde_json::from_str(body).unwrap();
                    (200, tx["id"].to_string())
                }
                ("GET", p) if p.starts_with(MEMPOOL_LOOKUP) || p.starts_with(CHAIN_LOOKUP) => {
                    lookup(p)
                }
                _ => (500, format!("unexpected {method} {target}")),
            }
        })
        .await;

        let mut config = TrackerBoxUpdateConfig {
            wallet_node_url: url.clone(),
            scanner_node_url: url,
            tracker_secret_key: Some(fx.secret),
            update_interval_seconds: 1,
            ..Default::default()
        };
        let shared = SharedTrackerState::new_with_tracker_key(fx.pubkey);
        shared.set_tracker_nft_id(hex::encode(fx.nft));
        // Not the digest in the tracker box's R5 (the empty tree), so there is a commit to make.
        shared.set_avl_root_digest([0x42; 33]);
        setup(&mut config, &shared, &fx);
        let (stop_tx, stop_rx) = tokio::sync::broadcast::channel(1);
        let updater = tokio::spawn(TrackerBoxUpdater::start(
            config,
            shared.clone(),
            stop_rx,
            None,
        ));

        let started = std::time::Instant::now();
        loop {
            let snapshot = seen.lock().unwrap().clone();
            if done(&snapshot) {
                break;
            }
            let lines: Vec<String> = snapshot
                .iter()
                .map(|r| format!("{} {}", r.method, r.target))
                .collect();
            assert!(started.elapsed() < Duration::from_secs(30), "{lines:#?}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(20), updater)
            .await
            .expect("the updater stops")
            .unwrap()
            .unwrap();
        let requests = seen.lock().unwrap().clone();
        (requests, shared)
    }

    fn count(seen: &[crate::local_wallet::tests::Seen], prefix: &str) -> usize {
        seen.iter().filter(|r| r.target.starts_with(prefix)).count()
    }

    fn is_broadcast(request: &crate::local_wallet::tests::Seen) -> bool {
        request.method == "POST" && request.target == "/transactions"
    }

    fn broadcasts(seen: &[crate::local_wallet::tests::Seen]) -> usize {
        seen.iter().filter(|r| is_broadcast(r)).count()
    }

    /// A commit that waits in the mempool stays pending however many cycles it takes: it is
    /// never rebuilt or broadcast again, and the chain is not even asked.
    #[tokio::test]
    async fn a_commit_in_the_mempool_is_never_resubmitted() {
        let cycles = MAX_PENDING_MISSING_CYCLES as usize + 2;
        let seen = run_updater_until(true, |seen| count(seen, MEMPOOL_LOOKUP) >= cycles).await;
        assert_eq!(broadcasts(&seen), 1, "broadcast once");
        assert_eq!(count(&seen, CHAIN_LOOKUP), 0);
    }

    /// A commit that is in neither the mempool nor a block for MAX_PENDING_MISSING_CYCLES
    /// consecutive cycles is dropped and rebuilt, and not one cycle earlier.
    #[tokio::test]
    async fn a_commit_missing_for_the_limit_of_cycles_is_rebuilt() {
        let seen = run_updater_until(false, |seen| broadcasts(seen) >= 2).await;
        let posts: Vec<usize> = seen
            .iter()
            .enumerate()
            .filter(|(_, r)| is_broadcast(r))
            .map(|(i, _)| i)
            .collect();
        let between = &seen[posts[0]..posts[1]];
        let missing = MAX_PENDING_MISSING_CYCLES as usize;
        assert_eq!(count(between, MEMPOOL_LOOKUP), missing);
        assert_eq!(count(between, CHAIN_LOOKUP), missing);
        // In every cycle the mempool is asked before the chain.
        let lookups: Vec<&str> = between
            .iter()
            .filter_map(|r| {
                if r.target.starts_with(MEMPOOL_LOOKUP) {
                    Some("mempool")
                } else if r.target.starts_with(CHAIN_LOOKUP) {
                    Some("chain")
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(lookups, ["mempool", "chain"].repeat(missing));
    }

    #[test]
    fn the_confirming_tx_reads_the_inclusion_height() {
        let body = serde_json::json!({
            "id": "aa".repeat(32),
            "inclusionHeight": 123_500,
            "numConfirmations": 1,
            "outputs": [{ "boxId": "ee".repeat(32), "creationHeight": 123_470 }]
        });
        assert_eq!(
            ConfirmingTx::from_indexed_tx(&body, "tx"),
            ConfirmingTx {
                box_id: "ee".repeat(32),
                height: 123_470,
                inclusion_height: 123_500,
                first_output_r5: None,
            }
        );
        // Round 5b (F1): the first output's R5, as the index serializes it.
        let with_r5 = serde_json::json!({
            "inclusionHeight": 123_500,
            "outputs": [{
                "boxId": "ee".repeat(32),
                "creationHeight": 123_470,
                "additionalRegisters": { "R4": "0e01aa", "R5": "64abcd" }
            }]
        });
        assert_eq!(
            ConfirmingTx::from_indexed_tx(&with_r5, "tx").first_output_r5,
            Some("64abcd".to_string())
        );
        // Unknown heights are 0 (depth 0: not deep enough), the box falls back to the tx id.
        assert_eq!(
            ConfirmingTx::from_indexed_tx(&serde_json::json!({}), "tx"),
            ConfirmingTx {
                box_id: "tx".to_string(),
                height: 0,
                inclusion_height: 0,
                first_output_r5: None,
            }
        );
    }

    /// A commit built at 123_470 that waited in the mempool and was included at the tip,
    /// 123_500, is at depth 1, not 31. With min_confirmation_depth 2 the updater keeps it
    /// pending (it does not even look the tracker box up again) until the next block, and only
    /// then treats it as confirmed and moves on.
    #[tokio::test]
    async fn confirmation_depth_counts_from_the_inclusion_height() {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        const BY_TOKEN: &str = "/blockchain/box/unspent/byTokenId/";
        let included_at = 123_500u64;
        let tx_json = serde_json::json!({
            "inclusionHeight": included_at,
            "numConfirmations": 1,
            "outputs": [{ "boxId": "ee".repeat(32), "creationHeight": included_at - 30 }]
        })
        .to_string();
        let lookup = move |path: &str| {
            if path.starts_with(CHAIN_LOOKUP) {
                (200, tx_json.clone())
            } else {
                (404, "{}".to_string())
            }
        };
        let height = Arc::new(AtomicU64::new(included_at));
        let next_block_at = Arc::new(AtomicUsize::new(usize::MAX));
        let (node_height, bump) = (height.clone(), next_block_at.clone());

        let seen = run_updater(lookup, height, move |seen| {
            let Some(broadcast) = seen.iter().position(is_broadcast) else {
                return false;
            };
            let bumped_at = bump.load(Ordering::SeqCst);
            if bumped_at == usize::MAX {
                // Three cycles at depth 1 (a status and a summary lookup each), then a block.
                if count(&seen[broadcast..], CHAIN_LOOKUP) >= 6 {
                    bump.store(seen.len(), Ordering::SeqCst);
                    node_height.store(included_at + 1, Ordering::SeqCst);
                }
                return false;
            }
            count(&seen[bumped_at..], BY_TOKEN) >= 1
        })
        .await;

        let broadcast = seen.iter().position(is_broadcast).unwrap();
        let bumped_at = next_block_at.load(Ordering::SeqCst);
        let waiting = &seen[broadcast..bumped_at];
        assert!(count(waiting, CHAIN_LOOKUP) >= 6);
        assert_eq!(count(waiting, BY_TOKEN), 0, "confirmed at depth 1");
        assert!(
            count(&seen[bumped_at..], BY_TOKEN) >= 1,
            "confirmed at depth 2"
        );
        assert_eq!(broadcasts(&seen), 1);
    }

    /// Round 5, item 4: with cycles 600 s apart, the pending commit is looked for between them,
    /// with one chain lookup per poll and nothing else, and once it is deep enough the new
    /// tracker box and the committed digest are recorded without waiting for the next cycle.
    #[tokio::test]
    async fn a_pending_commit_is_polled_between_cycles() {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        let included_at = 123_500u64;
        let new_box = "ee".repeat(32);
        let tx_json = serde_json::json!({
            "inclusionHeight": included_at,
            "outputs": [{ "boxId": new_box, "creationHeight": included_at - 1 }]
        })
        .to_string();
        let chain_lookups = Arc::new(AtomicUsize::new(0));
        let lookups = chain_lookups.clone();
        // Three polls find nothing, the fourth finds the commit in a block.
        let lookup = move |path: &str| {
            if path.starts_with(CHAIN_LOOKUP) && lookups.fetch_add(1, Ordering::SeqCst) >= 3 {
                (200, tx_json.clone())
            } else {
                (404, "{}".to_string())
            }
        };
        let height = Arc::new(AtomicU64::new(included_at + 1));
        let (seen, shared) = run_updater_with(
            lookup,
            height,
            |config, _, _| {
                config.update_interval_seconds = 600;
                config.pending_poll_interval = Duration::from_millis(100);
            },
            |seen| count(seen, CHAIN_LOOKUP) >= 4,
        )
        .await;

        assert_eq!(broadcasts(&seen), 1);
        let broadcast = seen.iter().position(is_broadcast).unwrap();
        let after: Vec<String> = seen[broadcast + 1..]
            .iter()
            .map(|r| r.target.split('?').next().unwrap_or_default().to_string())
            .collect();
        // Four polls, one chain lookup each, and the height for the depth once it was found
        // (the `/info` before them is the commit's submitted height).
        assert_eq!(count(&seen[broadcast..], CHAIN_LOOKUP), 4, "{after:?}");
        assert_eq!(count(&seen[broadcast..], MEMPOOL_LOOKUP), 0, "{after:?}");
        assert_eq!(count(&seen[broadcast..], "/blockchain/box/unspent/byTokenId/"), 0);
        let first_poll = broadcast
            + seen[broadcast..]
                .iter()
                .position(|r| r.target.starts_with(CHAIN_LOOKUP))
                .unwrap();
        assert_eq!(count(&seen[first_poll..], "/info"), 1, "{after:?}");

        assert_eq!(shared.get_pending().tx_id, None, "no longer pending");
        assert_eq!(shared.get_confirmed().digest, Some([0x42; 33]));
        assert_eq!(shared.get_confirmed().box_id, Some(new_box.clone()));
        assert_eq!(shared.get_tracker_box_id(), Some(new_box), "builds read the new box");
    }

    /// The submitted redemption the deferral tests use, and the mock answers for it.
    const REDEMPTION_TX: &str = "abababababababababababababababababababababababababababababababab";

    /// Round 5, item 3: while a redemption submitted through `/redemption/submit` waits in the
    /// mempool and reads the current tracker box, no commit is made; once it is in a block, the
    /// next cycle commits. A redemption that reads another box holds nothing back and is
    /// forgotten without a lookup.
    #[tokio::test]
    async fn a_commit_waits_for_a_submitted_redemption_in_the_mempool() {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        let pool_lookups = Arc::new(AtomicUsize::new(0));
        let pool = pool_lookups.clone();
        let lookup = move |path: &str| {
            let id = path.rsplit('/').next().unwrap_or_default();
            if id == REDEMPTION_TX {
                if path.starts_with(MEMPOOL_LOOKUP) {
                    // In the mempool for three cycles, then in a block.
                    if pool.fetch_add(1, Ordering::SeqCst) < 3 {
                        return (200, "{}".to_string());
                    }
                    return (404, "{}".to_string());
                }
                return (200, "{}".to_string());
            }
            // The commit, once made, waits in the mempool.
            if path.starts_with(MEMPOOL_LOOKUP) {
                (200, "{}".to_string())
            } else {
                (404, "{}".to_string())
            }
        };
        let height = Arc::new(AtomicU64::new(123_500));
        let (seen, shared) = run_updater_with(
            lookup,
            height,
            |_, shared, fx| {
                // Round 5b (F10): the data input id matches in any case.
                shared.record_submitted_redemption(
                    REDEMPTION_TX.to_string(),
                    vec![fx.tracker_api.box_id.to_ascii_uppercase()],
                );
                shared.record_submitted_redemption("cd".repeat(32), vec!["ff".repeat(32)]);
            },
            |seen| broadcasts(seen) >= 1,
        )
        .await;

        let broadcast = seen.iter().position(is_broadcast).unwrap();
        let before = &seen[..broadcast];
        let redemption_mempool = format!("{MEMPOOL_LOOKUP}{REDEMPTION_TX}");
        assert_eq!(count(before, &redemption_mempool), 4, "three cycles held back, then gone");
        assert!(count(before, "/blockchain/box/unspent/byTokenId/") >= 4);
        assert_eq!(count(&seen, &format!("{MEMPOOL_LOOKUP}{}", "cd".repeat(32))), 0);
        assert!(shared.get_submitted_redemptions().is_empty(), "both forgotten");
    }

    /// Round 5, item 3: a redemption that stays in the mempool holds a commit back for at most
    /// `max_commit_deferral`; then the commit is made anyway.
    #[tokio::test]
    async fn a_redemption_holds_a_commit_back_for_a_limited_time() {
        use std::sync::atomic::AtomicU64;
        let lookup = |path: &str| {
            if path.starts_with(MEMPOOL_LOOKUP) {
                (200, "{}".to_string())
            } else {
                (404, "{}".to_string())
            }
        };
        let height = Arc::new(AtomicU64::new(123_500));
        let started = std::time::Instant::now();
        let (seen, shared) = run_updater_with(
            lookup,
            height,
            |config, shared, fx| {
                config.max_commit_deferral = Duration::from_millis(2_500);
                shared.record_submitted_redemption(
                    REDEMPTION_TX.to_string(),
                    vec![fx.tracker_api.box_id.clone()],
                );
            },
            |seen| broadcasts(seen) >= 1,
        )
        .await;
        assert!(started.elapsed() >= Duration::from_millis(2_500));
        let broadcast = seen.iter().position(is_broadcast).unwrap();
        let redemption_mempool = format!("{MEMPOOL_LOOKUP}{REDEMPTION_TX}");
        assert!(count(&seen[..broadcast], &redemption_mempool) >= 2);
        assert_eq!(count(&seen[broadcast..], &redemption_mempool), 0);
        assert!(shared.get_submitted_redemptions().is_empty());
    }

    /// Round 5, item 3: within 200 blocks of the emergency window no commit is held back, not
    /// even for a redemption in the mempool: the first cycle commits.
    #[tokio::test]
    async fn no_commit_is_held_back_near_the_emergency_window() {
        use std::sync::atomic::AtomicU64;
        let lookup = |path: &str| {
            if path.starts_with(MEMPOOL_LOOKUP) {
                (200, "{}".to_string())
            } else {
                (404, "{}".to_string())
            }
        };
        // The fixture's tracker box was created at 123_000.
        let height = Arc::new(AtomicU64::new(
            123_000 + crate::config::TRACKER_EMERGENCY_WINDOW_BLOCKS
                - COMMIT_DEFERRAL_EMERGENCY_MARGIN_BLOCKS,
        ));
        let (seen, _) = run_updater_with(
            lookup,
            height,
            |_, shared, fx| {
                shared.record_submitted_redemption(
                    REDEMPTION_TX.to_string(),
                    vec![fx.tracker_api.box_id.clone()],
                );
            },
            |seen| broadcasts(seen) >= 1,
        )
        .await;
        let broadcast = seen.iter().position(is_broadcast).unwrap();
        assert_eq!(
            count(&seen[..broadcast], &format!("{MEMPOOL_LOOKUP}{REDEMPTION_TX}")),
            0,
            "not even looked up"
        );
        assert_eq!(count(&seen[..broadcast], "/blockchain/box/unspent/byTokenId/"), 1);
    }

    /// Round 5b (F3): redemptions submitted one after another, each in the mempool and each
    /// younger than `max_commit_deferral`, hold commits back for at most `max_commit_deferral`
    /// in total from the first deferral; then the commit is made although one still waits.
    #[tokio::test]
    async fn back_to_back_redemptions_hold_a_commit_back_for_the_cap_in_total() {
        use std::sync::atomic::AtomicU64;
        let lookup = |path: &str| {
            if path.starts_with(MEMPOOL_LOOKUP) {
                (200, "{}".to_string())
            } else {
                (404, "{}".to_string())
            }
        };
        let cap = Duration::from_millis(2_500);
        let height = Arc::new(AtomicU64::new(123_500));
        let held: Arc<std::sync::Mutex<Option<(SharedTrackerState, String)>>> = Arc::default();
        let setup_held = held.clone();
        let started = std::time::Instant::now();
        let mut next = 0u32;
        let mut last_submit = std::time::Instant::now();
        let (seen, _) = run_updater_with(
            lookup,
            height,
            move |config, shared, fx| {
                config.max_commit_deferral = cap;
                shared.record_submitted_redemption(
                    format!("{:064x}", 0),
                    vec![fx.tracker_api.box_id.clone()],
                );
                *setup_held.lock().unwrap() = Some((shared.clone(), fx.tracker_api.box_id.clone()));
            },
            |seen| {
                // A new redemption every 600 ms: the newest is always younger than the cap.
                if last_submit.elapsed() >= Duration::from_millis(600) && broadcasts(seen) == 0 {
                    next += 1;
                    last_submit = std::time::Instant::now();
                    let held = held.lock().unwrap();
                    let (shared, tracker_box) = held.as_ref().unwrap();
                    shared.record_submitted_redemption(
                        format!("{next:064x}"),
                        vec![tracker_box.clone()],
                    );
                }
                broadcasts(seen) >= 1
            },
        )
        .await;
        let elapsed = started.elapsed();
        assert!(elapsed >= cap, "{elapsed:?}");
        assert!(elapsed < cap + Duration::from_secs(4), "{elapsed:?}");
        let broadcast = seen.iter().position(is_broadcast).unwrap();
        let looked_up: std::collections::HashSet<&str> = seen[..broadcast]
            .iter()
            .filter_map(|r| r.target.strip_prefix(MEMPOOL_LOOKUP))
            .collect();
        assert!(looked_up.len() >= 2, "several redemptions held it back: {looked_up:?}");
    }

    /// Round 5b (F3): a due heartbeat (nothing new to commit, the tracker box `heartbeat_blocks`
    /// old) is never held back for a redemption in the mempool, and neither is a commit of a new
    /// digest once the box is that old: the first cycle commits without looking the redemption
    /// up.
    #[tokio::test]
    async fn a_due_heartbeat_is_never_held_back() {
        use std::sync::atomic::AtomicU64;
        for new_digest in [false, true] {
            let lookup = |path: &str| {
                if path.starts_with(MEMPOOL_LOOKUP) {
                    (200, "{}".to_string())
                } else {
                    (404, "{}".to_string())
                }
            };
            // The fixture's tracker box was created at 123_000; 720 blocks is the default.
            let height = Arc::new(AtomicU64::new(123_000 + 720));
            let (seen, _) = run_updater_with(
                lookup,
                height,
                |config, shared, fx| {
                    assert_eq!(config.heartbeat_blocks, 720);
                    if !new_digest {
                        let r5 = hex::decode(&fx.tracker_api.additional_registers["R5"]).unwrap();
                        shared.set_avl_root_digest(r5[1..34].try_into().unwrap());
                    }
                    shared.record_submitted_redemption(
                        REDEMPTION_TX.to_string(),
                        vec![fx.tracker_api.box_id.clone()],
                    );
                },
                |seen| broadcasts(seen) >= 1,
            )
            .await;
            let broadcast = seen.iter().position(is_broadcast).unwrap();
            assert_eq!(
                count(&seen[..broadcast], &format!("{MEMPOOL_LOOKUP}{REDEMPTION_TX}")),
                0,
                "new digest {new_digest}: not even looked up"
            );
            assert_eq!(
                count(&seen[..broadcast], "/blockchain/box/unspent/byTokenId/"),
                1,
                "new digest {new_digest}: the first cycle commits"
            );
        }
    }

    #[test]
    fn commits_may_wait_until_200_blocks_before_the_emergency_window() {
        let window = crate::config::TRACKER_EMERGENCY_WINDOW_BLOCKS;
        assert!(commit_may_wait(1_000, 1_000));
        assert!(commit_may_wait(1_000 + window - 201, 1_000));
        assert!(!commit_may_wait(1_000 + window - 200, 1_000));
        assert!(!commit_may_wait(1_000 + window + 5, 1_000));
        // A box "created" above the node height (a lagging node) is young, not old.
        assert!(commit_may_wait(900, 1_000));
    }

    /// Round 5b, F10: submitted redemption ids are kept in lower case and forgotten in any.
    #[test]
    fn submitted_redemption_ids_are_kept_in_lower_case() {
        let shared = SharedTrackerState::new();
        shared.record_submitted_redemption("AB".repeat(32), vec!["CD".repeat(32)]);
        let all = shared.get_submitted_redemptions();
        assert_eq!(all[0].tx_id, "ab".repeat(32));
        assert_eq!(all[0].data_input_ids, vec!["cd".repeat(32)]);
        shared.forget_submitted_redemptions(&["Ab".repeat(32)]);
        assert!(shared.get_submitted_redemptions().is_empty());
    }

    #[test]
    fn submitted_redemptions_are_bounded_and_forgotten_by_id() {
        let shared = SharedTrackerState::new();
        for i in 0..MAX_SUBMITTED_REDEMPTIONS + 5 {
            shared.record_submitted_redemption(format!("tx-{i}"), vec!["box".to_string()]);
        }
        let all = shared.get_submitted_redemptions();
        assert_eq!(all.len(), MAX_SUBMITTED_REDEMPTIONS);
        assert_eq!(all[0].tx_id, "tx-5", "the oldest made room");
        // The same id again replaces its entry.
        shared.record_submitted_redemption("tx-5".to_string(), vec!["other".to_string()]);
        let all = shared.get_submitted_redemptions();
        assert_eq!(all.len(), MAX_SUBMITTED_REDEMPTIONS);
        assert_eq!(all.last().unwrap().data_input_ids, ["other"]);
        shared.forget_submitted_redemptions(&["tx-5".to_string(), "tx-6".to_string()]);
        assert_eq!(
            shared.get_submitted_redemptions().len(),
            MAX_SUBMITTED_REDEMPTIONS - 2
        );
    }

    #[test]
    fn the_update_interval_env_refuses_zero_and_garbage() {
        assert_eq!(update_interval_from_env(None), Ok(600));
        assert_eq!(update_interval_from_env(Some("")), Ok(600));
        assert_eq!(update_interval_from_env(Some(" 120 ")), Ok(120));
        assert_eq!(update_interval_from_env(Some("10")), Ok(10));
        let zero = update_interval_from_env(Some("0")).unwrap_err();
        assert!(zero.contains("is 0"), "{zero}");
        for garbage in ["10m", "-5", "1.5", "six hundred"] {
            let err = update_interval_from_env(Some(garbage)).unwrap_err();
            assert!(err.contains("whole number of seconds"), "{garbage}: {err}");
        }
    }

    /// A config built in code with interval 0 no longer panics the updater task.
    #[tokio::test]
    async fn an_updater_with_interval_zero_runs_instead_of_panicking() {
        let config = TrackerBoxUpdateConfig {
            wallet_node_url: "http://127.0.0.1:1".to_string(),
            scanner_node_url: "http://127.0.0.1:1".to_string(),
            update_interval_seconds: 0,
            ..Default::default()
        };
        let (stop_tx, stop_rx) = tokio::sync::broadcast::channel(1);
        let updater = tokio::spawn(TrackerBoxUpdater::start(
            config,
            SharedTrackerState::new(),
            stop_rx,
            None,
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!updater.is_finished(), "the updater stopped (panicked?)");
        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), updater)
            .await
            .expect("stops")
            .expect("no panic")
            .unwrap();
    }
}
