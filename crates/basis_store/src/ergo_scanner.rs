//! Ergo blockchain scanner for monitoring Basis reserve contracts
//! This module provides blockchain integration using /blockchain endpoints (no node scans).

use std::{
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use reqwest::Client;

/// Response from `POST /blockchain/box/unspent/byAddress` is a JSON array of IndexedErgoBox.
pub(crate) type ByAddressResponse = Vec<IndexedErgoBox>;

/// Box representation returned by Ergo `/blockchain/*` endpoints (IndexedErgoBox).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IndexedErgoBox {
    #[serde(rename = "boxId")]
    box_id: String,
    value: u64,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    #[serde(rename = "creationHeight")]
    creation_height: u64,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    #[serde(rename = "additionalRegisters")]
    additional_registers: std::collections::HashMap<String, String>,
    #[serde(default)]
    assets: Vec<IndexedBoxAsset>,
    #[serde(flatten)]
    _extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Asset representation in an IndexedErgoBox.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IndexedBoxAsset {
    #[serde(rename = "tokenId")]
    token_id: String,
    amount: u64,
}

impl From<IndexedErgoBox> for ScanBox {
    fn from(box_: IndexedErgoBox) -> Self {
        Self {
            box_id: box_.box_id,
            value: box_.value,
            ergo_tree: box_.ergo_tree,
            creation_height: box_.creation_height,
            transaction_id: box_.transaction_id,
            additional_registers: box_.additional_registers,
            assets: box_
                .assets
                .into_iter()
                .map(|a| BoxAsset {
                    token_id: a.token_id,
                    amount: a.amount,
                })
                .collect(),
        }
    }
}

use crate::{
    persistence::{QuarantinedReserve, RemovedReserve, ReserveStorage, ScannerMetadataStorage},
    reopen_guard::{ReopenCheck, ReopenGuard, RESERVE_REOPEN_BLOCKED},
    ExtendedReserveInfo, ReserveTracker,
};

/// Normalize a box id the way `ExtendedReserveInfo.box_id` is stored:
/// hex-decode (when valid hex) and re-encode, so comparisons with node-provided
/// box ids are case- and encoding-insensitive.
fn normalized_box_id(box_id: &str) -> String {
    hex::encode(hex::decode(box_id).unwrap_or_else(|_| box_id.as_bytes().to_vec()))
}

/// The ergoTree of a pay-to-public-key (P2PK) box: `0008cd` followed by the
/// 33-byte compressed public key (see `basis_offchain::ergo_tx::pubkey_to_address`).
fn p2pk_ergo_tree(pubkey_hex: &str) -> String {
    format!("0008cd{}", pubkey_hex)
}

/// Maximum generations walked backwards when verifying that a new reserve box
/// descends from the tracked one (issue #19). Covers tracker downtime spanning
/// several reserve actions (top-up of a top-up, etc.). Round 6c (P1-1): 64,
/// not 8 (nine top-ups fit in one block), and running out gives no verdict
/// (retry; a singleton NFT still decides), never a quarantine.
const LINEAGE_WALK_DEPTH: usize = 64;

/// The reserve NFT id (hex, lower case) when `(token_id, amount)` can be one: a
/// 32-byte token held once.
fn reserve_nft(token_id: &str, amount: u64) -> Option<String> {
    (amount == 1 && token_id.len() == 64 && hex::decode(token_id).is_ok())
        .then(|| token_id.to_ascii_lowercase())
}

/// The reserve NFT of a scanned box: its first token when held once.
fn scan_box_nft(scan_box: &ScanBox) -> Option<String> {
    scan_box
        .assets
        .first()
        .and_then(|asset| reserve_nft(&asset.token_id, asset.amount))
}

/// Node requests the lineage and ownership checks may make in one scan cycle
/// on the shared lane (round 6c). The checks walk at most `LINEAGE_WALK_DEPTH`
/// transactions per box; past the budget a check gives no verdict and is
/// retried next cycle. Round 6d (P1): the tracked lane (reading the tracked
/// boxes, their anchors and the singleton lookup of a box holding a tracked
/// NFT) is outside this budget, bounded by the number of tracked reserves, and
/// those boxes are checked first, so a successor whose NFT is a singleton is
/// still followed however many other boxes the scan lists.
const LINEAGE_REQUESTS_PER_CYCLE: usize = 512;

/// Root candidates checked against the node per scan cycle (round 6d, P1).
/// Never-checked candidates go first, then the least recently checked, so a
/// new reserve is not starved by junk that stays undecided.
const MAX_ROOT_CHECKS_PER_CYCLE: usize = 128;

/// How deep the spend of a tracked reserve must be before a scan without any
/// valid box removes it (round 6d, P2-3).
const SPENT_REMOVAL_DEPTH: u64 = 10;

/// How far the blockchain index may be behind the node's full height before a
/// scan cycle is skipped (round 6e): a lagging index shows old boxes as unspent.
const MAX_INDEX_LAG: u64 = 2;

/// A skipped cycle is logged as a warning once per this many in a row (round 6f).
const LAG_WARN_EVERY: u64 = 30;

/// How long `GET /blockchain/indexedHeight` may take before the cycle is
/// skipped (round 8): the client's request timeout; short in tests.
#[cfg(not(test))]
const INDEX_HEIGHT_TIMEOUT: Duration = crate::http::REQUEST_TIMEOUT;
#[cfg(test)]
const INDEX_HEIGHT_TIMEOUT: Duration = Duration::from_secs(3);

/// Round 8 (review LOW-1): how far the index height may be above the node's
/// `/info` height that the scanner loop read just before the cycle (blocks
/// that arrived in between).
const INFO_HEIGHT_MARGIN: u64 = 2;

/// Wall-clock time the shared-lane checks of one scan cycle may take (round 6e,
/// LOW-5); past it they give no verdict and are retried next cycle.
const CYCLE_TIME_LIMIT: std::time::Duration = std::time::Duration::from_secs(120);

/// Blocks after refund initiation when the owner may complete the refund
/// (contract action #3, `basis.es`).
const REFUND_DELAY_BLOCKS: u64 = 43_200;

/// How long a removed reserve box is remembered (round 6d, P2-3): 720 blocks,
/// about a day, counted in index height (round 6f-2: not wall-clock, so the
/// records do not expire while cycles are skipped or the index height is
/// unknown). A box a reorg brings back within that time is restored as the
/// tracked box instead of being judged as a root.
const REMEMBER_REMOVED_BLOCKS: u64 = 720;

/// What the scanner knows about reserve NFTs (round 6c, P1-2). Round 8: the
/// facts of the chain in it (the NFT of a tracked box, the singleton verdict of
/// a tracked NFT) are also kept in the reserve store and loaded at start, so a
/// restart does not ask the node for them again; this map stays the cache.
#[derive(Debug, Default)]
pub struct NftCache {
    /// Reserve box id -> its reserve NFT (`None`: it holds none).
    box_nft: std::collections::HashMap<String, Option<String>>,
    /// NFT id -> whether its emission is 1.
    singleton: std::collections::HashMap<String, bool>,
    /// Round 8: the NFTs whose singleton verdict is in the store.
    stored_singletons: std::collections::HashSet<String>,
    /// Round 8 (review LOW-4): the tracked boxes whose NFT is in the store; a
    /// box missing here is written again at its next sight.
    stored_box_nfts: std::collections::HashSet<String>,
    /// Round 6d (P2-3): removed reserve box id -> its record, its NFT, when
    /// (ms) and, round 6f-2, at which index height. Round 6e: the record
    /// anchors the lineage of a box holding its NFT, so the successor of a
    /// removed box is followed, not judged as a root.
    removed: std::collections::HashMap<String, RemovedReserve>,
    /// Round 6d (P1): root candidate box id -> the cycle it was last checked in.
    root_checked: std::collections::HashMap<String, u64>,
    /// Scan cycles run so far.
    cycles: u64,
    /// Round 6f (P2-1): tracked box id -> the index height when the index
    /// first did not know it.
    unknown_since: std::collections::HashMap<String, u64>,
    /// Round 6f: scan cycles skipped for a lagging index, in a row and in all;
    /// round 8: or for no usable index height.
    lag_skips_in_a_row: u64,
    lag_skips: u64,
    /// Round 8: the highest index height a cycle ran with since the start; a
    /// cycle is skipped while the index is below it (in memory only, so a
    /// restart forgets it).
    index_height_seen: Option<u64>,
}

/// Bytes of a transaction read for its inclusion height (round 6e).
const TX_PREFIX_BYTES: usize = 64 * 1024;

/// Bytes of transaction inputs one scan cycle keeps for reuse (round 6d, P1);
/// past it a transaction is still read but not kept.
const CYCLE_MEMO_BYTES: usize = 64 * 1024 * 1024;

/// What one scan cycle has asked the node (round 6d, P1): request count of the
/// shared lane, root checks, and the answers by id, so a transaction or box
/// read by many candidates is fetched once. Reset at each cycle.
#[derive(Debug, Default)]
pub struct CycleState {
    /// When the cycle started (round 6e, LOW-5).
    started: Option<std::time::Instant>,
    /// The height of the blockchain index this cycle (round 6e).
    height: Option<u64>,
    requests: usize,
    root_checks: usize,
    memo_bytes: usize,
    tx_inputs: std::collections::HashMap<String, Result<Vec<ChainBox>, String>>,
    boxes: std::collections::HashMap<String, Result<Option<ChainBox>, String>>,
    /// Box ids the scan listed this cycle (`None` outside `process_scan_boxes`).
    scanned: Option<std::collections::HashSet<String>>,
}

/// (Owner, denomination id) -> (box id, NFT) of the boxes tracked in a scan
/// cycle (round 6f).
type TrackedThisCycle =
    std::collections::HashMap<(String, Option<String>), Vec<(String, Option<String>)>>;

/// Which allowance a node request of the admission checks counts against
/// (round 6d, P1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lane {
    /// The tracked reserves and boxes holding their NFT: not budgeted.
    Tracked,
    /// Everything else: `LINEAGE_REQUESTS_PER_CYCLE`.
    Shared,
}

/// A lineage verdict (round 6d).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lineage {
    /// The box continues the tracked reserve.
    Successor,
    /// It does not.
    NotSuccessor,
    /// It holds the reserve NFT after a pending refund was completed (R7 not
    /// kept, P2-2): the owner made it anew, so it is judged as a root.
    Root,
    /// Not a successor: the NFT entered the box itself from outside any reserve
    /// box (its own creating transaction has no reserve input holding it;
    /// round 6f). Only `walk_to_spender` gives it.
    Foreign,
}

/// R7 of a box as the contract reads it (`getOrElse(0)`).
fn refund_height(r7: Option<&String>) -> u64 {
    decode_ergo_long_register(r7)
}

/// Whether going from a box with refund height `before` to one with `after`
/// breaks what contract actions #0 and #1 keep (round 6d, P2-2): a pending
/// refund (R7 != 0) is kept by every action but the owner's refund completion
/// (#2 needs R7 = 0).
fn refund_broken(before: u64, after: u64) -> bool {
    before != 0 && after != before
}

/// A box as the blockchain index gives it: an input of
/// `GET /blockchain/transaction/byId`, or `GET /blockchain/box/byId`.
#[derive(Debug, Clone)]
pub struct ChainBox {
    box_id: String,
    address: String,
    creating_tx: String,
    /// The transaction that spent the box; empty while unspent.
    spent_tx: String,
    ergo_tree: String,
    /// `(token id, amount)` in box order; `None` when the index gave no `assets`.
    assets: Option<Vec<(String, u64)>>,
    /// Serialized registers (hex) by name.
    registers: std::collections::HashMap<String, String>,
}

impl ChainBox {
    /// About how much memory the box takes.
    fn approx_bytes(&self) -> usize {
        self.box_id.len()
            + self.address.len()
            + self.creating_tx.len()
            + self.spent_tx.len()
            + self.ergo_tree.len()
            + self
                .assets
                .as_ref()
                .map_or(0, |assets| assets.iter().map(|(id, _)| id.len() + 8).sum())
            + self
                .registers
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
            + 64
    }

    /// The box's reserve NFT: its first token when held once.
    fn reserve_nft(&self) -> Option<String> {
        let (token_id, amount) = self.assets.as_ref()?.first()?;
        reserve_nft(token_id, *amount)
    }

    /// Whether the box holds `nft` as a reserve box does (at `tokens(0)`,
    /// amount 1) with the given R4 and R6 (serialized, hex).
    fn is_reserve_box_of(&self, nft: &str, r4: &str, r6: &str) -> bool {
        self.reserve_nft().as_deref() == Some(nft)
            && self
                .registers
                .get("R4")
                .is_some_and(|v| v.eq_ignore_ascii_case(r4))
            && self
                .registers
                .get("R6")
                .is_some_and(|v| v.eq_ignore_ascii_case(r6))
    }

    fn from_json(input: &serde_json::Value) -> Option<Self> {
        let text = |field: &str| {
            input
                .get(field)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        let assets = input
            .get("assets")
            .and_then(|a| a.as_array())
            .map(|assets| {
                assets
                    .iter()
                    .map(|asset| {
                        (
                            asset
                                .get("tokenId")
                                .and_then(|t| t.as_str())
                                .unwrap_or_default()
                                .to_string(),
                            asset.get("amount").and_then(|a| a.as_u64()).unwrap_or(0),
                        )
                    })
                    .collect()
            });
        // Registers come as hex strings, or as objects with `serializedValue`.
        let registers = input
            .get("additionalRegisters")
            .and_then(|r| r.as_object())
            .map(|registers| {
                registers
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .as_str()
                            .or_else(|| value.get("serializedValue").and_then(|v| v.as_str()))
                            .map(|hex| (name.clone(), hex.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            box_id: input.get("boxId")?.as_str()?.to_string(),
            address: text("address"),
            creating_tx: text("transactionId"),
            spent_tx: text("spentTransactionId"),
            ergo_tree: text("ergoTree"),
            assets,
            registers,
        })
    }
}

/// Admission decision for a parsed reserve box (issue #19).
///
/// Only one box per (owner, denomination) lineage is ever tracked: a
/// C4-validated root, or a verified successor of the currently tracked box.
/// Everything else is quarantined before it reaches the tracker, so an
/// attacker cannot poison `ReserveTracker::resolve_issuer_reserve` with a dust
/// duplicate carrying the victim's key in R4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveAdmission {
    /// The box may be tracked.
    Admitted,
    /// The box must not be tracked; `reason` is persisted on the quarantine
    /// record.
    Quarantined { reason: String },
    /// Admission could not be decided this cycle (e.g. a node error during the
    /// lineage check); retry next cycle. The box is neither admitted nor
    /// quarantined, and the tracked box for the same (owner, denomination)
    /// must not be removed as spent while a successor candidate is pending.
    Retry,
    /// Retry next cycle without keeping any tracked box (round 6d): a root
    /// candidate past the per-cycle cap or without a verdict, or a newcomer
    /// whose owner's tracked reserve is spent this cycle.
    Deferred,
}

/// The outcome of ingesting one scanned reserve box (parse + admission +
/// tracking), used by both scan ingestion paths (issue #19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanBoxIngest {
    /// The box was admitted and (re-)stored; carries the normalized box id.
    Tracked(String),
    /// The box was rejected as unparseable or quarantined; carries the
    /// normalized box id. Rejected boxes never trigger removal of themselves
    /// and must not block removal of other genuinely-spent reserves.
    Rejected(String),
    /// The lineage check was inconclusive this cycle; carries the owner pubkey
    /// and denomination of the pending lineage so the caller keeps the
    /// currently tracked box until the check resolves.
    Pending(String, crate::DenomKey),
    /// Retried next cycle, keeping no tracked box (round 6d); carries the
    /// normalized box id.
    Deferred(String),
}

/// Page size for `POST /blockchain/box/unspent/byAddress`. The node defaults to
/// 5 boxes (newest first) when no limit is given, which silently dropped older
/// reserves from tracking (issue: scanner only saw 5 reserve boxes per address).
///
/// Each page is read through `read_json_capped` (2 MiB). A box can serialize to
/// 4 KB and the node renders it as pretty-printed hex plus the P2S address, so
/// a page must stay small enough that a full page of maximum-size boxes fits:
/// with 1000 per page, a few hundred junk boxes at the reserve address stopped
/// every scan for good (follow-up review N4).
const RESERVE_BOX_PAGE_LIMIT: u64 = 100;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Scanner error: {0}")]
    Generic(String),
    #[error("Store error: {0}")]
    StoreError(String),
    #[error("Node error: {0}")]
    NodeError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Box error: {0}")]
    BoxError(String),
    #[error("Invalid transaction {0}")]
    InvalidTransaction(String),
    #[error("Reserve box validation failed at TX id: {0}")]
    InvalidReserveBox(String),
    #[error("HTTP error: {0}")]
    HttpError(String),
    #[error("JSON parse error: {0}")]
    JsonError(String),
    /// Round 8 (operator: refuse to start): the tracked reserves in the store
    /// did not load completely; the message says which and how to recover. The
    /// tracker must not start on it.
    #[error("{0}")]
    ReservesUnreadable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    Reserves,
}

impl ScanType {
    pub fn to_str(&self) -> &'static str {
        match self {
            ScanType::Reserves => "reserves",
        }
    }
}

/// Which reserve contract a scanned box was found at. Determines how collateral and
/// denomination are derived (specs/ergo/multi_collateral_reserves.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveContractKind {
    /// ERG-collateralized reserve (`contract/basis.es`)
    Erg,
    /// Token-collateralized reserve (`contract/basis-token.es`); the token id is
    /// read per box from `tokens(1)`
    Token,
}

/// A scanned reserve box tagged with the contract slot and address it was found at.
pub struct TaggedScanBox {
    pub scan_box: ScanBox,
    pub kind: ReserveContractKind,
    /// The reserve contract P2S address this box was found at (its contract address).
    pub contract_address: String,
}

/// Configuration for scanner. `Debug` hides `api_key` and any credentials in `node_url`.
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Starting block height for scanning
    pub start_height: Option<u64>,
    /// Basis reserve contract P2S address (optional)
    pub reserve_contract_p2s: Option<String>,
    /// Basis token reserve contract P2S address (optional). Reserves found at this
    /// address are token-backed; the denomination is derived per box from `tokens(1)`
    /// (specs/ergo/multi_collateral_reserves.md).
    pub token_reserve_contract_p2s: Option<String>,
    /// This tracker's NFT ID (hex-encoded, 32 bytes). When set, reserve boxes whose R6
    /// register does not reference this NFT are rejected (C4 validation).
    pub tracker_nft_id: Option<String>,
    /// Ergo node URL
    pub node_url: String,
    /// Scan registration name
    pub scan_name: Option<String>,
    /// API key for Ergo node authentication
    pub api_key: Option<String>,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let NodeConfig {
            start_height,
            reserve_contract_p2s,
            token_reserve_contract_p2s,
            tracker_nft_id,
            node_url,
            scan_name,
            api_key,
        } = self;
        f.debug_struct("NodeConfig")
            .field("start_height", start_height)
            .field("reserve_contract_p2s", reserve_contract_p2s)
            .field("token_reserve_contract_p2s", token_reserve_contract_p2s)
            .field("tracker_nft_id", tracker_nft_id)
            .field("node_url", &crate::redact::Url(node_url))
            .field("scan_name", scan_name)
            .field("api_key", &crate::redact::Secret(api_key))
            .finish()
    }
}

/// Inner state for scanner that requires synchronization
#[derive(Clone)]
pub struct ServerStateInner {
    pub current_height: u64,
    pub last_scanned_height: u64,
    pub scan_active: bool,
}

/// Server state for scanner
/// Uses real blockchain integration with proper synchronization
#[derive(Clone)]
pub struct ServerState {
    pub config: NodeConfig,
    pub inner: Arc<Mutex<ServerStateInner>>,
    pub client: Client,
    pub reserve_tracker: ReserveTracker,
    pub metadata_storage: ScannerMetadataStorage,
    pub reserve_storage: ReserveStorage,
    /// Reserve NFTs of tracked boxes and singleton verdicts (round 6c).
    pub nft_cache: Arc<std::sync::Mutex<NftCache>>,
    /// What the current scan cycle has asked the node (round 6d).
    pub cycle: Arc<std::sync::Mutex<CycleState>>,
    /// Round 7 (N9): the interim guard against reopening a reserve after redemptions, shared
    /// with the tracker thread and `/reserves/create`. Off unless the server sets it from
    /// `[server] reserve_reopen_guard` (`main.rs`), so a scanner built here alone behaves as
    /// before round 7.
    pub reopen_guard: ReopenGuard,
}

impl ServerState {
    /// Create HTTP request builder with API key header if configured
    fn request_builder(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        debug!("Request method: {}, URL: {}", method, url);

        let mut request = self.client.request(method, url);

        // Add API key header if configured (never log the key itself)
        if let Some(api_key) = &self.config.api_key {
            debug!("Using configured API key for request to: {}", url);
            request = request.header("api_key", api_key);
        } else {
            debug!("No API key configured for request to: {}", url);
        }

        request
    }

    /// Create a server state that uses real Ergo scanner
    pub fn new(config: NodeConfig, data_dir: impl AsRef<Path>) -> Result<Self, ScannerError> {
        let start_height = config.start_height.unwrap_or(0);
        let client = crate::http::bounded_client();
        let data_dir = data_dir.as_ref();

        // Log which Ergo node is being used (INFO level); never log the API key
        info!("Initializing Ergo scanner with node: {}", config.node_url);
        if config.api_key.is_some() {
            info!("Ergo node API key is configured");
        } else {
            warn!("No API key configured for Ergo node");
        }

        // Open scanner metadata storage - create directory if it doesn't exist
        let storage_path = data_dir.join("scanner_metadata");

        // Create directory if it doesn't exist
        if let Some(parent) = storage_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ScannerError::StoreError(format!(
                    "Failed to create scanner metadata directory: {}",
                    e
                ))
            })?;
        }

        let metadata_storage = ScannerMetadataStorage::open(&storage_path).map_err(|e| {
            ScannerError::StoreError(format!("Failed to open scanner metadata storage: {:?}", e))
        })?;

        // Open reserve storage - create directory if it doesn't exist
        let reserve_storage_path = data_dir.join("reserves");

        // Create directory if it doesn't exist
        if let Some(parent) = reserve_storage_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ScannerError::StoreError(format!(
                    "Failed to create reserve storage directory: {}",
                    e
                ))
            })?;
        }

        let reserve_storage = ReserveStorage::open(&reserve_storage_path).map_err(|e| {
            ScannerError::StoreError(format!("Failed to open reserve storage: {:?}", e))
        })?;

        // Create reserve tracker and load existing reserves from database
        let reserve_tracker = ReserveTracker::new();

        // Load existing reserves from database. Round 8 (operator: refuse to
        // start): all of them, or no scanner state at all. Started with fewer,
        // the scanner would judge the live reserve boxes it no longer tracks as
        // new roots (and quarantine them), and prune their stored NFT facts.
        let existing_reserves = reserve_storage
            .tracked_reserves_at_start()
            .map_err(|e| {
                ScannerError::ReservesUnreadable(refuse_start_message(&reserve_storage_path, &e))
            })?;
        let reserves_count = existing_reserves.len();
        for reserve in existing_reserves {
            let box_id = reserve.box_id.clone();
            reserve_tracker.update_reserve(reserve).map_err(|e| {
                ScannerError::ReservesUnreadable(format!(
                    "Refusing to start: tracked reserve record {} in {} (partition \"reserves\") cannot be loaded ({}). To recover, restore the data directory from the latest backup in {}, or remove that record by hand, then start the tracker again.",
                    crate::persistence::printable_key(box_id.as_bytes()),
                    reserve_storage_path.display(),
                    e,
                    RESERVE_BACKUP_DIR
                ))
            })?;
        }
        info!("Loaded {} reserves from database", reserves_count);
        // Round 6f: the reserve boxes removed lately, so a restart keeps them.
        let mut nft_cache = NftCache::default();
        let removed_loaded = match reserve_storage.removed_reserves() {
            Ok(removed) => {
                for entry in removed {
                    nft_cache.removed.insert(entry.record.box_id.clone(), entry);
                }
                true
            }
            Err(e) => {
                warn!("Failed to load removed reserves: {:?}", e);
                false
            }
        };
        let tracked: std::collections::HashSet<String> = reserve_tracker
            .get_all_reserves()
            .into_iter()
            .map(|reserve| reserve.box_id)
            .collect();
        load_nft_facts(&reserve_storage, &tracked, removed_loaded, &mut nft_cache);

        // Create synchronized inner state
        let inner = Arc::new(Mutex::new(ServerStateInner {
            current_height: 0,
            last_scanned_height: start_height,
            scan_active: false,
        }));

        Ok(Self {
            config,
            inner,
            client,
            reserve_tracker,
            metadata_storage,
            reserve_storage,
            nft_cache: Arc::new(std::sync::Mutex::new(nft_cache)),
            cycle: Arc::default(),
            reopen_guard: ReopenGuard::default(),
        })
    }

    /// Fetch current blockchain height directly from the node, bypassing cache.
    /// Used by the scanner loop so it detects new blocks immediately instead of
    /// reusing a potentially stale cached value for up to 10 minutes.
    pub async fn fetch_current_height(&self) -> Result<u64, ScannerError> {
        let url = format!("{}/info", self.config.node_url);
        info!("Fetching current blockchain height from: {}", url);

        let response = self
            .request_builder(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(|e| ScannerError::HttpError(format!("Failed to connect to node: {}", e)))?;

        if !response.status().is_success() {
            return Err(ScannerError::NodeError(format!(
                "Node returned status: {}",
                response.status()
            )));
        }

        let info: serde_json::Value = crate::http::read_json_capped(response)
            .await
            .map_err(|e| ScannerError::JsonError(format!("Failed to parse node info: {}", e)))?;

        let height = info["fullHeight"].as_u64().ok_or_else(|| {
            ScannerError::NodeError("Failed to parse fullHeight from node info".to_string())
        })?;

        // Keep the cache fresh for other callers that don't need the latest height.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if let Err(e) = self.metadata_storage.store_blockchain_height(height, now) {
            warn!("Failed to cache blockchain height: {:?}", e);
        }

        Ok(height)
    }

    /// Get current blockchain height from cache or Ergo node.
    /// Uses cached value if less than 10 minutes old, otherwise fetches from node.
    pub async fn get_current_height(&self) -> Result<u64, ScannerError> {
        const CACHE_TTL_MS: u64 = 600_000; // 10 minutes in milliseconds

        // Check if we have a cached height
        match self.metadata_storage.get_blockchain_height() {
            Ok(Some((cached_height, cached_timestamp))) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                if now.saturating_sub(cached_timestamp) < CACHE_TTL_MS {
                    debug!("Using cached blockchain height: {}", cached_height);
                    return Ok(cached_height);
                }

                debug!("Cached blockchain height expired, fetching from node");
            }
            Ok(None) => {
                debug!("No cached blockchain height found, fetching from node");
            }
            Err(e) => {
                warn!("Failed to read cached blockchain height: {:?}", e);
            }
        }

        // Fetch from node
        let url = format!("{}/info", self.config.node_url);

        let response = self
            .request_builder(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(|e| ScannerError::HttpError(format!("Failed to connect to node: {}", e)))?;

        if !response.status().is_success() {
            return Err(ScannerError::NodeError(format!(
                "Node returned status: {}",
                response.status()
            )));
        }

        let info: serde_json::Value = crate::http::read_json_capped(response)
            .await
            .map_err(|e| ScannerError::JsonError(format!("Failed to parse node info: {}", e)))?;

        let height = info["fullHeight"].as_u64().ok_or_else(|| {
            ScannerError::NodeError("Failed to parse fullHeight from node info".to_string())
        })?;

        // Store in cache with current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if let Err(e) = self.metadata_storage.store_blockchain_height(height, now) {
            warn!("Failed to cache blockchain height: {:?}", e);
        }

        Ok(height)
    }

    /// One page (`offset`, `RESERVE_BOX_PAGE_LIMIT` boxes) of the unspent boxes
    /// at `address`.
    async fn fetch_reserve_page(
        &self,
        url: &str,
        address: &str,
        offset: u64,
    ) -> Result<ByAddressResponse, ScannerError> {
        let response = self
            .request_builder(reqwest::Method::POST, url)
            .query(&[
                ("offset", offset.to_string()),
                ("limit", RESERVE_BOX_PAGE_LIMIT.to_string()),
            ])
            .json(&address)
            .send()
            .await
            .map_err(|e| {
                ScannerError::HttpError(format!(
                    "Failed to fetch reserve boxes for {}: {}",
                    address, e
                ))
            })?;

        let status = response.status();
        if !status.is_success() {
            let response_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response".to_string());
            error!(
                "Failed to get reserve boxes for {} with status {}: {}",
                address, status, response_text
            );
            return Err(ScannerError::NodeError(format!(
                "Failed to get reserve boxes for {} with status: {}",
                address, status
            )));
        }

        let parsed: ByAddressResponse = crate::http::read_json_capped(response)
            .await
            .map_err(|e| {
                ScannerError::JsonError(format!(
                    "Failed to parse reserve boxes response for {}: {}",
                    address, e
                ))
            })
            .and_then(|value| {
                serde_json::from_value(value).map_err(|e| {
                    ScannerError::JsonError(format!(
                        "Failed to parse reserve boxes response for {}: {}",
                        address, e
                    ))
                })
            })?;
        Ok(parsed)
    }

    /// Get unspent reserve boxes via `POST /blockchain/box/unspent/byAddress`,
    /// tagged with the contract slot and address they were found at.
    /// Queries both the ERG-backed and token-backed reserve contract addresses when
    /// configured, merging the results and removing duplicates.
    pub async fn get_unspent_reserve_boxes_tagged(
        &self,
    ) -> Result<Vec<TaggedScanBox>, ScannerError> {
        let mut slots = Vec::new();
        if let Some(ref p2s) = self.config.reserve_contract_p2s {
            if !p2s.is_empty() {
                slots.push((p2s.clone(), ReserveContractKind::Erg));
            }
        }
        if let Some(ref p2s) = self.config.token_reserve_contract_p2s {
            if !p2s.is_empty() {
                slots.push((p2s.clone(), ReserveContractKind::Token));
            }
        }

        if slots.is_empty() {
            warn!("No reserve contract P2S specified, scanner will have no boxes to fetch");
            return Ok(Vec::new());
        }

        let url = format!("{}/blockchain/box/unspent/byAddress", self.config.node_url);
        let mut all_boxes: Vec<TaggedScanBox> = Vec::new();

        for (address, kind) in slots {
            info!("Fetching unspent reserve boxes for contract: {}", address);

            // The node applies a default limit of 5 boxes (newest first) when no
            // `limit` is given, which silently drops older reserves. Page through
            // the full result set: keep fetching until a page comes back short.
            let mut offset: u64 = 0;
            let mut address_box_count = 0usize;
            loop {
                let parsed = self.fetch_reserve_page(&url, &address, offset).await?;
                let page_len = parsed.len();
                address_box_count += page_len;
                all_boxes.extend(parsed.into_iter().map(|b| TaggedScanBox {
                    scan_box: b.into(),
                    kind,
                    contract_address: address.clone(),
                }));

                if (page_len as u64) < RESERVE_BOX_PAGE_LIMIT {
                    break;
                }
                offset += RESERVE_BOX_PAGE_LIMIT;
            }
            // Round 6e (P1): newest first, a box made while the later pages were
            // read lands on page 0, already read; read it again. (A box missed
            // anyway is not removed: see `process_scan_boxes`.)
            if offset > 0 {
                let again = self.fetch_reserve_page(&url, &address, 0).await?;
                all_boxes.extend(again.into_iter().map(|b| TaggedScanBox {
                    scan_box: b.into(),
                    kind,
                    contract_address: address.clone(),
                }));
            }

            info!("Found {} reserve boxes for {}", address_box_count, address);
        }

        // Deduplicate by box_id in case both contracts somehow return the same box.
        let mut seen = std::collections::HashSet::new();
        all_boxes.retain(|b| seen.insert(b.scan_box.box_id.clone()));

        info!("Total unique reserve boxes: {}", all_boxes.len());
        Ok(all_boxes)
    }

    /// Get unspent reserve boxes without contract-slot tags.
    pub async fn get_unspent_reserve_boxes(&self) -> Result<Vec<ScanBox>, ScannerError> {
        Ok(self
            .get_unspent_reserve_boxes_tagged()
            .await?
            .into_iter()
            .map(|t| t.scan_box)
            .collect())
    }

    /// Check if scanner is active
    pub async fn is_active(&self) -> bool {
        // Use async lock for async context
        let inner = self.inner.lock().await;
        inner.scan_active
    }

    /// Start scanning with real blockchain integration
    pub async fn start_scanning(&mut self) -> Result<(), ScannerError> {
        info!("Starting Ergo blockchain scanner for reserves");

        if self.config.reserve_contract_p2s.is_none()
            && self.config.token_reserve_contract_p2s.is_none()
        {
            warn!("No reserve contract P2S specified, scanner will have no boxes to fetch");
        }

        // Update inner state
        {
            let mut inner = self.inner.lock().await;
            inner.scan_active = true;
        }

        Ok(())
    }

    /// Get last scanned height
    pub async fn last_scanned_height(&self) -> u64 {
        let inner = self.inner.lock().await;
        inner.last_scanned_height
    }

    /// Get the reserve tracker
    pub fn reserve_tracker(&self) -> &ReserveTracker {
        &self.reserve_tracker
    }

    /// Get the reserve storage for direct database access
    pub fn reserve_storage(&self) -> &ReserveStorage {
        &self.reserve_storage
    }

    /// Get unspent boxes from the blockchain via the reserve contract address.
    pub async fn get_scan_boxes(&self) -> Result<Vec<TaggedScanBox>, ScannerError> {
        self.get_unspent_reserve_boxes_tagged().await
    }

    /// Parse reserve box into ExtendedReserveInfo.
    ///
    /// Collateral and denomination are derived **per box** from the contract slot the
    /// box was found at (specs/ergo/multi_collateral_reserves.md):
    /// - Erg slot: collateral is the box ERG value.
    /// - Token slot: the box must hold exactly two tokens (reserve NFT at #0, reserve
    ///   token at #1); collateral is the #1 amount and the denomination is its id.
    pub fn parse_reserve_box(
        &self,
        scan_box: &ScanBox,
        kind: ReserveContractKind,
        contract_address: &str,
    ) -> Result<ExtendedReserveInfo, ScannerError> {
        let box_id = scan_box.box_id.clone();
        let value = scan_box.value;
        let creation_height = scan_box.creation_height;

        // Extract owner public key from R4 register
        let owner_pubkey_raw = scan_box
            .additional_registers
            .get("R4")
            .ok_or_else(|| {
                ScannerError::InvalidReserveBox(format!("Missing R4 register in box {}", box_id))
            })?
            .clone();

        // Strip the 0x07 prefix if present (GroupElement type identifier from Ergo registers)
        let owner_pubkey = if owner_pubkey_raw.starts_with("07") && owner_pubkey_raw.len() >= 66 {
            // Extract the actual 33-byte public key (66 hex chars) after the 0x07 prefix
            owner_pubkey_raw[2..].to_string()
        } else {
            // Use as-is if no prefix or wrong length
            owner_pubkey_raw
        };

        // Extract tracker NFT ID from R6 register (required according to spec)
        let tracker_nft_id_raw = scan_box
            .additional_registers
            .get("R6")
            .ok_or_else(|| {
                ScannerError::InvalidReserveBox(format!("Missing R6 register in box {}", box_id))
            })?
            .clone();

        // Create extended reserve info
        // Decode the hex-encoded public key to actual bytes
        let owner_pubkey_bytes = hex::decode(&owner_pubkey).map_err(|_| {
            ScannerError::InvalidReserveBox(format!(
                "Invalid hex in owner pubkey for box {}",
                box_id
            ))
        })?;

        // C4: R4 must be a valid compressed secp256k1 point, otherwise the
        // reserve can never be redeemed against on-chain.
        let owner_pubkey_array: &[u8; 33] =
            owner_pubkey_bytes.as_slice().try_into().map_err(|_| {
                ScannerError::InvalidReserveBox(format!(
                    "Invalid owner pubkey length in box {}: expected 33 bytes, got {}",
                    box_id,
                    owner_pubkey_bytes.len()
                ))
            })?;
        basis_core::impls::validate_public_key(owner_pubkey_array).map_err(|_| {
            ScannerError::InvalidReserveBox(format!(
                "Invalid owner pubkey (not a valid curve point) in box {}",
                box_id
            ))
        })?;

        // Decode the hex-encoded tracker NFT ID to actual bytes
        // R6 contains a Coll[Byte] value with Ergo serialization prefix: 0e20 (type + length)
        // We need to strip the first 2 bytes (4 hex chars) to get the actual data
        let tracker_nft_hex = if tracker_nft_id_raw.len() >= 4 {
            &tracker_nft_id_raw[4..]
        } else {
            tracker_nft_id_raw.as_str()
        };
        let tracker_nft_id_bytes = hex::decode(tracker_nft_hex).map_err(|_| {
            ScannerError::InvalidReserveBox(format!(
                "Invalid hex in tracker NFT ID for box {}",
                box_id
            ))
        })?;

        // Validate that the tracker NFT ID is exactly 32 bytes (the actual tracker NFT ID)
        if tracker_nft_id_bytes.len() != 32 {
            return Err(ScannerError::InvalidReserveBox(format!(
                "Invalid tracker NFT ID length in box {}: expected 32 bytes, got {}",
                box_id,
                tracker_nft_id_bytes.len()
            )));
        }

        // C4: when this tracker's NFT ID is configured, R6 must reference it,
        // otherwise the reserve is bound to a different (or fake) tracker.
        if let Some(configured_nft) = self
            .config
            .tracker_nft_id
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            if !tracker_nft_hex.eq_ignore_ascii_case(configured_nft) {
                return Err(ScannerError::InvalidReserveBox(format!(
                    "Tracker NFT ID mismatch in box {}: R6 references {}, this tracker is {}",
                    box_id, tracker_nft_hex, configured_nft
                )));
            }
        }

        // C4: R7 must be a serialized Long (type byte 0x05) when present. Any
        // other type (e.g. Int) makes SELF.R7[Long] throw on-chain, bricking
        // the box, while the scanner would silently read it as 0.
        if let Some(r7_raw) = scan_box.additional_registers.get("R7") {
            if !r7_raw.starts_with("05") {
                return Err(ScannerError::InvalidReserveBox(format!(
                    "R7 register in box {} is not a Long (expected 0x05 prefix): {}",
                    box_id, r7_raw
                )));
            }
        }

        // Extract refund initiation height from R7 register (optional; absent = 0)
        let refund_initiation_height =
            decode_ergo_long_register(scan_box.additional_registers.get("R7"));

        // Derive collateral and denomination per box from the contract slot.
        let (collateral_amount, reserve_token_id_bytes) = match kind {
            ReserveContractKind::Erg => (value, None),
            ReserveContractKind::Token => {
                // The token reserve contract pins positions: tokens(0) is the reserve
                // NFT (amount 1), tokens(1) is the collateral token. Anything else is
                // malformed and cannot be redeemed on-chain.
                if scan_box.assets.len() != 2 {
                    return Err(ScannerError::InvalidReserveBox(format!(
                        "Token reserve box {} must hold exactly 2 tokens (reserve NFT + collateral token), got {}",
                        box_id,
                        scan_box.assets.len()
                    )));
                }
                let collateral_asset = &scan_box.assets[1];
                let token_bytes = hex::decode(&collateral_asset.token_id).map_err(|_| {
                    ScannerError::InvalidReserveBox(format!(
                        "Invalid collateral token id hex in box {}",
                        box_id
                    ))
                })?;
                if token_bytes.len() != 32 {
                    return Err(ScannerError::InvalidReserveBox(format!(
                        "Collateral token id in box {} is not 32 bytes",
                        box_id
                    )));
                }
                (collateral_asset.amount, Some(token_bytes))
            }
        };

        // NOTE (issue #19): the C4 setup checks (R7 == 0, empty R5 tree) are NOT
        // done here. They depend on tracker state (they apply only to root boxes,
        // never to legitimate top-up/redemption successors), so they live in
        // `admit_reserve_box`. This function is purely per-box structural
        // validation.

        let box_id_bytes = hex::decode(&box_id).unwrap_or_else(|_| box_id.as_bytes().to_vec());
        let mut reserve_info = ExtendedReserveInfo::new(
            &box_id_bytes,
            &owner_pubkey_bytes,
            collateral_amount,
            Some(&tracker_nft_id_bytes),
            creation_height,
            refund_initiation_height,
            reserve_token_id_bytes.as_deref(),
        );
        // The contract address is where the box was actually found, not a global
        // config value (ERG and token reserves live at different addresses).
        reserve_info.set_contract_address(contract_address.to_string());

        Ok(reserve_info)
    }

    /// C4 setup checks for a root candidate (the first box of an
    /// (owner, denomination) lineage). Returns the violation reason, or `None`
    /// when the box is a cleanly created reserve.
    ///
    /// A reserve created with a pending refund (R7 != 0) can be withdrawn
    /// immediately, and a reserve created with a non-empty tree (R5) can block
    /// creditors from ever redeeming, so neither must be counted as collateral.
    /// These checks must NOT run on successor boxes: a redemption legitimately
    /// leaves R5 non-empty and refund initiation legitimately sets R7.
    fn root_setup_violation(
        scan_box: &ScanBox,
        reserve_info: &ExtendedReserveInfo,
    ) -> Option<String> {
        // Round 6b: the lineage is followed by the reserve NFT, so a root without
        // one could never be followed past its first action.
        if scan_box
            .assets
            .first()
            .and_then(|asset| reserve_nft(&asset.token_id, asset.amount))
            .is_none()
        {
            return Some(format!(
                "Reserve box {} created without a reserve NFT (a token held once at tokens(0))",
                reserve_info.box_id
            ));
        }
        if reserve_info.base_info.refund_initiation_height != 0 {
            return Some(format!(
                "Reserve box {} created with a pending refund (R7 = {})",
                reserve_info.box_id, reserve_info.base_info.refund_initiation_height
            ));
        }
        let empty_tree_register = empty_reserve_tree_register();
        match scan_box.additional_registers.get("R5") {
            Some(r5) if r5.eq_ignore_ascii_case(&empty_tree_register) => None,
            other => Some(format!(
                "Reserve box {} created with a non-empty AVL tree (R5 = {:?})",
                reserve_info.box_id, other
            )),
        }
    }

    /// Fetch the inputs of a transaction via
    /// `GET /blockchain/transaction/byId/{txId}` (the index gives each input as
    /// a full box).
    async fn fetch_tx_inputs(
        &self,
        tx_id: &str,
        lane: Lane,
    ) -> Result<Vec<ChainBox>, ScannerError> {
        if let Some(known) = self.cycle_state().tx_inputs.get(tx_id) {
            return known.clone().map_err(ScannerError::NodeError);
        }
        if lane == Lane::Shared {
            self.take_node_budget(tx_id)?;
        }
        let fetched = self.fetch_tx_inputs_uncached(tx_id).await;
        let size = fetched
            .as_ref()
            .map_or(0, |inputs| inputs.iter().map(ChainBox::approx_bytes).sum());
        let mut cycle = self.cycle_state();
        if cycle.memo_bytes + size <= CYCLE_MEMO_BYTES {
            cycle.memo_bytes += size;
            cycle.tx_inputs.insert(
                tx_id.to_string(),
                fetched.as_ref().map(Vec::clone).map_err(|e| e.to_string()),
            );
        }
        drop(cycle);
        fetched
    }

    async fn fetch_tx_inputs_uncached(&self, tx_id: &str) -> Result<Vec<ChainBox>, ScannerError> {
        let url = format!(
            "{}/blockchain/transaction/byId/{}",
            self.config.node_url, tx_id
        );

        let response = self
            .request_builder(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(|e| {
                ScannerError::HttpError(format!("Failed to fetch transaction {}: {}", tx_id, e))
            })?;

        if !response.status().is_success() {
            return Err(ScannerError::NodeError(format!(
                "Node returned status {} for transaction {}",
                response.status(),
                tx_id
            )));
        }

        let tx: serde_json::Value = crate::http::read_json_capped(response).await.map_err(|e| {
            ScannerError::JsonError(format!("Failed to parse transaction {}: {}", tx_id, e))
        })?;

        let inputs = tx.get("inputs").and_then(|i| i.as_array()).ok_or_else(|| {
            ScannerError::JsonError(format!("Transaction {} has no inputs array", tx_id))
        })?;

        Ok(inputs.iter().filter_map(ChainBox::from_json).collect())
    }

    /// GET `/blockchain/box/byId/{id}`: the box, spent or unspent, as the index
    /// gives it; `None` when the index does not know it.
    async fn fetch_indexed_box(
        &self,
        box_id: &str,
        lane: Lane,
    ) -> Result<Option<ChainBox>, ScannerError> {
        if let Some(known) = self.cycle_state().boxes.get(box_id) {
            return known.clone().map_err(ScannerError::NodeError);
        }
        if lane == Lane::Shared {
            self.take_node_budget(box_id)?;
        }
        let fetched = self.fetch_indexed_box_uncached(box_id).await;
        self.cycle_state().boxes.insert(
            box_id.to_string(),
            fetched
                .as_ref()
                .map(Option::clone)
                .map_err(|e| e.to_string()),
        );
        fetched
    }

    /// The height of the block that included transaction `tx_id`
    /// (`inclusionHeight`), or `None` when the node cannot tell.
    async fn fetch_tx_inclusion_height(&self, tx_id: &str) -> Option<u64> {
        let url = format!(
            "{}/blockchain/transaction/byId/{}",
            self.config.node_url, tx_id
        );
        let mut response = self
            .request_builder(reqwest::Method::GET, &url)
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        // Round 6e: only the start of the body is read, so a transaction over
        // the body cap still tells its height. The transaction's own field
        // comes before its inputs (whose boxes have one too).
        let mut prefix: Vec<u8> = Vec::new();
        let mut complete = false;
        while prefix.len() < TX_PREFIX_BYTES {
            match response.chunk().await {
                Ok(Some(chunk)) => prefix.extend_from_slice(&chunk),
                Ok(None) => {
                    complete = true;
                    break;
                }
                Err(_) => return None,
            }
        }
        let text = String::from_utf8_lossy(&prefix);
        let head = match text.find("\"inputs\"") {
            Some(end) => &text[..end],
            None if complete => &text[..],
            None => return None,
        };
        let after = &head[head.find("\"inclusionHeight\"")? + "\"inclusionHeight\"".len()..];
        let digits = after.trim_start().strip_prefix(':')?.trim_start();
        let end = digits
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(digits.len());
        digits[..end].parse::<u64>().ok().filter(|h| *h > 0)
    }

    async fn fetch_indexed_box_uncached(
        &self,
        box_id: &str,
    ) -> Result<Option<ChainBox>, ScannerError> {
        let url = format!("{}/blockchain/box/byId/{}", self.config.node_url, box_id);
        let response = self
            .request_builder(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(|e| {
                ScannerError::HttpError(format!("Failed to fetch box {}: {}", box_id, e))
            })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(ScannerError::NodeError(format!(
                "Node returned status {} for box {}",
                response.status(),
                box_id
            )));
        }
        let value: serde_json::Value =
            crate::http::read_json_capped(response).await.map_err(|e| {
                ScannerError::JsonError(format!("Failed to parse box {}: {}", box_id, e))
            })?;
        ChainBox::from_json(&value)
            .map(Some)
            .ok_or_else(|| ScannerError::JsonError(format!("Box {} has no boxId", box_id)))
    }

    /// The reserve NFT of a tracked box (round 6c, P1-2): cached, else read once
    /// with `/blockchain/box/byId` (the box may be spent by now). `None` when
    /// the box holds no reserve NFT.
    async fn tracked_nft(&self, box_id: &str) -> Result<Option<String>, ScannerError> {
        if let Some(nft) = self.nft_cache().box_nft.get(box_id) {
            return Ok(nft.clone());
        }
        let Some(chain_box) = self.fetch_indexed_box(box_id, Lane::Tracked).await? else {
            return Err(ScannerError::NodeError(format!(
                "Tracked reserve box {} is not in the blockchain index",
                box_id
            )));
        };
        let nft = chain_box.reserve_nft();
        self.remember_nft(box_id, nft.clone());
        Ok(nft)
    }

    /// Whether the token index gives `nft` an emission of exactly 1 (round 6c,
    /// P2-2): only then can no other box ever hold it. Cached per token.
    async fn is_singleton_nft(&self, nft: &str, lane: Lane) -> Result<bool, ScannerError> {
        if let Some(singleton) = self.nft_cache().singleton.get(nft) {
            return Ok(*singleton);
        }
        if lane == Lane::Shared {
            self.take_node_budget(nft)?;
        }
        let url = format!("{}/blockchain/token/byId/{}", self.config.node_url, nft);
        let response = self
            .request_builder(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(|e| {
                ScannerError::HttpError(format!("Failed to fetch token {}: {}", nft, e))
            })?;
        if !response.status().is_success() {
            return Err(ScannerError::NodeError(format!(
                "Node returned status {} for token {}",
                response.status(),
                nft
            )));
        }
        let token: serde_json::Value =
            crate::http::read_json_capped(response).await.map_err(|e| {
                ScannerError::JsonError(format!("Failed to parse token {}: {}", nft, e))
            })?;
        let Some(emission) = token.get("emissionAmount").and_then(|a| a.as_u64()) else {
            return Err(ScannerError::JsonError(format!(
                "Token {} has no emissionAmount",
                nft
            )));
        };
        let singleton = emission == 1;
        let store = {
            let mut cache = self.nft_cache();
            cache.singleton.insert(nft.to_string(), singleton);
            // Round 8: stored when a tracked box holds it (else once one does,
            // `remember_nft`), so the store keeps the NFTs of tracked reserves
            // only, not those of every root candidate.
            singleton
                && cache
                    .box_nft
                    .values()
                    .any(|held| held.as_deref() == Some(nft))
                && cache.stored_singletons.insert(nft.to_string())
        };
        if store {
            self.store_singleton(nft);
        }
        Ok(singleton)
    }

    fn nft_cache(&self) -> std::sync::MutexGuard<'_, NftCache> {
        self.nft_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn cycle_state(&self) -> std::sync::MutexGuard<'_, CycleState> {
        self.cycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Remember the reserve NFT of tracked box `box_id` (round 6c). Round 8: a
    /// new NFT is also stored, and so is its singleton verdict when known. A
    /// box id names one box, so a known NFT is kept when an answer shows none
    /// (a box listed without its assets, say).
    fn remember_nft(&self, box_id: &str, nft: Option<String>) {
        let (store_nft, store_singleton) = {
            let mut cache = self.nft_cache();
            if nft.is_none() && matches!(cache.box_nft.get(box_id), Some(Some(_))) {
                return;
            }
            let before = cache.box_nft.insert(box_id.to_string(), nft.clone());
            let Some(nft) = nft else {
                return;
            };
            let store_nft = before.as_ref() != Some(&Some(nft.clone()))
                || !cache.stored_box_nfts.contains(box_id);
            let store_singleton = cache.singleton.get(&nft) == Some(&true)
                && cache.stored_singletons.insert(nft.clone());
            (store_nft.then(|| nft.clone()), store_singleton.then_some(nft))
        };
        if let Some(nft) = store_nft {
            match self.reserve_storage.store_box_nft(box_id, &nft) {
                Ok(()) => {
                    self.nft_cache().stored_box_nfts.insert(box_id.to_string());
                }
                // Review LOW-4: tried again the next time the box is seen.
                Err(e) => {
                    self.nft_cache().stored_box_nfts.remove(box_id);
                    warn!("Failed to store the NFT of reserve box {}: {:?}", box_id, e);
                }
            }
        }
        if let Some(nft) = store_singleton {
            self.store_singleton(&nft);
        }
    }

    /// Round 8: store that `nft` is a singleton (emission 1).
    fn store_singleton(&self, nft: &str) {
        if let Err(e) = self.reserve_storage.store_nft_emission(nft, 1) {
            warn!("Failed to store the emission of NFT {}: {:?}", nft, e);
            self.nft_cache().stored_singletons.remove(nft);
        }
    }

    /// Count one node request of the lineage checks against this cycle's
    /// budget (round 6c): junk candidates cannot make a cycle unbounded.
    fn take_node_budget(&self, what: &str) -> Result<(), ScannerError> {
        let mut cycle = self.cycle_state();
        if cycle
            .started
            .is_some_and(|started| started.elapsed() > CYCLE_TIME_LIMIT)
        {
            return Err(ScannerError::NodeError(format!(
                "scan cycle time limit of {} s used up before reading {}",
                CYCLE_TIME_LIMIT.as_secs(),
                what
            )));
        }
        let used = cycle.requests;
        cycle.requests += 1;
        if used >= LINEAGE_REQUESTS_PER_CYCLE {
            return Err(ScannerError::NodeError(format!(
                "lineage request budget of this cycle ({}) is used up before {}",
                LINEAGE_REQUESTS_PER_CYCLE, what
            )));
        }
        Ok(())
    }

    /// Verdict on `scan_box`, which holds the reserve NFT `nft` of the tracked
    /// box `anchor`; `Err` is no verdict this cycle (retry).
    ///
    /// Both reserve contracts keep the token list, the R4 owner and the R6
    /// tracker NFT of the output a reserve input names (`selfPreserved`), and
    /// only the owner's signature takes tokens out (refund completion). A top-up
    /// needs no signature, so anyone may add other reserve-contract outputs with
    /// the owner's R4 to a transaction spending the reserve (round 6b); only the
    /// box holding the NFT continues the lineage.
    ///
    /// 1. The tracked box must hold the NFT with the same R4 and R6. When the
    ///    transaction that spent it created `scan_box` and the NFT is a
    ///    singleton, that is the successor (no transaction is read, however
    ///    large).
    /// 2. Otherwise the walk goes back from `scan_box` through the creating
    ///    transactions, each time to the input that holds the NFT at
    ///    `tokens(0)` with amount 1, the same R4 and R6, and is the tracked box
    ///    or at the reserve contract, until that input is the tracked box or was
    ///    created by the transaction that spent it (at most
    ///    `LINEAGE_WALK_DEPTH` transactions). No such input: not a successor.
    /// 3. When the walk gives no verdict (depth used up, a transaction over the
    ///    body cap, a node error; round 6c P1-1/P1-2), a singleton NFT decides:
    ///    with the tracked box spent, no other box can hold it. So it does when
    ///    the index does not know the tracked box (a reorg dropped it) or shows
    ///    it unspent (round 6d, P2-1).
    ///
    /// Every step must keep a pending refund (R7 != 0): only the owner's refund
    /// completion does not, and then the box is judged as a root (round 6d,
    /// P2-2). The tracked box and the singleton lookup are read on the tracked
    /// lane (round 6d, P1).
    async fn is_lineage_successor(
        &self,
        scan_box: &ScanBox,
        nft: &str,
        anchor: &ExtendedReserveInfo,
        contract_address: &str,
    ) -> Result<Lineage, ScannerError> {
        let (Some(r4), Some(r6)) = (
            scan_box.additional_registers.get("R4"),
            scan_box.additional_registers.get("R6"),
        ) else {
            return Ok(Lineage::NotSuccessor);
        };
        let box_r7 = refund_height(scan_box.additional_registers.get("R7"));
        let anchor_r7 = anchor.base_info.refund_initiation_height;
        // The singleton decides: the tracked box cannot hold the NFT any more.
        // R4 is the anchor's owner (same owner and denomination), and
        // `parse_reserve_box` bound R6 to this tracker.
        let by_singleton = |why: String| async move {
            if self.is_singleton_nft(nft, Lane::Tracked).await? {
                info!(
                    "Reserve box {} follows tracked box {} by its singleton NFT {} ({})",
                    scan_box.box_id, anchor.box_id, nft, why
                );
                Ok(if refund_broken(anchor_r7, box_r7) {
                    Lineage::Root
                } else {
                    Lineage::Successor
                })
            } else {
                Err(ScannerError::NodeError(format!(
                    "lineage of box {} to {}: {}; its NFT {} is not a singleton",
                    scan_box.box_id, anchor.box_id, why, nft
                )))
            }
        };

        let known = self
            .fetch_indexed_box(&anchor.box_id, Lane::Tracked)
            .await?;
        let spent_by = match &known {
            None => {
                // Round 6e (P2-1): the tracked box is not on chain (a reorg
                // dropped it), so its R7 says nothing. Walk back to a box of
                // the lineage that is: one removed lately. The NFT entering the
                // box from outside any reserve box: a new reserve, a root.
                // Otherwise the singleton decides only when R7 is unchanged.
                let walked = self
                    .walk_to_spender(
                        scan_box,
                        nft,
                        r4,
                        r6,
                        &anchor.box_id,
                        anchor_r7,
                        None,
                        true,
                        contract_address,
                    )
                    .await;
                // Round 6f (P2-2): only an NFT that entered the box itself makes
                // it a root; one that entered an earlier box is where the walk
                // reached the lineage's own root, which says nothing.
                return match walked {
                    Ok(Some(Lineage::Foreign)) => Ok(Lineage::Root),
                    Ok(Some(verdict @ (Lineage::Successor | Lineage::Root))) => Ok(verdict),
                    _ if anchor_r7 == box_r7 => {
                        by_singleton(format!(
                            "the index does not know tracked box {}",
                            anchor.box_id
                        ))
                        .await
                    }
                    _ => Err(ScannerError::NodeError(format!(
                        "the index does not know tracked box {} (R7 {}), and box {} (R7 {}) does not lead \
                         back to a box of the lineage on chain",
                        anchor.box_id, anchor_r7, scan_box.box_id, box_r7
                    ))),
                };
            }
            Some(known) if !known.is_reserve_box_of(nft, r4, r6) => {
                return Ok(Lineage::NotSuccessor)
            }
            Some(known) if known.spent_tx.is_empty() => {
                // Round 6e (P2-1): the index shows the tracked box unspent, so
                // it lags or the box is an earlier one: only a box made from the
                // tracked box (the walk reaches it) follows it.
                let walked = self
                    .walk_to_spender(
                        scan_box,
                        nft,
                        r4,
                        r6,
                        &anchor.box_id,
                        anchor_r7,
                        None,
                        false,
                        contract_address,
                    )
                    .await;
                return match walked {
                    Ok(Some(verdict @ (Lineage::Successor | Lineage::Root))) => Ok(verdict),
                    _ => Err(ScannerError::NodeError(format!(
                        "tracked box {} shows unspent and box {} does not descend from it",
                        anchor.box_id, scan_box.box_id
                    ))),
                };
            }
            Some(known) => known.spent_tx.clone(),
        };
        if scan_box.transaction_id.eq_ignore_ascii_case(&spent_by) {
            if refund_broken(anchor_r7, box_r7) {
                return Ok(Lineage::Root);
            }
            if self.is_singleton_nft(nft, Lane::Tracked).await? {
                return Ok(Lineage::Successor);
            }
            // Not a singleton: the transaction is read (the walk).
        }

        let walked = self
            .walk_to_spender(
                scan_box,
                nft,
                r4,
                r6,
                &anchor.box_id,
                anchor_r7,
                Some(&spent_by),
                false,
                contract_address,
            )
            .await;
        match walked {
            Ok(Some(Lineage::Foreign)) => Ok(Lineage::NotSuccessor),
            Ok(Some(verdict)) => Ok(verdict),
            Ok(None) => {
                by_singleton(format!(
                    "no verdict within {} transactions",
                    LINEAGE_WALK_DEPTH
                ))
                .await
            }
            Err(e) => by_singleton(e.to_string()).await,
        }
    }

    /// Step 2 of [`Self::is_lineage_successor`]: `Ok(None)` when the depth runs
    /// out. It stops at the tracked box, at a box made by `spent_by` (the
    /// transaction that spent it), or, with `to_removed`, at a box removed
    /// lately (round 6e).
    #[allow(clippy::too_many_arguments)]
    async fn walk_to_spender(
        &self,
        scan_box: &ScanBox,
        nft: &str,
        r4: &str,
        r6: &str,
        known_box_id: &str,
        known_r7: u64,
        spent_by: Option<&str>,
        to_removed: bool,
        contract_address: &str,
    ) -> Result<Option<Lineage>, ScannerError> {
        let mut tx_id = scan_box.transaction_id.clone();
        let mut after_r7 = refund_height(scan_box.additional_registers.get("R7"));
        for hop in 0..LINEAGE_WALK_DEPTH {
            let inputs = self.fetch_tx_inputs(&tx_id, Lane::Shared).await?;
            if inputs.iter().any(|input| input.assets.is_none()) {
                return Err(ScannerError::JsonError(format!(
                    "Transaction {} lists an input without its assets",
                    tx_id
                )));
            }
            let Some(carrier) = inputs.iter().find(|input| {
                input.is_reserve_box_of(nft, r4, r6)
                    && (normalized_box_id(&input.box_id) == known_box_id
                        || input.address == contract_address)
            }) else {
                // The NFT came in from elsewhere (or was minted here): into the
                // box itself, or into an earlier box of its lineage (round 6f).
                return Ok(Some(if hop == 0 {
                    Lineage::Foreign
                } else {
                    Lineage::NotSuccessor
                }));
            };
            let carrier_r7 = refund_height(carrier.registers.get("R7"));
            if refund_broken(carrier_r7, after_r7) {
                return Ok(Some(Lineage::Root));
            }
            if normalized_box_id(&carrier.box_id) == known_box_id {
                return Ok(Some(Lineage::Successor));
            }
            if spent_by.is_some_and(|spent_by| carrier.creating_tx.eq_ignore_ascii_case(spent_by)) {
                return Ok(Some(if refund_broken(known_r7, carrier_r7) {
                    Lineage::Root
                } else {
                    Lineage::Successor
                }));
            }
            if to_removed
                && self
                    .nft_cache()
                    .removed
                    .contains_key(&normalized_box_id(&carrier.box_id))
            {
                return Ok(Some(Lineage::Successor));
            }
            if carrier.creating_tx.is_empty() {
                return Ok(Some(Lineage::NotSuccessor));
            }
            after_r7 = carrier_r7;
            tx_id = carrier.creating_tx.clone();
        }
        Ok(None)
    }

    /// Whether a root candidate was made by its R4 owner (issue #19): its
    /// creating transaction spends an input locked by P2PK of `owner_pubkey`
    /// (ergoTree `0008cd || 33-byte pubkey`), which only the holder of the R4
    /// key can do.
    ///
    /// Round 6c (a): a fresh reserve can be topped up (no signature needed)
    /// before the scanner first sees it. Then the walk follows its NFT back
    /// through reserve boxes (NFT at `tokens(0)`, same R4 and R6, at the
    /// contract, still clean: empty R5, R7 = 0, so only top-ups happened) to
    /// the box whose creating transaction has the owner's P2PK input.
    async fn has_owner_root(
        &self,
        scan_box: &ScanBox,
        nft: &str,
        owner_pubkey: &str,
        contract_address: &str,
    ) -> Result<bool, ScannerError> {
        let expected = p2pk_ergo_tree(owner_pubkey);
        let (Some(r4), Some(r6)) = (
            scan_box.additional_registers.get("R4"),
            scan_box.additional_registers.get("R6"),
        ) else {
            return Ok(false);
        };
        let empty_tree = empty_reserve_tree_register();
        let mut tx_id = scan_box.transaction_id.clone();
        for _ in 0..LINEAGE_WALK_DEPTH {
            let inputs = self.fetch_tx_inputs(&tx_id, Lane::Shared).await?;
            if inputs
                .iter()
                .any(|input| input.ergo_tree.eq_ignore_ascii_case(&expected))
            {
                return Ok(true);
            }
            if inputs.iter().any(|input| input.assets.is_none()) {
                return Err(ScannerError::JsonError(format!(
                    "Transaction {} lists an input without its assets",
                    tx_id
                )));
            }
            let Some(carrier) = inputs.iter().find(|input| {
                input.is_reserve_box_of(nft, r4, r6) && input.address == contract_address
            }) else {
                return Ok(false);
            };
            // Round 6d (P2-2): a reserve with a pending refund (R7 != 0) is only
            // spent into a clean box by the owner's refund completion (#0 and #1
            // keep R7, #2 needs R7 = 0, and the NFT is a singleton): the owner
            // made this box.
            if refund_height(carrier.registers.get("R7")) != 0 {
                return Ok(true);
            }
            let clean = carrier
                .registers
                .get("R5")
                .is_some_and(|r5| r5.eq_ignore_ascii_case(&empty_tree));
            if !clean || carrier.creating_tx.is_empty() {
                return Ok(false);
            }
            tx_id = carrier.creating_tx.clone();
        }
        Err(ScannerError::NodeError(format!(
            "no owner input within {} transactions before box {}",
            LINEAGE_WALK_DEPTH, scan_box.box_id
        )))
    }

    /// Admission control for a parsed reserve box (issue #19).
    ///
    /// A box is admitted only when it is
    /// 1. the currently tracked box itself (refresh), or a box removed as spent
    ///    in the last day that a reorg brought back (restored, round 6d P2-3),
    /// 2. a C4-clean root for an (owner, denomination) with no tracked reserve,
    ///    holding a singleton reserve NFT, made by the R4 owner (its creating
    ///    transaction spends a P2PK input of the R4 key, or it descends by its
    ///    NFT through top-ups from such a box, or from a reserve whose pending
    ///    refund the owner completed), or
    /// 3. the successor of a tracked box of its (owner, denomination): it holds
    ///    that box's reserve NFT at `tokens(0)` with amount 1, and the same R4
    ///    and R6 (round 6b/6c, see `is_lineage_successor`). One that does so
    ///    after the owner completed a pending refund is judged as a root.
    ///
    /// A box holding no tracked reserve's NFT while the owner has a tracked
    /// reserve in the denomination is quarantined at once, with no walk (round
    /// 6c, P1-2): a newcomer never displaces a tracked reserve. Only when none of
    /// those tracked boxes is in this cycle's scan (the owner withdrew it) is
    /// the newcomer deferred, to be judged as a root once the spent box is
    /// removed (round 6d). Anything else is quarantined too, so a dust duplicate
    /// with the victim's key in R4 can never turn `resolve_issuer_reserve`
    /// ambiguous and block the issuer. A box already persisted as quarantined
    /// stays quarantined until an operator releases it.
    pub async fn admit_reserve_box(
        &self,
        scan_box: &ScanBox,
        reserve_info: &ExtendedReserveInfo,
        contract_address: &str,
    ) -> ReserveAdmission {
        let box_id = reserve_info.box_id.clone();

        // The tracked box itself is always admitted (periodic refresh).
        if self.reserve_tracker.get_reserve(&box_id).is_ok() {
            self.remember_nft(&box_id, scan_box_nft(scan_box));
            return ReserveAdmission::Admitted;
        }
        // A tracked box a reorg brought back: it was verified when it was
        // tracked, and a box id names one box (round 6d, P2-3). Not while a
        // tracked box of the owner there is in the scan too (the index would be
        // inconsistent): then the usual checks run.
        if self.nft_cache().removed.contains_key(&box_id) {
            let denomination = reserve_info.denomination();
            let tracked_in_scan = self.cycle_state().scanned.as_ref().is_some_and(|scanned| {
                self.reserve_tracker
                    .get_reserves_by_owner(&reserve_info.owner_pubkey)
                    .iter()
                    .any(|r| r.denomination() == denomination && scanned.contains(&r.box_id))
            });
            if !tracked_in_scan {
                // The record is forgotten once the box is stored again
                // (`ingest_scan_box`, round 6f-2).
                info!(
                    "Restoring reserve box {}: it was removed as spent and is unspent again (reorg)",
                    box_id
                );
                return ReserveAdmission::Admitted;
            }
        }

        // Once quarantined, always quarantined.
        match self.reserve_storage.get_quarantined(&box_id) {
            Ok(Some(record)) => {
                return ReserveAdmission::Quarantined {
                    reason: record.reason,
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Failed to read quarantine record for {}: {:?}", box_id, e);
            }
        }

        let denomination = reserve_info.denomination();
        let denomination_id = denomination
            .as_ref()
            .map(|d| d.denomination_id())
            .unwrap_or_else(|| "unknown".to_string());
        let tracked: Vec<ExtendedReserveInfo> = self
            .reserve_tracker
            .get_reserves_by_owner(&reserve_info.owner_pubkey)
            .into_iter()
            .filter(|r| r.denomination().as_ref() == denomination.as_ref())
            .collect();
        let retry = |what: &str, e: ScannerError| {
            warn!(
                "{} for reserve box {} failed ({}); retrying next cycle",
                what, box_id, e
            );
            ReserveAdmission::Retry
        };

        // Round 6e (P1): a removed box of the owner here whose NFT this box
        // holds anchors its lineage, so the successor of a box removed lately
        // (missed by the scan for a while) is followed, not judged as a root.
        let removed_anchor = scan_box_nft(scan_box).and_then(|nft| {
            self.nft_cache()
                .removed
                .values()
                .filter(|removed| {
                    removed.nft.as_deref() == Some(nft.as_str())
                        && removed.record.owner_pubkey == reserve_info.owner_pubkey
                        && removed.record.denomination() == denomination
                })
                // Round 6f: the one removed last.
                .max_by_key(|removed| removed.removed_at)
                .map(|removed| (removed.record.clone(), nft))
        });

        if tracked.is_empty() {
            if let Some((anchor, nft)) = removed_anchor {
                match self
                    .is_lineage_successor(scan_box, &nft, &anchor, contract_address)
                    .await
                {
                    Ok(Lineage::Successor) => {
                        info!(
                            "Reserve box {} follows removed box {} by its NFT",
                            box_id, anchor.box_id
                        );
                        return ReserveAdmission::Admitted;
                    }
                    Ok(Lineage::Root) => {
                        return self
                            .admit_root(scan_box, reserve_info, contract_address, false)
                            .await
                    }
                    Ok(Lineage::NotSuccessor | Lineage::Foreign) => {}
                    Err(e) => return retry("Lineage check (removed box)", e),
                }
            }
            return self
                .admit_root(scan_box, reserve_info, contract_address, true)
                .await;
        }

        // The owner has a tracked reserve in this denomination: only the box
        // holding its NFT may continue it.
        let newcomer = |why: String, gone: bool| {
            // Round 6d: the owner's tracked boxes all left the scan this cycle
            // (spent, a withdrawal say): judge the box as a root once they are
            // removed, instead of quarantining a new reserve for good. Round
            // 6f: or the index shows them spent (`tracked_all_gone`).
            if gone {
                info!(
                    "Deferring reserve box {} of {}: it {}, and the tracked box is spent this cycle",
                    box_id, reserve_info.owner_pubkey, why
                );
                return ReserveAdmission::Deferred;
            }
            ReserveAdmission::Quarantined {
                reason: format!(
                    "duplicate reserve box {} for owner {} in denomination {} {}; the tracked box {} keeps the reserve. \
                     R4 is not authenticated on-chain and a top-up needs no signature, so this is likely a blocking \
                     attempt (issue #19, round 6b/6c)",
                    box_id,
                    reserve_info.owner_pubkey,
                    denomination_id,
                    why,
                    tracked
                        .iter()
                        .map(|r| r.box_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        };
        let Some(nft) = scan_box_nft(scan_box) else {
            return newcomer(
                "holds no reserve NFT at tokens(0)".to_string(),
                self.tracked_all_gone(&tracked).await,
            );
        };
        let mut anchor = None;
        let mut unknown = None;
        for reserve in &tracked {
            match self.tracked_nft(&reserve.box_id).await {
                Ok(Some(tracked_nft)) if tracked_nft == nft => {
                    anchor = Some(reserve.clone());
                    break;
                }
                Ok(_) => {}
                Err(e) => unknown = Some(e),
            }
        }
        let Some(anchor) = anchor.or(removed_anchor.map(|(record, _)| record)) else {
            return match unknown {
                Some(e) => retry("Reading the tracked reserve NFT", e),
                None => newcomer(
                    format!("does not hold the tracked reserve NFT (it holds {})", nft),
                    self.tracked_all_gone(&tracked).await,
                ),
            };
        };
        match self
            .is_lineage_successor(scan_box, &nft, &anchor, contract_address)
            .await
        {
            Ok(Lineage::Successor) => ReserveAdmission::Admitted,
            Ok(Lineage::NotSuccessor | Lineage::Foreign) => newcomer(
                format!(
                "holds the reserve NFT {} but does not continue the tracked box {} through reserve boxes",
                nft, anchor.box_id
            ),
                self.tracked_all_gone(&tracked).await,
            ),
            Ok(Lineage::Root) => {
                info!(
                    "Reserve box {} holds the NFT of tracked box {} after a completed refund: judged as a root",
                    box_id, anchor.box_id
                );
                self.admit_root(scan_box, reserve_info, contract_address, false)
                    .await
            }
            Err(e) => retry("Lineage check", e),
        }
    }

    /// Whether none of `tracked` is unspent this cycle (rounds 6d/6f): each is
    /// missing from the scan, or listed but spent in the index (the page-0
    /// re-read can list a spent box next to the owner's new box). Read on the
    /// tracked lane, once per cycle and box.
    async fn tracked_all_gone(&self, tracked: &[ExtendedReserveInfo]) -> bool {
        for reserve in tracked {
            let listed = self
                .cycle_state()
                .scanned
                .as_ref()
                .map(|scanned| scanned.contains(&reserve.box_id));
            match listed {
                None => return false,
                Some(false) => continue,
                Some(true) => {}
            }
            match self.fetch_indexed_box(&reserve.box_id, Lane::Tracked).await {
                Ok(Some(chain_box)) if !chain_box.spent_tx.is_empty() => {}
                _ => return false,
            }
        }
        true
    }

    /// The root rules (issue #19, rounds 6c/6d): C4-clean, a singleton reserve
    /// NFT, made by the R4 owner. `capped`: a root candidate of an owner with no
    /// tracked reserve, which counts against `MAX_ROOT_CHECKS_PER_CYCLE` and
    /// is deferred past it; a box holding a tracked NFT (after a completed
    /// refund) is not capped, and its retries keep the tracked box.
    async fn admit_root(
        &self,
        scan_box: &ScanBox,
        reserve_info: &ExtendedReserveInfo,
        contract_address: &str,
        capped: bool,
    ) -> ReserveAdmission {
        let box_id = &reserve_info.box_id;
        // Cheap C4 setup checks first (they include the reserve NFT).
        if let Some(violation) = Self::root_setup_violation(scan_box, reserve_info) {
            return ReserveAdmission::Quarantined { reason: violation };
        }
        let Some(nft) = scan_box_nft(scan_box) else {
            return ReserveAdmission::Quarantined {
                reason: format!("Reserve box {} holds no reserve NFT", box_id),
            };
        };
        let retry = |what: &str, e: ScannerError| {
            warn!(
                "{} for reserve root {} failed ({}); retrying next cycle",
                what, box_id, e
            );
            if capped {
                ReserveAdmission::Deferred
            } else {
                ReserveAdmission::Retry
            }
        };
        if capped {
            let cycles = self.nft_cache().cycles;
            let mut cycle = self.cycle_state();
            if cycle.root_checks >= MAX_ROOT_CHECKS_PER_CYCLE {
                return ReserveAdmission::Deferred;
            }
            cycle.root_checks += 1;
            drop(cycle);
            self.nft_cache().root_checked.insert(box_id.clone(), cycles);
        }
        let lane = if capped { Lane::Shared } else { Lane::Tracked };
        match self.is_singleton_nft(&nft, lane).await {
            Ok(true) => {}
            Ok(false) => {
                return ReserveAdmission::Quarantined {
                    reason: format!(
                        "reserve root {} holds NFT {} whose emission is not 1: another box could hold it too (round 6c)",
                        box_id, nft
                    ),
                }
            }
            Err(e) => return retry("Token index check", e),
        }
        match self
            .has_owner_root(scan_box, &nft, &reserve_info.owner_pubkey, contract_address)
            .await
        {
            Ok(true) => self.reopen_verdict(reserve_info, capped),
            Ok(false) => ReserveAdmission::Quarantined {
                reason: format!(
                    "reserve root {} for owner {} was created by a transaction spending no P2PK input of the R4 key, \
                     and its NFT does not lead back through top-ups to a box that was; R4 is not authenticated \
                     on-chain, so this is likely a dust-box blocking attempt (issue #19)",
                    box_id, reserve_info.owner_pubkey
                ),
            },
            Err(e) => retry("Ownership check", e),
        }
    }

    /// Round 7 (N9 interim guard): the last root rule. A root that passes all the
    /// others is still not admitted when the tracker holds redemptions of its owner
    /// in its denomination: it starts with an empty R5, so the contract would pay
    /// those notes again. It is quarantined with a `reserve_reopen_blocked` reason,
    /// unless an operator released it from such a quarantine
    /// (`POST /reserves/quarantined/release`). Until the tracker has published its
    /// history (just after a start) the root waits, like a root without a verdict.
    /// Only roots get here: the tracked box, its successors and a restored box
    /// never do.
    fn reopen_verdict(&self, reserve_info: &ExtendedReserveInfo, capped: bool) -> ReserveAdmission {
        let wait = if capped {
            ReserveAdmission::Deferred
        } else {
            ReserveAdmission::Retry
        };
        // A parsed box has a 33-byte owner key and, being parsed, a denomination; a pair
        // that cannot be keyed has no reserve tree at the tracker either.
        let owner: Option<crate::PubKey> = hex::decode(&reserve_info.owner_pubkey)
            .ok()
            .and_then(|bytes| bytes.as_slice().try_into().ok());
        let (Some(owner), Some(denomination)) = (owner, reserve_info.denomination()) else {
            return ReserveAdmission::Admitted;
        };
        let box_id = &reserve_info.box_id;
        match self.reopen_guard.check(&owner, &denomination) {
            ReopenCheck::Allowed => ReserveAdmission::Admitted,
            ReopenCheck::Unknown => {
                info!(
                    "Reserve root {} waits: the tracker has not published its redemption history yet",
                    box_id
                );
                wait
            }
            ReopenCheck::Blocked => match self.reserve_storage.quarantine_releases() {
                Ok(releases)
                    if releases.iter().any(|release| {
                        release.record.box_id == *box_id
                            && release.record.reason.starts_with(RESERVE_REOPEN_BLOCKED)
                    }) =>
                {
                    warn!(
                        "Admitting reserve root {} of {} in {}: the tracker holds redemptions there, \
                         but an operator released this box from the reopen guard",
                        box_id,
                        reserve_info.owner_pubkey,
                        denomination.denomination_id()
                    );
                    ReserveAdmission::Admitted
                }
                Ok(_) => ReserveAdmission::Quarantined {
                    reason: format!(
                        "{}: reserve root {} of owner {} in denomination {} starts with an empty \
                         redemption tree (R5), while this tracker holds redemptions of that owner \
                         there, so notes redeemed before could be redeemed again from it (N9). \
                         Round 7 interim guard; an operator who checked it can release it with \
                         POST /reserves/quarantined/release",
                        RESERVE_REOPEN_BLOCKED,
                        box_id,
                        reserve_info.owner_pubkey,
                        denomination.denomination_id()
                    ),
                },
                Err(e) => {
                    warn!(
                        "Reading the quarantine releases for reserve root {} failed ({:?}); retrying next cycle",
                        box_id, e
                    );
                    wait
                }
            },
        }
    }

    /// Parse, admit, and (when admitted) track and persist one scanned reserve
    /// box. Both ingestion paths (`process_scan_boxes` and the server's scanner
    /// sync) go through here so admission control cannot be bypassed
    /// (issue #19).
    pub async fn ingest_scan_box(&self, tagged: &TaggedScanBox) -> ScanBoxIngest {
        let scan_box = &tagged.scan_box;
        let normalized_id = normalized_box_id(&scan_box.box_id);

        let reserve_info =
            match self.parse_reserve_box(scan_box, tagged.kind, &tagged.contract_address) {
                Ok(info) => info,
                Err(e) => {
                    warn!(
                        "Skipping unparseable reserve box {}: {} - registers: {:?}",
                        scan_box.box_id, e, scan_box.additional_registers
                    );
                    return ScanBoxIngest::Rejected(normalized_id);
                }
            };

        match self
            .admit_reserve_box(scan_box, &reserve_info, &tagged.contract_address)
            .await
        {
            ReserveAdmission::Admitted => {
                self.remember_nft(&reserve_info.box_id, scan_box_nft(scan_box));
                if let Err(e) = self.reserve_tracker.update_reserve(reserve_info.clone()) {
                    warn!("Failed to update reserve {}: {}", scan_box.box_id, e);
                    return ScanBoxIngest::Rejected(normalized_id);
                }
                if let Err(e) = self.reserve_storage.store_reserve(&reserve_info) {
                    warn!(
                        "Failed to persist reserve {} to database: {:?}",
                        scan_box.box_id, e
                    );
                } else {
                    info!("Updated and persisted reserve: {}", scan_box.box_id);
                    // Round 6f-2 (LOW-4): a restored box's removed record goes
                    // only now that the box is stored again.
                    if self
                        .nft_cache()
                        .removed
                        .remove(&reserve_info.box_id)
                        .is_some()
                    {
                        if let Err(e) = self.reserve_storage.forget_removed(&reserve_info.box_id) {
                            warn!(
                                "Failed to forget removed reserve {}: {:?}",
                                reserve_info.box_id, e
                            );
                        }
                    }
                }
                ScanBoxIngest::Tracked(reserve_info.box_id)
            }
            ReserveAdmission::Quarantined { reason } => {
                warn!("Quarantining reserve box {}: {}", scan_box.box_id, reason);
                let record = QuarantinedReserve {
                    box_id: reserve_info.box_id.clone(),
                    owner_pubkey: reserve_info.owner_pubkey.clone(),
                    denomination: reserve_info
                        .denomination()
                        .map(|d| d.denomination_id())
                        .unwrap_or_else(|| "unknown".to_string()),
                    reason,
                    quarantined_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };
                if let Err(e) = self.reserve_storage.store_quarantined(&record) {
                    warn!(
                        "Failed to persist quarantine record for {}: {:?}",
                        scan_box.box_id, e
                    );
                }
                ScanBoxIngest::Rejected(reserve_info.box_id)
            }
            ReserveAdmission::Retry => {
                let denomination = reserve_info.denomination().unwrap_or(crate::DenomKey::Erg);
                ScanBoxIngest::Pending(reserve_info.owner_pubkey.clone(), denomination)
            }
            ReserveAdmission::Deferred => ScanBoxIngest::Deferred(reserve_info.box_id),
        }
    }

    /// Scan cycles skipped so far because the blockchain index lagged
    /// (round 6f).
    pub fn skipped_cycles(&self) -> u64 {
        self.nft_cache().lag_skips
    }

    /// `GET /blockchain/indexedHeight` (round 6e): the index height when it is
    /// within `MAX_INDEX_LAG` blocks of `fullHeight`; an error, and the cycle
    /// is skipped, when the index lags further.
    ///
    /// Round 8: an error too, so the cycle is skipped and nothing acts on a
    /// guessed height (removal depths, the unknown-to-the-index clocks, the
    /// expiry of removed records, admission against a stale index), when the
    /// node gives no usable answer: the request fails or times out, the status
    /// is not a success, the body is not JSON or lacks either height, the
    /// index is above `fullHeight`, or the index is below the highest height a
    /// cycle ran with since the start (it went back: a rollback or another
    /// node; the cycles wait until it is there again).
    async fn index_height(&self) -> Result<u64, ScannerError> {
        let url = format!("{}/blockchain/indexedHeight", self.config.node_url);
        let unusable = |why: String| {
            ScannerError::NodeError(format!(
                "no usable index height: GET /blockchain/indexedHeight {}",
                why
            ))
        };
        let response = self
            .request_builder(reqwest::Method::GET, &url)
            .timeout(INDEX_HEIGHT_TIMEOUT)
            .send()
            .await
            .map_err(|e| {
                unusable(if e.is_timeout() {
                    format!("timed out after {} ms", INDEX_HEIGHT_TIMEOUT.as_millis())
                } else {
                    format!("failed ({})", e)
                })
            })?;
        if !response.status().is_success() {
            return Err(unusable(format!("answered HTTP {}", response.status())));
        }
        let answer = crate::http::read_json_capped(response)
            .await
            .map_err(|e| unusable(format!("gave an unreadable answer ({})", e)))?;
        let field = |name: &str| answer.get(name).and_then(|v| v.as_u64());
        let (Some(indexed), Some(full)) = (field("indexedHeight"), field("fullHeight")) else {
            return Err(unusable(
                "gave no indexedHeight and fullHeight (both whole numbers)".to_string(),
            ));
        };
        if indexed > full {
            return Err(unusable(format!(
                "gave indexedHeight {} above fullHeight {}",
                indexed, full
            )));
        }
        // Round 8 (review LOW-1): nor above the node's own `/info` height,
        // which the scanner loop read just before this cycle (0: not read, as
        // when a test runs a cycle by hand), by more than INFO_HEIGHT_MARGIN.
        // One implausible answer must neither run a cycle nor raise the mark
        // that the went-back check below compares with.
        let info_height = self.inner.lock().await.current_height;
        if info_height != 0 && indexed > info_height.saturating_add(INFO_HEIGHT_MARGIN) {
            return Err(unusable(format!(
                "gave indexedHeight {} above height {} that /info gave just before (by more than {} blocks)",
                indexed, info_height, INFO_HEIGHT_MARGIN
            )));
        }
        if full > indexed.saturating_add(MAX_INDEX_LAG) {
            return Err(ScannerError::NodeError(format!(
                "the blockchain index is at height {} while the node is at {} (more than {} blocks behind)",
                indexed, full, MAX_INDEX_LAG
            )));
        }
        let mut cache = self.nft_cache();
        if let Some(seen) = cache.index_height_seen.filter(|seen| indexed < *seen) {
            return Err(ScannerError::NodeError(format!(
                "the blockchain index is at height {} below {}, where an earlier cycle saw it; \
                 waiting until it is there again (a restart forgets {})",
                indexed, seen, seen
            )));
        }
        cache.index_height_seen = Some(indexed);
        Ok(indexed)
    }

    /// The height spends are measured against in this cycle's removals: the
    /// index height of the cycle. Round 8: never the node's `fullHeight`; with
    /// no index height (outside a scan cycle) no spend is deep.
    fn removal_height(&self) -> Option<u64> {
        self.cycle_state().height
    }

    /// Whether the index shows tracked reserve `reserve` spent at least
    /// `SPENT_REMOVAL_DEPTH` blocks deep (rounds 6d/6e). The spend height is
    /// the spending transaction's `inclusionHeight` (box/byId has none).
    async fn spent_deep(&self, reserve: &ExtendedReserveInfo) -> bool {
        let spent_at = match self.fetch_indexed_box(&reserve.box_id, Lane::Tracked).await {
            Ok(Some(chain_box)) if !chain_box.spent_tx.is_empty() => {
                self.nft_cache().unknown_since.remove(&reserve.box_id);
                self.fetch_tx_inclusion_height(&chain_box.spent_tx).await
            }
            Ok(Some(_)) => {
                self.nft_cache().unknown_since.remove(&reserve.box_id);
                info!(
                    "Keeping reserve {}: missing from the scan but unspent in the index",
                    reserve.box_id
                );
                return false;
            }
            Ok(None) => {
                // Round 6f (P2-1): a box the index does not know was dropped by
                // a reorg (or never existed on the winning fork): gone once the
                // index is SPENT_REMOVAL_DEPTH blocks past the height where it
                // was first unknown. A reorg bringing it back restores it.
                // Round 6f-2 (P2-A): only by the index height of this cycle,
                // never the node's fullHeight: a lagging or rebuilding index
                // does not know boxes that exist.
                let Some(height) = self.cycle_state().height else {
                    info!(
                        "Keeping reserve {}: unknown to the index, whose height is unknown",
                        reserve.box_id
                    );
                    return false;
                };
                let since = *self
                    .nft_cache()
                    .unknown_since
                    .entry(reserve.box_id.clone())
                    .or_insert(height);
                if height >= since.saturating_add(SPENT_REMOVAL_DEPTH) {
                    warn!(
                        "Reserve {} has been unknown to the index since height {} (now {}): removing it",
                        reserve.box_id, since, height
                    );
                    return true;
                }
                info!(
                    "Keeping reserve {}: missing from the scan and unknown to the index since height {}",
                    reserve.box_id, since
                );
                return false;
            }
            Err(e) => {
                warn!(
                    "Cannot tell whether reserve {} is spent ({}); keeping it",
                    reserve.box_id, e
                );
                return false;
            }
        };
        let height = self.removal_height();
        let deep = match (spent_at, height) {
            (Some(spent_at), Some(height)) => {
                height.saturating_sub(spent_at) + 1 >= SPENT_REMOVAL_DEPTH
            }
            _ => false,
        };
        if !deep {
            info!(
                "Keeping reserve {}: its spend (height {:?}, now {:?}) is not {} blocks deep yet",
                reserve.box_id, spent_at, height, SPENT_REMOVAL_DEPTH
            );
        }
        deep
    }

    /// Start a scan cycle (round 6d, P1): reset the per-cycle node answers and
    /// budget, learn the NFT of every tracked reserve (from the scan, else one
    /// `/blockchain/box/byId` on the tracked lane), and order the boxes: the
    /// tracked ones, boxes removed lately, and boxes holding a tracked NFT
    /// first, so no other box can use up the budget before them; then the rest,
    /// never-checked root candidates before the least recently checked.
    async fn begin_cycle(
        &self,
        scan_boxes: Vec<TaggedScanBox>,
        index_height: Option<u64>,
    ) -> Vec<TaggedScanBox> {
        let scanned: std::collections::HashSet<String> = scan_boxes
            .iter()
            .map(|tagged| normalized_box_id(&tagged.scan_box.box_id))
            .collect();
        {
            let mut cycle = self.cycle_state();
            *cycle = CycleState::default();
            cycle.scanned = Some(scanned.clone());
            cycle.started = Some(std::time::Instant::now());
            cycle.height = index_height;
        }
        {
            let mut cache = self.nft_cache();
            cache.cycles += 1;
            // Round 6f-2: expiry by index height, only in a cycle that knows
            // it; a record removed without one starts counting now.
            let mut expired: Vec<String> = Vec::new();
            let mut counted: Vec<RemovedReserve> = Vec::new();
            if let Some(height) = index_height {
                for (box_id, removed) in cache.removed.iter_mut() {
                    let since = match removed.removed_height {
                        Some(since) => since,
                        None => {
                            removed.removed_height = Some(height);
                            counted.push(removed.clone());
                            height
                        }
                    };
                    if height >= since.saturating_add(REMEMBER_REMOVED_BLOCKS) {
                        expired.push(box_id.clone());
                    }
                }
            }
            for removed in counted {
                if let Err(e) = self.reserve_storage.store_removed(&removed) {
                    warn!(
                        "Failed to remember removed reserve {}: {:?}",
                        removed.record.box_id, e
                    );
                }
            }
            for box_id in expired {
                cache.removed.remove(&box_id);
                if let Err(e) = self.reserve_storage.forget_removed(&box_id) {
                    warn!("Failed to forget removed reserve {}: {:?}", box_id, e);
                }
            }
            cache
                .root_checked
                .retain(|box_id, _| scanned.contains(box_id));
        }

        let tracked = self.reserve_tracker.get_all_reserves();
        {
            // Round 6f-2 (LOW-1): only tracked boxes missing from this scan; a
            // box listed again starts counting anew when it is next missing.
            let tracked_ids: std::collections::HashSet<&String> =
                tracked.iter().map(|r| &r.box_id).collect();
            self.nft_cache()
                .unknown_since
                .retain(|box_id, _| tracked_ids.contains(box_id) && !scanned.contains(box_id));
        }
        for reserve in &tracked {
            if self.nft_cache().box_nft.contains_key(&reserve.box_id) {
                continue;
            }
            match scan_boxes
                .iter()
                .find(|tagged| normalized_box_id(&tagged.scan_box.box_id) == reserve.box_id)
            {
                Some(tagged) => self.remember_nft(&reserve.box_id, scan_box_nft(&tagged.scan_box)),
                None => {
                    if let Err(e) = self.tracked_nft(&reserve.box_id).await {
                        warn!(
                            "Cannot read the NFT of tracked reserve {}: {}",
                            reserve.box_id, e
                        );
                    }
                }
            }
        }
        let (first_ids, first_nfts, root_checked) = {
            let cache = self.nft_cache();
            let mut ids: std::collections::HashSet<String> =
                tracked.iter().map(|r| r.box_id.clone()).collect();
            ids.extend(cache.removed.keys().cloned());
            let nfts: std::collections::HashSet<String> = tracked
                .iter()
                .filter_map(|r| cache.box_nft.get(&r.box_id).cloned().flatten())
                .chain(
                    cache
                        .removed
                        .values()
                        .filter_map(|removed| removed.nft.clone()),
                )
                .collect();
            (ids, nfts, cache.root_checked.clone())
        };
        // Round 6e (LOW-5): the singleton answers kept are those of the NFTs
        // in this scan and of the tracked and removed boxes.
        {
            let scan_nfts: std::collections::HashSet<String> = scan_boxes
                .iter()
                .filter_map(|tagged| scan_box_nft(&tagged.scan_box))
                .collect();
            self.nft_cache()
                .singleton
                .retain(|nft, _| scan_nfts.contains(nft) || first_nfts.contains(nft));
        }
        let (mut first, mut rest): (Vec<_>, Vec<_>) = scan_boxes.into_iter().partition(|tagged| {
            first_ids.contains(&normalized_box_id(&tagged.scan_box.box_id))
                || scan_box_nft(&tagged.scan_box).is_some_and(|nft| first_nfts.contains(&nft))
        });
        rest.sort_by_key(|tagged| {
            root_checked
                .get(&normalized_box_id(&tagged.scan_box.box_id))
                .map_or(0, |cycle| cycle + 1)
        });
        first.append(&mut rest);
        first
    }

    /// Process scan boxes and update reserve tracker
    pub async fn process_scan_boxes(&self) -> Result<(), ScannerError> {
        info!("Starting to process scan boxes...");
        // Round 6e (P2-1): a lagging blockchain index shows boxes spent since
        // as unspent; skip the cycle rather than judge by it. Round 8: so is a
        // cycle without a usable index height (no answer, a malformed one, or
        // an index that went back): a no-op, retried at the next block.
        let index_height = match self.index_height().await {
            Ok(height) => {
                self.nft_cache().lag_skips_in_a_row = 0;
                height
            }
            Err(e) => {
                // Round 6f: a warning on the first skip and every
                // LAG_WARN_EVERY skips in a row, the rest at info.
                let in_a_row = {
                    let mut cache = self.nft_cache();
                    cache.lag_skips += 1;
                    cache.lag_skips_in_a_row += 1;
                    cache.lag_skips_in_a_row
                };
                if in_a_row % LAG_WARN_EVERY == 1 {
                    warn!(
                        "Skipping this scan cycle ({} in a row, {} in all): {}",
                        in_a_row,
                        self.skipped_cycles(),
                        e
                    );
                } else {
                    info!("Skipping this scan cycle ({} in a row): {}", in_a_row, e);
                }
                return Ok(());
            }
        };
        let scan_boxes = self.get_scan_boxes().await?;
        info!("Retrieved {} scan boxes to process", scan_boxes.len());
        let scan_boxes = self.begin_cycle(scan_boxes, Some(index_height)).await;

        let mut current_box_ids = Vec::new();
        // Box IDs that failed admission, normalized the same way
        // `ExtendedReserveInfo.box_id` is stored. A rejected box is skipped but
        // never triggers removal of itself, and it must not block removal of
        // OTHER genuinely-spent reserves.
        let mut quarantined_box_ids: Vec<String> = Vec::new();
        // (Owner, denomination) pairs with a successor candidate whose lineage
        // check was inconclusive this cycle (issue #19): the tracked box must
        // not be removed as spent, or a transient node error would orphan the
        // lineage and brick the issuer.
        let mut pending_lineages: Vec<(String, crate::DenomKey)> = Vec::new();

        for tagged in &scan_boxes {
            let scan_box = &tagged.scan_box;
            debug!(
                "Processing scan box: ID={}, value={}, registers={:?}",
                scan_box.box_id, scan_box.value, scan_box.additional_registers
            );

            match self.ingest_scan_box(tagged).await {
                ScanBoxIngest::Tracked(box_id) => {
                    debug!("Successfully tracked reserve box: box_id={}", box_id);
                    current_box_ids.push(box_id);
                }
                ScanBoxIngest::Rejected(box_id) => {
                    quarantined_box_ids.push(box_id);
                }
                ScanBoxIngest::Pending(owner, denomination) => {
                    pending_lineages.push((owner, denomination));
                }
                ScanBoxIngest::Deferred(box_id) => {
                    debug!("Reserve box {} deferred to the next cycle", box_id);
                }
            }
        }

        // Remove reserves that are no longer in the scan
        // NOTE: Disabled for testing to prevent manually-inserted reserves from being deleted
        // when they don't exist on the local test node.
        let all_reserves = self.reserve_tracker.get_all_reserves();
        info!(
            "Current tracker has {} reserves, {} are still active in scan",
            all_reserves.len(),
            current_box_ids.len()
        );

        // Round 6e (P1): a reserve absent from the scan is removed only when a
        // box holding its NFT is tracked this cycle (its successor), or when
        // the index shows it spent at least SPENT_REMOVAL_DEPTH blocks deep.
        // The scan is read page by page, so an unspent box can be missing from
        // it (moved to a page already read), with or without an attacker; and a
        // scan with no valid box at all (manually inserted reserves on a local
        // test node, round 6c) removes nothing the chain does not show spent.
        let mut tracked_now = TrackedThisCycle::new();
        // Round 6f-2 (P2-A): the rules for boxes unknown to the index need the
        // index height of this cycle.
        let index_known = self.cycle_state().height.is_some();
        {
            let cache = self.nft_cache();
            for reserve in &all_reserves {
                if current_box_ids.contains(&reserve.box_id) {
                    let nft = cache.box_nft.get(&reserve.box_id).cloned().flatten();
                    tracked_now
                        .entry((
                            reserve.owner_pubkey.clone(),
                            reserve.denomination().map(|d| d.denomination_id()),
                        ))
                        .or_default()
                        .push((reserve.box_id.clone(), nft));
                }
            }
        }
        for reserve in all_reserves {
            if quarantined_box_ids.contains(&reserve.box_id) {
                continue;
            }
            // A box of the same owner and denomination holding its NFT is
            // tracked this cycle: its successor (round 6e; same owner, round 6f).
            let denomination = reserve.denomination();
            let owner_key = (
                reserve.owner_pubkey.clone(),
                denomination.as_ref().map(|d| d.denomination_id()),
            );
            let mut followed = self
                .nft_cache()
                .box_nft
                .get(&reserve.box_id)
                .cloned()
                .flatten()
                .is_some_and(|nft| {
                    tracked_now.get(&owner_key).is_some_and(|boxes| {
                        boxes.iter().any(|(id, held)| {
                            *id != reserve.box_id && held.as_deref() == Some(nft.as_str())
                        })
                    })
                });
            // Round 6f: a box the index does not know (a reorg dropped it)
            // next to another tracked box of its owner and denomination is
            // gone at once, its NFT known or not (after a restart).
            if !followed
                && index_known
                && !current_box_ids.contains(&reserve.box_id)
                && tracked_now
                    .get(&owner_key)
                    .is_some_and(|boxes| boxes.iter().any(|(id, _)| *id != reserve.box_id))
                && matches!(
                    self.fetch_indexed_box(&reserve.box_id, Lane::Tracked).await,
                    Ok(None)
                )
            {
                info!(
                    "Reserve {} is unknown to the index while its owner's reserve is tracked",
                    reserve.box_id
                );
                followed = true;
            }
            if current_box_ids.contains(&reserve.box_id) {
                // Round 6f (P2-3): the page-0 re-read can list a spent box next
                // to its successor or the owner's new box. A listed box is gone
                // when the index shows it spent; asked only when another
                // tracked box holds its NFT or this cycle already read it spent.
                let read_spent = matches!(
                    self.cycle_state().boxes.get(&reserve.box_id),
                    Some(Ok(Some(chain_box))) if !chain_box.spent_tx.is_empty()
                );
                if !(followed || read_spent) {
                    continue;
                }
                match self.fetch_indexed_box(&reserve.box_id, Lane::Tracked).await {
                    Ok(Some(chain_box)) if !chain_box.spent_tx.is_empty() => info!(
                        "Reserve {} is listed by the scan but spent in the index",
                        reserve.box_id
                    ),
                    _ => continue,
                }
            }
            // A successor candidate is pending a lineage retry for this
            // (owner, denomination): keep the tracked box so the lineage anchor
            // is not lost (issue #19), but only while it is the owner's only
            // reserve there. Once a successor holding its NFT is tracked, a
            // pending check never keeps a spent box next to it (round 6c, P1-2).
            let pending = pending_lineages.iter().any(|(owner, pending_denom)| {
                *owner == reserve.owner_pubkey && Some(pending_denom) == denomination.as_ref()
            }) && self
                .reserve_tracker
                .get_reserves_by_owner(&reserve.owner_pubkey)
                .into_iter()
                .filter(|r| r.denomination() == denomination)
                .count()
                <= 1;
            if pending {
                // Round 6e (LOW-2): unless the owner could complete its refund
                // (R7 + 43,200 blocks have passed) and its spend is deep: then
                // the reserve is gone, whatever the pending box turns out to be.
                let refund_due = reserve.base_info.refund_initiation_height != 0
                    && self.removal_height().is_some_and(|height| {
                            height
                                >= reserve.base_info.refund_initiation_height + REFUND_DELAY_BLOCKS
                        });
                // Round 6f (P2-1): nor a box the index does not know (its NFT
                // may be unknown, so every newcomer is pending), once it has
                // been unknown for SPENT_REMOVAL_DEPTH blocks.
                let unknown = matches!(
                    self.cycle_state().boxes.get(&reserve.box_id),
                    Some(Ok(None))
                );
                // Round 6f-2 (P2-A): `spent_deep` counts an unknown box only
                // in a cycle that knows the index height.
                if !((refund_due || unknown)
                    && self.spent_deep(&reserve).await)
                {
                    info!(
                        "Keeping reserve {} (successor lineage check pending)",
                        reserve.box_id
                    );
                    continue;
                }
                info!(
                    "Reserve {} is spent deep and its refund was due: a pending check no longer keeps it",
                    reserve.box_id
                );
            } else if !followed && !self.spent_deep(&reserve).await {
                continue;
            }
            info!(
                "Removing spent reserve: {} (not found in current scan)",
                reserve.box_id
            );
            // Remove from in-memory tracker
            if let Err(e) = self.reserve_tracker.remove_reserve(&reserve.box_id) {
                warn!("Failed to remove reserve {}: {}", reserve.box_id, e);
            } else {
                // Remembered for a day (round 6d, P2-3): a reorg may bring it back.
                let removed_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let removed_height = self.cycle_state().height;
                let mut cache = self.nft_cache();
                let removed = RemovedReserve {
                    record: reserve.clone(),
                    nft: cache.box_nft.remove(&reserve.box_id).flatten(),
                    removed_at,
                    removed_height,
                };
                cache.stored_box_nfts.remove(&reserve.box_id);
                cache
                    .removed
                    .insert(reserve.box_id.clone(), removed.clone());
                drop(cache);
                // Round 8: the removed record keeps the NFT from now on. Review
                // LOW-3: the box NFT entry goes only once the removed record is
                // written, so a crash in between never leaves the box with
                // neither.
                match self.reserve_storage.store_removed(&removed) {
                    Ok(()) => {
                        if let Err(e) = self.reserve_storage.forget_box_nft(&reserve.box_id) {
                            warn!(
                                "Failed to forget the NFT of removed reserve {}: {:?}",
                                reserve.box_id, e
                            );
                        }
                    }
                    Err(e) => warn!(
                        "Failed to remember removed reserve {}: {:?}",
                        reserve.box_id, e
                    ),
                }
                // Remove from database
                if let Err(e) = self.reserve_storage.remove_reserve(&reserve.box_id) {
                    warn!(
                        "Failed to remove reserve {} from database: {:?}",
                        reserve.box_id, e
                    );
                } else {
                    info!("Removed spent reserve: {}", reserve.box_id);
                }
            }
        }

        debug!(
            "Finished processing scan boxes: {} processed, {} in tracker after processing",
            scan_boxes.len(),
            self.reserve_tracker.get_all_reserves().len()
        );

        Ok(())
    }
}

/// Round 8 (operator: refuse to start): the ERROR line of a start whose
/// tracked reserves did not load, naming the records by key only.
fn refuse_start_message(
    path: &Path,
    unreadable: &crate::persistence::TrackedReservesUnreadable,
) -> String {
    const SHOWN: usize = 100;
    match unreadable {
        crate::persistence::TrackedReservesUnreadable::Undecodable(keys) => {
            let mut named = keys.iter().take(SHOWN).cloned().collect::<Vec<_>>().join(", ");
            if keys.len() > SHOWN {
                named.push_str(&format!(" and {} more", keys.len() - SHOWN));
            }
            format!(
                "Refusing to start: {} tracked reserve record(s) in {} (partition \"reserves\") do not decode, keys: {}. Started without them, the scanner would judge their live reserve boxes as new roots. To recover, restore the data directory from the latest backup in {}, or remove the record(s) with these keys by hand, then start the tracker again.",
                keys.len(),
                path.display(),
                named,
                RESERVE_BACKUP_DIR
            )
        }
        crate::persistence::TrackedReservesUnreadable::Read(e) => format!(
            "Refusing to start: the tracked reserve records in {} (partition \"reserves\") cannot be read ({}). To recover, restore the data directory from the latest backup in {}, then start the tracker again.",
            path.display(),
            e,
            RESERVE_BACKUP_DIR
        ),
    }
}

/// Where the operator's backups of the data directory are (`tracker-ops/run/backup.sh`).
const RESERVE_BACKUP_DIR: &str = "/var/backups/basis-tracker";

/// Round 8: load the NFT facts kept in the reserve store into `cache` at start.
/// Only those of tracked reserves are kept: the NFT of a box the tracker does
/// not track, and the emission of an NFT no tracked or removed box holds, are
/// removed from the store. The tracked reserves always loaded completely (else
/// the tracker does not start); review LOW-2: without the removed reserves
/// (`removed_loaded` false) no emission is removed. A damaged entry was removed
/// by the store (the node is asked again); a store that cannot be read leaves
/// the cache empty, as before round 8.
fn load_nft_facts(
    storage: &ReserveStorage,
    tracked: &std::collections::HashSet<String>,
    removed_loaded: bool,
    cache: &mut NftCache,
) {
    let facts = match storage.nft_facts() {
        Ok(facts) => facts,
        Err(e) => {
            warn!(
                "Failed to load the stored NFT facts ({:?}); they are read from the node again",
                e
            );
            return;
        }
    };
    let mut pruned = 0usize;
    for (box_id, nft) in facts.box_nft {
        if tracked.contains(&box_id) {
            cache.stored_box_nfts.insert(box_id.clone());
            cache.box_nft.insert(box_id, Some(nft));
        } else {
            pruned += 1;
            if let Err(e) = storage.forget_box_nft(&box_id) {
                warn!("Failed to forget the NFT of reserve box {}: {:?}", box_id, e);
            }
        }
    }
    let prune_emissions = removed_loaded;
    if !prune_emissions {
        warn!("Stored NFT emissions are kept as they are: the removed reserves did not load");
    }
    let held: std::collections::HashSet<String> = cache
        .box_nft
        .values()
        .flatten()
        .cloned()
        .chain(cache.removed.values().filter_map(|removed| removed.nft.clone()))
        .collect();
    for (nft, emission) in facts.emission {
        if !prune_emissions || held.contains(&nft) {
            cache.singleton.insert(nft.clone(), emission == 1);
            if emission == 1 {
                cache.stored_singletons.insert(nft);
            }
        } else {
            pruned += 1;
            if let Err(e) = storage.forget_nft_emission(&nft) {
                warn!("Failed to forget the emission of NFT {}: {:?}", nft, e);
            }
        }
    }
    if facts.dropped > 0 {
        warn!(
            "{} stored NFT fact(s) did not read back and were removed; the node is asked for them again",
            facts.dropped
        );
    }
    info!(
        "Loaded the NFTs of {} tracked reserve box(es) and {} singleton verdict(s) from the store ({} no longer needed)",
        cache.box_nft.len(),
        cache.singleton.len(),
        pruned
    );
}

/// Start the reserve scanner loop in the background.
///
/// The loop stops at its next wait once `shutdown` receives a message or its sender is
/// dropped; await the returned handle to know when it has.
pub async fn start_scanner(
    state: ServerState,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Result<tokio::task::JoinHandle<Result<(), ScannerError>>, ScannerError> {
    let state = Arc::new(state);
    Ok(tokio::spawn(reserve_scanner_loop(state, shutdown)))
}

/// Create a scanner with default configuration
pub fn create_default_scanner(data_dir: impl AsRef<Path>) -> Result<ServerState, ScannerError> {
    let config = NodeConfig::default();
    ServerState::new(config, data_dir)
}

/// Ergo box representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErgoBox {
    pub box_id: String,
    pub value: u64,
    pub ergo_tree: String,
    pub creation_height: u64,
    pub transaction_id: String,
    pub additional_registers: std::collections::HashMap<String, String>,
}

impl ErgoBox {
    /// Get a specific register value
    pub fn get_register(&self, register: &str) -> Option<&str> {
        self.additional_registers.get(register).map(|s| s.as_str())
    }

    /// Check if this box has a specific register
    pub fn has_register(&self, register: &str) -> bool {
        self.additional_registers.contains_key(register)
    }
}

/// Scan box representation from Ergo node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanBox {
    pub box_id: String,
    pub value: u64,
    pub ergo_tree: String,
    pub creation_height: u64,
    pub transaction_id: String,
    pub additional_registers: std::collections::HashMap<String, String>,
    /// Assets in the box (tokens)
    #[serde(default)]
    pub assets: Vec<BoxAsset>,
}

/// Asset in an Ergo box
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxAsset {
    /// Token ID
    pub token_id: String,
    /// Amount
    pub amount: u64,
}

/// Events related to reserve activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReserveEvent {
    /// A new reserve was created
    ReserveCreated {
        box_id: String,
        owner_pubkey: String,
        collateral_amount: u64,
        height: u64,
    },
    /// An existing reserve was topped up
    ReserveToppedUp {
        box_id: String,
        additional_collateral: u64,
        height: u64,
    },
    /// A redemption occurred from a reserve
    ReserveRedeemed {
        box_id: String,
        redeemed_amount: u64,
        height: u64,
    },
    /// A reserve was spent/closed
    ReserveSpent { box_id: String, height: u64 },
}

/// Default node configuration
impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            start_height: None,
            reserve_contract_p2s: None,
            token_reserve_contract_p2s: None,
            tracker_nft_id: None,
            node_url: "http://localhost:9053".to_string(), // Local Ergo node
            scan_name: Some("Basis Reserve Scanner".to_string()),
            api_key: None,
        }
    }
}

/// Sleep for `duration`. Returns true, early, when the shutdown signal arrives first or its
/// sender is gone.
async fn sleep_unless_shutdown(
    shutdown: &mut tokio::sync::broadcast::Receiver<()>,
    duration: Duration,
) -> bool {
    tokio::select! {
        biased;
        _ = shutdown.recv() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

/// Reserve scanner loop (background task).
///
/// Runs until `shutdown` fires: a cycle in progress is finished, and the loop returns at the
/// wait that follows it.
pub async fn reserve_scanner_loop(
    state: Arc<ServerState>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Result<(), ScannerError> {
    info!("Starting reserve scanner background loop");

    let mut consecutive_failures = 0;
    const MAX_CONSECUTIVE_FAILURES: u32 = 5;

    loop {
        // Update current height
        match state.fetch_current_height().await {
            Ok(height) => {
                // Log height update at INFO level
                let previous_height = {
                    let inner = state.inner.lock().await;
                    inner.current_height
                };

                if height != previous_height {
                    info!("Current Ergo blockchain height: {}", height);
                    // Update current height in state
                    {
                        let mut inner = state.inner.lock().await;
                        inner.current_height = height;
                    }
                }

                // Process scan boxes whenever the height has advanced
                if height > state.last_scanned_height().await {
                    match state.process_scan_boxes().await {
                        Ok(()) => {
                            consecutive_failures = 0;
                            // Update last scanned height on success
                            {
                                let mut inner = state.inner.lock().await;
                                inner.last_scanned_height = height;
                            }
                        }
                        Err(e) => {
                            error!("Failed to process scan boxes: {}", e);
                            consecutive_failures += 1;

                            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                                error!(
                                    "Too many consecutive failures ({}), waiting before retry",
                                    consecutive_failures
                                );
                                // Wait longer after many failures
                                if sleep_unless_shutdown(&mut shutdown, Duration::from_secs(60))
                                    .await
                                {
                                    info!("Reserve scanner stopped");
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to get current height: {}", e);
                consecutive_failures += 1;
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    error!(
                        "Too many consecutive failures ({}), waiting before retry",
                        consecutive_failures
                    );
                    if sleep_unless_shutdown(&mut shutdown, Duration::from_secs(60)).await {
                        info!("Reserve scanner stopped");
                        return Ok(());
                    }
                }
            }
        }

        // Wait before next scan (shorter wait if we're recovering)
        let wait_time = if consecutive_failures > 0 {
            Duration::from_secs(10) // Shorter wait during recovery
        } else {
            Duration::from_secs(30) // Normal wait
        };
        if sleep_unless_shutdown(&mut shutdown, wait_time).await {
            info!("Reserve scanner stopped");
            return Ok(());
        }
    }
}

/// Serialized value of the R5 register of a freshly created reserve: the empty
/// AVL+ tree (32-byte keys, insert+update flags `0x03`, no fixed value length).
/// Format: `0x64` (AvlTree type) || 33-byte digest || `03` || `20` || `00`.
pub fn empty_reserve_tree_register() -> String {
    let tree = basis_trees::BasisAvlTree::new().expect("failed to create empty AVL tree");
    format!("64{}032000", hex::encode(tree.root_digest()))
}

/// Decode an Ergo `Long` constant from its serialized hex representation.
/// Format: type byte `05` followed by zigzag-VLQ encoded value.
/// Missing, malformed, or negative values are treated as `0`.
pub fn decode_ergo_long_register(value: Option<&String>) -> u64 {
    let hex = match value {
        Some(h) if h.starts_with("05") && h.len() > 2 => &h[2..],
        _ => return 0,
    };
    let bytes = match hex::decode(hex) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    decode_vlq_long(&bytes)
        .ok()
        .and_then(|v| if v >= 0 { Some(v as u64) } else { None })
        .unwrap_or(0)
}

/// Decode a zigzag-VLQ encoded signed long.
fn decode_vlq_long(bytes: &[u8]) -> Result<i64, String> {
    let mut zigzag: u64 = 0;
    let mut shift = 0;
    for &byte in bytes {
        let value = (byte & 0x7f) as u64;
        zigzag |= value << shift;
        if byte & 0x80 == 0 {
            let n = zigzag as i64;
            return Ok((n >> 1) ^ -(n & 1));
        }
        shift += 7;
        if shift > 63 {
            return Err("VLQ overflow".to_string());
        }
    }
    Err("Incomplete VLQ".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Valid compressed secp256k1 point (generator) with the 0x07 GroupElement prefix.
    const VALID_PREFIXED_PUBKEY: &str =
        "070279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// The reserve NFT (`tokens(0)`, amount 1) of the test reserve boxes.
    const TEST_RESERVE_NFT: &str =
        "4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e";

    #[test]
    fn test_empty_reserve_tree_register_constant() {
        // The empty AVL+ tree register value is a protocol constant: reserves are
        // only accepted when first seen with exactly this tree in R5.
        assert_eq!(
            empty_reserve_tree_register(),
            "644ec61f485b98eb87153f7c57db4f5ecd75556fddbc403b41acf8441fde8e160900032000"
        );
    }

    /// Phase 2 acceptance (specs/ergo/multi_collateral_reserves.md §13): mixed ERG and
    /// token reserves parse per box, each with its own denomination and the contract
    /// address of the slot it was found at.
    #[test]
    fn test_parse_mixed_denomination_boxes() {
        let nft_id = "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304";
        let token_a =
            "a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669".to_string();
        let token_b = "b8".repeat(32);

        let state = c4_test_state(NodeConfig::default());

        // ERG reserve: one NFT, ERG value is the collateral.
        let erg_box = c4_test_box();
        let erg = state
            .parse_reserve_box(&erg_box, ReserveContractKind::Erg, "erg_p2s")
            .expect("ERG reserve parses");
        assert_eq!(erg.base_info.collateral_amount, erg_box.value);
        assert_eq!(erg.base_info.reserve_token_id, "");
        assert_eq!(erg.denomination(), Some(crate::DenomKey::Erg));
        assert_eq!(erg.base_info.contract_address, "erg_p2s");

        // Token reserve A: collateral is tokens(1) amount, denomination is tokens(1) id.
        let mut tok_a_box = c4_test_box();
        tok_a_box.box_id = "token_box_a".to_string();
        tok_a_box.assets = vec![
            BoxAsset {
                token_id: nft_id.to_string(),
                amount: 1,
            },
            BoxAsset {
                token_id: token_a.clone(),
                amount: 5000,
            },
        ];
        let tok_a = state
            .parse_reserve_box(&tok_a_box, ReserveContractKind::Token, "token_p2s")
            .expect("token reserve A parses");
        assert_eq!(tok_a.base_info.collateral_amount, 5000);
        assert_eq!(tok_a.base_info.reserve_token_id, token_a.clone());
        assert_eq!(
            tok_a.denomination(),
            Some(crate::DenomKey::Token(
                hex::decode(&token_a).unwrap().try_into().unwrap()
            ))
        );
        assert_eq!(tok_a.base_info.contract_address, "token_p2s");

        // A different token on the same contract address is a different denomination.
        let mut tok_b_box = tok_a_box.clone();
        tok_b_box.box_id = "token_box_b".to_string();
        tok_b_box.assets[1] = BoxAsset {
            token_id: token_b.to_string(),
            amount: 700,
        };
        let tok_b = state
            .parse_reserve_box(&tok_b_box, ReserveContractKind::Token, "token_p2s")
            .expect("token reserve B parses");
        assert_ne!(tok_a.denomination(), tok_b.denomination());

        // Malformed token boxes are rejected, not misclassified.
        let mut bad = c4_test_box();
        bad.assets = vec![]; // token slot but no collateral token
        assert!(state
            .parse_reserve_box(&bad, ReserveContractKind::Token, "token_p2s")
            .is_err());
        let mut bad3 = c4_test_box();
        bad3.assets = vec![
            BoxAsset {
                token_id: nft_id.to_string(),
                amount: 1,
            },
            BoxAsset {
                token_id: token_a.clone(),
                amount: 5,
            },
            BoxAsset {
                token_id: token_b.clone(),
                amount: 5,
            },
        ];
        assert!(state
            .parse_reserve_box(&bad3, ReserveContractKind::Token, "token_p2s")
            .is_err());
    }

    #[test]
    fn test_parse_reserve_box_with_r6_register() {
        // Create a mock scan box with a public key that has the 0x07 prefix
        // and a valid 32-byte tracker NFT ID in R6 register
        let mut registers = HashMap::new();
        // This is a 33-byte public key with 0x07 prefix (GroupElement format)
        let prefixed_pubkey = VALID_PREFIXED_PUBKEY;
        registers.insert("R4".to_string(), prefixed_pubkey.to_string());
        // Fresh reserves must carry the empty AVL+ tree in R5 (C4)
        registers.insert("R5".to_string(), empty_reserve_tree_register());
        // This is a 32-byte tracker NFT ID with Ergo Coll[Byte] serialization prefix (0e20 + 64 hex chars)
        let tracker_nft_id = "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304";
        let tracker_nft_id_serialized = format!("0e20{}", tracker_nft_id);
        registers.insert("R6".to_string(), tracker_nft_id_serialized);

        let scan_box = ScanBox {
            box_id: "test_box_id".to_string(),
            value: 1000000000, // 1 ERG
            creation_height: 1000,
            ergo_tree: "test_ergo_tree".to_string(),
            transaction_id: "test_tx_id".to_string(),
            additional_registers: registers,
            assets: vec![],
        };

        // Create a dummy server state for testing
        let config = NodeConfig::default();
        let data_dir = std::env::temp_dir().join(format!(
            "basis_scanner_test_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let server_state =
            ServerState::new(config, &data_dir).expect("Failed to create server state");

        // Test the parse_reserve_box function
        let result =
            server_state.parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s");

        match result {
            Ok(reserve_info) => {
                // The owner_pubkey should have the 0x07 prefix stripped
                let expected_pubkey = &prefixed_pubkey[2..]; // Remove first 2 characters (07)

                assert_eq!(reserve_info.owner_pubkey, expected_pubkey);
                // The tracker_nft_id should match the one from R6 register
                assert_eq!(reserve_info.base_info.tracker_nft_id, tracker_nft_id);
                println!(
                    "SUCCESS: Prefix was correctly stripped. Original: {}, Stripped: {}",
                    prefixed_pubkey, reserve_info.owner_pubkey
                );
                println!(
                    "SUCCESS: Tracker NFT ID correctly extracted from R6 register: {}",
                    reserve_info.base_info.tracker_nft_id
                );
            }
            Err(e) => {
                panic!("Failed to parse reserve box: {:?}", e);
            }
        }
    }

    #[test]
    fn test_parse_reserve_box_missing_r6_register() {
        // Create a mock scan box with a public key but missing R6 register
        let mut registers = HashMap::new();
        // This is a 33-byte public key with 0x07 prefix (GroupElement format)
        let prefixed_pubkey = VALID_PREFIXED_PUBKEY;
        registers.insert("R4".to_string(), prefixed_pubkey.to_string());
        // Note: R6 register is intentionally missing

        let scan_box = ScanBox {
            box_id: "test_box_id_2".to_string(),
            value: 1000000000, // 1 ERG
            creation_height: 1000,
            ergo_tree: "test_ergo_tree".to_string(),
            transaction_id: "test_tx_id".to_string(),
            additional_registers: registers,
            assets: vec![],
        };

        // Create a dummy server state for testing
        let config = NodeConfig::default();
        let data_dir = std::env::temp_dir().join(format!(
            "basis_scanner_test_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let server_state =
            ServerState::new(config, &data_dir).expect("Failed to create server state");

        // Test the parse_reserve_box function - should return an error
        let result =
            server_state.parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s");

        match result {
            Ok(_) => {
                panic!("Expected error when R6 register is missing, but parsing succeeded");
            }
            Err(e) => {
                // Check that the error message mentions the missing R6 register
                assert!(e.to_string().contains("Missing R6 register"));
                println!(
                    "SUCCESS: Correctly returned error for missing R6 register: {:?}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_parse_reserve_box_invalid_r6_length() {
        // Create a mock scan box with an invalid R6 register (not 32 bytes)
        let mut registers = HashMap::new();
        // This is a 33-byte public key with 0x07 prefix (GroupElement format)
        let prefixed_pubkey = VALID_PREFIXED_PUBKEY;
        registers.insert("R4".to_string(), prefixed_pubkey.to_string());
        // This is an invalid tracker NFT ID with wrong length (only 16 bytes = 32 hex chars, should be 32 bytes = 64 hex chars)
        let invalid_tracker_nft_id = "1af23d4e5f6a7b8c9daebfc0d1e2f304";
        registers.insert("R6".to_string(), invalid_tracker_nft_id.to_string());

        let scan_box = ScanBox {
            box_id: "test_box_id_3".to_string(),
            value: 1000000000, // 1 ERG
            creation_height: 1000,
            ergo_tree: "test_ergo_tree".to_string(),
            transaction_id: "test_tx_id".to_string(),
            additional_registers: registers,
            assets: vec![],
        };

        // Create a dummy server state for testing
        let config = NodeConfig::default();
        let data_dir = std::env::temp_dir().join(format!(
            "basis_scanner_test_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let server_state =
            ServerState::new(config, &data_dir).expect("Failed to create server state");

        // Test the parse_reserve_box function - should return an error
        let result =
            server_state.parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s");

        match result {
            Ok(_) => {
                panic!("Expected error when R6 register has invalid length, but parsing succeeded");
            }
            Err(e) => {
                // Check that the error message mentions the invalid length
                assert!(e.to_string().contains("Invalid tracker NFT ID length"));
                println!(
                    "SUCCESS: Correctly returned error for invalid R6 register length: {:?}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    async fn test_process_scan_boxes_removes_absent_reserves_on_clean_scan() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Mock node returns one valid reserve box. A pre-existing stored reserve
        // that is absent from the scan should be removed because the snapshot is
        // fully parseable and therefore authoritative.
        let prefixed_pubkey = VALID_PREFIXED_PUBKEY;
        let tracker_nft_id = "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304";
        let empty_tree = empty_reserve_tree_register();
        let body = format!(
            concat!(
                "[",
                "{{\"boxId\":\"valid_box_1\",\"value\":1000,\"ergoTree\":\"00\",\"creationHeight\":100,",
                "\"transactionId\":\"tx1\",\"assets\":[{{\"tokenId\":\"{TEST_RESERVE_NFT}\",\"amount\":1}}],\"additionalRegisters\":{{\"R4\":\"{}\",\"R5\":\"{}\",\"R6\":\"0e20{}\"}}}}",
                "]"
            ),
            prefixed_pubkey, empty_tree, tracker_nft_id,
            TEST_RESERVE_NFT = TEST_RESERVE_NFT
        );

        // The scanned box is a root: its creating tx must spend a P2PK input of
        // the R4 owner key (issue #19).
        let owner_tree = p2pk_ergo_tree(&VALID_PREFIXED_PUBKEY[2..]);
        let txs = HashMap::from([(
            "tx1".to_string(),
            tx_json(
                "tx1",
                &[(
                    &"33".repeat(32),
                    "some_address",
                    &"44".repeat(32),
                    &owner_tree,
                )],
            ),
        )]);
        // Round 6e (P1): the absent reserve is removed because the index shows
        // it spent, 20 blocks deep.
        let mut txs = txs;
        txs.extend([
            tracked_box_route("preexisting_box", &[], Some("spend_tx")),
            spend_tx_route("spend_tx"),
            indexed_route(TEST_SPENT_AT + 20, TEST_SPENT_AT + 20),
        ]);
        let addr = spawn_mock_node(body, std::sync::Arc::new(txs)).await;

        let config = NodeConfig {
            node_url: format!("http://{}", addr),
            reserve_contract_p2s: Some("test_p2s".to_string()),
            ..Default::default()
        };
        let data_dir = std::env::temp_dir().join(format!(
            "basis_scanner_remove_test_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let server_state =
            ServerState::new(config, &data_dir).expect("Failed to create server state");

        // Pre-existing reserve that is NOT in the scan result.
        let preexisting = ExtendedReserveInfo {
            base_info: crate::ReserveInfo {
                collateral_amount: 500,
                last_updated_height: 0,
                contract_address: "test".to_string(),
                tracker_nft_id: "test".to_string(),
                refund_initiation_height: 0,
                reserve_token_id: String::new(),
            },
            total_debt: 0,
            box_id: "preexisting_box".to_string(),
            owner_pubkey: "deadbeef".to_string(),
            last_updated_timestamp: 0,
        };
        server_state
            .reserve_tracker
            .update_reserve(preexisting.clone())
            .unwrap();
        server_state
            .reserve_storage
            .store_reserve(&preexisting)
            .unwrap();

        server_state.process_scan_boxes().await.unwrap();

        let remaining: Vec<String> = server_state
            .reserve_tracker
            .get_all_reserves()
            .into_iter()
            .map(|r| r.box_id)
            .collect();
        assert!(
            remaining.contains(&hex::encode("valid_box_1")),
            "valid scanned box should be tracked (hex-encoded box id): {:?}",
            remaining
        );
        assert!(
            !remaining.contains(&"preexisting_box".to_string()),
            "absent pre-existing reserve must be removed on a clean scan: {:?}",
            remaining
        );
    }

    #[tokio::test]
    async fn test_process_scan_boxes_preserves_reserves_on_empty_scan() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Mock node returns an empty array. No reserves should be removed because
        // an empty scan is not treated as authoritative proof that all reserves
        // were spent (this also protects manually-inserted test reserves).
        let body = "[]";

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    // Round 8: a cycle needs the index height.
                    let body = if String::from_utf8_lossy(&buf[..n])
                        .starts_with("GET /blockchain/indexedHeight")
                    {
                        r#"{"indexedHeight":1000,"fullHeight":1000}"#
                    } else {
                        body
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });

        let config = NodeConfig {
            node_url: format!("http://{}", addr),
            reserve_contract_p2s: Some("test_p2s".to_string()),
            ..Default::default()
        };
        let data_dir = std::env::temp_dir().join(format!(
            "basis_scanner_empty_test_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let server_state =
            ServerState::new(config, &data_dir).expect("Failed to create server state");

        let preexisting = ExtendedReserveInfo {
            base_info: crate::ReserveInfo {
                collateral_amount: 500,
                last_updated_height: 0,
                contract_address: "test".to_string(),
                tracker_nft_id: "test".to_string(),
                refund_initiation_height: 0,
                reserve_token_id: String::new(),
            },
            total_debt: 0,
            box_id: "preexisting_box".to_string(),
            owner_pubkey: "deadbeef".to_string(),
            last_updated_timestamp: 0,
        };
        server_state
            .reserve_tracker
            .update_reserve(preexisting.clone())
            .unwrap();
        server_state
            .reserve_storage
            .store_reserve(&preexisting)
            .unwrap();

        server_state.process_scan_boxes().await.unwrap();

        let remaining: Vec<String> = server_state
            .reserve_tracker
            .get_all_reserves()
            .into_iter()
            .map(|r| r.box_id)
            .collect();
        assert!(
            remaining.contains(&"preexisting_box".to_string()),
            "pre-existing reserve must be preserved on an empty scan: {:?}",
            remaining
        );
    }

    #[tokio::test]
    async fn test_process_scan_boxes_removes_spent_reserve_despite_garbage_box() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Mock node returning one valid reserve box and one malformed box
        // (missing R4). The malformed box is quarantined individually: it is
        // skipped with a warning, but it must NOT block removal of a tracked
        // reserve that is genuinely spent (absent from the scan).
        let prefixed_pubkey = VALID_PREFIXED_PUBKEY;
        let tracker_nft_id = "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304";
        let empty_tree = empty_reserve_tree_register();
        let body = format!(
            concat!(
                "[",
                "{{\"boxId\":\"valid_box_1\",\"value\":1000,\"ergoTree\":\"00\",\"creationHeight\":100,",
                "\"transactionId\":\"tx1\",\"assets\":[{{\"tokenId\":\"{TEST_RESERVE_NFT}\",\"amount\":1}}],\"additionalRegisters\":{{\"R4\":\"{}\",\"R5\":\"{}\",\"R6\":\"0e20{}\"}}}}",
                ",",
                "{{\"boxId\":\"bad_box_2\",\"value\":1000,\"ergoTree\":\"00\",\"creationHeight\":100,",
                "\"transactionId\":\"tx2\",\"additionalRegisters\":{{}}}}",
                "]"
            ),
            prefixed_pubkey, empty_tree, tracker_nft_id,
            TEST_RESERVE_NFT = TEST_RESERVE_NFT
        );

        // The valid box is a root: its creating tx must spend a P2PK input of
        // the R4 owner key (issue #19).
        let owner_tree = p2pk_ergo_tree(&VALID_PREFIXED_PUBKEY[2..]);
        let txs = HashMap::from([(
            "tx1".to_string(),
            tx_json(
                "tx1",
                &[(
                    &"33".repeat(32),
                    "some_address",
                    &"44".repeat(32),
                    &owner_tree,
                )],
            ),
        )]);
        // Round 6e (P1): the absent reserve is removed because the index shows
        // it spent, 20 blocks deep.
        let mut txs = txs;
        txs.extend([
            tracked_box_route("preexisting_box", &[], Some("spend_tx")),
            spend_tx_route("spend_tx"),
            indexed_route(TEST_SPENT_AT + 20, TEST_SPENT_AT + 20),
        ]);
        let addr = spawn_mock_node(body, std::sync::Arc::new(txs)).await;

        let config = NodeConfig {
            node_url: format!("http://{}", addr),
            reserve_contract_p2s: Some("test_p2s".to_string()),
            ..Default::default()
        };
        let data_dir = std::env::temp_dir().join(format!(
            "basis_scanner_test_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let server_state =
            ServerState::new(config, &data_dir).expect("Failed to create server state");

        // Pre-existing reserve that is NOT in the scan result (genuinely spent).
        let preexisting = ExtendedReserveInfo {
            base_info: crate::ReserveInfo {
                collateral_amount: 500,
                last_updated_height: 0,
                contract_address: "test".to_string(),
                tracker_nft_id: "test".to_string(),
                refund_initiation_height: 0,
                reserve_token_id: String::new(),
            },
            total_debt: 0,
            box_id: "preexisting_box".to_string(),
            owner_pubkey: "deadbeef".to_string(),
            last_updated_timestamp: 0,
        };
        server_state
            .reserve_tracker
            .update_reserve(preexisting.clone())
            .unwrap();
        server_state
            .reserve_storage
            .store_reserve(&preexisting)
            .unwrap();

        server_state.process_scan_boxes().await.unwrap();

        let remaining: Vec<String> = server_state
            .reserve_tracker
            .get_all_reserves()
            .into_iter()
            .map(|r| r.box_id)
            .collect();
        assert!(
            remaining.contains(&hex::encode("valid_box_1")),
            "valid scanned box should be tracked (hex-encoded box id): {:?}",
            remaining
        );
        assert!(
            !remaining.contains(&hex::encode("bad_box_2")),
            "unparseable box must be skipped, not tracked: {:?}",
            remaining
        );
        assert!(
            !remaining.contains(&"preexisting_box".to_string()),
            "one garbage box must not block removal of a genuinely spent reserve: {:?}",
            remaining
        );
    }

    #[tokio::test]
    async fn test_get_unspent_reserve_boxes_paginates_all_pages() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // The node defaults to 5 boxes per page; the scanner must pass an
        // explicit limit and keep paging until a short page comes back.
        // Mock node: page 1 is full (RESERVE_BOX_PAGE_LIMIT boxes), page 2 has
        // 7 more; ALL of them must end up tracked.
        let full_page = RESERVE_BOX_PAGE_LIMIT as usize;
        let extra_page = 7usize;
        let total = full_page + extra_page;

        let tracker_nft_id = "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304";
        let empty_tree = empty_reserve_tree_register();

        // Each box gets a distinct owner key: admission control (issue #19)
        // tracks only one reserve per (owner, denomination), so same-owner
        // duplicates would be quarantined instead of tracked.
        let owners: Vec<String> = (0..total)
            .map(|_| hex::encode(basis_core::impls::generate_keypair().1))
            .collect();

        let box_json = |i: usize| {
            format!(
                "{{\"boxId\":\"{:064x}\",\"value\":1000,\"ergoTree\":\"00\",\"creationHeight\":100,",
                i
            ) + &format!(
                "\"transactionId\":\"{:064x}\",\"assets\":[{{\"tokenId\":\"{TEST_RESERVE_NFT}\",\"amount\":1}}],\"additionalRegisters\":{{\"R4\":\"07{}\",\"R5\":\"{}\",\"R6\":\"0e20{}\"}}}}",
                i, owners[i], empty_tree, tracker_nft_id
            )
        };
        let page = |from: usize, count: usize| {
            format!(
                "[{}]",
                (from..from + count)
                    .map(box_json)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let page1 = page(0, full_page);
        let page2 = page(full_page, extra_page);

        // Every box is a root (distinct owner per box), so its creating tx must
        // spend a P2PK input of the owner key (issue #19).
        let txs: std::sync::Arc<HashMap<String, String>> = std::sync::Arc::new(
            (0..total)
                .map(|i| {
                    let tx_id = format!("{:064x}", i);
                    let tree = p2pk_ergo_tree(&owners[i]);
                    (
                        tx_id.clone(),
                        tx_json(
                            &tx_id,
                            &[(&"33".repeat(32), "some_address", &"44".repeat(32), &tree)],
                        ),
                    )
                })
                .collect(),
        );

        let seen_offsets = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
        let seen_offsets_server = seen_offsets.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let page1 = page1.clone();
                let page2 = page2.clone();
                let seen_offsets = seen_offsets_server.clone();
                let txs = txs.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let request_line = request.lines().next().unwrap_or_default();
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();

                    // Transaction lookups (issue #19 admission) are answered
                    // from the tx map, token lookups (round 6c) with a
                    // singleton; box-list queries are paginated below.
                    let lookup = if let Some(tx_id) =
                        path.strip_prefix("/blockchain/transaction/byId/")
                    {
                        Some(match txs.get(tx_id) {
                            Some(body) => ("200 OK", body.clone()),
                            None => ("404 Not Found", "{}".to_string()),
                        })
                    } else if path.starts_with("/blockchain/indexedHeight") {
                        // Round 8: a cycle needs the index height.
                        Some((
                            "200 OK",
                            r#"{"indexedHeight":1000,"fullHeight":1000}"#.to_string(),
                        ))
                    } else {
                        path.strip_prefix("/blockchain/token/byId/").map(|token| {
                            (
                                "200 OK",
                                serde_json::json!({ "id": token, "emissionAmount": 1 }).to_string(),
                            )
                        })
                    };
                    if let Some((status, body)) = lookup {
                        let response = format!(
                            "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            status,
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        return;
                    }

                    let offset: u64 = request_line
                        .split('&')
                        .flat_map(|part| part.split('?'))
                        .find_map(|part| part.strip_prefix("offset="))
                        .and_then(|v| {
                            v.chars()
                                .take_while(|c| c.is_ascii_digit())
                                .collect::<String>()
                                .parse()
                                .ok()
                        })
                        .unwrap_or(0);
                    seen_offsets.lock().unwrap().push(offset);

                    let body = match offset {
                        0 => page1,
                        o if o == RESERVE_BOX_PAGE_LIMIT => page2,
                        _ => "[]".to_string(),
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });

        let config = NodeConfig {
            node_url: format!("http://{}", addr),
            reserve_contract_p2s: Some("test_p2s".to_string()),
            ..Default::default()
        };
        let data_dir = std::env::temp_dir().join(format!(
            "basis_scanner_pagination_test_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let server_state =
            ServerState::new(config, &data_dir).expect("Failed to create server state");

        server_state.process_scan_boxes().await.unwrap();

        // Round 6e: page 0 is read again at the end (boxes made meanwhile).
        assert_eq!(
            seen_offsets.lock().unwrap().as_slice(),
            &[0u64, RESERVE_BOX_PAGE_LIMIT, 0],
            "scanner must request page 2 after a full first page"
        );

        let tracked = server_state.reserve_tracker.get_all_reserves();
        assert_eq!(
            tracked.len(),
            total,
            "all reserves across every page must be tracked"
        );
        for i in 0..total {
            let box_id = format!("{:064x}", i);
            assert!(
                tracked.iter().any(|r| r.box_id == box_id),
                "reserve box {} from the scan must be tracked",
                box_id
            );
        }
    }

    /// Follow-up review N4: anyone can create maximum-size boxes at the reserve
    /// address for ~0.0015 ERG each. A full page of them, rendered the way the
    /// node returns indexed boxes, must still fit under the body cap, or every
    /// scan fails from then on.
    #[test]
    fn full_page_of_maximum_size_boxes_fits_the_body_cap() {
        let tree_hex = crate::contract_compiler::get_basis_token_reserve_ergo_tree_hex().unwrap();
        let address = crate::contract_compiler::get_basis_token_reserve_contract_p2s().unwrap();
        // Ergo caps a serialized box at 4096 bytes; let registers fill what the tree leaves.
        let per_register = (4096 - tree_hex.len() / 2 - 100) / 6;
        let register = || format!("0e{}", "ab".repeat(per_register));
        let box_json = |i: usize| {
            serde_json::json!({
                "boxId": format!("{:064x}", i),
                "transactionId": format!("{:064x}", i),
                "blockId": format!("{:064x}", i),
                "value": u64::MAX,
                "index": 0,
                "globalIndex": i,
                "creationHeight": 1_900_000,
                "settlementHeight": 1_900_000,
                "inclusionHeight": 1_900_000,
                "ergoTree": tree_hex,
                "address": address,
                "assets": [],
                "additionalRegisters": {
                    "R4": register(), "R5": register(), "R6": register(),
                    "R7": register(), "R8": register(), "R9": register()
                },
                "spentTransactionId": null,
                "spendingHeight": null
            })
        };
        let page: Vec<_> = (0..RESERVE_BOX_PAGE_LIMIT as usize).map(box_json).collect();
        let body = serde_json::to_string_pretty(&page).unwrap();
        assert!(
            body.len() <= crate::http::MAX_BODY_BYTES,
            "a full page of {} maximum-size boxes is {} bytes, over the {} byte cap",
            RESERVE_BOX_PAGE_LIMIT,
            body.len(),
            crate::http::MAX_BODY_BYTES
        );
    }

    #[test]
    fn test_parse_reserve_box_uses_token_collateral_per_box() {
        let reserve_token_id =
            "a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669".to_string();
        let nft_id = "69c5d7a4df2e72252b0015d981876fe338ca240d5576d4e731dfd848ae18fe2b".to_string();
        let owner_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        let mut registers = std::collections::HashMap::new();
        registers.insert("R4".to_string(), format!("07{}", owner_pubkey));
        registers.insert("R5".to_string(), empty_reserve_tree_register());
        registers.insert("R6".to_string(), format!("0e20{}", nft_id));
        registers.insert("R7".to_string(), "0500".to_string());

        let scan_box = ScanBox {
            box_id: "token_reserve_box".to_string(),
            value: 10000000, // 0.01 ERG min-box-value
            creation_height: 1000,
            ergo_tree: "test".to_string(),
            transaction_id: "test_tx".to_string(),
            additional_registers: registers,
            assets: vec![
                BoxAsset {
                    token_id: nft_id.clone(),
                    amount: 1,
                },
                BoxAsset {
                    token_id: reserve_token_id.clone(),
                    amount: 5000,
                },
            ],
        };

        let config = NodeConfig::default();
        let data_dir = std::env::temp_dir().join(format!(
            "basis_token_scanner_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let server_state =
            ServerState::new(config, &data_dir).expect("Failed to create server state");

        let reserve_info = server_state
            .parse_reserve_box(&scan_box, ReserveContractKind::Token, "test_p2s")
            .expect("should parse token reserve box");

        assert_eq!(
            reserve_info.base_info.collateral_amount, 5000,
            "collateral should be taken from reserve token amount"
        );
        assert_eq!(
            reserve_info.base_info.reserve_token_id, reserve_token_id,
            "reserve_token_id should be recorded"
        );
        assert_eq!(reserve_info.base_info.tracker_nft_id, nft_id);
    }

    /// Build a minimal valid first-seen reserve box for the C4 rejection tests.
    fn c4_test_box() -> ScanBox {
        let nft_id = "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304";
        let mut registers = HashMap::new();
        registers.insert("R4".to_string(), VALID_PREFIXED_PUBKEY.to_string());
        registers.insert("R5".to_string(), empty_reserve_tree_register());
        registers.insert("R6".to_string(), format!("0e20{}", nft_id));
        ScanBox {
            box_id: "c4_test_box".to_string(),
            value: 1000000000,
            creation_height: 1000,
            ergo_tree: "test_ergo_tree".to_string(),
            transaction_id: "test_tx_id".to_string(),
            additional_registers: registers,
            assets: vec![BoxAsset {
                token_id: TEST_RESERVE_NFT.to_string(),
                amount: 1,
            }],
        }
    }

    fn c4_test_state(config: NodeConfig) -> ServerState {
        let data_dir = std::env::temp_dir().join(format!(
            "basis_scanner_c4_test_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        ServerState::new(config, &data_dir).expect("Failed to create server state")
    }

    #[test]
    fn test_parse_reserve_box_rejects_non_long_r7() {
        // An Int-typed R7 would make SELF.R7[Long] throw on-chain, bricking the
        // box, while the scanner would read it as 0.
        let mut scan_box = c4_test_box();
        scan_box
            .additional_registers
            .insert("R7".to_string(), "0401".to_string()); // Int 1
        let state = c4_test_state(NodeConfig::default());
        let err = state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .unwrap_err();
        assert!(
            err.to_string().contains("not a Long"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_admission_quarantines_root_with_pending_refund() {
        // R7 = Long 1 (zigzag 2 -> VLQ 0x02): refund pending from creation.
        // Parsing succeeds (the box is structurally valid); the C4 setup check
        // rejects it at admission (issue #19).
        let mut scan_box = c4_test_box();
        scan_box
            .additional_registers
            .insert("R7".to_string(), "0502".to_string());
        let state = c4_test_state(NodeConfig::default());
        let info = state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .expect("structurally valid box parses");
        match state.admit_reserve_box(&scan_box, &info, "test_p2s").await {
            ReserveAdmission::Quarantined { reason } => {
                assert!(
                    reason.contains("pending refund"),
                    "unexpected reason: {}",
                    reason
                );
            }
            other => panic!("expected Quarantined, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_admission_quarantines_root_with_prefilled_tree() {
        let mut scan_box = c4_test_box();
        scan_box.additional_registers.insert(
            "R5".to_string(),
            "64ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff032000"
                .to_string(),
        );
        let state = c4_test_state(NodeConfig::default());
        let info = state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .expect("structurally valid box parses");
        match state.admit_reserve_box(&scan_box, &info, "test_p2s").await {
            ReserveAdmission::Quarantined { reason } => {
                assert!(
                    reason.contains("non-empty AVL tree"),
                    "unexpected reason: {}",
                    reason
                );
            }
            other => panic!("expected Quarantined, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_admission_admits_clean_root() {
        // A clean root whose creating transaction spends a P2PK input of the
        // R4 owner key is admitted (issue #19 ownership proof).
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let scan_box = c4_test_box();
        let owner_tree = p2pk_ergo_tree(owner);
        let txs = HashMap::from([(
            scan_box.transaction_id.clone(),
            tx_json(
                &scan_box.transaction_id,
                &[(
                    &"33".repeat(32),
                    "some_address",
                    &"44".repeat(32),
                    &owner_tree,
                )],
            ),
        )]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(txs)).await);
        let info = state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .expect("valid box parses");
        assert_eq!(
            state.admit_reserve_box(&scan_box, &info, "test_p2s").await,
            ReserveAdmission::Admitted
        );
    }

    #[tokio::test]
    async fn test_admission_quarantines_root_without_owner_p2pk_input() {
        // Front-run attempt (issue #19): a C4-clean box carrying the victim's
        // key in R4, but its creating transaction spends no P2PK input of that
        // key, so the box is never tracked.
        let scan_box = c4_test_box();
        let txs = HashMap::from([(
            scan_box.transaction_id.clone(),
            tx_json(
                &scan_box.transaction_id,
                &[(&"33".repeat(32), "some_address", &"44".repeat(32), "00")],
            ),
        )]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(txs)).await);
        let info = state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .expect("valid box parses");
        match state.admit_reserve_box(&scan_box, &info, "test_p2s").await {
            ReserveAdmission::Quarantined { reason } => {
                assert!(
                    reason.contains("no P2PK input"),
                    "unexpected reason: {}",
                    reason
                );
            }
            other => panic!("expected Quarantined, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_admission_quarantines_root_with_foreign_p2pk_input() {
        // The creating tx spends a P2PK input, but of a DIFFERENT key than R4.
        let scan_box = c4_test_box();
        let other_key = hex::encode(basis_core::impls::generate_keypair().1);
        let foreign_tree = p2pk_ergo_tree(&other_key);
        let txs = HashMap::from([(
            scan_box.transaction_id.clone(),
            tx_json(
                &scan_box.transaction_id,
                &[(
                    &"33".repeat(32),
                    "some_address",
                    &"44".repeat(32),
                    &foreign_tree,
                )],
            ),
        )]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(txs)).await);
        let info = state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .expect("valid box parses");
        match state.admit_reserve_box(&scan_box, &info, "test_p2s").await {
            ReserveAdmission::Quarantined { reason } => {
                assert!(
                    reason.contains("no P2PK input"),
                    "unexpected reason: {}",
                    reason
                );
            }
            other => panic!("expected Quarantined, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_reserve_box_rejects_foreign_tracker_nft() {
        let scan_box = c4_test_box();
        let config = NodeConfig {
            tracker_nft_id: Some(
                "69c5d7a4df2e72252b0015d981876fe338ca240d5576d4e731dfd848ae18fe2b".to_string(),
            ),
            ..Default::default()
        };
        let state = c4_test_state(config);
        let err = state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .unwrap_err();
        assert!(
            err.to_string().contains("Tracker NFT ID mismatch"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_parse_reserve_box_accepts_own_tracker_nft() {
        let scan_box = c4_test_box();
        let config = NodeConfig {
            tracker_nft_id: Some(
                "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304".to_string(),
            ),
            ..Default::default()
        };
        let state = c4_test_state(config);
        state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .expect("reserve bound to the configured tracker NFT should parse");
    }

    #[test]
    fn test_parse_reserve_box_rejects_invalid_pubkey() {
        let mut scan_box = c4_test_box();
        scan_box.additional_registers.insert(
            "R4".to_string(),
            "07c5b4b2f6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4".to_string(),
        );
        let state = c4_test_state(NodeConfig::default());
        let err = state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .unwrap_err();
        assert!(
            err.to_string().contains("Invalid owner pubkey"),
            "unexpected error: {}",
            err
        );
    }

    /// Spawn a mock node that serves `boxes_body` for box-list queries and
    /// answers `GET /blockchain/transaction/byId/{txId}` from `txs`
    /// (404 when the transaction is unknown).
    async fn spawn_mock_node(
        boxes_body: String,
        txs: std::sync::Arc<HashMap<String, String>>,
    ) -> std::net::SocketAddr {
        spawn_counting_mock_node(boxes_body, txs).await.0
    }

    /// Requests a mock node received, by path.
    type Hits = std::sync::Arc<std::sync::Mutex<HashMap<String, usize>>>;

    /// Mock node route key: the box list the scan gets after its first request.
    const SCAN_AFTER_FIRST_READ: &str = "scan-after-first-read";

    /// Mock node route body: the request is never answered (round 8).
    const MOCK_HANG: &str = "!hang";

    /// `spawn_mock_node`, also counting the requests by path. The scan answer
    /// is paged by the `offset` and `limit` of the query.
    async fn spawn_counting_mock_node(
        boxes_body: String,
        txs: std::sync::Arc<HashMap<String, String>>,
    ) -> (std::net::SocketAddr, Hits) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Hits::default();
        let hits_task = hits.clone();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let boxes_body = boxes_body.clone();
                let txs = txs.clone();
                let hits = hits_task.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let request_line = request.lines().next().unwrap_or_default();
                    let target = request_line.split_whitespace().nth(1).unwrap_or_default();
                    let (path, query) = target.split_once('?').unwrap_or((target, ""));
                    let reads = {
                        let mut hits = hits.lock().unwrap();
                        let count = hits.entry(path.to_string()).or_default();
                        *count += 1;
                        *count
                    };
                    // Round 8: a route `MOCK_HANG` never answers, one
                    // starting with `!` answers its status (`!500 body`).
                    if txs.get(path).is_some_and(|body| body == MOCK_HANG) {
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        return;
                    }
                    // `txs` keys are transaction ids, or full paths for the
                    // box and token index (404 when absent).
                    let (status, body) = if let Some(body) = txs.get(path) {
                        match body.strip_prefix('!').and_then(|rest| rest.split_once(' ')) {
                            Some((code, rest)) => (
                                match code {
                                    "500" => "500 Internal Server Error",
                                    "503" => "503 Service Unavailable",
                                    _ => "404 Not Found",
                                },
                                rest.to_string(),
                            ),
                            None => ("200 OK", body.clone()),
                        }
                    } else if path == "/blockchain/indexedHeight" {
                        // Round 8: a cycle needs the index height. Unless a
                        // test gives one, the index is at the node's height
                        // (the `/info` route), else at TEST_SPENT_AT.
                        let height = txs
                            .get("/info")
                            .and_then(|info| serde_json::from_str::<serde_json::Value>(info).ok())
                            .and_then(|info| info["fullHeight"].as_u64())
                            .unwrap_or(TEST_SPENT_AT);
                        (
                            "200 OK",
                            serde_json::json!({ "indexedHeight": height, "fullHeight": height })
                                .to_string(),
                        )
                    } else if let Some(tx_id) = path.strip_prefix("/blockchain/transaction/byId/") {
                        match txs.get(tx_id) {
                            Some(body) => ("200 OK", body.clone()),
                            None => ("404 Not Found", "{}".to_string()),
                        }
                    } else if let Some(token) = path.strip_prefix("/blockchain/token/byId/") {
                        // Unless a test says otherwise, every token is a singleton.
                        (
                            "200 OK",
                            serde_json::json!({ "id": token, "emissionAmount": 1 }).to_string(),
                        )
                    } else if path.starts_with("/blockchain/box/byId/") {
                        ("404 Not Found", "{}".to_string())
                    } else {
                        let param = |name: &str| {
                            query.split('&').find_map(|part| {
                                part.strip_prefix(name)?
                                    .strip_prefix('=')?
                                    .parse::<usize>()
                                    .ok()
                            })
                        };
                        // `SCAN_AFTER_FIRST_READ`: the list a scan reads after
                        // its first request (a box made meanwhile, round 6e).
                        let boxes_body = match txs.get(SCAN_AFTER_FIRST_READ) {
                            Some(later) if reads > 1 => later.clone(),
                            _ => boxes_body,
                        };
                        match (
                            serde_json::from_str::<Vec<serde_json::Value>>(&boxes_body),
                            param("offset"),
                            param("limit"),
                        ) {
                            (Ok(all), Some(offset), Some(limit)) => (
                                "200 OK",
                                serde_json::Value::from(
                                    all.into_iter().skip(offset).take(limit).collect::<Vec<_>>(),
                                )
                                .to_string(),
                            ),
                            _ => ("200 OK", boxes_body),
                        }
                    };
                    let response = format!(
                        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        status,
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        (addr, hits)
    }

    fn mock_state(addr: std::net::SocketAddr) -> ServerState {
        c4_test_state(NodeConfig {
            node_url: format!("http://{}", addr),
            reserve_contract_p2s: Some("test_p2s".to_string()),
            ..Default::default()
        })
    }

    /// Insert a tracked reserve (in-memory + persisted), ERG denomination.
    fn insert_tracked_reserve(state: &ServerState, box_id: &str, owner_pubkey: &str) {
        let info = ExtendedReserveInfo {
            base_info: crate::ReserveInfo {
                collateral_amount: 1_000_000_000,
                last_updated_height: 0,
                contract_address: "test_p2s".to_string(),
                tracker_nft_id: "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304"
                    .to_string(),
                refund_initiation_height: 0,
                reserve_token_id: String::new(),
            },
            total_debt: 0,
            box_id: normalized_box_id(box_id),
            owner_pubkey: owner_pubkey.to_string(),
            last_updated_timestamp: 0,
        };
        state.reserve_tracker.update_reserve(info.clone()).unwrap();
        state.reserve_storage.store_reserve(&info).unwrap();
    }

    /// A transaction whose inputs are boxes without tokens.
    fn tx_json(tx_id: &str, inputs: &[(&str, &str, &str, &str)]) -> String {
        tx_json_inputs(
            tx_id,
            inputs
                .iter()
                .map(|(box_id, address, creating_tx, ergo_tree)| {
                    plain_input(box_id, address, creating_tx, ergo_tree)
                })
                .collect(),
        )
    }

    fn tx_json_inputs(tx_id: &str, inputs: Vec<serde_json::Value>) -> String {
        serde_json::json!({
            "id": tx_id,
            "inclusionHeight": TEST_SPENT_AT,
            "inputs": inputs,
            "outputs": []
        })
        .to_string()
    }

    /// An input box without tokens (a wallet box, say).
    fn plain_input(
        box_id: &str,
        address: &str,
        creating_tx: &str,
        ergo_tree: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "boxId": box_id,
            "address": address,
            "transactionId": creating_tx,
            "ergoTree": ergo_tree,
            "assets": [],
            "additionalRegisters": {}
        })
    }

    /// A reserve box of the `VALID_PREFIXED_PUBKEY` owner at `test_p2s` as an
    /// input, holding `assets` (the reserve NFT first).
    fn reserve_input(box_id: &str, creating_tx: &str, assets: &[(&str, u64)]) -> serde_json::Value {
        serde_json::json!({
            "boxId": box_id,
            "address": "test_p2s",
            "transactionId": creating_tx,
            "ergoTree": "00",
            "assets": assets
                .iter()
                .map(|(token_id, amount)| serde_json::json!({ "tokenId": token_id, "amount": amount }))
                .collect::<Vec<_>>(),
            "additionalRegisters": {
                "R4": VALID_PREFIXED_PUBKEY,
                "R5": empty_reserve_tree_register(),
                "R6": format!("0e20{}", TEST_TRACKER_NFT)
            }
        })
    }

    /// The tracker NFT the test reserve boxes name in R6.
    const TEST_TRACKER_NFT: &str =
        "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304";

    /// The mock node route of `/blockchain/box/byId` for the tracked reserve
    /// box `box_id` holding `assets`, spent by `spent_by` (unspent: `None`).
    fn tracked_box_route(
        box_id: &str,
        assets: &[(&str, u64)],
        spent_by: Option<&str>,
    ) -> (String, String) {
        let mut chain_box = reserve_input(box_id, &"c0".repeat(32), assets);
        // Like the node: `spentTransactionId`, no spend height (round 6e).
        chain_box["spentTransactionId"] = serde_json::json!(spent_by);
        (
            format!("/blockchain/box/byId/{}", box_id),
            chain_box.to_string(),
        )
    }

    /// The height the test transactions are included at (`inclusionHeight`).
    const TEST_SPENT_AT: u64 = 1_000;

    /// The mock node route of `/blockchain/transaction/byId` for a spending
    /// transaction `tx_id` with no inputs, included at `TEST_SPENT_AT`.
    fn spend_tx_route(tx_id: &str) -> (String, String) {
        (tx_id.to_string(), tx_json_inputs(tx_id, vec![]))
    }

    /// The mock node route of `/blockchain/indexedHeight`.
    fn indexed_route(indexed: u64, full: u64) -> (String, String) {
        (
            "/blockchain/indexedHeight".to_string(),
            serde_json::json!({ "indexedHeight": indexed, "fullHeight": full }).to_string(),
        )
    }

    /// The mock node route of `/info` at `height`.
    fn info_route(height: u64) -> (String, String) {
        (
            "/info".to_string(),
            serde_json::json!({ "fullHeight": height }).to_string(),
        )
    }

    /// The mock node route of `/blockchain/token/byId` for `token`.
    fn token_route(token: &str, emission: u64) -> (String, String) {
        (
            format!("/blockchain/token/byId/{}", token),
            serde_json::json!({ "id": token, "emissionAmount": emission }).to_string(),
        )
    }

    #[tokio::test]
    async fn test_admission_quarantines_duplicate_dust_box() {
        // Issue #19: an attacker creates a dust box at the reserve contract
        // with the victim's key in R4 while the victim's reserve is unspent.
        // The box is C4-clean, so only the lineage check can reject it.
        let tracked_box = "11".repeat(32);
        let attacker_box = "22".repeat(32);
        let attacker_tx = "aa".repeat(32);

        // The attacker's creating transaction does NOT spend the tracked box,
        // and the dust box holds the attacker's own NFT (round 6c: decided at
        // once, no walk). The tracked box is unspent.
        let txs = HashMap::from([
            (
                attacker_tx.clone(),
                tx_json(
                    &attacker_tx,
                    &[(
                        &"33".repeat(32),
                        "some_other_address",
                        &"44".repeat(32),
                        "00",
                    )],
                ),
            ),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], None),
        ]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(txs)).await);

        let owner = &VALID_PREFIXED_PUBKEY[2..];
        insert_tracked_reserve(&state, &tracked_box, owner);

        let mut scan_box = c4_test_box();
        scan_box.box_id = attacker_box.clone();
        scan_box.transaction_id = attacker_tx.clone();
        scan_box.value = 1_000_000; // dust
        scan_box.assets[0].token_id = "33".repeat(32);

        let tagged = TaggedScanBox {
            scan_box,
            kind: ReserveContractKind::Erg,
            contract_address: "test_p2s".to_string(),
        };
        assert_eq!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Rejected(attacker_box.clone()),
            "the dust duplicate must be quarantined"
        );

        // The quarantine record is persisted with the reason...
        let record = state
            .reserve_storage
            .get_quarantined(&attacker_box)
            .unwrap()
            .expect("quarantine record persisted");
        assert!(
            record
                .reason
                .contains("does not hold the tracked reserve NFT"),
            "unexpected reason: {}",
            record.reason
        );

        // ...and the victim's reserve still resolves unambiguously.
        let resolved = state
            .reserve_tracker
            .resolve_issuer_reserve(owner, &crate::DenomKey::Erg);
        assert!(
            resolved.is_ok(),
            "issuer must not be blocked: {:?}",
            resolved
        );
        assert_eq!(resolved.unwrap().box_id, tracked_box);

        // Once quarantined, always quarantined (no re-evaluation).
        assert_eq!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Rejected(attacker_box)
        );
    }

    #[tokio::test]
    async fn test_admission_admits_lineage_successor() {
        // A top-up/redemption successor: its creating transaction spends the
        // tracked box, and the contract guarantees register continuity.
        let tracked_box = "11".repeat(32);
        let successor_box = "55".repeat(32);
        let successor_tx = "bb".repeat(32);

        let txs = HashMap::from([
            (
                successor_tx.clone(),
                tx_json_inputs(
                    &successor_tx,
                    vec![
                        plain_input(
                            &"cd".repeat(32),
                            "some_address",
                            &"ce".repeat(32),
                            "0008cd02",
                        ),
                        reserve_input(&tracked_box, &"cc".repeat(32), &[(TEST_RESERVE_NFT, 1)]),
                    ],
                ),
            ),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&successor_tx)),
        ]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(txs)).await);

        let owner = &VALID_PREFIXED_PUBKEY[2..];
        insert_tracked_reserve(&state, &tracked_box, owner);

        let mut scan_box = c4_test_box();
        scan_box.box_id = successor_box.clone();
        scan_box.transaction_id = successor_tx.clone();
        // A redemption successor legitimately has a non-empty R5 tree.
        scan_box.additional_registers.insert(
            "R5".to_string(),
            "64aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa032000"
                .to_string(),
        );

        let tagged = TaggedScanBox {
            scan_box,
            kind: ReserveContractKind::Erg,
            contract_address: "test_p2s".to_string(),
        };
        assert_eq!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Tracked(successor_box)
        );
    }

    #[tokio::test]
    async fn test_admission_admits_successor_across_missed_generations() {
        // The tracker was down while the reserve moved tracked -> mid -> tip;
        // the lineage walk must follow the reserve-contract inputs backwards.
        let tracked_box = "11".repeat(32);
        let mid_box = "66".repeat(32);
        let tip_box = "77".repeat(32);
        let tip_tx = "dd".repeat(32);
        let mid_tx = "ee".repeat(32);

        let txs = HashMap::from([
            (
                tip_tx.clone(),
                tx_json_inputs(
                    &tip_tx,
                    vec![reserve_input(&mid_box, &mid_tx, &[(TEST_RESERVE_NFT, 1)])],
                ),
            ),
            (
                mid_tx.clone(),
                tx_json_inputs(
                    &mid_tx,
                    vec![reserve_input(
                        &tracked_box,
                        &"ff".repeat(32),
                        &[(TEST_RESERVE_NFT, 1)],
                    )],
                ),
            ),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&mid_tx)),
            // Not a singleton: only the walk can tell.
            token_route(TEST_RESERVE_NFT, 2),
        ]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(txs)).await);

        let owner = &VALID_PREFIXED_PUBKEY[2..];
        insert_tracked_reserve(&state, &tracked_box, owner);

        let mut scan_box = c4_test_box();
        scan_box.box_id = tip_box.clone();
        scan_box.transaction_id = tip_tx.clone();

        let tagged = TaggedScanBox {
            scan_box,
            kind: ReserveContractKind::Erg,
            contract_address: "test_p2s".to_string(),
        };
        assert_eq!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Tracked(tip_box)
        );
    }

    #[tokio::test]
    async fn test_process_scan_boxes_keeps_tracked_reserve_on_lineage_retry() {
        // The scan returns a would-be successor plus an unrelated valid box
        // (so the removal loop runs). The successor's tx lookup fails (404),
        // making it Pending: the tracked box must NOT be removed as spent.
        let tracked_box = "11".repeat(32);
        let successor_box = "55".repeat(32);
        let successor_tx = "bb".repeat(32);
        let other_box = "99".repeat(32);
        let other_tx = "12".repeat(32);
        let other_owner = hex::encode(basis_core::impls::generate_keypair().1);
        let nft_id = "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304";
        let empty_tree = empty_reserve_tree_register();

        let boxes_body = format!(
            concat!(
                "[",
                "{{\"boxId\":\"{}\",\"value\":1000,\"ergoTree\":\"00\",\"creationHeight\":100,",
                "\"transactionId\":\"{}\",\"assets\":[{{\"tokenId\":\"{TEST_RESERVE_NFT}\",\"amount\":1}}],\"additionalRegisters\":{{\"R4\":\"{}\",\"R5\":\"{}\",\"R6\":\"0e20{}\"}}}}",
                ",",
                "{{\"boxId\":\"{}\",\"value\":1000,\"ergoTree\":\"00\",\"creationHeight\":100,",
                "\"transactionId\":\"{}\",\"assets\":[{{\"tokenId\":\"{TEST_RESERVE_NFT}\",\"amount\":1}}],\"additionalRegisters\":{{\"R4\":\"07{}\",\"R5\":\"{}\",\"R6\":\"0e20{}\"}}}}",
                "]"
            ),
            successor_box, successor_tx, VALID_PREFIXED_PUBKEY, empty_tree, nft_id,
            other_box, other_tx, other_owner, empty_tree, nft_id,
            TEST_RESERVE_NFT = TEST_RESERVE_NFT
        );

        // The successor's creating tx is unknown (404 -> lineage Retry), while
        // the unrelated root's tx carries its owner's P2PK input.
        let other_tree = p2pk_ergo_tree(&other_owner);
        let txs = HashMap::from([(
            other_tx.clone(),
            tx_json(
                &other_tx,
                &[(
                    &"33".repeat(32),
                    "some_address",
                    &"44".repeat(32),
                    &other_tree,
                )],
            ),
        )]);
        let state = mock_state(spawn_mock_node(boxes_body, std::sync::Arc::new(txs)).await);
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        insert_tracked_reserve(&state, &tracked_box, owner);

        state.process_scan_boxes().await.unwrap();

        let remaining: Vec<String> = state
            .reserve_tracker
            .get_all_reserves()
            .into_iter()
            .map(|r| r.box_id)
            .collect();
        assert!(
            remaining.contains(&tracked_box),
            "tracked reserve must be kept while the successor lineage check is pending: {:?}",
            remaining
        );
        assert!(
            !remaining.contains(&successor_box),
            "unverified successor must not be tracked: {:?}",
            remaining
        );
        assert!(
            remaining.contains(&other_box),
            "unrelated root must be admitted: {:?}",
            remaining
        );
    }

    #[tokio::test]
    async fn test_process_scan_boxes_quarantines_duplicate_and_keeps_issuer_working() {
        // The issue #19 scenario end to end: the scan returns the victim's own
        // reserve plus the attacker's C4-clean dust duplicate in one cycle.
        let tracked_box = "11".repeat(32);
        let attacker_box = "22".repeat(32);
        let attacker_tx = "aa".repeat(32);
        let nft_id = "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304";
        let empty_tree = empty_reserve_tree_register();

        let boxes_body = format!(
            concat!(
                "[",
                "{{\"boxId\":\"{}\",\"value\":1000000000,\"ergoTree\":\"00\",\"creationHeight\":100,",
                "\"transactionId\":\"{}\",\"assets\":[{{\"tokenId\":\"{TEST_RESERVE_NFT}\",\"amount\":1}}],\"additionalRegisters\":{{\"R4\":\"{}\",\"R5\":\"{}\",\"R6\":\"0e20{}\"}}}}",
                ",",
                "{{\"boxId\":\"{}\",\"value\":1000000,\"ergoTree\":\"00\",\"creationHeight\":200,",
                "\"transactionId\":\"{}\",\"assets\":[{{\"tokenId\":\"{ATTACKER_NFT}\",\"amount\":1}}],\"additionalRegisters\":{{\"R4\":\"{}\",\"R5\":\"{}\",\"R6\":\"0e20{}\"}}}}",
                "]"
            ),
            tracked_box, "00".repeat(32), VALID_PREFIXED_PUBKEY, empty_tree, nft_id,
            attacker_box, attacker_tx, VALID_PREFIXED_PUBKEY, empty_tree, nft_id,
            TEST_RESERVE_NFT = TEST_RESERVE_NFT,
            ATTACKER_NFT = "33".repeat(32)
        );
        let txs = HashMap::from([(
            attacker_tx.clone(),
            tx_json(
                &attacker_tx,
                &[(
                    &"33".repeat(32),
                    "some_other_address",
                    &"44".repeat(32),
                    "00",
                )],
            ),
        )]);
        let state = mock_state(spawn_mock_node(boxes_body, std::sync::Arc::new(txs)).await);
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        insert_tracked_reserve(&state, &tracked_box, owner);

        state.process_scan_boxes().await.unwrap();

        // The attacker box is quarantined...
        assert!(state
            .reserve_storage
            .get_quarantined(&attacker_box)
            .unwrap()
            .is_some());
        // ...and the issuer's single reserve still resolves.
        let resolved = state
            .reserve_tracker
            .resolve_issuer_reserve(owner, &crate::DenomKey::Erg)
            .expect("issuer must keep working");
        assert_eq!(resolved.box_id, tracked_box);
    }

    #[tokio::test]
    async fn test_admission_quarantines_root_without_reserve_nft() {
        // Round 6b: the lineage is followed by the reserve NFT, so a root
        // without one (or with a token held more than once at tokens(0)) is
        // never tracked.
        let state = c4_test_state(NodeConfig::default());
        for assets in [
            vec![],
            vec![BoxAsset {
                token_id: TEST_RESERVE_NFT.to_string(),
                amount: 2,
            }],
        ] {
            let mut scan_box = c4_test_box();
            scan_box.assets = assets;
            let info = state
                .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
                .expect("structurally valid box parses");
            match state.admit_reserve_box(&scan_box, &info, "test_p2s").await {
                ReserveAdmission::Quarantined { reason } => {
                    assert!(
                        reason.contains("reserve NFT"),
                        "unexpected reason: {}",
                        reason
                    );
                }
                other => panic!("expected Quarantined, got {:?}", other),
            }
        }
    }

    /// A scanned reserve-contract box as the node lists it.
    fn scanned_box_json(
        box_id: &str,
        tx_id: &str,
        value: u64,
        assets: &[(&str, u64)],
        r7: Option<&str>,
    ) -> serde_json::Value {
        let mut registers = serde_json::json!({
            "R4": VALID_PREFIXED_PUBKEY,
            "R5": empty_reserve_tree_register(),
            "R6": format!("0e20{}", TEST_TRACKER_NFT)
        });
        if let Some(r7) = r7 {
            registers["R7"] = serde_json::Value::from(r7);
        }
        serde_json::json!({
            "boxId": box_id,
            "value": value,
            "ergoTree": "00",
            "creationHeight": 200,
            "transactionId": tx_id,
            "assets": assets
                .iter()
                .map(|(token_id, amount)| serde_json::json!({ "tokenId": token_id, "amount": amount }))
                .collect::<Vec<_>>(),
            "additionalRegisters": registers
        })
    }

    /// Round 6b attack: a top-up needs no owner signature and the contract only
    /// checks the output it names, so the attacker's transaction spends its own
    /// box A and the victim's tracked reserve G (NFT N) into G + 0.1 ERG and a
    /// box P at the reserve contract with R4 = victim, R6 = our tracker NFT,
    /// an empty R5, R7 = 0 and a fresh NFT (A's id). Both are scanned in one
    /// cycle. Whatever the input order, scan order and box-id order, the
    /// tracker follows only the box holding N; P is quarantined and the victim
    /// keeps exactly one reserve.
    #[tokio::test]
    async fn test_sibling_without_the_reserve_nft_never_continues_the_reserve() {
        let tracked_box = "11".repeat(32);
        let attacker_box = "a1".repeat(32);
        let attack_tx = "bb".repeat(32);
        let topped_up = "55".repeat(32);
        for sibling in ["22".repeat(32), "88".repeat(32)] {
            for attacker_input_first in [true, false] {
                for sibling_scanned_first in [true, false] {
                    let attacker = plain_input(
                        &attacker_box,
                        "attacker_address",
                        &"a2".repeat(32),
                        &p2pk_ergo_tree(&"03".repeat(33)),
                    );
                    let reserve =
                        reserve_input(&tracked_box, &"c0".repeat(32), &[(TEST_RESERVE_NFT, 1)]);
                    let inputs = if attacker_input_first {
                        vec![attacker, reserve]
                    } else {
                        vec![reserve, attacker]
                    };
                    let txs = HashMap::from([
                        (attack_tx.clone(), tx_json_inputs(&attack_tx, inputs)),
                        tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&attack_tx)),
                    ]);
                    let genuine = scanned_box_json(
                        &topped_up,
                        &attack_tx,
                        1_100_000_000,
                        &[(TEST_RESERVE_NFT, 1)],
                        None,
                    );
                    let fake = scanned_box_json(
                        &sibling,
                        &attack_tx,
                        1_000_000,
                        &[(attacker_box.as_str(), 1)],
                        Some("0500"),
                    );
                    let scanned = if sibling_scanned_first {
                        serde_json::json!([fake, genuine])
                    } else {
                        serde_json::json!([genuine, fake])
                    };
                    let state = mock_state(
                        spawn_mock_node(scanned.to_string(), std::sync::Arc::new(txs)).await,
                    );
                    let owner = &VALID_PREFIXED_PUBKEY[2..];
                    insert_tracked_reserve(&state, &tracked_box, owner);

                    state.process_scan_boxes().await.unwrap();

                    let case = format!(
                        "sibling {}, attacker input first {}, sibling scanned first {}",
                        &sibling[..2],
                        attacker_input_first,
                        sibling_scanned_first
                    );
                    let tracked: Vec<String> = state
                        .reserve_tracker
                        .get_reserves_by_owner(owner)
                        .into_iter()
                        .map(|r| r.box_id)
                        .collect();
                    assert_eq!(tracked, vec![topped_up.clone()], "{case}");
                    assert!(
                        state
                            .reserve_storage
                            .get_quarantined(&sibling)
                            .unwrap()
                            .is_some(),
                        "{case}"
                    );
                    let resolved = state
                        .reserve_tracker
                        .resolve_issuer_reserve(owner, &crate::DenomKey::Erg)
                        .unwrap_or_else(|e| panic!("{case}: {e:?}"));
                    assert_eq!(resolved.box_id, topped_up, "{case}");
                    assert_eq!(
                        resolved.base_info.collateral_amount, 1_100_000_000,
                        "{case}"
                    );
                }
            }
        }
    }

    /// Round 6b: a box holding the reserve NFT more than once, or at another
    /// position than tokens(0), or with another R6, is no successor.
    #[tokio::test]
    async fn test_successor_needs_the_nft_at_tokens0_and_the_same_registers() {
        let tracked_box = "11".repeat(32);
        let tx = "bb".repeat(32);
        let other_token = "6f".repeat(32);
        let txs = HashMap::from([
            (
                tx.clone(),
                tx_json_inputs(
                    &tx,
                    vec![reserve_input(
                        &tracked_box,
                        &"c0".repeat(32),
                        &[(TEST_RESERVE_NFT, 1)],
                    )],
                ),
            ),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&tx)),
        ]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(txs)).await);
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        insert_tracked_reserve(&state, &tracked_box, owner);

        let other_r6 = {
            let mut scan_box = c4_test_box();
            scan_box
                .additional_registers
                .insert("R6".to_string(), format!("0e20{}", "1b".repeat(32)));
            scan_box
        };
        let cases = [
            ("6a", vec![(TEST_RESERVE_NFT, 2)], c4_test_box()),
            (
                "6b",
                vec![(other_token.as_str(), 1), (TEST_RESERVE_NFT, 1)],
                c4_test_box(),
            ),
            ("6c", vec![(TEST_RESERVE_NFT, 1)], other_r6),
        ];
        for (id, assets, mut scan_box) in cases {
            let box_id = id.repeat(32);
            scan_box.box_id = box_id.clone();
            scan_box.transaction_id = tx.clone();
            scan_box.assets = assets
                .into_iter()
                .map(|(token_id, amount)| BoxAsset {
                    token_id: token_id.to_string(),
                    amount,
                })
                .collect();
            let tagged = TaggedScanBox {
                scan_box,
                kind: ReserveContractKind::Erg,
                contract_address: "test_p2s".to_string(),
            };
            assert_eq!(
                state.ingest_scan_box(&tagged).await,
                ScanBoxIngest::Rejected(box_id),
                "case {id}"
            );
        }
        assert_eq!(
            state
                .reserve_tracker
                .resolve_issuer_reserve(owner, &crate::DenomKey::Erg)
                .unwrap()
                .box_id,
            tracked_box
        );
    }

    /// Round 6b: a token reserve (reserve NFT at tokens(0), collateral token at
    /// tokens(1)) is followed by its NFT through a redemption; a sibling with
    /// the collateral token but a fresh NFT is not.
    #[tokio::test]
    async fn test_token_reserve_successor_is_followed_by_its_nft() {
        let tracked_box = "11".repeat(32);
        let tx = "bb".repeat(32);
        let token = "54".repeat(32);
        let txs = HashMap::from([
            (
                tx.clone(),
                tx_json_inputs(
                    &tx,
                    vec![
                        plain_input(
                            &"a1".repeat(32),
                            "attacker_address",
                            &"a2".repeat(32),
                            "0008cd03",
                        ),
                        reserve_input(
                            &tracked_box,
                            &"c0".repeat(32),
                            &[(TEST_RESERVE_NFT, 1), (token.as_str(), 500)],
                        ),
                    ],
                ),
            ),
            tracked_box_route(
                &tracked_box,
                &[(TEST_RESERVE_NFT, 1), (token.as_str(), 500)],
                Some(&tx),
            ),
        ]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(txs)).await);
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let info = ExtendedReserveInfo {
            base_info: crate::ReserveInfo {
                collateral_amount: 500,
                last_updated_height: 0,
                contract_address: "test_p2s".to_string(),
                tracker_nft_id: TEST_TRACKER_NFT.to_string(),
                refund_initiation_height: 0,
                reserve_token_id: token.clone(),
            },
            total_debt: 0,
            box_id: tracked_box.clone(),
            owner_pubkey: owner.to_string(),
            last_updated_timestamp: 0,
        };
        state.reserve_tracker.update_reserve(info).unwrap();

        let scan = |box_id: &str, assets: Vec<(&str, u64)>| {
            let mut scan_box = c4_test_box();
            scan_box.box_id = box_id.to_string();
            scan_box.transaction_id = tx.clone();
            // A redemption leaves a non-empty tree.
            scan_box.additional_registers.insert(
                "R5".to_string(),
                "64aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa032000"
                    .to_string(),
            );
            scan_box.assets = assets
                .into_iter()
                .map(|(token_id, amount)| BoxAsset {
                    token_id: token_id.to_string(),
                    amount,
                })
                .collect();
            TaggedScanBox {
                scan_box,
                kind: ReserveContractKind::Token,
                contract_address: "test_p2s".to_string(),
            }
        };
        let sibling = "22".repeat(32);
        let fresh_nft = "a1".repeat(32);
        assert_eq!(
            state
                .ingest_scan_box(&scan(
                    &sibling,
                    vec![(fresh_nft.as_str(), 1), (token.as_str(), 1)]
                ))
                .await,
            ScanBoxIngest::Rejected(sibling)
        );
        let redeemed = "55".repeat(32);
        assert_eq!(
            state
                .ingest_scan_box(&scan(
                    &redeemed,
                    vec![(TEST_RESERVE_NFT, 1), (token.as_str(), 400)]
                ))
                .await,
            ScanBoxIngest::Tracked(redeemed.clone())
        );
        let followed = state.reserve_tracker.get_reserve(&redeemed).unwrap();
        assert_eq!(followed.base_info.collateral_amount, 400);
    }

    /// The node gave a transaction's inputs without their assets: no verdict
    /// (a wrong "no" would quarantine the reserve for good), retried next cycle.
    #[tokio::test]
    async fn test_lineage_without_input_assets_is_retried() {
        let tracked_box = "11".repeat(32);
        let tx = "bb".repeat(32);
        let mut input = reserve_input(&tracked_box, &"c0".repeat(32), &[(TEST_RESERVE_NFT, 1)]);
        input.as_object_mut().unwrap().remove("assets");
        // The tracked box was spent by another transaction (so the walk is
        // needed), and the NFT is no singleton (so only the walk can tell).
        let txs = HashMap::from([
            (tx.clone(), tx_json_inputs(&tx, vec![input])),
            tracked_box_route(
                &tracked_box,
                &[(TEST_RESERVE_NFT, 1)],
                Some(&"99".repeat(32)),
            ),
            token_route(TEST_RESERVE_NFT, 2),
        ]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(txs)).await);
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        insert_tracked_reserve(&state, &tracked_box, owner);
        let mut scan_box = c4_test_box();
        scan_box.box_id = "55".repeat(32);
        scan_box.transaction_id = tx;
        let tagged = TaggedScanBox {
            scan_box,
            kind: ReserveContractKind::Erg,
            contract_address: "test_p2s".to_string(),
        };
        assert_eq!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Pending(owner.to_string(), crate::DenomKey::Erg)
        );
    }

    fn tagged_erg(scan_box: ScanBox) -> TaggedScanBox {
        TaggedScanBox {
            scan_box,
            kind: ReserveContractKind::Erg,
            contract_address: "test_p2s".to_string(),
        }
    }

    fn chain_box_id(k: usize) -> String {
        format!("{:064x}", 0x1000 + k)
    }

    fn chain_tx_id(k: usize) -> String {
        format!("{:064x}", 0x2000 + k)
    }

    /// A reserve that moved `n` times since the tracker last saw it: box 0 (the
    /// tracked box) is spent by tx 0, which creates box 1, and so on; box `n`
    /// (created by tx `n - 1`) is scanned now. Returns the node routes, the
    /// tracked box id and the scanned box.
    fn reserve_chain(n: usize) -> (HashMap<String, String>, String, ScanBox) {
        let mut routes = HashMap::new();
        for k in 0..n {
            let created_by = if k == 0 {
                "c0".repeat(32)
            } else {
                chain_tx_id(k - 1)
            };
            routes.insert(
                chain_tx_id(k),
                tx_json_inputs(
                    &chain_tx_id(k),
                    vec![reserve_input(
                        &chain_box_id(k),
                        &created_by,
                        &[(TEST_RESERVE_NFT, 1)],
                    )],
                ),
            );
        }
        routes.extend([tracked_box_route(
            &chain_box_id(0),
            &[(TEST_RESERVE_NFT, 1)],
            Some(&chain_tx_id(0)),
        )]);
        let mut tip = c4_test_box();
        tip.box_id = chain_box_id(n);
        tip.transaction_id = chain_tx_id(n - 1);
        (routes, chain_box_id(0), tip)
    }

    /// Round 6c (P1-1): nine top-ups between two scans (one block is enough)
    /// ran past the old depth of 8 and quarantined the reserve for good.
    #[tokio::test]
    async fn test_successor_ten_generations_later_is_followed() {
        let (mut routes, tracked, tip) = reserve_chain(10);
        // Not a singleton: only the walk can tell.
        routes.extend([token_route(TEST_RESERVE_NFT, 2)]);
        let state =
            mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(routes)).await);
        insert_tracked_reserve(&state, &tracked, &VALID_PREFIXED_PUBKEY[2..]);
        let tip_id = tip.box_id.clone();
        assert_eq!(
            state.ingest_scan_box(&tagged_erg(tip)).await,
            ScanBoxIngest::Tracked(tip_id)
        );
    }

    /// Round 6c (P1-1): past `LINEAGE_WALK_DEPTH` the walk gives no verdict:
    /// retried (never quarantined) when the NFT is no singleton, followed when
    /// it is one.
    #[tokio::test]
    async fn test_walk_out_of_depth_is_retried_or_decided_by_a_singleton() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        for singleton in [false, true] {
            let (mut routes, tracked, tip) = reserve_chain(LINEAGE_WALK_DEPTH + 2);
            if !singleton {
                routes.extend([token_route(TEST_RESERVE_NFT, 2)]);
            }
            let state =
                mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(routes)).await);
            insert_tracked_reserve(&state, &tracked, owner);
            let tip_id = tip.box_id.clone();
            let expected = if singleton {
                ScanBoxIngest::Tracked(tip_id.clone())
            } else {
                ScanBoxIngest::Pending(owner.to_string(), crate::DenomKey::Erg)
            };
            assert_eq!(state.ingest_scan_box(&tagged_erg(tip)).await, expected);
            assert!(state
                .reserve_storage
                .get_quarantined(&tip_id)
                .unwrap()
                .is_none());
        }
    }

    /// A transaction whose `byId` JSON is over the body cap.
    fn fat_tx_body() -> String {
        format!(
            "{{\"id\":\"fat\",\"inputs\":[],\"pad\":\"{}\"}}",
            "0".repeat(crate::http::MAX_BODY_BYTES + 16)
        )
    }

    /// Round 6c (P1-2): a sibling P made by a transaction over the 2 MiB body
    /// cap. P holds no tracked NFT, so it is quarantined at once (no walk, no
    /// pending); the top-up G' made by that same transaction is the tracked
    /// box's spender's output and is followed without reading it.
    #[tokio::test]
    async fn test_fat_transaction_does_not_strand_the_reserve() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let fat_tx = "fa".repeat(32);
        let topped_up = "55".repeat(32);
        let sibling = "22".repeat(32);
        let routes = HashMap::from([
            (fat_tx.clone(), fat_tx_body()),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&fat_tx)),
        ]);
        let scanned = serde_json::json!([
            scanned_box_json(
                &sibling,
                &fat_tx,
                1_000_000,
                &[("a1".repeat(32).as_str(), 1)],
                None
            ),
            scanned_box_json(
                &topped_up,
                &fat_tx,
                1_100_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None
            ),
        ]);
        let state =
            mock_state(spawn_mock_node(scanned.to_string(), std::sync::Arc::new(routes)).await);
        insert_tracked_reserve(&state, &tracked_box, owner);
        state.process_scan_boxes().await.unwrap();
        let tracked: Vec<String> = state
            .reserve_tracker
            .get_reserves_by_owner(owner)
            .into_iter()
            .map(|r| r.box_id)
            .collect();
        assert_eq!(tracked, vec![topped_up]);
        assert!(state
            .reserve_storage
            .get_quarantined(&sibling)
            .unwrap()
            .is_some());

        // Two generations, the later transaction fat: the walk cannot read it,
        // and the singleton NFT decides.
        let (mut routes, tracked, tip) = reserve_chain(2);
        routes.insert(chain_tx_id(1), fat_tx_body());
        let state =
            mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(routes)).await);
        insert_tracked_reserve(&state, &tracked, owner);
        let tip_id = tip.box_id.clone();
        assert_eq!(
            state.ingest_scan_box(&tagged_erg(tip)).await,
            ScanBoxIngest::Tracked(tip_id)
        );
    }

    /// Round 6c (P1-2): a candidate whose check stays pending never keeps the
    /// spent tracked box next to the successor holding its NFT. Q holds the
    /// NFT too (no singleton) and is made by a transaction the node cannot
    /// give; G' is the direct successor. In either scan order the owner ends
    /// with G' alone.
    #[tokio::test]
    async fn test_pending_check_never_keeps_a_spent_box_next_to_its_successor() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let top_up_tx = "bb".repeat(32);
        let topped_up = "55".repeat(32);
        let other = "66".repeat(32);
        for other_first in [true, false] {
            let routes = HashMap::from([
                tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&top_up_tx)),
                token_route(TEST_RESERVE_NFT, 2),
                // No singleton: the top-up transaction is read.
                (
                    top_up_tx.clone(),
                    tx_json_inputs(
                        &top_up_tx,
                        vec![reserve_input(
                            &tracked_box,
                            &"c0".repeat(32),
                            &[(TEST_RESERVE_NFT, 1)],
                        )],
                    ),
                ),
            ]);
            let genuine = scanned_box_json(
                &topped_up,
                &top_up_tx,
                1_100_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None,
            );
            let pending = scanned_box_json(
                &other,
                &"cd".repeat(32),
                1_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None,
            );
            let scanned = if other_first {
                serde_json::json!([pending, genuine])
            } else {
                serde_json::json!([genuine, pending])
            };
            let state =
                mock_state(spawn_mock_node(scanned.to_string(), std::sync::Arc::new(routes)).await);
            insert_tracked_reserve(&state, &tracked_box, owner);
            state.process_scan_boxes().await.unwrap();
            let tracked: Vec<String> = state
                .reserve_tracker
                .get_reserves_by_owner(owner)
                .into_iter()
                .map(|r| r.box_id)
                .collect();
            assert_eq!(
                tracked,
                vec![topped_up.clone()],
                "other first {other_first}"
            );
            assert!(state
                .reserve_storage
                .get_quarantined(&other)
                .unwrap()
                .is_none());
        }
    }

    /// Round 6c (P2-2): a root whose NFT the token index does not give an
    /// emission of 1 is never tracked.
    #[tokio::test]
    async fn test_admission_quarantines_root_with_non_singleton_nft() {
        let routes = HashMap::from([token_route(TEST_RESERVE_NFT, 2)]);
        let state =
            mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(routes)).await);
        let scan_box = c4_test_box();
        let info = state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .unwrap();
        match state.admit_reserve_box(&scan_box, &info, "test_p2s").await {
            ReserveAdmission::Quarantined { reason } => {
                assert!(
                    reason.contains("emission is not 1"),
                    "unexpected reason: {}",
                    reason
                );
            }
            other => panic!("expected Quarantined, got {:?}", other),
        }
    }

    /// Round 6c (P2-2): the carrier is the input that holds the NFT as a
    /// reserve box does, not the first input holding the token. A wallet box
    /// with the token comes first in the transaction; the reserve box after it
    /// was made by the transaction that spent the tracked box.
    #[tokio::test]
    async fn test_carrier_is_the_reserve_input_not_the_first_holder() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let first_tx = "b1".repeat(32);
        let second_tx = "b2".repeat(32);
        let middle = "66".repeat(32);
        let routes = HashMap::from([
            (
                second_tx.clone(),
                tx_json_inputs(
                    &second_tx,
                    vec![
                        {
                            let mut wallet = plain_input(
                                &"a1".repeat(32),
                                "wallet_address",
                                &"a2".repeat(32),
                                "0008cd03",
                            );
                            wallet["assets"] =
                                serde_json::json!([{ "tokenId": TEST_RESERVE_NFT, "amount": 1 }]);
                            wallet
                        },
                        reserve_input(&middle, &first_tx, &[(TEST_RESERVE_NFT, 1)]),
                    ],
                ),
            ),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&first_tx)),
            token_route(TEST_RESERVE_NFT, 2),
        ]);
        let state =
            mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(routes)).await);
        insert_tracked_reserve(&state, &tracked_box, owner);
        let mut tip = c4_test_box();
        tip.box_id = "77".repeat(32);
        tip.transaction_id = second_tx;
        assert_eq!(
            state.ingest_scan_box(&tagged_erg(tip)).await,
            ScanBoxIngest::Tracked("77".repeat(32))
        );
    }

    /// Round 6c (a): a fresh reserve R is topped up by someone else (who also
    /// adds a sibling P) before the scanner first sees it. R' descends by its
    /// NFT from R, whose creating transaction has the owner's P2PK input:
    /// tracked. P is not. A reserve box on the way with a non-empty tree (a
    /// redemption happened) does not lead back to a root.
    #[tokio::test]
    async fn test_root_topped_up_before_first_scan_is_admitted() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let root_tx = "b0".repeat(32);
        let top_up_tx = "b1".repeat(32);
        let root = "10".repeat(32);
        let topped_up = "55".repeat(32);
        let sibling = "22".repeat(32);
        for redeemed_on_the_way in [false, true] {
            for sibling_first in [true, false] {
                let mut root_input = reserve_input(&root, &root_tx, &[(TEST_RESERVE_NFT, 1)]);
                if redeemed_on_the_way {
                    root_input["additionalRegisters"]["R5"] = serde_json::json!(
                        "64aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa032000"
                    );
                }
                let routes = HashMap::from([
                    (
                        root_tx.clone(),
                        tx_json(
                            &root_tx,
                            &[(
                                &"33".repeat(32),
                                "owner_address",
                                &"44".repeat(32),
                                &p2pk_ergo_tree(owner),
                            )],
                        ),
                    ),
                    (
                        top_up_tx.clone(),
                        tx_json_inputs(
                            &top_up_tx,
                            vec![
                                plain_input(
                                    &"a1".repeat(32),
                                    "attacker_address",
                                    &"a2".repeat(32),
                                    "0008cd03",
                                ),
                                root_input,
                            ],
                        ),
                    ),
                ]);
                let genuine = scanned_box_json(
                    &topped_up,
                    &top_up_tx,
                    1_100_000_000,
                    &[(TEST_RESERVE_NFT, 1)],
                    None,
                );
                let fake = scanned_box_json(
                    &sibling,
                    &top_up_tx,
                    1_000_000,
                    &[("a1".repeat(32).as_str(), 1)],
                    None,
                );
                let scanned = if sibling_first {
                    serde_json::json!([fake, genuine])
                } else {
                    serde_json::json!([genuine, fake])
                };
                let state = mock_state(
                    spawn_mock_node(scanned.to_string(), std::sync::Arc::new(routes)).await,
                );
                state.process_scan_boxes().await.unwrap();
                let case = format!("redeemed {redeemed_on_the_way}, sibling first {sibling_first}");
                let tracked: Vec<String> = state
                    .reserve_tracker
                    .get_reserves_by_owner(owner)
                    .into_iter()
                    .map(|r| r.box_id)
                    .collect();
                if redeemed_on_the_way {
                    assert!(tracked.is_empty(), "{case}: {tracked:?}");
                    assert!(
                        state
                            .reserve_storage
                            .get_quarantined(&topped_up)
                            .unwrap()
                            .is_some(),
                        "{case}"
                    );
                } else {
                    assert_eq!(tracked, vec![topped_up.clone()], "{case}");
                }
                assert!(
                    state
                        .reserve_storage
                        .get_quarantined(&sibling)
                        .unwrap()
                        .is_some(),
                    "{case}"
                );
            }
        }
    }

    /// Round 6c (b): the only tracked reserve is withdrawn (refund completion,
    /// no successor). The scan then lists no valid box, which used to skip
    /// removal for good, so the owner's next reserve was quarantined as a
    /// newcomer. Now a reserve absent from such a scan is removed when the
    /// chain shows it spent, and kept when it does not.
    #[tokio::test]
    async fn test_last_reserve_spent_without_successor_is_removed() {
        // Round 6d (P2-3): and only once the spend is SPENT_REMOVAL_DEPTH deep.
        // Round 6e: the spend height is the spending transaction's
        // `inclusionHeight`, read from the start of its body (so also over the
        // body cap); the height now is the index height, else `/info`.
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let deep_at = TEST_SPENT_AT + SPENT_REMOVAL_DEPTH - 1;
        let fat_spend = |tx_id: &str| {
            format!(
                "{{\"id\":\"{tx_id}\",\"inclusionHeight\":{TEST_SPENT_AT},\"inputs\":[],\"pad\":\"{}\"}}",
                "0".repeat(crate::http::MAX_BODY_BYTES + 16)
            )
        };
        for (spent, height, fat, indexed, removed) in [
            (false, deep_at + 100, false, false, false),
            (true, deep_at - 1, false, false, false),
            (true, deep_at, false, false, true),
            (true, deep_at, true, false, true),
            (true, deep_at - 1, false, true, false),
            (true, deep_at, false, true, true),
        ] {
            let spent_by = "cc".repeat(32);
            let routes = HashMap::from([
                tracked_box_route(
                    &tracked_box,
                    &[(TEST_RESERVE_NFT, 1)],
                    spent.then_some(spent_by.as_str()),
                ),
                if fat {
                    (spent_by.clone(), fat_spend(&spent_by))
                } else {
                    spend_tx_route(&spent_by)
                },
                if indexed {
                    indexed_route(height, height + 1)
                } else {
                    info_route(height)
                },
            ]);
            let state =
                mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(routes)).await);
            insert_tracked_reserve(&state, &tracked_box, owner);
            state.process_scan_boxes().await.unwrap();
            let case = format!("spent {spent}, height {height}, fat {fat}, indexed {indexed}");
            assert_eq!(
                state.reserve_tracker.get_reserve(&tracked_box).is_ok(),
                !removed,
                "{case}"
            );
            assert_eq!(
                state
                    .reserve_storage
                    .get_reserve(&tracked_box)
                    .unwrap()
                    .is_some(),
                !removed,
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn reserve_scanner_loop_stops_on_shutdown() {
        // Nothing listens on port 1: each cycle fails at once and the loop waits 10 s to retry.
        let state = c4_test_state(NodeConfig {
            node_url: "http://127.0.0.1:1".to_string(),
            ..Default::default()
        });
        let (stop_tx, stop_rx) = tokio::sync::broadcast::channel::<()>(1);
        let scanner = start_scanner(state, stop_rx).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop_tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), scanner)
            .await
            .expect("the scanner stops at its wait instead of sleeping on");
        assert!(matches!(result, Ok(Ok(()))), "{result:?}");
    }

    /// A valid compressed public key (hex) for owner number `i`.
    fn test_owner_key(i: usize) -> String {
        let secp = secp256k1::Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[24..].copy_from_slice(&(i as u64 + 1_000).to_be_bytes());
        let secret = secp256k1::SecretKey::from_slice(&secret).unwrap();
        hex::encode(secp256k1::PublicKey::from_secret_key(&secp, &secret).serialize())
    }

    /// R7 = 1000 (a pending refund), as a Long constant.
    const R7_REFUND_1000: &str = "05d00f";

    /// Round 6d (P1): one transaction over the 2 MiB body cap spends the
    /// tracked box T into its successor S and 512 junk reserve boxes, each with
    /// its own singleton NFT and another R4, all listed before S. S is followed
    /// and T removed; no junk box is tracked or quarantined; the transaction is
    /// read once per cycle; the root checks stop at the cap, and the next cycle
    /// checks the junk boxes not checked yet.
    #[tokio::test]
    async fn test_junk_roots_never_starve_the_successor() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let successor = "55".repeat(32);
        let fat_tx = "fa".repeat(32);
        let mut scanned: Vec<serde_json::Value> = (0..512)
            .map(|i| {
                let nft = format!("{:064x}", 0x7000 + i);
                let mut junk = scanned_box_json(
                    &format!("{:064x}", 0x9000 + i),
                    &fat_tx,
                    1_000_000_000,
                    &[(nft.as_str(), 1)],
                    None,
                );
                junk["additionalRegisters"]["R4"] =
                    serde_json::Value::from(format!("07{}", test_owner_key(i)));
                junk
            })
            .collect();
        scanned.push(scanned_box_json(
            &successor,
            &fat_tx,
            1_100_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None,
        ));
        let routes = HashMap::from([
            (fat_tx.clone(), fat_tx_body()),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&fat_tx)),
        ]);
        let (addr, hits) = spawn_counting_mock_node(
            serde_json::Value::from(scanned).to_string(),
            std::sync::Arc::new(routes),
        )
        .await;
        let state = mock_state(addr);
        insert_tracked_reserve(&state, &tracked_box, owner);
        let fat_path = format!("/blockchain/transaction/byId/{fat_tx}");

        for cycle in 1..=2 {
            state.process_scan_boxes().await.unwrap();
            assert!(
                state.reserve_tracker.get_reserve(&successor).is_ok(),
                "cycle {cycle}"
            );
            assert!(state.reserve_tracker.get_reserve(&tracked_box).is_err());
            assert_eq!(state.reserve_tracker.get_all_reserves().len(), 1);
            assert!(state
                .reserve_storage
                .get_all_quarantined()
                .unwrap()
                .is_empty());
            assert_eq!(
                hits.lock().unwrap()[&fat_path],
                cycle,
                "read once per cycle"
            );
            assert_eq!(
                state.nft_cache().root_checked.len(),
                cycle * MAX_ROOT_CHECKS_PER_CYCLE,
                "never-checked roots first"
            );
            assert!(state.cycle_state().requests <= LINEAGE_REQUESTS_PER_CYCLE);
        }
    }

    /// Round 6d (P2-1): a reorg dropped the transaction that made the tracked
    /// successor S (the index no longer knows S), and T was spent again into
    /// S2. A box holding the singleton NFT follows S, and S is removed; with a
    /// NFT that is not a singleton the check stays pending and S is kept.
    /// Round 6e: when the index shows S unspent, S2 follows S only when it was
    /// made from S (the index lags); otherwise it may be an earlier box, and
    /// the check stays pending.
    #[tokio::test]
    async fn test_successor_dropped_by_a_reorg_is_replaced_by_the_singleton_holder() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let phantom = "51".repeat(32);
        let respent = "52".repeat(32);
        let respend_tx = "e2".repeat(32);
        for (index_shows, singleton, made_from_s, followed) in [
            ("unknown", true, false, true),
            ("unknown", false, false, false),
            ("unspent", true, false, false),
            ("unspent", false, false, false),
            ("unspent", true, true, true),
            ("unspent", false, true, true),
        ] {
            let mut routes =
                HashMap::from([token_route(TEST_RESERVE_NFT, if singleton { 1 } else { 2 })]);
            if index_shows == "unspent" {
                routes.extend([tracked_box_route(&phantom, &[(TEST_RESERVE_NFT, 1)], None)]);
            }
            if made_from_s {
                routes.insert(
                    respend_tx.clone(),
                    tx_json_inputs(
                        &respend_tx,
                        vec![reserve_input(&phantom, "c0c0", &[(TEST_RESERVE_NFT, 1)])],
                    ),
                );
            }
            let scanned = serde_json::json!([scanned_box_json(
                &respent,
                &respend_tx,
                1_000_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None
            )]);
            let state =
                mock_state(spawn_mock_node(scanned.to_string(), std::sync::Arc::new(routes)).await);
            insert_tracked_reserve(&state, &phantom, owner);
            state.remember_nft(&phantom, Some(TEST_RESERVE_NFT.to_string()));
            state.process_scan_boxes().await.unwrap();
            let case = format!(
                "index shows S {index_shows}, singleton {singleton}, made from S {made_from_s}"
            );
            assert_eq!(
                state.reserve_tracker.get_reserve(&respent).is_ok(),
                followed,
                "{case}"
            );
            assert_eq!(
                state.reserve_tracker.get_reserve(&phantom).is_ok(),
                !followed,
                "{case}"
            );
            assert!(
                state
                    .reserve_storage
                    .get_all_quarantined()
                    .unwrap()
                    .is_empty(),
                "{case}"
            );
        }
    }

    /// Round 6d (P2-2): the tracked box T has a pending refund (R7 = 1000).
    /// The owner completes it into a box R holding the same NFT with R7 = 0,
    /// directly or after a top-up. R is judged as a root: with R5 already
    /// filled it is quarantined (C4); a clean R is admitted, the refund
    /// completion being the owner's.
    #[tokio::test]
    async fn test_refund_completion_with_the_same_nft_is_judged_as_a_root() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let topped_up = "12".repeat(32);
        let recreated = "13".repeat(32);
        let spend_tx = "e1".repeat(32);
        let complete_tx = "e3".repeat(32);
        let pending_refund = |box_id: &str, creating_tx: &str| {
            let mut input = reserve_input(box_id, creating_tx, &[(TEST_RESERVE_NFT, 1)]);
            input["additionalRegisters"]["R7"] = serde_json::Value::from(R7_REFUND_1000);
            input
        };
        for (after_top_up, prefilled_r5) in
            [(false, true), (false, false), (true, true), (true, false)]
        {
            let (last, last_tx) = if after_top_up {
                (pending_refund(&topped_up, &spend_tx), complete_tx.clone())
            } else {
                (pending_refund(&tracked_box, "c0c0"), spend_tx.clone())
            };
            let routes = HashMap::from([
                tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&spend_tx)),
                (last_tx.clone(), tx_json_inputs(&last_tx, vec![last])),
            ]);
            let mut box_r = scanned_box_json(
                &recreated,
                &last_tx,
                1_000_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                Some("0500"),
            );
            if prefilled_r5 {
                box_r["additionalRegisters"]["R5"] =
                    serde_json::Value::from(format!("64{}032000", "77".repeat(33)));
            }
            let state = mock_state(
                spawn_mock_node(
                    serde_json::json!([box_r]).to_string(),
                    std::sync::Arc::new(routes),
                )
                .await,
            );
            insert_tracked_reserve(&state, &tracked_box, owner);
            let mut info = state.reserve_tracker.get_reserve(&tracked_box).unwrap();
            info.base_info.refund_initiation_height = 1000;
            state.reserve_tracker.update_reserve(info).unwrap();
            state.process_scan_boxes().await.unwrap();
            let case = format!("after a top-up {after_top_up}, R5 filled {prefilled_r5}");
            assert_eq!(
                state.reserve_tracker.get_reserve(&recreated).is_ok(),
                !prefilled_r5,
                "{case}"
            );
            let quarantined = state.reserve_storage.get_quarantined(&recreated).unwrap();
            assert_eq!(quarantined.is_some(), prefilled_r5, "{case}");
            if let Some(record) = quarantined {
                assert!(
                    record.reason.contains("non-empty AVL tree"),
                    "{case}: {}",
                    record.reason
                );
            }
        }
    }

    /// Round 6d (P2-3): the successor S of T was tracked and T removed; a reorg
    /// drops S, and T is unspent again. T is restored as the tracked box (its
    /// NFT is not a singleton, so no lineage check could take it back), and S
    /// is removed.
    #[tokio::test]
    async fn test_a_removed_box_a_reorg_brings_back_is_restored() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let successor = "55".repeat(32);
        let spend_tx = "e1".repeat(32);
        let routes = HashMap::from([
            token_route(TEST_RESERVE_NFT, 2),
            (
                spend_tx.clone(),
                tx_json_inputs(
                    &spend_tx,
                    vec![reserve_input(
                        &tracked_box,
                        "c0c0",
                        &[(TEST_RESERVE_NFT, 1)],
                    )],
                ),
            ),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&spend_tx)),
        ]);
        let before = serde_json::json!([scanned_box_json(
            &successor,
            &spend_tx,
            1_100_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None
        )]);
        let after = serde_json::json!([scanned_box_json(
            &tracked_box,
            "c0c0",
            1_000_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None
        )]);
        let routes = std::sync::Arc::new(routes);
        let state = mock_state(spawn_mock_node(before.to_string(), routes.clone()).await);
        insert_tracked_reserve(&state, &tracked_box, owner);
        state.process_scan_boxes().await.unwrap();
        assert!(state.reserve_tracker.get_reserve(&successor).is_ok());
        assert!(state.reserve_tracker.get_reserve(&tracked_box).is_err());

        // The reorg: the scan shows T again, S is gone.
        let mut config = state.config.clone();
        config.node_url = format!(
            "http://{}",
            spawn_mock_node(after.to_string(), routes).await
        );
        let state = ServerState { config, ..state };
        state.process_scan_boxes().await.unwrap();
        assert!(state.reserve_tracker.get_reserve(&tracked_box).is_ok());
        assert!(state
            .reserve_storage
            .get_reserve(&tracked_box)
            .unwrap()
            .is_some());
        assert!(state.reserve_tracker.get_reserve(&successor).is_err());
        assert!(state
            .reserve_storage
            .get_all_quarantined()
            .unwrap()
            .is_empty());
    }

    /// Round 6d (LOW): with a NFT that is not a singleton the direct-spend
    /// shortcut is not taken: a box made by the transaction that spent T is
    /// followed only when that transaction is read and spends T; when it
    /// cannot be read the check stays pending and T is kept.
    #[tokio::test]
    async fn test_shortcut_only_for_a_singleton_nft() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let candidate = "55".repeat(32);
        let spend_tx = "e1".repeat(32);
        for (singleton, tx_readable, followed) in [
            (true, false, true),
            (false, false, false),
            (false, true, true),
        ] {
            let mut routes = HashMap::from([
                token_route(TEST_RESERVE_NFT, if singleton { 1 } else { 2 }),
                tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&spend_tx)),
            ]);
            if tx_readable {
                routes.insert(
                    spend_tx.clone(),
                    tx_json_inputs(
                        &spend_tx,
                        vec![reserve_input(
                            &tracked_box,
                            "c0c0",
                            &[(TEST_RESERVE_NFT, 1)],
                        )],
                    ),
                );
            }
            let scanned = serde_json::json!([scanned_box_json(
                &candidate,
                &spend_tx,
                1_100_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None
            )]);
            let (addr, hits) =
                spawn_counting_mock_node(scanned.to_string(), std::sync::Arc::new(routes)).await;
            let state = mock_state(addr);
            insert_tracked_reserve(&state, &tracked_box, owner);
            state.process_scan_boxes().await.unwrap();
            let case = format!("singleton {singleton}, transaction readable {tx_readable}");
            assert_eq!(
                state.reserve_tracker.get_reserve(&candidate).is_ok(),
                followed,
                "{case}"
            );
            assert_eq!(
                state.reserve_tracker.get_reserve(&tracked_box).is_ok(),
                !followed,
                "{case}"
            );
            let reads = hits
                .lock()
                .unwrap()
                .get(&format!("/blockchain/transaction/byId/{spend_tx}"))
                .copied()
                .unwrap_or(0);
            assert_eq!(reads, usize::from(!singleton), "{case}");
        }
    }

    /// Round 6d (LOW): the owner withdrew the tracked reserve T and made a new
    /// reserve R2 (another NFT) in the same scan window. R2 is not quarantined
    /// for good next to a spent T: it waits, T is removed once its spend is
    /// deep enough, and R2 is then admitted as a root.
    #[tokio::test]
    async fn test_new_reserve_in_the_window_of_a_withdrawal_waits_for_the_root_check() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let new_box = "66".repeat(32);
        let withdraw_tx = "e1".repeat(32);
        let create_tx = "e6".repeat(32);
        let new_nft = "67".repeat(32);
        let routes = HashMap::from([
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&withdraw_tx)),
            spend_tx_route(&withdraw_tx),
            info_route(TEST_SPENT_AT + 50),
            (
                create_tx.clone(),
                tx_json_inputs(
                    &create_tx,
                    vec![plain_input(
                        &"68".repeat(32),
                        "owner_wallet",
                        "c1c1",
                        &p2pk_ergo_tree(owner),
                    )],
                ),
            ),
        ]);
        let scanned = serde_json::json!([scanned_box_json(
            &new_box,
            &create_tx,
            1_000_000_000,
            &[(new_nft.as_str(), 1)],
            None
        )]);
        let state =
            mock_state(spawn_mock_node(scanned.to_string(), std::sync::Arc::new(routes)).await);
        insert_tracked_reserve(&state, &tracked_box, owner);

        state.process_scan_boxes().await.unwrap();
        assert!(state
            .reserve_storage
            .get_quarantined(&new_box)
            .unwrap()
            .is_none());
        assert!(state.reserve_tracker.get_reserve(&tracked_box).is_err());
        assert!(state.reserve_tracker.get_reserve(&new_box).is_err());

        state.process_scan_boxes().await.unwrap();
        assert!(state.reserve_tracker.get_reserve(&new_box).is_ok());
        assert!(state
            .reserve_storage
            .get_all_quarantined()
            .unwrap()
            .is_empty());
    }

    /// The state of `state` on another mock node (the chain moved on).
    async fn on_node(
        state: ServerState,
        boxes_body: String,
        routes: HashMap<String, String>,
    ) -> (ServerState, Hits) {
        let (addr, hits) = spawn_counting_mock_node(boxes_body, std::sync::Arc::new(routes)).await;
        let mut config = state.config.clone();
        config.node_url = format!("http://{}", addr);
        (ServerState { config, ..state }, hits)
    }

    /// A non-empty R5 (a reserve that has paid redemptions).
    fn used_tree_register() -> String {
        format!("64{}032000", "77".repeat(33))
    }

    /// Round 6e (P1): the scan misses both the tracked box T and its successor
    /// X (a page race: T pushed past page 0 by junk, then topped up between two
    /// page reads), while another reserve U is listed. T is not removed unless
    /// the index shows it spent at least 10 blocks deep. Next cycle X is listed
    /// (with a used R5): it is followed, from T or, once T was removed, from
    /// the removed T; never judged as a root and quarantined.
    #[tokio::test]
    async fn test_a_scan_missing_the_tracked_box_never_strands_the_reserve() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let other_owner = test_owner_key(7);
        let tracked_box = "11".repeat(32);
        let other_box = "21".repeat(32);
        let successor = "55".repeat(32);
        let top_up_tx = "e1".repeat(32);
        let mut other = scanned_box_json(
            &other_box,
            "c1c1",
            1_000_000_000,
            &[(&"2f".repeat(32), 1)],
            None,
        );
        other["additionalRegisters"]["R4"] = serde_json::Value::from(format!("07{other_owner}"));
        let mut x = scanned_box_json(
            &successor,
            &top_up_tx,
            1_100_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None,
        );
        x["additionalRegisters"]["R5"] = serde_json::Value::from(used_tree_register());
        for (index_shows, height, removed) in [
            ("unspent", TEST_SPENT_AT + 100, false),
            ("spent", TEST_SPENT_AT + 1, false),
            ("spent", TEST_SPENT_AT + SPENT_REMOVAL_DEPTH + 5, true),
        ] {
            let routes = HashMap::from([
                tracked_box_route(
                    &tracked_box,
                    &[(TEST_RESERVE_NFT, 1)],
                    (index_shows == "spent").then_some(top_up_tx.as_str()),
                ),
                spend_tx_route(&top_up_tx),
                indexed_route(height, height),
            ]);
            let state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
            insert_tracked_reserve(&state, &tracked_box, owner);
            insert_tracked_reserve(&state, &other_box, &other_owner);
            state.remember_nft(&tracked_box, Some(TEST_RESERVE_NFT.to_string()));
            state.remember_nft(&other_box, Some("2f".repeat(32)));

            let (state, _) = on_node(
                state,
                serde_json::json!([other.clone()]).to_string(),
                routes.clone(),
            )
            .await;
            state.process_scan_boxes().await.unwrap();
            let case = format!("index shows T {index_shows} at height {height}");
            assert!(
                state.reserve_tracker.get_reserve(&other_box).is_ok(),
                "{case}"
            );
            assert_eq!(
                state.reserve_tracker.get_reserve(&tracked_box).is_err(),
                removed,
                "{case}"
            );

            // Next cycle the scan lists X (the index shows T spent now).
            let mut routes = routes;
            routes.extend([tracked_box_route(
                &tracked_box,
                &[(TEST_RESERVE_NFT, 1)],
                Some(&top_up_tx),
            )]);
            let (state, _) = on_node(
                state,
                serde_json::json!([other.clone(), x.clone()]).to_string(),
                routes,
            )
            .await;
            state.process_scan_boxes().await.unwrap();
            assert!(
                state.reserve_tracker.get_reserve(&successor).is_ok(),
                "{case}"
            );
            assert!(
                state.reserve_tracker.get_reserve(&tracked_box).is_err(),
                "{case}"
            );
            assert!(
                state
                    .reserve_storage
                    .get_all_quarantined()
                    .unwrap()
                    .is_empty(),
                "{case}"
            );
        }
    }

    /// Round 6e (P1): a box made while the later pages were read lands on page
    /// 0, already read; page 0 is read again at the end, so the successor X of
    /// the tracked box T is seen in the same cycle.
    #[tokio::test]
    async fn test_page_zero_is_read_again_after_the_last_page() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let successor = "55".repeat(32);
        let top_up_tx = "e1".repeat(32);
        // A full page of boxes the scanner skips (no R4).
        let filler: Vec<serde_json::Value> = (0..RESERVE_BOX_PAGE_LIMIT)
            .map(|i| {
                let mut b = scanned_box_json(&format!("{:064x}", 0xa000 + i), "c1c1", 1, &[], None);
                b["additionalRegisters"] = serde_json::json!({});
                b
            })
            .collect();
        let mut later = vec![scanned_box_json(
            &successor,
            &top_up_tx,
            1_100_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None,
        )];
        later.extend(filler.iter().cloned());
        let routes = HashMap::from([
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&top_up_tx)),
            spend_tx_route(&top_up_tx),
            (
                SCAN_AFTER_FIRST_READ.to_string(),
                serde_json::Value::from(later).to_string(),
            ),
        ]);
        let (addr, hits) = spawn_counting_mock_node(
            serde_json::Value::from(filler).to_string(),
            std::sync::Arc::new(routes),
        )
        .await;
        let state = mock_state(addr);
        insert_tracked_reserve(&state, &tracked_box, owner);
        state.process_scan_boxes().await.unwrap();
        assert_eq!(hits.lock().unwrap()["/blockchain/box/unspent/byAddress"], 3);
        // Round 6f: the re-read lists page 0 again; each box once.
        let listed = state.get_scan_boxes().await.unwrap();
        let unique: std::collections::HashSet<&String> =
            listed.iter().map(|b| &b.scan_box.box_id).collect();
        assert_eq!(listed.len(), RESERVE_BOX_PAGE_LIMIT as usize + 1);
        assert_eq!(unique.len(), listed.len());
        assert!(state.reserve_tracker.get_reserve(&successor).is_ok());
        assert!(state.reserve_tracker.get_reserve(&tracked_box).is_err());
    }

    /// Round 6e (P2-1): fork A had the refund start T0 -> T1 (R7 = 1000), which
    /// the tracker followed; the reorg to fork B has a redemption T0 -> X
    /// (R7 = 0, a used R5). The index no longer knows T1, so its R7 says
    /// nothing: X leads back to T0, removed lately, and is followed. Without
    /// T0 remembered (a restart) the check stays pending: X is not quarantined.
    #[tokio::test]
    async fn test_a_reorg_dropping_a_refund_start_does_not_quarantine_the_reserve() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let t0 = "10".repeat(32);
        let t1 = "11".repeat(32);
        let x = "12".repeat(32);
        let init_tx = "e1".repeat(32);
        let redeem_tx = "e2".repeat(32);
        let t1_json = scanned_box_json(
            &t1,
            &init_tx,
            1_000_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            Some(R7_REFUND_1000),
        );
        let mut x_json =
            scanned_box_json(&x, &redeem_tx, 900_000_000, &[(TEST_RESERVE_NFT, 1)], None);
        x_json["additionalRegisters"]["R5"] = serde_json::Value::from(used_tree_register());
        let fork_b = HashMap::from([
            tracked_box_route(&t0, &[(TEST_RESERVE_NFT, 1)], Some(&redeem_tx)),
            (
                redeem_tx.clone(),
                tx_json_inputs(
                    &redeem_tx,
                    vec![reserve_input(&t0, "c0c0", &[(TEST_RESERVE_NFT, 1)])],
                ),
            ),
        ]);
        for remembered in [true, false] {
            let state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
            if remembered {
                // Fork A: T1 follows T0, and T0 is removed.
                insert_tracked_reserve(&state, &t0, owner);
                let (fork_a, _) = on_node(
                    state,
                    serde_json::json!([t1_json.clone()]).to_string(),
                    HashMap::from([tracked_box_route(
                        &t0,
                        &[(TEST_RESERVE_NFT, 1)],
                        Some(&init_tx),
                    )]),
                )
                .await;
                fork_a.process_scan_boxes().await.unwrap();
                assert!(fork_a.reserve_tracker.get_reserve(&t1).is_ok());
                assert!(fork_a.reserve_tracker.get_reserve(&t0).is_err());
                let (fork_b_state, _) = on_node(
                    fork_a,
                    serde_json::json!([x_json.clone()]).to_string(),
                    fork_b.clone(),
                )
                .await;
                fork_b_state.process_scan_boxes().await.unwrap();
                assert!(fork_b_state.reserve_tracker.get_reserve(&x).is_ok());
                assert!(fork_b_state.reserve_tracker.get_reserve(&t1).is_err());
                assert!(fork_b_state
                    .reserve_storage
                    .get_all_quarantined()
                    .unwrap()
                    .is_empty());
            } else {
                insert_tracked_reserve(&state, &t1, owner);
                let mut info = state.reserve_tracker.get_reserve(&t1).unwrap();
                info.base_info.refund_initiation_height = 1000;
                state.reserve_tracker.update_reserve(info).unwrap();
                state.remember_nft(&t1, Some(TEST_RESERVE_NFT.to_string()));
                let (fork_b_state, _) = on_node(
                    state,
                    serde_json::json!([x_json.clone()]).to_string(),
                    fork_b.clone(),
                )
                .await;
                fork_b_state.process_scan_boxes().await.unwrap();
                assert!(fork_b_state.reserve_tracker.get_reserve(&x).is_err());
                assert!(fork_b_state.reserve_tracker.get_reserve(&t1).is_ok());
                assert!(fork_b_state
                    .reserve_storage
                    .get_all_quarantined()
                    .unwrap()
                    .is_empty());
            }
        }
    }

    /// Round 6e (P2-1): with the blockchain index more than 2 blocks behind the
    /// node, a scan cycle is skipped: the box list is not read and nothing
    /// changes. Within 2 blocks the cycle runs.
    #[tokio::test]
    async fn test_a_lagging_index_skips_the_cycle() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let successor = "55".repeat(32);
        let top_up_tx = "e1".repeat(32);
        for (full, runs) in [(1_005, false), (1_002, true)] {
            let routes = HashMap::from([
                tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&top_up_tx)),
                spend_tx_route(&top_up_tx),
                indexed_route(1_000, full),
            ]);
            let scanned = serde_json::json!([scanned_box_json(
                &successor,
                &top_up_tx,
                1_100_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None
            )]);
            let (addr, hits) =
                spawn_counting_mock_node(scanned.to_string(), std::sync::Arc::new(routes)).await;
            let state = mock_state(addr);
            insert_tracked_reserve(&state, &tracked_box, owner);
            state.process_scan_boxes().await.unwrap();
            let scans = hits
                .lock()
                .unwrap()
                .get("/blockchain/box/unspent/byAddress")
                .copied()
                .unwrap_or(0);
            assert_eq!(scans, usize::from(runs), "full height {full}");
            assert_eq!(
                state.skipped_cycles(),
                u64::from(!runs),
                "full height {full}"
            );
            assert_eq!(state.reserve_tracker.get_reserve(&successor).is_ok(), runs);
            assert_eq!(
                state.reserve_tracker.get_reserve(&tracked_box).is_ok(),
                !runs
            );
        }
    }

    /// Round 8: the scene of the index-height tests. The tracked box T was spent
    /// by `top_up_tx`, which made its successor S; the scan lists S. A cycle
    /// that runs tracks S and removes T.
    fn index_height_scene(index_route: Option<(String, String)>) -> (HashMap<String, String>, String) {
        let tracked_box = "11".repeat(32);
        let top_up_tx = "e1".repeat(32);
        let mut routes = HashMap::from([
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&top_up_tx)),
            spend_tx_route(&top_up_tx),
        ]);
        routes.extend(index_route);
        let scanned = serde_json::json!([scanned_box_json(
            &"55".repeat(32),
            &top_up_tx,
            1_100_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None
        )]);
        (routes, scanned.to_string())
    }

    /// Round 8 (item 1): without a usable `GET /blockchain/indexedHeight`
    /// answer a cycle is a no-op: an HTTP error, a timeout, a body that is not
    /// JSON, a missing or non-numeric field, or an index above `fullHeight`.
    /// The box list is not read, nothing is tracked, removed or quarantined, no
    /// clock starts, and the skip is counted; the next cycle with a good answer
    /// runs as usual. An index at the largest height does not overflow.
    #[tokio::test]
    async fn test_no_usable_index_height_skips_the_cycle() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let successor = "55".repeat(32);
        let path = "/blockchain/indexedHeight".to_string();
        for (case, body) in [
            ("HTTP 500", "!500 {}".to_string()),
            ("HTTP 503", "!503 {\"error\":503}".to_string()),
            ("HTTP 404", "!404 {}".to_string()),
            ("timeout", MOCK_HANG.to_string()),
            ("not JSON", "<html>bad gateway</html>".to_string()),
            ("empty object", "{}".to_string()),
            ("no fullHeight", r#"{"indexedHeight":1000}"#.to_string()),
            ("no indexedHeight", r#"{"fullHeight":1000}"#.to_string()),
            (
                "heights as strings",
                r#"{"indexedHeight":"1000","fullHeight":"1000"}"#.to_string(),
            ),
            (
                "negative height",
                r#"{"indexedHeight":-1,"fullHeight":1000}"#.to_string(),
            ),
            (
                "index above fullHeight",
                r#"{"indexedHeight":1001,"fullHeight":1000}"#.to_string(),
            ),
            (
                "index far above fullHeight",
                format!(r#"{{"indexedHeight":{},"fullHeight":1000}}"#, u64::MAX),
            ),
            (
                "index far below fullHeight",
                format!(r#"{{"indexedHeight":5,"fullHeight":{}}}"#, u64::MAX),
            ),
        ] {
            let (routes, scanned) = index_height_scene(Some((path.clone(), body)));
            let (addr, hits) =
                spawn_counting_mock_node(scanned.clone(), std::sync::Arc::new(routes)).await;
            let state = mock_state(addr);
            insert_tracked_reserve(&state, &tracked_box, owner);
            state.process_scan_boxes().await.unwrap();
            let hits = hits.lock().unwrap().clone();
            assert_eq!(hits.get("/blockchain/indexedHeight"), Some(&1), "{case}");
            assert_eq!(
                hits.len(),
                1,
                "{case}: only the index height is asked, got {hits:?}"
            );
            assert_eq!(state.skipped_cycles(), 1, "{case}");
            assert_eq!(state.nft_cache().cycles, 0, "{case}");
            assert!(state.reserve_tracker.get_reserve(&tracked_box).is_ok(), "{case}");
            assert!(state.reserve_tracker.get_reserve(&successor).is_err(), "{case}");
            assert!(state.nft_cache().unknown_since.is_empty(), "{case}");
            assert!(state.nft_cache().removed.is_empty(), "{case}");
            assert!(
                state.reserve_storage.get_all_quarantined().unwrap().is_empty(),
                "{case}"
            );

            // A retry with a usable answer runs the cycle.
            let (routes, scanned) =
                index_height_scene(Some(indexed_route(TEST_SPENT_AT, TEST_SPENT_AT)));
            let (state, _) = on_node(state, scanned, routes).await;
            state.process_scan_boxes().await.unwrap();
            assert_eq!(state.skipped_cycles(), 1, "{case}");
            assert!(state.reserve_tracker.get_reserve(&successor).is_ok(), "{case}");
            assert!(state.reserve_tracker.get_reserve(&tracked_box).is_err(), "{case}");
        }

        // The largest heights pass the checks without an overflow.
        let (routes, scanned) = index_height_scene(Some(indexed_route(u64::MAX, u64::MAX)));
        let state = mock_state(spawn_mock_node(scanned, std::sync::Arc::new(routes)).await);
        insert_tracked_reserve(&state, &tracked_box, owner);
        state.process_scan_boxes().await.unwrap();
        assert_eq!(state.skipped_cycles(), 0);
        assert!(state.reserve_tracker.get_reserve(&successor).is_ok());
    }

    /// Round 8 (item 1): an index height below the highest one a cycle ran
    /// with since the start (a rollback, or another node behind) skips the
    /// cycle until the index is back there, within the lag limit or not; a
    /// restart forgets the highest height.
    #[tokio::test]
    async fn test_an_index_going_back_skips_the_cycle() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let listed = serde_json::json!([scanned_box_json(
            &tracked_box,
            "c0c0",
            1_000_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None
        )])
        .to_string();
        let mut state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
        insert_tracked_reserve(&state, &tracked_box, owner);
        for (indexed, full, runs) in [
            (1_000, 1_000, true),
            (999, 999, false),
            (999, 1_001, false),
            (998, 998, false),
            (1_000, 1_001, true),
            (1_001, 1_001, true),
            (1_000, 1_000, false),
        ] {
            let (addr, hits) = spawn_counting_mock_node(
                listed.clone(),
                std::sync::Arc::new(HashMap::from([indexed_route(indexed, full)])),
            )
            .await;
            let skipped = state.skipped_cycles();
            state = on_node_at(state, addr);
            state.process_scan_boxes().await.unwrap();
            let scans = hits
                .lock()
                .unwrap()
                .get("/blockchain/box/unspent/byAddress")
                .copied()
                .unwrap_or(0);
            assert_eq!(scans > 0, runs, "index {indexed}, full {full}");
            assert_eq!(
                state.skipped_cycles() - skipped,
                u64::from(!runs),
                "index {indexed}, full {full}"
            );
            assert!(state.reserve_tracker.get_reserve(&tracked_box).is_ok());
        }
        assert_eq!(state.nft_cache().index_height_seen, Some(1_001));
        // A new process starts without it (`index_height_seen` is in memory).
        state.nft_cache().index_height_seen = None;
        let (addr, hits) = spawn_counting_mock_node(
            listed,
            std::sync::Arc::new(HashMap::from([indexed_route(999, 999)])),
        )
        .await;
        let state = on_node_at(state, addr);
        state.process_scan_boxes().await.unwrap();
        assert!(hits.lock().unwrap().contains_key("/blockchain/box/unspent/byAddress"));
    }

    /// `state` on the node at `addr`.
    fn on_node_at(state: ServerState, addr: std::net::SocketAddr) -> ServerState {
        let mut config = state.config.clone();
        config.node_url = format!("http://{}", addr);
        ServerState { config, ..state }
    }

    /// Round 6e (LOW-5): past the cycle's time limit a walk reads nothing more
    /// and the check is retried; and the singleton answers kept are those of
    /// the NFTs in the scan and of the tracked boxes.
    #[tokio::test]
    async fn test_cycle_time_limit_and_singleton_pruning() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let candidate = "55".repeat(32);
        let spend_tx = "e1".repeat(32);
        let candidate_tx = "e5".repeat(32);
        let routes = HashMap::from([
            token_route(TEST_RESERVE_NFT, 2),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&spend_tx)),
            (
                candidate_tx.clone(),
                tx_json_inputs(
                    &candidate_tx,
                    vec![reserve_input(
                        &tracked_box,
                        "c0c0",
                        &[(TEST_RESERVE_NFT, 1)],
                    )],
                ),
            ),
        ]);
        let scanned = scanned_box_json(
            &candidate,
            &candidate_tx,
            1_100_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None,
        );
        let (addr, hits) = spawn_counting_mock_node(
            serde_json::json!([scanned.clone()]).to_string(),
            std::sync::Arc::new(routes),
        )
        .await;
        let state = mock_state(addr);
        insert_tracked_reserve(&state, &tracked_box, owner);
        let tagged = tagged_erg(
            serde_json::from_value::<IndexedErgoBox>(scanned)
                .unwrap()
                .into(),
        );
        let tx_path = format!("/blockchain/transaction/byId/{candidate_tx}");

        state.cycle_state().started =
            Some(std::time::Instant::now() - CYCLE_TIME_LIMIT - std::time::Duration::from_secs(1));
        assert!(matches!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Pending(..)
        ));
        assert_eq!(hits.lock().unwrap().get(&tx_path), None);

        state.nft_cache().singleton.insert("de".repeat(32), true);
        state.process_scan_boxes().await.unwrap();
        assert!(state.reserve_tracker.get_reserve(&candidate).is_ok());
        assert_eq!(hits.lock().unwrap()[&tx_path], 1);
        let singleton = state.nft_cache().singleton.clone();
        assert!(singleton.contains_key(TEST_RESERVE_NFT));
        assert!(!singleton.contains_key(&"de".repeat(32)));
    }

    /// Round 6e (LOW-2): a pending check keeps a spent tracked box with a
    /// pending refund only until the owner could complete the refund (R7 +
    /// 43,200 blocks) and the spend is deep.
    #[tokio::test]
    async fn test_a_pending_check_stops_keeping_a_box_whose_refund_was_due() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let complete_tx = "e3".repeat(32);
        let recreated = "13".repeat(32);
        let top_up_tx = "e4".repeat(32);
        for (height, kept) in [
            (1_000 + REFUND_DELAY_BLOCKS - 1, true),
            (1_000 + REFUND_DELAY_BLOCKS, false),
        ] {
            let routes = HashMap::from([
                tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&complete_tx)),
                spend_tx_route(&complete_tx),
                indexed_route(height, height),
            ]);
            // The re-created reserve, topped up since: its lineage gives no
            // verdict (the top-up transaction cannot be read).
            let scanned = serde_json::json!([scanned_box_json(
                &recreated,
                &top_up_tx,
                1_000_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None
            )]);
            let state =
                mock_state(spawn_mock_node(scanned.to_string(), std::sync::Arc::new(routes)).await);
            insert_tracked_reserve(&state, &tracked_box, owner);
            let mut info = state.reserve_tracker.get_reserve(&tracked_box).unwrap();
            info.base_info.refund_initiation_height = 1000;
            state.reserve_tracker.update_reserve(info).unwrap();
            state.process_scan_boxes().await.unwrap();
            assert_eq!(
                state.reserve_tracker.get_reserve(&tracked_box).is_ok(),
                kept,
                "height {height}"
            );
            assert!(state.reserve_tracker.get_reserve(&recreated).is_err());
            assert!(state
                .reserve_storage
                .get_all_quarantined()
                .unwrap()
                .is_empty());
        }
    }

    /// The transaction routes of a new root created by the R4 owner (a P2PK
    /// input of the owner key).
    fn owner_root_tx(tx_id: &str) -> (String, String) {
        (
            tx_id.to_string(),
            tx_json_inputs(
                tx_id,
                vec![plain_input(
                    &"68".repeat(32),
                    "owner_wallet",
                    "c1c1",
                    &p2pk_ergo_tree(&VALID_PREFIXED_PUBKEY[2..]),
                )],
            ),
        )
    }

    /// Round 6f (P2-1): a root R was tracked, its block orphaned, and its input
    /// double-spent on the winning fork: the index never knows R and nothing
    /// holds its NFT. R is removed once the index is SPENT_REMOVAL_DEPTH blocks
    /// past the height where it was first unknown, and the owner's real new
    /// reserve R2, deferred until then, is admitted as a root. Also when R's
    /// NFT is not known (a restart): R2's check is pending, which does not
    /// keep R past that depth.
    #[tokio::test]
    async fn test_a_tracked_box_the_index_does_not_know_is_removed_after_the_depth() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let phantom = "51".repeat(32);
        let new_box = "66".repeat(32);
        let create_tx = "e6".repeat(32);
        let r2 = scanned_box_json(
            &new_box,
            &create_tx,
            1_000_000_000,
            &[(&"67".repeat(32), 1)],
            None,
        );
        for nft_known in [true, false] {
            let mut state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
            insert_tracked_reserve(&state, &phantom, owner);
            if nft_known {
                state.remember_nft(&phantom, Some(TEST_RESERVE_NFT.to_string()));
            }
            for (height, phantom_kept, r2_tracked) in [
                (1_000, true, false),
                (1_000 + SPENT_REMOVAL_DEPTH - 1, true, false),
                (1_000 + SPENT_REMOVAL_DEPTH, false, false),
                (1_000 + SPENT_REMOVAL_DEPTH + 1, false, true),
            ] {
                let routes =
                    HashMap::from([owner_root_tx(&create_tx), indexed_route(height, height)]);
                state = on_node(state, serde_json::json!([r2.clone()]).to_string(), routes)
                    .await
                    .0;
                state.process_scan_boxes().await.unwrap();
                assert_eq!(
                    state.reserve_tracker.get_reserve(&phantom).is_ok(),
                    phantom_kept,
                    "height {height}, NFT known {nft_known}"
                );
                assert_eq!(
                    state.reserve_tracker.get_reserve(&new_box).is_ok(),
                    r2_tracked,
                    "height {height}, NFT known {nft_known}"
                );
                assert!(state
                    .reserve_storage
                    .get_all_quarantined()
                    .unwrap()
                    .is_empty());
            }
        }
    }

    /// Round 6f (P2-2): the tracked T1 is unknown to the index and nothing of
    /// its lineage is remembered (a restart). On the winning fork Y descends
    /// from T0, made by the reserve's root creation. Reaching that root is not
    /// "the NFT came from outside": with R7 unchanged the singleton decides,
    /// with R7 changed the check is pending; never a quarantined root. Only an
    /// NFT that entered Y itself makes Y a root.
    #[tokio::test]
    async fn test_reaching_the_lineage_root_is_not_a_new_root() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let t0 = "10".repeat(32);
        let t1 = "11".repeat(32);
        let y = "12".repeat(32);
        let root_tx = "e0".repeat(32);
        let redeem_tx = "e2".repeat(32);
        let mut y_json =
            scanned_box_json(&y, &redeem_tx, 900_000_000, &[(TEST_RESERVE_NFT, 1)], None);
        y_json["additionalRegisters"]["R5"] = serde_json::Value::from(used_tree_register());
        for (t1_refund, nft_enters_y, followed, quarantined) in [
            (0, false, true, false),
            (1000, false, false, false),
            (0, true, false, true),
        ] {
            let y_inputs = if nft_enters_y {
                // The NFT comes from a wallet box into Y itself.
                let mut wallet = plain_input(&"69".repeat(32), "wallet", "c1c1", "0008cd00");
                wallet["assets"] =
                    serde_json::json!([{ "tokenId": TEST_RESERVE_NFT, "amount": 1 }]);
                vec![wallet]
            } else {
                vec![reserve_input(&t0, &root_tx, &[(TEST_RESERVE_NFT, 1)])]
            };
            let routes = HashMap::from([
                (redeem_tx.clone(), tx_json_inputs(&redeem_tx, y_inputs)),
                // T0's creation: the root, no reserve input.
                owner_root_tx(&root_tx),
            ]);
            let state = mock_state(
                spawn_mock_node(
                    serde_json::json!([y_json.clone()]).to_string(),
                    std::sync::Arc::new(routes),
                )
                .await,
            );
            insert_tracked_reserve(&state, &t1, owner);
            let mut info = state.reserve_tracker.get_reserve(&t1).unwrap();
            info.base_info.refund_initiation_height = t1_refund;
            state.reserve_tracker.update_reserve(info).unwrap();
            state.remember_nft(&t1, Some(TEST_RESERVE_NFT.to_string()));
            state.process_scan_boxes().await.unwrap();
            let case = format!("T1 R7 {t1_refund}, NFT enters Y {nft_enters_y}");
            assert_eq!(
                state.reserve_tracker.get_reserve(&y).is_ok(),
                followed,
                "{case}"
            );
            assert_eq!(
                state.reserve_storage.get_quarantined(&y).unwrap().is_some(),
                quarantined,
                "{case}"
            );
        }
    }

    /// Round 6f (P2-3): with page 0 read again, one scan can list the spent
    /// tracked box T (from the first read) next to the owner's new box R2 (from
    /// the re-read, close and reopen in one block) or next to T's successor S.
    /// A listed box the index shows spent is gone: R2 waits for the root check
    /// instead of being quarantined, and T leaves next to S at once.
    #[tokio::test]
    async fn test_a_listed_but_spent_box_is_gone() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let t_json = scanned_box_json(
            &tracked_box,
            "c0c0",
            1_000_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None,
        );

        // Close and reopen.
        let new_box = "66".repeat(32);
        let withdraw_tx = "e1".repeat(32);
        let create_tx = "e6".repeat(32);
        let r2 = scanned_box_json(
            &new_box,
            &create_tx,
            1_000_000_000,
            &[(&"67".repeat(32), 1)],
            None,
        );
        let mut state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
        insert_tracked_reserve(&state, &tracked_box, owner);
        for (height, listed, t_kept, r2_tracked) in [
            (
                TEST_SPENT_AT + 1,
                vec![t_json.clone(), r2.clone()],
                true,
                false,
            ),
            (
                TEST_SPENT_AT + 20,
                vec![t_json.clone(), r2.clone()],
                false,
                false,
            ),
            (TEST_SPENT_AT + 21, vec![r2.clone()], false, true),
        ] {
            let routes = HashMap::from([
                tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&withdraw_tx)),
                spend_tx_route(&withdraw_tx),
                owner_root_tx(&create_tx),
                indexed_route(height, height),
            ]);
            state = on_node(state, serde_json::Value::from(listed).to_string(), routes)
                .await
                .0;
            state.process_scan_boxes().await.unwrap();
            assert_eq!(
                state.reserve_tracker.get_reserve(&tracked_box).is_ok(),
                t_kept,
                "height {height}"
            );
            assert_eq!(
                state.reserve_tracker.get_reserve(&new_box).is_ok(),
                r2_tracked,
                "height {height}"
            );
            assert!(state
                .reserve_storage
                .get_all_quarantined()
                .unwrap()
                .is_empty());
        }

        // A redemption or top-up: T and its successor S listed together.
        let successor = "55".repeat(32);
        let top_up_tx = "e4".repeat(32);
        let routes = HashMap::from([
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&top_up_tx)),
            spend_tx_route(&top_up_tx),
            indexed_route(TEST_SPENT_AT + 1, TEST_SPENT_AT + 1),
        ]);
        let listed = serde_json::json!([
            t_json,
            scanned_box_json(
                &successor,
                &top_up_tx,
                1_100_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None
            )
        ]);
        let state =
            mock_state(spawn_mock_node(listed.to_string(), std::sync::Arc::new(routes)).await);
        insert_tracked_reserve(&state, &tracked_box, owner);
        state.process_scan_boxes().await.unwrap();
        let reserves: Vec<String> = state
            .reserve_tracker
            .get_reserves_by_owner(owner)
            .into_iter()
            .map(|r| r.box_id)
            .collect();
        assert_eq!(reserves, vec![successor]);
    }

    /// Round 6f (LOW): of two removed boxes holding the NFT, the one removed
    /// last anchors the lineage (with a NFT that is not a singleton, the older
    /// one would leave the check pending).
    #[tokio::test]
    async fn test_the_last_removed_box_anchors_the_lineage() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let older = "31".repeat(32);
        let newer = "32".repeat(32);
        let candidate = "55".repeat(32);
        let spend_tx = "e5".repeat(32);
        let routes = HashMap::from([
            token_route(TEST_RESERVE_NFT, 2),
            tracked_box_route(&older, &[(TEST_RESERVE_NFT, 1)], Some(&"e9".repeat(32))),
            tracked_box_route(&newer, &[(TEST_RESERVE_NFT, 1)], Some(&spend_tx)),
            (
                spend_tx.clone(),
                tx_json_inputs(
                    &spend_tx,
                    vec![reserve_input(&newer, "c0c0", &[(TEST_RESERVE_NFT, 1)])],
                ),
            ),
        ]);
        let scanned = serde_json::json!([scanned_box_json(
            &candidate,
            &spend_tx,
            1_000_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None
        )]);
        let state =
            mock_state(spawn_mock_node(scanned.to_string(), std::sync::Arc::new(routes)).await);
        for (box_id, removed_at) in [(&older, 1u64), (&newer, 2)] {
            insert_tracked_reserve(&state, box_id, owner);
            let record = state.reserve_tracker.get_reserve(box_id).unwrap();
            state.reserve_tracker.remove_reserve(box_id).unwrap();
            state.nft_cache().removed.insert(
                record.box_id.clone(),
                RemovedReserve {
                    record,
                    nft: Some(TEST_RESERVE_NFT.to_string()),
                    removed_at,
                    removed_height: None,
                },
            );
        }
        state.process_scan_boxes().await.unwrap();
        assert!(state.reserve_tracker.get_reserve(&candidate).is_ok());
    }

    /// Round 6f: the removed boxes survive a restart. T was followed by S and
    /// removed; after a restart a reorg drops S and T is unspent again: T is
    /// restored (its NFT is not a singleton, so no lineage check could take it
    /// back), and S is removed.
    #[tokio::test]
    async fn test_removed_boxes_survive_a_restart() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let successor = "55".repeat(32);
        let spend_tx = "e1".repeat(32);
        let routes = std::sync::Arc::new(HashMap::from([
            token_route(TEST_RESERVE_NFT, 2),
            (
                spend_tx.clone(),
                tx_json_inputs(
                    &spend_tx,
                    vec![reserve_input(
                        &tracked_box,
                        "c0c0",
                        &[(TEST_RESERVE_NFT, 1)],
                    )],
                ),
            ),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&spend_tx)),
            // Round 6f-2: the immediate rule needs the index height.
            indexed_route(
                TEST_SPENT_AT + SPENT_REMOVAL_DEPTH,
                TEST_SPENT_AT + SPENT_REMOVAL_DEPTH,
            ),
        ]));
        let data_dir = std::env::temp_dir().join(format!(
            "basis_scanner_restart_test_{}_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let open = |addr: std::net::SocketAddr| {
            ServerState::new(
                NodeConfig {
                    node_url: format!("http://{}", addr),
                    reserve_contract_p2s: Some("test_p2s".to_string()),
                    ..Default::default()
                },
                &data_dir,
            )
            .unwrap()
        };
        {
            let before = serde_json::json!([scanned_box_json(
                &successor,
                &spend_tx,
                1_100_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None
            )]);
            let state = open(spawn_mock_node(before.to_string(), routes.clone()).await);
            insert_tracked_reserve(&state, &tracked_box, owner);
            state.process_scan_boxes().await.unwrap();
            assert!(state.reserve_tracker.get_reserve(&successor).is_ok());
            assert!(state.reserve_tracker.get_reserve(&tracked_box).is_err());
        }
        let after = serde_json::json!([scanned_box_json(
            &tracked_box,
            "c0c0",
            1_000_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None
        )]);
        let state = open(spawn_mock_node(after.to_string(), routes).await);
        assert!(state.nft_cache().removed.contains_key(&tracked_box));
        state.process_scan_boxes().await.unwrap();
        assert!(state.reserve_tracker.get_reserve(&tracked_box).is_ok());
        assert!(state.reserve_tracker.get_reserve(&successor).is_err());
        assert!(state
            .reserve_storage
            .get_all_quarantined()
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    /// Round 6f-2 (P2-A): while the index height is unknown (indexedHeight
    /// fails or says nothing) a tracked box the index does not know is kept,
    /// however far the node's fullHeight moves: the 10-block rule, the pending
    /// override and the immediate rule next to a sibling count only in index
    /// height. Once the index height is known again, counting starts there, and
    /// the removed record carries that height. Round 8: such a cycle is now
    /// skipped altogether (`test_no_usable_index_height_skips_the_cycle`).
    #[tokio::test]
    async fn test_unknown_to_an_index_of_unknown_height_is_kept() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let phantom = "51".repeat(32);
        let new_box = "66".repeat(32);
        let create_tx = "e6".repeat(32);
        let r2 = scanned_box_json(
            &new_box,
            &create_tx,
            1_000_000_000,
            &[(&"67".repeat(32), 1)],
            None,
        );
        let no_index = || ("/blockchain/indexedHeight".to_string(), "{}".to_string());
        for nft_known in [true, false] {
            let mut state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
            insert_tracked_reserve(&state, &phantom, owner);
            if nft_known {
                state.remember_nft(&phantom, Some(TEST_RESERVE_NFT.to_string()));
            }
            for (index, full, kept) in [
                (None, 1_000, true),
                (None, 1_000 + SPENT_REMOVAL_DEPTH, true),
                (None, 1_000 + 3 * SPENT_REMOVAL_DEPTH, true),
                (Some(2_000), 2_000, true),
                (
                    Some(2_000 + SPENT_REMOVAL_DEPTH - 1),
                    2_000 + SPENT_REMOVAL_DEPTH - 1,
                    true,
                ),
                (
                    Some(2_000 + SPENT_REMOVAL_DEPTH),
                    2_000 + SPENT_REMOVAL_DEPTH,
                    false,
                ),
            ] {
                let mut routes = HashMap::from([owner_root_tx(&create_tx), info_route(full)]);
                let (path, body) = match index {
                    Some(height) => indexed_route(height, height),
                    None => no_index(),
                };
                routes.insert(path, body);
                state = on_node(state, serde_json::json!([r2.clone()]).to_string(), routes)
                    .await
                    .0;
                state.process_scan_boxes().await.unwrap();
                assert_eq!(
                    state.reserve_tracker.get_reserve(&phantom).is_ok(),
                    kept,
                    "index {index:?}, full {full}, NFT known {nft_known}"
                );
                if index.is_none() {
                    assert!(!state.nft_cache().unknown_since.contains_key(&phantom));
                }
                assert!(state
                    .reserve_storage
                    .get_all_quarantined()
                    .unwrap()
                    .is_empty());
            }
            assert_eq!(
                state
                    .nft_cache()
                    .removed
                    .get(&phantom)
                    .and_then(|removed| removed.removed_height),
                Some(2_000 + SPENT_REMOVAL_DEPTH)
            );
        }

        // The immediate rule: a sibling of the owner is tracked and listed.
        let sibling = "52".repeat(32);
        let listed = serde_json::json!([scanned_box_json(
            &sibling,
            "c0c0",
            1_000_000_000,
            &[(&"68".repeat(32), 1)],
            None
        )])
        .to_string();
        let mut state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
        insert_tracked_reserve(&state, &phantom, owner);
        insert_tracked_reserve(&state, &sibling, owner);
        for (index, kept) in [(None, true), (Some(3_000), false)] {
            let mut routes = HashMap::from([info_route(3_000)]);
            let (path, body) = match index {
                Some(height) => indexed_route(height, height),
                None => no_index(),
            };
            routes.insert(path, body);
            state = on_node(state, listed.clone(), routes).await.0;
            state.process_scan_boxes().await.unwrap();
            assert_eq!(
                state.reserve_tracker.get_reserve(&phantom).is_ok(),
                kept,
                "index {index:?}"
            );
            assert!(state.reserve_tracker.get_reserve(&sibling).is_ok());
        }
    }

    /// Round 6f-2 (P2-A): removed records expire by index height
    /// (REMEMBER_REMOVED_BLOCKS), only in cycles that know it, never by
    /// wall-clock; a record without a removal height starts counting at the
    /// first such cycle, and that height is stored.
    #[tokio::test]
    async fn test_removed_records_expire_by_index_height() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
        let counted = "71".repeat(32);
        let uncounted = "72".repeat(32);
        for (box_id, removed_height) in [(&counted, Some(1_000)), (&uncounted, None)] {
            insert_tracked_reserve(&state, box_id, owner);
            let record = state.reserve_tracker.get_reserve(box_id).unwrap();
            state.reserve_tracker.remove_reserve(box_id).unwrap();
            let removed = RemovedReserve {
                record,
                nft: None,
                // Long past by wall-clock.
                removed_at: 0,
                removed_height,
            };
            state.reserve_storage.store_removed(&removed).unwrap();
            state.nft_cache().removed.insert(box_id.clone(), removed);
        }
        let stored = |box_id: &String| {
            state
                .reserve_storage
                .removed_reserves()
                .unwrap()
                .into_iter()
                .find(|removed| removed.record.box_id == *box_id)
                .map(|removed| removed.removed_height)
        };
        let mut seen_known = false;
        for (index, counted_kept, uncounted_kept) in [
            (None, true, true),
            (Some(1_500), true, true),
            (None, true, true),
            (Some(1_000 + REMEMBER_REMOVED_BLOCKS - 1), true, true),
            (Some(1_000 + REMEMBER_REMOVED_BLOCKS), false, true),
            (Some(1_500 + REMEMBER_REMOVED_BLOCKS - 1), false, true),
            (Some(1_500 + REMEMBER_REMOVED_BLOCKS), false, false),
        ] {
            state.begin_cycle(Vec::new(), index).await;
            for (box_id, kept) in [(&counted, counted_kept), (&uncounted, uncounted_kept)] {
                assert_eq!(
                    state.nft_cache().removed.contains_key(box_id),
                    kept,
                    "{box_id} at {index:?}"
                );
                assert_eq!(stored(box_id).is_some(), kept, "{box_id} at {index:?}");
            }
            seen_known |= index.is_some();
            if uncounted_kept {
                assert_eq!(
                    stored(&uncounted),
                    Some(seen_known.then_some(1_500)),
                    "at {index:?}"
                );
            }
        }
    }

    /// Round 6f-2 (LOW-1): a tracked box that was missing and unknown to the
    /// index once, then listed again, starts counting anew when it is missing
    /// again: its old `since` does not remove it early.
    #[tokio::test]
    async fn test_a_box_listed_again_counts_its_unknown_height_anew() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let listed = serde_json::json!([scanned_box_json(
            &tracked_box,
            "c0c0",
            1_000_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None
        )])
        .to_string();
        let mut state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
        insert_tracked_reserve(&state, &tracked_box, owner);
        state.remember_nft(&tracked_box, Some(TEST_RESERVE_NFT.to_string()));
        for (height, is_listed, kept, since) in [
            (1_000, false, true, Some(1_000)),
            (1_005, true, true, None),
            (1_000 + SPENT_REMOVAL_DEPTH + 2, false, true, Some(1_012)),
            (1_012 + SPENT_REMOVAL_DEPTH - 1, false, true, Some(1_012)),
            (1_012 + SPENT_REMOVAL_DEPTH, false, false, None),
        ] {
            let body = if is_listed {
                listed.clone()
            } else {
                "[]".to_string()
            };
            let routes = HashMap::from([indexed_route(height, height)]);
            state = on_node(state, body, routes).await.0;
            state.process_scan_boxes().await.unwrap();
            assert_eq!(
                state.reserve_tracker.get_reserve(&tracked_box).is_ok(),
                kept,
                "height {height}"
            );
            if kept {
                assert_eq!(
                    state.nft_cache().unknown_since.get(&tracked_box).copied(),
                    since,
                    "height {height}"
                );
            }
        }
    }

    /// Round 6f-2 (LOW-4): a removed box a reorg brings back keeps its removed
    /// record until it is stored again; when the store fails (here: a box id
    /// too long for a key) the record stays, so the box is still restored next
    /// time instead of being judged anew.
    #[tokio::test]
    async fn test_a_restored_box_is_forgotten_only_once_stored() {
        let state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
        for (box_id, stored) in [("ab".repeat(40_000), false), ("11".repeat(32), true)] {
            let mut scan_box = c4_test_box();
            scan_box.box_id = box_id.clone();
            let tagged = tagged_erg(scan_box);
            let record = state
                .parse_reserve_box(&tagged.scan_box, tagged.kind, &tagged.contract_address)
                .unwrap();
            let removed = RemovedReserve {
                record,
                nft: None,
                removed_at: 1,
                removed_height: Some(1_000),
            };
            if stored {
                state.reserve_storage.store_removed(&removed).unwrap();
            }
            state.nft_cache().removed.insert(box_id.clone(), removed);
            assert_eq!(
                state.ingest_scan_box(&tagged).await,
                ScanBoxIngest::Tracked(box_id.clone())
            );
            assert_eq!(
                state
                    .reserve_storage
                    .get_reserve(&box_id)
                    .unwrap()
                    .is_some(),
                stored
            );
            assert_eq!(state.nft_cache().removed.contains_key(&box_id), !stored);
            assert!(!state
                .reserve_storage
                .removed_reserves()
                .unwrap()
                .iter()
                .any(|removed| removed.record.box_id == box_id && stored));
        }
    }

    // Round 7: the interim guard against reopening a reserve after redemptions (N9).

    /// The owner of the test reserve boxes (`VALID_PREFIXED_PUBKEY`) as a key.
    fn test_owner() -> crate::PubKey {
        hex::decode(&VALID_PREFIXED_PUBKEY[2..])
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// `state` with the reopen guard on and these (owner, denomination) pairs with
    /// redemptions at the tracker; `None`: the tracker has not published them yet.
    fn with_reopen_guard(
        state: ServerState,
        history: Option<Vec<(crate::PubKey, crate::DenomKey)>>,
    ) -> ServerState {
        let guard = ReopenGuard::new(true);
        if let Some(pairs) = history {
            guard.load(pairs);
        }
        ServerState {
            reopen_guard: guard,
            ..state
        }
    }

    /// A clean ERG root of the test owner, made by a transaction that spends the
    /// owner's P2PK input, on a node that serves that transaction.
    async fn owner_root() -> (ServerState, TaggedScanBox) {
        let mut scan_box = c4_test_box();
        scan_box.box_id = "31".repeat(32);
        scan_box.transaction_id = "e7".repeat(32);
        let routes = HashMap::from([owner_root_tx(&scan_box.transaction_id)]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(routes)).await);
        (state, tagged_erg(scan_box))
    }

    /// Round 7 (N9): the tracker holds redemptions of the owner in ERG, so a new
    /// clean root of the owner in ERG is quarantined with the reopen reason (and
    /// stays so); an operator release lets the next check admit it. Redemptions in
    /// another denomination, or of another owner, block nothing; with no history
    /// (a fresh tracker) the root is admitted as before.
    #[tokio::test]
    async fn test_reopen_guard_quarantines_a_new_root_until_released() {
        let owner = test_owner();
        let box_id = "31".repeat(32);
        let token = crate::DenomKey::Token([0x99; 32]);
        for (history, blocked) in [
            (vec![(owner, crate::DenomKey::Erg)], true),
            (vec![(owner, token)], false),
            (vec![([0x02; 33], crate::DenomKey::Erg)], false),
            (vec![], false),
        ] {
            let (state, tagged) = owner_root().await;
            let state = with_reopen_guard(state, Some(history.clone()));
            let case = format!("history {history:?}");
            if !blocked {
                assert_eq!(
                    state.ingest_scan_box(&tagged).await,
                    ScanBoxIngest::Tracked(box_id.clone()),
                    "{case}"
                );
                continue;
            }
            for _ in 0..2 {
                assert_eq!(
                    state.ingest_scan_box(&tagged).await,
                    ScanBoxIngest::Rejected(box_id.clone()),
                    "{case}"
                );
            }
            let record = state
                .reserve_storage
                .get_quarantined(&box_id)
                .unwrap()
                .expect("quarantined");
            assert!(
                record.reason.starts_with(RESERVE_REOPEN_BLOCKED),
                "{}",
                record.reason
            );
            assert!(state.reserve_tracker.get_reserve(&box_id).is_err());

            let release = state
                .reserve_storage
                .release_quarantined(&box_id, "the owner's reserve; creditors told", 1)
                .unwrap()
                .expect("released");
            assert!(release.record.reason.starts_with(RESERVE_REOPEN_BLOCKED));
            assert_eq!(
                state.ingest_scan_box(&tagged).await,
                ScanBoxIngest::Tracked(box_id.clone()),
                "{case}"
            );
            assert!(state.reserve_storage.get_quarantined(&box_id).unwrap().is_none());
        }
    }

    /// Round 7 (N9): a release from another quarantine is no release from the
    /// reopen guard: a box once quarantined for another reason, released, and now
    /// held only by the guard, is quarantined again with the reopen reason, and a
    /// release of that admits it.
    #[tokio::test]
    async fn test_reopen_guard_needs_a_release_of_its_own() {
        let (state, tagged) = owner_root().await;
        let state = with_reopen_guard(state, Some(vec![(test_owner(), crate::DenomKey::Erg)]));
        let box_id = "31".repeat(32);
        state
            .reserve_storage
            .store_quarantined(&QuarantinedReserve {
                box_id: box_id.clone(),
                owner_pubkey: VALID_PREFIXED_PUBKEY[2..].to_string(),
                denomination: "erg".to_string(),
                reason: "an older rule".to_string(),
                quarantined_at: 0,
            })
            .unwrap();
        state
            .reserve_storage
            .release_quarantined(&box_id, "older rule", 1)
            .unwrap()
            .unwrap();
        assert_eq!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Rejected(box_id.clone())
        );
        let record = state.reserve_storage.get_quarantined(&box_id).unwrap().unwrap();
        assert!(record.reason.starts_with(RESERVE_REOPEN_BLOCKED), "{}", record.reason);
        state
            .reserve_storage
            .release_quarantined(&box_id, "reopen checked", 2)
            .unwrap()
            .unwrap();
        assert_eq!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Tracked(box_id)
        );
    }

    /// Round 7 (N9): until the tracker publishes its redemption history (the first
    /// moments after a start) a root waits: deferred, not quarantined, not tracked.
    #[tokio::test]
    async fn test_reopen_guard_defers_a_root_until_the_history_is_known() {
        let (state, tagged) = owner_root().await;
        let state = with_reopen_guard(state, None);
        let box_id = "31".repeat(32);
        assert_eq!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Deferred(box_id.clone())
        );
        assert!(state.reserve_storage.get_quarantined(&box_id).unwrap().is_none());
        state
            .reopen_guard
            .load(Vec::<(crate::PubKey, crate::DenomKey)>::new());
        assert_eq!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Tracked(box_id)
        );
    }

    /// Round 7 (N9): with the guard off (`[server] reserve_reopen_guard = false`)
    /// the root is admitted whatever the history, as before round 7.
    #[tokio::test]
    async fn test_reopen_guard_off_admits_the_root() {
        let (state, tagged) = owner_root().await;
        let guard = ReopenGuard::new(false);
        guard.load(vec![(test_owner(), crate::DenomKey::Erg)]);
        let state = ServerState {
            reopen_guard: guard,
            ..state
        };
        assert_eq!(
            state.ingest_scan_box(&tagged).await,
            ScanBoxIngest::Tracked("31".repeat(32))
        );
    }

    /// Round 7 (N9): the owner completes the refund of the tracked reserve into a
    /// clean box holding the same NFT (judged as a root since round 6d). With
    /// redemptions at the tracker it is quarantined with the reopen reason, not
    /// tracked, and the refunding box is not touched by it. Round 7b: before the
    /// history is known (an uncapped root: `Retry`) the box is neither tracked nor
    /// quarantined and the refunding box stays tracked; once the history is
    /// published (empty) the next cycle tracks it.
    #[tokio::test]
    async fn test_reopen_guard_quarantines_a_refund_completion_root() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let recreated = "13".repeat(32);
        let spend_tx = "e1".repeat(32);
        let mut refunding = reserve_input(&tracked_box, "c0c0", &[(TEST_RESERVE_NFT, 1)]);
        refunding["additionalRegisters"]["R5"] = serde_json::Value::from(used_tree_register());
        refunding["additionalRegisters"]["R7"] = serde_json::Value::from(R7_REFUND_1000);
        let routes = HashMap::from([
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&spend_tx)),
            (spend_tx.clone(), tx_json_inputs(&spend_tx, vec![refunding])),
        ]);
        let box_r = scanned_box_json(
            &recreated,
            &spend_tx,
            1_000_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            Some("0500"),
        );
        for history in [true, false] {
            let state = mock_state(
                spawn_mock_node(
                    serde_json::json!([box_r.clone()]).to_string(),
                    std::sync::Arc::new(routes.clone()),
                )
                .await,
            );
            let pairs = if history {
                vec![(test_owner(), crate::DenomKey::Erg)]
            } else {
                vec![]
            };
            let mut state = with_reopen_guard(state, Some(pairs));
            insert_tracked_reserve(&state, &tracked_box, owner);
            let mut info = state.reserve_tracker.get_reserve(&tracked_box).unwrap();
            info.base_info.refund_initiation_height = 1000;
            state.reserve_tracker.update_reserve(info).unwrap();
            if !history {
                // Round 7b: the same cycle before the tracker published the history.
                state.reopen_guard = ReopenGuard::new(true);
                state.process_scan_boxes().await.unwrap();
                assert!(state.reserve_tracker.get_reserve(&recreated).is_err());
                assert!(state.reserve_storage.get_quarantined(&recreated).unwrap().is_none());
                assert!(
                    state.reserve_tracker.get_reserve(&tracked_box).is_ok(),
                    "the refunding box stays tracked while the root waits"
                );
                state
                    .reopen_guard
                    .load(Vec::<(crate::PubKey, crate::DenomKey)>::new());
            }
            state.process_scan_boxes().await.unwrap();
            assert_eq!(
                state.reserve_tracker.get_reserve(&recreated).is_ok(),
                !history,
                "history {history}"
            );
            let quarantined = state.reserve_storage.get_quarantined(&recreated).unwrap();
            assert_eq!(quarantined.is_some(), history, "history {history}");
            if let Some(record) = quarantined {
                assert!(
                    record.reason.starts_with(RESERVE_REOPEN_BLOCKED),
                    "{}",
                    record.reason
                );
            }
        }
    }

    /// Round 7b: the C4 setup checks come before the reopen guard. A root with a
    /// non-empty tree (R5) or a pending refund (R7) of an owner with redemptions
    /// keeps its C4 quarantine reason, also before the history is known.
    #[tokio::test]
    async fn test_c4_comes_before_the_reopen_guard() {
        let box_id = "31".repeat(32);
        for (register, value, reason) in [
            ("R5", used_tree_register(), "non-empty AVL tree"),
            ("R7", R7_REFUND_1000.to_string(), "pending refund"),
        ] {
            for history in [Some(vec![(test_owner(), crate::DenomKey::Erg)]), None] {
                let case = format!("{register}, history {history:?}");
                let (state, mut tagged) = owner_root().await;
                let state = with_reopen_guard(state, history);
                tagged
                    .scan_box
                    .additional_registers
                    .insert(register.to_string(), value.clone());
                assert_eq!(
                    state.ingest_scan_box(&tagged).await,
                    ScanBoxIngest::Rejected(box_id.clone()),
                    "{case}"
                );
                let record = state
                    .reserve_storage
                    .get_quarantined(&box_id)
                    .unwrap()
                    .expect("quarantined");
                assert!(record.reason.contains(reason), "{case}: {}", record.reason);
                assert!(
                    !record.reason.starts_with(RESERVE_REOPEN_BLOCKED),
                    "{case}: {}",
                    record.reason
                );
            }
        }
    }

    /// Round 7 (N9): the guard never touches a tracked reserve or its successors.
    /// With redemptions of the owner at the tracker, and also before the tracker
    /// published them, the tracked box is refreshed, and a successor made by a
    /// top-up (R5 as it was), a redemption (R5 used) or a refund start (R7 set) is
    /// followed; nothing is quarantined.
    #[tokio::test]
    async fn test_reopen_guard_leaves_tracked_reserves_and_successors_alone() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let successor_box = "55".repeat(32);
        let successor_tx = "bb".repeat(32);
        let routes = std::sync::Arc::new(HashMap::from([
            (
                successor_tx.clone(),
                tx_json_inputs(
                    &successor_tx,
                    vec![
                        plain_input(&"cd".repeat(32), "some_address", &"ce".repeat(32), "0008cd02"),
                        reserve_input(&tracked_box, &"cc".repeat(32), &[(TEST_RESERVE_NFT, 1)]),
                    ],
                ),
            ),
            tracked_box_route(&tracked_box, &[(TEST_RESERVE_NFT, 1)], Some(&successor_tx)),
        ]));
        for history in [Some(vec![(test_owner(), crate::DenomKey::Erg)]), None] {
            for (action, r5, r7) in [
                ("top-up", empty_reserve_tree_register(), None),
                ("redemption", used_tree_register(), None),
                ("refund start", used_tree_register(), Some(R7_REFUND_1000)),
            ] {
                let case = format!("{action}, history {history:?}");
                let state = with_reopen_guard(
                    mock_state(spawn_mock_node("[]".to_string(), routes.clone()).await),
                    history.clone(),
                );
                insert_tracked_reserve(&state, &tracked_box, owner);

                let mut tracked = c4_test_box();
                tracked.box_id = tracked_box.clone();
                assert_eq!(
                    state.ingest_scan_box(&tagged_erg(tracked)).await,
                    ScanBoxIngest::Tracked(tracked_box.clone()),
                    "{case}"
                );

                let mut successor = c4_test_box();
                successor.box_id = successor_box.clone();
                successor.transaction_id = successor_tx.clone();
                successor.additional_registers.insert("R5".to_string(), r5);
                if let Some(r7) = r7 {
                    successor
                        .additional_registers
                        .insert("R7".to_string(), r7.to_string());
                }
                assert_eq!(
                    state.ingest_scan_box(&tagged_erg(successor)).await,
                    ScanBoxIngest::Tracked(successor_box.clone()),
                    "{case}"
                );
                assert!(
                    state.reserve_storage.get_all_quarantined().unwrap().is_empty(),
                    "{case}"
                );
            }
        }
    }

    /// Round 7 (N9): a restart on live data. Three reserves are tracked and
    /// persisted (fresh, after redemptions, with a refund started), their owners
    /// all have redemptions at the tracker. A new scanner on the same data dir with
    /// the guard on (history published or not yet) lists the three boxes: all stay
    /// tracked, nothing is quarantined.
    #[tokio::test]
    async fn test_reopen_guard_restart_on_live_data_quarantines_nothing() {
        let owners: Vec<String> = (0..3).map(test_owner_key).collect();
        let boxes: Vec<String> = ["a1", "a2", "a3"].iter().map(|b| b.repeat(32)).collect();
        let data_dir = std::env::temp_dir().join(format!(
            "basis_scanner_reopen_restart_test_{}_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let listed: Vec<serde_json::Value> = boxes
            .iter()
            .zip(&owners)
            .enumerate()
            .map(|(i, (box_id, owner))| {
                let nft = format!("{:064x}", 0x4e00 + i);
                let mut listed = scanned_box_json(
                    box_id,
                    &"c0".repeat(32),
                    1_000_000_000,
                    &[(nft.as_str(), 1)],
                    (i == 2).then_some(R7_REFUND_1000),
                );
                listed["additionalRegisters"]["R4"] = serde_json::Value::from(format!("07{owner}"));
                if i > 0 {
                    listed["additionalRegisters"]["R5"] =
                        serde_json::Value::from(used_tree_register());
                }
                listed
            })
            .collect();
        let history: Vec<(crate::PubKey, crate::DenomKey)> = owners
            .iter()
            .map(|owner| {
                (
                    hex::decode(owner).unwrap().try_into().unwrap(),
                    crate::DenomKey::Erg,
                )
            })
            .collect();
        let open = |addr: std::net::SocketAddr| {
            ServerState::new(
                NodeConfig {
                    node_url: format!("http://{}", addr),
                    reserve_contract_p2s: Some("test_p2s".to_string()),
                    ..Default::default()
                },
                &data_dir,
            )
            .unwrap()
        };
        let body = serde_json::Value::from(listed).to_string();
        {
            let state = open(spawn_mock_node(body.clone(), Default::default()).await);
            for (box_id, owner) in boxes.iter().zip(&owners) {
                insert_tracked_reserve(&state, box_id, owner);
            }
        }
        for published in [false, true] {
            let state = with_reopen_guard(
                open(spawn_mock_node(body.clone(), Default::default()).await),
                published.then(|| history.clone()),
            );
            assert_eq!(state.reserve_tracker.get_all_reserves().len(), 3);
            state.process_scan_boxes().await.unwrap();
            for box_id in &boxes {
                assert!(
                    state.reserve_tracker.get_reserve(box_id).is_ok(),
                    "published {published}: {box_id}"
                );
            }
            assert!(
                state.reserve_storage.get_all_quarantined().unwrap().is_empty(),
                "published {published}"
            );
        }
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    /// A fresh data dir for a restart test.
    fn restart_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "basis_scanner_{}_{}_{}",
            name,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ))
    }

    /// A scanner process on `data_dir` and the node at `addr`.
    fn open_at(data_dir: &std::path::Path, addr: std::net::SocketAddr) -> ServerState {
        ServerState::new(
            NodeConfig {
                node_url: format!("http://{}", addr),
                reserve_contract_p2s: Some("test_p2s".to_string()),
                ..Default::default()
            },
            data_dir,
        )
        .unwrap()
    }

    /// Round 8 (item 2): the NFT facts survive a restart. T was followed by
    /// S (cycle 1, which read the token index once); then S is spent into S2.
    /// The cycle that follows S2 asks the node exactly the same after a
    /// restart as in the process that never stopped: the NFT of S and the
    /// singleton verdict of its NFT come from the store. Without them (a store
    /// from before round 8, or entries that no longer read back) the cycle
    /// asks the token index once more and follows S2 all the same; a damaged
    /// entry is removed, and the facts are stored again.
    #[tokio::test]
    async fn test_known_nft_facts_survive_a_restart() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let t = "11".repeat(32);
        let s1 = "55".repeat(32);
        let s2 = "56".repeat(32);
        let tx1 = "e1".repeat(32);
        let tx2 = "e2".repeat(32);
        let token_path = format!("/blockchain/token/byId/{}", TEST_RESERVE_NFT);
        let first_cycle = |data_dir: std::path::PathBuf| {
            let (t, s1, tx1, token_path) =
                (t.clone(), s1.clone(), tx1.clone(), token_path.clone());
            async move {
                let routes = HashMap::from([
                    tracked_box_route(&t, &[(TEST_RESERVE_NFT, 1)], Some(&tx1)),
                    spend_tx_route(&tx1),
                    indexed_route(1_000, 1_000),
                ]);
                let listed = serde_json::json!([scanned_box_json(
                    &s1,
                    &tx1,
                    1_100_000_000,
                    &[(TEST_RESERVE_NFT, 1)],
                    None
                )]);
                let (addr, hits) =
                    spawn_counting_mock_node(listed.to_string(), std::sync::Arc::new(routes)).await;
                let state = open_at(&data_dir, addr);
                insert_tracked_reserve(&state, &t, owner);
                state.process_scan_boxes().await.unwrap();
                assert!(state.reserve_tracker.get_reserve(&s1).is_ok());
                assert!(state.reserve_tracker.get_reserve(&t).is_err());
                assert_eq!(hits.lock().unwrap().get(&token_path).copied(), Some(1));
                state
            }
        };
        let second_node = || async {
            let routes = HashMap::from([
                tracked_box_route(&s1, &[(TEST_RESERVE_NFT, 1)], Some(&tx2)),
                spend_tx_route(&tx2),
                indexed_route(1_001, 1_001),
            ]);
            let listed = serde_json::json!([scanned_box_json(
                &s2,
                &tx2,
                1_200_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None
            )]);
            spawn_counting_mock_node(listed.to_string(), std::sync::Arc::new(routes)).await
        };
        let second_cycle = |state: ServerState, hits: Hits| {
            let (s1, s2) = (s1.clone(), s2.clone());
            async move {
                state.process_scan_boxes().await.unwrap();
                assert!(state.reserve_tracker.get_reserve(&s2).is_ok());
                assert!(state.reserve_tracker.get_reserve(&s1).is_err());
                assert!(state.reserve_storage.get_all_quarantined().unwrap().is_empty());
                let hits = hits.lock().unwrap().clone();
                (state, hits)
            }
        };

        // A: the process never stops.
        let dir_a = restart_dir("nft_facts_a");
        let state = first_cycle(dir_a.clone()).await;
        let (addr, hits) = second_node().await;
        let (_, hits_a) = second_cycle(on_node_at(state, addr), hits).await;
        assert_eq!(hits_a.get(&token_path), None, "{hits_a:?}");

        // B: a restart between the two cycles.
        let dir_b = restart_dir("nft_facts_b");
        drop(first_cycle(dir_b.clone()).await);
        let (addr, hits) = second_node().await;
        let restarted = open_at(&dir_b, addr);
        assert_eq!(
            restarted.nft_cache().box_nft.get(&s1),
            Some(&Some(TEST_RESERVE_NFT.to_string()))
        );
        assert_eq!(restarted.nft_cache().singleton.get(TEST_RESERVE_NFT), Some(&true));
        let (_, hits_b) = second_cycle(restarted, hits).await;
        assert_eq!(hits_b, hits_a, "a warm restart asks the node nothing more");

        // C: no stored facts; D: damaged ones.
        for damaged in [false, true] {
            let dir = restart_dir("nft_facts_cd");
            let state = first_cycle(dir.clone()).await;
            state.reserve_storage.forget_box_nft(&s1).unwrap();
            state.reserve_storage.forget_nft_emission(TEST_RESERVE_NFT).unwrap();
            if damaged {
                state
                    .reserve_storage
                    .insert_raw_nft_fact(false, s1.as_bytes(), b"{\"nft\":\"not hex\"}");
                state
                    .reserve_storage
                    .insert_raw_nft_fact(true, TEST_RESERVE_NFT.as_bytes(), b"\xff");
                state
                    .reserve_storage
                    .insert_raw_nft_fact(true, b"not an id", b"{\"emission\":1}");
            }
            drop(state);
            let (addr, hits) = second_node().await;
            let restarted = open_at(&dir, addr);
            assert!(restarted.nft_cache().box_nft.is_empty(), "damaged {damaged}");
            assert!(restarted.nft_cache().singleton.is_empty(), "damaged {damaged}");
            assert_eq!(
                restarted.reserve_storage.nft_facts().unwrap(),
                crate::persistence::NftFacts::default(),
                "damaged entries are removed"
            );
            let (state, hits_c) = second_cycle(restarted, hits).await;
            let mut expected = hits_a.clone();
            expected.insert(token_path.clone(), 1);
            assert_eq!(hits_c, expected, "damaged {damaged}");
            let facts = state.reserve_storage.nft_facts().unwrap();
            assert_eq!(
                facts.box_nft,
                HashMap::from([(s2.clone(), TEST_RESERVE_NFT.to_string())]),
                "damaged {damaged}"
            );
            assert_eq!(
                facts.emission,
                HashMap::from([(TEST_RESERVE_NFT.to_string(), 1)]),
                "damaged {damaged}"
            );
            drop(state);
            let _ = std::fs::remove_dir_all(&dir);
        }
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    /// Round 8 (item 2): only the facts of tracked reserves are kept. At start
    /// the NFT of a box that is not tracked any more and the emission of an NFT
    /// no tracked or removed box holds leave the store; a removed box's NFT
    /// lives on in its removed record (and keeps its emission), not in the box
    /// NFT partition.
    #[tokio::test]
    async fn test_stored_nft_facts_follow_the_tracked_reserves() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let t = "11".repeat(32);
        let s1 = "55".repeat(32);
        let tx1 = "e1".repeat(32);
        let dir = restart_dir("nft_facts_prune");
        {
            let routes = HashMap::from([
                tracked_box_route(&t, &[(TEST_RESERVE_NFT, 1)], Some(&tx1)),
                spend_tx_route(&tx1),
                indexed_route(1_000, 1_000),
            ]);
            let listed = serde_json::json!([scanned_box_json(
                &s1,
                &tx1,
                1_100_000_000,
                &[(TEST_RESERVE_NFT, 1)],
                None
            )]);
            let state = open_at(
                &dir,
                spawn_mock_node(listed.to_string(), std::sync::Arc::new(routes)).await,
            );
            insert_tracked_reserve(&state, &t, owner);
            state.remember_nft(&t, Some(TEST_RESERVE_NFT.to_string()));
            assert_eq!(state.reserve_storage.nft_facts().unwrap().box_nft.len(), 1);
            state.process_scan_boxes().await.unwrap();
            assert!(state.reserve_tracker.get_reserve(&s1).is_ok());
            let facts = state.reserve_storage.nft_facts().unwrap();
            // T was removed: its NFT is in its removed record now.
            assert_eq!(
                facts.box_nft,
                HashMap::from([(s1.clone(), TEST_RESERVE_NFT.to_string())])
            );
            assert_eq!(
                state.nft_cache().removed[&t].nft.as_deref(),
                Some(TEST_RESERVE_NFT)
            );
            // Facts of boxes nobody tracks (a failed store, an older process).
            state
                .reserve_storage
                .store_box_nft(&"77".repeat(32), &"78".repeat(32))
                .unwrap();
            state
                .reserve_storage
                .store_nft_emission(&"78".repeat(32), 1)
                .unwrap();
        }
        let state = open_at(&dir, spawn_mock_node("[]".to_string(), Default::default()).await);
        let facts = state.reserve_storage.nft_facts().unwrap();
        assert_eq!(
            facts.box_nft,
            HashMap::from([(s1.clone(), TEST_RESERVE_NFT.to_string())])
        );
        assert_eq!(
            facts.emission,
            HashMap::from([(TEST_RESERVE_NFT.to_string(), 1)])
        );
        assert!(!state.nft_cache().box_nft.contains_key(&"77".repeat(32)));
        // A known NFT is not forgotten for an answer that lists no assets.
        state.remember_nft(&s1, None);
        assert_eq!(
            state.nft_cache().box_nft.get(&s1),
            Some(&Some(TEST_RESERVE_NFT.to_string()))
        );
        drop(state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Round 8 (item 2): fork A had T0 -> T (tracked); the reorg to fork B
    /// has a redemption T0 -> X (a used R5), and the tracker restarted. The
    /// index does not know T. With T's NFT in the store, X is followed as
    /// T's successor (the walk reaches no box of the lineage, the singleton
    /// NFT decides) and T leaves. Without it (a store from before round 8,
    /// where T's NFT was in memory only), nothing anchors X: it waits while T
    /// is kept, T leaves once it has been unknown for 10 index blocks, and X
    /// is then judged as a root and quarantined for its used R5.
    #[tokio::test]
    async fn test_a_restart_keeps_the_nft_of_a_tracked_box_the_index_lost() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let t0 = "10".repeat(32);
        let t = "11".repeat(32);
        let x = "12".repeat(32);
        let redeem_tx = "e2".repeat(32);
        let mut x_json =
            scanned_box_json(&x, &redeem_tx, 900_000_000, &[(TEST_RESERVE_NFT, 1)], None);
        x_json["additionalRegisters"]["R5"] = serde_json::Value::from(used_tree_register());
        let fork_b = |height: u64| {
            HashMap::from([
                (
                    redeem_tx.clone(),
                    tx_json_inputs(
                        &redeem_tx,
                        vec![reserve_input(&t0, "c0c0", &[(TEST_RESERVE_NFT, 1)])],
                    ),
                ),
                indexed_route(height, height),
            ])
        };
        for warm in [true, false] {
            let dir = restart_dir("nft_facts_reorg");
            {
                // Fork A: T is tracked and listed.
                let t_json =
                    scanned_box_json(&t, "c0c0", 1_000_000_000, &[(TEST_RESERVE_NFT, 1)], None);
                let state = open_at(
                    &dir,
                    spawn_mock_node(
                        serde_json::json!([t_json]).to_string(),
                        std::sync::Arc::new(HashMap::from([indexed_route(990, 990)])),
                    )
                    .await,
                );
                insert_tracked_reserve(&state, &t, owner);
                if warm {
                    state.process_scan_boxes().await.unwrap();
                }
                assert!(state.reserve_tracker.get_reserve(&t).is_ok());
            }
            let mut state =
                open_at(&dir, spawn_mock_node("[]".to_string(), Default::default()).await);
            for height in [1_000, 1_000 + SPENT_REMOVAL_DEPTH, 1_001 + SPENT_REMOVAL_DEPTH] {
                state = on_node(state, serde_json::json!([x_json.clone()]).to_string(), fork_b(height))
                    .await
                    .0;
                state.process_scan_boxes().await.unwrap();
                let quarantined = state.reserve_storage.get_all_quarantined().unwrap();
                if warm {
                    assert!(state.reserve_tracker.get_reserve(&x).is_ok(), "height {height}");
                    assert!(state.reserve_tracker.get_reserve(&t).is_err(), "height {height}");
                    assert!(quarantined.is_empty(), "height {height}");
                } else if height == 1_000 {
                    assert!(state.reserve_tracker.get_reserve(&x).is_err());
                    assert!(state.reserve_tracker.get_reserve(&t).is_ok());
                    assert!(quarantined.is_empty());
                } else if height == 1_000 + SPENT_REMOVAL_DEPTH {
                    assert!(state.reserve_tracker.get_reserve(&t).is_err());
                    assert!(quarantined.is_empty());
                } else {
                    assert!(state.reserve_tracker.get_reserve(&x).is_err());
                    assert_eq!(quarantined.len(), 1);
                    assert_eq!(quarantined[0].box_id, x);
                }
            }
            drop(state);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Round 8 (review LOW-1): an index height above the node's `/info`
    /// height, which the loop read just before the cycle, by more than
    /// INFO_HEIGHT_MARGIN skips the cycle and leaves the went-back mark where
    /// it was, so one implausible answer (here 10^9, or u64::MAX) does not
    /// make every later cycle skip as "went back". Within the margin it runs.
    #[tokio::test]
    async fn test_an_index_above_the_info_height_skips_the_cycle() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let listed = serde_json::json!([scanned_box_json(
            &tracked_box,
            "c0c0",
            1_000_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None
        )])
        .to_string();
        let mut state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
        insert_tracked_reserve(&state, &tracked_box, owner);
        state.inner.lock().await.current_height = 1_000;
        for (indexed, full, runs, mark) in [
            (1_000_000_000, 1_000_000_000, false, None),
            (u64::MAX, u64::MAX, false, None),
            (1_000, 1_000, true, Some(1_000)),
            (1_003, 1_003, false, Some(1_000)),
            (1_000_000_000, 1_000_000_000, false, Some(1_000)),
            (1_002, 1_002, true, Some(1_002)),
        ] {
            let (addr, hits) = spawn_counting_mock_node(
                listed.clone(),
                std::sync::Arc::new(HashMap::from([indexed_route(indexed, full)])),
            )
            .await;
            let skipped = state.skipped_cycles();
            state = on_node_at(state, addr);
            state.process_scan_boxes().await.unwrap();
            let scanned = hits
                .lock()
                .unwrap()
                .contains_key("/blockchain/box/unspent/byAddress");
            assert_eq!(scanned, runs, "index {indexed}");
            assert_eq!(state.skipped_cycles() - skipped, u64::from(!runs), "index {indexed}");
            assert_eq!(state.nft_cache().index_height_seen, mark, "index {indexed}");
            assert!(state.reserve_tracker.get_reserve(&tracked_box).is_ok());
            assert!(state.nft_cache().unknown_since.is_empty());
        }
        // The next block: the node's /info moves on, and so may the index.
        state.inner.lock().await.current_height = 1_001;
        let (addr, hits) = spawn_counting_mock_node(
            listed,
            std::sync::Arc::new(HashMap::from([indexed_route(1_003, 1_003)])),
        )
        .await;
        let state = on_node_at(state, addr);
        state.process_scan_boxes().await.unwrap();
        assert!(hits.lock().unwrap().contains_key("/blockchain/box/unspent/byAddress"));
        assert_eq!(state.nft_cache().index_height_seen, Some(1_003));
    }

    /// Round 8 (operator: refuse to start; was review LOW-2): a tracked reserve
    /// record that does not decode makes the start fail: no scanner state, an
    /// error naming the record's key (not its contents) and saying how to
    /// recover, and nothing pruned or written, so the stored NFT facts are all
    /// still there for the start after the repair. With the record removed the
    /// start works and the reserve and its NFT load. Without the removed
    /// reserves, emissions are not pruned.
    #[tokio::test]
    async fn test_an_undecodable_tracked_reserve_refuses_the_start() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let t = "11".repeat(32);
        let bad = "5a".repeat(32);
        let dir = restart_dir("nft_facts_unloaded");
        let node = spawn_mock_node("[]".to_string(), Default::default()).await;
        {
            let state = open_at(&dir, node);
            insert_tracked_reserve(&state, &t, owner);
            state
                .nft_cache()
                .singleton
                .insert(TEST_RESERVE_NFT.to_string(), true);
            state.remember_nft(&t, Some(TEST_RESERVE_NFT.to_string()));
            state
                .reserve_storage
                .insert_raw_reserve(bad.as_bytes(), b"{\"secret\":\"not a reserve\"}");
        }
        let expected_boxes = HashMap::from([(t.clone(), TEST_RESERVE_NFT.to_string())]);
        let expected_emissions = HashMap::from([(TEST_RESERVE_NFT.to_string(), 1)]);
        let refused = ServerState::new(
            NodeConfig {
                node_url: format!("http://{}", node),
                reserve_contract_p2s: Some("test_p2s".to_string()),
                ..Default::default()
            },
            &dir,
        );
        let Err(ScannerError::ReservesUnreadable(message)) = refused else {
            panic!("the start must fail");
        };
        assert!(
            message.starts_with("Refusing to start: 1 tracked reserve record(s) in "),
            "{message}"
        );
        assert!(message.contains(&format!("keys: {bad}.")), "{message}");
        assert!(message.contains("/var/backups/basis-tracker"), "{message}");
        assert!(!message.contains("not a reserve") && !message.contains(&t), "{message}");
        {
            let storage = ReserveStorage::open(&dir.join("reserves")).unwrap();
            let facts = storage.nft_facts().unwrap();
            assert_eq!(facts.box_nft, expected_boxes);
            assert_eq!(facts.emission, expected_emissions);
            storage.remove_reserve(&bad).unwrap();
        }
        let state = open_at(&dir, node);
        assert!(state.reserve_tracker.get_reserve(&t).is_ok());
        assert_eq!(
            state.nft_cache().box_nft.get(&t),
            Some(&Some(TEST_RESERVE_NFT.to_string()))
        );
        assert_eq!(state.reserve_storage.nft_facts().unwrap().box_nft, expected_boxes);
        drop(state);

        // The removed reserves did not load: an emission no box holds stays.
        let storage = ReserveStorage::open(&dir.join("emissions_only")).unwrap();
        let unheld = "78".repeat(32);
        storage.store_nft_emission(&unheld, 1).unwrap();
        let mut cache = NftCache::default();
        load_nft_facts(&storage, &Default::default(), false, &mut cache);
        assert_eq!(storage.nft_facts().unwrap().emission.len(), 1);
        let mut cache = NftCache::default();
        load_nft_facts(&storage, &Default::default(), true, &mut cache);
        assert!(storage.nft_facts().unwrap().emission.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Round 8 (review LOW-4): a failed write of a tracked box's NFT, or of
    /// its singleton verdict, is tried again the next time the box is seen
    /// (each cycle that lists it), not only when the value changes.
    #[tokio::test]
    async fn test_a_failed_nft_fact_write_is_tried_again() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let t = "11".repeat(32);
        let listed = serde_json::json!([scanned_box_json(
            &t,
            "c0c0",
            1_000_000_000,
            &[(TEST_RESERVE_NFT, 1)],
            None
        )])
        .to_string();
        let mut state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
        insert_tracked_reserve(&state, &t, owner);
        state
            .nft_cache()
            .singleton
            .insert(TEST_RESERVE_NFT.to_string(), true);
        state.reserve_storage.fail_nft_fact_writes(true);
        for (height, failing) in [(1_000, true), (1_001, true), (1_002, false)] {
            state.reserve_storage.fail_nft_fact_writes(failing);
            let routes = HashMap::from([indexed_route(height, height)]);
            state = on_node(state, listed.clone(), routes).await.0;
            state.process_scan_boxes().await.unwrap();
            assert!(state.reserve_tracker.get_reserve(&t).is_ok());
            let facts = state.reserve_storage.nft_facts().unwrap();
            assert_eq!(facts.box_nft.is_empty(), failing, "height {height}");
            assert_eq!(facts.emission.is_empty(), failing, "height {height}");
        }
        assert_eq!(
            state.reserve_storage.nft_facts().unwrap().box_nft,
            HashMap::from([(t.clone(), TEST_RESERVE_NFT.to_string())])
        );
    }

    /// Round 8 (review 5): the removal clocks saturate. A tracked box unknown
    /// to the index and a removed record, both counting from 5 below
    /// u64::MAX: the cycle there keeps both (with plain additions it would
    /// panic: tests and release builds check overflow), and the clocks run
    /// out at u64::MAX itself.
    #[tokio::test]
    async fn test_removal_clocks_saturate_at_the_top() {
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        let removed_box = "71".repeat(32);
        let mut state = mock_state(spawn_mock_node("[]".to_string(), Default::default()).await);
        insert_tracked_reserve(&state, &tracked_box, owner);
        state.remember_nft(&tracked_box, Some(TEST_RESERVE_NFT.to_string()));
        insert_tracked_reserve(&state, &removed_box, owner);
        let record = state.reserve_tracker.get_reserve(&removed_box).unwrap();
        state.reserve_tracker.remove_reserve(&removed_box).unwrap();
        state.reserve_storage.remove_reserve(&removed_box).unwrap();
        let removed = RemovedReserve {
            record,
            nft: Some("2f".repeat(32)),
            removed_at: 0,
            removed_height: Some(u64::MAX - 5),
        };
        state.reserve_storage.store_removed(&removed).unwrap();
        state.nft_cache().removed.insert(removed_box.clone(), removed);
        for (height, kept) in [(u64::MAX - 5, true), (u64::MAX - 1, true), (u64::MAX, false)] {
            let routes = HashMap::from([indexed_route(height, height)]);
            state = on_node(state, "[]".to_string(), routes).await.0;
            state.process_scan_boxes().await.unwrap();
            assert_eq!(state.skipped_cycles(), 0, "height {height}");
            assert_eq!(
                state.reserve_tracker.get_reserve(&tracked_box).is_ok(),
                kept,
                "height {height}"
            );
            assert_eq!(
                state.nft_cache().removed.contains_key(&removed_box),
                kept,
                "height {height}"
            );
            if kept {
                assert_eq!(
                    state.nft_cache().unknown_since.get(&tracked_box).copied(),
                    Some(u64::MAX - 5)
                );
            }
        }
    }

    /// Round 8 (review 6): the singleton verdict of a root candidate's NFT is
    /// cached but not stored: here a junk root whose NFT has emission 1 and
    /// whose creating transaction spends no input of the R4 key is
    /// quarantined, and `reserve_nft_emissions` stays empty.
    #[tokio::test]
    async fn test_a_junk_roots_singleton_is_not_stored() {
        let scan_box = c4_test_box();
        let other_key = hex::encode(basis_core::impls::generate_keypair().1);
        let routes = HashMap::from([
            (
                scan_box.transaction_id.clone(),
                tx_json(
                    &scan_box.transaction_id,
                    &[(
                        &"33".repeat(32),
                        "some_address",
                        &"44".repeat(32),
                        &p2pk_ergo_tree(&other_key),
                    )],
                ),
            ),
            token_route(TEST_RESERVE_NFT, 1),
        ]);
        let state = mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(routes)).await);
        let info = state
            .parse_reserve_box(&scan_box, ReserveContractKind::Erg, "test_p2s")
            .unwrap();
        assert!(matches!(
            state.admit_reserve_box(&scan_box, &info, "test_p2s").await,
            ReserveAdmission::Quarantined { .. }
        ));
        assert_eq!(state.nft_cache().singleton.get(TEST_RESERVE_NFT), Some(&true));
        let facts = state.reserve_storage.nft_facts().unwrap();
        assert!(facts.emission.is_empty(), "{facts:?}");
        assert!(facts.box_nft.is_empty(), "{facts:?}");
    }
}
