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
    persistence::{QuarantinedReserve, ReserveStorage, ScannerMetadataStorage},
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
/// (round 6c). The checks walk at most `LINEAGE_WALK_DEPTH` transactions per
/// box, and only boxes holding a tracked reserve's NFT (or root candidates)
/// are walked; past the budget a check gives no verdict and is retried next
/// cycle, and a successor whose NFT is a singleton is still followed.
const LINEAGE_REQUESTS_PER_CYCLE: usize = 512;

/// What the scanner knows about reserve NFTs (round 6c, P1-2), in memory only:
/// it is read back from the node after a restart.
#[derive(Debug, Default)]
pub struct NftCache {
    /// Reserve box id -> its reserve NFT (`None`: it holds none).
    box_nft: std::collections::HashMap<String, Option<String>>,
    /// NFT id -> whether its emission is 1.
    singleton: std::collections::HashMap<String, bool>,
}

/// A box as the blockchain index gives it: an input of
/// `GET /blockchain/transaction/byId`, or `GET /blockchain/box/byId`.
#[derive(Debug, Clone)]
struct ChainBox {
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
    /// Node requests of the lineage checks in the current scan cycle.
    pub lineage_requests: Arc<std::sync::atomic::AtomicUsize>,
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

        // Load existing reserves from database
        if let Ok(existing_reserves) = reserve_storage.get_all_reserves() {
            let reserves_count = existing_reserves.len();
            for reserve in existing_reserves {
                if let Err(e) = reserve_tracker.update_reserve(reserve) {
                    warn!("Failed to load reserve from database: {}", e);
                }
            }
            info!("Loaded {} reserves from database", reserves_count);
        }

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
            nft_cache: Arc::default(),
            lineage_requests: Arc::default(),
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
                let response = self
                    .request_builder(reqwest::Method::POST, &url)
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
    async fn fetch_tx_inputs(&self, tx_id: &str) -> Result<Vec<ChainBox>, ScannerError> {
        self.take_node_budget(tx_id)?;
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
    async fn fetch_indexed_box(&self, box_id: &str) -> Result<Option<ChainBox>, ScannerError> {
        self.take_node_budget(box_id)?;
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
        let Some(chain_box) = self.fetch_indexed_box(box_id).await? else {
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
    async fn is_singleton_nft(&self, nft: &str) -> Result<bool, ScannerError> {
        if let Some(singleton) = self.nft_cache().singleton.get(nft) {
            return Ok(*singleton);
        }
        self.take_node_budget(nft)?;
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
        self.nft_cache()
            .singleton
            .insert(nft.to_string(), singleton);
        Ok(singleton)
    }

    fn nft_cache(&self) -> std::sync::MutexGuard<'_, NftCache> {
        self.nft_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn remember_nft(&self, box_id: &str, nft: Option<String>) {
        self.nft_cache().box_nft.insert(box_id.to_string(), nft);
    }

    /// Count one node request of the lineage checks against this cycle's
    /// budget (round 6c): junk candidates cannot make a cycle unbounded.
    fn take_node_budget(&self, what: &str) -> Result<(), ScannerError> {
        let used = self
            .lineage_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if used >= LINEAGE_REQUESTS_PER_CYCLE {
            return Err(ScannerError::NodeError(format!(
                "lineage request budget of this cycle ({}) is used up before {}",
                LINEAGE_REQUESTS_PER_CYCLE, what
            )));
        }
        Ok(())
    }

    /// Verdict on `scan_box`, which holds the reserve NFT `nft` of the tracked
    /// box `known_box_id`: `Ok(true)` it continues that reserve, `Ok(false)` it
    /// does not (quarantine), `Err` no verdict this cycle (retry).
    ///
    /// Both reserve contracts keep the token list, the R4 owner and the R6
    /// tracker NFT of the output a reserve input names (`selfPreserved`), and
    /// only the owner's signature takes tokens out (refund completion). A top-up
    /// needs no signature, so anyone may add other reserve-contract outputs with
    /// the owner's R4 to a transaction spending the reserve (round 6b); only the
    /// box holding the NFT continues the lineage.
    ///
    /// 1. The tracked box must hold the NFT with the same R4 and R6. When the
    ///    transaction that spent it created `scan_box`, that is the successor
    ///    (no transaction is read, however large).
    /// 2. Otherwise the walk goes back from `scan_box` through the creating
    ///    transactions, each time to the input that holds the NFT at
    ///    `tokens(0)` with amount 1, the same R4 and R6, and is the tracked box
    ///    or at the reserve contract, until that input is the tracked box or was
    ///    created by the transaction that spent it (at most
    ///    `LINEAGE_WALK_DEPTH` transactions). No such input: not a successor.
    /// 3. When the walk gives no verdict (depth used up, a transaction over the
    ///    body cap, a node error; round 6c P1-1/P1-2), a singleton NFT decides:
    ///    with the tracked box spent, no other box can hold it.
    async fn is_lineage_successor(
        &self,
        scan_box: &ScanBox,
        nft: &str,
        known_box_id: &str,
        contract_address: &str,
    ) -> Result<bool, ScannerError> {
        let (Some(r4), Some(r6)) = (
            scan_box.additional_registers.get("R4"),
            scan_box.additional_registers.get("R6"),
        ) else {
            return Ok(false);
        };
        let Some(known) = self.fetch_indexed_box(known_box_id).await? else {
            return Err(ScannerError::NodeError(format!(
                "Tracked reserve box {} is not in the blockchain index",
                known_box_id
            )));
        };
        if !known.is_reserve_box_of(nft, r4, r6) {
            return Ok(false);
        }
        if known.spent_tx.is_empty() {
            // The index has not seen the spend yet, or the token is held more
            // than once: no verdict.
            return Err(ScannerError::NodeError(format!(
                "Tracked reserve box {} is unspent while box {} holds its reserve NFT",
                known_box_id, scan_box.box_id
            )));
        }
        if scan_box
            .transaction_id
            .eq_ignore_ascii_case(&known.spent_tx)
        {
            return Ok(true);
        }

        let walked = self
            .walk_to_spender(
                scan_box,
                nft,
                r4,
                r6,
                known_box_id,
                &known.spent_tx,
                contract_address,
            )
            .await;
        match walked {
            Ok(Some(verdict)) => Ok(verdict),
            no_verdict => {
                let why = match no_verdict {
                    Err(e) => e.to_string(),
                    _ => format!("no verdict within {} transactions", LINEAGE_WALK_DEPTH),
                };
                if self.is_singleton_nft(nft).await? {
                    info!(
                        "Reserve box {} follows tracked box {} by its singleton NFT {} ({})",
                        scan_box.box_id, known_box_id, nft, why
                    );
                    Ok(true)
                } else {
                    Err(ScannerError::NodeError(format!(
                        "lineage of box {} to {}: {}; its NFT {} is not a singleton",
                        scan_box.box_id, known_box_id, why, nft
                    )))
                }
            }
        }
    }

    /// Step 2 of [`Self::is_lineage_successor`]: `Ok(None)` when the depth runs
    /// out.
    #[allow(clippy::too_many_arguments)]
    async fn walk_to_spender(
        &self,
        scan_box: &ScanBox,
        nft: &str,
        r4: &str,
        r6: &str,
        known_box_id: &str,
        spent_by: &str,
        contract_address: &str,
    ) -> Result<Option<bool>, ScannerError> {
        let mut tx_id = scan_box.transaction_id.clone();
        for _ in 0..LINEAGE_WALK_DEPTH {
            let inputs = self.fetch_tx_inputs(&tx_id).await?;
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
                // The NFT came in from elsewhere (or was minted here).
                return Ok(Some(false));
            };
            if normalized_box_id(&carrier.box_id) == known_box_id
                || carrier.creating_tx.eq_ignore_ascii_case(spent_by)
            {
                return Ok(Some(true));
            }
            if carrier.creating_tx.is_empty() {
                return Ok(Some(false));
            }
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
            let inputs = self.fetch_tx_inputs(&tx_id).await?;
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
            let clean = carrier
                .registers
                .get("R5")
                .is_some_and(|r5| r5.eq_ignore_ascii_case(&empty_tree))
                && carrier.registers.get("R7").is_none_or(|r7| {
                    r7.starts_with("05") && decode_ergo_long_register(Some(r7)) == 0
                });
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
    /// 1. the currently tracked box itself (refresh), or
    /// 2. a C4-clean root for an (owner, denomination) with no tracked reserve,
    ///    holding a singleton reserve NFT, made by the R4 owner (its creating
    ///    transaction spends a P2PK input of the R4 key, or it descends by its
    ///    NFT through top-ups from such a box), or
    /// 3. the successor of a tracked box of its (owner, denomination): it holds
    ///    that box's reserve NFT at `tokens(0)` with amount 1, and the same R4
    ///    and R6 (round 6b/6c, see `is_lineage_successor`).
    ///
    /// A box holding no tracked reserve's NFT while the owner has a tracked
    /// reserve in the denomination is quarantined at once, with no walk and no
    /// retry (round 6c, P1-2): a newcomer never displaces a tracked reserve.
    /// Anything else is quarantined too, so a dust duplicate with the victim's
    /// key in R4 can never turn `resolve_issuer_reserve` ambiguous and block
    /// the issuer. A box already persisted as quarantined stays quarantined
    /// until an operator releases it.
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

        if tracked.is_empty() {
            // Root candidate: cheap C4 setup checks first (they include the
            // reserve NFT), then the node calls.
            if let Some(violation) = Self::root_setup_violation(scan_box, reserve_info) {
                return ReserveAdmission::Quarantined { reason: violation };
            }
            let Some(nft) = scan_box_nft(scan_box) else {
                return ReserveAdmission::Quarantined {
                    reason: format!("Reserve box {} holds no reserve NFT", box_id),
                };
            };
            match self.is_singleton_nft(&nft).await {
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
            let proof = self
                .has_owner_root(scan_box, &nft, &reserve_info.owner_pubkey, contract_address)
                .await;
            return match proof {
                Ok(true) => ReserveAdmission::Admitted,
                Ok(false) => ReserveAdmission::Quarantined {
                    reason: format!(
                        "reserve root {} for owner {} was created by a transaction spending no P2PK input of the R4 key, \
                         and its NFT does not lead back through top-ups to a box that was; R4 is not authenticated \
                         on-chain, so this is likely a dust-box blocking attempt (issue #19)",
                        box_id, reserve_info.owner_pubkey
                    ),
                },
                Err(e) => retry("Ownership check", e),
            };
        }

        // The owner has a tracked reserve in this denomination: only the box
        // holding its NFT may continue it.
        let newcomer = |why: String| {
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
            return newcomer("holds no reserve NFT at tokens(0)".to_string());
        };
        let mut anchor = None;
        let mut unknown = None;
        for reserve in &tracked {
            match self.tracked_nft(&reserve.box_id).await {
                Ok(Some(tracked_nft)) if tracked_nft == nft => {
                    anchor = Some(reserve.box_id.clone());
                    break;
                }
                Ok(_) => {}
                Err(e) => unknown = Some(e),
            }
        }
        let Some(anchor) = anchor else {
            return match unknown {
                Some(e) => retry("Reading the tracked reserve NFT", e),
                None => newcomer(format!(
                    "does not hold the tracked reserve NFT (it holds {})",
                    nft
                )),
            };
        };
        match self
            .is_lineage_successor(scan_box, &nft, &anchor, contract_address)
            .await
        {
            Ok(true) => ReserveAdmission::Admitted,
            Ok(false) => newcomer(format!(
                "holds the reserve NFT {} but does not continue the tracked box {} through reserve boxes",
                nft, anchor
            )),
            Err(e) => retry("Lineage check", e),
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
        }
    }

    /// Process scan boxes and update reserve tracker
    pub async fn process_scan_boxes(&self) -> Result<(), ScannerError> {
        info!("Starting to process scan boxes...");
        let scan_boxes = self.get_scan_boxes().await?;
        info!("Retrieved {} scan boxes to process", scan_boxes.len());
        self.lineage_requests
            .store(0, std::sync::atomic::Ordering::Relaxed);

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

        // Round 6c (b): with no valid box in the scan the snapshot is not taken
        // as authoritative (manually inserted reserves on a local test node), so
        // a reserve absent from it is removed only when the chain shows it spent
        // (the last reserve withdrawn by refund completion, say). Otherwise an
        // absent reserve is spent.
        let authoritative = !current_box_ids.is_empty();
        if !authoritative {
            info!("Scan returned no valid box: absent reserves are removed only when the chain shows them spent");
        }
        for reserve in all_reserves {
            if current_box_ids.contains(&reserve.box_id)
                || quarantined_box_ids.contains(&reserve.box_id)
            {
                continue;
            }
            // A successor candidate is pending a lineage retry for this
            // (owner, denomination): keep the tracked box so the lineage anchor
            // is not lost (issue #19), but only while it is the owner's only
            // reserve there. Once a successor holding its NFT is tracked, a
            // pending check never keeps a spent box next to it (round 6c, P1-2).
            let denomination = reserve.denomination();
            if pending_lineages.iter().any(|(owner, pending_denom)| {
                *owner == reserve.owner_pubkey && Some(pending_denom) == denomination.as_ref()
            }) {
                let reserves_there = self
                    .reserve_tracker
                    .get_reserves_by_owner(&reserve.owner_pubkey)
                    .into_iter()
                    .filter(|r| r.denomination() == denomination)
                    .count();
                if reserves_there <= 1 {
                    info!(
                        "Keeping reserve {} (successor lineage check pending)",
                        reserve.box_id
                    );
                    continue;
                }
            }
            if !authoritative {
                match self.fetch_indexed_box(&reserve.box_id).await {
                    Ok(Some(chain_box)) if !chain_box.spent_tx.is_empty() => {}
                    Ok(_) => continue,
                    Err(e) => {
                        warn!(
                            "Cannot tell whether reserve {} is spent ({}); keeping it",
                            reserve.box_id, e
                        );
                        continue;
                    }
                }
            }
            info!(
                "Removing spent reserve: {} (not found in current scan)",
                reserve.box_id
            );
            // Remove from in-memory tracker
            if let Err(e) = self.reserve_tracker.remove_reserve(&reserve.box_id) {
                warn!("Failed to remove reserve {}: {}", reserve.box_id, e);
            } else {
                self.nft_cache().box_nft.remove(&reserve.box_id);
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
                let body = body.to_string();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = socket.read(&mut buf).await;
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

        assert_eq!(
            seen_offsets.lock().unwrap().as_slice(),
            &[0u64, RESERVE_BOX_PAGE_LIMIT],
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
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let boxes_body = boxes_body.clone();
                let txs = txs.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let request_line = request.lines().next().unwrap_or_default();
                    let path = request_line.split_whitespace().nth(1).unwrap_or_default();
                    // `txs` keys are transaction ids, or full paths for the
                    // box and token index (404 when absent).
                    let (status, body) = if let Some(body) = txs.get(path) {
                        ("200 OK", body.clone())
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
                        ("200 OK", boxes_body)
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
        addr
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
        serde_json::json!({ "id": tx_id, "inputs": inputs, "outputs": [] }).to_string()
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
        chain_box["spentTransactionId"] = serde_json::json!(spent_by);
        (
            format!("/blockchain/box/byId/{}", box_id),
            chain_box.to_string(),
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
        let owner = &VALID_PREFIXED_PUBKEY[2..];
        let tracked_box = "11".repeat(32);
        for spent in [true, false] {
            let spent_by = "cc".repeat(32);
            let routes = HashMap::from([tracked_box_route(
                &tracked_box,
                &[(TEST_RESERVE_NFT, 1)],
                spent.then_some(spent_by.as_str()),
            )]);
            let state =
                mock_state(spawn_mock_node("[]".to_string(), std::sync::Arc::new(routes)).await);
            insert_tracked_reserve(&state, &tracked_box, owner);
            state.process_scan_boxes().await.unwrap();
            assert_eq!(
                state.reserve_tracker.get_reserve(&tracked_box).is_ok(),
                !spent,
                "spent {spent}"
            );
            assert_eq!(
                state
                    .reserve_storage
                    .get_reserve(&tracked_box)
                    .unwrap()
                    .is_some(),
                !spent
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
}
