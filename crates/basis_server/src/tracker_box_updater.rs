//! Tracker Box Updater Service
//!
//! This module implements a background service that periodically updates the R4 and R5 register values
//! of the tracker box every 10 minutes. The update transaction is built and signed in this process
//! with `ergo.tracker_secret_key` and submitted through the node's public `POST /transactions`;
//! no node wallet endpoint is used.

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

/// Shared state for the tracker box updater
#[derive(Debug, Clone)]
pub struct SharedTrackerState {
    pub avl_root_digest: Arc<RwLock<[u8; 33]>>,
    pub tracker_pubkey: Arc<RwLock<[u8; 33]>>,
    pub tracker_box_id: Arc<RwLock<Option<String>>>,
    pub tracker_nft_id: Arc<RwLock<Option<String>>>,
    pub confirmed: Arc<RwLock<ConfirmedState>>,
    pub pending: Arc<RwLock<PendingState>>,
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
}

impl std::fmt::Debug for TrackerBoxUpdateConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackerBoxUpdateConfig")
            .field("wallet_node_url", &self.wallet_node_url)
            .field(
                "wallet_api_key",
                &self.wallet_api_key.as_ref().map(|_| "<redacted>"),
            )
            .field("scanner_node_url", &self.scanner_node_url)
            .field(
                "scanner_api_key",
                &self.scanner_api_key.as_ref().map(|_| "<redacted>"),
            )
            .field("update_interval_seconds", &self.update_interval_seconds)
            .field("fee", &self.fee)
            .field("change_address", &self.change_address)
            .field(
                "tracker_secret_key",
                &self.tracker_secret_key.as_ref().map(|_| "<redacted>"),
            )
            .field("min_confirmation_depth", &self.min_confirmation_depth)
            .field(
                "reserve_contract_addresses",
                &self.reserve_contract_addresses,
            )
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
    /// responses but not on `/wallet/boxes/unspent` inner `box` objects.
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

/// Tracker box updater service
pub struct TrackerBoxUpdater;

/// Number of consecutive update cycles in which a submitted update transaction
/// may be missing from the node (mempool and blockchain) before it is treated
/// as dropped/rejected and the pending notes are reverted. With the default
/// 600s update interval this bounds the stall to roughly 30 minutes.
const MAX_PENDING_MISSING_CYCLES: u32 = 3;

/// Whether a pending update transaction that the node has not seen for
/// `missing_cycles` consecutive cycles should be treated as dropped/rejected
/// (and the pending notes reverted so a fresh update can be submitted).
fn pending_tx_is_dropped(missing_cycles: u32) -> bool {
    missing_cycles >= MAX_PENDING_MISSING_CYCLES
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
        let mut ticker = interval(Duration::from_secs(config.update_interval_seconds));

        let mut last_submitted_digest: Option<[u8; 33]> = None;
        let mut pending_tx: Option<(String, [u8; 33])> = None;
        // Consecutive cycles in which the pending update tx was not found on the
        // node (neither mempool nor blockchain). A dropped/rejected tx would
        // otherwise stay `pending` forever and block all future updates
        // (issue #15 S6).
        let mut pending_missing_cycles: u32 = 0;

        info!(
            "Tracker box updater started with {}s interval",
            config.update_interval_seconds
        );

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown_rx.recv() => {
                    info!("Tracker box updater received shutdown signal, stopping");
                    return Ok(());
                }
            }

            if let Some((tx_id, expected_digest)) = pending_tx.clone() {
                match Self::check_transaction_confirmation(&config, &tx_id).await {
                    Ok(true) => {
                        // Look up the confirming box to record its height/id.
                        let (box_id, height) =
                            match Self::fetch_tracker_box_summary(&config, &tx_id).await {
                                Ok(summary) => summary,
                                Err(e) => {
                                    error!(
                                        "Failed to fetch confirming box for {}: {}. Will retry.",
                                        tx_id, e
                                    );
                                    continue;
                                }
                            };

                        // Require a minimum on-chain depth (presence in a block
                        // alone is not confirmation) before promoting pending
                        // notes to Confirmed.
                        if config.min_confirmation_depth > 1 {
                            match Self::get_node_height(&config).await {
                                Ok(current) => {
                                    let depth = confirmation_depth(current as u64, height);
                                    if depth < config.min_confirmation_depth {
                                        info!(
                                            "Transaction {} included at height {} (depth {}/{}), waiting for more confirmations...",
                                            tx_id, height, depth, config.min_confirmation_depth
                                        );
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to fetch node height for depth check of {}: {}. Will retry.",
                                        tx_id, e
                                    );
                                    continue;
                                }
                            }
                        }

                        info!("Transaction {} confirmed on chain. Update complete.", tx_id);
                        last_submitted_digest = Some(expected_digest);
                        pending_missing_cycles = 0;

                        shared_state.set_confirmed(expected_digest, box_id.clone(), height);
                        shared_state.clear_pending();
                        pending_tx = None;

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

                        // Issue #17 phase 2: with the from-edge decrease now
                        // confirmed, evaluate staged exchanges (apply the
                        // to-edge increase or cancel if the reserve changed).
                        Self::process_pending_exchanges(&config, &cmd_tx).await;
                    }
                    Ok(false) => {
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
                                "Transaction {} still pending, waiting for next cycle...",
                                tx_id
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

            let current_digest = shared_state.get_avl_root_digest();
            let tracker_pubkey = shared_state.get_tracker_pubkey();

            if current_digest == [0u8; 33] {
                info!("AVL root digest not initialized yet, skipping update");
                continue;
            }

            let tracker_box = match Self::find_tracker_box(&config, &tracker_nft_id).await {
                Ok(box_data) => box_data,
                Err(e) => {
                    error!("Failed to find tracker box: {}", e);
                    continue;
                }
            };

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
                            info!("On-chain tracker box already has current AVL root digest");
                            last_submitted_digest = Some(current_digest);
                            continue;
                        }
                    }
                }
            }

            // If a previous submission for a different digest is still pending
            // and never confirmed, skip submitting a new one (the confirmation
            // check at the top of the loop handles the in-flight tx).
            if let Some(last) = last_submitted_digest {
                if last == current_digest {
                    info!("AVL root digest unchanged, skipping redundant update");
                    continue;
                }
            }

            if !tracker_box_spendable {
                continue;
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

    /// Fetch a minimal summary (box_id, creation_height) for a tracker box by
    /// spending transaction id. Falls back to the supplied tx id on error.
    async fn fetch_tracker_box_summary(
        config: &TrackerBoxUpdateConfig,
        tx_id: &str,
    ) -> Result<(String, u64), TrackerBoxUpdaterError> {
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

        // The new tracker box is the first output of the update transaction.
        if let Some(outputs) = body.get("outputs").and_then(|o| o.as_array()) {
            if let Some(first) = outputs.first() {
                let box_id = first
                    .get("boxId")
                    .and_then(|b| b.as_str())
                    .unwrap_or(tx_id)
                    .to_string();
                let height = first
                    .get("creationHeight")
                    .and_then(|h| h.as_u64())
                    .unwrap_or(0);
                return Ok((box_id, height));
            }
        }

        Ok((tx_id.to_string(), 0))
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

    /// Check if a transaction has been confirmed on-chain by querying the blockchain API
    pub async fn check_transaction_confirmation(
        config: &TrackerBoxUpdateConfig,
        tx_id: &str,
    ) -> Result<bool, TrackerBoxUpdaterError> {
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

        match response.status().as_u16() {
            200 => Ok(true),
            404 => Ok(false),
            status => {
                let body = response.text().await.unwrap_or_default();
                Err(TrackerBoxUpdaterError::HttpError(format!(
                    "HTTP {} checking transaction: {}",
                    status, body
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

/// Build the transaction that commits `avl_root_digest` to the tracker box.
///
/// - inputs: `[tracker box, fee boxes...]`, empty context extensions, no data inputs;
/// - output 0: the new tracker box: same value and script as the old one, created at
///   `height`, tracker NFT first and then the old box's other tokens, R4 = tracker pk,
///   R5 = AVL tree with `avl_root_digest`, R6 = tracker NFT id, any R7+ copied;
/// - output 1: the miner fee;
/// - output 2: change (fee inputs minus the fee) to `change_tree`, without tokens, when there
///   is any.
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
    use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
    use ergo_lib::ergotree_ir::chain::ergo_box::{
        BoxTokens, ErgoBoxCandidate, NonMandatoryRegisterId, NonMandatoryRegisters,
    };
    use ergo_lib::ergotree_ir::chain::token::{Token, TokenId};
    use ergo_lib::ergotree_ir::ergo_tree::ErgoTree;
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
    let change = fee_total - fee;

    let fee_tree_bytes = hex::decode(ergo_lib::wallet::miner_fee::MINERS_FEE_BASE16_BYTES)
        .map_err(|e| ser("fee tree", e.to_string()))?;
    let fee_tree =
        ErgoTree::sigma_parse_bytes(&fee_tree_bytes).map_err(|e| ser("fee tree", e.to_string()))?;
    let value = |what: &str, v: u64| BoxValue::try_from(v).map_err(|e| ser(what, e.to_string()));

    let mut outputs = vec![
        ErgoBoxCandidate {
            value: tracker_box.value,
            ergo_tree: tracker_box.ergo_tree.clone(),
            tokens: Some(new_tokens),
            additional_registers: registers,
            creation_height: height,
        },
        ErgoBoxCandidate {
            value: value("fee", fee)?,
            ergo_tree: fee_tree,
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: height,
        },
    ];
    if change > 0 {
        outputs.push(ErgoBoxCandidate {
            value: value("change", change)?,
            ergo_tree: change_tree.clone(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: height,
        });
    }

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
            ..Default::default()
        };
        let printed = format!("{config:?}");
        assert!(!printed.contains(&hex::encode(secret)));
        assert!(!printed.contains("92, 92, 92"), "{printed}");
        assert!(!printed.contains("wallet-key"));
        assert!(printed.contains("<redacted>"));
    }
}
