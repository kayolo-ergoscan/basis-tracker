//! Tracker-assisted 2-phase redemption build/submit endpoints.
//!
//! This mirrors the proven CLI local-sign flow (`basis_cli::commands::transaction`), split across
//! two parties:
//!   * `POST /redemption/build`  — the tracker constructs the unsigned redemption transaction
//!     (same byte layout the node and reserve contract accept, context extension in Scala order),
//!     selects wallet fee inputs, and signs ONLY the fee input(s) locally with its own secret.
//!     It returns the unsigned tx, the fee-signed partial tx, and the sigma-serialized input/data
//!     boxes the client needs to finish signing.
//!   * the client (TUI) adds ONLY the reserve input's `proveDlog(receiver)` proof over the same
//!     `bytes_to_sign`, then calls `POST /redemption/submit` with the fully-signed tx.
//!   * `POST /redemption/submit` — the tracker broadcasts the fully-signed transaction, but only
//!     when its echoed `unsigned_tx` matches a live entry recorded by `/redemption/build`
//!     (single-use, 30-minute expiry) and the signed transaction has the built transaction's id.
//!     The tracker state advance uses the STORED entry values, never caller-supplied amounts
//!     (PR #16 B6).
//!
//! Neither end reorders the reserve-input context extension: the tracker emits it in Scala
//! `ContextExtension` order, so both ends sign an identical `bytes_to_sign`.

// Axum handlers returning `(StatusCode, Json<ApiResponse<..>>)` have a large `Err` variant by
// construction; boxing the error would add noise without benefit here.
#![allow(clippy::result_large_err)]

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use ergo_lib::chain::ergo_state_context::ErgoStateContext;
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::Transaction;
use ergo_lib::ergo_chain_types::Header;
use ergo_lib::ergotree_interpreter::sigma_protocol::prover::ProofBytes;
use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use ergo_lib::wallet::secret_key::SecretKey;

use basis_offchain::ergo_tx::{
    address_to_ergo_tree, build_savl_tree_from_digest, decode_box_id, ergo_tree_to_p2pk_address,
    pubkey_to_address, reorder_reserve_extension_scala, serialize_coll_bytes, serialize_ergo_byte,
    serialize_ergo_long,
};
use basis_offchain::signing::add_input_proof;

use crate::models::{error_response, success_response, ApiResponse};
use crate::{AppState, TrackerCommand};

/// Minimum post-redemption reserve output value (0.001 ERG min box value).
const MIN_RESERVE_REMAINDER: u64 = 1_000_000;
/// Minimum ERG value for the recipient output box when redeeming token-backed reserves.
const TOKEN_RECIPIENT_MIN_VALUE_NANOERG: u64 = 1_000_000;
/// Miner-fee recipient contract from the Scala reference implementation.
const FEE_CONTRACT_TREE: &str = "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304";

// ----- request / response models -----

#[derive(Debug, Deserialize)]
pub struct RedemptionBuildRequest {
    pub issuer_pubkey: String,
    pub recipient_pubkey: String,
    pub amount: u64,
    /// Legacy field, ignored by the server (and optional): the stored note's payment
    /// timestamp is used for the signature, context extension, and reserve tree value
    /// (issue #15 S4 — never sign caller-supplied values).
    #[serde(default)]
    pub timestamp: u64,
    /// Issuer's 65-byte Schnorr signature (hex) over
    /// `signing_message(issuer || receiver || totalDebt || timestamp)`.
    pub issuer_signature: String,
    #[serde(default)]
    pub emergency: bool,
    /// Optional tracker box id. Used only when it equals a tracker box id the tracker itself
    /// knows (its live or last confirmed box); any other value is ignored, so caller input
    /// never reaches a node request.
    #[serde(default)]
    pub tracker_box_id: Option<String>,
    /// Deprecated and ignored. Change always goes to the owner of the tracker's
    /// selected fee box (or the configured change address as fallback); a
    /// caller-supplied address would let anyone drain tracker wallet boxes.
    #[serde(default)]
    pub change_address: Option<String>,
    /// Denomination of the note being redeemed ("erg" or "token:<64-hex>"); default
    /// resolution: the pair's existing note's denomination when unambiguous, else "erg".
    #[serde(default)]
    pub denomination: String,
    /// REQUIRED. When the recipient signed this request, in milliseconds since the Unix epoch.
    /// Must be within [`BUILD_REQUEST_MAX_SKEW_MS`] of the tracker's clock and greater than the
    /// recipient's previous build request.
    #[serde(default)]
    pub request_timestamp: u64,
    /// REQUIRED. The recipient's 65-byte Basis Schnorr signature (hex) over
    /// [`basis_store::schnorr::build_request_message`]`(tracker NFT, issuer, recipient,
    /// denomination, amount, request_timestamp)`. Only the recipient can ask for a build, so
    /// nobody else can spend the pair's build budget.
    #[serde(default)]
    pub receiver_signature: String,
}

#[derive(Debug, Serialize)]
pub struct RedemptionBuildResponse {
    /// Node-canonical unsigned transaction (reserve-input extension in Scala order).
    pub unsigned_tx: Value,
    /// Fee-signed transaction (reserve input proof empty); base for the client to splice the
    /// reserve proof into.
    pub partial_tx: Value,
    /// Sigma-serialized input boxes (hex), in transaction-input order.
    pub input_box_binaries: Vec<String>,
    /// Sigma-serialized data-input boxes (hex).
    pub data_box_binaries: Vec<String>,
    /// Last 10 block headers, newest first: the order the fee inputs were signed with.
    /// `PreHeader::from(headers[0])` and `ErgoStateContext::new(pre_header, headers, ..)` give the
    /// client the same context, so it can finish signing without its own node connection.
    pub headers: Vec<Header>,
    pub reserve_box_id: String,
    pub tracker_box_id: String,
    pub reserve_output_value: u64,
    pub recipient_output_value: u64,
    pub total_debt: u64,
    pub change_amount: u64,
    pub change_address: String,
    pub recipient_address: String,
    pub is_first_redemption: bool,
    pub fee: u64,
    /// Cumulative `already_redeemed` value this redemption inserts into the reserve tree
    /// (previous reserve-tree value + redeemed amount). The client round-trips it to
    /// `/redemption/submit` so the tracker can sync its local reserve tree with the value
    /// that was actually proven on-chain.
    pub new_already_redeemed: u64,
    /// Who pays the miner fee: `"recipient"` (ERG reserves: the fee comes out of the payout,
    /// the transaction spends only the reserve and the tracker signs nothing) or `"tracker"`
    /// (token reserves: tracker fee inputs, signed in `partial_tx`).
    pub fee_paid_by: String,
}

/// `fee_paid_by` of an ERG-reserve build: the miner fee comes out of the payout.
pub const FEE_PAID_BY_RECIPIENT: &str = "recipient";
/// `fee_paid_by` of a token-reserve build: the tracker's fee inputs pay the fee.
pub const FEE_PAID_BY_TRACKER: &str = "tracker";

#[derive(Debug, Clone, Deserialize)]
pub struct RedemptionSubmitRequest {
    pub signed_tx: Value,
    /// The exact `unsigned_tx` value returned by `POST /redemption/build`. Its SHA-256
    /// identifies the pending build entry this submit binds to; without a live entry the
    /// submit is rejected with 409 (PR #16 B6).
    pub unsigned_tx: Value,
    /// DEPRECATED and IGNORED: the issuer is taken from the pending build entry recorded by
    /// `/redemption/build`. Kept on the wire only for client compatibility (PR #16 B6).
    pub issuer_pubkey: String,
    /// DEPRECATED and IGNORED: see `issuer_pubkey`.
    pub recipient_pubkey: String,
    /// DEPRECATED and IGNORED: the redeemed amount is taken from the pending build entry.
    /// Kept on the wire only for client compatibility (PR #16 B6).
    pub redeemed_amount: u64,
    /// DEPRECATED and IGNORED: the cumulative reserve-tree value is taken from the pending
    /// build entry. Kept on the wire only for client compatibility (PR #16 B6).
    pub new_already_redeemed: u64,
}

#[derive(Debug, Serialize)]
pub struct RedemptionSubmitResponse {
    pub tx_id: String,
}

// ----- node client -----

#[derive(Debug, Clone, Deserialize)]
struct NodeAsset {
    #[serde(alias = "tokenId")]
    token_id: String,
    #[allow(dead_code)]
    amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct NodeBox {
    #[serde(alias = "boxId")]
    box_id: String,
    value: u64,
    #[serde(alias = "ergoTree")]
    ergo_tree: String,
    #[serde(default)]
    assets: Vec<NodeAsset>,
    #[serde(default, alias = "additionalRegisters")]
    additional_registers: HashMap<String, String>,
}

impl NodeBox {
    /// The 33-byte reserve AVL tree digest held in R5, if present. R5 serializes as
    /// `0x64 || 33-byte digest || flags || keylen || valuelen`, so the digest is hex chars [2..68].
    fn r5_digest_hex(&self) -> Option<String> {
        let r5 = self.additional_registers.get("R5")?;
        if r5.len() >= 68 && r5.starts_with("64") {
            Some(r5[2..68].to_string())
        } else {
            None
        }
    }
}

struct NodeClient {
    url: String,
    api_key: Option<String>,
}

impl NodeClient {
    /// Node used for chain reads (`/utxo/*` on chain boxes, `/blocks/*`): the
    /// scanner node (`[ergo.scanner]`, extra-indexed).
    fn chain(state: &AppState) -> Self {
        NodeClient {
            url: state
                .config
                .ergo
                .scanner
                .node_url
                .trim_end_matches('/')
                .to_string(),
            api_key: state
                .config
                .ergo
                .scanner
                .api_key
                .clone()
                .filter(|k| !k.is_empty()),
        }
    }

    /// Node that receives broadcasts (`POST /transactions`). Falls back to the
    /// scanner node when `[ergo.wallet]` is not configured. No wallet endpoint is used.
    fn wallet(state: &AppState) -> Self {
        let (url, api_key) = state.config.ergo_wallet_node();
        NodeClient {
            url: url.trim_end_matches('/').to_string(),
            api_key,
        }
    }

    async fn get_json(&self, path: &str) -> Result<Value, String> {
        let client = basis_store::http::bounded_client();
        let url = format!("{}{}", self.url, path);
        let mut req = client.get(&url);
        if let Some(ref k) = self.api_key {
            req = req.header("api_key", k);
        }
        let resp = req.send().await.map_err(|e| format!("GET {url}: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = basis_store::http::read_body_capped(resp)
                .await
                .unwrap_or_default();
            return Err(format!("GET {url} HTTP {status}: {body}"));
        }
        basis_store::http::read_json_capped(resp)
            .await
            .map_err(|e| format!("GET {url} json: {e}"))
    }

    async fn box_binary(&self, box_id: &str) -> Result<String, String> {
        let v = self.get_json(&format!("/utxo/byIdBinary/{box_id}")).await?;
        v["bytes"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| format!("missing 'bytes' for box {box_id}"))
    }

    async fn box_details(&self, box_id: &str) -> Result<NodeBox, String> {
        let v = self.get_json(&format!("/utxo/byId/{box_id}")).await?;
        serde_json::from_value(v).map_err(|e| format!("parse box {box_id}: {e}"))
    }

    /// Token-free boxes locked by `P2PK(tracker_pubkey)`, from the public
    /// `POST /blockchain/box/unspent/byAddress` (no node wallet, no API key). Boxes spent in the
    /// mempool are skipped; token-bearing boxes (the tracker box among them) are never returned,
    /// and neither are `exclude_box_ids`, whatever the index says they hold.
    async fn tracker_fee_boxes(
        &self,
        tracker_pubkey: &[u8; 33],
        enough: u64,
        exclude_box_ids: &[&str],
    ) -> Result<Vec<NodeBox>, String> {
        let address = crate::local_wallet::p2pk_address(tracker_pubkey)?;
        let tree = crate::local_wallet::p2pk_tree_hex(tracker_pubkey);
        let node = crate::local_wallet::NodeEndpoint::new(&self.url, self.api_key.clone());
        let scan =
            crate::local_wallet::scan_fee_boxes(&node, &address, &tree, exclude_box_ids, enough)
                .await?;
        if scan.truncated {
            tracing::warn!(
                "fee box scan of the tracker address stopped after {} pages",
                crate::local_wallet::BY_ADDRESS_MAX_PAGES
            );
        }
        Ok(scan
            .boxes
            .into_iter()
            .map(|b| NodeBox {
                box_id: b.box_id,
                value: b.value,
                ergo_tree: b.ergo_tree,
                assets: Vec::new(),
                additional_registers: b.additional_registers,
            })
            .collect())
    }

    async fn last_headers(&self) -> Result<Vec<Header>, String> {
        let v = self.get_json("/blocks/lastHeaders/10").await?;
        serde_json::from_value(v).map_err(|e| format!("parse last headers: {e}"))
    }

    /// Signing context from the node's last 10 headers: newest first, with the pre-header
    /// taken from the newest. The node lists them oldest first;
    /// [`crate::local_wallet::state_context_from_headers`] orders them, as for the tracker's
    /// own commits.
    async fn state_context(&self) -> Result<ErgoStateContext, String> {
        crate::local_wallet::state_context_from_headers(self.last_headers().await?)
    }

    async fn broadcast(&self, tx: &Value) -> Result<String, String> {
        let client = basis_store::http::bounded_client();
        let url = format!("{}/transactions", self.url);
        let mut req = client.post(&url).json(tx);
        if let Some(ref k) = self.api_key {
            req = req.header("api_key", k);
        }
        let resp = req.send().await.map_err(|e| format!("broadcast: {e}"))?;
        let status = resp.status();
        let body = basis_store::http::read_body_capped(resp)
            .await
            .unwrap_or_default();
        if !status.is_success() {
            return Err(format!("broadcast rejected HTTP {status}: {body}"));
        }
        Ok(parse_broadcast_tx_id(&body))
    }
}

fn parse_broadcast_tx_id(body: &str) -> String {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        match value {
            Value::String(s) => return s,
            Value::Object(map) => {
                if let Some(Value::String(id)) = map.get("id") {
                    return id.clone();
                }
            }
            _ => {}
        }
    }
    body.trim().trim_matches('"').to_string()
}

// ----- pending redemption registry (PR #16 B6) -----

/// How long a pending redemption entry stays usable after `/redemption/build`.
///
/// Generous enough for a client to sign and submit, short enough that a captured build
/// response is not a standing capability. A newer build for the same (issuer, recipient,
/// denomination) replaces the entry earlier (see [`PendingRedemptionRegistry::record`]), so a
/// build that is never submitted (a dry run) neither waits out this time nor blocks the next.
pub const PENDING_REDEMPTION_TTL: Duration = Duration::from_secs(30 * 60);

/// Largest number of outstanding pending entries. Each entry is small and the map is pruned
/// on every call, so this only bounds memory if `/redemption/build` is hammered.
const MAX_PENDING_REDEMPTIONS: usize = 1024;

/// SHA-256 of the canonical JSON serialization of an `unsigned_tx` value.
pub type UnsignedTxFingerprint = [u8; 32];

/// Fingerprint of an unsigned transaction JSON value, as returned in `unsigned_tx` by
/// `/redemption/build` and echoed back to `/redemption/submit`.
///
/// Both sides hash the same `serde_json::Value` type, so the digest is stable for a value the
/// server itself produced; any modification by the caller changes the digest.
pub fn unsigned_tx_fingerprint(unsigned_tx: &Value) -> Result<UnsignedTxFingerprint, String> {
    use sha2::Digest as _;
    let bytes = serde_json::to_vec(unsigned_tx)
        .map_err(|e| format!("failed to serialize unsigned_tx: {e}"))?;
    Ok(sha2::Sha256::digest(&bytes).into())
}

/// Transaction id (hex) of an unsigned transaction JSON value, as the node computes it:
/// `blake2b256` of the bytes to sign, which cover inputs (with context extensions), data
/// inputs and outputs. A signed transaction has the same id as the unsigned one it signs.
pub fn unsigned_tx_id(unsigned_tx: &Value) -> Result<String, String> {
    let unsigned: UnsignedTransaction = serde_json::from_value(unsigned_tx.clone())
        .map_err(|e| format!("unsigned_tx is not a valid unsigned transaction: {e}"))?;
    Ok(String::from(unsigned.id()))
}

/// Server-side state recorded by `/redemption/build` and consumed by `/redemption/submit`.
///
/// Everything that mutates tracker state after a broadcast comes from this entry, never from
/// caller-supplied request fields (PR #16 B6).
#[derive(Debug, Clone)]
pub struct PendingRedemption {
    /// Id of the unsigned transaction the build returned. Submit only accepts a signed
    /// transaction with exactly this id.
    pub unsigned_tx_id: String,
    /// Reserve box the built transaction spends.
    pub reserve_box_id: String,
    /// Issuer (reserve owner) compressed public key, hex.
    pub issuer_pubkey: String,
    /// Recipient (creditor) compressed public key, hex.
    pub recipient_pubkey: String,
    /// Amount redeemed by the built transaction.
    pub redeemed_amount: u64,
    /// Cumulative reserve-tree `already_redeemed` value the build proved on-chain.
    pub new_already_redeemed: u64,
    /// Reserve AVL tree root digest (33 bytes) the build placed in the reserve output's R5.
    pub reserve_r5_digest: Vec<u8>,
    /// Denomination of the note being redeemed.
    pub denomination: basis_store::DenomKey,
    issued_at: Instant,
}

impl PendingRedemption {
    /// Whether `other` redeems the same note: the same (issuer, recipient, denomination).
    fn redeems_same_note(&self, other: &PendingRedemption) -> bool {
        self.issuer_pubkey.eq_ignore_ascii_case(&other.issuer_pubkey)
            && self.recipient_pubkey.eq_ignore_ascii_case(&other.recipient_pubkey)
            && self.denomination == other.denomination
    }

    /// Create an entry stamped with the current time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        unsigned_tx_id: String,
        reserve_box_id: String,
        issuer_pubkey: String,
        recipient_pubkey: String,
        redeemed_amount: u64,
        new_already_redeemed: u64,
        reserve_r5_digest: Vec<u8>,
        denomination: basis_store::DenomKey,
    ) -> Self {
        Self {
            unsigned_tx_id,
            reserve_box_id,
            issuer_pubkey,
            recipient_pubkey,
            redeemed_amount,
            new_already_redeemed,
            reserve_r5_digest,
            denomination,
            issued_at: Instant::now(),
        }
    }
}

/// Registry of outstanding, single-use pending redemptions.
#[derive(Debug, Default)]
pub struct PendingRedemptionRegistry {
    entries: std::sync::Mutex<HashMap<UnsignedTxFingerprint, PendingRedemption>>,
}

impl PendingRedemptionRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a pending redemption for `fingerprint`, valid for [`PENDING_REDEMPTION_TTL`].
    ///
    /// The entry REPLACES any pending entry for the same (issuer, recipient, denomination): only
    /// the newest build of a note can be submitted. Only the recipient can ask for a build (its
    /// signature is checked first), so nobody else can retire a recipient's build this way, and a
    /// build that is never submitted (a dry run, a lost response) does not hold a slot or block
    /// the next build for the pair.
    ///
    /// Returns false when the registry is full, which the caller should surface as a
    /// "try again" rather than silently dropping the entry.
    pub fn record(&self, fingerprint: UnsignedTxFingerprint, entry: PendingRedemption) -> bool {
        let mut entries = self.lock();
        Self::prune(&mut entries);
        entries.retain(|fp, pending| *fp == fingerprint || !pending.redeems_same_note(&entry));
        if entries.len() >= MAX_PENDING_REDEMPTIONS && !entries.contains_key(&fingerprint) {
            return false;
        }
        entries.insert(fingerprint, entry);
        true
    }

    /// Validate `signed_tx` against the pending entry for `fingerprint` and consume the entry.
    ///
    /// The entry is removed on the FIRST submit attempt (single-use): an unknown or expired
    /// fingerprint yields 409; a signed transaction that is not the built one (different tx
    /// id), does not spend the build's reserve box, or whose reserve-output R5 digest differs
    /// from the build's yields 400. After a failed attempt the client must call
    /// `/redemption/build` again.
    pub fn validate_and_consume(
        &self,
        fingerprint: &UnsignedTxFingerprint,
        signed_tx: &Value,
    ) -> Result<PendingRedemption, (StatusCode, String)> {
        let entry = {
            let mut entries = self.lock();
            Self::prune(&mut entries);
            entries.remove(fingerprint)
        };
        let entry =
            match entry {
                Some(e) => e,
                None => return Err((
                    StatusCode::CONFLICT,
                    "Unknown, expired or already-used unsigned_tx. Call POST /redemption/build \
                     again to obtain a fresh one."
                        .to_string(),
                )),
            };

        // The signed transaction must be exactly the transaction the build produced. Checking
        // only "spends the reserve" and "outputs[0] carries the digest" let a caller submit any
        // other transaction that touches the reserve box (e.g. an unsigned top-up with a decoy
        // box at outputs[0]) and still have the stored redemption applied. ergo-lib recomputes
        // the id from the transaction body when parsing, so a forged `id` field is rejected.
        let signed: Transaction = serde_json::from_value(signed_tx.clone()).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("signed_tx is not a valid signed transaction: {e}"),
            )
        })?;
        let signed_tx_id = String::from(signed.id());
        if signed_tx_id != entry.unsigned_tx_id {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "signed_tx {} is not the transaction {} built by the matching \
                     /redemption/build call",
                    signed_tx_id, entry.unsigned_tx_id
                ),
            ));
        }

        // The signed transaction must spend the reserve box the build selected.
        let spends_reserve = signed_tx
            .get("inputs")
            .and_then(Value::as_array)
            .map(|inputs| {
                inputs.iter().any(|input| {
                    input.get("boxId").and_then(Value::as_str)
                        == Some(entry.reserve_box_id.as_str())
                })
            })
            .unwrap_or(false);
        if !spends_reserve {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "signed_tx does not spend the reserve box {} from the matching \
                     /redemption/build call",
                    entry.reserve_box_id
                ),
            ));
        }

        // The reserve output (index 0 by construction) must carry the reserve-tree digest the
        // build computed; otherwise the tracker's local tree would diverge from what lands
        // on-chain. R5 serializes as `0x64 || 33-byte digest || flags || keylen || valuelen`.
        let expected_digest_hex = hex::encode(&entry.reserve_r5_digest);
        let r5_matches = signed_tx
            .get("outputs")
            .and_then(Value::as_array)
            .and_then(|outputs| outputs.first())
            .and_then(|o| o.get("additionalRegisters"))
            .and_then(|r| r.get("R5"))
            .and_then(Value::as_str)
            .map(|r5| {
                r5.len() >= 68
                    && r5.starts_with("64")
                    && r5[2..68].eq_ignore_ascii_case(&expected_digest_hex)
            })
            .unwrap_or(false);
        if !r5_matches {
            return Err((
                StatusCode::BAD_REQUEST,
                "signed_tx reserve output R5 does not match the reserve tree digest computed by \
                 /redemption/build"
                    .to_string(),
            ));
        }

        Ok(entry)
    }

    /// Number of live entries. Used by tests.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        let mut entries = self.lock();
        Self::prune(&mut entries);
        entries.len()
    }

    /// Drop expired entries. Called on every record/validate, so no timer is needed.
    fn prune(entries: &mut HashMap<UnsignedTxFingerprint, PendingRedemption>) {
        let now = Instant::now();
        entries.retain(|_, entry| now.duration_since(entry.issued_at) < PENDING_REDEMPTION_TTL);
    }

    /// Lock the map, recovering from a poisoned mutex.
    ///
    /// A panic while holding this lock would only ever mean the map is in a consistent state
    /// (each entry is independent), so refusing all subsequent submissions would be worse than
    /// continuing.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<UnsignedTxFingerprint, PendingRedemption>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ----- per-pair build rate limiter (PR #16 M1) -----

/// The rolling window of every `/redemption/build` limit.
const BUILD_WINDOW: Duration = Duration::from_secs(3600);
/// How often all windows are swept for keys with no attempt left in [`BUILD_WINDOW`].
const BUILD_WINDOW_SWEEP_EVERY: Duration = Duration::from_secs(60);
/// Most (issuer, recipient) pairs the per-pair window keeps. When it is full of pairs that
/// built within the hour, the pair whose latest attempt is the oldest makes room: memory stays
/// bounded, and the per-issuer and total caps still bound what builds cost the tracker.
const MAX_TRACKED_BUILD_PAIRS: usize = 10_000;

/// Most recipients whose last `request_timestamp` is kept, and most recipients the
/// per-recipient window keeps. When the timestamp table is full of recipients seen within
/// [`BUILD_REQUEST_TIMESTAMP_RETENTION`], new recipients are refused (429) rather than an
/// entry evicted, so a flood cannot reopen a replay window for someone else's request.
const MAX_TRACKED_BUILD_RECIPIENTS: usize = 10_000;
/// How long the last accepted `request_timestamp` of a recipient is kept. Anything older than
/// twice [`BUILD_REQUEST_MAX_SKEW_MS`] fails the clock check anyway, so a replay of a forgotten
/// request is still refused.
pub const BUILD_REQUEST_TIMESTAMP_RETENTION: Duration = Duration::from_secs(600);
/// How far `request_timestamp` of a build request may be from the tracker's clock, either way.
pub const BUILD_REQUEST_MAX_SKEW_MS: u64 = 120_000;

/// Rolling one-hour limits for `/redemption/build`, plus the recipients' request timestamps.
///
/// Every limit counts only requests the recipient signed (`receiver_signature`) for a note the
/// tracker holds, so nobody else can use up a pair's or a recipient's budget, and junk never
/// costs a node request:
/// - every such build counts against its (issuer, recipient) pair
///   (`server.redemption_build_max_per_pair_per_hour`) and its recipient
///   (`server.redemption_build_max_per_recipient_per_hour`), [`Self::check_and_record`]. Round 5:
///   counted right after the note lookup, before the committed proof and the cheap checks, so a
///   signed request that fails a later check still uses one unit of its own budget;
/// - a build about to sign tracker fee inputs (token reserves; ERG redemptions pay the fee out
///   of the payout and sign nothing) also counts against its issuer
///   (`server.redemption_build_max_per_issuer_per_hour`) and against all such builds together
///   (`server.redemption_build_max_per_hour`), [`Self::check_and_record_fee_signing`].
///
/// Keys with no attempt in the last hour are dropped, so the maps stay bounded.
#[derive(Debug, Default)]
pub struct BuildRateLimiter {
    windows: std::sync::Mutex<BuildWindows>,
}

#[derive(Debug, Default)]
struct BuildWindows {
    pairs: HashMap<(String, String), Vec<Instant>>,
    recipients: HashMap<String, Vec<Instant>>,
    issuers: HashMap<String, Vec<Instant>>,
    all: Vec<Instant>,
    /// Last accepted `request_timestamp` of each recipient, and when it was accepted.
    request_timestamps: HashMap<String, (u64, Instant)>,
    swept_at: Option<Instant>,
}

/// Drop the attempts that left the window.
fn keep_recent(attempts: &mut Vec<Instant>, now: Instant) {
    attempts.retain(|t| now.duration_since(*t) < BUILD_WINDOW);
}

impl BuildWindows {
    /// Why `request_timestamp` cannot be the newest build request of `recipient` (409), if it
    /// cannot: it is not greater than the recipient's last accepted one, still remembered.
    fn timestamp_refusal(
        &self,
        recipient: &str,
        request_timestamp: u64,
        now: Instant,
    ) -> Option<(StatusCode, String)> {
        match self.request_timestamps.get(recipient) {
            Some((previous, accepted_at))
                if now.duration_since(*accepted_at) < BUILD_REQUEST_TIMESTAMP_RETENTION
                    && request_timestamp <= *previous =>
            {
                Some((
                    StatusCode::CONFLICT,
                    format!(
                        "request_timestamp {request_timestamp} is not greater than this \
                         recipient's previous build request ({previous}): sign every build \
                         request with a new, later timestamp"
                    ),
                ))
            }
            _ => None,
        }
    }

    /// Drop every attempt that left the window, and every key left without one.
    fn sweep(&mut self, now: Instant) {
        self.pairs.retain(|_, attempts| {
            keep_recent(attempts, now);
            !attempts.is_empty()
        });
        self.recipients.retain(|_, attempts| {
            keep_recent(attempts, now);
            !attempts.is_empty()
        });
        self.issuers.retain(|_, attempts| {
            keep_recent(attempts, now);
            !attempts.is_empty()
        });
        keep_recent(&mut self.all, now);
        self.request_timestamps.retain(|_, (_, accepted_at)| {
            now.duration_since(*accepted_at) < BUILD_REQUEST_TIMESTAMP_RETENTION
        });
        self.swept_at = Some(now);
    }

    fn sweep_when_due(&mut self, now: Instant) {
        let due = self
            .swept_at
            .is_none_or(|t| now.duration_since(t) >= BUILD_WINDOW_SWEEP_EVERY);
        if due {
            self.sweep(now);
        }
    }

    /// Why a build for `issuer` may not sign fee inputs now, if it may not.
    fn fee_signing_refusal(
        &mut self,
        issuer: &str,
        now: Instant,
        max_per_issuer: u32,
        max_total: u32,
    ) -> Option<String> {
        keep_recent(&mut self.all, now);
        if self.all.len() >= max_total as usize {
            return Some(format!(
                "rate limit exceeded: at most {max_total} redemption builds per hour in total"
            ));
        }
        let issuer_builds = self.issuers.get_mut(issuer).map_or(0, |attempts| {
            keep_recent(attempts, now);
            attempts.len()
        });
        if issuer_builds >= max_per_issuer as usize {
            return Some(format!(
                "rate limit exceeded: at most {max_per_issuer} redemption builds per hour per issuer"
            ));
        }
        None
    }
}

impl BuildRateLimiter {
    /// Create an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BuildWindows> {
        self.windows.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Err (409) when `request_timestamp` is not greater than the previous accepted build
    /// request of `recipient`; records nothing. Round 5 (item 2): a replay stops here, before
    /// the note lookup, while the timestamp is only recorded
    /// ([`Self::check_and_record_request_timestamp`]) once the lookup found a note, so keys
    /// without a note cannot fill the timestamp table.
    pub fn check_request_timestamp(
        &self,
        recipient: &str,
        request_timestamp: u64,
    ) -> Result<(), (StatusCode, String)> {
        let mut windows = self.lock();
        let now = Instant::now();
        windows.sweep_when_due(now);
        windows
            .timestamp_refusal(recipient, request_timestamp, now)
            .map_or(Ok(()), Err)
    }

    /// Accept `request_timestamp` as the newest build request of `recipient`: Err (409) when it
    /// is not greater than the recipient's previous accepted one, so a captured request cannot
    /// be replayed, or (429) when the table is full of recipients seen in the last
    /// [`BUILD_REQUEST_TIMESTAMP_RETENTION`]. Call it only after the signature verified and
    /// the note lookup found the note.
    pub fn check_and_record_request_timestamp(
        &self,
        recipient: &str,
        request_timestamp: u64,
    ) -> Result<(), (StatusCode, String)> {
        let mut windows = self.lock();
        let now = Instant::now();
        windows.sweep_when_due(now);
        if let Some(refusal) = windows.timestamp_refusal(recipient, request_timestamp, now) {
            return Err(refusal);
        }
        // A recipient already in the table overwrites its entry; a new one needs room.
        if !windows.request_timestamps.contains_key(recipient)
            && windows.request_timestamps.len() >= MAX_TRACKED_BUILD_RECIPIENTS
        {
            windows.sweep(now);
            if windows.request_timestamps.len() >= MAX_TRACKED_BUILD_RECIPIENTS {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many recipients asked for redemption builds in the last minutes; try \
                     again shortly"
                        .to_string(),
                ));
            }
        }
        windows
            .request_timestamps
            .insert(recipient.to_string(), (request_timestamp, now));
        Ok(())
    }

    /// Number of recipients whose last request timestamp is kept. Used by tests.
    #[cfg(test)]
    pub fn tracked_request_timestamps(&self) -> usize {
        self.lock().request_timestamps.len()
    }

    /// Record a verified build for `(issuer, recipient)`; returns Err, recording nothing, when
    /// the pair has reached `max_per_pair` or the recipient `max_per_recipient` builds within the
    /// last rolling hour.
    pub fn check_and_record(
        &self,
        issuer: &str,
        recipient: &str,
        max_per_pair: u32,
        max_per_recipient: u32,
    ) -> Result<(), String> {
        let mut windows = self.lock();
        let now = Instant::now();
        windows.sweep_when_due(now);
        let key = (issuer.to_string(), recipient.to_string());
        if !windows.pairs.contains_key(&key) && windows.pairs.len() >= MAX_TRACKED_BUILD_PAIRS {
            windows.sweep(now);
            if windows.pairs.len() >= MAX_TRACKED_BUILD_PAIRS {
                let stalest = windows
                    .pairs
                    .iter()
                    .min_by_key(|(_, attempts)| attempts.last().copied())
                    .map(|(pair, _)| pair.clone());
                if let Some(pair) = stalest {
                    windows.pairs.remove(&pair);
                }
            }
        }
        if !windows.recipients.contains_key(recipient)
            && windows.recipients.len() >= MAX_TRACKED_BUILD_RECIPIENTS
        {
            windows.sweep(now);
            if windows.recipients.len() >= MAX_TRACKED_BUILD_RECIPIENTS {
                let stalest = windows
                    .recipients
                    .iter()
                    .min_by_key(|(_, attempts)| attempts.last().copied())
                    .map(|(recipient, _)| recipient.clone());
                if let Some(stalest) = stalest {
                    windows.recipients.remove(&stalest);
                }
            }
        }
        let pair_builds = windows.pairs.get_mut(&key).map_or(0, |attempts| {
            keep_recent(attempts, now);
            attempts.len()
        });
        if pair_builds >= max_per_pair as usize {
            return Err(format!(
                "rate limit exceeded: at most {} redemption builds per hour per \
                 (issuer, recipient) pair",
                max_per_pair
            ));
        }
        let recipient_builds = windows.recipients.get_mut(recipient).map_or(0, |attempts| {
            keep_recent(attempts, now);
            attempts.len()
        });
        if recipient_builds >= max_per_recipient as usize {
            return Err(format!(
                "rate limit exceeded: at most {} redemption builds per hour per recipient",
                max_per_recipient
            ));
        }
        windows.pairs.entry(key).or_default().push(now);
        windows
            .recipients
            .entry(recipient.to_string())
            .or_default()
            .push(now);
        Ok(())
    }

    /// Err when a build for `issuer` could not sign fee inputs now (see
    /// [`Self::check_and_record_fee_signing`]); records nothing. Lets a build stop before any
    /// node request once a cap is reached.
    pub fn check_fee_signing(
        &self,
        issuer: &str,
        max_per_issuer: u32,
        max_total: u32,
    ) -> Result<(), String> {
        let refusal =
            self.lock()
                .fee_signing_refusal(issuer, Instant::now(), max_per_issuer, max_total);
        refusal.map_or(Ok(()), Err)
    }

    /// Record a build for `issuer` that is about to sign fee inputs; returns Err, recording
    /// nothing, when `issuer` has had `max_per_issuer` such builds within the last rolling hour
    /// or all issuers together `max_total`.
    pub fn check_and_record_fee_signing(
        &self,
        issuer: &str,
        max_per_issuer: u32,
        max_total: u32,
    ) -> Result<(), String> {
        let mut windows = self.lock();
        let now = Instant::now();
        windows.sweep_when_due(now);
        if let Some(refusal) = windows.fee_signing_refusal(issuer, now, max_per_issuer, max_total) {
            return Err(refusal);
        }
        windows.all.push(now);
        windows
            .issuers
            .entry(issuer.to_string())
            .or_default()
            .push(now);
        Ok(())
    }
}

/// Room kept on top of a build's cost when the fee scan counts the tracker's balance: change
/// that cannot form a box goes to the fee (at most the minimum value of a change box, far
/// below this), and the scan must see past it to compare the balance with the reserve.
const FEE_FLOOR_SCAN_MARGIN: u64 = 1_000_000;

/// Why a build may not spend the tracker's fee boxes, if it may not: `seen` is the token-free
/// value the fee scan counted at the tracker address (a lower bound: the scan stops once it has
/// enough), `spent` the selected fee inputs, and `change_back` the change that returns to the
/// tracker address. Commits and heartbeats pay from the same boxes, so a build that would leave
/// less than `commit_reserve` there is refused.
fn fee_floor_refusal(
    seen: u64,
    spent: u64,
    change_back: u64,
    commit_reserve: u64,
) -> Option<String> {
    let after = seen.saturating_sub(spent).saturating_add(change_back);
    (after < commit_reserve).then(|| {
        format!(
            "the tracker is low on fee funds: this build would leave {after} nanoERG at the \
             tracker address, below the {commit_reserve} nanoERG kept for its commits \
             ([transaction] commit_reserve_nano). Try again once the tracker address is funded."
        )
    })
}

/// Select wallet boxes covering the required fee, excluding the reserve box and token-bearing boxes.
fn select_fee_inputs(
    wallet_boxes: &[NodeBox],
    required: u64,
    reserve_box_id: &str,
) -> Option<(Vec<NodeBox>, u64)> {
    let mut candidates: Vec<&NodeBox> = wallet_boxes
        .iter()
        .filter(|b| b.box_id != reserve_box_id && b.assets.is_empty())
        .collect();
    candidates.sort_by_key(|b| b.value);

    if let Some(b) = candidates.iter().find(|b| b.value >= required) {
        return Some((vec![(*b).clone()], b.value));
    }
    let mut selected = Vec::new();
    let mut total = 0u64;
    for b in candidates {
        total += b.value;
        selected.push(b.clone());
        if total >= required {
            return Some((selected, total));
        }
    }
    None
}

/// Checks a built redemption before it is returned, and before the tracker signs any fee input
/// with its own key.
///
/// The fee inputs were picked from the address index (`byAddress`), which can be stale or
/// wrong. These checks read the boxes as the node returned their bytes (`/utxo/byIdBinary`),
/// which is what the transaction spends, so a wrong index entry (for the tracker box above
/// all) can never get the tracker to sign away a token such as its own NFT:
/// - `input_boxes` are exactly the boxes `unsigned` spends, in order;
/// - with `tracker_tree_hex` (a token redemption, whose fee the tracker pays), every fee input
///   (every input after the reserve, input 0) is locked by `P2PK(tracker key)` and holds no
///   token; without it (an ERG redemption, whose fee comes out of the payout) the reserve is the
///   only input;
/// - the transaction moves every input token to the outputs with the same total and creates
///   none ([`crate::local_wallet::check_tokens_preserved`]);
///
/// and that the node would take it, as far as that is known without the reserve input's proof:
/// - the outputs hold exactly the value of the inputs;
/// - no output is below its minimum value (360 nanoERG per serialized byte);
/// - every output is created at `height` (the signing context's) or below, and no lower than
///   any input.
fn check_built_redemption(
    unsigned: &UnsignedTransaction,
    input_boxes: &[ErgoBox],
    tracker_tree_hex: Option<&str>,
    height: u32,
) -> Result<(), String> {
    if input_boxes.len() != unsigned.inputs.len() {
        return Err(format!(
            "{} boxes for {} inputs",
            input_boxes.len(),
            unsigned.inputs.len()
        ));
    }
    for (i, (input, ergo_box)) in unsigned.inputs.iter().zip(input_boxes).enumerate() {
        if input.box_id != ergo_box.box_id() {
            return Err(format!(
                "input {i} spends box {}, but the node's bytes are box {}",
                String::from(input.box_id),
                String::from(ergo_box.box_id())
            ));
        }
    }
    if tracker_tree_hex.is_none() && input_boxes.len() > 1 {
        return Err(format!(
            "an ERG redemption spends only the reserve, but this one has {} inputs",
            input_boxes.len()
        ));
    }
    for (i, fee_box) in input_boxes.iter().enumerate().skip(1) {
        let id = String::from(fee_box.box_id());
        let tree = fee_box
            .ergo_tree
            .sigma_serialize_bytes()
            .map_err(|e| format!("fee input {i} ({id}) script: {e}"))?;
        if !tracker_tree_hex.is_some_and(|t| hex::encode(tree).eq_ignore_ascii_case(t)) {
            return Err(format!(
                "fee input {i} ({id}) is not locked by P2PK(tracker key)"
            ));
        }
        if let Some(tokens) = &fee_box.tokens {
            let token_ids: Vec<String> = tokens.iter().map(|t| String::from(t.token_id)).collect();
            return Err(format!(
                "fee input {i} ({id}) holds tokens {token_ids:?}; a fee input must hold none"
            ));
        }
    }
    let outputs = unsigned.output_candidates.as_vec();
    crate::local_wallet::check_tokens_preserved(input_boxes, outputs, None)?;

    let value_in = input_boxes
        .iter()
        .try_fold(0u64, |acc, b| acc.checked_add(*b.value.as_u64()))
        .ok_or("input values overflow")?;
    let value_out = outputs
        .iter()
        .try_fold(0u64, |acc, c| acc.checked_add(*c.value.as_u64()))
        .ok_or("output values overflow")?;
    if value_in != value_out {
        return Err(format!(
            "inputs hold {value_in} nanoERG but outputs {value_out}"
        ));
    }
    let newest_input = input_boxes
        .iter()
        .map(|b| b.creation_height)
        .max()
        .unwrap_or(0);
    for (i, output) in outputs.iter().enumerate() {
        let value = *output.value.as_u64();
        let min = crate::local_wallet::min_box_value(output)?;
        if value < min {
            return Err(format!(
                "output {i} holds {value} nanoERG, below its minimum value {min}"
            ));
        }
        if output.creation_height > height || output.creation_height < newest_input {
            return Err(format!(
                "output {i} is created at height {}, outside {newest_input}..={height}",
                output.creation_height
            ));
        }
    }
    Ok(())
}

/// Verify the proofs of the fee inputs (every input after the reserve, input 0) of the
/// partially signed `tx` against the signing context. The reserve input's proof is the
/// client's to add, so it is not checked here.
fn verify_fee_input_proofs(
    tx: &Transaction,
    input_boxes: &[ErgoBox],
    data_boxes: &[ErgoBox],
    state_context: &ErgoStateContext,
) -> Result<(), String> {
    let context = ergo_lib::wallet::signing::TransactionContext::new(
        tx.clone(),
        input_boxes.to_vec(),
        data_boxes.to_vec(),
    )
    .map_err(|e| format!("transaction context: {e}"))?;
    let bytes_to_sign = tx
        .bytes_to_sign()
        .map_err(|e| format!("bytes to sign: {e}"))?;
    for i in 1..tx.inputs.len() {
        let mut input_context = ergo_lib::wallet::signing::make_context(state_context, &context, i)
            .map_err(|e| format!("fee input {i} context: {e}"))?;
        let verified = ergo_lib::chain::transaction::verify_tx_input_proof(
            &context,
            &mut input_context,
            state_context,
            i,
            &bytes_to_sign,
        )
        .map_err(|e| format!("fee input {i}: {e}"))?;
        if !verified.result {
            return Err(format!("fee input {i}: the proof does not verify"));
        }
    }
    Ok(())
}

/// Minimum value of a box at `ergo_tree_hex` holding `value` and nothing else, created at
/// `height` (see [`crate::local_wallet::min_box_value`]).
fn plain_box_min_value(ergo_tree_hex: &str, value: u64, height: u32) -> Result<u64, String> {
    use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
    use ergo_lib::ergotree_ir::chain::ergo_box::{ErgoBoxCandidate, NonMandatoryRegisters};
    let candidate = ErgoBoxCandidate {
        value: BoxValue::try_from(value.max(BoxValue::MIN_RAW))
            .map_err(|e| format!("box value: {e}"))?,
        ergo_tree: parse_ergo_tree(ergo_tree_hex)?,
        tokens: None,
        additional_registers: NonMandatoryRegisters::empty(),
        creation_height: height,
    };
    crate::local_wallet::min_box_value(&candidate)
}

fn parse_ergo_tree(
    ergo_tree_hex: &str,
) -> Result<ergo_lib::ergotree_ir::ergo_tree::ErgoTree, String> {
    let bytes = hex::decode(ergo_tree_hex).map_err(|e| format!("ergo tree hex: {e}"))?;
    ergo_lib::ergotree_ir::ergo_tree::ErgoTree::sigma_parse_bytes(&bytes)
        .map_err(|e| format!("ergo tree: {e}"))
}

/// The miner fee and the change of a redemption whose fee inputs leave `leftover` nanoERG
/// after `fee` (and, for a token reserve, the recipient's box). Change below the minimum value
/// of its box at `change_tree_hex` cannot form a box: it is added to the fee, and there is no
/// change output (change 0).
fn fee_and_change(
    fee: u64,
    leftover: u64,
    change_tree_hex: &str,
    height: u32,
) -> Result<(u64, u64), String> {
    let change_tree = parse_ergo_tree(change_tree_hex)?;
    match crate::local_wallet::change_output(leftover, &change_tree, height)? {
        Some(_) => Ok((fee, leftover)),
        None => fee
            .checked_add(leftover)
            .map(|fee| (fee, 0))
            .ok_or_else(|| "fee overflows".to_string()),
    }
}

type ApiResult<T> = Result<T, (StatusCode, Json<ApiResponse<RedemptionBuildResponse>>)>;

fn api_err<T>(status: StatusCode, msg: impl Into<String>) -> ApiResult<T> {
    Err((status, Json(error_response(msg.into()))))
}

/// A node request of a build failed. SECURITY (round 4, C2): the client learns only what was
/// being read; the node's URL, status and body go to the log.
fn node_err<T>(what: &str, detail: impl std::fmt::Display) -> ApiResult<T> {
    tracing::warn!("redemption build: node request for {what} failed: {detail}");
    api_err(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("the tracker could not read {what} from its node; try again later"),
    )
}

/// Height used by the cheap minimum-value check, before the node gives the real one: the
/// largest a creation height can encode to, so the bound is never below the real minimum.
const CHEAP_CHECK_HEIGHT: u32 = i32::MAX as u32;

/// Milliseconds since the Unix epoch, by the tracker's clock.
pub(crate) fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Check the recipient's signature over a build request (round 4, C2).
///
/// The recipient signs [`basis_store::schnorr::build_request_message`] over the tracker NFT,
/// the issuer, the recipient, the denomination, the amount and `request_timestamp`, with the
/// same Basis Schnorr scheme as notes. The timestamp must be within
/// [`BUILD_REQUEST_MAX_SKEW_MS`] of `now_ms`; that it rises per recipient is checked by
/// [`BuildRateLimiter::check_and_record_request_timestamp`] after this.
fn verify_build_request_signature(
    payload: &RedemptionBuildRequest,
    tracker_nft_id: &[u8; 32],
    recipient_pk: &basis_store::PubKey,
    issuer_pk: &basis_store::PubKey,
    denomination: &basis_store::DenomKey,
    now_ms: u64,
) -> Result<(), (StatusCode, String)> {
    let bad = |msg: String| Err((StatusCode::BAD_REQUEST, msg));
    if payload.receiver_signature.trim().is_empty() || payload.request_timestamp == 0 {
        return bad(
            "receiver_signature and request_timestamp are required: the recipient signs every \
             build request (message \"basis-build-v1\" || tracker NFT || issuer || recipient || \
             denomination id || amount || request_timestamp)"
                .to_string(),
        );
    }
    let signature: [u8; 65] = match hex::decode(payload.receiver_signature.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(sig) => sig,
        None => return bad("receiver_signature must be 65-byte hex".to_string()),
    };
    if payload.request_timestamp.abs_diff(now_ms) > BUILD_REQUEST_MAX_SKEW_MS {
        return bad(format!(
            "request_timestamp {} is more than {} s away from the tracker's clock ({now_ms} ms); \
             sign the request again with the current time",
            payload.request_timestamp,
            BUILD_REQUEST_MAX_SKEW_MS / 1000
        ));
    }
    let message = basis_store::schnorr::build_request_message(
        tracker_nft_id,
        issuer_pk,
        recipient_pk,
        denomination,
        payload.amount,
        payload.request_timestamp,
    );
    if basis_store::schnorr::schnorr_verify(&signature, &message, recipient_pk).is_err() {
        return bad(format!(
            "receiver_signature does not verify: the recipient must sign this request for \
             denomination {} (message \"basis-build-v1\" || tracker NFT || issuer || recipient \
             || denomination id || amount || request_timestamp)",
            denomination.denomination_id()
        ));
    }
    Ok(())
}

// ----- handlers -----

/// Build the unsigned redemption transaction and sign the fee input(s) locally.
#[axum::debug_handler]
pub async fn build_redemption(
    State(state): State<AppState>,
    Json(payload): Json<RedemptionBuildRequest>,
) -> (StatusCode, Json<ApiResponse<RedemptionBuildResponse>>) {
    match build_redemption_inner(&state, &payload).await {
        Ok(resp) => (StatusCode::OK, Json(success_response(resp))),
        Err(e) => e,
    }
}

/// Sign the tracker signature (context var #6) for a redemption build.
///
/// The message is bound to the note's STORED denomination: the token reserve
/// contract verifies var #6 over
/// `blake2b256(owner || receiver || tokenId) || totalDebt || timestamp || trackerNftId`
/// (specs/ergo/multi_collateral_reserves.md §4.1). Signing the ERG debtKey instead
/// made every token-denomination tracker signature unverifiable on-chain, so
/// non-emergency token redemptions could never be redeemed through the normal window.
#[allow(clippy::too_many_arguments)]
fn sign_tracker_redemption(
    tracker_secret: &[u8; 32],
    tracker_pubkey: &basis_store::PubKey,
    issuer_pk: &basis_store::PubKey,
    recipient_pk: &basis_store::PubKey,
    denomination: &basis_store::DenomKey,
    total_debt: u64,
    timestamp: u64,
    tracker_nft_id: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let message = basis_store::schnorr::signing_message(
        issuer_pk,
        recipient_pk,
        denomination,
        total_debt,
        timestamp,
        tracker_nft_id,
    );
    basis_store::schnorr::schnorr_sign(&message, tracker_secret, tracker_pubkey)
        .map(|sig| sig.to_vec())
        .map_err(|e| format!("tracker schnorr sign: {e:?}"))
}

async fn build_redemption_inner(
    state: &AppState,
    payload: &RedemptionBuildRequest,
) -> ApiResult<RedemptionBuildResponse> {
    // Validate public keys.
    let issuer_pubkey_bytes = match hex::decode(&payload.issuer_pubkey) {
        Ok(b) if b.len() == 33 => b,
        _ => return api_err(StatusCode::BAD_REQUEST, "issuer_pubkey must be 33-byte hex"),
    };
    let recipient_pubkey_bytes = match hex::decode(&payload.recipient_pubkey) {
        Ok(b) if b.len() == 33 => b,
        _ => {
            return api_err(
                StatusCode::BAD_REQUEST,
                "recipient_pubkey must be 33-byte hex",
            )
        }
    };
    let issuer_pk: [u8; 33] = issuer_pubkey_bytes.clone().try_into().unwrap();
    let recipient_pk: [u8; 33] = recipient_pubkey_bytes.clone().try_into().unwrap();
    let issuer_pubkey: basis_store::PubKey = issuer_pk;
    let recipient_pubkey: basis_store::PubKey = recipient_pk;

    // Resolve the note denomination (default: the pair's existing note's
    // denomination when unambiguous, else ERG).
    let denomination = match crate::api::resolve_denomination(
        state,
        &issuer_pubkey,
        &recipient_pubkey,
        &payload.denomination,
    )
    .await
    {
        Ok(d) => d,
        Err(msg) => {
            return api_err(
                StatusCode::BAD_REQUEST,
                format!("invalid denomination: {msg}"),
            )
        }
    };

    if payload.amount == 0 {
        return api_err(StatusCode::BAD_REQUEST, "amount must be positive");
    }

    // The tracker NFT binds the recipient's request signature, like every redemption
    // signature, to this tracker.
    let tracker_nft_id = match &state.config.ergo.tracker_nft_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tracker NFT id not configured",
            )
        }
    };
    let tracker_nft_bytes: [u8; 32] = match hex::decode(&tracker_nft_id)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(b) => b,
        None => {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tracker NFT id is not 32-byte hex",
            )
        }
    };

    // SECURITY (round 4, C2): only the recipient may ask for a build. Their signature over the
    // request is checked first, before any budget is counted or the node is asked, so nobody
    // else can use up a pair's builds or make the tracker work for them, and a captured request
    // cannot be replayed (the timestamp must rise).
    if let Err((status, msg)) = verify_build_request_signature(
        payload,
        &tracker_nft_bytes,
        &recipient_pk,
        &issuer_pk,
        &denomination,
        now_unix_ms(),
    ) {
        return api_err(status, msg);
    }
    // A replay stops here; the timestamp is recorded only after the note lookup (round 5,
    // item 2), so keys without a note cannot fill the timestamp table.
    let recipient_hex = hex::encode(recipient_pk);
    let issuer_hex = hex::encode(issuer_pk);
    if let Err((status, msg)) = state
        .redemption_build_rate
        .check_request_timestamp(&recipient_hex, payload.request_timestamp)
    {
        return api_err(status, msg);
    }

    let recipient_address = match pubkey_to_address(&payload.recipient_pubkey) {
        Ok(a) => a,
        Err(e) => return api_err(StatusCode::BAD_REQUEST, format!("recipient address: {e}")),
    };
    let recipient_ergo_tree = match address_to_ergo_tree(&recipient_address) {
        Ok(t) => t,
        Err(e) => return api_err(StatusCode::BAD_REQUEST, format!("recipient tree: {e}")),
    };

    // Look up the note to confirm it exists. The stored note's payment
    // timestamp is authoritative for the tracker signature, context var #4, and
    // the reserve tree value — the caller-supplied `payload.timestamp` is
    // ignored (issue #15 S4). Total debt is authoritative from the committed
    // tracker proof below.
    let note = {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if state
            .tx
            .send(TrackerCommand::GetNoteByIssuerAndRecipient {
                issuer_pubkey,
                recipient_pubkey,
                denomination,
                response_tx: tx,
            })
            .await
            .is_err()
        {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tracker thread unavailable",
            );
        }
        match rx.await {
            Ok(Ok(Some(note))) => note,
            Ok(Ok(None)) => {
                return api_err(
                    StatusCode::BAD_REQUEST,
                    "note not found for issuer/recipient",
                )
            }
            Ok(Err(e)) => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("note lookup failed: {e:?}"),
                )
            }
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "tracker unavailable"),
        }
    };

    // Round 5 (items 1, 2): the request is the recipient's and the tracker holds its note, so
    // the timestamp is recorded and the budgets are counted now, before the committed proof and
    // the cheap checks. Only the recipient can spend their own budget; a signed request that
    // fails a later check still uses one unit of it.
    if let Err((status, msg)) = state
        .redemption_build_rate
        .check_and_record_request_timestamp(&recipient_hex, payload.request_timestamp)
    {
        return api_err(status, msg);
    }
    if let Err(msg) = state.redemption_build_rate.check_and_record(
        &issuer_hex,
        &recipient_hex,
        state.config.server.redemption_build_max_per_pair_per_hour,
        state.config.server.redemption_build_max_per_recipient_per_hour,
    ) {
        return api_err(StatusCode::TOO_MANY_REQUESTS, msg);
    }

    // SECURITY (PR #16 H2): fail closed when the issuer has more than one tracked reserve.
    // A note is bound to `hash(owner || receiver)`, not to a reserve box, so with two reserves
    // the same note redeems in full against EACH of them; building against one would let the
    // creditor drain the others. Refuse until the owner consolidates to a single reserve.
    if let Err(msg) =
        crate::api::ensure_single_issuer_reserve(state, &payload.issuer_pubkey, &denomination).await
    {
        return api_err(StatusCode::CONFLICT, msg);
    }

    // Tracker lookup proof (context var #8) + authoritative total debt.
    // The proof is generated against the COMMITTED on-chain tracker state (the
    // latest confirmed tracker box digest), not the live local tree: any note
    // posted after the last commitment would otherwise change the digest and
    // break every redemption (issue #15 S6). The total debt is the value
    // committed on-chain for this note.
    let (tracker_lookup_proof, total_debt) = {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if state
            .tx
            .send(TrackerCommand::GetCommittedTrackerLookupProof {
                issuer_pubkey,
                recipient_pubkey,
                denomination,
                response_tx: tx,
            })
            .await
            .is_err()
        {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tracker thread unavailable",
            );
        }
        match rx.await {
            Ok(Ok(proof)) => {
                let total_debt = if proof.value.len() == 8 {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&proof.value);
                    u64::from_be_bytes(b)
                } else {
                    0
                };
                (proof.proof, total_debt)
            }
            Ok(Err(basis_store::NoteError::NoteNotConfirmed)) => {
                return api_err(
                    StatusCode::BAD_REQUEST,
                    "note is not committed on-chain yet; wait for the next tracker box update",
                )
            }
            Ok(Err(basis_store::NoteError::StaleCommittedDebt { committed, local })) => {
                return api_err(
                    StatusCode::CONFLICT,
                    format!(
                        "the committed tracker state for this note ({}) is ahead of its current total ({}) because a consented debt decrease (exchange) has not been committed yet; building a redemption now would over-redeem. Retry after the next tracker box update (issue #17)",
                        committed, local
                    ),
                )
            }
            Ok(Err(e)) => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("tracker proof: {e:?}"),
                )
            }
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "tracker unavailable"),
        }
    };

    // Reserve lookup proof (context var #7) and the `already_redeemed` value the reserve tree
    // holds for this note.
    let (reserve_lookup_proof, already_redeemed) = {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if state
            .tx
            .send(TrackerCommand::GetReserveLookupProof {
                issuer_pubkey,
                recipient_pubkey,
                denomination,
                response_tx: tx,
            })
            .await
            .is_err()
        {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tracker thread unavailable",
            );
        }
        let lookup = match rx.await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("reserve lookup proof: {e:?}"),
                )
            }
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "tracker unavailable"),
        };
        let already_redeemed = if lookup.value.len() == 16 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&lookup.value[8..16]);
            u64::from_be_bytes(b)
        } else if lookup.value.len() == 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&lookup.value);
            u64::from_be_bytes(b)
        } else {
            0
        };
        (lookup.proof, already_redeemed)
    };
    let is_first_redemption = already_redeemed == 0;
    let new_already_redeemed = match already_redeemed.checked_add(payload.amount) {
        Some(v) => v,
        None => {
            return api_err(
                StatusCode::BAD_REQUEST,
                "cumulative redeemed amount overflows u64",
            )
        }
    };

    // Cheap checks (round 4, C2), before any node request: a build that cannot succeed
    // on-chain stops here.
    // 1. The contract releases at most `totalDebt - redeemedDebt` (basis.es `debtDelta`).
    let outstanding = total_debt.saturating_sub(already_redeemed);
    if payload.amount > outstanding {
        return api_err(
            StatusCode::BAD_REQUEST,
            format!(
                "amount {} exceeds the committed outstanding debt of this note: {outstanding} \
                 (committed total {total_debt} minus {already_redeemed} already redeemed)",
                payload.amount
            ),
        );
    }
    // 2. The recipient's box must be worth at least its minimum value. An ERG redemption pays
    //    the miner fee out of the payout, so that box holds `amount - fee`. (A token redemption
    //    gives the recipient a fixed 0.001 ERG box, always above the minimum.)
    let token_denomination = matches!(denomination, basis_store::DenomKey::Token(_));
    let fee = state.config.transaction_fee();
    if !token_denomination {
        let payout = match payload.amount.checked_sub(fee) {
            Some(v) if v > 0 => v,
            _ => {
                return api_err(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "amount {} nanoERG does not cover the {fee} nanoERG miner fee, which an \
                         ERG redemption pays out of the payout",
                        payload.amount
                    ),
                )
            }
        };
        match plain_box_min_value(&recipient_ergo_tree, payout, CHEAP_CHECK_HEIGHT) {
            Ok(min) if payout < min => {
                return api_err(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "the recipient's box would hold {payout} nanoERG (amount {} minus the \
                         {fee} nanoERG miner fee), below its minimum value ({min} nanoERG)",
                        payload.amount
                    ),
                )
            }
            Ok(_) => {}
            Err(e) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    }
    // 3. The issuer signature (context var #2) must verify over the message the contract checks:
    //    the committed total debt (var #3) and the note's timestamp (var #4).
    let issuer_signature: [u8; 65] = match hex::decode(payload.issuer_signature.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(sig) => sig,
        None => {
            return api_err(
                StatusCode::BAD_REQUEST,
                "issuer_signature must be 65-byte hex",
            )
        }
    };
    let issuer_message = basis_store::schnorr::signing_message(
        &issuer_pk,
        &recipient_pk,
        &note.denomination,
        total_debt,
        note.timestamp,
        &note.tracker_nft_id,
    );
    if basis_store::schnorr::schnorr_verify(&issuer_signature, &issuer_message, &issuer_pk).is_err()
    {
        return api_err(
            StatusCode::BAD_REQUEST,
            format!(
                "issuer_signature does not verify over the committed total debt ({total_debt}) \
                 and the note's timestamp ({}): send the issuer's note signature for that total",
                note.timestamp
            ),
        );
    }

    // Builds that sign tracker fee inputs (token reserves) also have a per-issuer and a total
    // budget, recorded right before signing; once one is used up, stop before the node.
    if token_denomination {
        if let Err(msg) = state.redemption_build_rate.check_fee_signing(
            &issuer_hex,
            state.config.server.redemption_build_max_per_issuer_per_hour,
            state.config.server.redemption_build_max_per_hour,
        ) {
            return api_err(StatusCode::TOO_MANY_REQUESTS, msg);
        }
    }

    let chain_node = NodeClient::chain(state);

    // Select the smallest reserve that covers the redemption, leaves a valid remainder, is actually
    // unspent on-chain, AND whose on-chain R5 (reserve AVL tree) matches the tracker's current
    // reserve tree digest — otherwise the insert proof cannot verify on-chain.
    let (reserve_box_id, reserve_collateral, reserve_refund_height, reserve_token_id) = {
        // The tracker's current reserve tree root digest; the spent reserve's R5 must equal this.
        let tracker_reserve_digest = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if state
                .tx
                .send(TrackerCommand::GetReserveStateDigest {
                    issuer_pubkey,
                    denomination,
                    response_tx: tx,
                })
                .await
                .is_err()
            {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "tracker thread unavailable",
                );
            }
            match rx.await {
                Ok(d) => hex::encode(d),
                Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "tracker unavailable"),
            }
        };

        let scanner = state.ergo_scanner.lock().await;
        let reserves = match scanner.reserve_storage().get_all_reserves() {
            Ok(r) => r,
            Err(e) => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("read reserves: {e:?}"),
                )
            }
        };
        drop(scanner);
        let normalized_issuer = basis_store::normalize_public_key(&payload.issuer_pubkey);
        let required = payload.amount.saturating_add(MIN_RESERVE_REMAINDER);

        // Gather matching candidates (issuer owner, sufficient collateral), smallest first.
        let mut candidates: Vec<(String, u64, u64, String)> = Vec::new();
        for reserve in &reserves {
            // Owner key may be double-hex-encoded in the DB.
            let owner = if let Ok(b) = hex::decode(&reserve.owner_pubkey) {
                if let Ok(s) = String::from_utf8(b.clone()) {
                    if s.chars().all(|c| c.is_ascii_hexdigit()) {
                        s
                    } else {
                        reserve.owner_pubkey.clone()
                    }
                } else {
                    reserve.owner_pubkey.clone()
                }
            } else {
                reserve.owner_pubkey.clone()
            };
            if basis_store::normalize_public_key(&owner) != normalized_issuer {
                continue;
            }
            // A note redeems only against a reserve of its own denomination
            // (specs/ergo/multi_collateral_reserves.md §6 invariant 3).
            if reserve.denomination().as_ref() != Some(&denomination) {
                continue;
            }
            let collateral = reserve.base_info.collateral_amount;
            // For token-backed reserves the collateral is measured in token units,
            // so we only need to cover the redemption amount. For ERG-backed reserves
            // the collateral is the box value in nanoERG and must leave the minimum
            // remainder in the reserve box.
            let collateral_required = if reserve.base_info.reserve_token_id.is_empty() {
                required
            } else {
                payload.amount
            };
            if collateral < collateral_required {
                continue;
            }
            candidates.push((
                decode_box_id(&reserve.box_id),
                collateral,
                reserve.base_info.refund_initiation_height,
                reserve.base_info.reserve_token_id.clone(),
            ));
        }
        candidates.sort_by_key(|(_, c, _, _)| *c);

        // Pick the smallest candidate that is unspent on-chain and whose R5 matches the tracker's
        // current reserve tree digest.
        let mut found: Option<(String, u64, u64, String)> = None;
        for (box_id, collateral, refund_height, reserve_token_id) in &candidates {
            // For ERG-backed reserves the box must hold enough ERG to cover the redemption
            // plus the minimum remainder. For token-backed reserves the ERG value is preserved,
            // so we only require the minimum box value.
            let min_box_value = if reserve_token_id.is_empty() {
                required
            } else {
                MIN_RESERVE_REMAINDER
            };
            match chain_node.box_details(box_id).await {
                Ok(b) if b.value >= min_box_value => match b.r5_digest_hex() {
                    Some(d) if d == tracker_reserve_digest => {
                        found = Some((
                            box_id.clone(),
                            *collateral,
                            *refund_height,
                            reserve_token_id.clone(),
                        ));
                        break;
                    }
                    Some(d) => {
                        tracing::warn!(
                            "reserve {} R5 {} != tracker tree {}; skipping",
                            box_id,
                            &d[..16.min(d.len())],
                            &tracker_reserve_digest[..16.min(tracker_reserve_digest.len())]
                        );
                    }
                    None => {
                        tracing::warn!("reserve {} has no R5 digest; skipping", box_id);
                    }
                },
                _ => {
                    tracing::warn!("skipping unavailable/insufficient reserve box {}", box_id);
                }
            }
        }
        match found {
            Some(id) => id,
            None => {
                return api_err(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "no unspent reserve with >= {required} units collateral and a reserve tree matching the tracker (digest {}) for issuer {}",
                        &tracker_reserve_digest[..16.min(tracker_reserve_digest.len())],
                        payload.issuer_pubkey
                    ),
                )
            }
        }
    };

    // Acceptance-policy compliance check at redemption time: reject redemptions
    // that would newly violate another debt holder's collateralization policy.
    // Emergency redemptions bypass the tracker (contract path after the time
    // lock) and are exempt from this check.
    if state.config.redemption.enforce_acceptance_policy && !payload.emergency {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if state
            .tx
            .send(TrackerCommand::GetNotesByIssuer {
                issuer_pubkey,
                response_tx: tx,
            })
            .await
            .is_err()
        {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tracker thread unavailable",
            );
        }
        let notes = match rx.await {
            Ok(Ok(notes)) => notes,
            Ok(Err(e)) => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("note lookup failed: {e:?}"),
                )
            }
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "tracker unavailable"),
        };

        // The miner fee is paid by explicit fee inputs, not deducted from the
        // reserve output, so the simulated post-redemption collateral only
        // decreases by the redeemed amount (fee = 0 here).
        if let Err(e) = crate::acceptance::redemption_check::check_redemption_policy_compliance(
            &issuer_pubkey,
            &recipient_pubkey,
            payload.amount,
            reserve_collateral,
            0,
            reserve_refund_height > 0,
            &notes,
            &denomination,
            &state.policy_storage,
            &state.config.acceptance,
        ) {
            use crate::acceptance::redemption_check::RedemptionPolicyError;
            let failure_id = match &e {
                RedemptionPolicyError::WouldViolatePolicy { .. } => "failed_policy_violation",
                RedemptionPolicyError::NotOldestNote { .. } => "failed_not_oldest_note",
            };
            tracing::warn!(
                "Redemption rejected by acceptance policy check ({}): {}",
                failure_id,
                e
            );
            return api_err(StatusCode::BAD_REQUEST, format!("{}: {}", failure_id, e));
        }
    }

    // Tracker box id (data input). Prefer the live shared state over the static
    // tracker storage, which can contain spent boxes. Every tracker box id known here is also
    // kept out of the fee inputs below.
    let known_tracker_box_ids: Vec<String> = {
        let shared = state.shared_tracker_state.lock().await;
        [shared.get_tracker_box_id(), shared.get_confirmed().box_id]
            .into_iter()
            .flatten()
            .collect()
    };
    // SECURITY (round 4, C2): a caller's `tracker_box_id` is used only when it is one of the
    // tracker boxes the tracker knows itself, so caller input never reaches a node URL.
    let tracker_box_id = match (&payload.tracker_box_id, known_tracker_box_ids.first()) {
        (_, None) => {
            return api_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "the tracker box is not known yet (the tracker has just started); retry shortly",
            )
        }
        (Some(requested), Some(default)) => {
            match known_tracker_box_ids
                .iter()
                .find(|known| known.eq_ignore_ascii_case(requested.trim()))
            {
                Some(known) => known.clone(),
                None => {
                    tracing::warn!(
                        "ignoring a caller tracker_box_id that is not a known tracker box: {:?}",
                        requested.chars().take(80).collect::<String>()
                    );
                    default.clone()
                }
            }
        }
        (None, Some(default)) => default.clone(),
    };

    // Reserve insert proof (context var #5) and the new reserve tree digest (output R5).
    let (insert_proof, new_reserve_digest) = {
        let (itx, irx) = tokio::sync::oneshot::channel();
        if state
            .tx
            .send(TrackerCommand::GetReserveInsertProof {
                issuer_pubkey,
                recipient_pubkey,
                denomination,
                timestamp: note.timestamp,
                new_already_redeemed,
                response_tx: itx,
            })
            .await
            .is_err()
        {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tracker thread unavailable",
            );
        }
        match irx.await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("reserve insert proof: {e:?}"),
                )
            }
            Err(_) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, "tracker unavailable"),
        }
    };

    // Tracker signature (context var #6), signed locally with the configured tracker secret.
    let tracker_signature: Vec<u8> = if !payload.emergency {
        let tracker_secret = match state.config.tracker_secret_key_bytes() {
            Some(s) => s,
            None => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "tracker secret key not configured for local signing",
                )
            }
        };
        let tracker_pubkey_bytes = match state.config.tracker_public_key_bytes() {
            Ok(Some(p)) => p,
            _ => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "tracker public key not configured",
                )
            }
        };
        match sign_tracker_redemption(
            &tracker_secret,
            &tracker_pubkey_bytes,
            &issuer_pk,
            &recipient_pk,
            &note.denomination,
            total_debt,
            note.timestamp,
            &note.tracker_nft_id,
        ) {
            Ok(sig) => sig,
            Err(e) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    } else {
        Vec::new()
    };

    // Signing context (contract does not read headers/params; height from PreHeader): the
    // newest header first, and the pre-header from the newest. The outputs are created at its
    // height, the chain tip, as the tracker's own commits are; the scanner's cached height can
    // be minutes old, below the creation height of a fee box from the latest commit.
    let state_context = match chain_node.state_context().await {
        Ok(context) => context,
        Err(e) => return node_err("the last block headers", e),
    };
    let current_height = state_context.pre_header.height;

    let reserve_box = match chain_node.box_details(&reserve_box_id).await {
        Ok(b) => b,
        Err(e) => return node_err("the reserve box", e),
    };
    let reserve_nft_id = reserve_box
        .assets
        .first()
        .map(|a| a.token_id.clone())
        .unwrap_or_else(|| tracker_nft_id.clone());

    // Token-backed reserves preserve the reserve's ERG value and move reserve tokens.
    let is_token_reserve = !reserve_token_id.is_empty();
    if is_token_reserve != token_denomination {
        return api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the selected reserve does not hold the note's denomination",
        );
    }
    // SECURITY (round 4, C2): an ERG redemption pays the miner fee out of the payout. The
    // reserve releases `amount`, the recipient's box gets `amount - fee` and the fee box `fee`;
    // the transaction spends only the reserve, so the tracker signs nothing and spends nothing.
    // contract/basis.es allows it: the redeem path bounds only what leaves the reserve
    // (`redeemed = SELF.value - selfOut.value`, `redeemed <= debtDelta`, basis.es:382-385) and
    // requires `proveDlog(receiver)` (basis.es:426), so the receiver signs these outputs; no
    // output other than the reserve's own is checked. A token reserve must keep its ERG value
    // (basis-token.es), so token redemptions still take the fee and the recipient's box value
    // from tracker fee inputs, under the fee-signing budgets.
    let fee_from_payout = !is_token_reserve;

    // Fee inputs (token reserves only) are signed below with the tracker secret, so they come
    // from the tracker's own P2PK address (public byAddress index, token-free boxes only).
    let (fee_boxes, fee_total, fee_funds_seen, tracker_tree_hex) = if fee_from_payout {
        (Vec::new(), 0u64, 0u64, None)
    } else {
        // The fee inputs must also fund the recipient's min-value ERG box.
        let fee_input_required = fee.saturating_add(TOKEN_RECIPIENT_MIN_VALUE_NANOERG);
        let tracker_pubkey_for_fees = match state.config.tracker_public_key_bytes() {
            Ok(Some(p)) => p,
            _ => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "tracker public key not configured",
                )
            }
        };
        // Never a fee input: the tracker box (it holds the tracker NFT) and the reserve box,
        // even if the address index lists one of them as a plain box. The parsed boxes are
        // checked again before signing (`check_built_redemption`).
        let fee_exclusions: Vec<&str> = known_tracker_box_ids
            .iter()
            .map(String::as_str)
            .chain([tracker_box_id.as_str(), reserve_box_id.as_str()])
            .collect();
        // The scan reads on until it has counted the reserve kept for commits on top of what
        // this build spends, so the fee floor below can be checked from the boxes it returns.
        let commit_reserve = state.config.transaction.commit_reserve_nano;
        let scan_enough = fee_input_required
            .saturating_add(commit_reserve)
            .saturating_add(FEE_FLOOR_SCAN_MARGIN);
        let wallet_boxes = match chain_node
            .tracker_fee_boxes(&tracker_pubkey_for_fees, scan_enough, &fee_exclusions)
            .await
        {
            Ok(b) => b,
            Err(e) => return node_err("the tracker's fee boxes", e),
        };
        let (fee_boxes, fee_total) =
            match select_fee_inputs(&wallet_boxes, fee_input_required, &reserve_box_id) {
                Some(v) => v,
                None => {
                    return api_err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            "no token-free boxes at the tracker address covering {fee_input_required} nanoERG fee"
                        ),
                    )
                }
            };
        let fee_funds_seen = wallet_boxes
            .iter()
            .fold(0u64, |acc, b| acc.saturating_add(b.value));
        (
            fee_boxes,
            fee_total,
            fee_funds_seen,
            Some(crate::local_wallet::p2pk_tree_hex(&tracker_pubkey_for_fees)),
        )
    };

    // Change address (token reserves): the owner of the first selected fee box (which we sign),
    // else config/recipient.
    // SECURITY: change always goes back to the tracker's own address.
    //
    // The fee inputs come from the TRACKER's address (`select_fee_inputs` over byAddress boxes)
    // and are signed with the tracker key, so a caller-chosen `change_address` meant a caller could
    // name any destination for the tracker's own ERG. Repeating a 1-nanoERG redemption against a
    // tiny self-owned reserve handed out one wallet box minus the fee each time.
    //
    // `change_address` is still accepted on the wire for compatibility, but it is IGNORED. The
    // configured change address wins; the fee box's own tree is the fallback when nothing is set.
    // An ERG redemption has no change (no fee inputs): its change address is empty.
    let change_address = match (fee_boxes.first(), &payload.change_address) {
        (None, _) => String::new(),
        (Some(first_fee_box), Some(a)) => {
            tracing::warn!(
                "Ignoring caller-supplied change_address ({:?}): redemption change always returns \
                 to the tracker's configured address.",
                a.chars().take(120).collect::<String>()
            );
            state
                .config
                .get_change_address()
                .or_else(|_| ergo_tree_to_p2pk_address(&first_fee_box.ergo_tree))
                .unwrap_or_else(|_| recipient_address.clone())
        }
        (Some(first_fee_box), None) => ergo_tree_to_p2pk_address(&first_fee_box.ergo_tree)
            .or_else(|_| state.config.get_change_address().map_err(|e| e.to_string()))
            .unwrap_or_else(|_| recipient_address.clone()),
    };

    // Build the reserve R5 register (updated reserve state as SAvlTree constant).
    let r5_bytes = build_savl_tree_from_digest(&hex::encode(&new_reserve_digest));
    let r5_hex = hex::encode(&r5_bytes);

    // Preserve the refund initiation height from the spent reserve box's R7 register.
    let refund_initiation_height = basis_store::ergo_scanner::decode_ergo_long_register(
        reserve_box.additional_registers.get("R7"),
    );

    // Context extension (Scala order applied below, before parsing).
    // Debt and timestamp are serialized as SIGNED Longs on-chain; values above i64::MAX
    // would wrap negative, so fail loudly instead of casting (stored notes are already
    // capped at i64::MAX — this is defense in depth for legacy databases).
    let total_debt_i64 = match i64::try_from(total_debt) {
        Ok(v) => v,
        Err(_) => {
            return api_err(
                StatusCode::CONFLICT,
                "stored totalDebt exceeds the on-chain signed-Long range".to_string(),
            )
        }
    };
    let note_timestamp_i64 = match i64::try_from(note.timestamp) {
        Ok(v) => v,
        Err(_) => {
            return api_err(
                StatusCode::CONFLICT,
                "stored note timestamp exceeds the on-chain signed-Long range".to_string(),
            )
        }
    };
    let mut context_extension: HashMap<String, String> = HashMap::new();
    context_extension.insert("0".to_string(), serialize_ergo_byte(0));
    context_extension.insert("1".to_string(), format!("07{}", payload.recipient_pubkey));
    context_extension.insert("2".to_string(), serialize_coll_bytes(&issuer_signature));
    context_extension.insert("3".to_string(), serialize_ergo_long(total_debt_i64));
    context_extension.insert("4".to_string(), serialize_ergo_long(note_timestamp_i64));
    context_extension.insert("5".to_string(), serialize_coll_bytes(&insert_proof));
    // Context var #6 must ALWAYS be present. The contract reads it with
    // `getVar[Coll[Byte]](6).get`, and `.get` on an absent var throws -- so omitting the key
    // outright made every emergency redemption fail on-chain, leaving the contract's own
    // `enoughTimeSpent` fallback (which allows omitting the tracker signature after the 3-day
    // window) unreachable. An EMPTY Coll[Byte] is the correct encoding for "no signature": the
    // contract branches on `trackerSigBytes.size > 0`. The Scala reference implementation and the
    // CLI both send var 6 unconditionally for the same reason.
    context_extension.insert(
        "6".to_string(),
        if payload.emergency {
            serialize_coll_bytes(&[])
        } else {
            serialize_coll_bytes(&tracker_signature)
        },
    );
    if let Some(ref lp) = reserve_lookup_proof {
        context_extension.insert("7".to_string(), serialize_coll_bytes(lp));
    }
    context_extension.insert("8".to_string(), serialize_coll_bytes(&tracker_lookup_proof));

    // Output ergoTrees.
    // The reserve output must carry exactly the script of the box being spent
    // (the contract requires selfOut.propositionBytes == SELF.propositionBytes).
    // Take it from the fetched on-chain box rather than a configured/hardcoded
    // constant, so a contract change can never leave this builder stale (B5).
    let reserve_ergo_tree = reserve_box.ergo_tree.clone();
    let reserve_contract_p2s = if is_token_reserve {
        state.config.basis_token_reserve_contract_p2s()
    } else {
        state.config.basis_reserve_contract_p2s()
    };
    match address_to_ergo_tree(reserve_contract_p2s) {
        Ok(configured_tree) if configured_tree != reserve_ergo_tree => {
            tracing::warn!(
                "reserve box {} script differs from the configured contract P2S {}; \
                 building with the box's own script",
                reserve_box_id,
                reserve_contract_p2s
            );
        }
        Ok(_) => {}
        Err(e) => {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("reserve contract P2S: {e}"),
            )
        }
    }
    let change_ergo_tree = if change_address.is_empty() {
        None
    } else {
        match address_to_ergo_tree(&change_address) {
            Ok(t) => Some(t),
            Err(e) => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("change tree: {e}"),
                )
            }
        }
    };

    // Build reserve/recipient outputs and change amount. Token-backed reserves keep the
    // original ERG value in the reserve and move reserve tokens to the recipient.
    let (
        reserve_output_value,
        reserve_output_assets,
        recipient_output_value,
        recipient_output_assets,
        change_amount,
    ) = if is_token_reserve {
        let token_amount_in = match reserve_box
            .assets
            .iter()
            .find(|a| a.token_id == reserve_token_id)
            .map(|a| a.amount)
        {
            Some(a) => a,
            None => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "reserve box missing configured reserve token",
                )
            }
        };
        let token_amount_out = token_amount_in.saturating_sub(payload.amount);
        if token_amount_out == 0 {
            return api_err(
                StatusCode::BAD_REQUEST,
                "reserve token amount would be zero after redemption",
            );
        }
        let reserve_assets = json!([
            { "tokenId": reserve_nft_id, "amount": 1 },
            { "tokenId": reserve_token_id, "amount": token_amount_out }
        ]);
        let recipient_assets = json!([{ "tokenId": reserve_token_id, "amount": payload.amount }]);
        let change = fee_total
            .saturating_sub(fee)
            .saturating_sub(TOKEN_RECIPIENT_MIN_VALUE_NANOERG);
        (
            reserve_box.value,
            reserve_assets,
            TOKEN_RECIPIENT_MIN_VALUE_NANOERG,
            recipient_assets,
            change,
        )
    } else {
        let reserve_output_value = reserve_box.value.saturating_sub(payload.amount);
        if reserve_output_value == 0 {
            return api_err(
                StatusCode::BAD_REQUEST,
                "reserve output value would be zero after redemption",
            );
        }
        let reserve_assets = json!([{ "tokenId": reserve_nft_id, "amount": 1 }]);
        // The fee comes out of the payout; the cheap checks above made sure `amount > fee`.
        (
            reserve_output_value,
            reserve_assets,
            payload.amount - fee,
            json!([]),
            0,
        )
    };

    // The node rejects an output below its minimum value (360 nanoERG per serialized byte).
    // The recipient of an ERG redemption gets `amount - fee`, so a smaller payout is refused
    // (checked at the real height; the cheap check above used a height bound).
    if !is_token_reserve {
        match plain_box_min_value(&recipient_ergo_tree, recipient_output_value, current_height) {
            Ok(min) if recipient_output_value < min => {
                return api_err(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "the recipient's box would hold {recipient_output_value} nanoERG, below \
                         its minimum value ({min} nanoERG)"
                    ),
                )
            }
            Ok(_) => {}
            Err(e) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    }
    // Change that cannot form a box goes to the miner fee, as in the tracker's own commits: a
    // fee box worth the fee plus 1 nanoERG no longer makes the build fail or the node reject it.
    let (fee, change_amount) = match &change_ergo_tree {
        Some(change_tree) => match fee_and_change(fee, change_amount, change_tree, current_height) {
            Ok(v) => v,
            Err(e) => return api_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        None => (fee, 0),
    };

    // Commits and heartbeats pay from the same token-free boxes: never leave less than
    // `[transaction] commit_reserve_nano` there.
    if let Some(tracker_tree_hex) = &tracker_tree_hex {
        let change_back = match &change_ergo_tree {
            Some(t) if t.eq_ignore_ascii_case(tracker_tree_hex) => change_amount,
            _ => 0,
        };
        let commit_reserve = state.config.transaction.commit_reserve_nano;
        if let Some(msg) = fee_floor_refusal(fee_funds_seen, fee_total, change_back, commit_reserve)
        {
            tracing::warn!("Refusing a redemption build: {msg}");
            return api_err(StatusCode::SERVICE_UNAVAILABLE, msg);
        }
    }

    // Inputs: reserve (index 0) then fee inputs (token reserves only).
    let mut inputs = vec![json!({ "boxId": reserve_box_id, "extension": context_extension })];
    for fb in &fee_boxes {
        inputs.push(json!({ "boxId": fb.box_id, "extension": json!({}) }));
    }

    let mut outputs = vec![
        json!({
            "value": reserve_output_value,
            "ergoTree": reserve_ergo_tree,
            "creationHeight": current_height,
            "assets": reserve_output_assets,
            "additionalRegisters": {
                "R4": format!("07{}", payload.issuer_pubkey),
                "R5": r5_hex,
                "R6": format!("0e{:02x}{}", tracker_nft_id.len() / 2, tracker_nft_id),
                "R7": serialize_ergo_long(refund_initiation_height as i64)
            }
        }),
        json!({
            "value": recipient_output_value,
            "ergoTree": recipient_ergo_tree,
            "creationHeight": current_height,
            "assets": recipient_output_assets,
            "additionalRegisters": {}
        }),
        json!({
            "value": fee,
            "ergoTree": FEE_CONTRACT_TREE,
            "creationHeight": current_height,
            "assets": [],
            "additionalRegisters": {}
        }),
    ];
    if let (Some(change_tree), true) = (&change_ergo_tree, change_amount > 0) {
        outputs.push(json!({
            "value": change_amount,
            "ergoTree": change_tree,
            "creationHeight": current_height,
            "assets": [],
            "additionalRegisters": {}
        }));
    }

    let mut unsigned_tx = json!({
        "inputs": inputs,
        "dataInputs": [ { "boxId": tracker_box_id } ],
        "outputs": outputs
    });

    // Reorder reserve-input extension into Scala ContextExtension order before parsing.
    reorder_reserve_extension_scala(&mut unsigned_tx);

    // The boxes as the node serializes them: what the transaction spends and reads.
    let reserve_box_binary = match chain_node.box_binary(&reserve_box_id).await {
        Ok(b) => b,
        Err(e) => return node_err("the reserve box bytes", e),
    };
    let tracker_box_binary = match chain_node.box_binary(&tracker_box_id).await {
        Ok(b) => b,
        Err(e) => return node_err("the tracker box bytes", e),
    };
    let mut fee_binaries = Vec::with_capacity(fee_boxes.len());
    for fb in &fee_boxes {
        match chain_node.box_binary(&fb.box_id).await {
            Ok(b) => fee_binaries.push(b),
            Err(e) => return node_err("a fee box's bytes", e),
        }
    }

    let unsigned: UnsignedTransaction = match serde_json::from_value(unsigned_tx.clone()) {
        Ok(u) => u,
        Err(e) => {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("parse unsigned tx: {e}"),
            )
        }
    };
    let built_tx_id = String::from(unsigned.id());

    let parse_box = |hexstr: &str, label: &str| -> ApiResult<ErgoBox> {
        let bytes = hex::decode(hexstr).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_response(format!("{label} hex: {e}"))),
            )
        })?;
        ErgoBox::sigma_parse_bytes(&bytes).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_response(format!("{label} parse: {e:?}"))),
            )
        })
    };
    let reserve_ebox = parse_box(&reserve_box_binary, "reserve box")?;
    let tracker_ebox = parse_box(&tracker_box_binary, "tracker box")?;
    let mut fee_eboxes = Vec::with_capacity(fee_binaries.len());
    for (i, fb) in fee_binaries.iter().enumerate() {
        fee_eboxes.push(parse_box(fb, &format!("fee box {i}"))?);
    }

    let mut input_boxes = vec![reserve_ebox];
    input_boxes.extend(fee_eboxes);
    let data_boxes = vec![tracker_ebox];

    if let Err(e) = check_built_redemption(
        &unsigned,
        &input_boxes,
        tracker_tree_hex.as_deref(),
        current_height,
    ) {
        tracing::error!("Refusing redemption build {built_tx_id}: {e}");
        return api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("refusing the built redemption: {e}"),
        );
    }

    let pre_header = state_context.pre_header.clone();
    let headers_array = state_context.headers.clone();

    let partial: Transaction = if fee_from_payout {
        // Nothing to sign: the only input is the reserve, which the recipient proves. The
        // partial transaction carries the context extension and empty proofs, the base the
        // client splices the reserve proof into.
        match Transaction::from_unsigned_tx(
            unsigned.clone(),
            vec![ProofBytes::Empty; unsigned.inputs.len()],
        ) {
            Ok(tx) => tx,
            Err(e) => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("partial tx: {e}"),
                )
            }
        }
    } else {
        if let Err(msg) = state.redemption_build_rate.check_and_record_fee_signing(
            &hex::encode(issuer_pk),
            state.config.server.redemption_build_max_per_issuer_per_hour,
            state.config.server.redemption_build_max_per_hour,
        ) {
            return api_err(StatusCode::TOO_MANY_REQUESTS, msg);
        }

        // Sign the fee input(s) locally with the tracker secret.
        let fee_secret = match state.config.tracker_secret_key_bytes() {
            Some(s) => s,
            None => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "tracker secret key not configured",
                )
            }
        };
        let fee_sk = match SecretKey::dlog_from_bytes(&fee_secret) {
            Some(sk) => sk,
            None => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid tracker dlog secret",
                )
            }
        };

        let n_inputs = unsigned.inputs.len();
        let mut partial: Option<Transaction> = None;
        for fee_idx in 1..n_inputs {
            match add_input_proof(
                &unsigned,
                partial.as_ref(),
                &input_boxes,
                &data_boxes,
                &pre_header,
                &headers_array,
                fee_idx,
                &fee_sk,
            ) {
                Ok(tx) => partial = Some(tx),
                Err(e) => {
                    return api_err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("fee input {fee_idx} signing: {e:?}"),
                    )
                }
            }
        }
        let partial = match partial {
            Some(tx) => tx,
            None => {
                return api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "a token redemption has no fee input to sign",
                )
            }
        };
        if let Err(e) = verify_fee_input_proofs(&partial, &input_boxes, &data_boxes, &state_context)
        {
            tracing::error!("Fee inputs of redemption {built_tx_id} do not verify: {e}");
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("fee input proofs do not verify: {e}"),
            );
        }
        partial
    };
    let partial_tx = serde_json::to_value(&partial).unwrap_or(Value::Null);

    let mut input_box_binaries = vec![reserve_box_binary];
    input_box_binaries.extend(fee_binaries);

    let response = RedemptionBuildResponse {
        unsigned_tx,
        partial_tx,
        input_box_binaries,
        data_box_binaries: vec![tracker_box_binary],
        headers: headers_array.to_vec(),
        reserve_box_id,
        tracker_box_id,
        reserve_output_value,
        recipient_output_value,
        total_debt,
        change_amount,
        change_address,
        recipient_address,
        is_first_redemption,
        fee,
        new_already_redeemed,
        fee_paid_by: if fee_from_payout {
            FEE_PAID_BY_RECIPIENT
        } else {
            FEE_PAID_BY_TRACKER
        }
        .to_string(),
    };

    // SECURITY (PR #16 B6): bind the future /redemption/submit to this exact build. The submit
    // endpoint only accepts a signed transaction whose echoed `unsigned_tx` hashes to a live
    // entry recorded here, and it advances tracker state from the STORED values below — never
    // from caller-supplied amounts. The entry is single-use and expires after
    // PENDING_REDEMPTION_TTL.
    let fingerprint = match unsigned_tx_fingerprint(&response.unsigned_tx) {
        Ok(fp) => fp,
        Err(e) => {
            return api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to fingerprint unsigned transaction: {e}"),
            )
        }
    };
    if !state.pending_redemptions.record(
        fingerprint,
        PendingRedemption::new(
            built_tx_id,
            response.reserve_box_id.clone(),
            hex::encode(issuer_pk),
            hex::encode(recipient_pk),
            payload.amount,
            new_already_redeemed,
            new_reserve_digest.clone(),
            denomination,
        ),
    ) {
        return api_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many outstanding redemption builds; try again shortly.",
        );
    }

    Ok(response)
}

/// Broadcast a fully-signed redemption transaction to the Ergo node.
///
/// SECURITY (PR #16 B6): the submit is bound to server-side state recorded by
/// `/redemption/build`. The echoed `unsigned_tx` must hash to a live, single-use pending
/// entry, and the signed transaction must have the built transaction's id (so it has the same
/// inputs, context extensions and outputs). After a successful broadcast the tracker's local state is synced
/// from the STORED entry (`redeemed_amount`, `new_already_redeemed`, issuer/recipient) — the
/// caller-supplied amount fields on the wire are ignored (kept only for compatibility).
#[axum::debug_handler]
pub async fn submit_redemption(
    State(state): State<AppState>,
    Json(payload): Json<RedemptionSubmitRequest>,
) -> (StatusCode, Json<ApiResponse<RedemptionSubmitResponse>>) {
    // (a) The echoed unsigned_tx must match a pending entry from /redemption/build.
    let fingerprint = match unsigned_tx_fingerprint(&payload.unsigned_tx) {
        Ok(fp) => fp,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(error_response(format!(
                    "failed to fingerprint unsigned_tx: {e}"
                ))),
            )
        }
    };

    // (b) + (d): validate the signed transaction against the stored entry and consume it
    // (single-use — on any failure the client must call /redemption/build again).
    let pending = match state
        .pending_redemptions
        .validate_and_consume(&fingerprint, &payload.signed_tx)
    {
        Ok(p) => p,
        Err((status, msg)) => return (status, Json(error_response(msg))),
    };

    // (c) Everything that touches tracker state comes from the STORED entry.
    let issuer_pubkey: basis_store::PubKey = match hex::decode(&pending.issuer_pubkey)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(pk) => pk,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_response(
                    "pending redemption entry has an invalid issuer_pubkey".to_string(),
                )),
            )
        }
    };
    let recipient_pubkey: basis_store::PubKey = match hex::decode(&pending.recipient_pubkey)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(pk) => pk,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_response(
                    "pending redemption entry has an invalid recipient_pubkey".to_string(),
                )),
            )
        }
    };

    let node = NodeClient::wallet(&state);
    let tx_id = match node.broadcast(&payload.signed_tx).await {
        Ok(tx_id) => tx_id,
        Err(e) => {
            // SECURITY (round 4, C2): the node's URL and answer stay in the log.
            tracing::warn!(
                "redemption {} broadcast failed: {e}",
                pending.unsigned_tx_id
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_response(format!(
                    "the node did not accept redemption {}; build it again with \
                     POST /redemption/build",
                    pending.unsigned_tx_id
                ))),
            );
        }
    };

    // Round 5, item 3: the updater holds back a commit that would spend the tracker box this
    // redemption reads as its data input while the redemption waits in the mempool.
    let data_input_ids: Vec<String> = payload
        .signed_tx
        .get("dataInputs")
        .and_then(Value::as_array)
        .map(|inputs| {
            inputs
                .iter()
                .filter_map(|input| input.get("boxId").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    state
        .shared_tracker_state
        .lock()
        .await
        .record_submitted_redemption(tx_id.clone(), data_input_ids);

    // Sync local note + reserve tree state with the broadcast transaction. The reserve
    // tree value must be the cumulative amount proven on-chain (from the build), which
    // can differ from the note's cumulative redeemed amount when reserves were created
    // fresh or state was repaired.
    let (tx, rx) = tokio::sync::oneshot::channel();
    if state
        .tx
        .send(TrackerCommand::CompleteRedemption {
            issuer_pubkey,
            recipient_pubkey,
            denomination: pending.denomination,
            redeemed_amount: pending.redeemed_amount,
            new_already_redeemed: Some(pending.new_already_redeemed),
            response_tx: tx,
        })
        .await
        .is_err()
    {
        tracing::error!(tx_id, "tracker thread unavailable; local state not synced");
    } else {
        match rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(tx_id, ?e, "local redemption state sync failed"),
            Err(_) => tracing::error!(tx_id, "tracker dropped state sync response"),
        }
    }

    (
        StatusCode::OK,
        Json(success_response(RedemptionSubmitResponse { tx_id })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet_box(id: &str, value: u64, with_token: bool) -> NodeBox {
        let assets = if with_token {
            vec![NodeAsset {
                token_id: "aa".repeat(32),
                amount: 1,
            }]
        } else {
            Vec::new()
        };
        NodeBox {
            box_id: id.to_string(),
            value,
            ergo_tree: "00".to_string(),
            assets,
            additional_registers: Default::default(),
        }
    }

    #[test]
    fn select_fee_inputs_picks_exact_single_box() {
        let boxes = vec![
            wallet_box("a", 5_000_000, false),
            wallet_box("b", 1_000_000, false),
        ];
        let (selected, total) = select_fee_inputs(&boxes, 1_000_000, "zz").unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].box_id, "b");
        assert_eq!(total, 1_000_000);
    }

    #[test]
    fn select_fee_inputs_prefers_smallest_sufficient() {
        let boxes = vec![
            wallet_box("big", 50_000_000, false),
            wallet_box("mid", 2_000_000, false),
            wallet_box("small", 500_000, false),
        ];
        let (selected, total) = select_fee_inputs(&boxes, 1_000_000, "zz").unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].box_id, "mid");
        assert_eq!(total, 2_000_000);
    }

    #[test]
    fn select_fee_inputs_aggregates_when_no_single_box_suffices() {
        let boxes = vec![
            wallet_box("a", 400_000, false),
            wallet_box("b", 300_000, false),
            wallet_box("c", 500_000, false),
        ];
        let (selected, total) = select_fee_inputs(&boxes, 1_000_000, "zz").unwrap();
        assert_eq!(selected.len(), 3);
        assert_eq!(total, 1_200_000);
    }

    #[test]
    fn select_fee_inputs_excludes_reserve_box() {
        let boxes = vec![wallet_box("reserve", 10_000_000, false)];
        assert!(select_fee_inputs(&boxes, 1_000_000, "reserve").is_none());
    }

    #[test]
    fn select_fee_inputs_excludes_token_boxes() {
        let boxes = vec![
            wallet_box("token", 10_000_000, true),
            wallet_box("free", 2_000_000, false),
        ];
        let (selected, _) = select_fee_inputs(&boxes, 1_000_000, "zz").unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].box_id, "free");
    }

    #[test]
    fn select_fee_inputs_returns_none_when_insufficient() {
        let boxes = vec![wallet_box("a", 100_000, false)];
        assert!(select_fee_inputs(&boxes, 1_000_000, "zz").is_none());
        assert!(select_fee_inputs(&[], 1_000_000, "zz").is_none());
    }

    fn r5_box(r5: Option<&str>) -> NodeBox {
        let mut registers = std::collections::HashMap::new();
        if let Some(v) = r5 {
            registers.insert("R5".to_string(), v.to_string());
        }
        NodeBox {
            box_id: "x".to_string(),
            value: 0,
            ergo_tree: "00".to_string(),
            assets: Vec::new(),
            additional_registers: registers,
        }
    }

    #[test]
    fn r5_digest_hex_extracts_digest_from_real_onchain_r5() {
        // Real R5 from the empty-tree reserve created on-chain (tx 2a5e653a...).
        // The new reserve uses flags 0x03 (insert+update allowed) for insertOrUpdate.
        let b = r5_box(Some(
            "644ec61f485b98eb87153f7c57db4f5ecd75556fddbc403b41acf8441fde8e160900032000",
        ));
        assert_eq!(
            b.r5_digest_hex().unwrap(),
            "4ec61f485b98eb87153f7c57db4f5ecd75556fddbc403b41acf8441fde8e160900"
        );
    }

    #[test]
    fn r5_digest_hex_handles_missing_or_malformed_r5() {
        assert!(r5_box(None).r5_digest_hex().is_none());
        // Wrong type prefix (not 0x64).
        assert!(r5_box(Some("0702aaaaaaaa")).r5_digest_hex().is_none());
        // Too short to contain a 33-byte digest.
        assert!(r5_box(Some("64abcd")).r5_digest_hex().is_none());
    }

    // ----- pending redemption registry (PR #16 B6) -----

    const RESERVE_BOX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const FUNDING_BOX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    /// P2PK ErgoTree of the secp256k1 generator, a valid stand-in for any recipient/attacker.
    const P2PK_TREE: &str =
        "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn output(ergo_tree: &str, value: u64, r5_digest: Option<&[u8]>) -> Value {
        let registers = match r5_digest {
            // Registers must be densely packed, so R4 (owner key) comes along with R5.
            Some(d) => json!({
                "R4": format!("07{}", &P2PK_TREE[6..]),
                "R5": format!("64{}032000", hex::encode(d)),
            }),
            None => json!({}),
        };
        json!({
            "value": value,
            "ergoTree": ergo_tree,
            "assets": [],
            "additionalRegisters": registers,
            "creationHeight": 1_000
        })
    }

    /// An unsigned transaction (as `/redemption/build` returns it) and the same transaction
    /// with empty proofs, standing in for the client's signed copy. ergo-lib computes both ids
    /// from the transaction body, exactly as the node does.
    fn tx_pair(inputs: &[&str], outputs: Vec<Value>) -> (Value, Value) {
        let unsigned_json = json!({
            "inputs": inputs
                .iter()
                .map(|id| json!({ "boxId": id, "extension": {} }))
                .collect::<Vec<_>>(),
            "dataInputs": [],
            "outputs": outputs,
        });
        let unsigned: UnsignedTransaction = serde_json::from_value(unsigned_json.clone()).unwrap();
        let proofs = vec![
            ergo_lib::ergotree_interpreter::sigma_protocol::prover::ProofBytes::Empty;
            inputs.len()
        ];
        let signed = Transaction::from_unsigned_tx(unsigned, proofs).unwrap();
        (unsigned_json, serde_json::to_value(&signed).unwrap())
    }

    /// The honest built redemption: spends the reserve, reserve successor first.
    fn built_redemption() -> (Value, Value) {
        tx_pair(
            &[RESERVE_BOX, FUNDING_BOX],
            vec![
                output(P2PK_TREE, 9_000_000_000, Some(&[0x11; 33])),
                output(P2PK_TREE, 1_000_000_000, None),
            ],
        )
    }

    fn pending_entry(unsigned_tx: &Value) -> PendingRedemption {
        PendingRedemption {
            unsigned_tx_id: unsigned_tx_id(unsigned_tx).unwrap(),
            reserve_box_id: RESERVE_BOX.to_string(),
            issuer_pubkey: "aa".repeat(33),
            recipient_pubkey: "bb".repeat(33),
            redeemed_amount: 1_000,
            new_already_redeemed: 2_000,
            reserve_r5_digest: vec![0x11; 33],
            denomination: basis_store::DenomKey::Erg,
            issued_at: Instant::now(),
        }
    }

    fn recorded(registry: &PendingRedemptionRegistry) -> (UnsignedTxFingerprint, Value) {
        let (unsigned, signed) = built_redemption();
        let fp = unsigned_tx_fingerprint(&unsigned).unwrap();
        assert!(registry.record(fp, pending_entry(&unsigned)));
        (fp, signed)
    }

    #[test]
    fn pending_entry_happy_path_returns_stored_state() {
        let registry = PendingRedemptionRegistry::new();
        let (fp, signed) = recorded(&registry);

        let entry = registry.validate_and_consume(&fp, &signed).unwrap();
        assert_eq!(entry.reserve_box_id, RESERVE_BOX);
        assert_eq!(entry.redeemed_amount, 1_000);
        assert_eq!(entry.new_already_redeemed, 2_000);
    }

    /// A newer build of the same note (issuer, recipient, denomination; keys in any case)
    /// replaces the pending entry: the older one is refused like an expired one (409). Builds
    /// of other notes are kept.
    #[test]
    fn a_new_build_replaces_the_pending_entry_of_the_same_note() {
        let registry = PendingRedemptionRegistry::new();
        let (first_fp, first_signed) = recorded(&registry);

        // Another note of the same issuer (another recipient), and the same pair in a token.
        let other_recipient = PendingRedemption {
            recipient_pubkey: "cc".repeat(33),
            ..pending_entry(&built_redemption().0)
        };
        assert!(registry.record([1u8; 32], other_recipient));
        let token = PendingRedemption {
            denomination: basis_store::DenomKey::Token([0x33; 32]),
            ..pending_entry(&built_redemption().0)
        };
        assert!(registry.record([2u8; 32], token));
        assert_eq!(registry.len(), 3);

        // A second build of the first note, keys in upper case.
        let (second_unsigned, second_signed) = tx_pair(
            &[RESERVE_BOX, FUNDING_BOX],
            vec![
                output(P2PK_TREE, 8_000_000_000, Some(&[0x11; 33])),
                output(P2PK_TREE, 2_000_000_000, None),
            ],
        );
        let second_fp = unsigned_tx_fingerprint(&second_unsigned).unwrap();
        assert_ne!(second_fp, first_fp);
        let second = PendingRedemption {
            issuer_pubkey: "AA".repeat(33),
            recipient_pubkey: "BB".repeat(33),
            ..pending_entry(&second_unsigned)
        };
        assert!(registry.record(second_fp, second));
        assert_eq!(registry.len(), 3, "replaced, not added");

        let err = registry
            .validate_and_consume(&first_fp, &first_signed)
            .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(registry
            .validate_and_consume(&second_fp, &second_signed)
            .is_ok());
        assert_eq!(registry.len(), 2, "the other notes' entries are untouched");
    }

    #[test]
    fn pending_entry_unknown_fingerprint_is_conflict() {
        let registry = PendingRedemptionRegistry::new();
        let fp = [7u8; 32];
        let err = registry
            .validate_and_consume(&fp, &json!({ "inputs": [] }))
            .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
    }

    #[test]
    fn pending_entry_is_single_use() {
        let registry = PendingRedemptionRegistry::new();
        let (fp, signed) = recorded(&registry);

        assert!(registry.validate_and_consume(&fp, &signed).is_ok());
        let err = registry.validate_and_consume(&fp, &signed).unwrap_err();
        assert_eq!(
            err.0,
            StatusCode::CONFLICT,
            "a replayed fingerprint must be refused"
        );
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn pending_entry_rejects_signed_tx_spending_a_different_box() {
        let registry = PendingRedemptionRegistry::new();
        let (fp, _) = recorded(&registry);

        let (_, signed) = tx_pair(
            &["3333333333333333333333333333333333333333333333333333333333333333"],
            vec![output(P2PK_TREE, 9_000_000_000, Some(&[0x11; 33]))],
        );
        let err = registry.validate_and_consume(&fp, &signed).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn pending_entry_rejects_signed_tx_with_wrong_r5_digest() {
        let registry = PendingRedemptionRegistry::new();
        let (fp, _) = recorded(&registry);

        let (_, signed) = tx_pair(
            &[RESERVE_BOX, FUNDING_BOX],
            vec![
                output(P2PK_TREE, 9_000_000_000, Some(&[0x22; 33])),
                output(P2PK_TREE, 1_000_000_000, None),
            ],
        );
        let err = registry.validate_and_consume(&fp, &signed).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    /// Follow-up review N1: a top-up (action 1, no signature needed) that spends the reserve and
    /// puts a decoy box carrying the build's R5 digest at `outputs[0]` passed the old "spends
    /// the reserve + outputs[0].R5" check, so the tracker applied a redemption that never
    /// happened and its reserve tree diverged from the chain.
    #[test]
    fn pending_entry_rejects_unrelated_tx_with_decoy_r5_output() {
        let registry = PendingRedemptionRegistry::new();
        let (fp, _) = recorded(&registry);

        let (_, top_up) = tx_pair(
            &[RESERVE_BOX, FUNDING_BOX],
            vec![
                // Attacker-owned decoy carrying the expected digest.
                output(P2PK_TREE, 1_000_000, Some(&[0x11; 33])),
                // Real reserve successor: R5 unchanged, +0.1 ERG.
                output(P2PK_TREE, 10_100_000_000, Some(&[0xff; 33])),
            ],
        );
        let err = registry.validate_and_consume(&fp, &top_up).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn pending_entry_rejects_forged_tx_id() {
        let registry = PendingRedemptionRegistry::new();
        let (fp, signed) = recorded(&registry);

        // Same claimed id, different body: ergo-lib recomputes the id and refuses it.
        let (_, mut other) = tx_pair(
            &[RESERVE_BOX, FUNDING_BOX],
            vec![
                output(P2PK_TREE, 1_000_000, Some(&[0x11; 33])),
                output(P2PK_TREE, 10_100_000_000, None),
            ],
        );
        other["id"] = signed["id"].clone();
        let err = registry.validate_and_consume(&fp, &other).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn pending_entry_expired_is_conflict() {
        let registry = PendingRedemptionRegistry::new();
        let (unsigned, signed) = built_redemption();
        let fp = unsigned_tx_fingerprint(&unsigned).unwrap();
        let mut entry = pending_entry(&unsigned);
        entry.issued_at = Instant::now() - PENDING_REDEMPTION_TTL - Duration::from_secs(1);
        // Bypass `record` so the stale timestamp survives (record sets nothing itself, but
        // inserting directly makes the intent explicit).
        registry.lock().insert(fp, entry);

        let err = registry.validate_and_consume(&fp, &signed).unwrap_err();
        assert_eq!(
            err.0,
            StatusCode::CONFLICT,
            "an expired entry must be refused"
        );
    }

    // ----- per-pair build rate limiter (PR #16 M1) -----

    #[test]
    fn build_rate_limiter_allows_up_to_limit_then_rejects() {
        let limiter = BuildRateLimiter::new();
        assert!(limiter.check_and_record("issuer", "recipient", 2, u32::MAX).is_ok());
        assert!(limiter.check_and_record("issuer", "recipient", 2, u32::MAX).is_ok());
        let err = limiter
            .check_and_record("issuer", "recipient", 2, u32::MAX)
            .unwrap_err();
        assert!(err.contains("rate limit exceeded"), "got: {err}");
        // A different pair is unaffected.
        assert!(limiter.check_and_record("issuer", "other", 2, u32::MAX).is_ok());
    }

    #[test]
    fn build_rate_limiter_prunes_attempts_older_than_an_hour() {
        let limiter = BuildRateLimiter::new();
        {
            let mut windows = limiter.windows.lock().unwrap();
            windows.pairs.insert(
                ("issuer".to_string(), "recipient".to_string()),
                vec![Instant::now() - Duration::from_secs(3601)],
            );
        }
        assert!(limiter.check_and_record("issuer", "recipient", 1, u32::MAX).is_ok());
    }

    fn an_hour_ago() -> Instant {
        Instant::now() - Duration::from_secs(3601)
    }

    /// Pairs with no build in the last hour are dropped, and a full window makes room for a new
    /// pair by dropping the pair whose latest build is the oldest: the map stays bounded.
    #[test]
    fn build_rate_limiter_forgets_old_pairs_and_stays_bounded() {
        let limiter = BuildRateLimiter::new();
        {
            let mut windows = limiter.windows.lock().unwrap();
            for i in 0..100 {
                windows
                    .pairs
                    .insert((format!("old-{i}"), "r".to_string()), vec![an_hour_ago()]);
            }
        }
        limiter.check_and_record("issuer", "recipient", 5, u32::MAX).unwrap();
        assert_eq!(limiter.windows.lock().unwrap().pairs.len(), 1, "swept");

        // Fill the window with pairs that built within the hour.
        {
            let mut windows = limiter.windows.lock().unwrap();
            let start = Instant::now() - Duration::from_secs(1800);
            for i in 0..MAX_TRACKED_BUILD_PAIRS - 1 {
                let at = start + Duration::from_millis(i as u64);
                windows
                    .pairs
                    .insert((format!("p-{i}"), "r".to_string()), vec![at]);
            }
            assert_eq!(windows.pairs.len(), MAX_TRACKED_BUILD_PAIRS);
        }
        limiter.check_and_record("new", "pair", 5, u32::MAX).unwrap();
        let windows = limiter.windows.lock().unwrap();
        assert_eq!(windows.pairs.len(), MAX_TRACKED_BUILD_PAIRS);
        assert!(!windows
            .pairs
            .contains_key(&("p-0".to_string(), "r".to_string())));
        assert!(windows
            .pairs
            .contains_key(&("new".to_string(), "pair".to_string())));
        assert!(windows
            .pairs
            .contains_key(&("issuer".to_string(), "recipient".to_string())));
    }

    #[test]
    fn fee_signing_is_capped_per_issuer_and_in_total() {
        let limiter = BuildRateLimiter::new();
        for _ in 0..2 {
            limiter.check_and_record_fee_signing("a", 2, 3).unwrap();
        }
        let err = limiter.check_fee_signing("a", 2, 3).unwrap_err();
        assert!(
            err.contains("2 redemption builds per hour per issuer"),
            "{err}"
        );
        let err = limiter.check_and_record_fee_signing("a", 2, 3).unwrap_err();
        assert!(err.contains("per issuer"), "{err}");

        // Another issuer has its own budget, until the total is used up.
        limiter.check_fee_signing("b", 2, 3).unwrap();
        limiter.check_and_record_fee_signing("b", 2, 3).unwrap();
        let err = limiter.check_and_record_fee_signing("c", 2, 3).unwrap_err();
        assert!(
            err.contains("3 redemption builds per hour in total"),
            "{err}"
        );
        assert!(limiter.check_fee_signing("c", 2, 3).is_err());

        // Refusals recorded nothing; builds older than an hour no longer count.
        {
            let mut windows = limiter.windows.lock().unwrap();
            assert_eq!(windows.all.len(), 3);
            windows.all = vec![an_hour_ago(); 3];
            windows
                .issuers
                .insert("a".to_string(), vec![an_hour_ago(); 2]);
        }
        limiter.check_and_record_fee_signing("a", 2, 3).unwrap();
        limiter.check_and_record_fee_signing("c", 2, 3).unwrap();
    }

    /// The per-recipient budget spans issuers; a refusal records nothing.
    #[test]
    fn build_budget_per_recipient_spans_issuers() {
        let limiter = BuildRateLimiter::new();
        limiter.check_and_record("i1", "r", 5, 2).unwrap();
        limiter.check_and_record("i2", "r", 5, 2).unwrap();
        let err = limiter.check_and_record("i3", "r", 5, 2).unwrap_err();
        assert!(err.contains("per recipient"), "{err}");
        // Another recipient is unaffected, and the refusal recorded nothing for the pair.
        limiter.check_and_record("i3", "other", 5, 2).unwrap();
        assert!(!limiter
            .windows
            .lock()
            .unwrap()
            .pairs
            .contains_key(&("i3".to_string(), "r".to_string())));
    }

    /// Request timestamps rise strictly per recipient; a forgotten entry (older than the
    /// retention) accepts any timestamp, which the clock window then bounds.
    #[test]
    fn request_timestamps_rise_per_recipient() {
        let limiter = BuildRateLimiter::new();
        limiter.check_and_record_request_timestamp("r", 100).unwrap();
        let (status, msg) = limiter
            .check_and_record_request_timestamp("r", 100)
            .unwrap_err();
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(msg.contains("not greater"), "{msg}");
        assert!(limiter.check_and_record_request_timestamp("r", 99).is_err());
        limiter.check_and_record_request_timestamp("r", 101).unwrap();
        // Recipients are independent.
        limiter.check_and_record_request_timestamp("s", 1).unwrap();

        {
            let mut windows = limiter.windows.lock().unwrap();
            let old = Instant::now() - BUILD_REQUEST_TIMESTAMP_RETENTION - Duration::from_secs(1);
            windows.request_timestamps.insert("r".to_string(), (101, old));
        }
        limiter.check_and_record_request_timestamp("r", 50).unwrap();
    }

    /// Round 5, item 2: the early check refuses a replay but records nothing; only the record
    /// after the note lookup moves the recipient's timestamp on.
    #[test]
    fn the_early_timestamp_check_records_nothing() {
        let limiter = BuildRateLimiter::new();
        limiter.check_request_timestamp("r", 100).unwrap();
        limiter.check_request_timestamp("r", 100).unwrap();
        assert_eq!(limiter.tracked_request_timestamps(), 0);
        limiter.check_and_record_request_timestamp("r", 100).unwrap();
        assert_eq!(limiter.tracked_request_timestamps(), 1);
        let (status, msg) = limiter.check_request_timestamp("r", 100).unwrap_err();
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(msg.contains("not greater"), "{msg}");
        limiter.check_request_timestamp("r", 101).unwrap();
        // Two requests that both passed the early check: the record still refuses the older.
        limiter.check_and_record_request_timestamp("r", 102).unwrap();
        assert!(limiter.check_and_record_request_timestamp("r", 101).is_err());
    }

    /// A full table of fresh recipients refuses new ones (429) instead of evicting an entry.
    #[test]
    fn request_timestamp_table_is_bounded() {
        let limiter = BuildRateLimiter::new();
        {
            let mut windows = limiter.windows.lock().unwrap();
            let now = Instant::now();
            for i in 0..MAX_TRACKED_BUILD_RECIPIENTS {
                windows.request_timestamps.insert(format!("r-{i}"), (1, now));
            }
        }
        let (status, _) = limiter
            .check_and_record_request_timestamp("new", 1)
            .unwrap_err();
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        // A known recipient still moves on.
        limiter.check_and_record_request_timestamp("r-0", 2).unwrap();
    }

    /// Per-pair attempts (builds that may still fail before fee signing) do not use the
    /// issuer's or the total budget.
    #[test]
    fn per_pair_attempts_do_not_use_the_signing_budgets() {
        let limiter = BuildRateLimiter::new();
        for i in 0..50 {
            limiter
                .check_and_record("issuer", &format!("recipient-{i}"), 60, u32::MAX)
                .unwrap();
        }
        limiter
            .check_and_record_fee_signing("issuer", 1, 1)
            .unwrap();
    }

    #[test]
    fn the_fee_floor_keeps_the_commit_reserve_at_the_tracker_address() {
        let reserve = 100_000_000;
        // 0.2 ERG seen, a 0.05 ERG box spent, 0.049 ERG change back: 0.199 ERG left.
        assert_eq!(
            fee_floor_refusal(200_000_000, 50_000_000, 49_000_000, reserve),
            None
        );
        // Exactly the reserve left.
        assert_eq!(fee_floor_refusal(101_000_000, 1_000_000, 0, reserve), None);
        // 1 nanoERG short.
        let msg = fee_floor_refusal(100_999_999, 1_000_000, 0, reserve).unwrap();
        assert!(msg.contains("leave 99999999 nanoERG"), "{msg}");
        assert!(msg.contains("commit_reserve_nano"), "{msg}");
        // Change sent elsewhere: the tracker address loses the whole box.
        assert!(fee_floor_refusal(150_000_000, 100_000_000, 0, reserve).is_some());
        assert!(fee_floor_refusal(150_000_000, 100_000_000, 99_000_000, reserve).is_none());
        // 0 disables the floor.
        assert_eq!(fee_floor_refusal(1_000_000, 1_000_000, 0, 0), None);
    }

    // ------------------------------------------------------------------
    // Tracker signature (context var #6) denomination binding
    //
    // The token reserve contract verifies var #6 over
    // blake2b256(owner || receiver || tokenId) || …; a signature over the ERG
    // debtKey makes every token redemption unverifiable on-chain.
    // ------------------------------------------------------------------

    fn sign_and_decode(
        denomination: &basis_store::DenomKey,
    ) -> (
        [u8; 65],
        basis_store::PubKey,
        basis_store::PubKey,
        basis_store::PubKey,
    ) {
        let (tracker_secret, tracker_pubkey) = basis_store::schnorr::generate_keypair();
        let (_, issuer_pk) = basis_store::schnorr::generate_keypair();
        let (_, recipient_pk) = basis_store::schnorr::generate_keypair();
        let sig = sign_tracker_redemption(
            &tracker_secret,
            &tracker_pubkey,
            &issuer_pk,
            &recipient_pk,
            denomination,
            5_000_000,
            1_743_379_200_000,
            &[0x42; 32],
        )
        .expect("tracker signature signs");
        assert_eq!(sig.len(), 65);
        let mut array = [0u8; 65];
        array.copy_from_slice(&sig);
        (array, tracker_pubkey, issuer_pk, recipient_pk)
    }

    #[test]
    fn tracker_redemption_signature_binds_token_denomination() {
        let token_id = [0xab_u8; 32];
        let denom = basis_store::DenomKey::Token(token_id);
        let (sig, tracker_pubkey, issuer_pk, recipient_pk) = sign_and_decode(&denom);

        // Verifies against the TOKEN debtKey message — what the token contract evaluates.
        let token_message = basis_store::schnorr::signing_message(
            &issuer_pk,
            &recipient_pk,
            &denom,
            5_000_000,
            1_743_379_200_000,
            &[0x42; 32],
        );
        basis_store::schnorr::schnorr_verify(&sig, &token_message, &tracker_pubkey)
            .expect("token tracker signature must verify over the token debtKey message");

        // Regression pin: the ERG debtKey message must NOT verify. Signing the ERG
        // key was the bug — such a signature is rejected by the reserve contract.
        let erg_message = basis_store::schnorr::signing_message(
            &issuer_pk,
            &recipient_pk,
            &basis_store::DenomKey::Erg,
            5_000_000,
            1_743_379_200_000,
            &[0x42; 32],
        );
        assert!(
            basis_store::schnorr::schnorr_verify(&sig, &erg_message, &tracker_pubkey).is_err(),
            "token-note tracker signature must not verify over the ERG debtKey message"
        );
    }

    #[test]
    fn tracker_redemption_signature_erg_note_unchanged() {
        let (sig, tracker_pubkey, issuer_pk, recipient_pk) =
            sign_and_decode(&basis_store::DenomKey::Erg);

        let erg_message = basis_store::schnorr::signing_message(
            &issuer_pk,
            &recipient_pk,
            &basis_store::DenomKey::Erg,
            5_000_000,
            1_743_379_200_000,
            &[0x42; 32],
        );
        basis_store::schnorr::schnorr_verify(&sig, &erg_message, &tracker_pubkey)
            .expect("ERG-note tracker signature still verifies over the ERG debtKey message");

        // Sanity: a different denomination's message must not verify for the ERG note.
        let token_message = basis_store::schnorr::signing_message(
            &issuer_pk,
            &recipient_pk,
            &basis_store::DenomKey::Token([0xab_u8; 32]),
            5_000_000,
            1_743_379_200_000,
            &[0x42; 32],
        );
        assert!(
            basis_store::schnorr::schnorr_verify(&sig, &token_message, &tracker_pubkey).is_err()
        );
    }

    /// The unsigned transaction spending `inputs` (empty extensions, no data input), in the
    /// node's JSON format, as the builder writes it.
    fn unsigned_spending(inputs: &[&ErgoBox], outputs: Vec<Value>) -> UnsignedTransaction {
        let inputs: Vec<Value> = inputs
            .iter()
            .map(|b| json!({ "boxId": String::from(b.box_id()), "extension": {} }))
            .collect();
        serde_json::from_value(json!({ "inputs": inputs, "dataInputs": [], "outputs": outputs }))
            .unwrap()
    }

    fn json_output(ergo_tree: &str, value: u64, tokens: &[([u8; 32], u64)]) -> Value {
        let assets: Vec<Value> = tokens
            .iter()
            .map(|(id, amount)| json!({ "tokenId": hex::encode(id), "amount": amount }))
            .collect();
        json!({
            "value": value,
            "ergoTree": ergo_tree,
            "creationHeight": HEIGHT,
            "assets": assets,
            "additionalRegisters": {}
        })
    }

    /// Boxes for a redemption: the tracker key, a reserve holding its NFT, a plain fee box of
    /// the tracker key and the tracker box (tracker key, tracker NFT).
    struct FeeSigningFixture {
        tracker_secret: [u8; 32],
        tracker_tree_hex: String,
        reserve: ErgoBox,
        fee_box: ErgoBox,
        tracker_box: ErgoBox,
    }

    const RESERVE_NFT: [u8; 32] = [0x77; 32];
    /// Creation height of the fixture outputs: the signing context's height.
    const HEIGHT: u32 = 123_400;
    const TRACKER_NFT: [u8; 32] = [0x11; 32];

    fn fee_signing_fixture(reserve_tokens: &[([u8; 32], u64)]) -> FeeSigningFixture {
        use crate::local_wallet::tests::{fresh_key, tree_of, utxo_box};
        let (tracker_secret, tracker) = fresh_key();
        let (_, owner) = fresh_key();
        let tracker_tree = tree_of(&tracker.public_key());
        FeeSigningFixture {
            tracker_secret,
            tracker_tree_hex: crate::local_wallet::p2pk_tree_hex(&tracker.public_key()),
            reserve: utxo_box(
                &tree_of(&owner.public_key()),
                10_000_000,
                reserve_tokens,
                &[],
                123_000,
                0,
            ),
            fee_box: utxo_box(&tracker_tree, 5_000_000, &[], &[], 123_100, 1),
            tracker_box: utxo_box(
                &tracker_tree,
                2_000_000,
                &[(TRACKER_NFT, 1)],
                &[],
                123_200,
                2,
            ),
        }
    }

    impl FeeSigningFixture {
        /// The outputs of an ERG redemption of 0.001 ERG paid from `fee_input`: the reserve with
        /// its NFT, the recipient, the miner fee (0.001 ERG) and the rest of `fee_input` back to
        /// the tracker as change, carrying `change_tokens`.
        fn outputs(&self, fee_input: &ErgoBox, change_tokens: &[([u8; 32], u64)]) -> Vec<Value> {
            let reserve_tree = hex::encode(self.reserve.ergo_tree.sigma_serialize_bytes().unwrap());
            let change = fee_input.value.as_u64() - 1_000_000;
            vec![
                json_output(&reserve_tree, 9_000_000, &[(RESERVE_NFT, 1)]),
                json_output(&self.tracker_tree_hex, 1_000_000, &[]),
                json_output(FEE_CONTRACT_TREE, 1_000_000, &[]),
                json_output(&self.tracker_tree_hex, change, change_tokens),
            ]
        }
    }

    #[test]
    fn an_honest_redemption_passes_the_fee_signing_checks() {
        let fx = fee_signing_fixture(&[(RESERVE_NFT, 1)]);
        let unsigned = unsigned_spending(&[&fx.reserve, &fx.fee_box], fx.outputs(&fx.fee_box, &[]));
        let inputs = vec![fx.reserve.clone(), fx.fee_box.clone()];
        check_built_redemption(&unsigned, &inputs, Some(&fx.tracker_tree_hex), HEIGHT).unwrap();
    }

    /// A stale or wrong index entry offered the tracker box as a plain fee box. Its bytes hold the
    /// tracker NFT, so the tracker refuses to sign, whether or not the outputs carry the NFT on.
    #[test]
    fn a_fee_input_holding_a_token_is_never_signed() {
        let fx = fee_signing_fixture(&[(RESERVE_NFT, 1)]);
        let inputs = vec![fx.reserve.clone(), fx.tracker_box.clone()];
        for nft_in_change in [&[][..], &[(TRACKER_NFT, 1)][..]] {
            let unsigned = unsigned_spending(
                &[&fx.reserve, &fx.tracker_box],
                fx.outputs(&fx.tracker_box, nft_in_change),
            );
            let err = check_built_redemption(&unsigned, &inputs, Some(&fx.tracker_tree_hex), HEIGHT)
                .unwrap_err();
            assert!(err.contains("fee input 1"), "{err}");
            assert!(err.contains("holds tokens"), "{err}");
            assert!(err.contains(&hex::encode(TRACKER_NFT)), "{err}");
        }
    }

    #[test]
    fn a_redemption_that_burns_or_mints_a_token_is_never_signed() {
        // The reserve holds a second token that no output carries on.
        let fx = fee_signing_fixture(&[(RESERVE_NFT, 1), ([0x55; 32], 7)]);
        let unsigned = unsigned_spending(&[&fx.reserve, &fx.fee_box], fx.outputs(&fx.fee_box, &[]));
        let inputs = vec![fx.reserve.clone(), fx.fee_box.clone()];
        let err =
            check_built_redemption(&unsigned, &inputs, Some(&fx.tracker_tree_hex), HEIGHT).unwrap_err();
        assert!(err.contains("would be burned"), "{err}");

        // The reserve output carries an NFT the reserve does not hold.
        let fx = fee_signing_fixture(&[]);
        let unsigned = unsigned_spending(&[&fx.reserve, &fx.fee_box], fx.outputs(&fx.fee_box, &[]));
        let inputs = vec![fx.reserve.clone(), fx.fee_box.clone()];
        let err =
            check_built_redemption(&unsigned, &inputs, Some(&fx.tracker_tree_hex), HEIGHT).unwrap_err();
        assert!(err.contains("in no input"), "{err}");
    }

    #[test]
    fn fee_inputs_of_another_key_or_another_box_are_never_signed() {
        use crate::local_wallet::tests::{fresh_key, tree_of, utxo_box};
        let fx = fee_signing_fixture(&[(RESERVE_NFT, 1)]);
        let (_, stranger) = fresh_key();
        let foreign = utxo_box(
            &tree_of(&stranger.public_key()),
            5_000_000,
            &[],
            &[],
            123_100,
            3,
        );
        let unsigned = unsigned_spending(&[&fx.reserve, &foreign], fx.outputs(&foreign, &[]));
        let inputs = vec![fx.reserve.clone(), foreign.clone()];
        let err =
            check_built_redemption(&unsigned, &inputs, Some(&fx.tracker_tree_hex), HEIGHT).unwrap_err();
        assert!(err.contains("not locked by P2PK(tracker key)"), "{err}");

        // The node's bytes are another box than the one the transaction spends.
        let unsigned = unsigned_spending(&[&fx.reserve, &fx.fee_box], fx.outputs(&fx.fee_box, &[]));
        let inputs = vec![fx.reserve.clone(), foreign];
        let err =
            check_built_redemption(&unsigned, &inputs, Some(&fx.tracker_tree_hex), HEIGHT).unwrap_err();
        assert!(err.contains("input 1 spends box"), "{err}");
    }

    #[test]
    fn a_redemption_the_node_would_reject_is_never_signed() {
        use crate::local_wallet::tests::utxo_box;
        let fx = fee_signing_fixture(&[(RESERVE_NFT, 1)]);
        let inputs = vec![fx.reserve.clone(), fx.fee_box.clone()];
        let check = |outputs: Vec<Value>, height: u32| {
            let unsigned = unsigned_spending(&[&fx.reserve, &fx.fee_box], outputs);
            check_built_redemption(&unsigned, &inputs, Some(&fx.tracker_tree_hex), height)
        };

        // Value created out of nothing.
        let mut outputs = fx.outputs(&fx.fee_box, &[]);
        outputs[3]["value"] = json!(4_000_001u64);
        let err = check(outputs, HEIGHT).unwrap_err();
        assert!(
            err.contains("inputs hold 15000000 nanoERG but outputs 15000001"),
            "{err}"
        );

        // Outputs created above the signing height.
        let err = check(fx.outputs(&fx.fee_box, &[]), HEIGHT - 1).unwrap_err();
        assert!(err.contains("created at height 123400"), "{err}");

        // Outputs created below a fee input's creation height.
        let tracker_tree = fx.fee_box.ergo_tree.clone();
        let late_fee_box = utxo_box(&tracker_tree, 5_000_000, &[], &[], HEIGHT + 1, 4);
        let unsigned = unsigned_spending(
            &[&fx.reserve, &late_fee_box],
            fx.outputs(&late_fee_box, &[]),
        );
        let late_inputs = vec![fx.reserve.clone(), late_fee_box];
        let err =
            check_built_redemption(&unsigned, &late_inputs, Some(&fx.tracker_tree_hex), HEIGHT + 1)
                .unwrap_err();
        assert!(err.contains("outside 123401..=123401"), "{err}");

        // Change of 1 nanoERG: balanced, but below the minimum value of a box.
        let dust_fee_box = utxo_box(&tracker_tree, 1_000_001, &[], &[], 123_100, 5);
        let unsigned = unsigned_spending(
            &[&fx.reserve, &dust_fee_box],
            fx.outputs(&dust_fee_box, &[]),
        );
        let dust_inputs = vec![fx.reserve.clone(), dust_fee_box];
        let err = check_built_redemption(&unsigned, &dust_inputs, Some(&fx.tracker_tree_hex), HEIGHT)
            .unwrap_err();
        assert!(
            err.contains("output 3 holds 1 nanoERG, below its minimum value"),
            "{err}"
        );
    }

    /// Change that cannot form a box goes to the miner fee: a single fee box worth the fee plus
    /// 1 nanoERG pays a fee of fee + 1 and leaves no change output.
    #[test]
    fn change_below_the_minimum_box_value_goes_to_the_fee() {
        let fx = fee_signing_fixture(&[]);
        let tree = &fx.tracker_tree_hex;
        let fee = 1_000_000;
        // Every value from 2^14 to 2^21 - 1 encodes in 3 bytes, so the minimum is the same.
        let min = plain_box_min_value(tree, 30_000, HEIGHT).unwrap();
        assert!((16_384..2_097_152).contains(&min), "{min}");
        assert_eq!(plain_box_min_value(tree, min, HEIGHT).unwrap(), min);

        assert_eq!(fee_and_change(fee, 0, tree, HEIGHT).unwrap(), (fee, 0));
        assert_eq!(fee_and_change(fee, 1, tree, HEIGHT).unwrap(), (fee + 1, 0));
        assert_eq!(
            fee_and_change(fee, min - 1, tree, HEIGHT).unwrap(),
            (fee + min - 1, 0)
        );
        assert_eq!(fee_and_change(fee, min, tree, HEIGHT).unwrap(), (fee, min));
        assert_eq!(
            fee_and_change(fee, 4_000_000, tree, HEIGHT).unwrap(),
            (fee, 4_000_000)
        );

        // A recipient box of 1 nanoERG is below its minimum: the handler refuses such an amount.
        assert!(plain_box_min_value(tree, 1, HEIGHT).unwrap() > 1);
    }

    /// The tracker's fee input proof verifies against the signing context; the same proof on
    /// other outputs does not.
    #[test]
    fn fee_input_proofs_are_verified_after_signing() {
        let fx = fee_signing_fixture(&[(RESERVE_NFT, 1)]);
        let state = crate::local_wallet::tests::fixture_state();
        let secret = SecretKey::dlog_from_bytes(&fx.tracker_secret).unwrap();
        let inputs = vec![fx.reserve.clone(), fx.fee_box.clone()];
        let unsigned = unsigned_spending(&[&fx.reserve, &fx.fee_box], fx.outputs(&fx.fee_box, &[]));
        let signed = add_input_proof(
            &unsigned,
            None,
            &inputs,
            &[],
            &state.pre_header,
            &state.headers,
            1,
            &secret,
        )
        .unwrap();
        verify_fee_input_proofs(&signed, &inputs, &[], &state).unwrap();

        // The same proofs on outputs that pay 1 nanoERG more to the miner.
        let mut outputs = fx.outputs(&fx.fee_box, &[]);
        outputs[2]["value"] = json!(1_000_001u64);
        outputs[3]["value"] = json!(3_999_999u64);
        let other = unsigned_spending(&[&fx.reserve, &fx.fee_box], outputs);
        let spliced = Transaction::new(
            signed.inputs.clone(),
            other.data_inputs.clone(),
            other.output_candidates.clone(),
        )
        .unwrap();
        let err = verify_fee_input_proofs(&spliced, &inputs, &[], &state).unwrap_err();
        assert!(err.contains("fee input 1"), "{err}");
    }

    /// The address index lists the tracker box without its NFT. The fee scan of a redemption
    /// excludes the known tracker box id, so it is not even offered.
    #[tokio::test]
    async fn the_fee_scan_never_offers_the_tracker_box() {
        use crate::local_wallet::tests::mock_node;
        let fx = fee_signing_fixture(&[(RESERVE_NFT, 1)]);
        let tracker_id = String::from(fx.tracker_box.box_id());
        let fee_id = String::from(fx.fee_box.box_id());
        let page = json!([
            { "boxId": tracker_id, "value": 2_000_000u64, "ergoTree": fx.tracker_tree_hex,
              "assets": [], "additionalRegisters": {}, "creationHeight": 123_200 },
            { "boxId": fee_id, "value": 5_000_000u64, "ergoTree": fx.tracker_tree_hex,
              "assets": [], "additionalRegisters": {}, "creationHeight": 123_100 }
        ])
        .to_string();
        let (url, _) = mock_node(move |method, target, _| {
            match (method, target.split('?').next().unwrap_or_default()) {
                ("POST", "/blockchain/box/unspent/byAddress") if target.contains("offset=0&") => {
                    (200, page.clone())
                }
                ("POST", "/blockchain/box/unspent/byAddress") => (200, "[]".to_string()),
                _ => (404, "{}".to_string()),
            }
        })
        .await;
        let node = NodeClient { url, api_key: None };
        let pubkey: [u8; 33] = hex::decode(&fx.tracker_tree_hex[6..])
            .unwrap()
            .try_into()
            .unwrap();

        let offered: Vec<String> = node
            .tracker_fee_boxes(&pubkey, u64::MAX, &[])
            .await
            .unwrap()
            .into_iter()
            .map(|b| b.box_id)
            .collect();
        assert_eq!(
            offered,
            [tracker_id.clone(), fee_id.clone()],
            "the stale entry"
        );

        let offered: Vec<String> = node
            .tracker_fee_boxes(&pubkey, u64::MAX, &[tracker_id.as_str()])
            .await
            .unwrap()
            .into_iter()
            .map(|b| b.box_id)
            .collect();
        assert_eq!(offered, [fee_id]);
    }

    /// The node lists its last headers oldest first. The redemption's signing context (and the
    /// headers returned to the client) must still start with the newest header, and the
    /// pre-header must come from it, not from the oldest.
    #[tokio::test]
    async fn redemption_signing_context_starts_with_the_newest_header() {
        use crate::local_wallet::tests::{mock_node, LAST_HEADERS_JSON};

        let (url, seen) = mock_node(|method, target, _| match (method, target) {
            ("GET", "/blocks/lastHeaders/10") => (200, LAST_HEADERS_JSON.to_string()),
            _ => (404, "{}".to_string()),
        })
        .await;
        let node = NodeClient { url, api_key: None };

        let raw: Vec<u32> = node
            .last_headers()
            .await
            .unwrap()
            .iter()
            .map(|h| h.height)
            .collect();
        assert_eq!(
            raw,
            (123_405..=123_414).collect::<Vec<_>>(),
            "fixture is oldest first"
        );

        let context = node.state_context().await.unwrap();
        assert_eq!(context.pre_header.height, 123_414);
        let heights: Vec<u32> = context.headers.iter().map(|h| h.height).collect();
        assert_eq!(heights, (123_405..=123_414).rev().collect::<Vec<_>>());
        assert!(seen
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.target == "/blocks/lastHeaders/10"));
    }
}
