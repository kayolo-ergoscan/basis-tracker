//! Reserve tree repair (round 6, risk 1): the admin route that brings one edge of a reserve tree
//! back in step with the chain.
//!
//! The tracker's reserve tree for an (issuer, denomination) must hash to R5 of the issuer's
//! reserve box on chain, or every build against the reserve fails. It can fall out of step with
//! a value whose timestamp differs from the chain's (a redemption applied with another
//! `reserve_tree_timestamp`, e.g. by the legacy `/redeem/complete` without it), and then nothing
//! brought it back: the idempotent apply refuses "the same amount with another timestamp", and
//! dropping the journal entry leaves the tree as it is.
//!
//! `POST /redemption/tree/repair` (Admin) sets the edge's value `timestamp ‖ already_redeemed`
//! (and the note's cumulative redeemed amount) to the chain's, but only when the reserve tree then
//! hashes to R5 of the issuer's tracked reserve box, read from the node's UTXO set: it can only
//! put the tracker where the chain is. The values are given explicitly or taken from a journal
//! entry (`tx_id`: its `reserve_tree_timestamp` and `new_already_redeemed`). A repeat changes
//! nothing; `dry_run` shows what it would do. A repair is written to the reserve journal in one
//! batch with the note (replayed at startup), recorded in the `reserve_tree_repairs` partition
//! (`GET /redemption/tree/repairs`), and logged; once the reserve tree equals the chain's, the
//! reserve's journal entries marked out of step (`digest_mismatch`) are removed with it.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use basis_store::persistence::{JournaledRedemption, ReserveTreeRepairRecord};
use basis_store::{DenomKey, PubKey, ReserveTreeRepairOutcome, ReserveTreeValue};
use tracing::{error, warn};

use crate::models::{error_response, success_response, ApiResponse};
use crate::{AppState, TrackerCommand};

/// Body of `POST /redemption/tree/repair`: either `tx_id` (a journaled redemption whose values
/// are taken) or the edge and value written out. `dry_run` changes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TreeRepairRequest {
    /// A journaled redemption (64 hex characters): the edge, `reserve_tree_timestamp` and
    /// `new_already_redeemed` come from its entry.
    #[serde(default)]
    pub tx_id: Option<String>,
    /// Issuer (reserve owner) key, 33 bytes hex.
    #[serde(default)]
    pub issuer_pubkey: Option<String>,
    /// Recipient key, 33 bytes hex.
    #[serde(default)]
    pub recipient_pubkey: Option<String>,
    /// `"erg"` (the default) or `"token:<64 hex>"`.
    #[serde(default)]
    pub denomination: Option<String>,
    /// The timestamp of the edge's value on chain.
    #[serde(default)]
    pub timestamp: Option<u64>,
    /// The edge's cumulative redeemed amount on chain.
    #[serde(default)]
    pub already_redeemed: Option<u64>,
    /// Check and answer what the repair would do, without changing anything.
    #[serde(default)]
    pub dry_run: bool,
}

type Answer<T> = (StatusCode, Json<ApiResponse<T>>);

fn refuse<T>(status: StatusCode, message: impl Into<String>) -> Answer<T> {
    (status, Json(error_response(message.into())))
}

/// The edge and value a request names.
struct Target {
    issuer: PubKey,
    recipient: PubKey,
    denomination: DenomKey,
    value: ReserveTreeValue,
    tx_id: Option<String>,
}

fn parse_key(hex_key: &str, what: &str) -> Result<PubKey, String> {
    hex::decode(hex_key.trim())
        .ok()
        .and_then(|bytes| PubKey::try_from(bytes.as_slice()).ok())
        .ok_or_else(|| format!("{what} must be a 33-byte key (66 hex characters)"))
}

fn target<T>(state: &AppState, request: &TreeRepairRequest) -> Result<Target, Answer<T>> {
    let explicit = request.issuer_pubkey.is_some()
        || request.recipient_pubkey.is_some()
        || request.denomination.is_some()
        || request.timestamp.is_some()
        || request.already_redeemed.is_some();
    if let Some(tx_id) = &request.tx_id {
        if explicit {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "give either tx_id or the edge and value, not both",
            ));
        }
        if tx_id.len() != 64 || !tx_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "tx_id must be a transaction id (64 hex characters)",
            ));
        }
        let entry: JournaledRedemption = match state.tracker_storage.journaled_redemption(tx_id) {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                return Err(refuse(
                    StatusCode::NOT_FOUND,
                    format!("no journaled redemption {}", tx_id.to_ascii_lowercase()),
                ))
            }
            Err(e) => {
                error!("Cannot read the redemption journal: {:?}", e);
                return Err(refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the tracker cannot read its redemption journal",
                ));
            }
        };
        let Some(timestamp) = entry.reserve_tree_timestamp else {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                format!(
                    "redemption {} was journaled without its reserve tree timestamp; give the edge and value explicitly",
                    entry.tx_id
                ),
            ));
        };
        let (issuer, recipient, denomination) = crate::redemption_confirmer::journal_keys(&entry)
            .map_err(|e| refuse(StatusCode::BAD_REQUEST, e))?;
        return Ok(Target {
            issuer,
            recipient,
            denomination,
            value: ReserveTreeValue {
                timestamp,
                already_redeemed: entry.new_already_redeemed,
            },
            tx_id: Some(entry.tx_id),
        });
    }

    let missing = |what: &str| refuse(StatusCode::BAD_REQUEST, format!("{what} is required"));
    let issuer = parse_key(
        request
            .issuer_pubkey
            .as_deref()
            .ok_or_else(|| missing("issuer_pubkey"))?,
        "issuer_pubkey",
    )
    .map_err(|e| refuse(StatusCode::BAD_REQUEST, e))?;
    let recipient = parse_key(
        request
            .recipient_pubkey
            .as_deref()
            .ok_or_else(|| missing("recipient_pubkey"))?,
        "recipient_pubkey",
    )
    .map_err(|e| refuse(StatusCode::BAD_REQUEST, e))?;
    let denomination = match request.denomination.as_deref().map(str::trim) {
        None | Some("") => DenomKey::Erg,
        Some(raw) => DenomKey::parse(raw).map_err(|e| {
            refuse(
                StatusCode::BAD_REQUEST,
                format!("denomination must be \"erg\" or \"token:<64 hex>\": {e}"),
            )
        })?,
    };
    let timestamp = request.timestamp.ok_or_else(|| missing("timestamp"))?;
    let already_redeemed = request
        .already_redeemed
        .ok_or_else(|| missing("already_redeemed"))?;
    Ok(Target {
        issuer,
        recipient,
        denomination,
        value: ReserveTreeValue {
            timestamp,
            already_redeemed,
        },
        tx_id: None,
    })
}

/// R5 digest of the issuer's tracked reserve box in `denomination`, read from the node's UTXO
/// set (so a spent box is never taken for the chain's state): `(box id, digest)`.
async fn chain_reserve_digest<T>(
    state: &AppState,
    issuer_hex: &str,
    denomination: &DenomKey,
) -> Result<(String, [u8; 33]), Answer<T>> {
    let box_id = match crate::api::ensure_single_issuer_reserve(state, issuer_hex, denomination)
        .await
    {
        Ok(Some(box_id)) => basis_offchain::ergo_tx::decode_box_id(&box_id),
        Ok(None) => {
            return Err(refuse(
                StatusCode::CONFLICT,
                format!(
                    "issuer {issuer_hex} has no tracked reserve in {}: there is no chain state to repair towards",
                    denomination.denomination_id()
                ),
            ))
        }
        Err(conflict) => return Err(refuse(StatusCode::CONFLICT, conflict)),
    };
    let node = &state.config.ergo.scanner;
    let path = format!("/utxo/byId/{box_id}");
    let mut request = basis_store::http::bounded_client()
        .get(format!("{}{path}", node.node_url.trim_end_matches('/')));
    if let Some(key) = node.api_key.as_deref().filter(|k| !k.is_empty()) {
        request = request.header("api_key", key);
    }
    let unreadable = |e: String| {
        refuse(
            StatusCode::BAD_GATEWAY,
            format!("the reserve box {box_id} cannot be read from the node: {e}"),
        )
    };
    let response = request
        .send()
        .await
        .map_err(|e| unreadable(e.to_string()))?;
    match response.status().as_u16() {
        200 => {}
        404 => {
            return Err(refuse(
                StatusCode::CONFLICT,
                format!(
                    "the tracked reserve box {box_id} is not in the node's UTXO set (spent, or not in a block yet); retry once the scanner follows the reserve"
                ),
            ))
        }
        status => return Err(unreadable(format!("HTTP {status}"))),
    }
    let body = basis_store::http::read_json_capped(response)
        .await
        .map_err(|e| unreadable(e.to_string()))?;
    let digest = body
        .get("additionalRegisters")
        .and_then(|r| r.get("R5"))
        .and_then(|r5| r5.as_str())
        .and_then(crate::redemption_confirmer::r5_digest_hex)
        .and_then(|hex_digest| hex::decode(hex_digest).ok())
        .and_then(|bytes| <[u8; 33]>::try_from(bytes.as_slice()).ok());
    match digest {
        Some(digest) => Ok((box_id, digest)),
        None => Err(refuse(
            StatusCode::CONFLICT,
            format!("the reserve box {box_id} has no reserve tree in R5"),
        )),
    }
}

/// `POST /redemption/tree/repair` (Admin; round 6, risk 1): see the module documentation.
/// `200` with the record when the reserve tree holds the value now (`repaired`, `unchanged`) or
/// would (`would_repair`, a dry run); `409` when the reserve tree with the value would not hash
/// to the chain's R5 (nothing changes), or there is no single unspent reserve box to compare
/// with; `404` for an unknown journal entry or note.
pub async fn repair_reserve_tree(
    State(state): State<AppState>,
    Json(request): Json<TreeRepairRequest>,
) -> Answer<ReserveTreeRepairRecord> {
    let target = match target(&state, &request) {
        Ok(target) => target,
        Err(answer) => return answer,
    };
    let issuer_hex = hex::encode(target.issuer);
    let (reserve_box_id, chain_digest) =
        match chain_reserve_digest(&state, &issuer_hex, &target.denomination).await {
            Ok(found) => found,
            Err(answer) => return answer,
        };

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    if state
        .tx
        .send(TrackerCommand::RepairReserveTreeValue {
            issuer_pubkey: target.issuer,
            recipient_pubkey: target.recipient,
            denomination: target.denomination,
            value: target.value,
            chain_digest,
            dry_run: request.dry_run,
            response_tx,
        })
        .await
        .is_err()
    {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "tracker thread unavailable",
        );
    }
    let repair = match response_rx.await {
        Ok(Ok(repair)) => repair,
        Ok(Err(basis_store::NoteError::NotFound)) => {
            return refuse(
                StatusCode::NOT_FOUND,
                "the tracker holds no note for this issuer, recipient and denomination",
            )
        }
        Ok(Err(e)) => return refuse(StatusCode::CONFLICT, format!("not repaired: {e:?}")),
        Err(_) => return refuse(StatusCode::SERVICE_UNAVAILABLE, "tracker unavailable"),
    };

    let mut record = ReserveTreeRepairRecord {
        repaired_at_ms: crate::redemption_build::now_unix_ms(),
        issuer_pubkey: issuer_hex.clone(),
        recipient_pubkey: hex::encode(target.recipient),
        denomination: target.denomination.denomination_id(),
        reserve_box_id: reserve_box_id.clone(),
        tx_id: target.tx_id,
        repair,
        cleared_marked: Vec::new(),
    };
    match record.repair.outcome {
        ReserveTreeRepairOutcome::Refused => {
            return refuse(
                StatusCode::CONFLICT,
                format!(
                    "not repaired: with {} ‖ {} for the edge the tracker's reserve tree would hash to {}, not to {} in R5 of reserve box {}; nothing changed",
                    record.repair.after.timestamp,
                    record.repair.after.already_redeemed,
                    record.repair.digest_after,
                    record.repair.chain_digest,
                    reserve_box_id
                ),
            )
        }
        ReserveTreeRepairOutcome::WouldRepair => {
            return (StatusCode::OK, Json(success_response(record)));
        }
        ReserveTreeRepairOutcome::Repaired | ReserveTreeRepairOutcome::Unchanged => {}
    }
    if request.dry_run {
        return (StatusCode::OK, Json(success_response(record)));
    }

    // The reserve tree equals R5 of the reserve box now: entries marked out of step with the
    // chain have nothing left to wait for.
    record.cleared_marked = clear_marked(&state, &target.issuer, &target.denomination).await;
    if record.repair.outcome == ReserveTreeRepairOutcome::Repaired
        || !record.cleared_marked.is_empty()
    {
        warn!(
            "Operator repaired the reserve tree of {} in {} towards reserve box {}: edge {} {:?} -> {:?} (note redeemed {} -> {}), reserve tree digest {} -> {} (R5 {}); cleared marked entries {:?}",
            record.issuer_pubkey,
            record.denomination,
            reserve_box_id,
            record.recipient_pubkey,
            record.repair.before,
            record.repair.after,
            record.repair.note_redeemed_before,
            record.repair.after.already_redeemed,
            record.repair.digest_before,
            record.repair.digest_after,
            record.repair.chain_digest,
            record.cleared_marked
        );
        if let Err(e) = state.tracker_storage.record_tree_repair(&record) {
            error!(
                "The reserve tree repair is made, but its record cannot be written: {:?}",
                e
            );
        }
    }
    (StatusCode::OK, Json(success_response(record)))
}

/// Remove the journal entries of `issuer`'s reserve in `denomination` that are marked out of
/// step with the chain (`digest_mismatch`); their ids.
async fn clear_marked(state: &AppState, issuer: &PubKey, denomination: &DenomKey) -> Vec<String> {
    let entries = match state.tracker_storage.journaled_redemptions() {
        Ok(entries) => entries,
        Err(e) => {
            error!("Cannot read the redemption journal: {:?}", e);
            return Vec::new();
        }
    };
    let mut cleared = Vec::new();
    for entry in entries {
        if entry.digest_mismatch.is_none() {
            continue;
        }
        match crate::redemption_confirmer::journal_keys(&entry) {
            Ok((entry_issuer, _, entry_denomination))
                if &entry_issuer == issuer && &entry_denomination == denomination => {}
            _ => continue,
        }
        match state
            .tracker_storage
            .remove_journaled_redemption(&entry.tx_id)
        {
            Ok(()) => cleared.push(entry.tx_id),
            Err(e) => error!(
                "Cannot remove marked journal entry {}: {:?}",
                entry.tx_id, e
            ),
        }
    }
    if !cleared.is_empty() {
        let shared = state.shared_tracker_state.lock().await.clone();
        shared.forget_submitted_redemptions(&cleared);
    }
    cleared
}

/// `GET /redemption/tree/repairs` (Admin; round 6, risk 1): every recorded reserve tree repair,
/// oldest first.
pub async fn list_tree_repairs(
    State(state): State<AppState>,
) -> Answer<Vec<ReserveTreeRepairRecord>> {
    match state.tracker_storage.tree_repairs() {
        Ok(records) => (StatusCode::OK, Json(success_response(records))),
        Err(e) => {
            error!("Cannot read the tree repairs: {:?}", e);
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the tracker cannot read its tree repairs",
            )
        }
    }
}
