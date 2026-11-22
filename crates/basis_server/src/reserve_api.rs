//! API handlers for reserve-related endpoints

use std::collections::HashMap;

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

use basis_store::persistence::JournaledRedemption;
use basis_store::{DenomKey, ExtendedReserveInfo, IouNote, PubKey};

use crate::{
    models::{success_response, ApiResponse},
    AppState, TrackerCommand,
};

/// Outstanding debt per (issuer, denomination) of the notes this tracker holds (round 5, item 5).
type OutstandingDebts = HashMap<(PubKey, DenomKey), u64>;

/// Add `note`'s outstanding debt (`amount_collected - amount_redeemed`) to its issuer's total in
/// its denomination; totals saturate at `u64::MAX`.
fn add_outstanding(debts: &mut OutstandingDebts, issuer: PubKey, note: &IouNote) {
    let outstanding = note.amount_collected.saturating_sub(note.amount_redeemed);
    let total = debts.entry((issuer, note.denomination)).or_insert(0);
    *total = total.saturating_add(outstanding);
}

/// Redeemed amounts of the redemptions waiting for the chain, per (issuer, denomination)
/// (round 5b, F11).
type PendingRedemptions = HashMap<(PubKey, DenomKey), u64>;

/// Add `entry`'s redeemed amount to its issuer's pending total in its denomination if it waits
/// for the chain: submitted through `/redemption/submit`, journaled, not applied yet. A marked
/// entry (`digest_mismatch`) is applied already and adds nothing. Totals saturate.
fn add_pending(pending: &mut PendingRedemptions, entry: &JournaledRedemption) {
    if entry.digest_mismatch.is_some() {
        return;
    }
    if let Ok((issuer, _, denomination)) = crate::redemption_confirmer::journal_keys(entry) {
        let total = pending.entry((issuer, denomination)).or_insert(0);
        *total = total.saturating_add(entry.redeemed_amount);
    }
}

/// The redemptions waiting for the chain, from the redemption journal: a handful of entries,
/// since builds of a reserve wait while it has one.
fn pending_redemptions(state: &AppState) -> Result<PendingRedemptions, String> {
    let entries = state
        .tracker_storage
        .journaled_redemptions()
        .map_err(|e| format!("redemption journal read failed: {e:?}"))?;
    let mut pending = PendingRedemptions::new();
    for entry in &entries {
        add_pending(&mut pending, entry);
    }
    Ok(pending)
}

/// The outstanding debts of the notes of `owners` and the redemptions of theirs waiting for the
/// chain: what [`reserve_view`] reports.
async fn reserve_figures(
    state: &AppState,
    owners: impl IntoIterator<Item = PubKey>,
) -> Result<(OutstandingDebts, PendingRedemptions), String> {
    let debts = outstanding_debts(state, owners).await?;
    Ok((debts, pending_redemptions(state)?))
}

/// The outstanding debts of the notes of `issuers`, read from the tracker thread through the
/// issuer index (one `GetNotesByIssuer` per issuer). Round 5b (F11): never all notes. An
/// issuer's notes are bounded by `server.notes_max_recipients_per_issuer` per denomination, and
/// the issuers asked about are the owners of reserves the scanner tracks, so the work per
/// request follows the reserves, not every note the tracker holds.
async fn outstanding_debts(
    state: &AppState,
    issuers: impl IntoIterator<Item = PubKey>,
) -> Result<OutstandingDebts, String> {
    let mut debts = OutstandingDebts::new();
    let issuers: std::collections::BTreeSet<PubKey> = issuers.into_iter().collect();
    for issuer in issuers {
        let (tx, rx) = tokio::sync::oneshot::channel();
        state
            .tx
            .send(TrackerCommand::GetNotesByIssuer {
                issuer_pubkey: issuer,
                response_tx: tx,
            })
            .await
            .map_err(|_| "tracker thread unavailable".to_string())?;
        let notes = rx
            .await
            .map_err(|_| "tracker thread unavailable".to_string())?
            .map_err(|e| format!("note lookup failed: {e:?}"))?;
        for note in &notes {
            add_outstanding(&mut debts, issuer, note);
        }
    }
    Ok(debts)
}

/// The owner key of a stored reserve (lower-case hex, possibly double-hex-encoded or with the
/// `07` register prefix), if it is a 33-byte key.
fn owner_key(owner_pubkey: &str) -> Option<PubKey> {
    let owner = decode_potentially_double_hex_encoded(owner_pubkey).to_ascii_lowercase();
    hex::decode(basis_store::normalize_public_key(&owner))
        .ok()
        .and_then(|bytes| PubKey::try_from(bytes.as_slice()).ok())
}

/// The API view of a reserve, with its outstanding debt from `debts` and its redemptions
/// waiting for the chain from `pending`.
///
/// `total_debt` is what the reserve's owner still owes in the reserve's denomination on the
/// notes this tracker holds (`amount_collected - amount_redeemed`, summed); it is per (owner,
/// denomination), not per box. `collateralization_ratio` is `collateral_amount / total_debt`,
/// and `null` when nothing is owed. A redemption submitted through `/redemption/submit` counts
/// only once it is applied (mined, `[confirmation] min_depth` deep): while it is journaled,
/// `total_debt` still includes it, `pending_redemption_amount` says how much, and once its block
/// is in, `collateral_amount` (the scanner's reserve box) may already be the smaller
/// successor's (round 5b, F11).
fn reserve_view(
    info: ExtendedReserveInfo,
    debts: &OutstandingDebts,
    pending: &PendingRedemptions,
) -> SerializableReserveInfo {
    let key = match (owner_key(&info.owner_pubkey), info.denomination()) {
        (Some(owner), Some(denomination)) => Some((owner, denomination)),
        _ => None,
    };
    let total_debt = key.and_then(|k| debts.get(&k).copied()).unwrap_or(0);
    let pending_redemption_amount = key.and_then(|k| pending.get(&k).copied()).unwrap_or(0);
    let collateral_amount = info.base_info.collateral_amount;
    let collateralization_ratio =
        (total_debt > 0).then(|| collateral_amount as f64 / total_debt as f64);
    SerializableReserveInfo {
        owner_pubkey: decode_potentially_double_hex_encoded(&info.owner_pubkey),
        box_id: info.box_id,
        collateral_amount,
        total_debt,
        pending_redemption_amount,
        tracker_nft_id: info.base_info.tracker_nft_id,
        reserve_token_id: info.base_info.reserve_token_id,
        last_updated_height: info.base_info.last_updated_height,
        last_updated_timestamp: info.last_updated_timestamp,
        collateralization_ratio,
        refund_initiation_height: info.base_info.refund_initiation_height,
    }
}

/// 500 for a failed read of the notes (or the redemption journal) behind the reserves' debt.
fn debt_read_failed<T>(e: String) -> (StatusCode, Json<ApiResponse<T>>) {
    tracing::error!("Failed to read the notes behind the reserves' debt: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(crate::models::error_response(
            "Failed to read the notes behind the reserves' debt".to_string(),
        )),
    )
}

// Helper function to decode potentially double-hex-encoded strings
fn decode_potentially_double_hex_encoded(hex_string: &str) -> String {
    // First, try to decode as hex
    if let Ok(decoded_bytes) = hex::decode(hex_string) {
        // Check if the decoded bytes look like a hex string (only contains valid hex chars)
        let decoded_as_string = String::from_utf8_lossy(&decoded_bytes);
        if is_hex_string(&decoded_as_string) {
            // It was double-encoded, return the single-decoded version
            return decoded_as_string.to_string();
        }
    }
    // If not double-encoded, return the original
    hex_string.to_string()
}

// Helper function to check if a string contains only valid hex characters
fn is_hex_string(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Get all reserves (regardless of issuer)
#[axum::debug_handler]
pub async fn get_all_reserves(
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<Vec<SerializableReserveInfo>>>) {
    tracing::debug!("Getting all reserves");

    // Get reserve storage from scanner and query database directly
    let stored = state
        .ergo_scanner
        .lock()
        .await
        .reserve_storage()
        .get_all_reserves();

    // Get all reserves from database
    match stored {
        Ok(all_reserves) => {
            // Round 5 (item 5): the debt of each reserve comes from the notes this tracker holds,
            // read for the owners of these reserves only (round 5b, F11).
            let owners = all_reserves
                .iter()
                .filter_map(|reserve| owner_key(&reserve.owner_pubkey));
            let (debts, pending) = match reserve_figures(&state, owners).await {
                Ok(figures) => figures,
                Err(e) => return debt_read_failed(e),
            };
            let reserves: Vec<SerializableReserveInfo> = all_reserves
                .into_iter()
                .map(|info| reserve_view(info, &debts, &pending))
                .collect();

            tracing::info!("Returning {} reserves (from database)", reserves.len());

            (StatusCode::OK, Json(success_response(reserves)))
        }
        Err(e) => {
            tracing::error!("Failed to get reserves from database: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(crate::models::error_response(
                    "Failed to retrieve reserves from database".to_string(),
                )),
            )
        }
    }
}

/// Get reserves by issuer public key
#[axum::debug_handler]
pub async fn get_reserves_by_issuer(
    State(state): State<AppState>,
    axum::extract::Path(pubkey_hex): axum::extract::Path<String>,
) -> (StatusCode, Json<ApiResponse<Vec<SerializableReserveInfo>>>) {
    tracing::debug!("Getting reserves for issuer: {}", pubkey_hex);

    // Get reserve storage from scanner and query database directly
    let stored = state
        .ergo_scanner
        .lock()
        .await
        .reserve_storage()
        .get_all_reserves();

    // Round 4 (C10): compare normalized keys, so an upper-case or 07-prefixed path finds the
    // issuer's reserves (the stored key is lower-case hex without the prefix).
    let wanted = basis_store::normalize_public_key(&pubkey_hex.to_ascii_lowercase());

    // Get all reserves from database and filter by issuer
    match stored {
        Ok(all_reserves) => {
            let mine: Vec<ExtendedReserveInfo> = all_reserves
                .into_iter()
                .filter(|reserve| {
                    basis_store::normalize_public_key(&reserve.owner_pubkey.to_ascii_lowercase())
                        == wanted
                })
                .collect();
            // Round 5 (item 5): the debt comes from the notes this tracker holds for the issuer.
            let owners = mine.first().and_then(|r| owner_key(&r.owner_pubkey));
            let (debts, pending) = match reserve_figures(&state, owners).await {
                Ok(figures) => figures,
                Err(e) => return debt_read_failed(e),
            };
            let reserves: Vec<SerializableReserveInfo> = mine
                .into_iter()
                .map(|info| reserve_view(info, &debts, &pending))
                .collect();

            tracing::info!(
                "Returning {} reserves for issuer {} (from database)",
                reserves.len(),
                pubkey_hex
            );

            (StatusCode::OK, Json(success_response(reserves)))
        }
        Err(e) => {
            tracing::error!("Failed to get reserves from database: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(crate::models::error_response(
                    "Failed to retrieve reserves from database".to_string(),
                )),
            )
        }
    }
}

/// Get a specific reserve by box ID
#[axum::debug_handler]
pub async fn get_reserve_by_box_id(
    State(state): State<AppState>,
    axum::extract::Path(box_id): axum::extract::Path<String>,
) -> (
    StatusCode,
    Json<ApiResponse<Option<SerializableReserveInfo>>>,
) {
    tracing::debug!("Getting reserve by box ID: {}", box_id);

    // Get reserve storage from scanner and query database directly
    let stored = state
        .ergo_scanner
        .lock()
        .await
        .reserve_storage()
        .get_reserve(&box_id);

    // Get the specific reserve from database
    match stored {
        Ok(Some(reserve_info)) => {
            // Round 5 (item 5): the debt comes from the notes this tracker holds for the owner.
            let (debts, pending) =
                match reserve_figures(&state, owner_key(&reserve_info.owner_pubkey)).await {
                    Ok(figures) => figures,
                    Err(e) => return debt_read_failed(e),
                };
            let serializable_reserve = reserve_view(reserve_info, &debts, &pending);

            tracing::info!("Successfully retrieved reserve with box ID: {}", box_id);

            (
                StatusCode::OK,
                Json(success_response(Some(serializable_reserve))),
            )
        }
        Ok(None) => {
            tracing::info!("Reserve with box ID {} not found", box_id);
            (StatusCode::NOT_FOUND, Json(success_response(None)))
        }
        Err(e) => {
            tracing::error!("Failed to get reserve from database: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(crate::models::error_response(
                    "Failed to retrieve reserve from database".to_string(),
                )),
            )
        }
    }
}

/// Serializable quarantine record for API responses (issue #19).
#[derive(Debug, Serialize)]
pub struct SerializableQuarantinedReserve {
    pub box_id: String,
    pub owner_pubkey: String,
    pub denomination: String,
    pub reason: String,
    pub quarantined_at: u64,
}

/// List reserve boxes rejected by admission control (issue #19).
///
/// Quarantined boxes are never tracked: a duplicate carrying someone else's key
/// in R4 cannot block the victim, and the record tells the operator why the box
/// was rejected.
#[axum::debug_handler]
pub async fn get_quarantined_reserves(
    State(state): State<AppState>,
) -> (
    StatusCode,
    Json<ApiResponse<Vec<SerializableQuarantinedReserve>>>,
) {
    tracing::debug!("Getting quarantined reserves");

    let scanner = state.ergo_scanner.lock().await;
    let reserve_storage = scanner.reserve_storage();

    match reserve_storage.get_all_quarantined() {
        Ok(records) => {
            let quarantined: Vec<SerializableQuarantinedReserve> = records
                .into_iter()
                .map(|r| SerializableQuarantinedReserve {
                    box_id: r.box_id,
                    owner_pubkey: decode_potentially_double_hex_encoded(&r.owner_pubkey),
                    denomination: r.denomination,
                    reason: r.reason,
                    quarantined_at: r.quarantined_at,
                })
                .collect();

            (StatusCode::OK, Json(success_response(quarantined)))
        }
        Err(e) => {
            tracing::error!("Failed to get quarantined reserves from database: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(crate::models::error_response(
                    "Failed to retrieve quarantined reserves from database".to_string(),
                )),
            )
        }
    }
}

/// Serializable version of ExtendedReserveInfo for API responses
#[derive(Debug, Serialize)]
pub struct SerializableReserveInfo {
    pub box_id: String,
    pub owner_pubkey: String,
    pub collateral_amount: u64,
    /// Outstanding debt of the owner in the reserve's denomination on the notes this tracker
    /// holds: the sum of `amount_collected - amount_redeemed` (round 5). Per (owner,
    /// denomination): two reserves of one owner in one denomination show the same debt. A
    /// journaled redemption (submitted, not yet applied) is still included (round 5b, F11).
    pub total_debt: u64,
    /// Round 5b (F11): the redeemed amount of the owner's redemptions in this denomination that
    /// wait for the chain (submitted through `/redemption/submit`, journaled, not applied yet);
    /// 0 when none waits. `total_debt` still includes it: once they are applied, the debt is
    /// `total_debt - pending_redemption_amount`.
    pub pending_redemption_amount: u64,
    pub tracker_nft_id: String, // Tracker NFT ID from R6 register (hex-encoded serialized SColl(SByte) format following byte_array_register_serialization.md spec)
    /// Reserve token ID (hex-encoded) for token-backed reserves, or empty for ERG reserves.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reserve_token_id: String,
    pub last_updated_height: u64,
    pub last_updated_timestamp: u64,
    /// `collateral_amount / total_debt`, `null` when `total_debt` is 0.
    pub collateralization_ratio: Option<f64>,
    pub refund_initiation_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(to: u8, total: u64, redeemed: u64, denomination: DenomKey) -> IouNote {
        IouNote {
            recipient_pubkey: [to; 33],
            amount_collected: total,
            amount_redeemed: redeemed,
            timestamp: 1,
            signature: [0u8; 65],
            tracker_nft_id: [0x5a; 32],
            denomination,
        }
    }

    fn reserve(owner: &PubKey, token: Option<[u8; 32]>, collateral: u64) -> ExtendedReserveInfo {
        ExtendedReserveInfo {
            base_info: basis_store::ReserveInfo {
                collateral_amount: collateral,
                last_updated_height: 1,
                contract_address: String::new(),
                tracker_nft_id: hex::encode([0x5a; 32]),
                refund_initiation_height: 0,
                reserve_token_id: token.map(hex::encode).unwrap_or_default(),
            },
            // Whatever the scanner stored: the view reports the notes' debt.
            total_debt: 12345,
            box_id: "box".to_string(),
            owner_pubkey: hex::encode(owner),
            last_updated_timestamp: 0,
        }
    }

    /// Round 5, item 5: a reserve's debt is what its owner still owes in its denomination on
    /// the notes this tracker holds (total minus redeemed, summed), and the ratio is the
    /// collateral over that debt, `null` when nothing is owed.
    #[test]
    fn a_reserve_reports_its_owners_outstanding_debt_and_ratio() {
        let (a, b) = ([0x02; 33], [0x03; 33]);
        let token = [0x7c; 32];
        let mut debts = OutstandingDebts::new();
        add_outstanding(&mut debts, a, &note(1, 300, 100, DenomKey::Erg));
        add_outstanding(&mut debts, a, &note(2, 400, 0, DenomKey::Erg));
        add_outstanding(&mut debts, a, &note(3, 50, 50, DenomKey::Token(token)));
        add_outstanding(&mut debts, b, &note(4, 10, 0, DenomKey::Erg));

        let none = PendingRedemptions::new();
        let erg = reserve_view(reserve(&a, None, 1_200), &debts, &none);
        assert_eq!(erg.total_debt, 600, "200 + 400");
        assert_eq!(erg.collateralization_ratio, Some(2.0));

        // Fully redeemed: nothing owed, no ratio.
        let tokens = reserve_view(reserve(&a, Some(token), 1_000), &debts, &none);
        assert_eq!(tokens.total_debt, 0);
        assert_eq!(tokens.collateralization_ratio, None);
        let json = serde_json::to_value(&tokens).unwrap();
        assert!(json["collateralization_ratio"].is_null(), "{json}");
        assert_eq!(json["total_debt"], 0);
        assert_eq!(json["pending_redemption_amount"], 0);

        // Another owner, and an owner stored with the register prefix.
        let other = reserve_view(reserve(&b, None, 5), &debts, &none);
        assert_eq!(other.total_debt, 10);
        assert_eq!(other.collateralization_ratio, Some(0.5));
        let mut prefixed = reserve(&b, None, 5);
        prefixed.owner_pubkey = format!("07{}", hex::encode(b));
        assert_eq!(reserve_view(prefixed, &debts, &none).total_debt, 10);

        // Totals saturate instead of overflowing.
        add_outstanding(&mut debts, b, &note(5, u64::MAX, 0, DenomKey::Erg));
        assert_eq!(
            reserve_view(reserve(&b, None, 5), &debts, &none).total_debt,
            u64::MAX
        );
    }

    /// Round 5b, F11: a reserve notes how much of its owner's debt waits for a redemption that
    /// is in a mempool or in a block not deep enough yet: the journaled amounts of its owner in
    /// its denomination. A marked entry is applied already and adds nothing. The debt and the
    /// ratio stay as the notes say.
    #[test]
    fn a_reserve_notes_the_redemptions_waiting_for_the_chain() {
        let (a, b) = ([0x02; 33], [0x03; 33]);
        let token = [0x7c; 32];
        let mut debts = OutstandingDebts::new();
        add_outstanding(&mut debts, a, &note(1, 300, 0, DenomKey::Erg));
        add_outstanding(&mut debts, b, &note(2, 50, 0, DenomKey::Erg));
        let journaled = |owner: &PubKey, denomination: DenomKey, amount: u64| JournaledRedemption {
            tx_id: "ab".repeat(32),
            issuer_pubkey: hex::encode(owner),
            recipient_pubkey: hex::encode([0x01; 33]),
            denomination: denomination.denomination_id(),
            redeemed_amount: amount,
            ..Default::default()
        };
        let mut pending = PendingRedemptions::new();
        add_pending(&mut pending, &journaled(&a, DenomKey::Erg, 100));
        add_pending(&mut pending, &journaled(&a, DenomKey::Erg, 20));
        add_pending(&mut pending, &journaled(&a, DenomKey::Token(token), 7));
        add_pending(
            &mut pending,
            &JournaledRedemption {
                digest_mismatch: Some("applied, out of step".to_string()),
                ..journaled(&b, DenomKey::Erg, 5)
            },
        );
        // An entry whose keys do not parse is skipped.
        add_pending(
            &mut pending,
            &JournaledRedemption {
                issuer_pubkey: "zz".to_string(),
                ..journaled(&a, DenomKey::Erg, 1_000)
            },
        );

        let erg = reserve_view(reserve(&a, None, 1_200), &debts, &pending);
        assert_eq!((erg.total_debt, erg.pending_redemption_amount), (300, 120));
        assert_eq!(erg.collateralization_ratio, Some(4.0));
        let json = serde_json::to_value(&erg).unwrap();
        assert_eq!(json["pending_redemption_amount"], 120);
        let tokens = reserve_view(reserve(&a, Some(token), 10), &debts, &pending);
        assert_eq!((tokens.total_debt, tokens.pending_redemption_amount), (0, 7));
        let other = reserve_view(reserve(&b, None, 5), &debts, &pending);
        assert_eq!((other.total_debt, other.pending_redemption_amount), (50, 0));
    }
}
