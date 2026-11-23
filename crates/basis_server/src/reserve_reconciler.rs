//! Reserve reconciler (round 6, risk 2): redemptions found on chain that this tracker did not
//! submit.
//!
//! Only redemptions submitted through `/redemption/submit` were journaled and applied. One
//! broadcast elsewhere (the recipient's own node, the front's `/node/transactions`, another
//! wallet), or one dropped from the journal and mined later, left the tracker's reserve tree one
//! redemption behind R5 of the reserve box on chain, and every build of that reserve failed
//! ("no unspent reserve box matches the tracker's reserve tree") until an operator repaired it.
//!
//! Before each journal pass the confirmer compares every tracked reserve of this tracker with the
//! tracker's reserve tree. For a reserve whose box (from the node's UTXO set) holds another R5
//! digest and that has no journaled redemption, it walks the reserve's lineage back on the node's
//! blockchain index (the box's creating transaction, its reserve input, at most
//! [`MAX_TRACE_STEPS`] steps) to the oldest reserve box whose R5 is the tracker's reserve tree. The
//! transaction that spent that box is reproduced from its context extension (action 0, the
//! receiver, the note timestamp) and the reserve's value (or reserve token) delta: the tracker's
//! reserve tree with `timestamp || stored + redeemed` for that edge must hash to R5 of the
//! transaction's reserve output. Then it is journaled like the tracker's own redemption
//! (`detected_on_chain`), and the confirmer applies it once it is `min_depth` deep, compared with
//! that R5. Several redemptions in a row are taken one per pass, oldest first. A step that cannot
//! be reproduced is logged once (per reserve box and tracker digest) for an operator
//! (`POST /redemption/tree/repair`); nothing is changed.
//!
//! The extension is read from the transaction's indexed input (`spendingProof`), or else from the
//! block's transactions (`/blocks/{blockId}/transactions`). Unchanged reserves cost no node
//! request: a reserve whose box and tracker digest were already compared is skipped.

use std::collections::HashMap;

use basis_store::persistence::{JournaledRedemption, TrackerStorage};
use basis_store::{DenomKey, PubKey, ReserveTracker};
use serde_json::Value;
use tracing::{info, warn};

use crate::tracker_box_updater::{SharedTrackerState, TrackerBoxUpdateConfig};
use crate::TrackerCommand;

/// How many reserve boxes back a reserve's lineage is followed to find the oldest step the
/// tracker has not applied.
pub const MAX_TRACE_STEPS: usize = 8;

/// What one pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Redemptions found on chain and journaled (`detected_on_chain`), by transaction id.
    pub journaled: Vec<String>,
    /// Reserve boxes out of step with the tracker that could not be traced or reproduced
    /// (logged for an operator).
    pub unexplained: Vec<String>,
}

/// Reserves already compared, by `(issuer, denomination)`: the reserve box and the tracker's
/// reserve tree digest they were compared at. Nothing is asked again until either changes.
#[derive(Debug, Default)]
pub struct ReconcileCache {
    compared: HashMap<(String, String), (String, String)>,
}

/// One pass over the tracked reserves of this tracker (see the module documentation).
pub async fn reconcile_reserves(
    config: &TrackerBoxUpdateConfig,
    storage: &TrackerStorage,
    shared_state: &SharedTrackerState,
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    reserves: &ReserveTracker,
    cache: &mut ReconcileCache,
) -> ReconcileOutcome {
    let mut outcome = ReconcileOutcome::default();
    let tracker_nft = shared_state.get_tracker_nft_id();
    let mut by_reserve: HashMap<(String, String), Vec<basis_store::ExtendedReserveInfo>> =
        HashMap::new();
    for info in reserves.get_all_reserves() {
        if let Some(nft) = &tracker_nft {
            if !info.base_info.tracker_nft_id.eq_ignore_ascii_case(nft) {
                continue;
            }
        }
        let Some(denomination) = info.denomination() else {
            continue;
        };
        let issuer = basis_store::normalize_public_key(&info.owner_pubkey.to_ascii_lowercase());
        by_reserve
            .entry((issuer, denomination.denomination_id()))
            .or_default()
            .push(info);
    }

    for ((issuer_hex, denomination_id), infos) in by_reserve {
        // Two reserves of one issuer in one denomination share one reserve tree: which one a
        // redemption spent is ambiguous, and builds refuse them anyway.
        let [info] = infos.as_slice() else {
            continue;
        };
        let Ok(denomination) = DenomKey::parse(&denomination_id) else {
            continue;
        };
        let Some(issuer) = hex::decode(&issuer_hex)
            .ok()
            .and_then(|bytes| PubKey::try_from(bytes.as_slice()).ok())
        else {
            continue;
        };
        // A journaled redemption of this reserve: the confirmer is on it.
        match crate::redemption_confirmer::waiting_redemption(storage, &issuer_hex, &denomination) {
            Ok(None) => {}
            Ok(Some(_)) => continue,
            Err(e) => {
                warn!("Reserve reconciler: the redemption journal cannot be read: {e}");
                return outcome;
            }
        }
        let Some(tracker_digest) = tracker_reserve_digest(cmd_tx, &issuer, &denomination).await
        else {
            return outcome;
        };
        let key = (issuer_hex.clone(), denomination_id.clone());
        let box_id = info.box_id.to_ascii_lowercase();
        if cache.compared.get(&key) == Some(&(box_id.clone(), tracker_digest.clone())) {
            continue;
        }
        match reconcile_reserve(
            config,
            storage,
            cmd_tx,
            &issuer,
            &denomination,
            &box_id,
            &tracker_digest,
        )
        .await
        {
            Ok(Step::Matches) => {}
            Ok(Step::Journaled(tx_id)) => {
                outcome.journaled.push(tx_id);
                // The digest changes once the confirmer applies it; compare again then.
                continue;
            }
            Ok(Step::Unexplained(why)) => {
                warn!(
                    "Reserve box {} of {} in {} holds another reserve tree than the tracker's ({}), and {}. Builds against this reserve fail until an operator brings the tracker's reserve tree in step (POST /redemption/tree/repair).",
                    box_id, issuer_hex, denomination_id, tracker_digest, why
                );
                outcome.unexplained.push(box_id.clone());
            }
            Err(e) => {
                // A node error or an index that lags behind: tried again at the next pass.
                info!(
                    "Reserve reconciler: reserve box {} of {} cannot be compared yet: {}",
                    box_id, issuer_hex, e
                );
                continue;
            }
        }
        cache.compared.insert(key, (box_id, tracker_digest));
    }
    outcome
}

/// What reconciling one reserve found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// Its box's R5 is the tracker's reserve tree, or the redemption is journaled already.
    Matches,
    /// A redemption found on chain was journaled.
    Journaled(String),
    /// Out of step, and not by a redemption the tracker can reproduce: why.
    Unexplained(String),
}

async fn reconcile_reserve(
    config: &TrackerBoxUpdateConfig,
    storage: &TrackerStorage,
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    issuer: &PubKey,
    denomination: &DenomKey,
    box_id: &str,
    tracker_digest: &str,
) -> Result<Step, String> {
    let Some(current) = node_get(config, &format!("/utxo/byId/{box_id}")).await? else {
        // Spent meanwhile, or not in a block yet: the scanner follows the reserve first.
        return Err(format!("reserve box {box_id} is not in the UTXO set"));
    };
    if box_digest(&current).as_deref() == Some(tracker_digest) {
        return Ok(Step::Matches);
    }

    // Walk back to the oldest reserve box whose R5 is the tracker's reserve tree.
    let mut successor = current;
    for _ in 0..MAX_TRACE_STEPS {
        let successor_id = str_field(&successor, "boxId").unwrap_or_default();
        let Some(tx_id) = str_field(&successor, "transactionId") else {
            return Err(format!("box {successor_id} names no creating transaction"));
        };
        let Some(tx) = node_get(config, &format!("/blockchain/transaction/byId/{tx_id}")).await?
        else {
            return Err(format!(
                "transaction {tx_id} is not in the blockchain index yet"
            ));
        };
        let Some((input_index, predecessor)) = reserve_input(config, &tx, &successor).await? else {
            return Ok(Step::Unexplained(format!(
                "its lineage starts at box {successor_id} (created by {tx_id}) without reaching the tracker's reserve tree"
            )));
        };
        if box_digest(&predecessor).as_deref() == Some(tracker_digest) {
            return reproduce(
                config,
                storage,
                cmd_tx,
                issuer,
                denomination,
                &tx,
                input_index,
                &predecessor,
                &successor,
            )
            .await;
        }
        successor = predecessor;
    }
    Ok(Step::Unexplained(format!(
        "no reserve box among its last {MAX_TRACE_STEPS} holds the tracker's reserve tree"
    )))
}

/// Reproduce the redemption `tx` that spent `predecessor` (input `input_index`) into
/// `successor`, and journal it when the tracker's reserve tree with it is R5 of `successor`.
#[allow(clippy::too_many_arguments)]
async fn reproduce(
    config: &TrackerBoxUpdateConfig,
    storage: &TrackerStorage,
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    issuer: &PubKey,
    denomination: &DenomKey,
    tx: &Value,
    input_index: usize,
    predecessor: &Value,
    successor: &Value,
) -> Result<Step, String> {
    let tx_id = str_field(tx, "id")
        .ok_or("the indexed transaction has no id")?
        .to_ascii_lowercase();
    let unexplained = |why: String| Ok(Step::Unexplained(format!("transaction {tx_id} {why}")));
    let Some(extension) = input_extension(config, tx, &tx_id, input_index).await? else {
        return Err(format!(
            "the context extension of transaction {tx_id} cannot be read from the node"
        ));
    };
    let var = |id: &str| extension.get(id).and_then(Value::as_str);
    let Some(selector) = var("0").and_then(parse_byte_constant) else {
        return unexplained("has no action byte (context variable 0)".to_string());
    };
    let (action, output_index) = (selector / 10, selector % 10);
    if action != 0 {
        return unexplained(format!(
            "spent the reserve with action {action}, not a redemption, and changed its tree"
        ));
    }
    let successor_id = str_field(successor, "boxId").unwrap_or_default();
    let output_id = tx
        .get("outputs")
        .and_then(Value::as_array)
        .and_then(|outputs| {
            usize::try_from(output_index)
                .ok()
                .and_then(|i| outputs.get(i))
        })
        .and_then(|output| str_field(output, "boxId"));
    if !output_id.is_some_and(|id| id.eq_ignore_ascii_case(&successor_id)) {
        return unexplained(format!(
            "names output {output_index} as the reserve, not box {successor_id}"
        ));
    }
    let (Some(recipient), Some(timestamp)) = (
        var("1").and_then(parse_group_element_constant),
        var("4").and_then(parse_long_constant),
    ) else {
        return unexplained(
            "lacks the receiver (variable 1) or timestamp (variable 4)".to_string(),
        );
    };
    let Ok(timestamp) = u64::try_from(timestamp) else {
        return unexplained(format!("has a negative timestamp {timestamp}"));
    };
    let redeemed = match reserve_amount(predecessor, denomination)
        .zip(reserve_amount(successor, denomination))
    {
        Some((before, after)) if before > after => before - after,
        _ => return unexplained("takes nothing out of the reserve".to_string()),
    };
    let stored = tracker_redeemed(cmd_tx, issuer, &recipient, denomination).await?;
    let new_already_redeemed = stored
        .checked_add(redeemed)
        .ok_or("the cumulative redeemed amount overflows")?;
    let expected = tracker_digest_with(
        cmd_tx,
        issuer,
        &recipient,
        denomination,
        timestamp,
        new_already_redeemed,
    )
    .await?;
    let Some(chain) = box_digest(successor) else {
        return unexplained(format!(
            "leaves no reserve tree in R5 of box {successor_id}"
        ));
    };
    if expected != chain {
        return unexplained(format!(
            "cannot be reproduced: {} of {} -> {} at {} (cumulative {}) gives reserve tree {}, not {} in R5 of box {}",
            redeemed,
            hex::encode(issuer),
            hex::encode(recipient),
            timestamp,
            new_already_redeemed,
            expected,
            chain,
            successor_id
        ));
    }

    let entry = JournaledRedemption {
        tx_id: tx_id.clone(),
        reserve_box_id: str_field(predecessor, "boxId")
            .unwrap_or_default()
            .to_ascii_lowercase(),
        issuer_pubkey: hex::encode(issuer),
        recipient_pubkey: hex::encode(recipient),
        denomination: denomination.denomination_id(),
        redeemed_amount: redeemed,
        new_already_redeemed,
        data_input_ids: tx
            .get("dataInputs")
            .and_then(Value::as_array)
            .map(|inputs| {
                inputs
                    .iter()
                    .filter_map(|input| str_field(input, "boxId"))
                    .map(|id| id.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default(),
        submitted_at_ms: crate::redemption_build::now_unix_ms(),
        reserve_tree_timestamp: Some(timestamp),
        reserve_r5_digest: Some(chain),
        detected_on_chain: true,
        ..Default::default()
    };
    match storage.journaled_redemption(&tx_id) {
        Ok(None) => {}
        Ok(Some(_)) => return Ok(Step::Matches),
        Err(e) => return Err(format!("the redemption journal cannot be read: {e:?}")),
    }
    storage
        .journal_redemption(&entry)
        .and_then(|()| storage.persist_journal())
        .map_err(|e| format!("redemption {tx_id} cannot be journaled: {e:?}"))?;
    warn!(
        "Redemption {} of {} -> {} ({} in {}, cumulative {}) is on chain but was not submitted through this tracker; journaled, and applied once it is {} blocks deep",
        tx_id,
        entry.issuer_pubkey,
        entry.recipient_pubkey,
        redeemed,
        entry.denomination,
        new_already_redeemed,
        config.min_confirmation_depth
    );
    Ok(Step::Journaled(tx_id))
}

/// The input of `tx` that is `successor`'s reserve before it: same contract and owner (R4);
/// the contract allows one per owner. With the full box when the index gives only its id.
async fn reserve_input(
    config: &TrackerBoxUpdateConfig,
    tx: &Value,
    successor: &Value,
) -> Result<Option<(usize, Value)>, String> {
    let (Some(tree), Some(owner)) = (str_field(successor, "ergoTree"), register(successor, "R4"))
    else {
        return Ok(None);
    };
    let inputs = tx
        .get("inputs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (index, input) in inputs.into_iter().enumerate() {
        let input = if input.get("ergoTree").is_some() {
            input
        } else {
            let Some(id) = str_field(&input, "boxId") else {
                continue;
            };
            match node_get(config, &format!("/blockchain/box/byId/{id}")).await? {
                Some(full) => full,
                None => return Err(format!("input box {id} is not in the blockchain index yet")),
            }
        };
        if str_field(&input, "ergoTree").is_some_and(|t| t.eq_ignore_ascii_case(&tree))
            && register(&input, "R4").is_some_and(|r4| r4.eq_ignore_ascii_case(&owner))
        {
            return Ok(Some((index, input)));
        }
    }
    Ok(None)
}

/// The context extension of input `input_index` of `tx`: from the indexed input's
/// `spendingProof`, or else from the block's transactions.
async fn input_extension(
    config: &TrackerBoxUpdateConfig,
    tx: &Value,
    tx_id: &str,
    input_index: usize,
) -> Result<Option<serde_json::Map<String, Value>>, String> {
    let extension_of = |tx: &Value| {
        tx.get("inputs")
            .and_then(Value::as_array)
            .and_then(|inputs| inputs.get(input_index))
            .and_then(|input| input.get("spendingProof"))
            .and_then(|proof| proof.get("extension"))
            .and_then(Value::as_object)
            .cloned()
    };
    if let Some(extension) = extension_of(tx) {
        return Ok(Some(extension));
    }
    let Some(block_id) = str_field(tx, "blockId") else {
        return Ok(None);
    };
    let Some(block) = node_get(config, &format!("/blocks/{block_id}/transactions")).await? else {
        return Ok(None);
    };
    Ok(block
        .get("transactions")
        .and_then(Value::as_array)
        .and_then(|txs| {
            txs.iter()
                .find(|t| str_field(t, "id").is_some_and(|id| id.eq_ignore_ascii_case(tx_id)))
        })
        .and_then(extension_of))
}

/// The amount a reserve box holds in `denomination`: its value, or its reserve token amount.
fn reserve_amount(reserve_box: &Value, denomination: &DenomKey) -> Option<u64> {
    match denomination {
        DenomKey::Erg => reserve_box.get("value").and_then(Value::as_u64),
        DenomKey::Token(id) => {
            let id = hex::encode(id);
            reserve_box
                .get("assets")
                .and_then(Value::as_array)?
                .iter()
                .find(|asset| {
                    str_field(asset, "tokenId").is_some_and(|t| t.eq_ignore_ascii_case(&id))
                })
                .and_then(|asset| asset.get("amount"))
                .and_then(Value::as_u64)
        }
    }
}

fn str_field(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_string)
}

fn register(reserve_box: &Value, name: &str) -> Option<String> {
    reserve_box
        .get("additionalRegisters")
        .and_then(|r| r.get(name))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The reserve tree digest (hex, lower case) in R5 of a box.
fn box_digest(reserve_box: &Value) -> Option<String> {
    register(reserve_box, "R5").and_then(|r5| crate::redemption_confirmer::r5_digest_hex(&r5))
}

/// A serialized `Byte` constant (`02 b`).
fn parse_byte_constant(hex_value: &str) -> Option<i8> {
    match hex::decode(hex_value).ok()?.as_slice() {
        [0x02, b] => Some(*b as i8),
        _ => None,
    }
}

/// A serialized `GroupElement` constant (`07` and 33 bytes).
fn parse_group_element_constant(hex_value: &str) -> Option<PubKey> {
    let bytes = hex::decode(hex_value).ok()?;
    match bytes.split_first() {
        Some((0x07, key)) => PubKey::try_from(key).ok(),
        _ => None,
    }
}

/// A serialized `Long` constant (`05` and the zigzag VLQ of the value).
fn parse_long_constant(hex_value: &str) -> Option<i64> {
    let bytes = hex::decode(hex_value).ok()?;
    let (&tag, rest) = bytes.split_first()?;
    if tag != 0x05 || rest.is_empty() || rest.len() > 10 {
        return None;
    }
    let mut raw: u64 = 0;
    for (i, byte) in rest.iter().enumerate() {
        raw |= u64::from(byte & 0x7f) << (7 * i);
        let last = byte & 0x80 == 0;
        if last != (i == rest.len() - 1) {
            return None;
        }
    }
    Some(((raw >> 1) as i64) ^ -((raw & 1) as i64))
}

/// `GET {scanner node}{path}`: the JSON on 200, `None` on 404, an error otherwise.
async fn node_get(config: &TrackerBoxUpdateConfig, path: &str) -> Result<Option<Value>, String> {
    let mut request = basis_store::http::bounded_client().get(format!(
        "{}{path}",
        config.scanner_node_url.trim_end_matches('/')
    ));
    if let Some(key) = config.scanner_api_key.as_deref().filter(|k| !k.is_empty()) {
        request = request.header("api_key", key);
    }
    let response = request.send().await.map_err(|e| format!("{path}: {e}"))?;
    match response.status().as_u16() {
        200 => basis_store::http::read_json_capped(response)
            .await
            .map(Some)
            .map_err(|e| format!("{path}: {e}")),
        404 => Ok(None),
        status => Err(format!("{path}: HTTP {status}")),
    }
}

async fn tracker_reserve_digest(
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    issuer: &PubKey,
    denomination: &DenomKey,
) -> Option<String> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCommand::GetReserveStateDigest {
            issuer_pubkey: *issuer,
            denomination: *denomination,
            response_tx,
        })
        .await
        .ok()?;
    response_rx.await.ok().map(hex::encode)
}

/// The cumulative redeemed amount of the edge in the tracker's reserve tree (0 when absent).
async fn tracker_redeemed(
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    issuer: &PubKey,
    recipient: &PubKey,
    denomination: &DenomKey,
) -> Result<u64, String> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCommand::GetReserveLookupProof {
            issuer_pubkey: *issuer,
            recipient_pubkey: *recipient,
            denomination: *denomination,
            response_tx,
        })
        .await
        .map_err(|_| "the tracker thread is unavailable".to_string())?;
    let lookup = response_rx
        .await
        .map_err(|_| "the tracker thread did not answer".to_string())?
        .map_err(|e| format!("the reserve tree cannot be read: {e:?}"))?;
    lookup
        .value
        .get(8..16)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| "the reserve tree value is not 16 bytes".to_string())
}

/// The tracker's reserve tree digest (hex) with the edge set to `timestamp ‖ already`.
async fn tracker_digest_with(
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    issuer: &PubKey,
    recipient: &PubKey,
    denomination: &DenomKey,
    timestamp: u64,
    new_already_redeemed: u64,
) -> Result<String, String> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCommand::GetReserveInsertProof {
            issuer_pubkey: *issuer,
            recipient_pubkey: *recipient,
            denomination: *denomination,
            timestamp,
            new_already_redeemed,
            response_tx,
        })
        .await
        .map_err(|_| "the tracker thread is unavailable".to_string())?;
    response_rx
        .await
        .map_err(|_| "the tracker thread did not answer".to_string())?
        .map(|(_, digest)| hex::encode(digest))
        .map_err(|e| format!("the reserve tree cannot be updated: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_constants_parse_as_the_build_writes_them() {
        use basis_offchain::ergo_tx::{serialize_ergo_byte, serialize_ergo_long};
        assert_eq!(parse_byte_constant(&serialize_ergo_byte(0)), Some(0));
        assert_eq!(parse_byte_constant(&serialize_ergo_byte(10)), Some(10));
        assert_eq!(parse_byte_constant("0500"), None);
        for value in [0i64, 1, -1, 63, 64, 1_700_000_000_000, i64::MAX, i64::MIN] {
            assert_eq!(
                parse_long_constant(&serialize_ergo_long(value)),
                Some(value),
                "{value}"
            );
        }
        assert_eq!(parse_long_constant("05"), None);
        assert_eq!(parse_long_constant("0580"), None, "unterminated");
        assert_eq!(parse_long_constant("050100"), None, "trailing byte");
        let key = [0x02; 33];
        assert_eq!(
            parse_group_element_constant(&format!("07{}", hex::encode(key))),
            Some(key)
        );
        assert_eq!(parse_group_element_constant(&hex::encode(key)), None);
    }
}
