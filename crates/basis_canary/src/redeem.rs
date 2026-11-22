//! `redeem`: the recipient redeems part of the issuer's debt from the issuer's reserve, with the
//! tracker's help.
//!
//! 1. The note must be committed on chain at its current total (the tracker proves redemptions
//!    against its committed tree), and its stored signature must cover that total: it is the
//!    issuer signature the contract checks (context var #2).
//! 2. `POST /tracker/signature` must return the tracker's signature over the same message.
//! 3. `POST /redemption/build`: the tracker builds the transaction, pays the fee from its own
//!    boxes and signs those inputs. The recipient's key needs no ERG.
//! 4. Every input and data input is read again from the node, and the transaction is checked
//!    before the recipient's key proves the reserve input (input 0).
//! 5. The signed transaction is validated in full against the node's last 10 headers, then
//!    submitted through `POST /redemption/submit`, or through the node if the tracker refuses.

use basis_server::local_wallet::{self, NodeEndpoint};
use basis_store::DenomKey;
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::Transaction;
use ergo_lib::ergo_chain_types::Header;
use ergo_lib::ergotree_ir::chain::ergo_box::{ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId};
use ergo_lib::ergotree_ir::ergo_tree::ErgoTree;
use ergo_lib::ergotree_ir::mir::constant::{Constant, TryExtractInto};
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::keys::FileKey;
use crate::note::{fetch_note, note_message};
use crate::tx;
use crate::{Context, Report};

/// `data` of `POST /tracker/signature`.
#[derive(Debug, Clone, Deserialize)]
pub struct TrackerSignature {
    pub success: bool,
    pub tracker_signature: String,
    pub tracker_pubkey: String,
    pub message_signed: String,
}

/// `data` of `POST /redemption/build`.
#[derive(Debug, Clone, Deserialize)]
pub struct BuildResponse {
    /// Exactly as built: `/redemption/submit` finds the build by the SHA-256 of this value.
    pub unsigned_tx: Value,
    pub partial_tx: Value,
    pub input_box_binaries: Vec<String>,
    pub data_box_binaries: Vec<String>,
    /// Last 10 headers, newest first: the context the fee inputs were proved in.
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
    #[serde(default)]
    pub new_already_redeemed: u64,
}

/// What the redemption must be.
#[derive(Debug, Clone)]
pub struct Expectation {
    pub issuer: [u8; 33],
    pub recipient: [u8; 33],
    pub amount: u64,
    /// Committed total debt of the note.
    pub total_debt: u64,
    pub timestamp: u64,
    pub issuer_signature: [u8; 65],
    pub tracker_nft: [u8; 32],
    pub tracker_pubkey: [u8; 33],
}

fn signature_bytes(what: &str, hex_value: &str) -> Result<[u8; 65], String> {
    hex::decode(hex_value.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{what} is not 65 bytes of hex"))
}

fn long_or_zero(c: Option<Constant>) -> Result<i64, String> {
    match c {
        None => Ok(0),
        Some(c) => c
            .try_extract_into::<i64>()
            .map_err(|_| "register is not a Long".to_string()),
    }
}

/// Read every input and data input of `unsigned` from the node (`GET /utxo/byIdBinary`), and
/// check that the boxes the tracker sent are the same boxes.
pub async fn node_boxes(
    node: &NodeEndpoint,
    unsigned: &UnsignedTransaction,
    build: &BuildResponse,
) -> Result<(Vec<ErgoBox>, Vec<ErgoBox>), String> {
    async fn read(
        node: &NodeEndpoint,
        ids: Vec<String>,
        sent: &[String],
        what: &str,
    ) -> Result<Vec<ErgoBox>, String> {
        if ids.len() != sent.len() {
            return Err(format!(
                "the build sent {} {what} boxes for {} {what}s",
                sent.len(),
                ids.len()
            ));
        }
        let mut boxes = Vec::with_capacity(ids.len());
        for (i, (id, binary)) in ids.iter().zip(sent).enumerate() {
            let from_tracker = hex::decode(binary)
                .ok()
                .and_then(|b| ErgoBox::sigma_parse_bytes(&b).ok())
                .ok_or_else(|| format!("the build's {what} box {i} does not parse"))?;
            if String::from(from_tracker.box_id()) != *id {
                return Err(format!(
                    "the build's {what} box {i} is {}, the transaction names {id}",
                    String::from(from_tracker.box_id())
                ));
            }
            boxes.push(local_wallet::fetch_box(node, id).await?);
        }
        Ok(boxes)
    }
    let input_ids = unsigned
        .inputs
        .iter()
        .map(|i| String::from(i.box_id))
        .collect();
    let data_ids = unsigned
        .data_inputs
        .iter()
        .flat_map(|d| d.iter())
        .map(|d| String::from(d.box_id))
        .collect();
    let inputs = read(node, input_ids, &build.input_box_binaries, "input").await?;
    let data_inputs = read(node, data_ids, &build.data_box_binaries, "data input").await?;
    Ok((inputs, data_inputs))
}

/// Checks run before the recipient's key proves the reserve input. Returns the index of the
/// payout output.
///
/// - The boxes are the ones the transaction names; data input 0 is the tracker box (token 0 is
///   the tracker NFT, R4 the tracker key that signed the redemption).
/// - Input 0 is the issuer's reserve under the contract compiled into this build (R4 = issuer,
///   R6 = tracker NFT, one token: its NFT). Every other input is a token-free `P2PK(tracker)`
///   box, so the recipient's proof spends nothing but the reserve.
/// - The reserve input's context extension is in Scala's serialization order (the node computes
///   the id from it) and holds: #0 = redeem into output 0, #1 = recipient, #2 = the issuer's note
///   signature, #3 = committed total, #4 = note timestamp, #5 and #8 proofs, #6 the tracker's
///   signature (verified), #7 exactly when the reserve tree already has this note.
/// - Output 0 keeps the reserve (script, tokens, R4, R6, R7) minus exactly `amount`; one output
///   pays exactly `amount` to `P2PK(recipient)` with no token; the others are the miner fee and
///   token-free change to the tracker.
/// - ERG in equals ERG out, no token is minted or burned, and the reserve NFT stays first in
///   output 0.
/// - The fee-signed transaction is this one, with proofs for every input but the reserve's.
pub fn check_redemption(
    unsigned: &UnsignedTransaction,
    partial: &Transaction,
    inputs: &[ErgoBox],
    data_inputs: &[ErgoBox],
    build: &BuildResponse,
    expect: &Expectation,
) -> Result<usize, String> {
    tx::check_box_ids(unsigned, inputs, data_inputs)?;
    let reserve_tree = tx::reserve_tree()?;
    let recipient_tree = tx::p2pk_tree(&expect.recipient)?;
    let tracker_tree = tx::p2pk_tree(&expect.tracker_pubkey)?;
    let nft = tx::coll_bytes(&expect.tracker_nft);
    if expect.tracker_pubkey == expect.recipient {
        return Err("the tracker key is the recipient key".to_string());
    }

    // The tracker box.
    let [tracker_box] = data_inputs else {
        return Err(format!(
            "{} data inputs; a redemption reads only the tracker box",
            data_inputs.len()
        ));
    };
    if String::from(tracker_box.box_id()) != build.tracker_box_id {
        return Err("data input 0 is not the build's tracker box".to_string());
    }
    match tx::box_tokens(tracker_box).first() {
        Some((id, 1)) if *id == hex::encode(expect.tracker_nft) => {}
        _ => return Err("data input 0 does not hold the tracker NFT as token 0".to_string()),
    }
    if tx::register(tracker_box, NonMandatoryRegisterId::R4)
        != Some(Constant::from(tx::point(&expect.tracker_pubkey)?))
    {
        return Err(format!(
            "the tracker box R4 is not the key {} that signed the redemption",
            hex::encode(expect.tracker_pubkey)
        ));
    }

    // Inputs.
    let reserve = inputs.first().ok_or("the transaction has no inputs")?;
    if String::from(reserve.box_id()) != build.reserve_box_id {
        return Err("input 0 is not the build's reserve box".to_string());
    }
    if reserve.ergo_tree != reserve_tree {
        return Err(
            "input 0 is not under the ERG reserve contract compiled into this build".to_string(),
        );
    }
    if tx::register(reserve, NonMandatoryRegisterId::R4)
        != Some(Constant::from(tx::point(&expect.issuer)?))
    {
        return Err("the reserve is not owned by the issuer (R4)".to_string());
    }
    if tx::register(reserve, NonMandatoryRegisterId::R6) != Some(nft.clone()) {
        return Err("the reserve is not bound to our tracker NFT (R6)".to_string());
    }
    let reserve_tokens = tx::box_tokens(reserve);
    let reserve_nft = match reserve_tokens.as_slice() {
        [(id, 1)] => id.clone(),
        other => {
            return Err(format!(
                "the reserve holds {other:?}, expected its NFT alone"
            ))
        }
    };
    for (i, b) in inputs.iter().enumerate().skip(1) {
        if b.ergo_tree != tracker_tree || !tx::box_tokens(b).is_empty() {
            return Err(format!(
                "input {i} is not a token-free P2PK(tracker) box; the recipient's proof could \
                 spend it"
            ));
        }
    }

    // Context extensions.
    let unsigned_inputs = unsigned.inputs.as_vec();
    for (i, input) in unsigned_inputs.iter().enumerate().skip(1) {
        if !input.extension.values.is_empty() {
            return Err(format!("fee input {i} has a context extension"));
        }
    }
    let extension = &unsigned_inputs[0].extension.values;
    let keys: Vec<u8> = extension.keys().copied().collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    let scala = basis_offchain::ergo_tx::scala_context_extension_order(&sorted);
    if keys != scala {
        return Err(format!(
            "the reserve input's context extension is in order {keys:?}, not Scala's {scala:?}; \
             the node would compute another transaction id"
        ));
    }
    let json_keys: Vec<String> = build.unsigned_tx["inputs"][0]["extension"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    if json_keys != keys.iter().map(u8::to_string).collect::<Vec<_>>() {
        return Err(format!(
            "the unsigned transaction JSON lists the reserve extension as {json_keys:?}, parsed \
             as {keys:?}"
        ));
    }
    let mut expected_keys = vec![0u8, 1, 2, 3, 4, 5, 6, 8];
    if !build.is_first_redemption {
        expected_keys.push(7);
    }
    expected_keys.sort_unstable();
    if sorted != expected_keys {
        return Err(format!(
            "the reserve input's context variables are {sorted:?}, expected {expected_keys:?} \
             (#7 only once the reserve tree holds this note)"
        ));
    }
    let var = |k: u8| {
        extension
            .get(&k)
            .cloned()
            .ok_or(format!("context var #{k} missing"))
    };
    let var_bytes = |k: u8| -> Result<Vec<u8>, String> {
        var(k)?
            .try_extract_into::<Vec<u8>>()
            .map_err(|_| format!("context var #{k} is not a Coll[Byte]"))
    };
    if var(0)? != Constant::from(0i8) {
        return Err("context var #0 is not 0 (redeem into output 0)".to_string());
    }
    if var(1)? != Constant::from(tx::point(&expect.recipient)?) {
        return Err("context var #1 is not the recipient key".to_string());
    }
    if var_bytes(2)? != expect.issuer_signature {
        return Err("context var #2 is not the note's issuer signature".to_string());
    }
    let total = i64::try_from(expect.total_debt).map_err(|_| "total debt out of range")?;
    if build.total_debt != expect.total_debt || var(3)? != Constant::from(total) {
        return Err(format!(
            "the build redeems against total debt {}, the note's committed total is {}",
            build.total_debt, expect.total_debt
        ));
    }
    let timestamp = i64::try_from(expect.timestamp).map_err(|_| "timestamp out of range")?;
    if var(4)? != Constant::from(timestamp) {
        return Err("context var #4 is not the note timestamp".to_string());
    }
    var_bytes(5)?;
    var_bytes(8)?;
    if !build.is_first_redemption {
        var_bytes(7)?;
    }
    let message = note_message(
        &expect.issuer,
        &expect.recipient,
        expect.total_debt,
        expect.timestamp,
        &expect.tracker_nft,
    )?;
    let tracker_signature: [u8; 65] = var_bytes(6)?
        .try_into()
        .map_err(|_| "context var #6 is not a 65-byte signature")?;
    basis_store::schnorr::schnorr_verify(&tracker_signature, &message, &expect.tracker_pubkey)
        .map_err(|_| "context var #6 is not the tracker's signature over the note message")?;

    // Outputs.
    let outputs = unsigned.output_candidates.as_vec();
    let reserve_out = outputs.first().ok_or("the transaction has no outputs")?;
    let reserve_left = reserve
        .value
        .as_u64()
        .checked_sub(expect.amount)
        .filter(|v| *v > 0)
        .ok_or("the reserve holds less than the amount")?;
    let out_reg = |o: &ErgoBoxCandidate, id| tx::candidate_register(o, id);
    if reserve_out.ergo_tree != reserve_tree
        || *reserve_out.value.as_u64() != reserve_left
        || tx::candidate_tokens(reserve_out) != reserve_tokens
        || out_reg(reserve_out, NonMandatoryRegisterId::R4)
            != tx::register(reserve, NonMandatoryRegisterId::R4)
        || out_reg(reserve_out, NonMandatoryRegisterId::R6) != Some(nft.clone())
        || out_reg(reserve_out, NonMandatoryRegisterId::R5).is_none()
    {
        return Err(format!(
            "output 0 does not keep the reserve minus {} nanoERG (script, tokens, R4, R5, R6)",
            expect.amount
        ));
    }
    if long_or_zero(out_reg(reserve_out, NonMandatoryRegisterId::R7))?
        != long_or_zero(tx::register(reserve, NonMandatoryRegisterId::R7))?
    {
        return Err("output 0 changes the reserve's refund height (R7)".to_string());
    }
    let fee_tree = tx::fee_tree()?;
    let mut payout = None;
    for (i, o) in outputs.iter().enumerate().skip(1) {
        if o.ergo_tree == recipient_tree {
            if payout.is_some() || *o.value.as_u64() != expect.amount || o.tokens.is_some() {
                return Err(format!(
                    "output {i} to the recipient is not the single token-free payout of {} \
                     nanoERG",
                    expect.amount
                ));
            }
            payout = Some(i);
        } else if o.ergo_tree == fee_tree || o.ergo_tree == tracker_tree {
            if o.tokens.is_some() {
                return Err(format!("output {i} carries tokens"));
            }
        } else {
            return Err(format!("output {i} goes to an unexpected script"));
        }
    }
    let payout = payout.ok_or("no output pays the recipient")?;
    if !outputs.iter().any(|o| o.ergo_tree == fee_tree) {
        return Err("no miner fee output".to_string());
    }

    tx::check_erg_preserved(inputs, outputs)?;
    local_wallet::check_tokens_preserved(inputs, outputs, None)?;
    local_wallet::check_nft_only_in_output0(outputs, &reserve_nft)?;

    // The fee-signed transaction.
    if partial.id() != unsigned.id() {
        return Err(
            "the build's fee-signed transaction is not its unsigned transaction".to_string(),
        );
    }
    let partial_inputs = partial.inputs.as_vec();
    if partial_inputs.len() != unsigned_inputs.len() {
        return Err("the fee-signed transaction has another number of inputs".to_string());
    }
    for (i, input) in partial_inputs.iter().enumerate() {
        let empty = Vec::<u8>::from(input.spending_proof.proof.clone()).is_empty();
        if i == 0 && !empty {
            return Err("the build already holds a proof for the reserve input".to_string());
        }
        if i > 0 && empty {
            return Err(format!("fee input {i} has no proof in the build"));
        }
    }
    Ok(payout)
}

/// Submit through `POST /redemption/submit`; through the node's `POST /transactions` if the
/// tracker refuses or cannot be reached. Returns the id and which path was used.
async fn submit(
    context: &Context,
    signed: &Transaction,
    build: &BuildResponse,
    expect: &Expectation,
    report: &mut Report,
) -> Result<String, String> {
    let local_id = String::from(signed.id());
    let body = json!({
        "signed_tx": serde_json::to_value(signed).map_err(|e| format!("encode transaction: {e}"))?,
        "unsigned_tx": build.unsigned_tx,
        "issuer_pubkey": hex::encode(expect.issuer),
        "recipient_pubkey": hex::encode(expect.recipient),
        "redeemed_amount": expect.amount,
        "new_already_redeemed": build.new_already_redeemed,
    });
    report.line(format!(
        "POST {}/redemption/submit (signed transaction {local_id})",
        context.tracker.url()
    ));
    let tracker_result = match context.tracker.post("/redemption/submit", &body).await {
        Ok(response) => {
            report.line(format!("HTTP {}", response.status));
            report.line(response.pretty());
            response.data("POST /redemption/submit", 200)
        }
        Err(e) => Err(e),
    };
    let error = match tracker_result {
        Ok(data) => {
            let tracker_id = data.get("tx_id").and_then(Value::as_str).unwrap_or("");
            if !tracker_id.eq_ignore_ascii_case(&local_id) {
                report.line(format!(
                    "warning: the tracker reports transaction id {tracker_id:?}; the signed \
                     transaction is {local_id}"
                ));
            }
            report.line(format!(
                "submitted through the tracker (POST /redemption/submit): transaction {local_id}"
            ));
            return Ok(local_id);
        }
        Err(e) => e,
    };
    report.line(format!("the tracker did not submit it: {error}"));
    report.line(format!(
        "submitting through the node instead: POST {}/transactions",
        context.node.url()
    ));
    match local_wallet::broadcast(&context.node, signed).await {
        Ok(id) => {
            report.line(format!(
                "submitted through the node (POST /transactions): transaction {id}"
            ));
            report.line(
                "warning: the tracker has not recorded this redemption (its submit failed), so \
                 its reserve tree does not include it, and it refuses to build the next \
                 redemption from this reserve until it does",
            );
            let repair = json!({
                "redemption_id": id,
                "issuer_pubkey": hex::encode(expect.issuer),
                "recipient_pubkey": hex::encode(expect.recipient),
                "denomination": "erg",
                "redeemed_amount": expect.amount,
                "new_already_redeemed": build.new_already_redeemed,
            });
            report.line(format!(
                "to record it once the transaction is in a block, an operator sends POST \
                 {}/redeem/complete with the Admin key (this tool has none and sends nothing) \
                 and the body:",
                context.tracker.url()
            ));
            report.line(repair.to_string());
            Ok(id)
        }
        Err(node_error) => Err(format!(
            "the redemption was not submitted: tracker: {error}; node: {node_error}"
        )),
    }
}

/// `redeem`.
pub async fn redeem(
    context: &Context,
    recipient: &FileKey,
    issuer: &[u8; 33],
    amount: u64,
    dry_run: bool,
    report: &mut Report,
) -> Result<(), String> {
    let recipient_pk = recipient.public_key();
    if *issuer == recipient_pk {
        return Err("the issuer is the recipient's own key".to_string());
    }
    if amount == 0 {
        return Err("--amount must be above 0".to_string());
    }
    let recipient_address = recipient.address()?;
    report.line(format!(
        "redeem: recipient {} ({recipient_address}) redeems {amount} nanoERG of the debt of \
         issuer {}, tracker NFT {}",
        hex::encode(recipient_pk),
        hex::encode(issuer),
        hex::encode(context.tracker_nft)
    ));

    // 1. The note, committed at its current total.
    let note = fetch_note(context, issuer, &recipient_pk)
        .await?
        .ok_or("the tracker has no ERG note from the issuer to this key")?;
    report.line(format!("note: {}", note.summary()));
    if note.denomination != DenomKey::Erg.denomination_id()
        || !note
            .tracker_nft_id
            .eq_ignore_ascii_case(&hex::encode(context.tracker_nft))
    {
        return Err(format!(
            "the note is in {} and bound to tracker NFT {}; expected an ERG note of {}",
            note.denomination,
            note.tracker_nft_id,
            hex::encode(context.tracker_nft)
        ));
    }
    let committed = note
        .confirmation
        .as_ref()
        .and_then(|c| c.confirmed_total_debt);
    if committed != Some(note.amount_collected) {
        return Err(format!(
            "the note's total {} is not committed on chain yet (committed: {}); wait for the \
             tracker's next box update to confirm (`status` shows it)",
            note.amount_collected,
            committed.map_or("none".to_string(), |c| c.to_string())
        ));
    }
    let redeemable = note
        .confirmation
        .as_ref()
        .map_or(0, |c| c.redeemable_amount);
    if amount > redeemable {
        return Err(format!(
            "--amount {amount} is above what is redeemable now: {redeemable} nanoERG (committed \
             total {} minus {} already redeemed)",
            note.amount_collected, note.amount_redeemed
        ));
    }

    // 2. The issuer signature is the stored note's.
    let message = note_message(
        issuer,
        &recipient_pk,
        note.amount_collected,
        note.timestamp,
        &context.tracker_nft,
    )?;
    let issuer_signature = signature_bytes("the stored note signature", &note.signature)?;
    basis_store::schnorr::schnorr_verify(&issuer_signature, &message, issuer).map_err(|_| {
        format!(
            "the stored note signature does not cover total {} at timestamp {}",
            note.amount_collected, note.timestamp
        )
    })?;
    report.line(format!(
        "issuer signature (stored note) verified over message {}",
        hex::encode(message)
    ));

    // 3. The tracker's signature over the same message.
    let signature_request = json!({
        "issuer_pubkey": hex::encode(issuer),
        "recipient_pubkey": hex::encode(recipient_pk),
        "total_debt": note.amount_collected,
        "timestamp": note.timestamp,
        "emergency": false,
        "denomination": "erg",
    });
    report.line(format!(
        "POST {}/tracker/signature {signature_request}",
        context.tracker.url()
    ));
    let response = context
        .tracker
        .post("/tracker/signature", &signature_request)
        .await?;
    report.line(format!("HTTP {}", response.status));
    report.line(response.pretty());
    let signed_by_tracker: TrackerSignature =
        serde_json::from_value(response.data("POST /tracker/signature", 200)?)
            .map_err(|e| format!("POST /tracker/signature: unexpected answer: {e}"))?;
    if !signed_by_tracker.success
        || !signed_by_tracker
            .message_signed
            .eq_ignore_ascii_case(&hex::encode(message))
    {
        return Err(format!(
            "the tracker signed {} instead of the note message {}",
            signed_by_tracker.message_signed,
            hex::encode(message)
        ));
    }
    let tracker_pubkey = tx::parse_pubkey("tracker_pubkey", &signed_by_tracker.tracker_pubkey)?;
    let tracker_signature =
        signature_bytes("tracker_signature", &signed_by_tracker.tracker_signature)?;
    basis_store::schnorr::schnorr_verify(&tracker_signature, &message, &tracker_pubkey)
        .map_err(|_| "the tracker's signature does not verify with its key".to_string())?;
    report.line(format!(
        "tracker signature verified with the tracker key {}",
        hex::encode(tracker_pubkey)
    ));

    // 4. The build.
    let build_request = json!({
        "issuer_pubkey": hex::encode(issuer),
        "recipient_pubkey": hex::encode(recipient_pk),
        "amount": amount,
        "timestamp": note.timestamp,
        "issuer_signature": hex::encode(issuer_signature),
        "emergency": false,
        "denomination": "erg",
    });
    report.line(format!(
        "POST {}/redemption/build {build_request} (counts against the tracker's hourly build \
         caps)",
        context.tracker.url()
    ));
    let response = context
        .tracker
        .post("/redemption/build", &build_request)
        .await?;
    report.line(format!("HTTP {}", response.status));
    let data = match response.data("POST /redemption/build", 200) {
        Ok(data) => data,
        Err(e) => {
            report.line(response.pretty());
            return Err(e);
        }
    };
    let build: BuildResponse = serde_json::from_value(data)
        .map_err(|e| format!("POST /redemption/build: unexpected answer: {e}"))?;
    report.line(format!(
        "build: reserve {} -> {} nanoERG; payout {} nanoERG; committed total debt {}; reserve \
         tree value after: {} redeemed; first redemption: {}; fee {} nanoERG and change {} \
         nanoERG to {} paid by the tracker",
        build.reserve_box_id,
        build.reserve_output_value,
        build.recipient_output_value,
        build.total_debt,
        build.new_already_redeemed,
        build.is_first_redemption,
        build.fee,
        build.change_amount,
        build.change_address
    ));

    let unsigned: UnsignedTransaction = serde_json::from_value(build.unsigned_tx.clone())
        .map_err(|e| format!("the build's unsigned transaction does not parse: {e}"))?;
    let partial: Transaction = serde_json::from_value(build.partial_tx.clone())
        .map_err(|e| format!("the build's fee-signed transaction does not parse: {e}"))?;
    let build_state = local_wallet::state_context_from_headers(build.headers.clone())
        .map_err(|e| format!("the build's headers: {e}"))?;

    // 5. The boxes from the node, and the checks.
    let (inputs, data_inputs) = node_boxes(&context.node, &unsigned, &build).await?;
    let expect = Expectation {
        issuer: *issuer,
        recipient: recipient_pk,
        amount,
        total_debt: note.amount_collected,
        timestamp: note.timestamp,
        issuer_signature,
        tracker_nft: context.tracker_nft,
        tracker_pubkey,
    };
    let payout_index =
        check_redemption(&unsigned, &partial, &inputs, &data_inputs, &build, &expect)?;
    report.line(
        "checks before signing: OK (boxes re-read from the node; reserve input under the \
         compiled contract, owned by the issuer, bound to our tracker NFT; every other input \
         P2PK(tracker); context extension in Scala order with the note's values and verified \
         signatures; reserve output keeps everything but the amount; one exact payout to \
         P2PK(recipient); ERG in = ERG out; no token minted or burned)",
    );

    let reserve_tree = tx::reserve_tree()?;
    let recipient_tree = tx::p2pk_tree(&recipient_pk)?;
    let tracker_tree = tx::p2pk_tree(&tracker_pubkey)?;
    let fee_tree = tx::fee_tree()?;
    let tracker_address = local_wallet::p2pk_address(&tracker_pubkey)?;
    let label = |tree: &ErgoTree| -> String {
        if *tree == reserve_tree {
            "the Basis ERG reserve contract".to_string()
        } else if *tree == recipient_tree {
            format!("P2PK(recipient) {recipient_address}")
        } else if *tree == tracker_tree {
            format!("P2PK(tracker) {tracker_address}")
        } else if *tree == fee_tree {
            "the miner fee".to_string()
        } else {
            "another script".to_string()
        }
    };
    report.line(tx::describe(&unsigned, &inputs, &data_inputs, &label)?.trim_end());
    if dry_run {
        report.line("unsigned transaction (exactly as the tracker built it):");
        report.line(
            serde_json::to_string_pretty(&build.unsigned_tx)
                .map_err(|e| format!("encode transaction: {e}"))?,
        );
    }

    // 6. Prove the reserve input, validate in full against the node's headers.
    let signed = recipient.prove_input(
        &unsigned,
        Some(&partial),
        &inputs,
        &data_inputs,
        &build_state,
        0,
    )?;
    if signed.id() != unsigned.id() {
        return Err("the signed transaction has another id than the build".to_string());
    }
    let state = local_wallet::fetch_state_context(&context.node).await?;
    tx::validate(&signed, &inputs, &data_inputs, &state)?;
    let tx_id = String::from(signed.id());
    report.line(format!(
        "proved the reserve input with the recipient key and validated the transaction in full \
         against the node's last 10 headers (tip {}): transaction {tx_id}",
        state.pre_header.height
    ));
    let payout = signed
        .outputs
        .as_vec()
        .get(payout_index)
        .ok_or("payout output missing")?;
    let payout_line = format!(
        "output {payout_index}, box {}, {} nanoERG to P2PK(recipient) {recipient_address}",
        String::from(payout.box_id()),
        payout.value.as_u64()
    );
    if dry_run {
        report.line(format!("payout once submitted: {payout_line}"));
        report.line("dry run: nothing submitted");
        return Ok(());
    }

    // 7. Submit.
    submit(context, &signed, &build, &expect, report).await?;
    report.line(format!("payout: {payout_line}"));
    Ok(())
}
