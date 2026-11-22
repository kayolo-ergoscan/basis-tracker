//! `reserve-create`: the owner locks ERG in a reserve bound to the tracker NFT.
//!
//! The reserve box is the one the tracker's `POST /reserves/create` describes (script, value,
//! assets, registers), checked against what was asked for and against the contract compiled into
//! this build. It is paid from token-free boxes at the owner's P2PK address; the reserve NFT is
//! minted from the first input, so its id is that input's box id. Every input is `P2PK(owner)`,
//! which the tracker's scanner requires before it admits a new reserve (issue #19).

use std::collections::BTreeMap;

use basis_server::local_wallet::{self, NodeEndpoint};
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::UnsignedInput;
use ergo_lib::ergotree_ir::chain::context_extension::ContextExtension;
use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
use ergo_lib::ergotree_ir::chain::ergo_box::{
    BoxTokens, ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId, NonMandatoryRegisters,
};
use ergo_lib::ergotree_ir::chain::token::{Token, TokenAmount};
use ergo_lib::ergotree_ir::ergo_tree::ErgoTree;
use ergo_lib::ergotree_ir::mir::constant::Constant;
use serde::Deserialize;
use serde_json::json;

use crate::keys::FileKey;
use crate::tx::{self, FEE};
use crate::{Context, Report};

/// `data` of the tracker's `POST /reserves/create` answer.
#[derive(Debug, Clone, Deserialize)]
pub struct ReservePayload {
    pub requests: Vec<PaymentRequest>,
    pub fee: u64,
    pub change_address: String,
}

/// One box the payload asks for.
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRequest {
    pub address: String,
    pub value: u64,
    pub assets: Vec<PayloadAsset>,
    pub registers: BTreeMap<String, String>,
}

/// A token in a [`PaymentRequest`].
#[derive(Debug, Clone, Deserialize)]
pub struct PayloadAsset {
    pub token_id: String,
    pub amount: u64,
}

/// The reserve output built from a checked payload, and what about the payload is worth saying.
#[derive(Debug)]
pub struct ReserveOutput {
    pub candidate: ErgoBoxCandidate,
    pub warnings: Vec<String>,
}

/// Check the payload against the request (`owner`, `erg_nano`, reserve NFT `reserve_nft`) and
/// `tracker_nft`, and build the reserve output it describes, created at `height`.
///
/// The payload must be exactly one box: the ERG reserve contract compiled into this build,
/// `erg_nano` nanoERG, the reserve NFT with amount 1 and nothing else, R4 = the owner key,
/// R5 = the empty reserve tree, R6 = `tracker_nft` (a reserve bound to another tracker is
/// refused), R7 absent or Long 0, no other register; its change address must be the owner's.
/// A register whose hex holds bytes after its value is read as the node reads it (the value
/// alone), the box gets the value's canonical encoding, and a warning says so.
pub fn reserve_output(
    payload: &ReservePayload,
    owner: &[u8; 33],
    erg_nano: u64,
    reserve_nft: &str,
    tracker_nft: &[u8; 32],
    height: u32,
) -> Result<ReserveOutput, String> {
    let [request] = payload.requests.as_slice() else {
        return Err(format!(
            "the payload asks for {} boxes; a reserve creation is exactly one",
            payload.requests.len()
        ));
    };
    let mut warnings = Vec::new();

    let ergo_tree = tx::address_tree(&request.address)?;
    if ergo_tree != tx::reserve_tree()? {
        return Err(format!(
            "payload address {} is not the ERG reserve contract compiled into this build",
            request.address
        ));
    }
    if request.value != erg_nano {
        return Err(format!(
            "payload value is {} nanoERG, {erg_nano} was asked for",
            request.value
        ));
    }
    match request.assets.as_slice() {
        [asset] if asset.token_id.eq_ignore_ascii_case(reserve_nft) && asset.amount == 1 => {}
        other => {
            return Err(format!(
                "payload assets {other:?} are not exactly the reserve NFT {reserve_nft} with \
                 amount 1"
            ))
        }
    }

    let registers = &request.registers;
    if let Some(other) = registers
        .keys()
        .find(|k| !matches!(k.as_str(), "R4" | "R5" | "R6" | "R7"))
    {
        return Err(format!("unexpected register {other} in the payload"));
    }
    let mut read = |id: &str| -> Result<Option<Constant>, String> {
        let Some(value) = registers.get(id) else {
            return Ok(None);
        };
        let (constant, canonical) =
            tx::parse_register(value).map_err(|e| format!("payload {id} {value:?}: {e}"))?;
        if !canonical {
            let encoded = tx::constant_hex(&constant)?;
            warnings.push(format!(
                "payload {id} is {value}: the value {encoded} followed by {} extra byte(s). The \
                 node reads only the value, so the reserve box gets {encoded}",
                (value.len() - encoded.len()) / 2
            ));
        }
        Ok(Some(constant))
    };
    let r4 = read("R4")?.ok_or("register R4 (owner key) missing from the payload")?;
    let r5 = read("R5")?.ok_or("register R5 (reserve tree) missing from the payload")?;
    let r6 = read("R6")?.ok_or("register R6 (tracker NFT id) missing from the payload")?;
    let r7 = read("R7")?;

    if r4 != Constant::from(tx::point(owner)?) {
        return Err(format!(
            "payload R4 is not the owner key {}",
            hex::encode(owner)
        ));
    }
    let empty_tree = basis_store::ergo_scanner::empty_reserve_tree_register();
    if !tx::constant_hex(&r5)?.eq_ignore_ascii_case(&empty_tree) {
        return Err(format!(
            "payload R5 {} is not the empty reserve tree {empty_tree}",
            tx::constant_hex(&r5)?
        ));
    }
    if r6 != tx::coll_bytes(tracker_nft) {
        return Err(format!(
            "payload R6 {} is not our tracker NFT {}; refusing to create a reserve bound to \
             another tracker",
            tx::constant_hex(&r6)?,
            hex::encode(tracker_nft)
        ));
    }
    if let Some(r7) = &r7 {
        if *r7 != Constant::from(0i64) {
            return Err(format!(
                "payload R7 {} is not Long 0: a new reserve has no refund pending",
                tx::constant_hex(r7)?
            ));
        }
    }

    let owner_address = local_wallet::p2pk_address(owner)?;
    if tx::address_tree(&payload.change_address)? != tx::p2pk_tree(owner)? {
        return Err(format!(
            "payload change address {} is not the owner's address {owner_address}",
            payload.change_address
        ));
    }

    let mut values = vec![r4, r5, r6];
    values.extend(r7);
    let additional_registers =
        NonMandatoryRegisters::try_from(values).map_err(|e| format!("registers: {e}"))?;
    let reserve_nft_id = tx::token_id(&tx::parse_id("reserve NFT id", reserve_nft)?)?;
    let tokens = BoxTokens::from_vec(vec![Token {
        token_id: reserve_nft_id,
        amount: TokenAmount::try_from(1u64).map_err(|e| format!("token amount: {e}"))?,
    }])
    .map_err(|e| format!("tokens: {e}"))?;
    let candidate = ErgoBoxCandidate {
        value: BoxValue::try_from(erg_nano).map_err(|e| format!("reserve value: {e}"))?,
        ergo_tree,
        tokens: Some(tokens),
        additional_registers,
        creation_height: height,
    };
    let min = local_wallet::min_box_value(&candidate)?;
    if erg_nano < min {
        return Err(format!(
            "--erg-nano {erg_nano} is below the minimum value of the reserve box ({min} nanoERG)"
        ));
    }
    Ok(ReserveOutput {
        candidate,
        warnings,
    })
}

/// A transaction ready to sign, with the boxes it spends in input order.
#[derive(Debug, Clone)]
pub struct BuiltTx {
    pub unsigned: UnsignedTransaction,
    pub inputs: Vec<ErgoBox>,
    /// Miner fee, including any leftover too small for a change box.
    pub fee: u64,
    /// Value of the change output (0 when there is none).
    pub change: u64,
}

/// Outputs `[reserve, fee, change]` spending `inputs`: 0.001 ERG fee, the rest back to
/// `change_tree`, or to the fee when it is too small for a box.
pub fn build_reserve_tx(
    inputs: Vec<ErgoBox>,
    reserve: ErgoBoxCandidate,
    change_tree: &ErgoTree,
    height: u32,
) -> Result<BuiltTx, String> {
    let total_in =
        tx::checked_sum(inputs.iter().map(|b| *b.value.as_u64())).ok_or("input value overflow")?;
    let required = reserve
        .value
        .as_u64()
        .checked_add(FEE)
        .ok_or("value overflow")?;
    let leftover = total_in.checked_sub(required).ok_or_else(|| {
        format!("the inputs hold {total_in} nanoERG, the transaction needs {required}")
    })?;
    let change_output = local_wallet::change_output(leftover, change_tree, height)?;
    let (fee, change) = match change_output {
        Some(_) => (FEE, leftover),
        None => (FEE + leftover, 0),
    };
    let mut outputs = vec![reserve, local_wallet::miner_fee_output(fee, height)?];
    outputs.extend(change_output);
    let unsigned_inputs = inputs
        .iter()
        .map(|b| UnsignedInput::new(b.box_id(), ContextExtension::empty()))
        .collect();
    let unsigned = UnsignedTransaction::new_from_vec(unsigned_inputs, vec![], outputs)
        .map_err(|e| format!("build transaction: {e}"))?;
    Ok(BuiltTx {
        unsigned,
        inputs,
        fee,
        change,
    })
}

/// Checks run before the reserve creation is signed:
/// - every input is locked by `P2PK(owner)` and holds no token, and there is at least one
///   (the scanner admits a reserve only when its creating transaction spends a P2PK input of
///   the R4 key, issue #19); input 0 is the box the reserve NFT id comes from;
/// - ERG in equals ERG out;
/// - the only token anywhere is the reserve NFT, minted with amount 1, first in output 0;
/// - output 0 is the reserve contract with R4 = owner, R5 = empty tree, R6 = `tracker_nft`,
///   R7 absent or Long 0 and no other register;
/// - output 1 is the miner fee, and an output 2 can only be token-free change to the owner.
pub fn check_reserve_tx(
    built: &BuiltTx,
    owner: &[u8; 33],
    reserve_nft: &str,
    tracker_nft: &[u8; 32],
) -> Result<(), String> {
    let owner_tree = tx::p2pk_tree(owner)?;
    let outputs = built.unsigned.output_candidates.as_vec();

    let p2pk_inputs = built
        .inputs
        .iter()
        .filter(|b| b.ergo_tree == owner_tree)
        .count();
    if p2pk_inputs == 0 {
        return Err(
            "no input is locked by P2PK(owner): the tracker would quarantine the reserve \
             (issue #19)"
                .to_string(),
        );
    }
    for b in &built.inputs {
        let id = String::from(b.box_id());
        if b.ergo_tree != owner_tree {
            return Err(format!("input {id} is not locked by P2PK(owner); refusing"));
        }
        if !tx::box_tokens(b).is_empty() {
            return Err(format!("input {id} holds tokens; refusing to move them"));
        }
    }
    let first = built.inputs.first().ok_or("no inputs")?;
    if !String::from(first.box_id()).eq_ignore_ascii_case(reserve_nft) {
        return Err(format!(
            "input 0 is {}, but the reserve NFT id is {reserve_nft}",
            String::from(first.box_id())
        ));
    }

    tx::check_erg_preserved(&built.inputs, outputs)?;
    local_wallet::check_tokens_preserved(&built.inputs, outputs, Some((reserve_nft, 1)))?;
    local_wallet::check_nft_only_in_output0(outputs, reserve_nft)?;

    let reserve = outputs.first().ok_or("no outputs")?;
    if reserve.ergo_tree != tx::reserve_tree()? {
        return Err("output 0 is not the ERG reserve contract".to_string());
    }
    let reg = |id| tx::candidate_register(reserve, id);
    if reg(NonMandatoryRegisterId::R4) != Some(Constant::from(tx::point(owner)?)) {
        return Err("output 0 R4 is not the owner key".to_string());
    }
    let r5 = reg(NonMandatoryRegisterId::R5)
        .map(|c| tx::constant_hex(&c))
        .transpose()?;
    if r5.as_deref() != Some(basis_store::ergo_scanner::empty_reserve_tree_register().as_str()) {
        return Err(format!("output 0 R5 {r5:?} is not the empty reserve tree"));
    }
    if reg(NonMandatoryRegisterId::R6) != Some(tx::coll_bytes(tracker_nft)) {
        return Err(format!(
            "output 0 R6 is not our tracker NFT {}; refusing",
            hex::encode(tracker_nft)
        ));
    }
    match reg(NonMandatoryRegisterId::R7) {
        None => {}
        Some(c) if c == Constant::from(0i64) => {}
        Some(c) => {
            return Err(format!(
                "output 0 R7 {} is not Long 0",
                tx::constant_hex(&c)?
            ))
        }
    }
    if reg(NonMandatoryRegisterId::R8).is_some() || reg(NonMandatoryRegisterId::R9).is_some() {
        return Err("output 0 has registers beyond R7".to_string());
    }

    match outputs.get(1) {
        Some(fee) if fee.ergo_tree == tx::fee_tree()? && *fee.value.as_u64() >= FEE => {}
        _ => return Err("output 1 is not the miner fee".to_string()),
    }
    if let Some(change) = outputs.get(2) {
        if change.ergo_tree != owner_tree || change.tokens.is_some() {
            return Err("output 2 is not token-free change to the owner".to_string());
        }
    }
    if outputs.len() > 3 {
        return Err(format!("{} outputs; expected at most 3", outputs.len()));
    }
    Ok(())
}

/// Token-free boxes at `address` (locked by exactly `owner_tree_hex`) worth at least `required`,
/// read from the node's UTXO set.
async fn fund(
    node: &NodeEndpoint,
    address: &str,
    owner_tree_hex: &str,
    required: u64,
) -> Result<Vec<ErgoBox>, String> {
    let scan = local_wallet::scan_fee_boxes(node, address, owner_tree_hex, &[], required).await?;
    let Some((picked, _)) = local_wallet::select_fee_boxes(&scan.boxes, required) else {
        return Err(format!(
            "not enough ERG at {address}: token-free boxes hold {} nanoERG in {} boxes ({} boxes \
             with tokens skipped{}), {required} nanoERG needed",
            scan.total(),
            scan.boxes.len(),
            scan.skipped_with_tokens,
            if scan.truncated {
                ", scan truncated"
            } else {
                ""
            }
        ));
    };
    let mut boxes = Vec::with_capacity(picked.len());
    for b in &picked {
        boxes.push(local_wallet::fetch_box(node, &b.box_id).await?);
    }
    Ok(boxes)
}

/// `reserve-create`.
pub async fn reserve_create(
    context: &Context,
    owner: &FileKey,
    erg_nano: u64,
    dry_run: bool,
    report: &mut Report,
) -> Result<(), String> {
    if erg_nano == 0 {
        return Err("--erg-nano must be above 0".to_string());
    }
    let owner_pk = owner.public_key();
    let address = owner.address()?;
    let owner_tree = tx::p2pk_tree(&owner_pk)?;
    report.line(format!(
        "reserve-create: owner {} ({address}), {erg_nano} nanoERG, tracker NFT {}",
        hex::encode(owner_pk),
        hex::encode(context.tracker_nft)
    ));

    let state = local_wallet::fetch_state_context(&context.node).await?;
    let height = state.pre_header.height;
    report.line(format!(
        "node {}: chain tip {height} (GET /blocks/lastHeaders/10)",
        context.node.url()
    ));

    let required = erg_nano.checked_add(FEE).ok_or("--erg-nano overflow")?;
    let inputs = fund(&context.node, &address, &owner.p2pk_tree_hex(), required).await?;
    let reserve_nft = String::from(inputs[0].box_id());
    report.line(format!(
        "funding: {} box(es) at {address}; reserve NFT id = id of input 0: {reserve_nft}",
        inputs.len()
    ));

    let request = json!({
        "nft_id": reserve_nft,
        "owner_pubkey": hex::encode(owner_pk),
        "erg_amount": erg_nano,
    });
    report.line(format!(
        "POST {}/reserves/create {request}",
        context.tracker.url()
    ));
    let response = context.tracker.post("/reserves/create", &request).await?;
    report.line(format!("HTTP {}", response.status));
    report.line(response.pretty());
    let data = response.data("POST /reserves/create", 200)?;
    let payload: ReservePayload = serde_json::from_value(data)
        .map_err(|e| format!("POST /reserves/create: unexpected payload: {e}"))?;
    if payload.fee != FEE {
        report.line(format!(
            "note: the payload's fee is {} nanoERG; this tool pays {FEE} nanoERG",
            payload.fee
        ));
    }

    let reserve = reserve_output(
        &payload,
        &owner_pk,
        erg_nano,
        &reserve_nft,
        &context.tracker_nft,
        height,
    )?;
    for warning in &reserve.warnings {
        report.line(format!("warning: {warning}"));
    }
    let built = build_reserve_tx(inputs, reserve.candidate, &owner_tree, height)?;
    check_reserve_tx(&built, &owner_pk, &reserve_nft, &context.tracker_nft)?;
    report.line(
        "checks before signing: OK (ERG in = ERG out; only the reserve NFT is minted, amount 1, \
         first in output 0; every input is P2PK(owner) and token-free; R4 = owner key, \
         R5 = empty reserve tree, R6 = our tracker NFT, R7 = Long 0)",
    );

    let reserve_tree = tx::reserve_tree()?;
    let fee_tree = tx::fee_tree()?;
    let label = |tree: &ErgoTree| -> String {
        if *tree == owner_tree {
            format!("P2PK(owner) {address}")
        } else if *tree == reserve_tree {
            "the Basis ERG reserve contract".to_string()
        } else if *tree == fee_tree {
            "the miner fee".to_string()
        } else {
            "another script".to_string()
        }
    };
    report.line(tx::describe(&built.unsigned, &built.inputs, &[], &label)?.trim_end());
    report.line(format!(
        "fee: {} nanoERG, change: {} nanoERG",
        built.fee, built.change
    ));
    if dry_run {
        report.line("unsigned transaction (node JSON):");
        report.line(tx::unsigned_json(&built.unsigned)?);
    }

    let signed =
        owner.sign_all_inputs(built.unsigned.clone(), built.inputs.clone(), vec![], &state)?;
    let tx_id = String::from(signed.id());
    let reserve_box_id = signed
        .outputs
        .as_vec()
        .first()
        .map(|b| String::from(b.box_id()))
        .ok_or("signed transaction has no outputs")?;
    report.line(format!(
        "signed locally with the owner key and validated in full against the node's last 10 \
         headers: transaction {tx_id}, reserve box {reserve_box_id}"
    ));
    if dry_run {
        report.line("dry run: nothing submitted");
        return Ok(());
    }
    let submitted = local_wallet::broadcast(&context.node, &signed).await?;
    report.line(format!(
        "submitted transaction {submitted} through POST {}/transactions",
        context.node.url()
    ));
    report.line(format!(
        "reserve box {reserve_box_id} (output 0), reserve NFT {reserve_nft}"
    ));
    report.line(format!(
        "next: after it confirms, GET /reserves/issuer/{} lists the reserve",
        hex::encode(owner_pk)
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ergo_lib::chain::transaction::TxId;
    use ergo_lib::ergotree_ir::chain::address::{Address, AddressEncoder, NetworkPrefix};
    use ergo_lib::ergotree_ir::chain::token::TokenId;

    use super::*;

    const NFT: [u8; 32] = [0x5a; 32];
    const ERG: u64 = 1_000_000_000;

    fn key() -> [u8; 33] {
        basis_store::schnorr::generate_keypair().1
    }

    fn reserve_address() -> String {
        let address = Address::recreate_from_ergo_tree(&tx::reserve_tree().unwrap()).unwrap();
        AddressEncoder::new(NetworkPrefix::Mainnet).address_to_str(&address)
    }

    /// The payload as the tracker's `POST /reserves/create` writes it.
    fn payload(owner: &[u8; 33], reserve_nft: &str) -> ReservePayload {
        serde_json::from_value(json!({
            "requests": [{
                "address": reserve_address(),
                "value": ERG,
                "assets": [{ "token_id": reserve_nft, "amount": 1 }],
                "registers": {
                    "R4": format!("07{}", hex::encode(owner)),
                    "R5": basis_store::ergo_scanner::empty_reserve_tree_register(),
                    "R6": format!("0e20{}", hex::encode(NFT)),
                    "R7": "05000000000000000000",
                },
            }],
            "fee": FEE,
            "change_address": local_wallet::p2pk_address(owner).unwrap(),
        }))
        .unwrap()
    }

    fn utxo(tree: &ErgoTree, value: u64, token: Option<[u8; 32]>, index: u16) -> ErgoBox {
        let tokens = token.map(|id| {
            BoxTokens::from_vec(vec![Token {
                token_id: TokenId::from_str(&hex::encode(id)).unwrap(),
                amount: TokenAmount::try_from(1u64).unwrap(),
            }])
            .unwrap()
        });
        ErgoBox::new(
            BoxValue::try_from(value).unwrap(),
            tree.clone(),
            tokens,
            NonMandatoryRegisters::empty(),
            100,
            TxId::zero(),
            index,
        )
        .unwrap()
    }

    #[test]
    fn the_trackers_payload_gives_the_exact_reserve_box() {
        let owner = key();
        let nft_box = "ab".repeat(32);
        let out =
            reserve_output(&payload(&owner, &nft_box), &owner, ERG, &nft_box, &NFT, 100).unwrap();
        let registers: Vec<String> = tx::REGISTER_IDS
            .iter()
            .filter_map(|r| tx::candidate_register(&out.candidate, *r))
            .map(|c| tx::constant_hex(&c).unwrap())
            .collect();
        assert_eq!(
            registers,
            vec![
                format!("07{}", hex::encode(owner)),
                basis_store::ergo_scanner::empty_reserve_tree_register(),
                format!("0e20{}", hex::encode(NFT)),
                "0500".to_string(),
            ]
        );
        assert_eq!(tx::candidate_tokens(&out.candidate), vec![(nft_box, 1)]);
        assert_eq!(*out.candidate.value.as_u64(), ERG);
        assert_eq!(out.candidate.ergo_tree, tx::reserve_tree().unwrap());
        // The tracker's R7 holds 8 bytes after the Long: said, and encoded canonically.
        assert_eq!(out.warnings.len(), 1);
        assert!(out.warnings[0].starts_with("payload R7 is 05000000000000000000"));
    }

    #[test]
    fn a_payload_that_is_not_the_request_is_refused() {
        let owner = key();
        let nft_box = "ab".repeat(32);
        let other_key = hex::encode(key());
        type Edit = Box<dyn Fn(&mut ReservePayload)>;
        let cases: Vec<(Edit, &str)> = vec![
            (
                Box::new(|p: &mut ReservePayload| {
                    p.requests[0]
                        .registers
                        .insert("R6".into(), format!("0e20{}", "77".repeat(32)));
                }),
                "refusing to create a reserve bound to another tracker",
            ),
            (
                Box::new(|p: &mut ReservePayload| p.requests[0].value = ERG + 1),
                "was asked for",
            ),
            (
                Box::new(move |p: &mut ReservePayload| {
                    p.requests[0]
                        .registers
                        .insert("R4".into(), format!("07{other_key}"));
                }),
                "is not the owner key",
            ),
            (
                Box::new(|p: &mut ReservePayload| {
                    let tree = basis_store::ergo_scanner::empty_reserve_tree_register();
                    let other = format!("{}{}", &tree[..4], "00".repeat(32));
                    p.requests[0]
                        .registers
                        .insert("R5".into(), other + &tree[68..]);
                }),
                "is not the empty reserve tree",
            ),
            (
                Box::new(|p: &mut ReservePayload| {
                    p.requests[0].registers.insert("R7".into(), "0502".into());
                }),
                "is not Long 0",
            ),
            (
                Box::new(|p: &mut ReservePayload| {
                    p.requests[0].registers.insert("R8".into(), "0500".into());
                }),
                "unexpected register R8",
            ),
            (
                Box::new(|p: &mut ReservePayload| {
                    p.requests[0].registers.remove("R6");
                }),
                "R6 (tracker NFT id) missing",
            ),
            (
                Box::new(|p: &mut ReservePayload| {
                    p.requests[0].assets.push(PayloadAsset {
                        token_id: "cd".repeat(32),
                        amount: 5,
                    });
                }),
                "are not exactly the reserve NFT",
            ),
            (
                Box::new(|p: &mut ReservePayload| {
                    p.requests[0].address = local_wallet::p2pk_address(&key()).unwrap();
                }),
                "is not the ERG reserve contract",
            ),
            (
                Box::new(|p: &mut ReservePayload| {
                    p.change_address = local_wallet::p2pk_address(&key()).unwrap()
                }),
                "is not the owner's address",
            ),
            (
                Box::new(|p: &mut ReservePayload| {
                    let extra = p.requests[0].clone();
                    p.requests.push(extra);
                }),
                "exactly one",
            ),
        ];
        for (edit, expected) in cases {
            let mut p = payload(&owner, &nft_box);
            edit(&mut p);
            let e = reserve_output(&p, &owner, ERG, &nft_box, &NFT, 100).unwrap_err();
            assert!(e.contains(expected), "expected {expected:?}, got {e:?}");
        }
    }

    #[test]
    fn the_transaction_spends_only_the_owners_token_free_boxes() {
        let owner = key();
        let owner_tree = tx::p2pk_tree(&owner).unwrap();
        let inputs = vec![
            utxo(&owner_tree, 600_000_000, None, 0),
            utxo(&owner_tree, 500_000_000, None, 1),
        ];
        let nft_box = String::from(inputs[0].box_id());
        let reserve = reserve_output(&payload(&owner, &nft_box), &owner, ERG, &nft_box, &NFT, 100)
            .unwrap()
            .candidate;
        let built = build_reserve_tx(inputs.clone(), reserve.clone(), &owner_tree, 100).unwrap();
        check_reserve_tx(&built, &owner, &nft_box, &NFT).unwrap();
        assert_eq!((built.fee, built.change), (FEE, 99_000_000));

        // Change too small for a box goes to the fee.
        let exact = vec![utxo(&owner_tree, ERG + FEE + 1_000, None, 0)];
        let nft_exact = String::from(exact[0].box_id());
        let reserve_exact = reserve_output(
            &payload(&owner, &nft_exact),
            &owner,
            ERG,
            &nft_exact,
            &NFT,
            100,
        )
        .unwrap()
        .candidate;
        let built = build_reserve_tx(exact, reserve_exact, &owner_tree, 100).unwrap();
        check_reserve_tx(&built, &owner, &nft_exact, &NFT).unwrap();
        assert_eq!((built.fee, built.change), (FEE + 1_000, 0));
        assert_eq!(built.unsigned.output_candidates.len(), 2);

        // Not enough ERG.
        let e = build_reserve_tx(vec![inputs[1].clone()], reserve.clone(), &owner_tree, 100)
            .unwrap_err();
        assert!(e.contains("the transaction needs"), "{e}");

        let refused = |inputs: Vec<ErgoBox>, nft: &str| {
            let built = build_reserve_tx(inputs, reserve.clone(), &owner_tree, 100).unwrap();
            check_reserve_tx(&built, &owner, nft, &NFT).unwrap_err()
        };
        let foreign = tx::p2pk_tree(&key()).unwrap();
        // No input of the owner: the scanner would quarantine the reserve.
        let only_foreign = vec![utxo(&foreign, 2 * ERG, None, 0)];
        let id = String::from(only_foreign[0].box_id());
        assert!(refused(only_foreign, &id).contains("quarantine"));
        // A foreign input next to the owner's.
        let mixed = vec![inputs[0].clone(), utxo(&foreign, ERG, None, 1)];
        assert!(refused(mixed, &nft_box).contains("is not locked by P2PK(owner)"));
        // An input holding a token.
        let with_token = vec![inputs[0].clone(), utxo(&owner_tree, ERG, Some([9; 32]), 1)];
        assert!(refused(with_token, &nft_box).contains("holds tokens"));
        // The reserve NFT must be minted from input 0.
        let swapped = vec![inputs[1].clone(), inputs[0].clone()];
        assert!(refused(swapped, &nft_box).contains("but the reserve NFT id is"));
    }
}
