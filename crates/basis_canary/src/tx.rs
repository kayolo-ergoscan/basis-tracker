//! Shared transaction helpers: ids and keys, registers, scripts, the checks run before signing,
//! full validation and the printed summary.

use std::str::FromStr;

use basis_server::local_wallet;
use ergo_lib::chain::ergo_state_context::ErgoStateContext;
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::Transaction;
use ergo_lib::ergo_chain_types::EcPoint;
use ergo_lib::ergotree_ir::chain::address::{Address, AddressEncoder};
use ergo_lib::ergotree_ir::chain::ergo_box::{ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId};
use ergo_lib::ergotree_ir::chain::token::TokenId;
use ergo_lib::ergotree_ir::ergo_tree::ErgoTree;
use ergo_lib::ergotree_ir::mir::constant::Constant;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use ergo_lib::wallet::signing::TransactionContext;

/// Miner fee the canary pays for the transactions it builds itself: 0.001 ERG.
pub const FEE: u64 = 1_000_000;

/// The non-mandatory registers, in order.
pub const REGISTER_IDS: [NonMandatoryRegisterId; 6] = [
    NonMandatoryRegisterId::R4,
    NonMandatoryRegisterId::R5,
    NonMandatoryRegisterId::R6,
    NonMandatoryRegisterId::R7,
    NonMandatoryRegisterId::R8,
    NonMandatoryRegisterId::R9,
];

/// A 32-byte id (box, token or transaction id) given in hex.
pub fn parse_id(what: &str, id: &str) -> Result<[u8; 32], String> {
    let id = id.trim();
    if !local_wallet::is_hex_id(id) {
        return Err(format!("{what} must be 64 hex characters, got {id:?}"));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(id, &mut out).map_err(|e| format!("{what}: {e}"))?;
    Ok(out)
}

/// A compressed secp256k1 public key given in hex (66 characters, a point on the curve).
pub fn parse_pubkey(what: &str, pubkey: &str) -> Result<[u8; 33], String> {
    let pubkey = pubkey.trim();
    let bytes: [u8; 33] = hex::decode(pubkey)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{what} must be 66 hex characters (33 bytes), got {pubkey:?}"))?;
    EcPoint::sigma_parse_bytes(&bytes)
        .map_err(|e| format!("{what} {pubkey} is not a public key: {e}"))?;
    Ok(bytes)
}

/// The curve point of a public key.
pub fn point(pubkey: &[u8; 33]) -> Result<EcPoint, String> {
    EcPoint::sigma_parse_bytes(pubkey).map_err(|e| format!("public key: {e}"))
}

/// A register value as the node reads it: the first constant in `hex_value`. Returns the
/// constant and whether `hex_value` is exactly its encoding (`false` when there are extra
/// bytes after it or the encoding is not canonical).
pub fn parse_register(hex_value: &str) -> Result<(Constant, bool), String> {
    let bytes = hex::decode(hex_value.trim()).map_err(|e| format!("not hex: {e}"))?;
    let constant =
        Constant::sigma_parse_bytes(&bytes).map_err(|e| format!("not a constant: {e}"))?;
    let canonical = constant
        .sigma_serialize_bytes()
        .map(|back| back == bytes)
        .unwrap_or(false);
    Ok((constant, canonical))
}

/// Hex of a serialized constant.
pub fn constant_hex(constant: &Constant) -> Result<String, String> {
    constant
        .sigma_serialize_bytes()
        .map(hex::encode)
        .map_err(|e| format!("serialize constant: {e}"))
}

/// `Coll[Byte]` constant of `bytes`.
pub fn coll_bytes(bytes: &[u8]) -> Constant {
    Constant::from(bytes.to_vec())
}

/// ErgoTree from its hex encoding.
pub fn tree_from_hex(tree_hex: &str) -> Result<ErgoTree, String> {
    let bytes = hex::decode(tree_hex).map_err(|e| format!("ErgoTree hex: {e}"))?;
    ErgoTree::sigma_parse_bytes(&bytes).map_err(|e| format!("ErgoTree: {e}"))
}

/// Hex encoding of an ErgoTree.
pub fn tree_hex(tree: &ErgoTree) -> Result<String, String> {
    tree.sigma_serialize_bytes()
        .map(hex::encode)
        .map_err(|e| format!("serialize ErgoTree: {e}"))
}

/// The script behind an address of either network.
pub fn address_tree(address: &str) -> Result<ErgoTree, String> {
    AddressEncoder::unchecked_parse_address_from_str(address)
        .map_err(|e| format!("invalid address {address:?}: {e}"))?
        .script()
        .map_err(|e| format!("no script for address {address:?}: {e}"))
}

/// `P2PK(pubkey)`.
pub fn p2pk_tree(pubkey: &[u8; 33]) -> Result<ErgoTree, String> {
    tree_from_hex(&local_wallet::p2pk_tree_hex(pubkey))
}

/// The public key of a plain P2PK script, `None` for any other script.
pub fn p2pk_owner(tree: &ErgoTree) -> Option<[u8; 33]> {
    match Address::recreate_from_ergo_tree(tree) {
        Ok(Address::P2Pk(owner)) => owner.h.sigma_serialize_bytes().ok()?.try_into().ok(),
        _ => None,
    }
}

/// The ERG reserve contract compiled into this build (the tracker refuses to start with any
/// other).
pub fn reserve_tree() -> Result<ErgoTree, String> {
    let hex_tree = basis_store::contract_compiler::get_basis_reserve_ergo_tree_hex()
        .map_err(|e| format!("compiled reserve contract: {e}"))?;
    tree_from_hex(&hex_tree)
}

/// The standard miner fee script.
pub fn fee_tree() -> Result<ErgoTree, String> {
    Ok(local_wallet::miner_fee_output(FEE, 0)?.ergo_tree)
}

/// Tokens of a box as `(id hex, amount)`, in order.
pub fn box_tokens(b: &ErgoBox) -> Vec<(String, u64)> {
    b.tokens
        .iter()
        .flat_map(|t| t.iter())
        .map(|t| (String::from(t.token_id), u64::from(t.amount)))
        .collect()
}

/// Tokens of an output candidate as `(id hex, amount)`, in order.
pub fn candidate_tokens(o: &ErgoBoxCandidate) -> Vec<(String, u64)> {
    o.tokens
        .iter()
        .flat_map(|t| t.iter())
        .map(|t| (String::from(t.token_id), u64::from(t.amount)))
        .collect()
}

/// A token id from 32 bytes.
pub fn token_id(id: &[u8; 32]) -> Result<TokenId, String> {
    TokenId::from_str(&hex::encode(id)).map_err(|e| format!("token id: {e}"))
}

/// Register `id` of a box, `None` when absent or unreadable.
pub fn register(b: &ErgoBox, id: NonMandatoryRegisterId) -> Option<Constant> {
    b.additional_registers.get_constant(id).ok().flatten()
}

/// Register `id` of an output candidate, `None` when absent or unreadable.
pub fn candidate_register(o: &ErgoBoxCandidate, id: NonMandatoryRegisterId) -> Option<Constant> {
    o.additional_registers.get_constant(id).ok().flatten()
}

/// Sum of `values`, `None` on overflow.
pub fn checked_sum(values: impl Iterator<Item = u64>) -> Option<u64> {
    let mut total = 0u64;
    for v in values {
        total = total.checked_add(v)?;
    }
    Some(total)
}

/// ERG in equals ERG out; returns the total.
pub fn check_erg_preserved(
    inputs: &[ErgoBox],
    outputs: &[ErgoBoxCandidate],
) -> Result<u64, String> {
    let erg_in = checked_sum(inputs.iter().map(|b| *b.value.as_u64()));
    let erg_out = checked_sum(outputs.iter().map(|o| *o.value.as_u64()));
    match (erg_in, erg_out) {
        (Some(i), Some(o)) if i == o => Ok(i),
        _ => Err(format!(
            "ERG not preserved: inputs {erg_in:?} nanoERG, outputs {erg_out:?} nanoERG"
        )),
    }
}

/// The boxes `unsigned` spends, in input order, must be exactly `inputs` (same ids), and its
/// data inputs exactly `data_inputs`.
pub fn check_box_ids(
    unsigned: &UnsignedTransaction,
    inputs: &[ErgoBox],
    data_inputs: &[ErgoBox],
) -> Result<(), String> {
    let input_ids: Vec<String> = unsigned
        .inputs
        .iter()
        .map(|i| String::from(i.box_id))
        .collect();
    let data_ids: Vec<String> = unsigned
        .data_inputs
        .iter()
        .flat_map(|d| d.iter())
        .map(|d| String::from(d.box_id))
        .collect();
    let have = |boxes: &[ErgoBox]| -> Vec<String> {
        boxes.iter().map(|b| String::from(b.box_id())).collect()
    };
    if input_ids != have(inputs) {
        return Err(format!(
            "the transaction spends {input_ids:?}, the boxes supplied are {:?}",
            have(inputs)
        ));
    }
    if data_ids != have(data_inputs) {
        return Err(format!(
            "the transaction reads {data_ids:?}, the data boxes supplied are {:?}",
            have(data_inputs)
        ));
    }
    Ok(())
}

/// Validate a signed transaction in full against `state`: every proof, ERG and token
/// preservation, box sizes and values, as the node does.
pub fn validate(
    signed: &Transaction,
    inputs: &[ErgoBox],
    data_inputs: &[ErgoBox],
    state: &ErgoStateContext,
) -> Result<(), String> {
    TransactionContext::new(signed.clone(), inputs.to_vec(), data_inputs.to_vec())
        .map_err(|e| format!("transaction context: {e}"))?
        .validate(state)
        .map_err(|e| format!("the signed transaction does not validate: {e}"))
}

/// The unsigned transaction as the JSON the node accepts, pretty-printed.
pub fn unsigned_json(unsigned: &UnsignedTransaction) -> Result<String, String> {
    serde_json::to_string_pretty(unsigned).map_err(|e| format!("encode transaction: {e}"))
}

/// Human summary of a transaction: inputs with their script, data inputs, outputs with tokens
/// and the exact register hex, and every non-empty context extension. `label` names a script.
pub fn describe(
    unsigned: &UnsignedTransaction,
    inputs: &[ErgoBox],
    data_inputs: &[ErgoBox],
    label: &dyn Fn(&ErgoTree) -> String,
) -> Result<String, String> {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "transaction {}", String::from(unsigned.id()));
    let _ = writeln!(out, "inputs:");
    for (i, b) in inputs.iter().enumerate() {
        let _ = writeln!(
            out,
            "  {i}: box {} {} nanoERG, {}, tokens {:?}",
            String::from(b.box_id()),
            b.value.as_u64(),
            label(&b.ergo_tree),
            box_tokens(b)
        );
        for reg in REGISTER_IDS {
            if let Some(c) = register(b, reg) {
                let _ = writeln!(out, "     {reg:?} = {}", constant_hex(&c)?);
            }
        }
    }
    if !data_inputs.is_empty() {
        let _ = writeln!(out, "data inputs:");
        for (i, b) in data_inputs.iter().enumerate() {
            let _ = writeln!(
                out,
                "  {i}: box {} {}, tokens {:?}",
                String::from(b.box_id()),
                label(&b.ergo_tree),
                box_tokens(b)
            );
            for reg in REGISTER_IDS {
                if let Some(c) = register(b, reg) {
                    let _ = writeln!(out, "     {reg:?} = {}", constant_hex(&c)?);
                }
            }
        }
    }
    let _ = writeln!(out, "outputs:");
    for (i, o) in unsigned.output_candidates.iter().enumerate() {
        let _ = writeln!(
            out,
            "  {i}: {} nanoERG to {}, creation height {}, tokens {:?}",
            o.value.as_u64(),
            label(&o.ergo_tree),
            o.creation_height,
            candidate_tokens(o)
        );
        for reg in REGISTER_IDS {
            if let Some(c) = candidate_register(o, reg) {
                let _ = writeln!(out, "     {reg:?} = {}", constant_hex(&c)?);
            }
        }
    }
    for (i, input) in unsigned.inputs.iter().enumerate() {
        if input.extension.values.is_empty() {
            continue;
        }
        let _ = writeln!(out, "context extension of input {i} (serialization order):");
        for (key, value) in input.extension.values.iter() {
            let _ = writeln!(out, "     #{key} = {}", constant_hex(value)?);
        }
    }
    Ok(out)
}
