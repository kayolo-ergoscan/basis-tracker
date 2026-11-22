//! One-time on-chain setup of a Basis tracker, signed locally with the tracker key.
//!
//! - `mint-nft` mints the tracker NFT (EIP-4 registers) into a box at `P2PK(tracker key)`.
//! - `init-box` turns the box holding that NFT into the tracker box: token 0 = NFT,
//!   R4 = tracker public key, R5 = empty AVL tree, R6 = NFT id.
//!
//! Both read only public node endpoints (`GET /blocks/lastHeaders/10`,
//! `POST /blockchain/box/unspent/byAddress`, `GET /blockchain/token/byId/{id}`,
//! `GET /blockchain/box/unspent/byTokenId/{id}`, `GET /utxo/byIdBinary/{id}`), sign in-process
//! and submit through `POST /transactions`. No node wallet or API key is needed, and the
//! secret key never leaves the process.
//!
//! Every transaction spends only boxes locked by the tracker key, pays a 0.001 ERG fee,
//! returns change to the tracker address, and is checked before signing: no token is burned,
//! only the new NFT is minted (by `mint-nft`), the NFT sits once, first in output 0, and the
//! ERG in equals the ERG out.

use basis_server::local_wallet::{self, NodeEndpoint, TrackerKey, UnspentBox};
use ergo_lib::chain::ergo_state_context::ErgoStateContext;
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::UnsignedInput;
use ergo_lib::ergotree_ir::chain::context_extension::ContextExtension;
use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
use ergo_lib::ergotree_ir::chain::ergo_box::{
    BoxTokens, ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId, NonMandatoryRegisters,
};
use ergo_lib::ergotree_ir::chain::token::{Token, TokenAmount, TokenId};
use ergo_lib::ergotree_ir::ergo_tree::ErgoTree;
use ergo_lib::ergotree_ir::mir::constant::Constant;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use ergo_lib::ergotree_ir::types::stype::SType;
use serde_json::Value;
use std::str::FromStr;

/// Miner fee of every bootstrap transaction: 0.001 ERG.
pub const FEE: u64 = 1_000_000;
/// Value of the box the NFT is minted into: 0.001 ERG.
pub const NFT_BOX_VALUE: u64 = 1_000_000;
/// Default value of the tracker box (`init-box --value-nano`): 0.001 ERG. Commits keep it.
pub const DEFAULT_TRACKER_BOX_VALUE: u64 = 1_000_000;
/// R5 of a new tracker box: the empty AVL tree (`SAvlTree`: digest of the empty tree,
/// flags 03 = insert and update allowed, key length 32, no fixed value length).
pub const EMPTY_TREE_R5_HEX: &str =
    "644ec61f485b98eb87153f7c57db4f5ecd75556fddbc403b41acf8441fde8e160900032000";
/// Default EIP-4 name of the tracker NFT.
pub const DEFAULT_NFT_NAME: &str = "Basis Tracker";
/// Default EIP-4 description of the tracker NFT.
pub const DEFAULT_NFT_DESCRIPTION: &str = "Basis tracker NFT";

const REGISTER_IDS: [NonMandatoryRegisterId; 6] = [
    NonMandatoryRegisterId::R4,
    NonMandatoryRegisterId::R5,
    NonMandatoryRegisterId::R6,
    NonMandatoryRegisterId::R7,
    NonMandatoryRegisterId::R8,
    NonMandatoryRegisterId::R9,
];

/// Parse one serialized constant and check that it serializes back to exactly `hex_str`.
fn constant_from_hex(hex_str: &str) -> Result<Constant, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("register {hex_str}: {e}"))?;
    let constant =
        Constant::sigma_parse_bytes(&bytes).map_err(|e| format!("register {hex_str}: {e}"))?;
    let back = constant
        .sigma_serialize_bytes()
        .map_err(|e| format!("register {hex_str}: {e}"))?;
    if back != bytes {
        return Err(format!("register {hex_str} does not round-trip"));
    }
    Ok(constant)
}

fn constant_hex(constant: &Constant) -> Result<String, String> {
    constant
        .sigma_serialize_bytes()
        .map(hex::encode)
        .map_err(|e| format!("serialize register: {e}"))
}

/// Hex of a `Coll[Byte]` constant: `0e ‖ VLQ(length) ‖ bytes`.
pub fn coll_byte_hex(bytes: &[u8]) -> Result<String, String> {
    constant_hex(&Constant::from(bytes.to_vec()))
}

/// EIP-4 registers of the tracker NFT, as hex: R4 = name, R5 = description, R6 = decimals
/// `"0"`, each a `Coll[Byte]` of UTF-8 text.
pub fn nft_register_hex(name: &str, description: &str) -> Result<[String; 3], String> {
    if name.trim().is_empty() {
        return Err("the NFT name must not be empty".to_string());
    }
    Ok([
        coll_byte_hex(name.as_bytes())?,
        coll_byte_hex(description.as_bytes())?,
        coll_byte_hex(b"0")?,
    ])
}

/// Registers of a new tracker box, as hex: R4 = `07 ‖ pk` (GroupElement), R5 =
/// [`EMPTY_TREE_R5_HEX`], R6 = `0e20 ‖ nft id` (Coll[Byte]).
pub fn tracker_register_hex(pubkey: &[u8; 33], nft_id: &[u8; 32]) -> [String; 3] {
    [
        format!("07{}", hex::encode(pubkey)),
        EMPTY_TREE_R5_HEX.to_string(),
        format!("0e20{}", hex::encode(nft_id)),
    ]
}

fn registers_from_hex(hex_values: &[String]) -> Result<NonMandatoryRegisters, String> {
    let constants = hex_values
        .iter()
        .map(|h| constant_from_hex(h))
        .collect::<Result<Vec<_>, _>>()?;
    NonMandatoryRegisters::try_from(constants).map_err(|e| format!("registers: {e}"))
}

/// Parse a 32-byte id (token or box id) given in hex.
pub fn parse_id(what: &str, id: &str) -> Result<[u8; 32], String> {
    let id = id.trim();
    if !local_wallet::is_hex_id(id) {
        return Err(format!("{what} must be 64 hex characters, got {id:?}"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex::decode(id).map_err(|e| format!("{what}: {e}"))?);
    Ok(out)
}

fn tokens_of(b: &ErgoBox) -> Vec<(String, u64)> {
    b.tokens
        .iter()
        .flat_map(|t| t.iter())
        .map(|t| (String::from(t.token_id), u64::from(t.amount)))
        .collect()
}

fn single_token(token_id: TokenId) -> Result<BoxTokens, String> {
    let amount = TokenAmount::try_from(1u64).map_err(|e| format!("token amount: {e}"))?;
    BoxTokens::from_vec(vec![Token { token_id, amount }]).map_err(|e| format!("tokens: {e}"))
}

fn box_value(what: &str, v: u64) -> Result<BoxValue, String> {
    BoxValue::try_from(v).map_err(|e| format!("{what}: {e}"))
}

/// A transaction ready to sign, with the boxes it spends in input order.
#[derive(Debug, Clone)]
pub struct BuiltTx {
    pub unsigned: UnsignedTransaction,
    pub inputs: Vec<ErgoBox>,
    /// Miner fee, including any dust leftover too small for a change box.
    pub fee: u64,
    /// Value of the change output (0 when there is none).
    pub change: u64,
}

/// Refuse any input that holds a token or is not locked by `owner_tree`.
fn check_plain_inputs(boxes: &[ErgoBox], owner_tree: &ErgoTree) -> Result<(), String> {
    for b in boxes {
        let id = String::from(b.box_id());
        if b.ergo_tree != *owner_tree {
            return Err(format!(
                "input {id} is not locked by P2PK(tracker key); refusing to spend it"
            ));
        }
        let tokens = tokens_of(b);
        if !tokens.is_empty() {
            return Err(format!(
                "input {id} holds unrelated token(s) {tokens:?}; refusing to spend it"
            ));
        }
    }
    Ok(())
}

/// Add the fee output and the change output (dust goes to the fee) to `outputs`, whose total
/// value is `payload_value`, and build the transaction spending `inputs`.
fn assemble(
    inputs: Vec<ErgoBox>,
    mut outputs: Vec<ErgoBoxCandidate>,
    payload_value: u64,
    change_tree: &ErgoTree,
    height: u32,
) -> Result<BuiltTx, String> {
    let total_in = inputs
        .iter()
        .try_fold(0u64, |acc, b| acc.checked_add(*b.value.as_u64()))
        .ok_or("input value overflow")?;
    let required = payload_value.checked_add(FEE).ok_or("value overflow")?;
    if total_in < required {
        return Err(format!(
            "the inputs hold {total_in} nanoERG, the transaction needs {required}"
        ));
    }
    let leftover = total_in - required;
    let change_output = local_wallet::change_output(leftover, change_tree, height)?;
    let (fee, change) = match change_output {
        Some(_) => (FEE, leftover),
        None => (FEE + leftover, 0),
    };
    outputs.push(local_wallet::miner_fee_output(fee, height)?);
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

/// Build the mint transaction. `inputs` are token-free boxes at `owner_tree`; the NFT id is
/// the id of the first input (the only token id a transaction may mint). Output 0 holds the
/// NFT (amount 1, EIP-4 registers) at `owner_tree`, output 1 is the fee, output 2 the change.
/// Returns the transaction and the NFT id.
pub fn build_mint_tx(
    inputs: Vec<ErgoBox>,
    owner_tree: &ErgoTree,
    name: &str,
    description: &str,
    height: u32,
) -> Result<(BuiltTx, String), String> {
    let first = inputs.first().ok_or("no input boxes")?;
    check_plain_inputs(&inputs, owner_tree)?;
    let nft_id = TokenId::from(first.box_id());
    let nft_box = ErgoBoxCandidate {
        value: box_value("NFT box value", NFT_BOX_VALUE)?,
        ergo_tree: owner_tree.clone(),
        tokens: Some(single_token(nft_id)?),
        additional_registers: registers_from_hex(&nft_register_hex(name, description)?)?,
        creation_height: height,
    };
    let min = local_wallet::min_box_value(&nft_box)?;
    if min > NFT_BOX_VALUE {
        return Err(format!(
            "the NFT box needs {min} nanoERG with this name and description, above the \
             {NFT_BOX_VALUE} nanoERG it gets; use a shorter name or description"
        ));
    }
    let tx = assemble(inputs, vec![nft_box], NFT_BOX_VALUE, owner_tree, height)?;
    Ok((tx, String::from(nft_id)))
}

/// Check that `b` can become the tracker box: it is locked by `owner_tree`, holds exactly the
/// NFT (amount 1) and no other token, and is not a tracker box already (R4 a GroupElement or
/// R5 an AVL tree): re-initializing would reset the committed digest to the empty tree.
pub fn check_nft_box(b: &ErgoBox, owner_tree: &ErgoTree, nft_id: &str) -> Result<(), String> {
    let id = String::from(b.box_id());
    let nft_id = nft_id.to_ascii_lowercase();
    if b.ergo_tree != *owner_tree {
        return Err(format!(
            "box {id} holding the NFT is not locked by P2PK(tracker key); send the NFT to the \
             tracker address first"
        ));
    }
    let tokens = tokens_of(b);
    if !tokens.iter().any(|(t, _)| *t == nft_id) {
        return Err(format!("box {id} does not hold token {nft_id}"));
    }
    if tokens != [(nft_id.clone(), 1)] {
        return Err(format!(
            "box {id} holds {tokens:?}, not only the NFT {nft_id} with amount 1; refusing to \
             spend unrelated tokens (move them out first)"
        ));
    }
    let register_type = |reg| {
        b.additional_registers
            .get_constant(reg)
            .ok()
            .flatten()
            .map(|c| c.tpe)
    };
    if register_type(NonMandatoryRegisterId::R4) == Some(SType::SGroupElement)
        || register_type(NonMandatoryRegisterId::R5) == Some(SType::SAvlTree)
    {
        return Err(format!(
            "box {id} already is a tracker box (R4 holds a public key or R5 an AVL tree); \
             init-box only initializes a newly minted NFT box and would reset the committed \
             digest"
        ));
    }
    Ok(())
}

/// Build the init transaction: input 0 is `nft_box`, then `fee_boxes` (token-free, at
/// `owner_tree`). Output 0 is the tracker box (`value`, NFT, R4–R6 from
/// [`tracker_register_hex`]) at `owner_tree`, output 1 the fee, output 2 the change.
pub fn build_init_tx(
    nft_box: ErgoBox,
    fee_boxes: Vec<ErgoBox>,
    owner_tree: &ErgoTree,
    pubkey: &[u8; 33],
    nft_id: &str,
    value: u64,
    height: u32,
) -> Result<BuiltTx, String> {
    let nft = parse_id("NFT id", nft_id)?;
    check_nft_box(&nft_box, owner_tree, nft_id)?;
    check_plain_inputs(&fee_boxes, owner_tree)?;
    let token_id = TokenId::from_str(&hex::encode(nft)).map_err(|e| format!("NFT id: {e}"))?;
    // Measured with the real value whenever it can be a box value at all; a tracker box
    // always needs far more than `BoxValue::MIN_RAW`, so a smaller value fails below.
    let tracker_box = ErgoBoxCandidate {
        value: box_value("tracker box value", value.max(BoxValue::MIN_RAW))?,
        ergo_tree: owner_tree.clone(),
        tokens: Some(single_token(token_id)?),
        additional_registers: registers_from_hex(&tracker_register_hex(pubkey, &nft))?,
        creation_height: height,
    };
    let min = local_wallet::min_box_value(&tracker_box)?;
    if value < min {
        return Err(format!(
            "--value-nano {value} is below the minimum value of the tracker box ({min} nanoERG)"
        ));
    }
    let mut inputs = vec![nft_box];
    inputs.extend(fee_boxes);
    assemble(inputs, vec![tracker_box], value, owner_tree, height)
}

/// Checks run on every transaction before it is signed or printed: ERG in equals ERG out, no
/// token is burned, only `nft_id` is minted (when `minting`), and the NFT appears exactly
/// once, first in output 0, with amount 1.
pub fn check_before_signing(tx: &BuiltTx, nft_id: &str, minting: bool) -> Result<(), String> {
    fn sum(values: impl Iterator<Item = u64>) -> Option<u64> {
        values
            .into_iter()
            .try_fold(0u64, |acc, v| acc.checked_add(v))
    }
    let outputs = tx.unsigned.output_candidates.as_vec();
    let erg_in = sum(tx.inputs.iter().map(|b| *b.value.as_u64()));
    let erg_out = sum(outputs.iter().map(|o| *o.value.as_u64()));
    if erg_in.is_none() || erg_in != erg_out {
        return Err(format!(
            "ERG not preserved: inputs {erg_in:?}, outputs {erg_out:?}"
        ));
    }
    let mint = minting.then_some((nft_id, 1));
    local_wallet::check_tokens_preserved(&tx.inputs, outputs, mint)?;
    local_wallet::check_nft_only_in_output0(outputs, nft_id)
}

/// Human-readable summary: inputs, outputs with tokens and exact register hex, fee, change.
pub fn describe(tx: &BuiltTx, owner_tree: &ErgoTree) -> Result<String, String> {
    use std::fmt::Write;
    let fee_tree = local_wallet::miner_fee_output(FEE, 0)?.ergo_tree;
    let mut out = String::new();
    let _ = writeln!(out, "inputs:");
    for (i, b) in tx.inputs.iter().enumerate() {
        let _ = writeln!(
            out,
            "  {i}: box {} {} nanoERG tokens {:?}",
            String::from(b.box_id()),
            b.value.as_u64(),
            tokens_of(b)
        );
    }
    let _ = writeln!(out, "outputs:");
    for (i, o) in tx.unsigned.output_candidates.iter().enumerate() {
        let to = if o.ergo_tree == *owner_tree {
            "tracker address"
        } else if o.ergo_tree == fee_tree {
            "miner fee"
        } else {
            "other script"
        };
        let tokens: Vec<(String, u64)> = o
            .tokens
            .iter()
            .flat_map(|t| t.iter())
            .map(|t| (String::from(t.token_id), u64::from(t.amount)))
            .collect();
        let _ = writeln!(
            out,
            "  {i}: {} nanoERG to {to}, creation height {}, tokens {tokens:?}",
            o.value.as_u64(),
            o.creation_height
        );
        for reg in REGISTER_IDS {
            if let Ok(Some(c)) = o.additional_registers.get_constant(reg) {
                let _ = writeln!(out, "     {reg:?} = {}", constant_hex(&c)?);
            }
        }
    }
    let _ = writeln!(
        out,
        "fee: {} nanoERG, change: {} nanoERG",
        tx.fee, tx.change
    );
    Ok(out)
}

/// The node endpoints and the key a bootstrap run uses.
pub struct Bootstrap {
    pub key: TrackerKey,
    /// Reads: headers, boxes, tokens.
    pub scanner: NodeEndpoint,
    /// `POST /transactions`.
    pub broadcast: NodeEndpoint,
}

impl Bootstrap {
    /// The tracker's P2PK address.
    pub fn address(&self) -> Result<String, String> {
        local_wallet::p2pk_address(&self.key.public_key())
    }

    fn owner_tree(&self) -> Result<ErgoTree, String> {
        let bytes = hex::decode(self.key.p2pk_tree_hex()).map_err(|e| e.to_string())?;
        ErgoTree::sigma_parse_bytes(&bytes).map_err(|e| format!("tracker tree: {e}"))
    }

    /// Token-free boxes at the tracker address worth at least `required`, read from the UTXO
    /// set. Boxes holding any token are never selected.
    async fn fund(&self, required: u64, exclude: &[&str]) -> Result<Vec<ErgoBox>, String> {
        let address = self.address()?;
        let scan = local_wallet::scan_fee_boxes(
            &self.scanner,
            &address,
            &self.key.p2pk_tree_hex(),
            exclude,
            required,
        )
        .await?;
        let Some((picked, _)) = local_wallet::select_fee_boxes(&scan.boxes, required) else {
            return Err(format!(
                "not enough ERG at {address}: token-free boxes hold {} nanoERG in {} boxes \
                 ({} boxes with tokens skipped{}), {required} nanoERG needed. Send ERG to {address} \
                 and wait for a confirmation.",
                scan.total(),
                scan.boxes.len(),
                scan.skipped_with_tokens,
                if scan.truncated { ", scan truncated" } else { "" }
            ));
        };
        let mut boxes = Vec::with_capacity(picked.len());
        for b in &picked {
            boxes.push(local_wallet::fetch_box(&self.scanner, &b.box_id).await?);
        }
        Ok(boxes)
    }

    /// Dry run: print the unsigned transaction. Otherwise sign it locally (full validation
    /// against `state`) and submit it.
    async fn sign_and_submit(
        &self,
        tx: BuiltTx,
        state: &ErgoStateContext,
        dry_run: bool,
        report: &mut String,
    ) -> Result<Option<String>, String> {
        if dry_run {
            let json = serde_json::to_string_pretty(&tx.unsigned)
                .map_err(|e| format!("encode transaction: {e}"))?;
            report.push_str("dry run: not signed, not submitted. Unsigned transaction:\n");
            report.push_str(&json);
            report.push('\n');
            return Ok(None);
        }
        let signed = self.key.sign(tx.unsigned, tx.inputs, vec![], state)?;
        let id = local_wallet::broadcast(&self.broadcast, &signed).await?;
        report.push_str(&format!("submitted transaction {id}\n"));
        Ok(Some(id))
    }

    /// `mint-nft`: mint the tracker NFT into a box at the tracker address.
    pub async fn mint_nft(
        &self,
        name: &str,
        description: &str,
        dry_run: bool,
    ) -> Result<String, String> {
        // Validate the registers before touching the node.
        nft_register_hex(name, description)?;
        let state = local_wallet::fetch_state_context(&self.scanner).await?;
        let height = state.pre_header.height;
        let owner_tree = self.owner_tree()?;
        let inputs = self.fund(NFT_BOX_VALUE + FEE, &[]).await?;
        let (tx, nft_id) = build_mint_tx(inputs, &owner_tree, name, description, height)?;
        check_before_signing(&tx, &nft_id, true)?;

        let mut report = format!(
            "mint-nft at height {height} from {}\nNFT id: {nft_id}\n",
            self.address()?
        );
        report.push_str(&describe(&tx, &owner_tree)?);
        if self
            .sign_and_submit(tx, &state, dry_run, &mut report)
            .await?
            .is_some()
        {
            report.push_str(&format!(
                "next: wait for a confirmation, then run `basis_bootstrap init-box --nft {nft_id}` \
                 and set ergo.tracker_nft_id = \"{nft_id}\"\n"
            ));
        }
        Ok(report)
    }

    /// `init-box`: turn the box holding the NFT into the tracker box.
    pub async fn init_box(
        &self,
        nft_id: &str,
        value: u64,
        dry_run: bool,
    ) -> Result<String, String> {
        let nft_id = hex::encode(parse_id("--nft", nft_id)?);
        let owner_tree = self.owner_tree()?;

        // The tracker NFT must be a single token: anyone holding a second one could pose as
        // the tracker box.
        let (status, text) = self
            .scanner
            .get(&format!("/blockchain/token/byId/{nft_id}"))
            .await?;
        if status == 404 {
            return Err(format!(
                "the node does not know token {nft_id} (is the mint confirmed?)"
            ));
        }
        if !(200..300).contains(&status) {
            return Err(format!(
                "GET /blockchain/token/byId/{nft_id} HTTP {status}: {text}"
            ));
        }
        let token: Value =
            serde_json::from_str(&text).map_err(|e| format!("parse token {nft_id}: {e}"))?;
        match token["emissionAmount"].as_u64() {
            Some(1) => {}
            other => {
                let amount = other.map_or("unknown".to_string(), |n| n.to_string());
                return Err(format!(
                    "token {nft_id} has emission amount {amount}; the tracker NFT must be a \
                     single token (emission 1)"
                ));
            }
        }

        let (status, text) = self
            .scanner
            .get(&format!(
                "/blockchain/box/unspent/byTokenId/{nft_id}?offset=0&limit=5"
            ))
            .await?;
        let holders: Vec<UnspentBox> = match status {
            404 => Vec::new(),
            200..=299 => serde_json::from_str(&text)
                .map_err(|e| format!("parse boxes holding {nft_id}: {e}"))?,
            _ => {
                return Err(format!(
                    "GET /blockchain/box/unspent/byTokenId/{nft_id} HTTP {status}: {text}"
                ))
            }
        };
        let holders: Vec<&UnspentBox> = holders
            .iter()
            .filter(|b| {
                b.assets
                    .iter()
                    .any(|a| a.token_id.eq_ignore_ascii_case(&nft_id))
            })
            .collect();
        let holder = match holders.as_slice() {
            [one] => *one,
            [] => {
                return Err(format!(
                    "no unspent box holds token {nft_id} (mint not confirmed yet, or spent)"
                ))
            }
            many => {
                return Err(format!(
                    "{} unspent boxes hold token {nft_id}; expected exactly one",
                    many.len()
                ))
            }
        };
        let nft_box = local_wallet::fetch_box(&self.scanner, &holder.box_id).await?;
        check_nft_box(&nft_box, &owner_tree, &nft_id)?;

        let state = local_wallet::fetch_state_context(&self.scanner).await?;
        let height = state.pre_header.height;
        let need = value
            .checked_add(FEE)
            .ok_or("value overflow")?
            .saturating_sub(*nft_box.value.as_u64());
        let fee_boxes = if need > 0 {
            self.fund(need, &[holder.box_id.as_str()]).await?
        } else {
            Vec::new()
        };
        let tx = build_init_tx(
            nft_box,
            fee_boxes,
            &owner_tree,
            &self.key.public_key(),
            &nft_id,
            value,
            height,
        )?;
        check_before_signing(&tx, &nft_id, false)?;

        let mut report = format!(
            "init-box at height {height} for {}\nNFT id: {nft_id}\n",
            self.address()?
        );
        report.push_str(&describe(&tx, &owner_tree)?);
        if self
            .sign_and_submit(tx, &state, dry_run, &mut report)
            .await?
            .is_some()
        {
            report.push_str(&format!(
                "next: set ergo.tracker_nft_id = \"{nft_id}\" and ergo.tracker_public_key = \
                 \"{}\", then start basis_server\n",
                hex::encode(self.key.public_key())
            ));
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
