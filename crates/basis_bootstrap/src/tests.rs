//! Tests use fixtures only: freshly generated keys, boxes built in memory, the node's
//! recorded `lastHeaders` response, and a mock node on 127.0.0.1.

use super::*;
use ergo_lib::chain::transaction::TxId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LAST_HEADERS_JSON: &str = include_str!(
    "../../../scala/src/test/resources/mockwebserver/node_responses/response_LastHeaders.json"
);
/// Height of the newest fixture header: outputs are created at this height.
const TIP: u32 = 123_414;

fn fixture_state() -> ErgoStateContext {
    let headers = serde_json::from_str(LAST_HEADERS_JSON).unwrap();
    local_wallet::state_context_from_headers(headers).unwrap()
}

fn fresh_key() -> ([u8; 32], TrackerKey) {
    let (secret, _) = basis_store::schnorr::generate_keypair();
    (secret, TrackerKey::from_secret_bytes(&secret).unwrap())
}

fn tree_of(pubkey: &[u8; 33]) -> ErgoTree {
    let hex_tree = local_wallet::p2pk_tree_hex(pubkey);
    ErgoTree::sigma_parse_bytes(&hex::decode(hex_tree).unwrap()).unwrap()
}

/// A box as the UTXO set would hold it; `index` keeps ids distinct.
fn utxo_box(
    tree: &ErgoTree,
    value: u64,
    tokens: &[([u8; 32], u64)],
    registers_hex: &[String],
    index: u16,
) -> ErgoBox {
    let tokens = (!tokens.is_empty()).then(|| {
        BoxTokens::from_vec(
            tokens
                .iter()
                .map(|(id, amount)| Token {
                    token_id: TokenId::from_str(&hex::encode(id)).unwrap(),
                    amount: TokenAmount::try_from(*amount).unwrap(),
                })
                .collect(),
        )
        .unwrap()
    });
    ErgoBox::new(
        BoxValue::try_from(value).unwrap(),
        tree.clone(),
        tokens,
        registers_from_hex(registers_hex).unwrap(),
        123_000,
        TxId::zero(),
        index,
    )
    .unwrap()
}

fn output_values(tx: &BuiltTx) -> Vec<u64> {
    tx.unsigned
        .output_candidates
        .iter()
        .map(|o| *o.value.as_u64())
        .collect()
}

fn output_registers(tx: &BuiltTx, index: usize) -> Vec<String> {
    let output = &tx.unsigned.output_candidates.as_vec()[index];
    REGISTER_IDS
        .iter()
        .filter_map(|r| output.additional_registers.get_constant(*r).unwrap())
        .map(|c| constant_hex(&c).unwrap())
        .collect()
}

fn output_tokens(tx: &BuiltTx, index: usize) -> Vec<(String, u64)> {
    let output = &tx.unsigned.output_candidates.as_vec()[index];
    output
        .tokens
        .iter()
        .flat_map(|t| t.iter())
        .map(|t| (String::from(t.token_id), u64::from(t.amount)))
        .collect()
}

const NFT: [u8; 32] = [0x5a; 32];

fn nft_box(tree: &ErgoTree, extra_tokens: &[([u8; 32], u64)], registers: &[String]) -> ErgoBox {
    let mut tokens = vec![(NFT, 1)];
    tokens.extend_from_slice(extra_tokens);
    utxo_box(tree, NFT_BOX_VALUE, &tokens, registers, 7)
}

fn eip4() -> Vec<String> {
    nft_register_hex(DEFAULT_NFT_NAME, DEFAULT_NFT_DESCRIPTION)
        .unwrap()
        .to_vec()
}

#[test]
fn registers_have_the_exact_encoding() {
    // Coll[Byte]: 0e ‖ VLQ(length) ‖ bytes.
    assert_eq!(
        coll_byte_hex(b"Basis Tracker").unwrap(),
        format!("0e0d{}", hex::encode("Basis Tracker"))
    );
    assert!(coll_byte_hex(&[0x61; 200]).unwrap().starts_with("0ec801"));

    let [r4, r5, r6] = nft_register_hex("Basis Tracker", "Basis tracker NFT").unwrap();
    assert_eq!(r4, format!("0e0d{}", hex::encode("Basis Tracker")));
    assert_eq!(r5, format!("0e11{}", hex::encode("Basis tracker NFT")));
    assert_eq!(r6, "0e0130");
    assert!(nft_register_hex("  ", "x").is_err());
    // UTF-8 is kept as is.
    let [r4, _, _] = nft_register_hex("Трекер", "").unwrap();
    assert_eq!(r4, format!("0e0c{}", hex::encode("Трекер")));

    let (_, key) = fresh_key();
    let pk = key.public_key();
    let [r4, r5, r6] = tracker_register_hex(&pk, &NFT);
    assert_eq!(r4, format!("07{}", hex::encode(pk)));
    assert_eq!(
        r5,
        "644ec61f485b98eb87153f7c57db4f5ecd75556fddbc403b41acf8441fde8e160900032000"
    );
    assert_eq!(r6, format!("0e20{}", hex::encode(NFT)));

    // R5 is the empty tree the tracker and the scanners start from.
    assert_eq!(
        EMPTY_TREE_R5_HEX,
        basis_store::ergo_scanner::empty_reserve_tree_register()
    );
    // The registers parse to the types the contracts read.
    assert_eq!(constant_from_hex(&r4).unwrap().tpe, SType::SGroupElement);
    assert_eq!(constant_from_hex(&r5).unwrap().tpe, SType::SAvlTree);
    assert_eq!(
        constant_from_hex(&r6).unwrap().tpe,
        SType::SColl(SType::SByte.into())
    );
}

#[test]
fn mint_tx_mints_from_the_first_input_and_signs() {
    let (_, key) = fresh_key();
    let tree = tree_of(&key.public_key());
    let inputs = vec![
        utxo_box(&tree, 3_000_000, &[], &[], 1),
        utxo_box(&tree, 500_000, &[], &[], 2),
    ];
    let first_id = String::from(inputs[0].box_id());
    let (tx, nft_id) = build_mint_tx(
        inputs,
        &tree,
        DEFAULT_NFT_NAME,
        DEFAULT_NFT_DESCRIPTION,
        TIP,
    )
    .unwrap();
    assert_eq!(nft_id, first_id);
    assert_eq!(
        output_values(&tx),
        vec![NFT_BOX_VALUE, FEE, 3_500_000 - NFT_BOX_VALUE - FEE]
    );
    assert_eq!(output_tokens(&tx, 0), vec![(nft_id.clone(), 1)]);
    assert_eq!(output_registers(&tx, 0), eip4());
    let outputs = tx.unsigned.output_candidates.as_vec();
    assert_eq!(outputs[0].ergo_tree, tree);
    assert_eq!(outputs[2].ergo_tree, tree);
    assert!(outputs[1].tokens.is_none() && outputs[2].tokens.is_none());
    assert!(outputs.iter().all(|o| o.creation_height == TIP));
    check_before_signing(&tx, &nft_id, true).unwrap();

    let signed = key
        .sign(tx.unsigned, tx.inputs, vec![], &fixture_state())
        .unwrap();
    let minted = signed
        .outputs
        .first()
        .tokens
        .as_ref()
        .unwrap()
        .first()
        .token_id;
    assert_eq!(String::from(minted), first_id);
}

#[test]
fn mint_tx_folds_dust_and_refuses_bad_inputs() {
    let (_, key) = fresh_key();
    let tree = tree_of(&key.public_key());
    let mint = |inputs: Vec<ErgoBox>, description: &str| {
        build_mint_tx(inputs, &tree, DEFAULT_NFT_NAME, description, TIP)
    };

    // A leftover too small for a box goes to the miner.
    let (tx, nft_id) = mint(
        vec![utxo_box(&tree, NFT_BOX_VALUE + FEE + 5, &[], &[], 1)],
        DEFAULT_NFT_DESCRIPTION,
    )
    .unwrap();
    assert_eq!(output_values(&tx), vec![NFT_BOX_VALUE, FEE + 5]);
    assert_eq!((tx.fee, tx.change), (FEE + 5, 0));
    check_before_signing(&tx, &nft_id, true).unwrap();
    key.sign(tx.unsigned, tx.inputs, vec![], &fixture_state())
        .unwrap();

    let err = |r: Result<(BuiltTx, String), String>| r.unwrap_err();
    let token_box = utxo_box(&tree, 5_000_000, &[([0x77; 32], 3)], &[], 1);
    assert!(err(mint(vec![token_box], "")).contains("unrelated token"));
    let (_, other) = fresh_key();
    let foreign = utxo_box(&tree_of(&other.public_key()), 5_000_000, &[], &[], 1);
    assert!(err(mint(vec![foreign], "")).contains("not locked by P2PK"));
    let short = utxo_box(&tree, NFT_BOX_VALUE + FEE - 1, &[], &[], 1);
    assert!(err(mint(vec![short], "")).contains("needs"));
    assert!(err(mint(vec![], "")).contains("no input"));
    let big = utxo_box(&tree, 50_000_000, &[], &[], 1);
    assert!(err(mint(vec![big], &"x".repeat(3_000))).contains("shorter"));
}

#[test]
fn init_tx_builds_the_tracker_box_and_signs() {
    let (_, key) = fresh_key();
    let pk = key.public_key();
    let tree = tree_of(&pk);
    let nft_hex = hex::encode(NFT);
    let tx = build_init_tx(
        nft_box(&tree, &[], &eip4()),
        vec![utxo_box(&tree, 5_000_000, &[], &[], 1)],
        &tree,
        &pk,
        &nft_hex,
        DEFAULT_TRACKER_BOX_VALUE,
        TIP,
    )
    .unwrap();
    // NFT box 1_000_000 + fee box 5_000_000 in; tracker box, fee and change out.
    assert_eq!(
        output_values(&tx),
        vec![DEFAULT_TRACKER_BOX_VALUE, FEE, 4_000_000]
    );
    assert_eq!(output_tokens(&tx, 0), vec![(nft_hex.clone(), 1)]);
    assert_eq!(
        output_registers(&tx, 0),
        tracker_register_hex(&pk, &NFT).to_vec()
    );
    assert_eq!(tx.unsigned.output_candidates.as_vec()[0].ergo_tree, tree);
    check_before_signing(&tx, &nft_hex, false).unwrap();
    key.sign(tx.unsigned, tx.inputs, vec![], &fixture_state())
        .unwrap();

    // Without fee boxes the NFT box value has to cover the tracker box and the fee.
    let tx = build_init_tx(
        utxo_box(&tree, 2_000_000, &[(NFT, 1)], &eip4(), 7),
        vec![],
        &tree,
        &pk,
        &nft_hex,
        DEFAULT_TRACKER_BOX_VALUE,
        TIP,
    )
    .unwrap();
    assert_eq!(output_values(&tx), vec![DEFAULT_TRACKER_BOX_VALUE, FEE]);
}

#[test]
fn init_tx_refuses_unrelated_tokens_foreign_boxes_and_existing_tracker_boxes() {
    let (_, key) = fresh_key();
    let pk = key.public_key();
    let tree = tree_of(&pk);
    let nft_hex = hex::encode(NFT);
    let fee_box = || utxo_box(&tree, 5_000_000, &[], &[], 1);
    let init = |nft_box: ErgoBox, fee_boxes: Vec<ErgoBox>, value: u64| {
        build_init_tx(nft_box, fee_boxes, &tree, &pk, &nft_hex, value, TIP).unwrap_err()
    };

    let with_extra = nft_box(&tree, &[([0x66; 32], 10)], &eip4());
    assert!(init(with_extra, vec![fee_box()], 1_000_000).contains("unrelated tokens"));

    let (_, other) = fresh_key();
    let foreign = nft_box(&tree_of(&other.public_key()), &[], &eip4());
    assert!(init(foreign, vec![fee_box()], 1_000_000).contains("not locked by P2PK"));

    let tracker = nft_box(&tree, &[], &tracker_register_hex(&pk, &NFT));
    assert!(init(tracker, vec![fee_box()], 1_000_000).contains("already is a tracker box"));

    let without_nft = utxo_box(&tree, 1_000_000, &[([0x66; 32], 1)], &[], 7);
    assert!(init(without_nft, vec![fee_box()], 1_000_000).contains("does not hold"));

    let token_fee_box = utxo_box(&tree, 5_000_000, &[([0x66; 32], 1)], &[], 1);
    assert!(
        init(nft_box(&tree, &[], &eip4()), vec![token_fee_box], 1_000_000)
            .contains("unrelated token")
    );

    assert!(init(nft_box(&tree, &[], &eip4()), vec![fee_box()], 1_000).contains("minimum"));
    assert!(build_init_tx(
        nft_box(&tree, &[], &eip4()),
        vec![fee_box()],
        &tree,
        &pk,
        "zz",
        1_000_000,
        TIP
    )
    .unwrap_err()
    .contains("64 hex"));
}

#[test]
fn pre_signing_checks_catch_burns_moves_and_unbalanced_erg() {
    use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
    let (_, key) = fresh_key();
    let pk = key.public_key();
    let tree = tree_of(&pk);
    let nft_hex = hex::encode(NFT);
    let tx = build_init_tx(
        nft_box(&tree, &[], &eip4()),
        vec![utxo_box(&tree, 5_000_000, &[], &[], 1)],
        &tree,
        &pk,
        &nft_hex,
        DEFAULT_TRACKER_BOX_VALUE,
        TIP,
    )
    .unwrap();
    let edited = |edit: &dyn Fn(&mut Vec<ErgoBoxCandidate>)| {
        let mut outputs = tx.unsigned.output_candidates.as_vec().clone();
        edit(&mut outputs);
        BuiltTx {
            unsigned: UnsignedTransaction::new_from_vec(
                tx.unsigned.inputs.as_vec().clone(),
                vec![],
                outputs,
            )
            .unwrap(),
            ..tx.clone()
        }
    };
    let nft_token = || single_token(TokenId::from_str(&nft_hex).unwrap()).unwrap();

    // The NFT moved to the change output.
    let moved = edited(&|o| {
        o[0].tokens = None;
        o[2].tokens = Some(nft_token());
    });
    assert!(check_before_signing(&moved, &nft_hex, false)
        .unwrap_err()
        .contains("must appear once"));
    // The NFT burned.
    let burned = edited(&|o| o[0].tokens = None);
    assert!(check_before_signing(&burned, &nft_hex, false)
        .unwrap_err()
        .contains("would be burned"));
    // init-box never mints: a second copy of the NFT is refused.
    let minted = edited(&|o| o[2].tokens = Some(nft_token()));
    assert!(check_before_signing(&minted, &nft_hex, false).is_err());
    // ERG out must equal ERG in.
    let unbalanced = edited(&|o| o[2].value = BoxValue::try_from(3_000_000u64).unwrap());
    assert!(check_before_signing(&unbalanced, &nft_hex, false)
        .unwrap_err()
        .contains("ERG not preserved"));
}

/// A request the mock node received.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    raw: String,
}

/// Minimal HTTP/1.1 server on 127.0.0.1 that answers with `respond(method, target, body)`.
async fn mock_node(
    respond: impl Fn(&str, &str, &str) -> (u16, String) + Send + Sync + 'static,
) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let (seen_task, respond) = (seen.clone(), Arc::new(respond));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let (seen, respond) = (seen_task.clone(), respond.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let header_end = loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let length = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + length {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let body = String::from_utf8_lossy(&buf[header_end..]).to_string();
                let mut line = head.lines().next().unwrap_or("").split_whitespace();
                let method = line.next().unwrap_or("").to_string();
                let target = line.next().unwrap_or("").to_string();
                let (status, payload) = respond(&method, &target, &body);
                seen.lock().unwrap().push(Seen {
                    method,
                    target,
                    raw: format!("{head}{body}"),
                });
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (url, seen)
}

/// The `IndexedErgoBox` JSON the node returns for `b`.
fn box_json(b: &ErgoBox) -> Value {
    let registers: serde_json::Map<String, Value> = REGISTER_IDS
        .iter()
        .filter_map(|r| {
            let c = b.additional_registers.get_constant(*r).unwrap()?;
            Some((format!("{r:?}"), Value::String(constant_hex(&c).unwrap())))
        })
        .collect();
    serde_json::json!({
        "boxId": String::from(b.box_id()),
        "value": b.value.as_u64(),
        "ergoTree": hex::encode(b.ergo_tree.sigma_serialize_bytes().unwrap()),
        "assets": tokens_of(b)
            .into_iter()
            .map(|(t, a)| serde_json::json!({ "tokenId": t, "amount": a }))
            .collect::<Vec<_>>(),
        "additionalRegisters": registers,
        "creationHeight": b.creation_height,
    })
}

/// A mock node holding `boxes` at the tracker address (`by_address`) and in the UTXO set,
/// answering token queries for [`NFT`] with `emission`, and accepting any transaction.
async fn node_with(
    by_address: Vec<ErgoBox>,
    nft_holder: Option<ErgoBox>,
    emission: u64,
) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let utxo: HashMap<String, ErgoBox> = by_address
        .iter()
        .chain(nft_holder.iter())
        .map(|b| (String::from(b.box_id()), b.clone()))
        .collect();
    let nft_hex = hex::encode(NFT);
    mock_node(move |method, target, body| {
        let path = target.split('?').next().unwrap_or("");
        if path == "/blocks/lastHeaders/10" {
            return (200, LAST_HEADERS_JSON.to_string());
        }
        if method == "POST" && path == "/blockchain/box/unspent/byAddress" {
            let first_page = target.contains("offset=0&");
            let page: Vec<Value> = if first_page {
                by_address.iter().map(box_json).collect()
            } else {
                Vec::new()
            };
            return (200, Value::Array(page).to_string());
        }
        if let Some(id) = path.strip_prefix("/utxo/byIdBinary/") {
            return match utxo.get(id) {
                Some(b) => (
                    200,
                    serde_json::json!({
                        "boxId": id,
                        "bytes": hex::encode(b.sigma_serialize_bytes().unwrap()),
                    })
                    .to_string(),
                ),
                None => (404, "{}".to_string()),
            };
        }
        if path == format!("/blockchain/token/byId/{nft_hex}") {
            return (
                200,
                serde_json::json!({ "id": nft_hex, "emissionAmount": emission, "decimals": 0 })
                    .to_string(),
            );
        }
        if path == format!("/blockchain/box/unspent/byTokenId/{nft_hex}") {
            let holders: Vec<Value> = nft_holder.iter().map(box_json).collect();
            return (200, Value::Array(holders).to_string());
        }
        if method == "POST" && path == "/transactions" {
            let tx: Value = serde_json::from_str(body).unwrap();
            return (200, format!("\"{}\"", tx["id"].as_str().unwrap()));
        }
        (404, "{}".to_string())
    })
    .await
}

fn bootstrap(key: TrackerKey, url: &str) -> Bootstrap {
    Bootstrap {
        key,
        scanner: NodeEndpoint::new(url, None),
        broadcast: NodeEndpoint::new(url, None),
    }
}

/// Only the public endpoints of the brief, and never the secret.
fn assert_public_only(seen: &[Seen], secret: &[u8; 32]) {
    let allowed = [
        "/blocks/lastHeaders/",
        "/blockchain/",
        "/utxo/",
        "/transactions",
    ];
    for r in seen {
        assert!(
            allowed.iter().any(|p| r.target.starts_with(p)),
            "unexpected endpoint {} {}",
            r.method,
            r.target
        );
        assert!(!r.raw.contains(&hex::encode(secret)), "secret sent");
        assert!(!r.raw.to_ascii_lowercase().contains("api_key"));
    }
}

#[tokio::test]
async fn mint_dry_run_prints_the_transaction_and_sends_nothing() {
    let (secret, key) = fresh_key();
    let tree = tree_of(&key.public_key());
    let foreign_token_box = utxo_box(&tree, 9_000_000, &[([0x44; 32], 1)], &[], 3);
    let fee_box = utxo_box(&tree, 3_000_000, &[], &[], 1);
    let fee_id = String::from(fee_box.box_id());
    let (url, seen) = node_with(vec![foreign_token_box, fee_box], None, 1).await;

    let report = bootstrap(key, &url)
        .mint_nft(DEFAULT_NFT_NAME, DEFAULT_NFT_DESCRIPTION, true)
        .await
        .unwrap();
    assert!(report.contains(&format!("NFT id: {fee_id}")), "{report}");
    for r in eip4() {
        assert!(report.contains(&format!("= {r}")), "{report}");
    }
    assert!(report.contains("dry run: not signed, not submitted"));
    assert!(report.contains("\"outputs\""), "unsigned JSON printed");

    let seen = seen.lock().unwrap().clone();
    assert!(seen.iter().all(|r| r.target != "/transactions"));
    // The box holding a foreign token is never fetched for spending.
    assert!(seen
        .iter()
        .filter(|r| r.target.starts_with("/utxo/byIdBinary/"))
        .all(|r| r.target.ends_with(&fee_id)));
    let scan = seen
        .iter()
        .find(|r| r.target.starts_with("/blockchain/box/unspent/byAddress"))
        .unwrap();
    assert!(scan.target.contains("excludeMempoolSpent=true"));
    assert_public_only(&seen, &secret);
}

#[tokio::test]
async fn mint_signs_locally_and_submits() {
    let (secret, key) = fresh_key();
    let tree = tree_of(&key.public_key());
    let fee_box = utxo_box(&tree, 3_000_000, &[], &[], 1);
    let fee_id = String::from(fee_box.box_id());
    let (url, seen) = node_with(vec![fee_box], None, 1).await;

    let report = bootstrap(key, &url)
        .mint_nft("Tracker", "Test", false)
        .await
        .unwrap();
    assert!(report.contains("submitted transaction"), "{report}");
    assert!(report.contains(&format!("init-box --nft {fee_id}")));

    let seen = seen.lock().unwrap().clone();
    let post = seen.iter().find(|r| r.target == "/transactions").unwrap();
    let body = post.raw.split("\r\n\r\n").nth(1).unwrap();
    let tx: Value = serde_json::from_str(body).unwrap();
    assert_eq!(tx["inputs"][0]["boxId"], fee_id.as_str());
    assert_eq!(tx["outputs"][0]["assets"][0]["tokenId"], fee_id.as_str());
    assert_eq!(tx["outputs"][0]["assets"][0]["amount"], 1);
    assert_eq!(tx["outputs"][0]["additionalRegisters"]["R6"], "0e0130");
    assert_public_only(&seen, &secret);
}

#[tokio::test]
async fn init_box_signs_locally_and_submits() {
    let (secret, key) = fresh_key();
    let pk = key.public_key();
    let tree = tree_of(&pk);
    let holder = nft_box(&tree, &[], &eip4());
    let holder_id = String::from(holder.box_id());
    let fee_box = utxo_box(&tree, 3_000_000, &[], &[], 1);
    let (url, seen) = node_with(vec![fee_box], Some(holder), 1).await;

    let report = bootstrap(key, &url)
        .init_box(&hex::encode(NFT), DEFAULT_TRACKER_BOX_VALUE, false)
        .await
        .unwrap();
    assert!(report.contains("submitted transaction"), "{report}");

    let seen = seen.lock().unwrap().clone();
    let post = seen.iter().find(|r| r.target == "/transactions").unwrap();
    let body = post.raw.split("\r\n\r\n").nth(1).unwrap();
    let tx: Value = serde_json::from_str(body).unwrap();
    assert_eq!(tx["inputs"][0]["boxId"], holder_id.as_str());
    let out0 = &tx["outputs"][0];
    assert_eq!(out0["assets"][0]["tokenId"], hex::encode(NFT).as_str());
    let [r4, r5, r6] = tracker_register_hex(&pk, &NFT);
    assert_eq!(out0["additionalRegisters"]["R4"], r4.as_str());
    assert_eq!(out0["additionalRegisters"]["R5"], r5.as_str());
    assert_eq!(out0["additionalRegisters"]["R6"], r6.as_str());
    assert_eq!(out0["value"], DEFAULT_TRACKER_BOX_VALUE);
    assert_public_only(&seen, &secret);
}

#[tokio::test]
async fn init_box_requires_a_single_token_nft() {
    let (_, key) = fresh_key();
    let tree = tree_of(&key.public_key());
    let holder = nft_box(&tree, &[], &eip4());
    let (url, seen) = node_with(vec![], Some(holder), 1_000).await;
    let err = bootstrap(key, &url)
        .init_box(&hex::encode(NFT), DEFAULT_TRACKER_BOX_VALUE, false)
        .await
        .unwrap_err();
    assert!(err.contains("emission amount 1000"), "{err}");
    assert!(seen
        .lock()
        .unwrap()
        .iter()
        .all(|r| r.target != "/transactions"));
}
