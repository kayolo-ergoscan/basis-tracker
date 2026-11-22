//! Keyless access to the tracker's own coins.
//!
//! The tracker never uses a node wallet or the node API key for its own transactions.
//! Spendable boxes come from the public extra-index endpoint
//! `POST /blockchain/box/unspent/byAddress` (with `excludeMempoolSpent=true`), and boxes that
//! hold any token are never used to pay fees: the tracker box with the tracker NFT lives at the
//! same P2PK address, and spending it as a fee input once burned an NFT on mainnet.

use std::collections::{HashMap, HashSet};

use ergo_lib::chain::ergo_state_context::ErgoStateContext;
use ergo_lib::chain::parameters::Parameters;
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::Transaction;
use ergo_lib::ergo_chain_types::{Header, PreHeader};
use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use ergo_lib::wallet::secret_key::SecretKey;
use ergo_lib::wallet::signing::TransactionContext;
use ergo_lib::wallet::Wallet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Page size for `POST /blockchain/box/unspent/byAddress`. The node defaults to 5 boxes
/// when no limit is given. Every page goes through `read_body_capped` (2 MiB), and 100
/// maximum-size boxes still fit (the reserve scanner uses the same page size).
pub const BY_ADDRESS_PAGE_LIMIT: u64 = 100;

/// Hard cap on the pages one scan reads. Anyone can send boxes to the tracker address, so a
/// scan must stay bounded; the cap is far above what an operator-funded address holds.
pub const BY_ADDRESS_MAX_PAGES: u64 = 50;

/// One Ergo node. `api_key` is forwarded only when an operator configured one; none of the
/// endpoints used by the tracker for its own transactions need it.
#[derive(Clone)]
pub struct NodeEndpoint {
    url: String,
    api_key: Option<String>,
}

impl std::fmt::Debug for NodeEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeEndpoint")
            .field("url", &self.url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl NodeEndpoint {
    /// A node at `url` (a trailing `/` is ignored). An empty `api_key` counts as none.
    pub fn new(url: &str, api_key: Option<String>) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            api_key: api_key.filter(|k| !k.is_empty()),
        }
    }

    /// Base URL without a trailing `/`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// `GET {url}{path}`; returns the status code and the (size-capped) body.
    pub async fn get(&self, path: &str) -> Result<(u16, String), String> {
        let url = format!("{}{}", self.url, path);
        let client = basis_store::http::bounded_client();
        let mut request = client.get(&url);
        if let Some(ref key) = self.api_key {
            request = request.header("api_key", key);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        let status = response.status().as_u16();
        let body = basis_store::http::read_body_capped(response)
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        Ok((status, body))
    }

    /// `POST {url}{path}?{query}` with a JSON body; returns the status code and the body.
    pub async fn post_json(
        &self,
        path: &str,
        query: &[(&str, String)],
        body: &Value,
    ) -> Result<(u16, String), String> {
        let url = format!("{}{}", self.url, path);
        let client = basis_store::http::bounded_client();
        let mut request = client.post(&url).query(query).json(body);
        if let Some(ref key) = self.api_key {
            request = request.header("api_key", key);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("POST {url}: {e}"))?;
        let status = response.status().as_u16();
        let body = basis_store::http::read_body_capped(response)
            .await
            .map_err(|e| format!("POST {url}: {e}"))?;
        Ok((status, body))
    }
}

/// A token in an [`UnspentBox`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnspentAsset {
    pub token_id: String,
    pub amount: u64,
}

/// The fields the tracker reads from an `IndexedErgoBox` returned by
/// `/blockchain/box/unspent/*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnspentBox {
    pub box_id: String,
    pub value: u64,
    pub ergo_tree: String,
    #[serde(default)]
    pub assets: Vec<UnspentAsset>,
    #[serde(default)]
    pub additional_registers: HashMap<String, String>,
    #[serde(default)]
    pub creation_height: u32,
}

/// Hex ErgoTree of `P2PK(pubkey)`: `00 08 cd ‖ pubkey`.
pub fn p2pk_tree_hex(pubkey: &[u8; 33]) -> String {
    format!("0008cd{}", hex::encode(pubkey))
}

/// Mainnet P2PK address of a compressed public key.
pub fn p2pk_address(pubkey: &[u8; 33]) -> Result<String, String> {
    basis_offchain::ergo_tx::pubkey_to_address(&hex::encode(pubkey))
}

/// What a scan of the tracker address found.
#[derive(Debug, Default, Clone)]
pub struct FeeBoxScan {
    /// Token-free boxes locked by the tracker key, in node order (newest first).
    pub boxes: Vec<UnspentBox>,
    /// Boxes skipped because they hold a token (the tracker box is one of them).
    pub skipped_with_tokens: usize,
    /// Boxes skipped for another reason: an excluded id or a different script.
    pub skipped_other: usize,
    /// True when [`BY_ADDRESS_MAX_PAGES`] stopped the scan before the address was exhausted.
    pub truncated: bool,
}

impl FeeBoxScan {
    /// Total value of the usable boxes.
    pub fn total(&self) -> u64 {
        self.boxes
            .iter()
            .fold(0u64, |acc, b| acc.saturating_add(b.value))
    }
}

/// Whether `b` may pay a fee: it holds no token, it is locked by exactly `owner_tree_hex`
/// (so the tracker key can sign it), and it is not one of `exclude_box_ids`.
pub fn is_fee_box(b: &UnspentBox, owner_tree_hex: &str, exclude_box_ids: &[&str]) -> bool {
    b.assets.is_empty()
        && b.ergo_tree.eq_ignore_ascii_case(owner_tree_hex)
        && !exclude_box_ids
            .iter()
            .any(|id| id.eq_ignore_ascii_case(&b.box_id))
}

/// Find fee boxes at `address` through `POST /blockchain/box/unspent/byAddress` on `node`.
///
/// Boxes already spent by a mempool transaction are skipped (`excludeMempoolSpent=true`), and
/// unconfirmed boxes are not offered (`includeUnconfirmed` keeps its default, false). Pages
/// of [`BY_ADDRESS_PAGE_LIMIT`] are read, newest boxes first, until a page comes back empty,
/// the usable boxes add up to `enough`, or [`BY_ADDRESS_MAX_PAGES`] pages were read. Only
/// boxes accepted by [`is_fee_box`] are returned.
pub async fn scan_fee_boxes(
    node: &NodeEndpoint,
    address: &str,
    owner_tree_hex: &str,
    exclude_box_ids: &[&str],
    enough: u64,
) -> Result<FeeBoxScan, String> {
    let mut scan = FeeBoxScan::default();
    let mut seen: HashSet<String> = HashSet::new();
    let body = Value::String(address.to_string());

    for page in 0..BY_ADDRESS_MAX_PAGES {
        let offset = page * BY_ADDRESS_PAGE_LIMIT;
        let query = [
            ("offset", offset.to_string()),
            ("limit", BY_ADDRESS_PAGE_LIMIT.to_string()),
            ("excludeMempoolSpent", "true".to_string()),
        ];
        let (status, text) = node
            .post_json("/blockchain/box/unspent/byAddress", &query, &body)
            .await?;
        // The node answers 404 when it has no unspent box for the address.
        if status == 404 {
            return Ok(scan);
        }
        if !(200..300).contains(&status) {
            return Err(format!(
                "POST /blockchain/box/unspent/byAddress HTTP {status}: {text}"
            ));
        }
        let boxes: Vec<UnspentBox> = serde_json::from_str(&text)
            .map_err(|e| format!("parse /blockchain/box/unspent/byAddress page: {e}"))?;
        if boxes.is_empty() {
            return Ok(scan);
        }
        for b in boxes {
            // A box can show up on two pages when a block arrives between the requests.
            if !seen.insert(b.box_id.to_ascii_lowercase()) {
                continue;
            }
            if !b.assets.is_empty() {
                scan.skipped_with_tokens += 1;
            } else if is_fee_box(&b, owner_tree_hex, exclude_box_ids) {
                scan.boxes.push(b);
            } else {
                scan.skipped_other += 1;
            }
        }
        if scan.total() >= enough {
            return Ok(scan);
        }
    }
    scan.truncated = true;
    Ok(scan)
}

/// Pick token-free boxes covering `required`: the smallest single box that suffices, else the
/// smallest boxes in ascending order until they do. `None` when all of them together fall short.
/// Token-bearing boxes are never picked.
pub fn select_fee_boxes(boxes: &[UnspentBox], required: u64) -> Option<(Vec<UnspentBox>, u64)> {
    let mut candidates: Vec<&UnspentBox> = boxes.iter().filter(|b| b.assets.is_empty()).collect();
    candidates.sort_by_key(|b| b.value);

    if let Some(b) = candidates.iter().find(|b| b.value >= required) {
        return Some((vec![(*b).clone()], b.value));
    }
    let mut selected = Vec::new();
    let mut total = 0u64;
    for b in candidates {
        total = total.saturating_add(b.value);
        selected.push(b.clone());
        if total >= required {
            return Some((selected, total));
        }
    }
    None
}

/// Whether `s` is a 32-byte id in hex (box, token or transaction id).
pub fn is_hex_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Read one box from the node's UTXO set through `GET /utxo/byIdBinary/{box_id}` and parse it.
/// The box id computed from the returned bytes must equal `box_id`.
pub async fn fetch_box(node: &NodeEndpoint, box_id: &str) -> Result<ErgoBox, String> {
    if !is_hex_id(box_id) {
        return Err(format!("not a box id: {box_id:?}"));
    }
    let (status, text) = node.get(&format!("/utxo/byIdBinary/{box_id}")).await?;
    if status == 404 {
        return Err(format!(
            "box {box_id} is not in the node's UTXO set (spent or not confirmed yet)"
        ));
    }
    if !(200..300).contains(&status) {
        return Err(format!(
            "GET /utxo/byIdBinary/{box_id} HTTP {status}: {text}"
        ));
    }
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("parse /utxo/byIdBinary/{box_id}: {e}"))?;
    let bytes_hex = value["bytes"]
        .as_str()
        .ok_or_else(|| format!("/utxo/byIdBinary/{box_id}: no 'bytes' field"))?;
    let bytes = hex::decode(bytes_hex).map_err(|e| format!("box {box_id} bytes: {e}"))?;
    let ergo_box =
        ErgoBox::sigma_parse_bytes(&bytes).map_err(|e| format!("parse box {box_id}: {e}"))?;
    let parsed_id = String::from(ergo_box.box_id());
    if !parsed_id.eq_ignore_ascii_case(box_id) {
        return Err(format!(
            "node returned box {parsed_id} when asked for {box_id}"
        ));
    }
    Ok(ergo_box)
}

/// Signing context from the node's last 10 headers. `GET /blocks/lastHeaders/10` lists them
/// oldest first; the context wants the newest first, and its pre-header is the newest header
/// (so `pre_header.height` is the chain tip the outputs are created at).
pub fn state_context_from_headers(mut headers: Vec<Header>) -> Result<ErgoStateContext, String> {
    if headers.len() < 10 {
        return Err(format!("need 10 block headers, got {}", headers.len()));
    }
    headers.sort_by(|a, b| b.height.cmp(&a.height));
    headers.truncate(10);
    let pre_header = PreHeader::from(headers[0].clone());
    let headers: [Header; 10] = headers
        .try_into()
        .map_err(|_| "need exactly 10 block headers".to_string())?;
    Ok(ErgoStateContext::new(
        pre_header,
        headers,
        Parameters::default(),
    ))
}

/// [`state_context_from_headers`] over `GET /blocks/lastHeaders/10` on `node`.
pub async fn fetch_state_context(node: &NodeEndpoint) -> Result<ErgoStateContext, String> {
    let (status, text) = node.get("/blocks/lastHeaders/10").await?;
    if !(200..300).contains(&status) {
        return Err(format!("GET /blocks/lastHeaders/10 HTTP {status}: {text}"));
    }
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("parse last headers: {e}"))?;
    let headers: Vec<Header> =
        serde_json::from_value(value).map_err(|e| format!("parse last headers: {e}"))?;
    state_context_from_headers(headers)
}

/// The tracker's signing key, parsed from `ergo.tracker_secret_key`.
///
/// The scalar never leaves the process: it is only handed to the local prover. `Debug`
/// prints the public key alone, and no error message contains the secret.
#[derive(Clone)]
pub struct TrackerKey {
    secret: SecretKey,
    public: [u8; 33],
}

impl std::fmt::Debug for TrackerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackerKey")
            .field("public", &hex::encode(self.public))
            .finish_non_exhaustive()
    }
}

impl TrackerKey {
    /// Parse a 32-byte big-endian secp256k1 scalar. Zero and values at or above the group
    /// order are rejected.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, String> {
        let secret = SecretKey::dlog_from_bytes(bytes).ok_or_else(|| {
            "tracker secret key is not a valid secp256k1 scalar (it must be below the group order)"
                .to_string()
        })?;
        let public = match &secret {
            SecretKey::DlogSecretKey(dlog) => {
                if dlog.is_zero() {
                    return Err("tracker secret key is zero".to_string());
                }
                let encoded = dlog
                    .public_image()
                    .h
                    .sigma_serialize_bytes()
                    .map_err(|e| format!("encode tracker public key: {e}"))?;
                <[u8; 33]>::try_from(encoded.as_slice())
                    .map_err(|_| "tracker public key is not 33 bytes".to_string())?
            }
            _ => return Err("tracker secret key is not a dlog secret".to_string()),
        };
        Ok(Self { secret, public })
    }

    /// The compressed public key `sk·G`.
    pub fn public_key(&self) -> [u8; 33] {
        self.public
    }

    /// Hex ErgoTree of `P2PK(sk·G)`.
    pub fn p2pk_tree_hex(&self) -> String {
        p2pk_tree_hex(&self.public)
    }

    /// Prove every input of `unsigned` with this key, then validate the signed transaction
    /// against `state` (ERG and token preservation, dust, heights, every proof).
    ///
    /// `inputs` must be the boxes `unsigned` spends, in order. Every one of them must be locked by
    /// exactly `P2PK(sk·G)`: the tracker never signs anything else.
    pub fn sign(
        &self,
        unsigned: UnsignedTransaction,
        inputs: Vec<ErgoBox>,
        data_inputs: Vec<ErgoBox>,
        state: &ErgoStateContext,
    ) -> Result<Transaction, String> {
        let own_tree = hex::decode(self.p2pk_tree_hex()).map_err(|e| e.to_string())?;
        for (i, input) in inputs.iter().enumerate() {
            let tree = input
                .ergo_tree
                .sigma_serialize_bytes()
                .map_err(|e| format!("input {i} tree: {e}"))?;
            if tree != own_tree {
                return Err(format!(
                    "input {i} ({}) is not locked by P2PK(tracker key); refusing to sign",
                    String::from(input.box_id())
                ));
            }
        }
        let context = TransactionContext::new(unsigned, inputs.clone(), data_inputs.clone())
            .map_err(|e| format!("transaction context: {e}"))?;
        let wallet = Wallet::from_secrets(vec![self.secret.clone()]);
        let signed = wallet
            .sign_transaction(context, state, None)
            .map_err(|e| format!("local signing failed: {e}"))?;
        TransactionContext::new(signed.clone(), inputs, data_inputs)
            .map_err(|e| format!("transaction context: {e}"))?
            .validate(state)
            .map_err(|e| format!("signed transaction does not validate: {e}"))?;
        Ok(signed)
    }
}

/// Submit a signed transaction through `POST /transactions` and return its id.
pub async fn broadcast(node: &NodeEndpoint, tx: &Transaction) -> Result<String, String> {
    let local_id = String::from(tx.id());
    let body = serde_json::to_value(tx).map_err(|e| format!("encode transaction: {e}"))?;
    let (status, text) = node.post_json("/transactions", &[], &body).await?;
    if !(200..300).contains(&status) {
        return Err(format!("POST /transactions HTTP {status}: {text}"));
    }
    // The node answers with the id as a JSON string.
    let node_id = match serde_json::from_str::<Value>(&text) {
        Ok(Value::String(id)) => id,
        Ok(Value::Object(map)) => map
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        _ => text.trim().trim_matches('"').to_string(),
    };
    if !node_id.is_empty() && !node_id.eq_ignore_ascii_case(&local_id) {
        return Err(format!(
            "node accepted the transaction under id {node_id}, expected {local_id}"
        ));
    }
    Ok(local_id)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(crate) const PK: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    pub(crate) fn unspent(id: &str, value: u64, tree: &str, tokens: &[(&str, u64)]) -> UnspentBox {
        UnspentBox {
            box_id: id.to_string(),
            value,
            ergo_tree: tree.to_string(),
            assets: tokens
                .iter()
                .map(|(t, a)| UnspentAsset {
                    token_id: t.to_string(),
                    amount: *a,
                })
                .collect(),
            additional_registers: HashMap::new(),
            creation_height: 1_000,
        }
    }

    #[test]
    fn p2pk_tree_and_address_match_the_key() {
        let tree = p2pk_tree_hex(&PK);
        assert_eq!(
            tree,
            "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        let address = p2pk_address(&PK).unwrap();
        assert_eq!(
            basis_offchain::ergo_tx::address_to_ergo_tree(&address).unwrap(),
            tree
        );
    }

    #[test]
    fn fee_box_filter_rejects_tokens_other_scripts_and_excluded_ids() {
        let tree = p2pk_tree_hex(&PK);
        let free = unspent("aa", 5_000_000, &tree, &[]);
        let nft_box = unspent("bb", 1_000_000, &tree, &[("11", 1)]);
        let other_script = unspent("cc", 5_000_000, "0008cd03ff", &[]);
        assert!(is_fee_box(&free, &tree, &[]));
        assert!(is_fee_box(&free, &tree.to_uppercase(), &[]));
        assert!(!is_fee_box(&free, &tree, &["AA"]));
        assert!(!is_fee_box(&nft_box, &tree, &[]));
        assert!(!is_fee_box(&other_script, &tree, &[]));
    }

    #[test]
    fn selection_never_uses_token_boxes() {
        let tree = p2pk_tree_hex(&PK);
        // Only the token box could pay; selection must refuse rather than spend it.
        let boxes = vec![
            unspent("nft", 50_000_000, &tree, &[("11", 1)]),
            unspent("small", 100_000, &tree, &[]),
        ];
        assert!(select_fee_boxes(&boxes, 1_000_000).is_none());
    }

    #[test]
    fn selection_prefers_smallest_sufficient_then_accumulates() {
        let tree = p2pk_tree_hex(&PK);
        let boxes = vec![
            unspent("big", 50_000_000, &tree, &[]),
            unspent("mid", 2_000_000, &tree, &[]),
            unspent("small", 500_000, &tree, &[]),
        ];
        let (picked, total) = select_fee_boxes(&boxes, 1_000_000).unwrap();
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].box_id, "mid");
        assert_eq!(total, 2_000_000);

        let small = vec![
            unspent("a", 400_000, &tree, &[]),
            unspent("b", 300_000, &tree, &[]),
            unspent("c", 500_000, &tree, &[]),
        ];
        let (picked, total) = select_fee_boxes(&small, 1_000_000).unwrap();
        assert_eq!(total, 1_200_000);
        assert_eq!(picked.len(), 3);
    }

    /// A captured request to the mock node.
    #[derive(Debug, Clone)]
    pub(crate) struct Seen {
        pub method: String,
        pub target: String,
        pub headers: String,
        pub body: String,
    }

    /// Minimal HTTP/1.1 server on 127.0.0.1 answering every request with
    /// `respond(method, target, body)` (`(status, body)`) and recording what it received.
    /// Never touches the network.
    pub(crate) async fn mock_node(
        respond: impl Fn(&str, &str, &str) -> (u16, String) + Send + Sync + 'static,
    ) -> (String, Arc<Mutex<Vec<Seen>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_task = seen.clone();
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let seen = seen_task.clone();
                let respond = respond.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let header_end = loop {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let content_length = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    while buf.len() < header_end + content_length {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let body = String::from_utf8_lossy(&buf[header_end..]).to_string();
                    let mut request_line = head.lines().next().unwrap_or("").split_whitespace();
                    let method = request_line.next().unwrap_or("").to_string();
                    let target = request_line.next().unwrap_or("").to_string();
                    let (status, payload) = respond(&method, &target, &body);
                    seen.lock().unwrap().push(Seen {
                        method,
                        target,
                        headers: head,
                        body,
                    });
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (format!("http://{addr}"), seen)
    }

    pub(crate) fn query_param(target: &str, name: &str) -> Option<String> {
        let query = target.split_once('?')?.1;
        query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == name).then(|| v.to_string())
        })
    }

    fn box_json(id: &str, value: u64, tree: &str, token: Option<&str>) -> Value {
        let assets = match token {
            Some(t) => serde_json::json!([{ "tokenId": t, "amount": 1 }]),
            None => serde_json::json!([]),
        };
        serde_json::json!({
            "boxId": id,
            "value": value,
            "ergoTree": tree,
            "assets": assets,
            "additionalRegisters": {},
            "creationHeight": 1000,
            "transactionId": "00".repeat(32),
            "index": 0,
            "address": "ignored",
            "globalIndex": 7,
            "inclusionHeight": 1001,
            "spentTransactionId": null
        })
    }

    #[tokio::test]
    async fn scan_uses_public_by_address_and_skips_token_boxes() {
        let tree = p2pk_tree_hex(&PK);
        let tree_for_node = tree.clone();
        let (url, seen) = mock_node(move |_, target, _| {
            let offset = query_param(target, "offset").unwrap_or_default();
            let page: Vec<Value> = match offset.as_str() {
                // Page 0: a full page (100 boxes): the NFT box, a foreign token box, and
                // 98 token-free dust boxes far below the fee.
                "0" => {
                    let mut v = vec![
                        box_json(
                            &"a0".repeat(32),
                            1_000_000,
                            &tree_for_node,
                            Some(&"11".repeat(32)),
                        ),
                        box_json(
                            &"a1".repeat(32),
                            2_000_000,
                            &tree_for_node,
                            Some(&"22".repeat(32)),
                        ),
                    ];
                    for i in 0..98u8 {
                        v.push(box_json(
                            &format!("{:02x}", i).repeat(32),
                            1,
                            &tree_for_node,
                            None,
                        ));
                    }
                    v
                }
                // Page 1: a real fee box, plus a repeat from page 0.
                "100" => vec![
                    box_json(&"b0".repeat(32), 5_000_000, &tree_for_node, None),
                    box_json(&"00".repeat(32), 1, &tree_for_node, None),
                ],
                _ => vec![],
            };
            (200, Value::Array(page).to_string())
        })
        .await;

        let node = NodeEndpoint::new(&url, None);
        let scan = scan_fee_boxes(&node, "9fakeAddress", &tree, &[], 1_000_000)
            .await
            .unwrap();

        assert_eq!(scan.skipped_with_tokens, 2);
        assert!(!scan.truncated);
        assert_eq!(
            scan.boxes.len(),
            99,
            "98 dust boxes + the fee box, no repeats"
        );
        assert!(scan.boxes.iter().all(|b| b.assets.is_empty()));
        assert!(scan.total() >= 1_000_000);

        let seen = seen.lock().unwrap().clone();
        // Stopped after page 1: the usable total covered `enough`.
        assert_eq!(seen.len(), 2);
        for (i, request) in seen.iter().enumerate() {
            assert_eq!(request.method, "POST");
            assert!(request
                .target
                .starts_with("/blockchain/box/unspent/byAddress?"));
            assert_eq!(
                query_param(&request.target, "offset").as_deref(),
                Some((i as u64 * BY_ADDRESS_PAGE_LIMIT).to_string().as_str())
            );
            assert_eq!(
                query_param(&request.target, "limit").as_deref(),
                Some("100")
            );
            assert_eq!(
                query_param(&request.target, "excludeMempoolSpent").as_deref(),
                Some("true")
            );
            // The body is the address as a JSON string; no api_key header is sent.
            assert_eq!(request.body, "\"9fakeAddress\"");
            assert!(!request.headers.to_ascii_lowercase().contains("api_key"));
        }
    }

    #[tokio::test]
    async fn scan_stops_on_empty_page_and_404() {
        let tree = p2pk_tree_hex(&PK);
        let tree_for_node = tree.clone();
        let (url, seen) =
            mock_node(
                move |_, target, _| match query_param(target, "offset").as_deref() {
                    Some("0") => (
                        200,
                        Value::Array(vec![box_json(
                            &"c0".repeat(32),
                            300_000,
                            &tree_for_node,
                            None,
                        )])
                        .to_string(),
                    ),
                    _ => (200, "[]".to_string()),
                },
            )
            .await;
        let node = NodeEndpoint::new(&url, None);
        let scan = scan_fee_boxes(&node, "9addr", &tree, &[], 1_000_000)
            .await
            .unwrap();
        assert_eq!(scan.boxes.len(), 1);
        assert_eq!(
            seen.lock().unwrap().len(),
            2,
            "one data page, one empty page"
        );

        let (url404, _) =
            mock_node(|_, _, _| (404, r#"{"error":404,"reason":"not-found"}"#.to_string())).await;
        let scan = scan_fee_boxes(&NodeEndpoint::new(&url404, None), "9addr", &tree, &[], 1)
            .await
            .unwrap();
        assert!(scan.boxes.is_empty());

        let (url500, _) = mock_node(|_, _, _| (500, "boom".to_string())).await;
        assert!(
            scan_fee_boxes(&NodeEndpoint::new(&url500, None), "9addr", &tree, &[], 1)
                .await
                .is_err()
        );
    }

    // ----- local signing -----

    use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
    use ergo_lib::chain::transaction::{TxId, UnsignedInput};
    use ergo_lib::ergotree_ir::chain::context_extension::ContextExtension;
    use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
    use ergo_lib::ergotree_ir::chain::ergo_box::{
        BoxTokens, ErgoBoxCandidate, NonMandatoryRegisters,
    };
    use ergo_lib::ergotree_ir::chain::token::{Token, TokenAmount, TokenId};
    use ergo_lib::ergotree_ir::ergo_tree::ErgoTree;
    use ergo_lib::ergotree_ir::mir::constant::Constant;

    /// Real mainnet-format headers (heights 123405..=123414, oldest first) from the Scala
    /// client's test fixtures.
    pub(crate) const LAST_HEADERS_JSON: &str = include_str!(
        "../../../scala/src/test/resources/mockwebserver/node_responses/response_LastHeaders.json"
    );

    pub(crate) fn fixture_headers() -> Vec<Header> {
        serde_json::from_str(LAST_HEADERS_JSON).unwrap()
    }

    pub(crate) fn fixture_state() -> ErgoStateContext {
        state_context_from_headers(fixture_headers()).unwrap()
    }

    /// A freshly generated key: tests never use a real one.
    pub(crate) fn fresh_key() -> ([u8; 32], TrackerKey) {
        let (secret, _) = basis_store::schnorr::generate_keypair();
        let key = TrackerKey::from_secret_bytes(&secret).unwrap();
        (secret, key)
    }

    pub(crate) fn tree_of(pubkey: &[u8; 33]) -> ErgoTree {
        ErgoTree::sigma_parse_bytes(&hex::decode(p2pk_tree_hex(pubkey)).unwrap()).unwrap()
    }

    /// A box as the UTXO set would hold it. `index` keeps ids distinct.
    pub(crate) fn utxo_box(
        tree: &ErgoTree,
        value: u64,
        tokens: &[([u8; 32], u64)],
        registers_hex: &[&str],
        creation_height: u32,
        index: u16,
    ) -> ErgoBox {
        let tokens = if tokens.is_empty() {
            None
        } else {
            Some(
                BoxTokens::from_vec(
                    tokens
                        .iter()
                        .map(|(id, amount)| Token {
                            token_id: TokenId::from_str(&hex::encode(id)).unwrap(),
                            amount: TokenAmount::try_from(*amount).unwrap(),
                        })
                        .collect(),
                )
                .unwrap(),
            )
        };
        let registers: Vec<Constant> = registers_hex
            .iter()
            .map(|h| Constant::sigma_parse_bytes(&hex::decode(h).unwrap()).unwrap())
            .collect();
        ErgoBox::new(
            BoxValue::try_from(value).unwrap(),
            tree.clone(),
            tokens,
            NonMandatoryRegisters::try_from(registers).unwrap(),
            creation_height,
            TxId::zero(),
            index,
        )
        .unwrap()
    }

    use std::str::FromStr;

    #[test]
    fn tracker_key_derives_the_public_key_and_rejects_bad_scalars() {
        // sk = 1 gives the generator point.
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(
            TrackerKey::from_secret_bytes(&one).unwrap().public_key(),
            PK
        );

        // Same public key as the secp256k1 crate derives for a fresh secret.
        let (secret, expected_pk) = basis_store::schnorr::generate_keypair();
        assert_eq!(
            TrackerKey::from_secret_bytes(&secret).unwrap().public_key(),
            expected_pk
        );

        assert!(TrackerKey::from_secret_bytes(&[0u8; 32])
            .unwrap_err()
            .contains("zero"));
        // The group order n and anything above it are not scalars.
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let n: [u8; 32] = n.try_into().unwrap();
        assert!(TrackerKey::from_secret_bytes(&n).is_err());
        assert!(TrackerKey::from_secret_bytes(&[0xff; 32]).is_err());

        // Debug never shows the secret.
        let printed = format!("{:?}", TrackerKey::from_secret_bytes(&secret).unwrap());
        assert!(!printed.contains(&hex::encode(secret)));
    }

    #[test]
    fn state_context_puts_the_newest_header_first() {
        let state = fixture_state();
        assert_eq!(state.pre_header.height, 123_414);
        assert_eq!(state.headers[0].height, 123_414);
        assert_eq!(state.headers[9].height, 123_405);
        assert!(state_context_from_headers(fixture_headers()[..9].to_vec()).is_err());
    }

    fn spend_all_to(
        inputs: &[ErgoBox],
        out_tree: &ErgoTree,
        fee: u64,
        height: u32,
    ) -> UnsignedTransaction {
        let total: u64 = inputs.iter().map(|b| *b.value.as_u64()).sum();
        let fee_tree = ErgoTree::sigma_parse_bytes(
            &hex::decode(ergo_lib::wallet::miner_fee::MINERS_FEE_BASE16_BYTES).unwrap(),
        )
        .unwrap();
        UnsignedTransaction::new_from_vec(
            inputs
                .iter()
                .map(|b| UnsignedInput::new(b.box_id(), ContextExtension::empty()))
                .collect(),
            vec![],
            vec![
                ErgoBoxCandidate {
                    value: BoxValue::try_from(total - fee).unwrap(),
                    ergo_tree: out_tree.clone(),
                    tokens: None,
                    additional_registers: NonMandatoryRegisters::empty(),
                    creation_height: height,
                },
                ErgoBoxCandidate {
                    value: BoxValue::try_from(fee).unwrap(),
                    ergo_tree: fee_tree,
                    tokens: None,
                    additional_registers: NonMandatoryRegisters::empty(),
                    creation_height: height,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn sign_proves_own_inputs_and_validates() {
        let (_, key) = fresh_key();
        let tree = tree_of(&key.public_key());
        let state = fixture_state();
        let inputs = vec![
            utxo_box(&tree, 3_000_000, &[], &[], 123_000, 0),
            utxo_box(&tree, 2_000_000, &[], &[], 123_001, 1),
        ];
        let unsigned = spend_all_to(&inputs, &tree, 1_000_000, 123_414);
        let signed = key.sign(unsigned, inputs, vec![], &state).unwrap();
        assert_eq!(signed.inputs.len(), 2);
        for input in signed.inputs.iter() {
            assert!(!Vec::<u8>::from(input.spending_proof.proof.clone()).is_empty());
        }
    }

    #[test]
    fn sign_refuses_inputs_of_another_key() {
        let (_, key) = fresh_key();
        let (_, other) = fresh_key();
        let state = fixture_state();
        let inputs = vec![
            utxo_box(&tree_of(&key.public_key()), 3_000_000, &[], &[], 123_000, 0),
            utxo_box(
                &tree_of(&other.public_key()),
                2_000_000,
                &[],
                &[],
                123_000,
                1,
            ),
        ];
        let unsigned = spend_all_to(&inputs, &tree_of(&key.public_key()), 1_000_000, 123_414);
        let err = key.sign(unsigned, inputs, vec![], &state).unwrap_err();
        assert!(err.contains("input 1"), "{err}");
    }

    #[test]
    fn sign_rejects_a_transaction_that_does_not_validate() {
        let (_, key) = fresh_key();
        let tree = tree_of(&key.public_key());
        let state = fixture_state();
        let inputs = vec![utxo_box(&tree, 3_000_000, &[], &[], 123_000, 0)];
        // Outputs created above the tip are invalid.
        let unsigned = spend_all_to(&inputs, &tree, 1_000_000, 123_415);
        let err = key.sign(unsigned, inputs, vec![], &state).unwrap_err();
        assert!(err.contains("does not validate"), "{err}");
    }

    #[tokio::test]
    async fn fetch_box_checks_the_returned_id() {
        let (_, key) = fresh_key();
        let tree = tree_of(&key.public_key());
        let wanted = utxo_box(&tree, 3_000_000, &[], &[], 123_000, 0);
        let other = utxo_box(&tree, 3_000_000, &[], &[], 123_000, 1);
        let wanted_id = String::from(wanted.box_id());
        let wanted_hex = hex::encode(wanted.sigma_serialize_bytes().unwrap());
        let other_hex = hex::encode(other.sigma_serialize_bytes().unwrap());
        let wanted_id_for_node = wanted_id.clone();
        let (url, seen) = mock_node(move |_, target, _| {
            let id = target.rsplit('/').next().unwrap_or_default().to_string();
            let bytes = if id == wanted_id_for_node {
                wanted_hex.clone()
            } else {
                other_hex.clone()
            };
            (
                200,
                serde_json::json!({ "boxId": id, "bytes": bytes }).to_string(),
            )
        })
        .await;
        let node = NodeEndpoint::new(&url, None);
        let fetched = fetch_box(&node, &wanted_id).await.unwrap();
        assert_eq!(fetched, wanted);
        assert_eq!(
            seen.lock().unwrap()[0].target,
            format!("/utxo/byIdBinary/{wanted_id}")
        );

        let liar = fetch_box(&node, &"00".repeat(32)).await.unwrap_err();
        assert!(liar.contains("when asked for"), "{liar}");
        assert!(fetch_box(&node, "../wallet").await.is_err());
    }

    #[tokio::test]
    async fn broadcast_posts_the_signed_transaction() {
        let (secret, key) = fresh_key();
        let tree = tree_of(&key.public_key());
        let state = fixture_state();
        let inputs = vec![utxo_box(&tree, 3_000_000, &[], &[], 123_000, 0)];
        let unsigned = spend_all_to(&inputs, &tree, 1_000_000, 123_414);
        let signed = key.sign(unsigned, inputs, vec![], &state).unwrap();
        let expected_id = String::from(signed.id());

        let (url, seen) = mock_node(|_, _, body| {
            let v: Value = serde_json::from_str(body).unwrap();
            (
                200,
                Value::String(v["id"].as_str().unwrap().to_string()).to_string(),
            )
        })
        .await;
        let node = NodeEndpoint::new(&url, None);
        assert_eq!(broadcast(&node, &signed).await.unwrap(), expected_id);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].target, "/transactions");
        assert!(!seen[0].body.contains(&hex::encode(secret)));
        assert!(!seen[0].headers.to_ascii_lowercase().contains("api_key"));

        let (url_bad, _) = mock_node(|_, _, _| (200, "\"ff\"".to_string())).await;
        assert!(broadcast(&NodeEndpoint::new(&url_bad, None), &signed)
            .await
            .is_err());
        let (url_rej, _) =
            mock_node(|_, _, _| (400, r#"{"error":400,"reason":"bad"}"#.to_string())).await;
        assert!(broadcast(&NodeEndpoint::new(&url_rej, None), &signed)
            .await
            .unwrap_err()
            .contains("HTTP 400"));
    }
}
