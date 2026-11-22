//! Secrets read from files: signing keys (`--secret-file`) and the tracker API key
//! (`--api-key-file`).
//!
//! Error messages name the file and what is wrong with it (missing, too large, wrong length,
//! not hex), never its content. `Debug` shows the public key of a signing key and nothing of an
//! API key.

use std::path::Path;

use basis_server::local_wallet::{self, TrackerKey};
use basis_store::reqwest::header::HeaderValue;
use ergo_lib::chain::ergo_state_context::ErgoStateContext;
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::Transaction;
use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox;
use ergo_lib::wallet::secret_key::SecretKey;

/// Largest key file accepted, in bytes. A key is 64 characters; anything much larger is the
/// wrong file.
pub const MAX_KEY_FILE_BYTES: u64 = 4096;

/// Read a small text file holding a secret. `kind` names it in errors ("secret file").
fn read_key_file(kind: &str, path: &Path) -> Result<String, String> {
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("{kind} {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{kind} {shown} is not a regular file"));
    }
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(format!(
            "{kind} {shown} is {} bytes; a key file holds a single key (at most \
             {MAX_KEY_FILE_BYTES} bytes)",
            meta.len()
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{kind} {shown}: {e}"))?;
    String::from_utf8(bytes).map_err(|_| format!("{kind} {shown} is not UTF-8 text"))
}

/// A secp256k1 key from a `--secret-file`: 64 hex characters, a 32-byte big-endian scalar.
/// Whitespace around it (a trailing newline) is ignored.
pub struct FileKey {
    secret: [u8; 32],
    key: TrackerKey,
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKey")
            .field("public", &hex::encode(self.public_key()))
            .finish_non_exhaustive()
    }
}

impl FileKey {
    /// Read and check the key in `path`.
    pub fn read(path: &Path) -> Result<Self, String> {
        let text = read_key_file("secret file", path)?;
        let hex_text = text.trim();
        let shown = path.display();
        if hex_text.len() != 64 {
            return Err(format!(
                "secret file {shown}: expected 64 hex characters (a 32-byte secret key), found \
                 {} characters",
                hex_text.chars().count()
            ));
        }
        let mut secret = [0u8; 32];
        hex::decode_to_slice(hex_text, &mut secret)
            .map_err(|_| format!("secret file {shown}: the key is not hex"))?;
        Self::from_secret(secret).map_err(|_| format!("secret file {shown}: {}", Self::INVALID_KEY))
    }

    const INVALID_KEY: &'static str =
        "not a valid secp256k1 secret key (zero, or not below the group order)";

    /// A key from its 32 secret bytes (tests generate fresh ones).
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, String> {
        let key = TrackerKey::from_secret_bytes(&secret).map_err(|_| Self::INVALID_KEY)?;
        Ok(Self { secret, key })
    }

    /// The compressed public key `sk·G`.
    pub fn public_key(&self) -> [u8; 33] {
        self.key.public_key()
    }

    /// The public key in hex (66 characters).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// Hex ErgoTree of `P2PK(sk·G)`.
    pub fn p2pk_tree_hex(&self) -> String {
        self.key.p2pk_tree_hex()
    }

    /// Mainnet P2PK address of the key.
    pub fn address(&self) -> Result<String, String> {
        local_wallet::p2pk_address(&self.public_key())
    }

    /// Basis Schnorr signature `a ‖ z` (65 bytes) over `message`, with the retry that keeps the
    /// challenge and `z` in the range the reserve contract accepts (the tracker's own signer).
    pub fn schnorr_sign(&self, message: &[u8]) -> Result<[u8; 65], String> {
        basis_store::schnorr::schnorr_sign(message, &self.secret, &self.public_key())
            .map_err(|e| format!("Schnorr signing failed: {e:?}"))
    }

    /// Prove every input of `unsigned` with this key and validate the signed transaction in
    /// full against `state`. Every input must be locked by exactly `P2PK(sk·G)`.
    pub fn sign_all_inputs(
        &self,
        unsigned: UnsignedTransaction,
        inputs: Vec<ErgoBox>,
        data_inputs: Vec<ErgoBox>,
        state: &ErgoStateContext,
    ) -> Result<Transaction, String> {
        self.key.sign(unsigned, inputs, data_inputs, state)
    }

    /// Prove input `index` of `unsigned` with this key, keeping the proofs `base` already has
    /// for the other inputs. `state` supplies the pre-header and headers the proof is made in.
    pub fn prove_input(
        &self,
        unsigned: &UnsignedTransaction,
        base: Option<&Transaction>,
        inputs: &[ErgoBox],
        data_inputs: &[ErgoBox],
        state: &ErgoStateContext,
        index: usize,
    ) -> Result<Transaction, String> {
        let secret = SecretKey::dlog_from_bytes(&self.secret).ok_or(Self::INVALID_KEY)?;
        basis_offchain::signing::add_input_proof(
            unsigned,
            base,
            inputs,
            data_inputs,
            &state.pre_header,
            &state.headers,
            index,
            &secret,
        )
        .map_err(|e| format!("proving input {index}: {e}"))
    }
}

/// The tracker API key from `--api-key-file`. It is only sent to the tracker, as the
/// `X-API-Key` header, marked sensitive.
#[derive(Clone)]
pub struct ApiKey(String);

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

impl ApiKey {
    /// Read the key in `path`: printable ASCII without spaces, whitespace around it ignored.
    pub fn read(path: &Path) -> Result<Self, String> {
        let text = read_key_file("API key file", path)?;
        let key = text.trim();
        let shown = path.display();
        if key.is_empty() {
            return Err(format!("API key file {shown} is empty"));
        }
        if !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(format!(
                "API key file {shown}: the key must be printable ASCII without spaces"
            ));
        }
        Ok(Self(key.to_string()))
    }

    /// The `X-API-Key` header value, marked sensitive so no `Debug` of a request shows it.
    pub(crate) fn header_value(&self) -> Result<HeaderValue, String> {
        let mut value = HeaderValue::from_str(&self.0)
            .map_err(|_| "the API key is not a valid header value".to_string())?;
        value.set_sensitive(true);
        Ok(value)
    }
}
