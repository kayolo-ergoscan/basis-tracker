//! Core types for Basis Tracker system

use blake2::{Blake2b, Digest};
use generic_array::typenum::U32;

/// Public key type (Secp256k1 compressed)
pub type PubKey = [u8; 33];

/// Signature type (Secp256k1 Schnorr) - 65 bytes (33 for 'a' component, 32 for 'z' component)
pub type Signature = [u8; 65];

/// Denomination of a debt record or reserve: native ERG or a specific token.
///
/// The denomination is part of the tracker debt-tree key derivation
/// (specs/ergo/multi_collateral_reserves.md):
/// - Erg:   key = blake2b256(owner ‖ receiver)            (matches contract/basis.es)
/// - Token: key = blake2b256(owner ‖ receiver ‖ tokenId)  (basis-token.es)
///
/// so one (issuer, creditor) pair can hold an independent debt per denomination in
/// the same tracker tree. The reserve redemption tree keys are denomination-free
/// (`blake2b256(owner ‖ receiver)`) in both contracts.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum DenomKey {
    /// Native ERG (empty debt-key suffix)
    #[default]
    Erg,
    /// Token collateral; the 32-byte token id
    Token([u8; 32]),
}

/// Error parsing a denomination id string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DenomKeyParseError {
    #[error("invalid denomination {0:?}: expected \"erg\" or \"token:<64 hex chars>\"")]
    InvalidFormat(String),
    #[error("invalid denomination token id {0:?}: {1}")]
    InvalidTokenId(String, String),
}

impl DenomKey {
    /// Debt-tree key suffix: `[]` for Erg, `token_id` for a token. No tag byte:
    /// both public keys are fixed 33 bytes, so the token id always starts at a
    /// fixed offset and ERG (66-byte input) cannot collide with a token (98-byte
    /// input).
    pub fn debt_key_suffix(&self) -> Vec<u8> {
        match self {
            DenomKey::Erg => Vec::new(),
            DenomKey::Token(token_id) => token_id.to_vec(),
        }
    }

    /// Debt-tree key: blake2b256(owner ‖ receiver ‖ suffix).
    pub fn debt_key(&self, owner_key: &PubKey, receiver_key: &PubKey) -> [u8; 32] {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(owner_key);
        hasher.update(receiver_key);
        hasher.update(self.debt_key_suffix());
        hasher.finalize().into()
    }

    /// Canonical string id: `"erg"` or `"token:<64-hex>"`.
    pub fn denomination_id(&self) -> String {
        match self {
            DenomKey::Erg => "erg".to_string(),
            DenomKey::Token(token_id) => format!("token:{}", hex::encode(token_id)),
        }
    }

    /// Parse a canonical denomination id (`"erg"` or `"token:<64-hex>"`).
    pub fn parse(s: &str) -> Result<Self, DenomKeyParseError> {
        if s.eq_ignore_ascii_case("erg") {
            return Ok(DenomKey::Erg);
        }
        if let Some(hex_part) = s.strip_prefix("token:") {
            let bytes = hex::decode(hex_part).map_err(|e| {
                DenomKeyParseError::InvalidTokenId(hex_part.to_string(), e.to_string())
            })?;
            let arr: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
                DenomKeyParseError::InvalidTokenId(
                    hex_part.to_string(),
                    format!("expected 32 bytes, got {}", b.len()),
                )
            })?;
            return Ok(DenomKey::Token(arr));
        }
        Err(DenomKeyParseError::InvalidFormat(s.to_string()))
    }

    /// Fixed-width binary encoding: `kind(1) ‖ token_id(32)` (33 bytes);
    /// token_id is all zeros for Erg.
    pub fn encode33(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        match self {
            DenomKey::Erg => out[0] = 0x00,
            DenomKey::Token(token_id) => {
                out[0] = 0x01;
                out[1..33].copy_from_slice(token_id);
            }
        }
        out
    }

    /// Decode the fixed-width binary form produced by `encode33`.
    pub fn decode33(bytes: &[u8; 33]) -> Result<Self, DenomKeyParseError> {
        match bytes[0] {
            0x00 => Ok(DenomKey::Erg),
            0x01 => {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes[1..33]);
                Ok(DenomKey::Token(id))
            }
            other => Err(DenomKeyParseError::InvalidFormat(format!(
                "unknown denomination kind byte 0x{other:02x}"
            ))),
        }
    }
}

impl std::fmt::Display for DenomKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.denomination_id())
    }
}

impl serde::Serialize for DenomKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.denomination_id())
    }
}

impl<'de> serde::Deserialize<'de> for DenomKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        DenomKey::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Compute the tracker debt-tree key for an (issuer, receiver, denomination) triple.
///
/// Erg:   blake2b256(owner ‖ receiver)
/// Token: blake2b256(owner ‖ receiver ‖ tokenId)
pub fn debt_tree_key(
    owner_key: &PubKey,
    receiver_key: &PubKey,
    denomination: &DenomKey,
) -> [u8; 32] {
    denomination.debt_key(owner_key, receiver_key)
}

/// Generate the signing message used when creating off-chain IOU notes.
///
/// message = debtKey || longToByteArray(totalDebt) || longToByteArray(timestamp) || trackerNftId
///
/// Where:
/// - debtKey = denomination-derived debt-tree key (32 bytes), see [`DenomKey::debt_key`]
/// - totalDebt: 8-byte big-endian total cumulative debt amount
/// - timestamp: 8-byte big-endian payment timestamp (milliseconds since Unix epoch)
/// - trackerNftId: 32-byte tracker NFT ID binding the signature to one tracker
///   (and thus one reserve contract deployment and one chain — issue #15 C3)
///
/// # Returns
/// * 80 bytes: debtKey (32) || totalDebt (8 BE) || timestamp (8 BE) || trackerNftId (32)
pub fn signing_message(
    owner_key: &PubKey,
    receiver_key: &PubKey,
    denomination: &DenomKey,
    total_debt: u64,
    timestamp: u64,
    tracker_nft_id: &[u8; 32],
) -> Vec<u8> {
    let key_hash = denomination.debt_key(owner_key, receiver_key);

    // Build message: debtKey || totalDebt || timestamp || trackerNftId (always 80 bytes)
    let mut message = Vec::with_capacity(80);
    message.extend_from_slice(&key_hash);
    message.extend_from_slice(&total_debt.to_be_bytes());
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(tracker_nft_id);

    message
}

/// Domain tag that starts every redemption build request message (`POST /redemption/build`).
pub const BUILD_REQUEST_DOMAIN: &[u8] = b"basis-build-v1";

/// Message the RECEIVER signs to request a redemption build (`POST /redemption/build`).
///
/// message = "basis-build-v1" (14 bytes ASCII) || trackerNftId (32) || issuer key (33)
///           || receiver key (33) || denomination id (UTF-8 of the canonical id: `erg` or
///           `token:<64 lowercase hex>`) || amount (8 BE) || requestTimestamp (8 BE, ms)
///
/// It is signed with the same Basis Schnorr scheme as notes. The domain tag keeps it from
/// ever being valid as a note or redemption message (those are exactly 80 bytes and start
/// with a debt-tree key); the denomination id is the only variable-length field and sits
/// between fixed-width ones, so the encoding is unambiguous. 131 bytes for ERG, 198 for a token.
pub fn build_request_message(
    tracker_nft_id: &[u8; 32],
    issuer_key: &PubKey,
    receiver_key: &PubKey,
    denomination: &DenomKey,
    amount: u64,
    request_timestamp_ms: u64,
) -> Vec<u8> {
    let denomination_id = denomination.denomination_id();
    let mut message =
        Vec::with_capacity(BUILD_REQUEST_DOMAIN.len() + 32 + 33 + 33 + denomination_id.len() + 16);
    message.extend_from_slice(BUILD_REQUEST_DOMAIN);
    message.extend_from_slice(tracker_nft_id);
    message.extend_from_slice(issuer_key);
    message.extend_from_slice(receiver_key);
    message.extend_from_slice(denomination_id.as_bytes());
    message.extend_from_slice(&amount.to_be_bytes());
    message.extend_from_slice(&request_timestamp_ms.to_be_bytes());
    message
}

/// Domain tag that starts every inbox request message (`GET /notes/recipient/{pubkey}`).
pub const INBOX_REQUEST_DOMAIN: &[u8] = b"basis-inbox-v1";

/// Length of every inbox request message: domain tag (14) + tracker NFT id (32) + recipient key
/// (33) + valid_until (8).
pub const INBOX_REQUEST_MESSAGE_LEN: usize = 87;

/// Message the RECIPIENT signs to have its note list in one call (`GET /notes/recipient/{pubkey}`).
///
/// message = "basis-inbox-v1" (14 bytes ASCII) || trackerNftId (32) || recipient key (33)
///           || validUntil (8 BE, unix seconds)
///
/// The tracker NFT id binds the signature to one tracker: another tracker (whose NFT differs)
/// refuses it. It is signed with the same Basis Schnorr scheme as notes. Every field has a fixed
/// width, so the message is always exactly [`INBOX_REQUEST_MESSAGE_LEN`] (87) bytes. It can never
/// be a note, redemption or exchange message (always 80 bytes, starting with a debt-tree key, a
/// hash output) or a build request (`"basis-build-v1"` prefix, 131 or 198 bytes): the lengths
/// differ and the domain tags differ at byte 6 (`i` against `b`). The signature only opens a
/// read; it moves nothing.
pub fn inbox_request_message(
    tracker_nft_id: &[u8; 32],
    recipient_key: &PubKey,
    valid_until_secs: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(INBOX_REQUEST_MESSAGE_LEN);
    message.extend_from_slice(INBOX_REQUEST_DOMAIN);
    message.extend_from_slice(tracker_nft_id);
    message.extend_from_slice(recipient_key);
    message.extend_from_slice(&valid_until_secs.to_be_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inbox: the exact bytes for fixed inputs, for clients (the web wallet's test checks the
    /// same hex). Tracker NFT 0x5a * 32; recipient 2G; valid until 2026-11-23T00:00:00Z
    /// (1795392000 s).
    #[test]
    fn worked_example_of_the_inbox_message() {
        let recipient: PubKey =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap()
                .try_into()
                .unwrap();
        let nft = [0x5a; 32];
        let message = inbox_request_message(&nft, &recipient, 1_795_392_000);
        assert_eq!(message.len(), INBOX_REQUEST_MESSAGE_LEN);
        assert_eq!(
            hex::encode(&message),
            concat!(
                "62617369732d696e626f782d7631",
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "000000006b038200"
            )
        );
        assert_eq!(&message[..14], b"basis-inbox-v1");
        assert_eq!(&message[14..46], &nft);
        assert_eq!(&message[46..79], &recipient);
        assert_eq!(&message[79..], &1_795_392_000u64.to_be_bytes());
    }

    /// The inbox message never equals any other message a key signs here: a note, redemption or
    /// exchange message (80 bytes for every input), a build request (131 or 198 bytes, its own
    /// tag), nor an inbox message for another tracker.
    #[test]
    fn inbox_message_never_equals_a_note_or_build_request() {
        assert_eq!(INBOX_REQUEST_DOMAIN.len(), BUILD_REQUEST_DOMAIN.len());
        assert_ne!(INBOX_REQUEST_DOMAIN, BUILD_REQUEST_DOMAIN);
        // The tags agree on "basis-" and differ from byte 6 on.
        assert_eq!(&INBOX_REQUEST_DOMAIN[..6], &BUILD_REQUEST_DOMAIN[..6]);
        assert_ne!(INBOX_REQUEST_DOMAIN[6], BUILD_REQUEST_DOMAIN[6]);
        assert!(![80usize, 131, 198].contains(&INBOX_REQUEST_MESSAGE_LEN));

        let keys: [PubKey; 3] = [[0x02; 33], [0x03; 33], {
            let mut k = [0xffu8; 33];
            k[0] = 0x02;
            k
        }];
        let nfts = [[0x5a; 32], [0x00; 32], [0xff; 32]];
        let denominations = [DenomKey::Erg, DenomKey::Token([0x7c; 32])];
        for nft in &nfts {
            for key in &keys {
                for until in [0u64, 1, 1_795_392_000, u64::MAX] {
                    let inbox = inbox_request_message(nft, key, until);
                    assert_eq!(inbox.len(), INBOX_REQUEST_MESSAGE_LEN);
                    assert_eq!(&inbox[..14], INBOX_REQUEST_DOMAIN);
                    for other_nft in &nfts {
                        if other_nft != nft {
                            assert_ne!(inbox_request_message(other_nft, key, until), inbox);
                        }
                    }
                    for other in &keys {
                        for denomination in &denominations {
                            for (a, b) in [(0u64, 0u64), (until, until), (u64::MAX, 1)] {
                                let note = signing_message(key, other, denomination, a, b, nft);
                                assert_eq!(note.len(), 80);
                                assert_ne!(note, inbox);
                                let build =
                                    build_request_message(nft, other, key, denomination, a, b);
                                assert!(build.len() == 131 || build.len() == 198);
                                assert_eq!(&build[..14], BUILD_REQUEST_DOMAIN);
                                assert_ne!(build, inbox);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Round 4: worked examples for clients (the canary tool among them): the exact bytes of
    /// the 80-byte note message (also what `/tracker/signature` signs) and of the build-request
    /// message of `POST /redemption/build`, for fixed inputs. A client that produces the same
    /// bytes signs what the tracker verifies. Keys: the secp256k1 generator G (issuer) and 2G
    /// (receiver); tracker NFT 0x5a * 32; 2026-11-22T00:00:00Z in ms.
    #[test]
    fn worked_examples_of_the_signed_messages() {
        let key = |h: &str| -> PubKey { hex::decode(h).unwrap().try_into().unwrap() };
        let issuer = key("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let receiver = key("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        let nft = [0x5a; 32];
        let ts = 1_795_305_600_000u64;

        assert_eq!(
            hex::encode(DenomKey::Erg.debt_key(&issuer, &receiver)),
            "87262ce92e4cc9c99666eb41bcab2a75ed76c937b50f9e441b4f5806138228ee"
        );
        let note = signing_message(&issuer, &receiver, &DenomKey::Erg, 1_000_000_000, ts, &nft);
        assert_eq!(
            hex::encode(&note),
            concat!(
                "87262ce92e4cc9c99666eb41bcab2a75ed76c937b50f9e441b4f5806138228ee",
                "000000003b9aca00",
                "000001a2008d7400",
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            )
        );

        let build = build_request_message(
            &nft,
            &issuer,
            &receiver,
            &DenomKey::Erg,
            500_000_000,
            ts + 60_000,
        );
        assert_eq!(build.len(), 131);
        assert_eq!(
            hex::encode(&build),
            concat!(
                "62617369732d6275696c642d7631",
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "657267",
                "000000001dcd6500",
                "000001a2008e5e60"
            )
        );

        let token = DenomKey::Token([0x7c; 32]);
        assert_eq!(
            hex::encode(token.debt_key(&issuer, &receiver)),
            "9166c9c9b26e3c9832d9285becd4a22fa265552a51ee77f0d6d5ae79ae6281be"
        );
        let build = build_request_message(&nft, &issuer, &receiver, &token, 500_000_000, ts + 60_000);
        assert_eq!(build.len(), 198);
    }

    #[test]
    fn denomination_id_roundtrip() {
        assert_eq!(DenomKey::Erg.denomination_id(), "erg");
        let id = [0xa5u8; 32];
        let key = DenomKey::Token(id);
        let s = key.denomination_id();
        assert_eq!(s, format!("token:{}", hex::encode(id)));
        assert_eq!(DenomKey::parse(&s).unwrap(), key);
        assert_eq!(DenomKey::parse("ERG").unwrap(), DenomKey::Erg);
    }

    #[test]
    fn build_request_message_layout() {
        let nft = [0x11u8; 32];
        let issuer = [0x02u8; 33];
        let receiver = [0x03u8; 33];
        let erg = build_request_message(&nft, &issuer, &receiver, &DenomKey::Erg, 7, 9);
        assert_eq!(erg.len(), 131);
        assert_eq!(&erg[..14], b"basis-build-v1");
        assert_eq!(&erg[14..46], &nft);
        assert_eq!(&erg[46..79], &issuer);
        assert_eq!(&erg[79..112], &receiver);
        assert_eq!(&erg[112..115], b"erg");
        assert_eq!(&erg[115..123], &7u64.to_be_bytes());
        assert_eq!(&erg[123..131], &9u64.to_be_bytes());

        let token = DenomKey::Token([0xabu8; 32]);
        let tok = build_request_message(&nft, &issuer, &receiver, &token, 7, 9);
        assert_eq!(tok.len(), 198);
        assert_eq!(&tok[112..182], format!("token:{}", "ab".repeat(32)).as_bytes());
        // Never the 80-byte note/redemption message shape.
        assert_ne!(erg.len(), 80);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(DenomKey::parse("").is_err());
        assert!(DenomKey::parse("usd").is_err());
        assert!(DenomKey::parse("token:zz").is_err());
        assert!(DenomKey::parse(&format!("token:{}", "aa".repeat(31))).is_err());
    }

    #[test]
    fn encode33_roundtrip() {
        for k in [DenomKey::Erg, DenomKey::Token([0x42u8; 32])] {
            assert_eq!(DenomKey::decode33(&k.encode33()).unwrap(), k);
        }
        assert!(DenomKey::decode33(&[0x07u8; 33]).is_err());
    }

    #[test]
    fn debt_key_namespaces_differ() {
        let owner = [0x02u8; 33];
        let receiver = [0x03u8; 33];
        let erg = DenomKey::Erg.debt_key(&owner, &receiver);
        let tok = DenomKey::Token([0xa5u8; 32]).debt_key(&owner, &receiver);
        let tok2 = DenomKey::Token([0xa6u8; 32]).debt_key(&owner, &receiver);
        assert_ne!(erg, tok);
        assert_ne!(tok, tok2);
    }

    #[test]
    fn erg_debt_key_matches_legacy_derivation() {
        // The ERG key must stay blake2b256(owner ‖ receiver), byte-identical to the
        // pre-denomination derivation (contract/basis.es is unchanged).
        let owner = [0x02u8; 33];
        let receiver = [0x03u8; 33];
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(owner);
        hasher.update(receiver);
        let legacy: [u8; 32] = hasher.finalize().into();
        assert_eq!(DenomKey::Erg.debt_key(&owner, &receiver), legacy);
    }

    #[test]
    fn signing_message_is_80_bytes() {
        let owner = [0x02u8; 33];
        let receiver = [0x03u8; 33];
        let nft = [0x42u8; 32];
        assert_eq!(
            signing_message(&owner, &receiver, &DenomKey::Erg, 1, 2, &nft).len(),
            80
        );
        assert_eq!(
            signing_message(
                &owner,
                &receiver,
                &DenomKey::Token([0xa5u8; 32]),
                1,
                2,
                &nft
            )
            .len(),
            80
        );
    }
}
