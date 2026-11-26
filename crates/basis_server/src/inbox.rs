//! `GET /notes/recipient/{pubkey}` for the recipient only (the inbox).
//!
//! The list of every note paid to one key says who pays whom, so the route answers only a caller
//! that proves it holds that key. The request carries two headers:
//!
//! * `X-Basis-Inbox-Until`: `valid_until`, unix seconds in decimal;
//! * `X-Basis-Inbox-Sig`: the recipient's Basis Schnorr signature (130 hex) over
//!   [`basis_store::schnorr::inbox_request_message`]`(recipient, valid_until)` =
//!   `"basis-inbox-v1" || recipient (33) || valid_until (8 BE)`, 55 bytes.
//!
//! The tracker answers 401 when a header is missing or malformed, when `valid_until` is not in
//! the future or lies more than [`INBOX_MAX_AHEAD_SECS`] (24 h) ahead, or when the signature does
//! not verify under the key of the path. A good token may be used again until it expires: it
//! only reads, and the client keeps it for that time instead of asking for the key again.
//!
//! An Admin caller (the operator's key, or auth mode `none` on loopback) needs no token: it can
//! read every note through `GET /notes` anyway.
//!
//! Verified requests of one recipient are capped per window ([`InboxRateLimiter`], 429), on top
//! of the front's per-IP limits, so one token cannot be replayed without bound. Refused
//! requests never count, so nobody can use up another key's budget without its signature.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use basis_store::PubKey;

/// Header carrying `valid_until` (unix seconds, decimal).
pub const INBOX_UNTIL_HEADER: &str = "x-basis-inbox-until";
/// Header carrying the recipient's signature (65 bytes, 130 hex characters).
pub const INBOX_SIG_HEADER: &str = "x-basis-inbox-sig";
/// How far ahead `valid_until` may lie.
pub const INBOX_MAX_AHEAD_SECS: u64 = 24 * 60 * 60;
/// The window of the per-recipient cap.
pub const INBOX_WINDOW: Duration = Duration::from_secs(600);
/// Verified inbox reads of one recipient per [`INBOX_WINDOW`].
pub const INBOX_MAX_PER_RECIPIENT: u32 = 30;
/// Recipients the cap tracks at most. Past it a new recipient is served untracked (the front's
/// per-IP limits still hold) rather than refused, so filling the table locks nobody out.
pub const MAX_TRACKED_INBOX_RECIPIENTS: usize = 10_000;

/// Why an inbox request was refused (HTTP 401).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxRefusal {
    /// `X-Basis-Inbox-Until` or `X-Basis-Inbox-Sig` is absent.
    MissingHeaders,
    /// `valid_until` is not 1 to 20 decimal digits of a u64.
    BadUntil,
    /// `valid_until` is not in the future.
    Expired,
    /// `valid_until` is more than 24 h ahead.
    TooFarAhead,
    /// The signature is not 130 hex characters.
    BadSignatureEncoding,
    /// The signature does not verify under the recipient key.
    BadSignature,
}

impl InboxRefusal {
    /// The `error` text of the 401 answer.
    pub fn message(self) -> &'static str {
        match self {
            Self::MissingHeaders => {
                "this list needs the recipient's signature: X-Basis-Inbox-Until and X-Basis-Inbox-Sig"
            }
            Self::BadUntil => "X-Basis-Inbox-Until must be unix seconds in decimal",
            Self::Expired => "the inbox signature has expired",
            Self::TooFarAhead => "X-Basis-Inbox-Until is more than 24 hours ahead",
            Self::BadSignatureEncoding => "X-Basis-Inbox-Sig must be 130 hex characters",
            Self::BadSignature => {
                "the inbox signature does not verify under this key (message \"basis-inbox-v1\" || key || valid_until u64 BE)"
            }
        }
    }
}

/// Checks an inbox token for `recipient` at `now_secs` (unix seconds) and returns its
/// `valid_until`. Cheap checks run first; the signature is verified last.
pub fn verify_inbox_request(
    recipient: &PubKey,
    until_header: Option<&str>,
    sig_header: Option<&str>,
    now_secs: u64,
) -> Result<u64, InboxRefusal> {
    let (Some(until), Some(sig)) = (until_header, sig_header) else {
        return Err(InboxRefusal::MissingHeaders);
    };
    let until = until.trim();
    if until.is_empty() || until.len() > 20 || !until.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InboxRefusal::BadUntil);
    }
    let valid_until: u64 = until.parse().map_err(|_| InboxRefusal::BadUntil)?;
    if valid_until <= now_secs {
        return Err(InboxRefusal::Expired);
    }
    if valid_until > now_secs.saturating_add(INBOX_MAX_AHEAD_SECS) {
        return Err(InboxRefusal::TooFarAhead);
    }
    let sig = sig.trim();
    if sig.len() != 130 {
        return Err(InboxRefusal::BadSignatureEncoding);
    }
    let signature: [u8; 65] = hex::decode(sig)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(InboxRefusal::BadSignatureEncoding)?;
    let message = basis_store::schnorr::inbox_request_message(recipient, valid_until);
    basis_store::schnorr::schnorr_verify(&signature, &message, recipient)
        .map_err(|_| InboxRefusal::BadSignature)?;
    Ok(valid_until)
}

/// Unix seconds now.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fixed-window cap on verified inbox reads per recipient.
#[derive(Debug)]
pub struct InboxRateLimiter {
    windows: Mutex<HashMap<PubKey, (Instant, u32)>>,
    window: Duration,
    max: u32,
    max_tracked: usize,
}

impl InboxRateLimiter {
    /// A limiter of `max` reads per `window` and recipient, tracking at most `max_tracked` keys.
    pub fn new(window: Duration, max: u32, max_tracked: usize) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            window,
            max,
            max_tracked,
        }
    }

    /// Counts one verified read of `recipient` at `now`; false when the cap is reached.
    pub fn try_hit(&self, recipient: &PubKey, now: Instant) -> bool {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((start, count)) = windows.get_mut(recipient) {
            if now.saturating_duration_since(*start) >= self.window {
                *start = now;
                *count = 0;
            }
            if *count >= self.max {
                return false;
            }
            *count += 1;
            return true;
        }
        if windows.len() >= self.max_tracked {
            let window = self.window;
            windows.retain(|_, (start, _)| now.saturating_duration_since(*start) < window);
            if windows.len() >= self.max_tracked {
                return true;
            }
        }
        windows.insert(*recipient, (now, 1));
        true
    }
}

/// The process-wide limiter of the inbox route.
pub fn inbox_rate_limiter() -> &'static InboxRateLimiter {
    static LIMITER: OnceLock<InboxRateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| {
        InboxRateLimiter::new(
            INBOX_WINDOW,
            INBOX_MAX_PER_RECIPIENT,
            MAX_TRACKED_INBOX_RECIPIENTS,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use basis_store::schnorr::{
        build_request_message, inbox_request_message, schnorr_sign, signing_message,
    };
    use basis_store::DenomKey;

    const NOW: u64 = 1_795_305_600; // 2026-11-22T00:00:00Z

    fn key(byte: u8) -> ([u8; 32], PubKey) {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize();
        (sk.secret_bytes(), pk)
    }

    fn token(secret: &[u8; 32], pk: &PubKey, until: u64) -> String {
        hex::encode(schnorr_sign(&inbox_request_message(pk, until), secret, pk).unwrap())
    }

    fn check(pk: &PubKey, until: &str, sig: &str) -> Result<u64, InboxRefusal> {
        verify_inbox_request(pk, Some(until), Some(sig), NOW)
    }

    #[test]
    fn a_good_token_verifies_and_may_be_used_again() {
        let (sk, pk) = key(7);
        let until = NOW + 3600;
        let sig = token(&sk, &pk, until);
        assert_eq!(check(&pk, &until.to_string(), &sig), Ok(until));
        // Replay within validity is allowed: the token only reads.
        assert_eq!(check(&pk, &until.to_string(), &sig), Ok(until));
        // Upper-case hex and surrounding spaces are the same token.
        assert_eq!(
            check(
                &pk,
                &format!(" {until} "),
                &format!(" {} ", sig.to_uppercase())
            ),
            Ok(until)
        );
        // Exactly 24 h ahead is still allowed.
        let edge = NOW + INBOX_MAX_AHEAD_SECS;
        assert_eq!(
            check(&pk, &edge.to_string(), &token(&sk, &pk, edge)),
            Ok(edge)
        );
    }

    #[test]
    fn another_keys_signature_is_refused() {
        let (_, pk) = key(7);
        let (other_sk, other_pk) = key(8);
        let until = NOW + 3600;
        let sig = token(&other_sk, &other_pk, until);
        assert_eq!(
            check(&pk, &until.to_string(), &sig),
            Err(InboxRefusal::BadSignature)
        );
        // Signed by the other key over THIS key's message: still not this key's signature.
        let sig = hex::encode(
            schnorr_sign(&inbox_request_message(&pk, until), &other_sk, &other_pk).unwrap(),
        );
        assert_eq!(
            check(&pk, &until.to_string(), &sig),
            Err(InboxRefusal::BadSignature)
        );
    }

    #[test]
    fn the_signature_binds_valid_until() {
        let (sk, pk) = key(7);
        let sig = token(&sk, &pk, NOW + 3600);
        assert_eq!(
            check(&pk, &(NOW + 3601).to_string(), &sig),
            Err(InboxRefusal::BadSignature)
        );
        // Leading zeros give the same number, hence the same signed message.
        assert_eq!(
            check(&pk, &format!("00{}", NOW + 3600), &sig),
            Ok(NOW + 3600)
        );
    }

    #[test]
    fn expired_and_too_far_ahead_are_refused() {
        let (sk, pk) = key(7);
        for until in [NOW - 1, NOW, 0] {
            assert_eq!(
                check(&pk, &until.to_string(), &token(&sk, &pk, until)),
                Err(InboxRefusal::Expired),
                "{until}"
            );
        }
        for until in [NOW + INBOX_MAX_AHEAD_SECS + 1, u64::MAX] {
            assert_eq!(
                check(&pk, &until.to_string(), &token(&sk, &pk, until)),
                Err(InboxRefusal::TooFarAhead),
                "{until}"
            );
        }
        // Near the end of time the bound saturates instead of wrapping: the time check passes
        // and the (empty) signature is what fails.
        assert_eq!(
            verify_inbox_request(
                &pk,
                Some(&u64::MAX.to_string()),
                Some(&"00".repeat(65)),
                u64::MAX - 10
            ),
            Err(InboxRefusal::BadSignature)
        );
    }

    #[test]
    fn malformed_headers_are_refused() {
        let (sk, pk) = key(7);
        let until = NOW + 3600;
        let sig = token(&sk, &pk, until);
        assert_eq!(
            verify_inbox_request(&pk, None, Some(&sig), NOW),
            Err(InboxRefusal::MissingHeaders)
        );
        assert_eq!(
            verify_inbox_request(&pk, Some(&until.to_string()), None, NOW),
            Err(InboxRefusal::MissingHeaders)
        );
        for bad in [
            "",
            "  ",
            "+1795309200",
            "-1",
            "1795309200.0",
            "0x6b0390",
            "1e9",
            "18446744073709551616",
            "123456789012345678901",
        ] {
            assert_eq!(
                check(&pk, bad, &sig),
                Err(InboxRefusal::BadUntil),
                "{bad:?}"
            );
        }
        for bad in [
            String::new(),
            sig[..128].to_string(),
            format!("{sig}00"),
            format!("{}zz", &sig[..128]),
            format!("0x{}", &sig[..128]),
        ] {
            assert_eq!(
                check(&pk, &until.to_string(), &bad),
                Err(InboxRefusal::BadSignatureEncoding),
                "{bad:?}"
            );
        }
        // 130 hex characters that are no signature at all.
        assert_eq!(
            check(&pk, &until.to_string(), &"00".repeat(65)),
            Err(InboxRefusal::BadSignature)
        );
    }

    /// A signature made for any other message this key signs (a note, a build request) is no
    /// inbox token, and an inbox signature is none of those: the messages differ.
    #[test]
    fn signatures_do_not_cross_between_messages() {
        let (sk, pk) = key(7);
        let (_, other) = key(9);
        let nft = [0x5a; 32];
        let until = NOW + 3600;
        let note = signing_message(&other, &pk, &DenomKey::Erg, 1_000, until, &nft);
        let build = build_request_message(&nft, &other, &pk, &DenomKey::Erg, 1_000, until);
        for message in [&note, &build] {
            let sig = hex::encode(schnorr_sign(message, &sk, &pk).unwrap());
            assert_eq!(
                check(&pk, &until.to_string(), &sig),
                Err(InboxRefusal::BadSignature)
            );
        }
        let inbox = schnorr_sign(&inbox_request_message(&pk, until), &sk, &pk).unwrap();
        for message in [&note, &build] {
            assert!(basis_store::schnorr::schnorr_verify(&inbox, message, &pk).is_err());
        }
    }

    /// The other message a recipient key signs through this tracker is an acceptance policy:
    /// its signed bytes are the policy JSON, which must parse before the signature is looked at.
    /// An inbox message starts with `b`, which starts no JSON value.
    #[test]
    fn an_inbox_message_is_never_a_policy() {
        for seed in [7u8, 8, 9] {
            let (_, pk) = key(seed);
            for until in [0u64, NOW, u64::MAX] {
                let message = inbox_request_message(&pk, until);
                assert!(serde_json::from_slice::<serde_json::Value>(&message).is_err());
                let text = String::from_utf8_lossy(&message);
                assert!(
                    crate::acceptance::validate::parse_and_validate_policy_json(&text).is_err()
                );
            }
        }
    }

    #[test]
    fn the_cap_counts_per_recipient_and_window() {
        let limiter = InboxRateLimiter::new(Duration::from_secs(600), 3, 2);
        let (_, a) = key(1);
        let (_, b) = key(2);
        let (_, c) = key(3);
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        for _ in 0..3 {
            assert!(limiter.try_hit(&a, t0));
        }
        assert!(!limiter.try_hit(&a, at(599)));
        // Another recipient has its own budget.
        assert!(limiter.try_hit(&b, at(10)));
        // The table is full (a, b, both in their window): a third key is served untracked,
        // never refused.
        for _ in 0..5 {
            assert!(limiter.try_hit(&c, at(100)));
        }
        // A new window starts over.
        assert!(limiter.try_hit(&a, at(600)));
        // Once b's window is over, the sweep makes room and c is tracked.
        for _ in 0..3 {
            assert!(limiter.try_hit(&c, at(700)));
        }
        assert!(!limiter.try_hit(&c, at(700)));
    }
}
