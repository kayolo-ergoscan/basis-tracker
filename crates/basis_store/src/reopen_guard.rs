//! Round 7: the interim guard against reopening a reserve after redemptions (follow-up
//! review N9, specs/ergo/reserve_admission.md "Round 7").
//!
//! The reserve contract reads which notes were redeemed, and how much, only from R5 of the
//! reserve box being spent. A reserve box made anew (its owner completed a refund and opened
//! another reserve, with the same NFT or a new one) starts with an empty R5, so every note of
//! that owner and denomination redeemed before could be redeemed from it again. Until a new
//! reserve can carry the redemption history in R5 (upstream PR #27 does it in its own way), this
//! tracker refuses `POST /reserves/create`, and the scanner quarantines a new root reserve box,
//! for an (owner, denomination) pair whose reserve tree at this tracker is not empty.
//!
//! The history is the tracker's reserve trees (`TrackerStateManager`, rebuilt at startup from
//! the `reserve_avl_journal` partition of `data/notes`): exactly what R5 of the pair's reserve
//! held. Only the tracker thread opens `data/notes`, so it publishes the pairs here, and the
//! scanner and the HTTP handlers read them. Until it has (the first moments after a start) the
//! answer is [`ReopenCheck::Unknown`]: a root waits, `/reserves/create` answers 503. It never
//! publishes them when the start could not replay the whole journal (round 7b, review P2-1):
//! the trees may miss redemptions, so the answer stays unknown. A tracked reserve and its
//! successors never ask.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use crate::{DenomKey, PubKey};

/// The reason code of the guard: the start of a quarantine reason, and the `code` of the 409
/// answer of `POST /reserves/create`.
pub const RESERVE_REOPEN_BLOCKED: &str = "reserve_reopen_blocked";

/// What the guard says about a new reserve of an (owner, denomination) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReopenCheck {
    /// The guard is off, or the tracker holds no redemption of the pair.
    Allowed,
    /// The tracker holds redemptions of the pair: a new reserve would start without them.
    Blocked,
    /// The guard is on but the tracker has not published its redemption history: not yet (just
    /// after a start), or not at all (the history is incomplete, round 7b).
    Unknown,
}

/// The (owner, denomination) pairs with redemptions at this tracker, shared by the tracker
/// thread (which writes it) and the scanner and HTTP handlers (which read it). Clones share
/// one state. The default is off.
#[derive(Debug, Clone, Default)]
pub struct ReopenGuard {
    enabled: bool,
    /// `None` until the tracker thread loads it.
    pairs: Arc<RwLock<Option<HashSet<(PubKey, DenomKey)>>>>,
}

impl ReopenGuard {
    /// A guard, on or off (`[server] reserve_reopen_guard`). Its history is unknown until
    /// [`Self::load`].
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            pairs: Arc::default(),
        }
    }

    /// Whether the guard is on.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Publish the pairs with redemptions (the tracker thread, once its reserve trees are
    /// rebuilt). Replaces what was there.
    pub fn load(&self, pairs: impl IntoIterator<Item = (PubKey, DenomKey)>) {
        let pairs: HashSet<_> = pairs.into_iter().collect();
        *self.pairs.write().unwrap_or_else(|e| e.into_inner()) = Some(pairs);
    }

    /// Add a pair with redemptions (the tracker thread, after a reserve tree change). Before
    /// [`Self::load`] it does nothing: the load reads every tree.
    pub fn record(&self, owner: &PubKey, denomination: &DenomKey) {
        if let Some(pairs) = self
            .pairs
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            pairs.insert((*owner, *denomination));
        }
    }

    /// The number of pairs with redemptions, `None` before [`Self::load`].
    pub fn pair_count(&self) -> Option<usize> {
        self.pairs
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(HashSet::len)
    }

    /// May a new reserve of `owner` in `denomination` be opened (created, or admitted as a
    /// root)?
    pub fn check(&self, owner: &PubKey, denomination: &DenomKey) -> ReopenCheck {
        if !self.enabled {
            return ReopenCheck::Allowed;
        }
        match self
            .pairs
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            None => ReopenCheck::Unknown,
            Some(pairs) if pairs.contains(&(*owner, *denomination)) => ReopenCheck::Blocked,
            Some(_) => ReopenCheck::Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guard_answers_by_pair_once_loaded() {
        let owner = [0x02; 33];
        let other = [0x03; 33];
        let token = DenomKey::Token([0x11; 32]);
        let guard = ReopenGuard::new(true);
        assert_eq!(guard.check(&owner, &DenomKey::Erg), ReopenCheck::Unknown);
        guard.record(&owner, &DenomKey::Erg);
        assert_eq!(guard.pair_count(), None, "a record before the load is not kept");

        guard.load([(owner, DenomKey::Erg)]);
        let shared = guard.clone();
        assert_eq!(shared.check(&owner, &DenomKey::Erg), ReopenCheck::Blocked);
        assert_eq!(shared.check(&owner, &token), ReopenCheck::Allowed);
        assert_eq!(shared.check(&other, &DenomKey::Erg), ReopenCheck::Allowed);
        guard.record(&owner, &token);
        assert_eq!(shared.check(&owner, &token), ReopenCheck::Blocked);
        assert_eq!(shared.pair_count(), Some(2));
    }

    /// A signed note of 1 000 from a fixed issuer key to `[0x03; 33]`, in ERG.
    fn issuer_and_note() -> (PubKey, PubKey, crate::IouNote) {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[0x41u8; 32]).unwrap();
        let issuer = secp256k1::PublicKey::from_secret_key(&secp, &secret).serialize();
        let recipient = [0x03u8; 33];
        let note = crate::IouNote::create_and_sign(
            recipient,
            1_000,
            NOTE_TIMESTAMP,
            &secret.secret_bytes(),
            &[0x42; 32],
            DenomKey::Erg,
        )
        .unwrap();
        (issuer, recipient, note)
    }

    const NOTE_TIMESTAMP: u64 = 1_700_000_000_000;

    /// The tracker publishes its pairs from its reserve trees: none on a fresh tracker, none for
    /// a note, the pair once a redemption is applied, and the same from the journal after a
    /// restart; never another denomination or issuer.
    #[test]
    fn the_tracker_publishes_its_redeemed_pairs() {
        let (issuer, recipient, note) = issuer_and_note();
        let erg = DenomKey::Erg;
        let dir = tempfile::tempdir().unwrap();
        {
            let mut redemptions =
                crate::RedemptionManager::new(crate::TrackerStateManager::new(dir.path()));
            let guard = ReopenGuard::new(true);
            redemptions.tracker.attach_reopen_guard(guard.clone());
            assert_eq!(guard.pair_count(), Some(0), "a fresh tracker has no history");
            redemptions.tracker.add_note(&issuer, &note).unwrap();
            assert_eq!(
                guard.check(&issuer, &erg),
                ReopenCheck::Allowed,
                "a note is no redemption"
            );
            redemptions
                .complete_redemption_at(
                    &issuer,
                    &recipient,
                    &erg,
                    300,
                    Some(300),
                    Some(NOTE_TIMESTAMP),
                )
                .unwrap();
            assert_eq!(guard.check(&issuer, &erg), ReopenCheck::Blocked);
            assert_eq!(
                guard.check(&issuer, &DenomKey::Token([0x11; 32])),
                ReopenCheck::Allowed
            );
            assert_eq!(guard.check(&recipient, &erg), ReopenCheck::Allowed);
        }
        let mut restarted = crate::TrackerStateManager::new(dir.path());
        assert_eq!(restarted.reserve_history_gap(), None);
        assert_eq!(restarted.redeemed_reserve_pairs(), vec![(issuer, erg)]);
        let guard = ReopenGuard::new(true);
        restarted.attach_reopen_guard(guard.clone());
        assert_eq!(guard.check(&issuer, &erg), ReopenCheck::Blocked);
        assert_eq!(guard.pair_count(), Some(1));
    }

    /// A repair of the reserve tree towards the chain's R5 (a redemption made without the
    /// tracker, round 6) is history too; a dry run is not.
    #[test]
    fn a_tree_repair_is_history() {
        let (issuer, recipient, note) = issuer_and_note();
        let erg = DenomKey::Erg;
        let dir = tempfile::tempdir().unwrap();
        let mut tracker = crate::TrackerStateManager::new(dir.path());
        let guard = ReopenGuard::new(true);
        tracker.attach_reopen_guard(guard.clone());
        tracker.add_note(&issuer, &note).unwrap();
        let (_, chain) = tracker
            .generate_reserve_insert_proof(&issuer, &recipient, &erg, NOTE_TIMESTAMP, 300)
            .unwrap();
        let chain: [u8; 33] = chain.as_slice().try_into().unwrap();
        let value = crate::ReserveTreeValue {
            timestamp: NOTE_TIMESTAMP,
            already_redeemed: 300,
        };
        let dry = tracker
            .repair_reserve_tree_value(&issuer, &recipient, &erg, value, &chain, true)
            .unwrap();
        assert_eq!(dry.outcome, crate::ReserveTreeRepairOutcome::WouldRepair);
        assert_eq!(guard.check(&issuer, &erg), ReopenCheck::Allowed);
        let repair = tracker
            .repair_reserve_tree_value(&issuer, &recipient, &erg, value, &chain, false)
            .unwrap();
        assert_eq!(repair.outcome, crate::ReserveTreeRepairOutcome::Repaired);
        assert_eq!(guard.check(&issuer, &erg), ReopenCheck::Blocked);
    }

    /// Round 7b (review P2-1): the start cannot replay the whole reserve AVL journal (a
    /// malformed entry, an entry of an unknown note, an entry whose denomination cannot be read
    /// and fails the whole read). The tracker then publishes nothing: the guard stays unknown
    /// for every pair (create answers 503, roots wait), it never opens on a partial history.
    /// The entries it could replay are still in the trees.
    #[test]
    fn an_incomplete_history_keeps_the_guard_closed() {
        let (issuer, recipient, note) = issuer_and_note();
        let erg = DenomKey::Erg;
        let mut full_key = u128::MAX.to_be_bytes().to_vec();
        full_key.extend_from_slice(&issuer);
        full_key.extend_from_slice(&[0x77; 32]);
        let mut bad_denomination = Vec::new();
        bad_denomination.extend_from_slice(&NOTE_TIMESTAMP.to_be_bytes());
        bad_denomination.extend_from_slice(&5u64.to_be_bytes());
        bad_denomination.extend_from_slice(&[0x07; 33]);
        for (case, gap) in [
            ("malformed", "1 malformed"),
            ("unknown note", "1 of an unknown note"),
            ("bad denomination", "could not be read"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            {
                let mut redemptions =
                    crate::RedemptionManager::new(crate::TrackerStateManager::new(dir.path()));
                redemptions.tracker.add_note(&issuer, &note).unwrap();
                redemptions
                    .complete_redemption_at(
                        &issuer,
                        &recipient,
                        &erg,
                        300,
                        Some(300),
                        Some(NOTE_TIMESTAMP),
                    )
                    .unwrap();
                let storage = &redemptions.tracker.storage;
                match case {
                    "malformed" => storage.insert_raw_reserve_avl_journal_entry(&[0xff; 20], &[0; 5]),
                    "unknown note" => storage
                        .append_reserve_avl_update(&issuer, &[0x05; 33], &erg, NOTE_TIMESTAMP, 7)
                        .unwrap(),
                    _ => storage.insert_raw_reserve_avl_journal_entry(&full_key, &bad_denomination),
                }
            }
            let mut restarted = crate::TrackerStateManager::new(dir.path());
            let found = restarted.reserve_history_gap().map(str::to_string);
            assert!(
                found.as_deref().is_some_and(|found| found.contains(gap)),
                "{case}: {found:?}"
            );
            if case != "bad denomination" {
                assert_eq!(
                    restarted.get_already_redeemed(&issuer, &recipient, &erg).unwrap(),
                    300,
                    "{case}"
                );
            }
            let guard = ReopenGuard::new(true);
            restarted.attach_reopen_guard(guard.clone());
            assert_eq!(guard.pair_count(), None, "{case}");
            assert_eq!(guard.check(&issuer, &erg), ReopenCheck::Unknown, "{case}");
            assert_eq!(guard.check(&recipient, &erg), ReopenCheck::Unknown, "{case}");
            // A later redemption does not open it either.
            guard.record(&issuer, &erg);
            assert_eq!(guard.pair_count(), None, "{case}");
            let off = ReopenGuard::new(false);
            restarted.attach_reopen_guard(off.clone());
            assert_eq!(off.check(&issuer, &erg), ReopenCheck::Allowed, "{case}");
        }
    }

    #[test]
    fn an_off_guard_allows_everything() {
        let owner = [0x02; 33];
        let guard = ReopenGuard::new(false);
        assert_eq!(guard.check(&owner, &DenomKey::Erg), ReopenCheck::Allowed);
        guard.load([(owner, DenomKey::Erg)]);
        assert_eq!(guard.check(&owner, &DenomKey::Erg), ReopenCheck::Allowed);
        assert!(!ReopenGuard::default().is_enabled());
    }
}
