//! Redemption state follows the chain (round 5, C8).
//!
//! `/redemption/submit` writes every redemption into the journal (`TrackerStorage`, partition
//! [`basis_store::persistence::REDEMPTION_JOURNAL_PARTITION`]) before it broadcasts it, and no
//! longer applies it to the note and the reserve tree. The confirmer looks at each journaled
//! redemption every [`REDEMPTION_CHECK_INTERVAL`], in the mempools first and then on chain (the
//! order of [`TrackerBoxUpdater::check_transaction_confirmation`]):
//!
//! * in a block and at least `[confirmation] min_depth` deep: applied (`CompleteRedemption`
//!   with the cumulative value the build proved, which is idempotent), then removed from the
//!   journal;
//! * in a mempool, or in a block that is not deep enough yet: kept;
//! * in neither for [`MAX_REDEMPTION_MISSING_CHECKS`] consecutive checks: dropped, never
//!   applied. The note and the reserve tree are as before the build, so the recipient can
//!   build it again;
//! * a node error: kept, and not counted as missing;
//! * applying fails (the tracker's state no longer matches the build): kept with the error,
//!   tried again at every check. Once an operator records it (`/redeem/complete` with the same
//!   cumulative value), the next attempt finds it applied and removes it.
//!
//! While a reserve has a journaled redemption, `/redemption/build` refuses it with 409
//! ([`waiting_redemption`]): a second build would spend the same reserve box, and until the
//! redemption is applied the reserve tree is one redemption behind the chain.
//!
//! The journal is read again at startup, so a restart neither forgets a submitted redemption
//! nor the commit it holds back ([`crate::tracker_box_updater`], round 5 item 3).

use std::time::Duration;

use basis_store::persistence::{JournaledRedemption, TrackerStorage};
use basis_store::{DenomKey, PubKey};
use tracing::{error, info, warn};

use crate::tracker_box_updater::{
    SharedTrackerState, TrackerBoxUpdateConfig, TrackerBoxUpdater, TxStatus,
};
use crate::TrackerCommand;

/// How often the confirmer looks at the journal.
pub const REDEMPTION_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Consecutive checks a journaled redemption may be in neither a mempool nor the chain before
/// it is dropped: about ten minutes at [`REDEMPTION_CHECK_INTERVAL`].
pub const MAX_REDEMPTION_MISSING_CHECKS: u32 = 10;

/// What one pass over the journal did, by transaction id.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    /// Applied to the note and the reserve tree, and removed from the journal.
    pub applied: Vec<String>,
    /// Gone from the mempools and the chain: removed without being applied.
    pub dropped: Vec<String>,
    /// Still journaled.
    pub waiting: Vec<String>,
}

/// Look at the journal every `interval` until `shutdown` fires.
pub async fn run(
    config: TrackerBoxUpdateConfig,
    storage: TrackerStorage,
    shared_state: SharedTrackerState,
    cmd_tx: tokio::sync::mpsc::Sender<TrackerCommand>,
    interval: Duration,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    let mut ticks =
        tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                info!("Redemption confirmer stopped");
                return;
            }
            _ = ticks.tick() => {
                check_journal(&config, &storage, &shared_state, &cmd_tx).await;
            }
        }
    }
}

/// One pass over the journal (see the module documentation).
pub async fn check_journal(
    config: &TrackerBoxUpdateConfig,
    storage: &TrackerStorage,
    shared_state: &SharedTrackerState,
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
) -> CheckOutcome {
    let mut outcome = CheckOutcome::default();
    let entries = match storage.journaled_redemptions() {
        Ok(entries) => entries,
        Err(e) => {
            error!("Cannot read the redemption journal: {:?}", e);
            return outcome;
        }
    };
    for mut entry in entries {
        let tx_id = entry.tx_id.clone();
        match TrackerBoxUpdater::check_transaction_confirmation(config, &tx_id).await {
            Ok(TxStatus::OnChain) => {
                reset_missing(storage, &mut entry);
                match TrackerBoxUpdater::confirmed_deep_enough(config, &tx_id).await {
                    // A failed apply stays journaled; `apply_journaled` recorded and logged it.
                    Ok(true) => {
                        if apply_journaled(storage, shared_state, cmd_tx, &entry)
                            .await
                            .is_ok()
                        {
                            outcome.applied.push(tx_id);
                            continue;
                        }
                    }
                    Ok(false) => {}
                    Err(e) => warn!(
                        "Depth of redemption {} cannot be read ({}); checking again later",
                        tx_id, e
                    ),
                }
            }
            Ok(TxStatus::InMempool) => reset_missing(storage, &mut entry),
            Ok(TxStatus::Missing) => {
                entry.missing_checks = entry.missing_checks.saturating_add(1);
                if entry.missing_checks >= MAX_REDEMPTION_MISSING_CHECKS {
                    warn!(
                        "Redemption {} of {} -> {} ({} in {}) was in neither a mempool nor the chain for {} checks: dropped. The note and the reserve tree are unchanged; the recipient can build it again.",
                        tx_id,
                        entry.issuer_pubkey,
                        entry.recipient_pubkey,
                        entry.redeemed_amount,
                        entry.denomination,
                        entry.missing_checks
                    );
                    forget(storage, shared_state, &tx_id);
                    outcome.dropped.push(tx_id);
                    continue;
                }
                if let Err(e) = storage.journal_redemption(&entry) {
                    error!("Cannot update journaled redemption {}: {:?}", tx_id, e);
                }
            }
            Err(e) => warn!(
                "Status of redemption {} cannot be read ({}); checking again later",
                tx_id, e
            ),
        }
        outcome.waiting.push(tx_id);
    }
    outcome
}

/// Apply a journaled redemption that is in a block, deep enough: `CompleteRedemption` with the
/// cumulative value the build proved (applying it again changes nothing), then remove it from
/// the journal and from the redemptions that hold back a commit. When applying fails, the entry
/// stays with the error, which is logged when it changes.
pub async fn apply_journaled(
    storage: &TrackerStorage,
    shared_state: &SharedTrackerState,
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    entry: &JournaledRedemption,
) -> Result<(), String> {
    let result = complete(cmd_tx, entry).await;
    match result {
        Ok(()) => {
            info!(
                "Redemption {} is on chain: applied {} of {} -> {} in {} (cumulative {})",
                entry.tx_id,
                entry.redeemed_amount,
                entry.issuer_pubkey,
                entry.recipient_pubkey,
                entry.denomination,
                entry.new_already_redeemed
            );
            forget(storage, shared_state, &entry.tx_id);
            Ok(())
        }
        Err(e) => {
            if entry.apply_error.as_deref() != Some(e.as_str()) {
                error!(
                    "Redemption {} is on chain but cannot be applied: {}. It stays journaled (its reserve builds nothing) and is tried again at every check; an operator can record it with POST /redeem/complete and new_already_redeemed {}.",
                    entry.tx_id, e, entry.new_already_redeemed
                );
                let mut failed = entry.clone();
                failed.apply_error = Some(e.clone());
                if let Err(store_error) = storage.journal_redemption(&failed) {
                    error!(
                        "Cannot update journaled redemption {}: {:?}",
                        entry.tx_id, store_error
                    );
                }
            }
            Err(e)
        }
    }
}

/// The journaled redemption that keeps `issuer`'s reserve in `denomination` from building, if
/// one does. The journal holds only redemptions the chain has not confirmed (and applied) yet.
pub fn waiting_redemption(
    storage: &TrackerStorage,
    issuer_hex: &str,
    denomination: &DenomKey,
) -> Result<Option<JournaledRedemption>, String> {
    let wanted = basis_store::normalize_public_key(&issuer_hex.to_ascii_lowercase());
    let denomination = denomination.denomination_id();
    storage
        .journaled_redemptions()
        .map(|entries| {
            entries.into_iter().find(|entry| {
                basis_store::normalize_public_key(&entry.issuer_pubkey.to_ascii_lowercase())
                    == wanted
                    && entry.denomination.eq_ignore_ascii_case(&denomination)
            })
        })
        .map_err(|e| format!("{e:?}"))
}

/// Put the journaled redemptions back among those that hold back a commit (startup): each with
/// its age from the journal, so the deferral limit counts from the submit, not the restart.
pub fn restore_submitted_redemptions(storage: &TrackerStorage, shared_state: &SharedTrackerState) {
    let entries = match storage.journaled_redemptions() {
        Ok(entries) => entries,
        Err(e) => {
            error!("Cannot read the redemption journal at startup: {:?}", e);
            return;
        }
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default();
    for entry in &entries {
        let age = Duration::from_millis(now_ms.saturating_sub(entry.submitted_at_ms));
        let submitted_at = std::time::Instant::now()
            .checked_sub(age)
            .unwrap_or_else(std::time::Instant::now);
        shared_state.record_submitted_redemption_at(
            entry.tx_id.clone(),
            entry.data_input_ids.clone(),
            submitted_at,
        );
    }
    if !entries.is_empty() {
        info!(
            "{} submitted redemption(s) wait for the chain (redemption journal)",
            entries.len()
        );
    }
}

async fn complete(
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    entry: &JournaledRedemption,
) -> Result<(), String> {
    let key = |hex_key: &str, what: &str| -> Result<PubKey, String> {
        hex::decode(hex_key)
            .ok()
            .and_then(|bytes| PubKey::try_from(bytes.as_slice()).ok())
            .ok_or_else(|| format!("the journaled {what} key {hex_key:?} is not a 33-byte key"))
    };
    let issuer_pubkey = key(&entry.issuer_pubkey, "issuer")?;
    let recipient_pubkey = key(&entry.recipient_pubkey, "recipient")?;
    let denomination = DenomKey::parse(&entry.denomination)
        .map_err(|e| format!("the journaled denomination {:?}: {e}", entry.denomination))?;
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCommand::CompleteRedemption {
            issuer_pubkey,
            recipient_pubkey,
            denomination,
            redeemed_amount: entry.redeemed_amount,
            new_already_redeemed: Some(entry.new_already_redeemed),
            response_tx,
        })
        .await
        .map_err(|_| "the tracker thread is unavailable".to_string())?;
    match response_rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("{e:?}")),
        Err(_) => Err("the tracker thread did not answer".to_string()),
    }
}

/// Remove `tx_id` from the journal and from the redemptions that hold back a commit.
fn forget(storage: &TrackerStorage, shared_state: &SharedTrackerState, tx_id: &str) {
    if let Err(e) = storage.remove_journaled_redemption(tx_id) {
        error!("Cannot remove journaled redemption {}: {:?}", tx_id, e);
    }
    shared_state.forget_submitted_redemptions(&[tx_id.to_string()]);
}

fn reset_missing(storage: &TrackerStorage, entry: &mut JournaledRedemption) {
    if entry.missing_checks > 0 {
        entry.missing_checks = 0;
        if let Err(e) = storage.journal_redemption(entry) {
            error!("Cannot update journaled redemption {}: {:?}", entry.tx_id, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const TX: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";

    /// Where the mock node has a transaction: (in the mempool, inclusion height in a block).
    #[derive(Default)]
    struct Chain {
        mempool: bool,
        included_at: Option<u64>,
        broken: bool,
    }

    struct Fixture {
        config: TrackerBoxUpdateConfig,
        storage: TrackerStorage,
        shared: SharedTrackerState,
        cmd_tx: tokio::sync::mpsc::Sender<TrackerCommand>,
        chain: Arc<Mutex<HashMap<String, Chain>>>,
        height: Arc<AtomicU64>,
        applied: Arc<AtomicUsize>,
        issuer: PubKey,
        recipient: PubKey,
        add_note: tokio::sync::mpsc::Sender<()>,
        _dir: tempfile::TempDir,
    }

    /// A mock node on 127.0.0.1 that knows the transactions in `chain`, and a tracker thread
    /// with a real `RedemptionManager` that answers `CompleteRedemption` and counts the
    /// successful ones. The note of 1000 from the issuer to the recipient exists unless
    /// `with_note` is false; a message on `add_note` adds it.
    async fn fixture(with_note: bool) -> Fixture {
        use crate::local_wallet::tests::mock_node;
        let chain: Arc<Mutex<HashMap<String, Chain>>> = Arc::default();
        let height = Arc::new(AtomicU64::new(1_000));
        let (node_chain, node_height) = (chain.clone(), height.clone());
        let (url, _seen) = mock_node(move |method, target, _body| {
            let not_found = (404, r#"{"error":404,"reason":"not-found"}"#.to_string());
            let chain = node_chain.lock().unwrap();
            if method == "GET" && target == "/info" {
                return (
                    200,
                    serde_json::json!({ "fullHeight": node_height.load(Ordering::SeqCst) })
                        .to_string(),
                );
            }
            if let Some(id) = target.strip_prefix("/transactions/unconfirmed/byTransactionId/") {
                return match chain.get(id) {
                    Some(c) if c.broken => (500, "{}".to_string()),
                    Some(c) if c.mempool => (200, serde_json::json!({ "id": id }).to_string()),
                    _ => not_found,
                };
            }
            if let Some(id) = target.strip_prefix("/blockchain/transaction/byId/") {
                return match chain.get(id).and_then(|c| c.included_at) {
                    Some(h) => (
                        200,
                        serde_json::json!({ "id": id, "inclusionHeight": h, "outputs": [] })
                            .to_string(),
                    ),
                    None => not_found,
                };
            }
            not_found
        })
        .await;

        let (secret, issuer) = basis_store::schnorr::generate_keypair();
        let recipient = basis_store::schnorr::generate_keypair().1;
        let note = basis_store::IouNote::create_and_sign(
            recipient,
            1_000,
            1_700_000_000_000,
            &secret,
            &[0x42; 32],
            DenomKey::Erg,
        )
        .unwrap();
        let applied = Arc::new(AtomicUsize::new(0));
        let thread_applied = applied.clone();
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<TrackerCommand>(16);
        let (add_note, mut add_note_rx) = tokio::sync::mpsc::channel::<()>(1);
        std::thread::spawn(move || {
            let mut manager = basis_store::RedemptionManager::new(
                basis_store::TrackerStateManager::new_with_temp_storage(),
            );
            if with_note {
                manager.tracker.add_note(&issuer, &note).unwrap();
            }
            while let Some(cmd) = cmd_rx.blocking_recv() {
                if add_note_rx.try_recv().is_ok() {
                    manager.tracker.add_note(&issuer, &note).unwrap();
                }
                match cmd {
                    TrackerCommand::CompleteRedemption {
                        issuer_pubkey,
                        recipient_pubkey,
                        denomination,
                        redeemed_amount,
                        new_already_redeemed,
                        response_tx,
                    } => {
                        let before = manager
                            .tracker
                            .get_note_optional(&issuer_pubkey, &recipient_pubkey, &denomination)
                            .unwrap()
                            .map(|n| n.amount_redeemed);
                        let result = manager.complete_redemption(
                            &issuer_pubkey,
                            &recipient_pubkey,
                            &denomination,
                            redeemed_amount,
                            new_already_redeemed,
                        );
                        let after = manager
                            .tracker
                            .get_note_optional(&issuer_pubkey, &recipient_pubkey, &denomination)
                            .unwrap()
                            .map(|n| n.amount_redeemed);
                        if result.is_ok() && before != after {
                            thread_applied.fetch_add(1, Ordering::SeqCst);
                        }
                        let _ = response_tx.send(result);
                    }
                    TrackerCommand::Shutdown => break,
                    _ => {}
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let storage = TrackerStorage::open(dir.path()).unwrap();
        let config = TrackerBoxUpdateConfig {
            scanner_node_url: url.clone(),
            wallet_node_url: url,
            min_confirmation_depth: 2,
            ..Default::default()
        };
        Fixture {
            config,
            storage,
            shared: SharedTrackerState::new(),
            cmd_tx,
            chain,
            height,
            applied,
            issuer,
            recipient,
            add_note,
            _dir: dir,
        }
    }

    impl Fixture {
        /// Journal a redemption of 300 (cumulative 300) as `/redemption/submit` does.
        fn journal(&self, tx_id: &str) {
            let entry = JournaledRedemption {
                tx_id: tx_id.to_string(),
                reserve_box_id: "ab".repeat(32),
                issuer_pubkey: hex::encode(self.issuer),
                recipient_pubkey: hex::encode(self.recipient),
                denomination: DenomKey::Erg.denomination_id(),
                redeemed_amount: 300,
                new_already_redeemed: 300,
                data_input_ids: vec!["cd".repeat(32)],
                submitted_at_ms: 1,
                missing_checks: 0,
                apply_error: None,
            };
            self.storage.journal_redemption(&entry).unwrap();
            self.shared
                .record_submitted_redemption(tx_id.to_string(), entry.data_input_ids);
        }

        fn set(&self, tx_id: &str, chain: Chain) {
            self.chain.lock().unwrap().insert(tx_id.to_string(), chain);
        }

        async fn check(&self) -> CheckOutcome {
            check_journal(&self.config, &self.storage, &self.shared, &self.cmd_tx).await
        }

        fn journaled(&self) -> Vec<JournaledRedemption> {
            self.storage.journaled_redemptions().unwrap()
        }
    }

    /// In the mempool, then in a block one deep: kept, nothing applied. Two deep: applied once,
    /// removed from the journal and from the redemptions that hold back a commit.
    #[tokio::test]
    async fn a_redemption_is_applied_once_it_is_deep_enough_in_a_block() {
        let fx = fixture(true).await;
        fx.journal(TX);
        fx.set(
            TX,
            Chain {
                mempool: true,
                ..Default::default()
            },
        );
        assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        fx.set(
            TX,
            Chain {
                included_at: Some(1_000),
                ..Default::default()
            },
        );
        assert_eq!(fx.check().await.waiting, vec![TX.to_string()], "depth 1 of 2");
        assert_eq!(fx.applied.load(Ordering::SeqCst), 0);
        assert_eq!(fx.shared.get_submitted_redemptions().len(), 1);

        fx.height.store(1_001, Ordering::SeqCst);
        let outcome = fx.check().await;
        assert_eq!(outcome.applied, vec![TX.to_string()]);
        assert_eq!(fx.applied.load(Ordering::SeqCst), 1);
        assert!(fx.journaled().is_empty());
        assert!(fx.shared.get_submitted_redemptions().is_empty());
        assert_eq!(fx.check().await, CheckOutcome::default());
    }

    /// Missing for fewer than the limit: kept and counted (the count is stored); seen in a
    /// mempool again: the count starts over. Missing for the limit: dropped, never applied.
    #[tokio::test]
    async fn a_redemption_missing_for_ten_checks_is_dropped_unapplied() {
        let fx = fixture(true).await;
        fx.journal(TX);
        for _ in 0..MAX_REDEMPTION_MISSING_CHECKS - 1 {
            assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        }
        assert_eq!(fx.journaled()[0].missing_checks, MAX_REDEMPTION_MISSING_CHECKS - 1);
        fx.set(
            TX,
            Chain {
                mempool: true,
                ..Default::default()
            },
        );
        fx.check().await;
        assert_eq!(fx.journaled()[0].missing_checks, 0);
        fx.set(TX, Chain::default());
        for _ in 0..MAX_REDEMPTION_MISSING_CHECKS - 1 {
            assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        }
        let outcome = fx.check().await;
        assert_eq!(outcome.dropped, vec![TX.to_string()]);
        assert!(fx.journaled().is_empty());
        assert!(fx.shared.get_submitted_redemptions().is_empty());
        assert_eq!(fx.applied.load(Ordering::SeqCst), 0);
    }

    /// A node error is not a missing check: the redemption stays, uncounted.
    #[tokio::test]
    async fn a_node_error_keeps_the_redemption_uncounted() {
        let fx = fixture(true).await;
        fx.journal(TX);
        fx.set(
            TX,
            Chain {
                broken: true,
                ..Default::default()
            },
        );
        for _ in 0..MAX_REDEMPTION_MISSING_CHECKS + 1 {
            assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        }
        assert_eq!(fx.journaled()[0].missing_checks, 0);
        assert_eq!(fx.applied.load(Ordering::SeqCst), 0);
    }

    /// A redemption on chain that cannot be applied stays journaled with the error and is tried
    /// again; once the tracker can apply it, it is applied and removed.
    #[tokio::test]
    async fn a_redemption_that_cannot_be_applied_stays_and_is_tried_again() {
        let fx = fixture(false).await;
        fx.journal(TX);
        fx.set(
            TX,
            Chain {
                included_at: Some(990),
                ..Default::default()
            },
        );
        assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        let kept = fx.journaled();
        assert!(
            kept[0].apply_error.as_deref().unwrap_or("").contains("NoteNotFound"),
            "{kept:?}"
        );
        assert!(waiting_redemption(&fx.storage, &hex::encode(fx.issuer), &DenomKey::Erg)
            .unwrap()
            .is_some());

        fx.add_note.send(()).await.unwrap();
        assert_eq!(fx.check().await.applied, vec![TX.to_string()]);
        assert_eq!(fx.applied.load(Ordering::SeqCst), 1);
        assert!(fx.journaled().is_empty());
    }

    /// The journal names the reserve that waits: by issuer (normalized) and denomination.
    #[tokio::test]
    async fn waiting_redemption_matches_issuer_and_denomination() {
        let fx = fixture(true).await;
        let issuer = hex::encode(fx.issuer);
        assert!(waiting_redemption(&fx.storage, &issuer, &DenomKey::Erg)
            .unwrap()
            .is_none());
        fx.journal(TX);
        for key in [
            issuer.clone(),
            issuer.to_ascii_uppercase(),
            format!("07{issuer}"),
        ] {
            let waiting = waiting_redemption(&fx.storage, &key, &DenomKey::Erg).unwrap();
            assert_eq!(waiting.map(|w| w.tx_id), Some(TX.to_string()), "{key}");
        }
        assert!(
            waiting_redemption(&fx.storage, &issuer, &DenomKey::Token([0x7c; 32]))
                .unwrap()
                .is_none()
        );
        assert!(
            waiting_redemption(&fx.storage, &hex::encode([0x02; 33]), &DenomKey::Erg)
                .unwrap()
                .is_none()
        );
    }

    /// At startup the journal refills the redemptions that hold back a commit, with their age.
    #[tokio::test]
    async fn the_journal_refills_the_commit_deferral_at_startup() {
        let fx = fixture(true).await;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut entry = JournaledRedemption {
            tx_id: TX.to_string(),
            reserve_box_id: "ab".repeat(32),
            issuer_pubkey: hex::encode(fx.issuer),
            recipient_pubkey: hex::encode(fx.recipient),
            denomination: "erg".to_string(),
            redeemed_amount: 300,
            new_already_redeemed: 300,
            data_input_ids: vec!["cd".repeat(32)],
            submitted_at_ms: now_ms - 5 * 60_000,
            missing_checks: 0,
            apply_error: None,
        };
        fx.storage.journal_redemption(&entry).unwrap();
        entry.tx_id = "8b".repeat(32);
        entry.submitted_at_ms = now_ms;
        fx.storage.journal_redemption(&entry).unwrap();

        let fresh = SharedTrackerState::new();
        restore_submitted_redemptions(&fx.storage, &fresh);
        let restored = fresh.get_submitted_redemptions();
        assert_eq!(restored.len(), 2);
        let old = restored.iter().find(|r| r.tx_id == TX).unwrap();
        assert_eq!(old.data_input_ids, vec!["cd".repeat(32)]);
        assert!(old.submitted_at.elapsed() >= Duration::from_secs(5 * 60 - 1));
        let new = restored.iter().find(|r| r.tx_id != TX).unwrap();
        assert!(new.submitted_at.elapsed() < Duration::from_secs(60));
    }
}
