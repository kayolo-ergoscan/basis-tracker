//! Redemption state follows the chain (round 5, C8; round 5b).
//!
//! `/redemption/submit` writes every redemption into the journal (`TrackerStorage`, partition
//! [`basis_store::persistence::REDEMPTION_JOURNAL_PARTITION`]) before it broadcasts it, and no
//! longer applies it to the note and the reserve tree. The confirmer looks at each journaled
//! redemption every [`REDEMPTION_CHECK_INTERVAL`], in the mempools first and then on chain (the
//! order of [`TrackerBoxUpdater::check_transaction_confirmation`]):
//!
//! * in a block and at least `[confirmation] min_depth` deep: applied (`CompleteRedemption`
//!   with the cumulative value and the reserve tree timestamp the build proved, which is
//!   idempotent), then removed from the journal. After the apply, the tracker's reserve tree
//!   digest is compared with R5 of the mined transaction's reserve output (round 5b, F1); when
//!   they differ, the error is logged and the entry stays, marked (`digest_mismatch`), so its
//!   reserve builds nothing until an operator has looked at it;
//! * in a mempool, or in a block that is not deep enough yet: kept;
//! * in neither: kept while it can still be mined (round 5b, F4). After
//!   [`MAX_REDEMPTION_MISSING_CHECKS`] consecutive such checks it is looked at every
//!   [`SLOW_CHECK_INTERVAL`] only, and dropped, never applied, once it can no longer be mined:
//!   its reserve box is spent by another transaction, or the tracker box it reads as a data
//!   input is spent by a confirmed commit. A reserve box spent by a transaction the index does
//!   not name yet (an index that lags behind the chain) keeps it;
//! * a node error: kept, and not counted as missing;
//! * applying fails (the tracker's state no longer matches the build): kept with the error,
//!   tried again at every check. Once an operator records it (`/redeem/complete` with the same
//!   cumulative value and timestamp), the next attempt finds it applied and removes it.
//!
//! Every write-back of an entry is a compare-and-set (round 5b, F8): an entry removed meanwhile
//! (refused at submit, dropped or applied by an operator) is not brought back.
//!
//! While a reserve has a journaled redemption, `/redemption/build` refuses it with 409
//! ([`waiting_redemption`]): a second build would spend the same reserve box, and until the
//! redemption is applied the reserve tree is one redemption behind the chain.
//! `/notes/exchange` refuses the issuer's two reserves the same way (round 5b, F5).
//!
//! An operator lists, drops and applies journal entries through the admin routes
//! `GET /redemption/journal`, `POST /redemption/journal/drop` and
//! `POST /redemption/journal/apply` ([`list_journal`], [`drop_journal_entry`],
//! [`apply_journal_entry`]; round 5b, F6).
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
/// it is looked at more closely (can it still be mined?) and more slowly: about ten minutes at
/// [`REDEMPTION_CHECK_INTERVAL`].
pub const MAX_REDEMPTION_MISSING_CHECKS: u32 = 10;

/// How often a redemption missing for [`MAX_REDEMPTION_MISSING_CHECKS`] checks that can still
/// be mined is looked at (round 5b, F4).
pub const SLOW_CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// What one pass over the journal did, by transaction id.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    /// Applied to the note and the reserve tree, and removed from the journal.
    pub applied: Vec<String>,
    /// Applied, but the tracker's reserve tree did not match the mined transaction's R5: kept,
    /// marked for an operator (round 5b, F1).
    pub mismatched: Vec<String>,
    /// Can no longer be mined: removed without being applied.
    pub dropped: Vec<String>,
    /// Still journaled.
    pub waiting: Vec<String>,
}

/// How a redemption the confirmer applied compared with the chain (round 5b, F1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// The tracker's reserve tree digest is the R5 of the reserve output (or there was nothing
    /// to compare with): removed from the journal.
    Matching,
    /// The digests differ: kept in the journal, marked (`digest_mismatch`).
    Mismatch,
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
    let now_ms = unix_ms();
    for mut entry in entries {
        let tx_id = entry.tx_id.clone();
        // Applied, but out of step with the chain: an operator's (GET /redemption/journal).
        // Not due yet: a long-missing redemption that can still be mined.
        if entry.digest_mismatch.is_some() || entry.next_check_at_ms > now_ms {
            outcome.waiting.push(tx_id);
            continue;
        }
        match TrackerBoxUpdater::check_transaction_confirmation(config, &tx_id).await {
            Ok(TxStatus::OnChain) => {
                reset_missing(storage, &mut entry);
                match TrackerBoxUpdater::confirmed_first_output_r5(config, &tx_id).await {
                    // A failed apply stays journaled; `apply_journaled_against` recorded and
                    // logged it.
                    Ok(Some(chain_r5)) => {
                        match apply_journaled_against(
                            storage,
                            shared_state,
                            cmd_tx,
                            &entry,
                            chain_r5.as_deref(),
                        )
                        .await
                        {
                            Ok(Applied::Matching) => {
                                outcome.applied.push(tx_id);
                                continue;
                            }
                            Ok(Applied::Mismatch) => {
                                outcome.mismatched.push(tx_id);
                                continue;
                            }
                            Err(_) => {}
                        }
                    }
                    Ok(None) => {}
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
                    match fate(config, shared_state, &entry).await {
                        Ok(Fate::CannotBeMined(why)) => {
                            warn!(
                                "Redemption {} of {} -> {} ({} in {}) can no longer be mined: {}. Dropped: nothing was applied, the note and the reserve tree are as before the build, and the reserve can be built against again.",
                                tx_id,
                                entry.issuer_pubkey,
                                entry.recipient_pubkey,
                                entry.redeemed_amount,
                                entry.denomination,
                                why
                            );
                            forget(storage, shared_state, &tx_id);
                            outcome.dropped.push(tx_id);
                            continue;
                        }
                        Ok(Fate::CanStillBeMined(why)) => {
                            let log = format!(
                                "Redemption {} was in neither a mempool nor the chain for {} checks, but it can still be mined: {}. It stays journaled (its reserve builds nothing) and is looked at every {} minutes.",
                                tx_id,
                                entry.missing_checks,
                                why,
                                SLOW_CHECK_INTERVAL.as_secs() / 60
                            );
                            if entry.missing_checks == MAX_REDEMPTION_MISSING_CHECKS {
                                warn!("{log}");
                            } else {
                                info!("{log}");
                            }
                        }
                        Err(e) => warn!(
                            "Whether redemption {} can still be mined cannot be read ({}); it stays journaled",
                            tx_id, e
                        ),
                    }
                    entry.next_check_at_ms = now_ms.saturating_add(
                        u64::try_from(SLOW_CHECK_INTERVAL.as_millis()).unwrap_or(u64::MAX),
                    );
                }
                write_back(storage, &entry);
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

/// Whether a redemption found in neither a mempool nor the chain can still be mined (round 5b,
/// F4), and why.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fate {
    CanStillBeMined(String),
    CannotBeMined(String),
}

/// See [`Fate`]. A redemption can no longer be mined once its reserve box is spent by another
/// transaction (the spender the blockchain index names), or once the tracker box it reads as a
/// data input is spent by a confirmed commit (the tracker's confirmed box is another one, and
/// the data input is out of the UTXO set). A reserve box out of the UTXO set whose spender the
/// index does not name yet may be spent by this very redemption, in a block the index has not
/// reached: it can still be applied, so it is kept.
async fn fate(
    config: &TrackerBoxUpdateConfig,
    shared_state: &SharedTrackerState,
    entry: &JournaledRedemption,
) -> Result<Fate, String> {
    if !TrackerBoxUpdater::box_is_unspent(config, &entry.reserve_box_id)
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(
            match TrackerBoxUpdater::box_spent_by(config, &entry.reserve_box_id)
                .await
                .map_err(|e| e.to_string())?
            {
                Some(spender) if spender.eq_ignore_ascii_case(&entry.tx_id) => {
                    Fate::CanStillBeMined(format!(
                        "its reserve box {} is spent by it; the transaction lookup has not caught up yet",
                        entry.reserve_box_id
                    ))
                }
                Some(spender) => Fate::CannotBeMined(format!(
                    "its reserve box {} is spent by transaction {}",
                    entry.reserve_box_id, spender
                )),
                None => Fate::CanStillBeMined(format!(
                    "its reserve box {} is spent by a transaction the blockchain index does not name yet",
                    entry.reserve_box_id
                )),
            },
        );
    }
    let Some(confirmed_box) = shared_state.get_confirmed().box_id else {
        return Ok(Fate::CanStillBeMined(
            "its reserve box is unspent, and the tracker's confirmed box is not known yet"
                .to_string(),
        ));
    };
    for data_input in &entry.data_input_ids {
        if data_input.eq_ignore_ascii_case(&confirmed_box) {
            continue;
        }
        if !TrackerBoxUpdater::box_is_unspent(config, data_input)
            .await
            .map_err(|e| e.to_string())?
        {
            return Ok(Fate::CannotBeMined(format!(
                "the tracker box {} it reads is spent by a confirmed commit (the tracker box is {} now)",
                data_input, confirmed_box
            )));
        }
    }
    Ok(Fate::CanStillBeMined(
        "its reserve box is unspent and the tracker box it reads is not spent by a confirmed commit"
            .to_string(),
    ))
}

/// Apply a journaled redemption that is in a block, deep enough, without the chain's R5 to
/// compare with: [`apply_journaled_against`] with the digest journaled at submit. Applied with a
/// matching reserve tree is `Ok`; a mismatch (the entry stays, marked) or a failed apply is an
/// error.
pub async fn apply_journaled(
    storage: &TrackerStorage,
    shared_state: &SharedTrackerState,
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    entry: &JournaledRedemption,
) -> Result<(), String> {
    match apply_journaled_against(storage, shared_state, cmd_tx, entry, None).await? {
        Applied::Matching => Ok(()),
        Applied::Mismatch => Err(format!(
            "redemption {} is applied, but the tracker's reserve tree differs from its R5",
            entry.tx_id
        )),
    }
}

/// Apply a journaled redemption that is in a block, deep enough: `CompleteRedemption` with the
/// cumulative value and the reserve tree timestamp the build proved (applying it again changes
/// nothing). Then the tracker's reserve tree digest is compared with `chain_r5` (the R5 register
/// of the mined transaction's reserve output) or, without it, the digest journaled at submit
/// (round 5b, F1): matching, the entry leaves the journal and the redemptions that hold back a
/// commit; differing, the error is logged and the entry stays, marked. When applying fails, the
/// entry stays with the error, which is logged when it changes.
pub async fn apply_journaled_against(
    storage: &TrackerStorage,
    shared_state: &SharedTrackerState,
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    entry: &JournaledRedemption,
    chain_r5: Option<&str>,
) -> Result<Applied, String> {
    if let Err(e) = complete(cmd_tx, entry).await {
        if entry.apply_error.as_deref() != Some(e.as_str()) {
            error!(
                "Redemption {} is on chain but cannot be applied: {}. It stays journaled (its reserve builds nothing) and is tried again at every check; an operator can record it with POST /redeem/complete (new_already_redeemed {}, reserve_tree_timestamp {:?}), apply it with POST /redemption/journal/apply, or drop it with POST /redemption/journal/drop.",
                entry.tx_id, e, entry.new_already_redeemed, entry.reserve_tree_timestamp
            );
            let mut failed = entry.clone();
            failed.apply_error = Some(e.clone());
            write_back(storage, &failed);
        }
        return Err(e);
    }

    let expected = chain_r5
        .and_then(r5_digest_hex)
        .or_else(|| entry.reserve_r5_digest.clone());
    let tracker = reserve_digest(cmd_tx, entry).await;
    match (expected, tracker) {
        (Some(expected), Ok(tracker)) if !expected.eq_ignore_ascii_case(&tracker) => {
            error!(
                "Redemption {} is applied ({} of {} -> {} in {}, cumulative {}), but the tracker's reserve tree digest {} differs from {} in R5 of its reserve output: the tracker's reserve tree is out of step with the chain, and builds against this reserve would fail. The entry stays journaled, marked, so the reserve builds nothing until an operator has looked at it (GET /redemption/journal; POST /redemption/journal/drop).",
                entry.tx_id,
                entry.redeemed_amount,
                entry.issuer_pubkey,
                entry.recipient_pubkey,
                entry.denomination,
                entry.new_already_redeemed,
                tracker,
                expected
            );
            let mut marked = entry.clone();
            marked.apply_error = None;
            marked.digest_mismatch = Some(format!(
                "tracker reserve tree digest {tracker}, R5 of the reserve output {expected}"
            ));
            write_back(storage, &marked);
            // Applied: it no longer holds back a commit.
            shared_state.forget_submitted_redemptions(std::slice::from_ref(&entry.tx_id));
            Ok(Applied::Mismatch)
        }
        (expected, tracker) => {
            match (&expected, &tracker) {
                (None, _) => warn!(
                    "Redemption {}: no R5 digest to compare the tracker's reserve tree with",
                    entry.tx_id
                ),
                (_, Err(e)) => warn!(
                    "Redemption {}: the tracker's reserve tree digest cannot be read ({}); not compared",
                    entry.tx_id, e
                ),
                _ => {}
            }
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
            Ok(Applied::Matching)
        }
    }
}

/// The 33-byte digest (hex, lower case) in a serialized AVL tree register value
/// (`0x64 || digest || flags || key length || value length`), if it is one.
pub fn r5_digest_hex(r5: &str) -> Option<String> {
    (r5.len() >= 68 && r5.starts_with("64") && r5.is_char_boundary(68))
        .then(|| r5[2..68].to_ascii_lowercase())
        .filter(|digest| digest.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The journaled redemption that keeps `issuer`'s reserve in `denomination` from building, if
/// one does. The journal holds only redemptions the chain has not confirmed (and applied) yet,
/// and applied ones marked for an operator (round 5b, F1).
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

/// Why `waiting` keeps its reserve from building or exchanging (the 409's reason).
pub fn waiting_reason(waiting: &JournaledRedemption) -> String {
    match &waiting.digest_mismatch {
        Some(mismatch) => format!(
            "redemption {} is applied, but the tracker's reserve tree is out of step with the \
             chain ({}); an operator has to look at it before the reserve is used again",
            waiting.tx_id, mismatch
        ),
        None => format!(
            "redemption {} is waiting for the chain; try again once it is confirmed, or once it \
             can no longer be mined (its reserve box spent by another transaction, or the \
             tracker box it reads replaced by a confirmed commit)",
            waiting.tx_id
        ),
    }
}

/// Put the journaled redemptions back among those that hold back a commit (startup): each with
/// its age from the journal, so the deferral limit counts from the submit, not the restart.
/// Entries marked after their apply (round 5b, F1) are mined and hold nothing back.
pub fn restore_submitted_redemptions(storage: &TrackerStorage, shared_state: &SharedTrackerState) {
    let entries = match storage.journaled_redemptions() {
        Ok(entries) => entries,
        Err(e) => {
            error!("Cannot read the redemption journal at startup: {:?}", e);
            return;
        }
    };
    let now_ms = unix_ms();
    let waiting: Vec<&JournaledRedemption> = entries
        .iter()
        .filter(|entry| entry.digest_mismatch.is_none())
        .collect();
    for entry in &waiting {
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
    if !waiting.is_empty() {
        info!(
            "{} submitted redemption(s) wait for the chain (redemption journal)",
            waiting.len()
        );
    }
    let marked = entries.len() - waiting.len();
    if marked > 0 {
        warn!(
            "{} applied redemption(s) are marked: the tracker's reserve tree was out of step with the chain after them (GET /redemption/journal)",
            marked
        );
    }
}

fn journal_keys(entry: &JournaledRedemption) -> Result<(PubKey, PubKey, DenomKey), String> {
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
    Ok((issuer_pubkey, recipient_pubkey, denomination))
}

async fn complete(
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    entry: &JournaledRedemption,
) -> Result<(), String> {
    let (issuer_pubkey, recipient_pubkey, denomination) = journal_keys(entry)?;
    if entry.reserve_tree_timestamp.is_none() {
        warn!(
            "Redemption {} was journaled without its reserve tree timestamp: it is applied with the note's current timestamp",
            entry.tx_id
        );
    }
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCommand::CompleteRedemption {
            issuer_pubkey,
            recipient_pubkey,
            denomination,
            redeemed_amount: entry.redeemed_amount,
            new_already_redeemed: Some(entry.new_already_redeemed),
            reserve_tree_timestamp: entry.reserve_tree_timestamp,
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

/// The tracker's reserve tree digest (hex) of `entry`'s issuer and denomination.
async fn reserve_digest(
    cmd_tx: &tokio::sync::mpsc::Sender<TrackerCommand>,
    entry: &JournaledRedemption,
) -> Result<String, String> {
    let (issuer_pubkey, _, denomination) = journal_keys(entry)?;
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    cmd_tx
        .send(TrackerCommand::GetReserveStateDigest {
            issuer_pubkey,
            denomination,
            response_tx,
        })
        .await
        .map_err(|_| "the tracker thread is unavailable".to_string())?;
    response_rx
        .await
        .map(hex::encode)
        .map_err(|_| "the tracker thread did not answer".to_string())
}

/// Remove `tx_id` from the journal and from the redemptions that hold back a commit.
pub(crate) fn forget(storage: &TrackerStorage, shared_state: &SharedTrackerState, tx_id: &str) {
    if let Err(e) = storage.remove_journaled_redemption(tx_id) {
        error!("Cannot remove journaled redemption {}: {:?}", tx_id, e);
    }
    shared_state.forget_submitted_redemptions(&[tx_id.to_string()]);
}

/// Write back `entry`, read from the journal earlier, unless it was removed meanwhile (round 5b,
/// F8).
fn write_back(storage: &TrackerStorage, entry: &JournaledRedemption) {
    match storage.update_journaled_redemption(entry) {
        Ok(true) => {}
        Ok(false) => info!(
            "Redemption {} left the journal meanwhile; not written back",
            entry.tx_id
        ),
        Err(e) => error!("Cannot update journaled redemption {}: {:?}", entry.tx_id, e),
    }
}

fn reset_missing(storage: &TrackerStorage, entry: &mut JournaledRedemption) {
    if entry.missing_checks > 0 || entry.next_check_at_ms > 0 {
        entry.missing_checks = 0;
        entry.next_check_at_ms = 0;
        write_back(storage, entry);
    }
}

/// Body of `POST /redemption/journal/drop` and `POST /redemption/journal/apply` (round 5b, F6).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JournalEntryRequest {
    /// The journaled redemption's transaction id (64 hex characters, any case).
    pub tx_id: String,
}

type JournalAnswer<T> = (
    axum::http::StatusCode,
    axum::Json<crate::models::ApiResponse<T>>,
);

fn journal_error<T>(status: axum::http::StatusCode, message: impl Into<String>) -> JournalAnswer<T> {
    (status, axum::Json(crate::models::error_response(message.into())))
}

/// The journal entry `tx_id` names, or the answer when there is none.
fn requested_entry<T>(
    storage: &TrackerStorage,
    tx_id: &str,
) -> Result<JournaledRedemption, JournalAnswer<T>> {
    use axum::http::StatusCode;
    if tx_id.len() != 64 || !tx_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(journal_error(
            StatusCode::BAD_REQUEST,
            "tx_id must be a transaction id (64 hex characters)",
        ));
    }
    match storage.journaled_redemption(tx_id) {
        Ok(Some(entry)) => Ok(entry),
        Ok(None) => Err(journal_error(
            StatusCode::NOT_FOUND,
            format!("no journaled redemption {}", tx_id.to_ascii_lowercase()),
        )),
        Err(e) => {
            error!("Cannot read the redemption journal: {:?}", e);
            Err(journal_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the tracker cannot read its redemption journal",
            ))
        }
    }
}

/// `GET /redemption/journal` (Admin; round 5b, F6): every journaled redemption, those waiting
/// for the chain and those marked after their apply (`digest_mismatch`), in key order.
pub async fn list_journal(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
) -> JournalAnswer<Vec<JournaledRedemption>> {
    match state.tracker_storage.journaled_redemptions() {
        Ok(entries) => (
            axum::http::StatusCode::OK,
            axum::Json(crate::models::success_response(entries)),
        ),
        Err(e) => {
            error!("Cannot read the redemption journal: {:?}", e);
            journal_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "the tracker cannot read its redemption journal",
            )
        }
    }
}

/// `POST /redemption/journal/drop` (Admin; round 5b, F6): remove a journaled redemption without
/// applying it, and stop it holding back a commit; answers the removed entry. Its reserve can
/// be built against again. If the transaction is mined after all, the tracker never applies it
/// and its reserve tree falls out of step with the chain, so drop only a redemption that can no
/// longer be mined, or a marked one an operator has dealt with.
pub async fn drop_journal_entry(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    axum::Json(request): axum::Json<JournalEntryRequest>,
) -> JournalAnswer<JournaledRedemption> {
    let entry = match requested_entry(&state.tracker_storage, &request.tx_id) {
        Ok(entry) => entry,
        Err(answer) => return answer,
    };
    if let Err(e) = state.tracker_storage.remove_journaled_redemption(&entry.tx_id) {
        error!("Cannot remove journaled redemption {}: {:?}", entry.tx_id, e);
        return journal_error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "the tracker cannot write its redemption journal",
        );
    }
    let shared = state.shared_tracker_state.lock().await.clone();
    shared.forget_submitted_redemptions(std::slice::from_ref(&entry.tx_id));
    warn!(
        "Operator dropped journaled redemption {} ({} of {} -> {} in {}, cumulative {}{}): nothing was applied. If it is mined after all, the tracker's reserve tree is out of step with the chain.",
        entry.tx_id,
        entry.redeemed_amount,
        entry.issuer_pubkey,
        entry.recipient_pubkey,
        entry.denomination,
        entry.new_already_redeemed,
        entry
            .digest_mismatch
            .as_deref()
            .map(|m| format!("; marked: {m}"))
            .unwrap_or_default()
    );
    (
        axum::http::StatusCode::OK,
        axum::Json(crate::models::success_response(entry)),
    )
}

/// `POST /redemption/journal/apply` (Admin; round 5b, F6): apply a journaled redemption now,
/// without looking at the chain, as the confirmer does once it is mined: the cumulative value
/// and the reserve tree timestamp the build proved, then the tracker's reserve tree compared
/// with the digest journaled at submit. Matching (or nothing to compare with), the entry leaves
/// the journal and the answer is it; differing, it stays marked (409); when it cannot be
/// applied, it stays with the error (409). Applying an applied redemption changes nothing.
pub async fn apply_journal_entry(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    axum::Json(request): axum::Json<JournalEntryRequest>,
) -> JournalAnswer<JournaledRedemption> {
    use axum::http::StatusCode;
    let entry = match requested_entry(&state.tracker_storage, &request.tx_id) {
        Ok(entry) => entry,
        Err(answer) => return answer,
    };
    let shared = state.shared_tracker_state.lock().await.clone();
    match apply_journaled_against(&state.tracker_storage, &shared, &state.tx, &entry, None).await
    {
        Ok(Applied::Matching) => {
            warn!(
                "Operator applied journaled redemption {} without the chain's confirmation",
                entry.tx_id
            );
            (StatusCode::OK, axum::Json(crate::models::success_response(entry)))
        }
        Ok(Applied::Mismatch) => journal_error(
            StatusCode::CONFLICT,
            format!(
                "redemption {} is applied, but the tracker's reserve tree differs from the digest journaled at submit; it stays journaled, marked (GET /redemption/journal)",
                entry.tx_id
            ),
        ),
        Err(e) => journal_error(
            StatusCode::CONFLICT,
            format!(
                "redemption {} cannot be applied ({e}); it stays journaled",
                entry.tx_id
            ),
        ),
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const TX: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
    /// The note's timestamp when the redemptions below were built.
    const BUILT_AT: u64 = 1_700_000_000_000;

    fn reserve_box() -> String {
        "ab".repeat(32)
    }

    fn tracker_box() -> String {
        "cd".repeat(32)
    }

    /// Where the mock node has a transaction.
    #[derive(Default, Clone)]
    struct Chain {
        mempool: bool,
        /// Inclusion height, once the blockchain index has it in a block.
        included_at: Option<u64>,
        /// The first output's R5 the index reports.
        r5: Option<String>,
        broken: bool,
    }

    /// What the mock node knows.
    #[derive(Default)]
    struct NodeState {
        txs: HashMap<String, Chain>,
        /// The UTXO set (`/utxo/byId`).
        unspent: HashSet<String>,
        /// The spenders the blockchain index names (`/blockchain/box/byId`).
        spent_by: HashMap<String, String>,
        /// Remove a transaction from the journal when its mempool lookup arrives: as if
        /// `/redemption/submit` or an operator removed it while the confirmer looked at it.
        remove_on_lookup: bool,
        /// Mempool lookups, by transaction id.
        lookups: HashMap<String, usize>,
    }

    struct Fixture {
        config: TrackerBoxUpdateConfig,
        storage: TrackerStorage,
        shared: SharedTrackerState,
        cmd_tx: tokio::sync::mpsc::Sender<TrackerCommand>,
        node: Arc<Mutex<NodeState>>,
        height: Arc<AtomicU64>,
        applied: Arc<AtomicUsize>,
        issuer: PubKey,
        issuer_secret: [u8; 32],
        recipient: PubKey,
        /// The note the tracker holds (unless the fixture was made without it).
        note: basis_store::IouNote,
        /// Adds a note to the tracker before the next command.
        add_note: tokio::sync::mpsc::Sender<basis_store::IouNote>,
        /// The reserve tree digest (hex) a build of 300 at [`BUILT_AT`] proved: what R5 of the
        /// redemption's reserve output holds.
        built_r5: String,
        _dir: tempfile::TempDir,
    }

    /// A mock node on 127.0.0.1 that knows what `node` holds, and a tracker thread with a real
    /// `RedemptionManager` that answers `CompleteRedemption` (counting the ones that changed
    /// the note), `GetReserveStateDigest` and nothing else. The note of 1000 from the issuer to
    /// the recipient exists unless `with_note` is false; a note sent on `add_note` is added.
    async fn fixture(with_note: bool) -> Fixture {
        use crate::local_wallet::tests::mock_node;
        let dir = tempfile::tempdir().unwrap();
        let storage = TrackerStorage::open(dir.path()).unwrap();
        let node: Arc<Mutex<NodeState>> = Arc::default();
        let height = Arc::new(AtomicU64::new(1_000));
        let (node_state, node_height, node_storage) =
            (node.clone(), height.clone(), storage.clone());
        let (url, _seen) = mock_node(move |method, target, _body| {
            let not_found = (404, r#"{"error":404,"reason":"not-found"}"#.to_string());
            let mut node = node_state.lock().unwrap();
            if method == "GET" && target == "/info" {
                return (
                    200,
                    serde_json::json!({ "fullHeight": node_height.load(Ordering::SeqCst) })
                        .to_string(),
                );
            }
            if let Some(id) = target.strip_prefix("/transactions/unconfirmed/byTransactionId/") {
                *node.lookups.entry(id.to_string()).or_default() += 1;
                if node.remove_on_lookup {
                    node_storage.remove_journaled_redemption(id).unwrap();
                }
                return match node.txs.get(id) {
                    Some(c) if c.broken => (500, "{}".to_string()),
                    Some(c) if c.mempool => (200, serde_json::json!({ "id": id }).to_string()),
                    _ => not_found,
                };
            }
            if let Some(id) = target.strip_prefix("/blockchain/transaction/byId/") {
                return match node.txs.get(id) {
                    Some(Chain {
                        included_at: Some(h),
                        r5,
                        ..
                    }) => {
                        let outputs = match r5 {
                            Some(r5) => serde_json::json!([{
                                "boxId": "e0".repeat(32),
                                "creationHeight": h,
                                "additionalRegisters": { "R5": r5 }
                            }]),
                            None => serde_json::json!([]),
                        };
                        (
                            200,
                            serde_json::json!({ "id": id, "inclusionHeight": h, "outputs": outputs })
                                .to_string(),
                        )
                    }
                    _ => not_found,
                };
            }
            if let Some(id) = target.strip_prefix("/utxo/byId/") {
                return if node.unspent.contains(id) {
                    (200, serde_json::json!({ "boxId": id }).to_string())
                } else {
                    not_found
                };
            }
            if let Some(id) = target.strip_prefix("/blockchain/box/byId/") {
                return (
                    200,
                    serde_json::json!({ "boxId": id, "spentTransactionId": node.spent_by.get(id) })
                        .to_string(),
                );
            }
            not_found
        })
        .await;

        let (issuer_secret, issuer) = basis_store::schnorr::generate_keypair();
        let recipient = basis_store::schnorr::generate_keypair().1;
        let note = basis_store::IouNote::create_and_sign(
            recipient,
            1_000,
            BUILT_AT,
            &issuer_secret,
            &[0x42; 32],
            DenomKey::Erg,
        )
        .unwrap();
        let applied = Arc::new(AtomicUsize::new(0));
        let thread_applied = applied.clone();
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<TrackerCommand>(16);
        let (add_note, mut add_note_rx) = tokio::sync::mpsc::channel::<basis_store::IouNote>(4);
        let (built_tx, built_rx) = std::sync::mpsc::channel();
        let first_note = note.clone();
        std::thread::spawn(move || {
            let mut manager = basis_store::RedemptionManager::new(
                basis_store::TrackerStateManager::new_with_temp_storage(),
            );
            if with_note {
                manager.tracker.add_note(&issuer, &first_note).unwrap();
            }
            let (_, built_r5) = manager
                .tracker
                .generate_reserve_insert_proof(&issuer, &recipient, &DenomKey::Erg, BUILT_AT, 300)
                .unwrap();
            built_tx.send(hex::encode(built_r5)).unwrap();
            while let Some(cmd) = cmd_rx.blocking_recv() {
                while let Ok(note) = add_note_rx.try_recv() {
                    manager.tracker.add_note(&issuer, &note).unwrap();
                }
                match cmd {
                    TrackerCommand::CompleteRedemption {
                        issuer_pubkey,
                        recipient_pubkey,
                        denomination,
                        redeemed_amount,
                        new_already_redeemed,
                        reserve_tree_timestamp,
                        response_tx,
                    } => {
                        let before = manager
                            .tracker
                            .get_note_optional(&issuer_pubkey, &recipient_pubkey, &denomination)
                            .unwrap()
                            .map(|n| n.amount_redeemed);
                        let result = manager.complete_redemption_at(
                            &issuer_pubkey,
                            &recipient_pubkey,
                            &denomination,
                            redeemed_amount,
                            new_already_redeemed,
                            reserve_tree_timestamp,
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
                    TrackerCommand::GetReserveStateDigest {
                        issuer_pubkey,
                        denomination,
                        response_tx,
                    } => {
                        let _ = response_tx
                            .send(manager.tracker.reserve_state_digest(&issuer_pubkey, &denomination));
                    }
                    TrackerCommand::Shutdown => break,
                    _ => {}
                }
            }
        });

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
            node,
            height,
            applied,
            issuer,
            issuer_secret,
            recipient,
            note,
            add_note,
            built_r5: built_rx.recv().unwrap(),
            _dir: dir,
        }
    }

    impl Fixture {
        /// The redemption of 300 (cumulative 300) built at [`BUILT_AT`], as
        /// `/redemption/submit` journals it.
        fn entry(&self, tx_id: &str) -> JournaledRedemption {
            JournaledRedemption {
                tx_id: tx_id.to_string(),
                reserve_box_id: reserve_box(),
                issuer_pubkey: hex::encode(self.issuer),
                recipient_pubkey: hex::encode(self.recipient),
                denomination: DenomKey::Erg.denomination_id(),
                redeemed_amount: 300,
                new_already_redeemed: 300,
                data_input_ids: vec![tracker_box()],
                submitted_at_ms: 1,
                reserve_tree_timestamp: Some(BUILT_AT),
                reserve_r5_digest: Some(self.built_r5.clone()),
                ..Default::default()
            }
        }

        /// Journal [`Self::entry`] as `/redemption/submit` does; its reserve and the tracker
        /// box it reads are unspent.
        fn journal(&self, tx_id: &str) {
            let entry = self.entry(tx_id);
            self.storage.journal_redemption(&entry).unwrap();
            self.shared
                .record_submitted_redemption(tx_id.to_string(), entry.data_input_ids);
            let mut node = self.node.lock().unwrap();
            node.unspent.insert(reserve_box());
            node.unspent.insert(tracker_box());
        }

        fn set(&self, tx_id: &str, chain: Chain) {
            self.node.lock().unwrap().txs.insert(tx_id.to_string(), chain);
        }

        /// `tx_id` in a block at `height`, its reserve output's R5 holding `digest` (hex).
        fn mine(&self, tx_id: &str, height: u64, digest: &str) {
            self.set(
                tx_id,
                Chain {
                    included_at: Some(height),
                    r5: Some(format!("64{digest}072000")),
                    ..Default::default()
                },
            );
            self.node.lock().unwrap().unspent.remove(&reserve_box());
        }

        /// The note re-signed by the issuer at `timestamp`, with the same debt.
        fn note_signed_at(&self, timestamp: u64) -> basis_store::IouNote {
            basis_store::IouNote::create_and_sign(
                self.recipient,
                1_000,
                timestamp,
                &self.issuer_secret,
                &[0x42; 32],
                DenomKey::Erg,
            )
            .unwrap()
        }

        async fn check(&self) -> CheckOutcome {
            check_journal(&self.config, &self.storage, &self.shared, &self.cmd_tx).await
        }

        fn journaled(&self) -> Vec<JournaledRedemption> {
            self.storage.journaled_redemptions().unwrap()
        }

        /// As if the slow check interval had passed for `tx_id`.
        fn make_due(&self, tx_id: &str) {
            let mut entry = self.storage.journaled_redemption(tx_id).unwrap().unwrap();
            entry.next_check_at_ms = 1;
            assert!(self.storage.update_journaled_redemption(&entry).unwrap());
        }

        fn lookups(&self, tx_id: &str) -> usize {
            self.node.lock().unwrap().lookups.get(tx_id).copied().unwrap_or(0)
        }

        async fn tracker_reserve_digest(&self) -> String {
            reserve_digest(&self.cmd_tx, &self.entry(TX)).await.unwrap()
        }
    }

    /// In the mempool, then in a block one deep: kept, nothing applied. Two deep: applied once
    /// (the index answers without outputs here, so the tracker's reserve tree is compared with
    /// the digest journaled at submit), removed from the journal and from the redemptions that
    /// hold back a commit.
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
        assert_eq!(fx.tracker_reserve_digest().await, fx.built_r5);
        assert_eq!(fx.check().await, CheckOutcome::default());
    }

    /// Round 5b (F1): the note is re-signed (a newer timestamp) after the build and before the
    /// redemption is applied. It is applied with the build's timestamp, so the tracker's reserve
    /// tree is the R5 of the mined reserve output, and the entry leaves the journal.
    #[tokio::test]
    async fn a_note_re_signed_between_build_and_apply_is_applied_as_built() {
        let fx = fixture(true).await;
        fx.journal(TX);
        fx.add_note
            .send(fx.note_signed_at(BUILT_AT + 60_000))
            .await
            .unwrap();
        fx.mine(TX, 990, &fx.built_r5);
        let outcome = fx.check().await;
        assert_eq!(outcome.applied, vec![TX.to_string()], "{outcome:?}");
        assert!(outcome.mismatched.is_empty());
        assert!(fx.journaled().is_empty());
        assert_eq!(fx.tracker_reserve_digest().await, fx.built_r5);
    }

    /// Round 5b (F1): applied, but the tracker's reserve tree does not hash to R5 of the mined
    /// reserve output. The error is logged and the entry stays, marked with both digests: it no
    /// longer holds back a commit, the confirmer leaves it alone (no second apply), its reserve
    /// stays blocked with the reason, and a restart does not count it as waiting.
    #[tokio::test]
    async fn a_reserve_tree_out_of_step_with_r5_is_marked_and_blocks_its_reserve() {
        let fx = fixture(true).await;
        fx.journal(TX);
        let other = "ee".repeat(33);
        fx.mine(TX, 990, &other);
        let outcome = fx.check().await;
        assert_eq!(outcome.mismatched, vec![TX.to_string()], "{outcome:?}");
        assert!(outcome.applied.is_empty());
        assert_eq!(fx.applied.load(Ordering::SeqCst), 1, "applied, then compared");
        let kept = fx.journaled();
        assert_eq!(kept.len(), 1);
        let mismatch = kept[0].digest_mismatch.clone().expect("marked");
        assert!(mismatch.contains(&fx.built_r5) && mismatch.contains(&other), "{mismatch}");
        assert!(fx.shared.get_submitted_redemptions().is_empty());

        let lookups = fx.lookups(TX);
        assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        assert_eq!(fx.lookups(TX), lookups, "a marked entry is not looked at again");
        assert_eq!(fx.applied.load(Ordering::SeqCst), 1);

        let waiting = waiting_redemption(&fx.storage, &hex::encode(fx.issuer), &DenomKey::Erg)
            .unwrap()
            .expect("the reserve stays blocked");
        assert!(waiting_reason(&waiting).contains("out of step"), "{}", waiting_reason(&waiting));
        let fresh = SharedTrackerState::new();
        restore_submitted_redemptions(&fx.storage, &fresh);
        assert!(fresh.get_submitted_redemptions().is_empty());
    }

    /// Round 5b (F4): missing for fewer than the limit: kept and counted (the count is stored);
    /// seen in a mempool again: the count starts over. Missing for the limit while it can still
    /// be mined: kept, and looked at only once the slow interval has passed. Once its reserve box
    /// is spent by another transaction it can no longer be mined: dropped, never applied.
    #[tokio::test]
    async fn a_missing_redemption_is_dropped_only_once_it_can_no_longer_be_mined() {
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
        for _ in 0..MAX_REDEMPTION_MISSING_CHECKS {
            assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        }
        let entry = &fx.journaled()[0];
        assert_eq!(entry.missing_checks, MAX_REDEMPTION_MISSING_CHECKS);
        assert!(
            entry.next_check_at_ms >= unix_ms() + SLOW_CHECK_INTERVAL.as_millis() as u64 - 60_000,
            "{entry:?}"
        );
        let lookups = fx.lookups(TX);
        assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        assert_eq!(fx.lookups(TX), lookups, "not due yet");

        fx.make_due(TX);
        assert_eq!(fx.check().await.waiting, vec![TX.to_string()], "still mineable");
        assert_eq!(fx.journaled()[0].missing_checks, MAX_REDEMPTION_MISSING_CHECKS + 1);

        {
            let mut node = fx.node.lock().unwrap();
            node.unspent.remove(&reserve_box());
            node.spent_by.insert(reserve_box(), "9c".repeat(32));
        }
        fx.make_due(TX);
        let outcome = fx.check().await;
        assert_eq!(outcome.dropped, vec![TX.to_string()]);
        assert!(fx.journaled().is_empty());
        assert!(fx.shared.get_submitted_redemptions().is_empty());
        assert_eq!(fx.applied.load(Ordering::SeqCst), 0);
    }

    /// Round 5b (F4): the redemption is in a block, but the blockchain index lags behind the
    /// chain for more than ten minutes: its reserve box is out of the UTXO set and the index
    /// names no spender yet. It stays journaled; once the index has the block, it is applied.
    #[tokio::test]
    async fn a_redemption_hidden_by_index_lag_is_kept_and_applied_later() {
        let fx = fixture(true).await;
        fx.journal(TX);
        fx.node.lock().unwrap().unspent.remove(&reserve_box());
        for _ in 0..MAX_REDEMPTION_MISSING_CHECKS + 5 {
            assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
            if fx.journaled()[0].next_check_at_ms > 0 {
                fx.make_due(TX);
            }
        }
        assert_eq!(fx.journaled().len(), 1);
        assert_eq!(fx.journaled()[0].missing_checks, MAX_REDEMPTION_MISSING_CHECKS + 5);

        // The index catches up; the slow interval passes.
        fx.mine(TX, 990, &fx.built_r5);
        fx.make_due(TX);
        assert_eq!(fx.check().await.applied, vec![TX.to_string()]);
        assert_eq!(fx.applied.load(Ordering::SeqCst), 1);
        assert!(fx.journaled().is_empty());
    }

    /// Round 5b (F4): a redemption reads the tracker box as a data input. Once a confirmed
    /// commit has replaced that box (it is out of the UTXO set, and the tracker's confirmed box
    /// is another one), the redemption can no longer be mined: dropped. While the tracker's
    /// confirmed box is the one it reads, it is kept.
    #[tokio::test]
    async fn a_redemption_whose_tracker_box_was_replaced_by_a_commit_is_dropped() {
        let fx = fixture(true).await;
        fx.journal(TX);
        fx.shared.set_confirmed([0x11; 33], tracker_box(), 900);
        for _ in 0..MAX_REDEMPTION_MISSING_CHECKS {
            assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        }
        fx.make_due(TX);
        assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);

        fx.node.lock().unwrap().unspent.remove(&tracker_box());
        fx.shared.set_confirmed([0x12; 33], "ef".repeat(32), 1_000);
        fx.make_due(TX);
        assert_eq!(fx.check().await.dropped, vec![TX.to_string()]);
        assert!(fx.journaled().is_empty());
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
        fx.mine(TX, 990, &fx.built_r5);
        assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        let kept = fx.journaled();
        assert!(
            kept[0].apply_error.as_deref().unwrap_or("").contains("NoteNotFound"),
            "{kept:?}"
        );
        assert!(waiting_redemption(&fx.storage, &hex::encode(fx.issuer), &DenomKey::Erg)
            .unwrap()
            .is_some());

        fx.add_note.send(fx.note.clone()).await.unwrap();
        assert_eq!(fx.check().await.applied, vec![TX.to_string()]);
        assert_eq!(fx.applied.load(Ordering::SeqCst), 1);
        assert!(fx.journaled().is_empty());
    }

    /// Round 5b (F8): an entry removed while the confirmer looks at it (refused at submit,
    /// dropped or applied by an operator) is not written back: neither its missing count nor an
    /// apply error brings it back.
    #[tokio::test]
    async fn an_entry_removed_meanwhile_is_not_written_back() {
        let fx = fixture(false).await;
        fx.journal(TX);
        fx.node.lock().unwrap().remove_on_lookup = true;
        assert_eq!(fx.check().await.waiting, vec![TX.to_string()]);
        assert!(fx.journaled().is_empty(), "missing count");

        fx.journal(TX);
        fx.mine(TX, 990, &fx.built_r5);
        fx.check().await;
        assert!(fx.journaled().is_empty(), "apply error");
        assert_eq!(fx.applied.load(Ordering::SeqCst), 0);
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

    /// At startup the journal refills the redemptions that hold back a commit, with their age;
    /// a marked entry (applied, out of step) holds nothing back.
    #[tokio::test]
    async fn the_journal_refills_the_commit_deferral_at_startup() {
        let fx = fixture(true).await;
        let now_ms = unix_ms();
        let mut entry = JournaledRedemption {
            submitted_at_ms: now_ms - 5 * 60_000,
            ..fx.entry(TX)
        };
        fx.storage.journal_redemption(&entry).unwrap();
        entry.tx_id = "8b".repeat(32);
        entry.submitted_at_ms = now_ms;
        fx.storage.journal_redemption(&entry).unwrap();
        entry.tx_id = "9d".repeat(32);
        entry.digest_mismatch = Some("marked".to_string());
        fx.storage.journal_redemption(&entry).unwrap();

        let fresh = SharedTrackerState::new();
        restore_submitted_redemptions(&fx.storage, &fresh);
        let restored = fresh.get_submitted_redemptions();
        assert_eq!(restored.len(), 2);
        let old = restored.iter().find(|r| r.tx_id == TX).unwrap();
        assert_eq!(old.data_input_ids, vec![tracker_box()]);
        assert!(old.submitted_at.elapsed() >= Duration::from_secs(5 * 60 - 1));
        let new = restored.iter().find(|r| r.tx_id == "8b".repeat(32)).unwrap();
        assert!(new.submitted_at.elapsed() < Duration::from_secs(60));
    }

    #[test]
    fn the_r5_digest_is_read_from_the_serialized_register() {
        let digest = "ab".repeat(33);
        assert_eq!(r5_digest_hex(&format!("64{digest}072000")), Some(digest.clone()));
        assert_eq!(
            r5_digest_hex(&format!("64{}", digest.to_ascii_uppercase())),
            Some(digest)
        );
        assert_eq!(r5_digest_hex("64abcd"), None);
        assert_eq!(r5_digest_hex(&format!("0e{}", "ab".repeat(33))), None);
        assert_eq!(r5_digest_hex(&format!("64{}", "zz".repeat(33))), None);
        assert_eq!(r5_digest_hex(&format!("64{}é", "ab".repeat(32))), None);
    }
}
