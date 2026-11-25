//! Persistence layer for IouNote storage using fjall database with extra indices
//!
//! This module provides efficient storage and retrieval of IOU notes with secondary indices
//! for fast lookups by issuer, recipient, and timestamp without full partition scans.

use crate::{
    reserve_tracker::ExtendedReserveInfo, DenomKey, IouNote, NoteConfirmation, NoteError, NoteKey,
    PendingExchangeRecord, PendingExchangeStatus, PubKey, TrackerBoxInfo,
};
use fjall::{Config, PartitionCreateOptions};
use std::path::Path;

/// Journal fsync interval of every keyspace, in milliseconds.
///
/// Each write already reaches the OS buffers (`manual_journal_persist` is off), which survives
/// a process crash. A background thread also syncs the journal to disk this often, so a power
/// loss loses at most about one second of writes. The thread lives as long as the keyspace,
/// which is why every storage below keeps its `Keyspace`.
pub const JOURNAL_FSYNC_MS: u16 = 1000;

/// Longest key fjall takes. lsm-tree asserts that a key is 1 to 65535 bytes long only AFTER the
/// write-ahead log took the write: an empty or longer key panics on the write and again on every
/// restart, while the log is replayed (round 5b, F2). Every key that comes from outside input
/// (the node's answers, request bodies) is checked with [`storable_key`] first.
pub const MAX_STORABLE_KEY_LEN: usize = u16::MAX as usize;

/// `key` if fjall can hold it (1 to [`MAX_STORABLE_KEY_LEN`] bytes), else an error naming `what`.
fn storable_key<'a>(what: &str, key: &'a [u8]) -> Result<&'a [u8], NoteError> {
    if key.is_empty() || key.len() > MAX_STORABLE_KEY_LEN {
        return Err(NoteError::StorageError(format!(
            "refusing a {what} of {} bytes as a key: keys are 1 to {MAX_STORABLE_KEY_LEN} bytes",
            key.len()
        )));
    }
    Ok(key)
}

/// Whether fjall can hold `key` (see [`storable_key`]). A key it cannot hold was never stored,
/// so a read finds nothing and a removal has nothing to do.
fn is_storable_key(key: &[u8]) -> bool {
    !key.is_empty() && key.len() <= MAX_STORABLE_KEY_LEN
}

/// A transaction id as the redemption journal keys it: 64 hex characters, lower-cased.
fn journal_key(tx_id: &str) -> Result<String, NoteError> {
    if tx_id.len() == 64 && tx_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(tx_id.to_ascii_lowercase())
    } else {
        Err(NoteError::StorageError(format!(
            "{:?} is not a transaction id (64 hex characters)",
            tx_id.chars().take(80).collect::<String>()
        )))
    }
}

/// Fixed-width note record length: issuer(33) ‖ collected(8) ‖ redeemed(8) ‖
/// timestamp(8) ‖ signature(65) ‖ recipient(33) ‖ tracker_nft_id(32) ‖
/// denomination(33) = 220 bytes.
const NOTE_VALUE_LEN: usize = 220;

/// Fixed-width reserve journal value length: timestamp(8) ‖ already_redeemed(8) ‖
/// denomination(33) = 49 bytes.
const JOURNAL_VALUE_LEN: usize = 49;

/// Database storage for IOU notes with extra indices for efficient querying
///
/// Uses three partitions:
/// - `iou_notes`: Main data storage (issuer+recipient -> note data)
/// - `issuer_index`: Secondary index (issuer_pubkey -> list of note keys)
/// - `recipient_index`: Secondary index (recipient_pubkey -> list of note keys)
pub struct NoteStorage {
    keyspace: fjall::Keyspace,
    notes_partition: fjall::Partition,
    issuer_index: fjall::Partition,
    recipient_index: fjall::Partition,
    confirmations_partition: fjall::Partition,
    reserve_avl_journal_partition: fjall::Partition,
    pending_exchanges_partition: fjall::Partition,
    /// Test-only fault-injection hook: while set, the atomic exchange commit
    /// methods return an error without writing anything (issue #20 tests).
    #[cfg(test)]
    pub fail_exchange_commits: std::sync::atomic::AtomicBool,
    /// Test-only fault-injection hook: while set, `store_note` returns an
    /// error without writing anything (add_note/update_note atomicity tests).
    #[cfg(test)]
    pub fail_note_store: std::sync::atomic::AtomicBool,
}

/// Database storage for scanner metadata
#[derive(Clone)]
pub struct ScannerMetadataStorage {
    /// Keeps the keyspace and its background threads (journal fsync, flushes, compaction)
    /// alive with this handle; dropping the last `Keyspace` stops them.
    _keyspace: fjall::Keyspace,
    partition: fjall::Partition,
}

/// A reserve box rejected by scanner admission control (issue #19), kept for
/// operator observability. Quarantined boxes are never tracked, so they cannot
/// poison `resolve_issuer_reserve` with a duplicate (owner, denomination).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuarantinedReserve {
    /// Box ID (normalized hex encoding, same as `ExtendedReserveInfo.box_id`).
    pub box_id: String,
    /// Owner public key from R4 (hex).
    pub owner_pubkey: String,
    /// Denomination: "ERG" or the hex-encoded token id.
    pub denomination: String,
    /// Why the box was rejected.
    pub reason: String,
    /// Unix timestamp (millis) when the box was quarantined.
    pub quarantined_at: u64,
}

/// An operator's release of a quarantined reserve box (round 6c): the
/// quarantine record leaves `quarantined_reserves`, so the scanner judges the
/// box again by the admission rules of the day at its next cycle (it is not
/// tracked by the release itself), and this journal keeps the record and the
/// operator's note.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuarantineRelease {
    /// The quarantine record as it was.
    pub record: QuarantinedReserve,
    /// What the operator checked.
    pub note: String,
    /// Unix timestamp (millis) of the release.
    pub released_at: u64,
}

/// A reserve box the scanner removed lately (round 6f), kept for about a day
/// so that, after a restart too, a reorg bringing the box back restores it and
/// a box holding its NFT is checked as its successor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemovedReserve {
    /// The reserve as it was tracked.
    pub record: ExtendedReserveInfo,
    /// Its reserve NFT, when known.
    pub nft: Option<String>,
    /// Unix timestamp (millis) of the removal.
    pub removed_at: u64,
    /// The index height the removal is counted from (set at the first cycle
    /// with a known index height; the record expires 720 blocks later).
    #[serde(default)]
    pub removed_height: Option<u64>,
}

/// Database storage for reserve information
#[derive(Clone)]
pub struct ReserveStorage {
    /// Keeps the keyspace and its background threads alive (see [`JOURNAL_FSYNC_MS`]);
    /// also commits the quarantine release batch.
    keyspace: fjall::Keyspace,
    partition: fjall::Partition,
    quarantine_partition: fjall::Partition,
    /// Round 6c: journal of quarantine releases, keyed `released_at (20 digits) : box id`.
    release_partition: fjall::Partition,
    /// Round 6f: reserve boxes removed lately, keyed by box id.
    removed_partition: fjall::Partition,
    /// Round 8: the reserve NFT of each tracked reserve box, keyed by box id
    /// ([`StoredBoxNft`]).
    box_nft_partition: fjall::Partition,
    /// Round 8: the emission of the NFTs of tracked reserves, keyed by NFT id
    /// ([`StoredNftEmission`]); only singletons are kept.
    nft_emission_partition: fjall::Partition,
}

/// Round 8: the reserve NFT a reserve box holds (its first token, held once).
/// A box id names one box, tokens included, so this is a fact of the chain
/// that no reorganization changes; the scanner reads it back after a restart
/// instead of asking the node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredBoxNft {
    /// The NFT id, 64 hex characters, lower case.
    pub nft: String,
}

/// Round 8: the emission of a reserve NFT as the token index gave it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredNftEmission {
    pub emission: u64,
}

/// Round 8: the NFT facts the scanner keeps ([`ReserveStorage::nft_facts`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NftFacts {
    /// Reserve box id -> its reserve NFT.
    pub box_nft: std::collections::HashMap<String, String>,
    /// NFT id -> its emission.
    pub emission: std::collections::HashMap<String, u64>,
    /// Entries that did not read back (a damaged key or value): removed, so
    /// the scanner asks the node again.
    pub dropped: usize,
}

/// Whether `id` is a 32-byte id in lower-case hex (as the scanner keeps box
/// and NFT ids).
fn is_lower_hex_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Database storage for tracker information
#[derive(Clone)]
pub struct TrackerStorage {
    /// Keeps the keyspace and its background threads alive (see [`JOURNAL_FSYNC_MS`]), and
    /// syncs the redemption journal to disk before a broadcast ([`Self::persist_journal`]).
    keyspace: fjall::Keyspace,
    partition: fjall::Partition,
    /// Redemptions submitted through `/redemption/submit` that the chain has not confirmed yet
    /// (round 5, C8; see [`JournaledRedemption`]).
    redemption_journal: fjall::Partition,
    /// The operator's reserve tree repairs, oldest first (round 6, risk 1; see
    /// [`ReserveTreeRepairRecord`]).
    tree_repairs: fjall::Partition,
    /// Journal entries an operator dropped (`POST /redemption/journal/drop`), by transaction id
    /// (round 6, review P2-1; see [`DroppedRedemption`]).
    redemption_drops: fjall::Partition,
    /// Serializes the journal writes, so a write-back of an entry read earlier
    /// ([`Self::update_journaled_redemption`]) never brings back an entry removed meanwhile
    /// (round 5b, F8). Shared by the clones of this storage.
    journal_writes: std::sync::Arc<std::sync::Mutex<()>>,
}

/// The partition of [`TrackerStorage`] that holds the submitted redemptions. It is created on
/// first open; a data dir without it (written before round 5) opens unchanged, and an older
/// binary leaves it alone.
pub const REDEMPTION_JOURNAL_PARTITION: &str = "redemption_journal";

/// The partition of [`TrackerStorage`] that records the operator's reserve tree repairs (round
/// 6, risk 1). It is created on first open; a data dir without it opens unchanged, and an older
/// binary leaves it alone.
pub const RESERVE_TREE_REPAIRS_PARTITION: &str = "reserve_tree_repairs";

/// The partition of [`TrackerStorage`] that remembers the journal entries an operator dropped
/// (round 6, review P2-1). It is created on first open; a data dir without it opens unchanged,
/// and an older binary leaves it alone.
pub const REDEMPTION_DROPS_PARTITION: &str = "redemption_drops";

/// A journal entry an operator dropped (`POST /redemption/journal/drop`), kept under its
/// transaction id so the reserve reconciler never journals that transaction again when it finds
/// it on chain (round 6, review P2-1): the operator decided about it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DroppedRedemption {
    /// Unix milliseconds of the drop.
    pub dropped_at_ms: u64,
    /// The entry as it was dropped.
    pub entry: JournaledRedemption,
}

/// One reserve tree repair (`POST /redemption/tree/repair`, round 6, risk 1), kept as the record
/// of what an operator changed: the edge, the reserve box whose R5 it was checked against, the
/// value before and after, and the marked journal entries it cleared. Stored as JSON under the
/// nanosecond it was written, so the partition lists the repairs in order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReserveTreeRepairRecord {
    /// Unix milliseconds of the repair.
    pub repaired_at_ms: u64,
    /// Issuer (reserve owner) key, lower-case hex.
    pub issuer_pubkey: String,
    /// Recipient key, lower-case hex.
    pub recipient_pubkey: String,
    /// The note's denomination (`DenomKey::denomination_id`).
    pub denomination: String,
    /// The reserve box on chain whose R5 digest the repaired reserve tree equals.
    pub reserve_box_id: String,
    /// The journaled redemption the value was taken from, when the request named one.
    #[serde(default)]
    pub tx_id: Option<String>,
    /// What the repair did.
    pub repair: crate::ReserveTreeRepair,
    /// Journal entries of the reserve that were marked (`digest_mismatch`) and were removed
    /// because the reserve tree now equals the chain's.
    #[serde(default)]
    pub cleared_marked: Vec<String>,
}

/// A redemption `/redemption/submit` broadcast (or is about to) that the chain has not
/// confirmed yet (round 5, C8). It is written before the broadcast and removed once the
/// redemption is applied to the note and the reserve tree (it is in a block, deep enough) or
/// dropped (gone from the mempools and the chain, or refused by the node). Stored as JSON under
/// the transaction id.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JournaledRedemption {
    /// Id of the redemption transaction (a signed transaction has its unsigned one's id).
    pub tx_id: String,
    /// The reserve box it spends.
    pub reserve_box_id: String,
    /// Issuer (reserve owner) key, lower-case hex.
    pub issuer_pubkey: String,
    /// Recipient key, lower-case hex.
    pub recipient_pubkey: String,
    /// The note's denomination (`DenomKey::denomination_id`).
    pub denomination: String,
    /// Amount it redeems.
    pub redeemed_amount: u64,
    /// The reserve tree's cumulative value for the note once it is applied.
    pub new_already_redeemed: u64,
    /// The boxes it reads as data inputs (the tracker box).
    pub data_input_ids: Vec<String>,
    /// Unix milliseconds when `/redemption/submit` wrote it.
    pub submitted_at_ms: u64,
    /// Consecutive checks that found it in neither a mempool nor the chain.
    #[serde(default)]
    pub missing_checks: u32,
    /// Why the last attempt to apply it failed, if one did.
    #[serde(default)]
    pub apply_error: Option<String>,
    /// The timestamp the build wrote into the note's reserve tree value (`timestamp ‖
    /// new_already_redeemed`): the note's timestamp at build time (round 5b, F1). The redemption
    /// is applied with exactly this value, so a note re-signed after the build does not put the
    /// tracker's reserve tree out of step with the reserve's R5. `None` (an entry written before
    /// round 5b) applies with the note's current timestamp.
    #[serde(default)]
    pub reserve_tree_timestamp: Option<u64>,
    /// The reserve tree digest (hex, 33 bytes) the transaction's reserve output carries in R5
    /// (round 5b, F1): what the tracker's reserve tree must hash to once it is applied.
    #[serde(default)]
    pub reserve_r5_digest: Option<String>,
    /// Set once it is applied, when the tracker's reserve tree digest then differed from R5 of
    /// the mined transaction's reserve output (round 5b, F1): the two digests. The entry stays,
    /// so its reserve builds nothing until an operator has looked at it; the confirmer leaves it
    /// alone.
    #[serde(default)]
    pub digest_mismatch: Option<String>,
    /// Unix milliseconds before which the confirmer does not look at it again (round 5b, F4): a
    /// redemption missing for long but still mineable is checked at a slower pace. 0: at every
    /// check.
    #[serde(default)]
    pub next_check_at_ms: u64,
    /// Round 6 (risk 2): found on chain, not submitted through this tracker: a redemption of a
    /// tracked reserve that was broadcast elsewhere (another node, the front's
    /// `/node/transactions`) or that left the journal and was mined later. The reserve
    /// reconciler journals it once the tracker's reserve tree reproduces the R5 it put on chain
    /// (`reserve_r5_digest`); the confirmer then applies it like the tracker's own, compared with
    /// that digest. It never holds back a commit.
    #[serde(default)]
    pub detected_on_chain: bool,
}

/// Database storage for per-recipient acceptance policies
///
/// Stores signed acceptance policies uploaded by recipients.
/// Key: recipient_pubkey (33 bytes), Value: (timestamp, policy_json, signature)
#[derive(Clone)]
pub struct AcceptancePolicyStorage {
    /// Keeps the keyspace and its background threads alive (see [`JOURNAL_FSYNC_MS`]), and
    /// makes a quarantine move one atomic batch.
    keyspace: fjall::Keyspace,
    partition: fjall::Partition,
    /// Policies the startup re-check refused (round 5, review 6), kept instead of deleted.
    quarantine: fjall::Partition,
}

/// The partition of [`AcceptancePolicyStorage`] that holds the policies the startup re-check
/// refused. It is created on first open; a data dir without it (written before round 5) opens
/// unchanged, and an older binary leaves it alone.
pub const POLICY_QUARANTINE_PARTITION: &str = "acceptance_policies_quarantine";

/// A policy record the startup re-check moved out of service (round 5, review 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedPolicy {
    /// The recipient the policy belonged to.
    pub recipient_pubkey: PubKey,
    /// Unix seconds of the move.
    pub quarantined_at: u64,
    /// Why the re-check refused it.
    pub reason: String,
    /// The record exactly as it was stored in `acceptance_policies`.
    pub record: Vec<u8>,
}

/// Stored acceptance policy record
#[derive(Debug, Clone)]
pub struct StoredPolicy {
    /// Unix timestamp when the policy was uploaded
    pub timestamp: u64,
    /// Serialized policy JSON string
    pub policy_json: String,
    /// Hex-encoded Schnorr signature (65 bytes = 130 hex chars)
    pub signature: String,
}

impl ScannerMetadataStorage {
    /// Open or create a new scanner metadata storage database
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, NoteError> {
        let keyspace = Config::new(path)
            .fsync_ms(Some(JOURNAL_FSYNC_MS))
            .open()
            .map_err(|e| NoteError::StorageError(format!("Failed to open database: {}", e)))?;

        let partition = keyspace
            .open_partition("scanner_metadata", PartitionCreateOptions::default())
            .map_err(|e| NoteError::StorageError(format!("Failed to open partition: {}", e)))?;

        Ok(Self {
            _keyspace: keyspace,
            partition,
        })
    }

    /// Store scan ID for a specific scan name
    pub fn store_scan_id(&self, scan_name: &str, scan_id: i32) -> Result<(), NoteError> {
        let value_bytes = scan_id.to_be_bytes().to_vec();
        self.partition
            .insert(
                storable_key("scan name", scan_name.as_bytes())?,
                &value_bytes,
            )
            .map_err(|e| NoteError::StorageError(format!("Failed to store scan ID: {}", e)))?;
        Ok(())
    }

    /// Retrieve scan ID for a specific scan name
    pub fn get_scan_id(&self, scan_name: &str) -> Result<Option<i32>, NoteError> {
        if !is_storable_key(scan_name.as_bytes()) {
            return Ok(None);
        }
        match self.partition.get(scan_name.as_bytes()) {
            Ok(Some(value_bytes)) => {
                if value_bytes.len() == 4 {
                    let scan_id = i32::from_be_bytes(value_bytes[0..4].try_into().unwrap());
                    Ok(Some(scan_id))
                } else {
                    Err(NoteError::StorageError(
                        "Invalid scan ID format".to_string(),
                    ))
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to get scan ID: {}",
                e
            ))),
        }
    }

    /// Remove scan ID for a specific scan name
    pub fn remove_scan_id(&self, scan_name: &str) -> Result<(), NoteError> {
        if !is_storable_key(scan_name.as_bytes()) {
            return Ok(());
        }
        self.partition
            .remove(scan_name.as_bytes())
            .map_err(|e| NoteError::StorageError(format!("Failed to remove scan ID: {}", e)))?;
        Ok(())
    }

    /// Store blockchain height with fetch timestamp
    /// Key: "blockchain_height", Value: 8 bytes height + 8 bytes timestamp (u64 BE)
    pub fn store_blockchain_height(&self, height: u64, timestamp: u64) -> Result<(), NoteError> {
        let mut value = Vec::with_capacity(16);
        value.extend_from_slice(&height.to_be_bytes());
        value.extend_from_slice(&timestamp.to_be_bytes());
        self.partition
            .insert("blockchain_height", &value)
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to store blockchain height: {}", e))
            })?;
        Ok(())
    }

    /// Retrieve cached blockchain height and fetch timestamp
    /// Returns Some((height, timestamp)) if present, None otherwise
    pub fn get_blockchain_height(&self) -> Result<Option<(u64, u64)>, NoteError> {
        match self.partition.get("blockchain_height") {
            Ok(Some(value_bytes)) => {
                if value_bytes.len() == 16 {
                    let height = u64::from_be_bytes(value_bytes[0..8].try_into().unwrap());
                    let timestamp = u64::from_be_bytes(value_bytes[8..16].try_into().unwrap());
                    Ok(Some((height, timestamp)))
                } else {
                    Err(NoteError::StorageError(
                        "Invalid blockchain height format".to_string(),
                    ))
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to get blockchain height: {}",
                e
            ))),
        }
    }
}

impl NoteStorage {
    /// Open or create a new note storage database with extra indices
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, NoteError> {
        let keyspace = Config::new(path)
            .fsync_ms(Some(JOURNAL_FSYNC_MS))
            .open()
            .map_err(|e| NoteError::StorageError(format!("Failed to open database: {}", e)))?;

        let notes_partition = keyspace
            .open_partition("iou_notes", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to open notes partition: {}", e))
            })?;

        let issuer_index = keyspace
            .open_partition("issuer_index", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to open issuer index partition: {}", e))
            })?;

        let recipient_index = keyspace
            .open_partition("recipient_index", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to open recipient index partition: {}", e))
            })?;

        let confirmations_partition = keyspace
            .open_partition("confirmations", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to open confirmations partition: {}", e))
            })?;

        let reserve_avl_journal_partition = keyspace
            .open_partition("reserve_avl_journal", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to open reserve AVL journal partition: {}",
                    e
                ))
            })?;

        let pending_exchanges_partition = keyspace
            .open_partition("pending_exchanges", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to open pending exchanges partition: {}",
                    e
                ))
            })?;

        Ok(Self {
            keyspace,
            notes_partition,
            issuer_index,
            recipient_index,
            confirmations_partition,
            reserve_avl_journal_partition,
            pending_exchanges_partition,
            #[cfg(test)]
            fail_exchange_commits: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_note_store: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Serialize a list of note keys to bytes
    fn serialize_note_keys(keys: &[NoteKey]) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Store count as u32
        bytes.extend_from_slice(&(keys.len() as u32).to_be_bytes());
        // Store each key (66 bytes)
        for key in keys {
            bytes.extend_from_slice(&key.to_bytes());
        }
        bytes
    }

    /// Serialize a note record: issuer(33) ‖ collected(8) ‖ redeemed(8) ‖
    /// timestamp(8) ‖ signature(65) ‖ recipient(33) ‖ tracker_nft_id(32) ‖
    /// denomination(33) = 220 bytes. Fixed-width, hand-rolled (no serde).
    fn serialize_note_value(issuer_pubkey: &PubKey, note: &IouNote) -> Vec<u8> {
        let mut value_bytes = Vec::with_capacity(NOTE_VALUE_LEN);
        value_bytes.extend_from_slice(issuer_pubkey);
        value_bytes.extend_from_slice(&note.amount_collected.to_be_bytes());
        value_bytes.extend_from_slice(&note.amount_redeemed.to_be_bytes());
        value_bytes.extend_from_slice(&note.timestamp.to_be_bytes());
        value_bytes.extend_from_slice(&note.signature);
        value_bytes.extend_from_slice(&note.recipient_pubkey);
        value_bytes.extend_from_slice(&note.tracker_nft_id);
        value_bytes.extend_from_slice(&note.denomination.encode33());
        value_bytes
    }

    /// Deserialize a note record written by `serialize_note_value`.
    /// Returns `None` for malformed (wrong-length or bad denomination byte) records.
    fn deserialize_note_value(value_bytes: &[u8]) -> Option<(PubKey, IouNote)> {
        if value_bytes.len() != NOTE_VALUE_LEN {
            return None;
        }
        let issuer_pubkey: PubKey = value_bytes[0..33].try_into().ok()?;
        let amount_collected = u64::from_be_bytes(value_bytes[33..41].try_into().ok()?);
        let amount_redeemed = u64::from_be_bytes(value_bytes[41..49].try_into().ok()?);
        let timestamp = u64::from_be_bytes(value_bytes[49..57].try_into().ok()?);
        let signature: [u8; 65] = value_bytes[57..122].try_into().ok()?;
        let recipient_pubkey: PubKey = value_bytes[122..155].try_into().ok()?;
        let tracker_nft_id: [u8; 32] = value_bytes[155..187].try_into().ok()?;
        let denomination = DenomKey::decode33(value_bytes[187..220].try_into().ok()?).ok()?;
        Some((
            issuer_pubkey,
            IouNote {
                recipient_pubkey,
                amount_collected,
                amount_redeemed,
                timestamp,
                signature,
                tracker_nft_id,
                denomination,
            },
        ))
    }

    /// Deserialize a list of note keys from bytes
    fn deserialize_note_keys(bytes: &[u8]) -> Result<Vec<NoteKey>, NoteError> {
        if bytes.len() < 4 {
            return Ok(Vec::new());
        }
        let count = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let mut keys = Vec::with_capacity(count);
        let expected_len = 4 + count * 32; // NoteKey is 32 bytes (blake2b hash)
        if bytes.len() < expected_len {
            return Err(NoteError::StorageError(
                "Invalid note key list format".to_string(),
            ));
        }
        let mut offset = 4;
        for _ in 0..count {
            let key_bytes: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
            keys.push(NoteKey::from_bytes(&key_bytes));
            offset += 32;
        }
        Ok(keys)
    }

    /// Add a note key to an index partition
    fn add_to_index(
        index: &fjall::Partition,
        pubkey: &PubKey,
        note_key: &NoteKey,
    ) -> Result<(), NoteError> {
        let pubkey_bytes = pubkey;
        let existing = index
            .get(pubkey_bytes)
            .map_err(|e| NoteError::StorageError(format!("Failed to read index: {}", e)))?;

        let mut keys = match existing {
            Some(bytes) => Self::deserialize_note_keys(&bytes)?,
            None => Vec::new(),
        };

        // Check if key already exists to avoid duplicates
        let key_bytes = note_key.to_bytes();
        if !keys.iter().any(|k| k.to_bytes() == key_bytes) {
            keys.push(note_key.clone());
            let serialized = Self::serialize_note_keys(&keys);
            index
                .insert(pubkey_bytes, &serialized)
                .map_err(|e| NoteError::StorageError(format!("Failed to update index: {}", e)))?;
        }

        Ok(())
    }

    /// Remove a note key from an index partition
    fn remove_from_index(
        index: &fjall::Partition,
        pubkey: &PubKey,
        note_key: &NoteKey,
    ) -> Result<(), NoteError> {
        let pubkey_bytes = pubkey;
        let existing = index
            .get(pubkey_bytes)
            .map_err(|e| NoteError::StorageError(format!("Failed to read index: {}", e)))?;

        let mut keys = match existing {
            Some(bytes) => Self::deserialize_note_keys(&bytes)?,
            None => return Ok(()),
        };

        let key_bytes = note_key.to_bytes();
        keys.retain(|k| k.to_bytes() != key_bytes);

        if keys.is_empty() {
            index.remove(pubkey_bytes).map_err(|e| {
                NoteError::StorageError(format!("Failed to remove index entry: {}", e))
            })?;
        } else {
            let serialized = Self::serialize_note_keys(&keys);
            index
                .insert(pubkey_bytes, &serialized)
                .map_err(|e| NoteError::StorageError(format!("Failed to update index: {}", e)))?;
        }

        Ok(())
    }

    /// Store an IOU note with its issuer public key
    pub fn store_note(&self, issuer_pubkey: &PubKey, note: &IouNote) -> Result<(), NoteError> {
        #[cfg(test)]
        if self
            .fail_note_store
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(NoteError::StorageError(
                "injected note store failure".to_string(),
            ));
        }

        let key = NoteKey::from_assets(issuer_pubkey, &note.recipient_pubkey, &note.denomination);
        let key_bytes = key.to_bytes();

        let value_bytes = Self::serialize_note_value(issuer_pubkey, note);

        // The note record and both index entries commit in ONE journaled
        // batch, so a crash or I/O error cannot leave a stored note with
        // stale indices (issue #20 follow-up). Index writes are computed
        // read-first and skipped when the key is already listed.
        let issuer_index_value =
            self.index_value_with_key(&self.issuer_index, issuer_pubkey, &key)?;
        let recipient_index_value =
            self.index_value_with_key(&self.recipient_index, &note.recipient_pubkey, &key)?;

        let mut batch = self.keyspace.batch();
        batch.insert(&self.notes_partition, &key_bytes, value_bytes);
        if let Some(value) = issuer_index_value {
            batch.insert(&self.issuer_index, issuer_pubkey, value);
        }
        if let Some(value) = recipient_index_value {
            batch.insert(&self.recipient_index, &note.recipient_pubkey, value);
        }
        batch
            .commit()
            .map_err(|e| NoteError::StorageError(format!("Failed to insert note: {}", e)))
    }

    /// Store a redemption: `note` with its new cumulative redeemed amount AND the reserve AVL
    /// journal entry (`tree_timestamp ‖ tree_value` for the note's reserve tree key) in ONE
    /// journaled batch (round 5b, F6). A crash or an I/O error cannot leave the note redeemed
    /// while the reserve tree is not, or the other way round.
    pub fn store_redemption(
        &self,
        issuer_pubkey: &PubKey,
        note: &IouNote,
        tree_timestamp: u64,
        tree_value: u64,
    ) -> Result<(), NoteError> {
        #[cfg(test)]
        if self
            .fail_note_store
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(NoteError::StorageError(
                "injected note store failure".to_string(),
            ));
        }

        let key = NoteKey::from_assets(issuer_pubkey, &note.recipient_pubkey, &note.denomination);
        let value_bytes = Self::serialize_note_value(issuer_pubkey, note);
        let issuer_index_value =
            self.index_value_with_key(&self.issuer_index, issuer_pubkey, &key)?;
        let recipient_index_value =
            self.index_value_with_key(&self.recipient_index, &note.recipient_pubkey, &key)?;
        let (journal_key, journal_value) = Self::reserve_avl_journal_entry(
            issuer_pubkey,
            &note.recipient_pubkey,
            &note.denomination,
            tree_timestamp,
            tree_value,
        )?;

        let mut batch = self.keyspace.batch();
        batch.insert(&self.notes_partition, key.to_bytes(), value_bytes);
        if let Some(value) = issuer_index_value {
            batch.insert(&self.issuer_index, issuer_pubkey, value);
        }
        if let Some(value) = recipient_index_value {
            batch.insert(&self.recipient_index, note.recipient_pubkey, value);
        }
        batch.insert(
            &self.reserve_avl_journal_partition,
            journal_key,
            journal_value,
        );
        batch
            .commit()
            .map_err(|e| NoteError::StorageError(format!("Failed to store a redemption: {}", e)))
    }

    /// Retrieve an IOU note by issuer, recipient and denomination
    pub fn get_note(
        &self,
        issuer_pubkey: &PubKey,
        recipient_pubkey: &PubKey,
        denomination: &DenomKey,
    ) -> Result<Option<IouNote>, NoteError> {
        let key = NoteKey::from_assets(issuer_pubkey, recipient_pubkey, denomination);
        let key_bytes = key.to_bytes();

        match self.notes_partition.get(&key_bytes) {
            Ok(Some(value_bytes)) => {
                let (_issuer, note) =
                    Self::deserialize_note_value(&value_bytes).ok_or_else(|| {
                        NoteError::StorageError("Invalid stored note format".to_string())
                    })?;
                Ok(Some(note))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to get note: {}",
                e
            ))),
        }
    }

    /// Persist a confirmation record for a note key.
    pub fn store_confirmation(
        &self,
        key_bytes: &[u8; 32],
        confirmation: &NoteConfirmation,
    ) -> Result<(), NoteError> {
        let value = serde_json::to_vec(confirmation).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize confirmation: {}", e))
        })?;
        self.confirmations_partition
            .insert(key_bytes, &value)
            .map_err(|e| NoteError::StorageError(format!("Failed to store confirmation: {}", e)))?;
        Ok(())
    }

    /// Retrieve a confirmation record for a note key.
    pub fn get_confirmation(
        &self,
        key_bytes: &[u8; 32],
    ) -> Result<Option<NoteConfirmation>, NoteError> {
        match self.confirmations_partition.get(key_bytes) {
            Ok(Some(value_bytes)) => {
                let confirmation: NoteConfirmation =
                    serde_json::from_slice(&value_bytes).map_err(|e| {
                        NoteError::StorageError(format!("Failed to parse confirmation: {}", e))
                    })?;
                Ok(Some(confirmation))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to get confirmation: {}",
                e
            ))),
        }
    }

    /// Retrieve all confirmation records.
    pub fn get_all_confirmations(&self) -> Result<Vec<([u8; 32], NoteConfirmation)>, NoteError> {
        let mut results = Vec::new();
        for entry in self.confirmations_partition.iter() {
            let (key, value) = entry.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate confirmations: {}", e))
            })?;
            if key.len() != 32 {
                continue;
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&key);
            let confirmation: NoteConfirmation = serde_json::from_slice(&value).map_err(|e| {
                NoteError::StorageError(format!("Failed to parse confirmation: {}", e))
            })?;
            results.push((key_bytes, confirmation));
        }
        Ok(results)
    }

    /// Persist a staged (pending) cross-denomination exchange record, keyed by
    /// the from-edge note key (issue #17).
    pub fn store_pending_exchange(
        &self,
        key_bytes: &[u8; 32],
        record: &PendingExchangeRecord,
    ) -> Result<(), NoteError> {
        let value = Self::serialize_pending_exchange(record)?;
        self.pending_exchanges_partition
            .insert(key_bytes, &value)
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to store pending exchange: {}", e))
            })?;
        Ok(())
    }

    /// Retrieve a staged exchange record for a from-edge note key.
    pub fn get_pending_exchange(
        &self,
        key_bytes: &[u8; 32],
    ) -> Result<Option<PendingExchangeRecord>, NoteError> {
        match self.pending_exchanges_partition.get(key_bytes) {
            Ok(Some(value_bytes)) => {
                let record = Self::deserialize_pending_exchange(&value_bytes)?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to get pending exchange: {}",
                e
            ))),
        }
    }

    /// Retrieve all staged exchange records with their from-edge note keys.
    pub fn get_all_pending_exchanges(
        &self,
    ) -> Result<Vec<([u8; 32], PendingExchangeRecord)>, NoteError> {
        let mut results = Vec::new();
        for entry in self.pending_exchanges_partition.iter() {
            let (key, value) = entry.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate pending exchanges: {}", e))
            })?;
            if key.len() != 32 {
                continue;
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&key);
            let record = Self::deserialize_pending_exchange(&value)?;
            results.push((key_bytes, record));
        }
        Ok(results)
    }

    /// Delete a staged exchange record (called when the to-edge increase is applied).
    pub fn delete_pending_exchange(&self, key_bytes: &[u8; 32]) -> Result<(), NoteError> {
        self.pending_exchanges_partition
            .remove(key_bytes)
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to delete pending exchange: {}", e))
            })?;
        Ok(())
    }

    /// Compute the index-partition write needed to add `note_key` to `index`,
    /// mirroring `add_to_index`'s dedup: `None` if the key is already listed,
    /// `Some(serialized_list)` otherwise. Read-first so the write can join an
    /// atomic batch.
    fn index_value_with_key(
        &self,
        index: &fjall::Partition,
        pubkey: &PubKey,
        note_key: &NoteKey,
    ) -> Result<Option<Vec<u8>>, NoteError> {
        let existing = index
            .get(pubkey)
            .map_err(|e| NoteError::StorageError(format!("Failed to read index: {}", e)))?;
        let mut keys = match existing {
            Some(bytes) => Self::deserialize_note_keys(&bytes)?,
            None => Vec::new(),
        };
        let key_bytes = note_key.to_bytes();
        if keys.iter().any(|k| k.to_bytes() == key_bytes) {
            return Ok(None);
        }
        keys.push(note_key.clone());
        Ok(Some(Self::serialize_note_keys(&keys)))
    }

    /// Atomically commit an exchange's phase 1 (issue #20): the staged exchange
    /// record, the decreased from-edge note, and its recomputed confirmation
    /// record land together or not at all (a single journaled fjall batch).
    /// The from-edge key already exists, so the issuer/recipient indices are
    /// unchanged. On `Err` nothing was written.
    pub fn commit_exchange_staged(
        &self,
        issuer_pubkey: &PubKey,
        staged_record: &PendingExchangeRecord,
        from_note: &IouNote,
        from_confirmation: &NoteConfirmation,
    ) -> Result<(), NoteError> {
        #[cfg(test)]
        if self
            .fail_exchange_commits
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(NoteError::StorageError(
                "injected exchange commit failure".to_string(),
            ));
        }

        let from_key = NoteKey::from_assets(
            issuer_pubkey,
            &from_note.recipient_pubkey,
            &from_note.denomination,
        );
        let staged_value = Self::serialize_pending_exchange(staged_record)?;
        let note_value = Self::serialize_note_value(issuer_pubkey, from_note);
        let confirmation_value = serde_json::to_vec(from_confirmation).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize confirmation: {}", e))
        })?;

        let mut batch = self.keyspace.batch();
        batch.insert(
            &self.pending_exchanges_partition,
            &from_key.key_hash,
            staged_value,
        );
        batch.insert(&self.notes_partition, from_key.to_bytes(), note_value);
        batch.insert(
            &self.confirmations_partition,
            &from_key.key_hash,
            confirmation_value,
        );
        batch
            .commit()
            .map_err(|e| NoteError::StorageError(format!("Failed to commit exchange: {}", e)))
    }

    /// Atomically commit an exchange's phase 2 (issue #20): the increased
    /// to-edge note, its index entries (if the edge is new), its recomputed
    /// confirmation record, and the removal of the staged record land together
    /// or not at all. On `Err` nothing was written, so the staged record
    /// survives and the apply is retried on the next confirmation cycle.
    pub fn commit_exchange_apply(
        &self,
        issuer_pubkey: &PubKey,
        to_note: &IouNote,
        to_confirmation: &NoteConfirmation,
        staged_key: &[u8; 32],
    ) -> Result<(), NoteError> {
        #[cfg(test)]
        if self
            .fail_exchange_commits
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(NoteError::StorageError(
                "injected exchange commit failure".to_string(),
            ));
        }

        let to_key = NoteKey::from_assets(
            issuer_pubkey,
            &to_note.recipient_pubkey,
            &to_note.denomination,
        );
        let note_value = Self::serialize_note_value(issuer_pubkey, to_note);
        let confirmation_value = serde_json::to_vec(to_confirmation).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize confirmation: {}", e))
        })?;
        let issuer_index_value =
            self.index_value_with_key(&self.issuer_index, issuer_pubkey, &to_key)?;
        let recipient_index_value =
            self.index_value_with_key(&self.recipient_index, &to_note.recipient_pubkey, &to_key)?;

        let mut batch = self.keyspace.batch();
        batch.insert(&self.notes_partition, to_key.to_bytes(), note_value);
        if let Some(value) = issuer_index_value {
            batch.insert(&self.issuer_index, issuer_pubkey, value);
        }
        if let Some(value) = recipient_index_value {
            batch.insert(&self.recipient_index, &to_note.recipient_pubkey, value);
        }
        batch.insert(
            &self.confirmations_partition,
            &to_key.key_hash,
            confirmation_value,
        );
        batch.remove(&self.pending_exchanges_partition, staged_key);
        batch
            .commit()
            .map_err(|e| NoteError::StorageError(format!("Failed to commit exchange apply: {}", e)))
    }

    /// Serialize a denomination as a tag byte plus a fixed 32-byte token id
    /// (zeroed for ERG).
    fn serialize_denom(denom: &DenomKey) -> [u8; 33] {
        let mut out = [0u8; 33];
        if let DenomKey::Token(token_id) = denom {
            out[0] = 1;
            out[1..33].copy_from_slice(token_id);
        }
        out
    }

    /// Inverse of [`Self::serialize_denom`].
    fn deserialize_denom(bytes: &[u8]) -> Result<DenomKey, NoteError> {
        match bytes.first() {
            Some(0) => Ok(DenomKey::Erg),
            Some(1) => {
                let token_id: [u8; 32] = bytes
                    .get(1..33)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| {
                        NoteError::StorageError(
                            "truncated token denomination in pending exchange record".to_string(),
                        )
                    })?;
                Ok(DenomKey::Token(token_id))
            }
            _ => Err(NoteError::StorageError(
                "invalid denomination tag in pending exchange record".to_string(),
            )),
        }
    }

    /// Append a length-prefixed UTF-8 string (u16 BE length).
    fn write_len_prefixed(out: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// Read a length-prefixed UTF-8 string written by
    /// [`Self::write_len_prefixed`]; returns the string and the consumed length.
    fn read_len_prefixed(buf: &[u8], offset: usize) -> Result<(String, usize), NoteError> {
        let len_end = offset
            .checked_add(2)
            .ok_or_else(|| NoteError::StorageError("truncated pending exchange record".into()))?;
        let len = u16::from_be_bytes(
            buf.get(offset..len_end)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| {
                    NoteError::StorageError("truncated pending exchange record".into())
                })?,
        ) as usize;
        let end = len_end
            .checked_add(len)
            .ok_or_else(|| NoteError::StorageError("truncated pending exchange record".into()))?;
        let bytes = buf
            .get(len_end..end)
            .ok_or_else(|| NoteError::StorageError("truncated pending exchange record".into()))?;
        let s = String::from_utf8(bytes.to_vec()).map_err(|e| {
            NoteError::StorageError(format!("invalid UTF-8 in pending exchange record: {}", e))
        })?;
        Ok((s, end - offset))
    }

    /// Serialize a pending exchange record. Fixed-width core fields plus
    /// length-prefixed strings (hand-rolled, no serde: the record embeds
    /// 33/65-byte arrays serde cannot derive over). Layout:
    /// issuer(33) ‖ recipient(33) ‖ from_denom(33) ‖ from_old_total(8) ‖
    /// from_new_total(8) ‖ to_denom(33) ‖ to_note(220, same encoding as note
    /// values) ‖ to_base_flag(1) ‖ to_base_collected(8) ‖
    /// reserve_box_id_len(2) ‖ reserve_box_id ‖ created_at(8) ‖ status_tag(1) ‖
    /// cancel_reason_len(2) ‖ cancel_reason.
    fn serialize_pending_exchange(record: &PendingExchangeRecord) -> Result<Vec<u8>, NoteError> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&record.issuer_pubkey);
        out.extend_from_slice(&record.recipient_pubkey);
        out.extend_from_slice(&Self::serialize_denom(&record.from_denomination));
        out.extend_from_slice(&record.from_old_total.to_be_bytes());
        out.extend_from_slice(&record.from_new_total.to_be_bytes());
        out.extend_from_slice(&Self::serialize_denom(&record.to_denomination));
        out.extend_from_slice(&Self::serialize_note_value(
            &record.issuer_pubkey,
            &record.to_note,
        ));
        match record.to_base_collected {
            Some(base) => {
                out.push(1);
                out.extend_from_slice(&base.to_be_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&0u64.to_be_bytes());
            }
        }
        Self::write_len_prefixed(&mut out, &record.reserve_box_id);
        out.extend_from_slice(&record.created_at.to_be_bytes());
        match &record.status {
            PendingExchangeStatus::Staged => {
                out.push(0);
                out.extend_from_slice(&0u16.to_be_bytes());
            }
            PendingExchangeStatus::Cancelled { reason } => {
                out.push(1);
                Self::write_len_prefixed(&mut out, reason);
            }
        }
        Ok(out)
    }

    /// Inverse of [`Self::serialize_pending_exchange`].
    fn deserialize_pending_exchange(
        value_bytes: &[u8],
    ) -> Result<PendingExchangeRecord, NoteError> {
        let truncated = || NoteError::StorageError("truncated pending exchange record".to_string());

        // Fixed-size cursor helper: returns `len` bytes and the new offset.
        fn take(buf: &[u8], offset: usize, len: usize) -> Result<(&[u8], usize), NoteError> {
            let end = offset.checked_add(len).ok_or_else(|| {
                NoteError::StorageError("truncated pending exchange record".into())
            })?;
            let slice = buf.get(offset..end).ok_or_else(|| {
                NoteError::StorageError("truncated pending exchange record".into())
            })?;
            Ok((slice, end))
        }

        let (issuer_bytes, offset) = take(value_bytes, 0, 33)?;
        let issuer_pubkey: PubKey = issuer_bytes.try_into().map_err(|_| truncated())?;
        let (recipient_bytes, offset) = take(value_bytes, offset, 33)?;
        let recipient_pubkey: PubKey = recipient_bytes.try_into().map_err(|_| truncated())?;
        let (denom_bytes, offset) = take(value_bytes, offset, 33)?;
        let from_denomination = Self::deserialize_denom(denom_bytes)?;
        let (total_bytes, offset) = take(value_bytes, offset, 8)?;
        let from_old_total = u64::from_be_bytes(total_bytes.try_into().map_err(|_| truncated())?);
        let (total_bytes, offset) = take(value_bytes, offset, 8)?;
        let from_new_total = u64::from_be_bytes(total_bytes.try_into().map_err(|_| truncated())?);
        let (denom_bytes, offset) = take(value_bytes, offset, 33)?;
        let to_denomination = Self::deserialize_denom(denom_bytes)?;
        let (note_bytes, offset) = take(value_bytes, offset, NOTE_VALUE_LEN)?;
        let (_, to_note) = Self::deserialize_note_value(note_bytes).ok_or_else(&truncated)?;
        let (flag_bytes, offset) = take(value_bytes, offset, 1)?;
        let (to_base_collected, offset) = if flag_bytes[0] == 0 {
            // Flag 0 still carries the reserved 8 zero bytes.
            let (_, offset) = take(value_bytes, offset, 8)?;
            (None, offset)
        } else {
            let (base_bytes, offset) = take(value_bytes, offset, 8)?;
            let base = u64::from_be_bytes(base_bytes.try_into().map_err(|_| truncated())?);
            (Some(base), offset)
        };
        let (reserve_box_id, consumed) = Self::read_len_prefixed(value_bytes, offset)?;
        let offset = offset + consumed;
        let (created_bytes, offset) = take(value_bytes, offset, 8)?;
        let created_at = u64::from_be_bytes(created_bytes.try_into().map_err(|_| truncated())?);
        let (status_bytes, offset) = take(value_bytes, offset, 1)?;
        let (status, offset) = if status_bytes[0] == 0 {
            // Staged still carries the reserved zero length prefix.
            let (_, offset) = take(value_bytes, offset, 2)?;
            (PendingExchangeStatus::Staged, offset)
        } else {
            let (reason, consumed) = Self::read_len_prefixed(value_bytes, offset)?;
            (
                PendingExchangeStatus::Cancelled { reason },
                offset + consumed,
            )
        };
        if offset != value_bytes.len() {
            return Err(NoteError::StorageError(
                "trailing bytes in pending exchange record".to_string(),
            ));
        }
        Ok(PendingExchangeRecord {
            issuer_pubkey,
            recipient_pubkey,
            from_denomination,
            from_old_total,
            from_new_total,
            to_denomination,
            to_note,
            to_base_collected,
            reserve_box_id,
            created_at,
            status,
        })
    }

    /// Retrieve notes by their keys using the main partition
    fn get_notes_by_keys(&self, keys: &[NoteKey]) -> Result<Vec<IouNote>, NoteError> {
        let mut notes = Vec::new();
        for key in keys {
            let key_bytes = key.to_bytes();
            if let Ok(Some(value_bytes)) = self.notes_partition.get(&key_bytes) {
                if let Some((_issuer, note)) = Self::deserialize_note_value(&value_bytes) {
                    notes.push(note);
                }
            }
        }
        Ok(notes)
    }

    fn get_notes_by_keys_with_issuer(
        &self,
        keys: &[NoteKey],
    ) -> Result<Vec<(PubKey, IouNote)>, NoteError> {
        let mut notes = Vec::new();
        for key in keys {
            let key_bytes = key.to_bytes();
            if let Ok(Some(value_bytes)) = self.notes_partition.get(&key_bytes) {
                if let Some(pair) = Self::deserialize_note_value(&value_bytes) {
                    notes.push(pair);
                }
            }
        }
        Ok(notes)
    }

    /// Get all notes for a specific issuer (uses issuer index for O(1) lookup)
    pub fn get_issuer_notes(&self, issuer_pubkey: &PubKey) -> Result<Vec<IouNote>, NoteError> {
        tracing::debug!(
            "Looking for notes from issuer using index: {:?}",
            issuer_pubkey
        );

        // Use the issuer index for efficient lookup
        match self.issuer_index.get(issuer_pubkey) {
            Ok(Some(bytes)) => {
                let keys = Self::deserialize_note_keys(&bytes)?;
                tracing::debug!("Found {} note keys in issuer index", keys.len());
                self.get_notes_by_keys(&keys)
            }
            Ok(None) => {
                tracing::debug!("No notes found in issuer index");
                Ok(Vec::new())
            }
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to read issuer index: {}",
                e
            ))),
        }
    }

    /// Get all notes for a specific recipient (uses recipient index for O(1) lookup)
    pub fn get_recipient_notes(
        &self,
        recipient_pubkey: &PubKey,
    ) -> Result<Vec<IouNote>, NoteError> {
        tracing::debug!(
            "Looking for notes for recipient using index: {:?}",
            recipient_pubkey
        );

        // Use the recipient index for efficient lookup
        match self.recipient_index.get(recipient_pubkey) {
            Ok(Some(bytes)) => {
                let keys = Self::deserialize_note_keys(&bytes)?;
                tracing::debug!("Found {} note keys in recipient index", keys.len());
                self.get_notes_by_keys(&keys)
            }
            Ok(None) => {
                tracing::debug!("No notes found in recipient index");
                Ok(Vec::new())
            }
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to read recipient index: {}",
                e
            ))),
        }
    }

    /// Get all notes for a specific recipient with issuer information
    pub fn get_recipient_notes_with_issuer(
        &self,
        recipient_pubkey: &PubKey,
    ) -> Result<Vec<(PubKey, IouNote)>, NoteError> {
        tracing::debug!(
            "Looking for notes for recipient with issuer using index: {:?}",
            recipient_pubkey
        );

        // Use the recipient index for efficient lookup
        match self.recipient_index.get(recipient_pubkey) {
            Ok(Some(bytes)) => {
                let keys = Self::deserialize_note_keys(&bytes)?;
                tracing::debug!("Found {} note keys in recipient index", keys.len());
                self.get_notes_by_keys_with_issuer(&keys)
            }
            Ok(None) => {
                tracing::debug!("No notes found in recipient index");
                Ok(Vec::new())
            }
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to read recipient index: {}",
                e
            ))),
        }
    }

    /// Rebuild secondary indices from existing notes in the database
    /// This should be called after upgrading to a version with indices when
    /// existing data may not have index entries
    pub fn rebuild_indices(&self) -> Result<usize, NoteError> {
        tracing::info!("Rebuilding note indices from existing data...");
        let mut count = 0;

        for item in self.notes_partition.iter() {
            let (key_bytes, value_bytes) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate partition: {}", e))
            })?;

            let Some((issuer_pubkey, note)) = Self::deserialize_note_value(&value_bytes) else {
                continue; // Skip invalid entries
            };

            // Reconstruct the note key from the stored key bytes
            let note_key = if key_bytes.len() == 32 {
                NoteKey::from_bytes(&key_bytes.as_ref().try_into().unwrap())
            } else {
                // Fallback: compute from pubkeys and denomination
                NoteKey::from_assets(&issuer_pubkey, &note.recipient_pubkey, &note.denomination)
            };

            // Rebuild indices
            Self::add_to_index(&self.issuer_index, &issuer_pubkey, &note_key)?;
            Self::add_to_index(&self.recipient_index, &note.recipient_pubkey, &note_key)?;
            count += 1;
        }

        tracing::info!("Index rebuild complete: {} notes indexed", count);
        Ok(count)
    }

    /// Get all notes in the database
    pub fn get_all_notes(&self) -> Result<Vec<IouNote>, NoteError> {
        let mut notes = Vec::new();

        for item in self.notes_partition.iter() {
            let (_key_bytes, value_bytes) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate partition: {}", e))
            })?;

            if let Some((_issuer, note)) = Self::deserialize_note_value(&value_bytes) {
                notes.push(note);
            }
        }

        Ok(notes)
    }

    /// Get all notes with issuer information
    pub fn get_all_notes_with_issuer(&self) -> Result<Vec<(PubKey, IouNote)>, NoteError> {
        let mut notes_with_issuer = Vec::new();

        for item in self.notes_partition.iter() {
            let (_key_bytes, value_bytes) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate partition: {}", e))
            })?;

            if let Some(pair) = Self::deserialize_note_value(&value_bytes) {
                notes_with_issuer.push(pair);
            }
        }

        Ok(notes_with_issuer)
    }

    /// Retrieve an IOU note by its 32-byte note key.
    pub fn get_note_by_key(&self, note_key: &NoteKey) -> Result<Option<IouNote>, NoteError> {
        let key_bytes = note_key.to_bytes();

        match self.notes_partition.get(&key_bytes) {
            Ok(Some(value_bytes)) => {
                let (_issuer, note) =
                    Self::deserialize_note_value(&value_bytes).ok_or_else(|| {
                        NoteError::StorageError("Invalid stored note format".to_string())
                    })?;
                Ok(Some(note))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to get note by key: {}",
                e
            ))),
        }
    }

    /// Delete a note and update indices
    pub fn delete_note(
        &self,
        issuer_pubkey: &PubKey,
        recipient_pubkey: &PubKey,
        denomination: &DenomKey,
    ) -> Result<(), NoteError> {
        let key = NoteKey::from_assets(issuer_pubkey, recipient_pubkey, denomination);
        let key_bytes = key.to_bytes();

        // Remove from main storage
        self.notes_partition
            .remove(&key_bytes)
            .map_err(|e| NoteError::StorageError(format!("Failed to remove note: {}", e)))?;

        // Update indices
        Self::remove_from_index(&self.issuer_index, issuer_pubkey, &key)?;
        Self::remove_from_index(&self.recipient_index, recipient_pubkey, &key)?;

        Ok(())
    }

    /// Append a reserve AVL tree update to the journal.
    ///
    /// The journal key is ordered by a nanosecond timestamp so that replaying entries
    /// in storage order reproduces the exact sequence of tree operations.
    pub fn append_reserve_avl_update(
        &self,
        issuer_pubkey: &PubKey,
        recipient_pubkey: &PubKey,
        denomination: &DenomKey,
        timestamp: u64,
        already_redeemed: u64,
    ) -> Result<(), NoteError> {
        let (key, value) = Self::reserve_avl_journal_entry(
            issuer_pubkey,
            recipient_pubkey,
            denomination,
            timestamp,
            already_redeemed,
        )?;
        self.reserve_avl_journal_partition
            .insert(&key, &value)
            .map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to append reserve AVL journal entry: {}",
                    e
                ))
            })?;

        Ok(())
    }

    /// The reserve AVL journal key (`nanos ‖ issuer ‖ note key`, so storage order is operation
    /// order) and value (`timestamp ‖ already_redeemed ‖ denomination`) of one tree update.
    fn reserve_avl_journal_entry(
        issuer_pubkey: &PubKey,
        recipient_pubkey: &PubKey,
        denomination: &DenomKey,
        timestamp: u64,
        already_redeemed: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), NoteError> {
        let note_key = NoteKey::from_assets(issuer_pubkey, recipient_pubkey, denomination);

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| NoteError::StorageError(format!("Failed to get system time: {}", e)))?
            .as_nanos();

        let mut key = Vec::with_capacity(16 + 33 + 32);
        key.extend_from_slice(&nanos.to_be_bytes());
        key.extend_from_slice(issuer_pubkey);
        key.extend_from_slice(&note_key.to_bytes());

        let mut value = Vec::with_capacity(JOURNAL_VALUE_LEN);
        value.extend_from_slice(&timestamp.to_be_bytes());
        value.extend_from_slice(&already_redeemed.to_be_bytes());
        value.extend_from_slice(&denomination.encode33());
        Ok((key, value))
    }

    /// Iterate the reserve AVL journal in operation order.
    ///
    /// Returns a vector of (issuer_pubkey, note_key, denomination, timestamp,
    /// already_redeemed) tuples.
    pub fn iter_reserve_avl_updates(
        &self,
    ) -> Result<Vec<(PubKey, NoteKey, DenomKey, u64, u64)>, NoteError> {
        Ok(self.iter_reserve_avl_updates_counting_skips()?.0)
    }

    /// [`Self::iter_reserve_avl_updates`], and the number of malformed entries it skipped
    /// (round 7b: a skipped entry means the rebuilt reserve trees may miss redemptions).
    #[allow(clippy::type_complexity)]
    pub fn iter_reserve_avl_updates_counting_skips(
        &self,
    ) -> Result<(Vec<(PubKey, NoteKey, DenomKey, u64, u64)>, usize), NoteError> {
        let mut updates = Vec::new();
        let mut malformed = 0usize;

        for item in self.reserve_avl_journal_partition.iter() {
            let (key, value) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate reserve AVL journal: {}", e))
            })?;

            if key.len() != 16 + 33 + 32 || value.len() != JOURNAL_VALUE_LEN {
                tracing::warn!(
                    "Skipping malformed reserve AVL journal entry: key_len={}, value_len={}",
                    key.len(),
                    value.len()
                );
                malformed += 1;
                continue;
            }

            let issuer_pubkey: PubKey = key[16..49].try_into().map_err(|_| {
                NoteError::StorageError("Invalid issuer pubkey in reserve AVL journal".to_string())
            })?;
            let note_key_bytes: [u8; 32] = key[49..81].try_into().unwrap();
            let note_key = NoteKey::from_bytes(&note_key_bytes);

            let timestamp = u64::from_be_bytes(value[0..8].try_into().unwrap());
            let already_redeemed = u64::from_be_bytes(value[8..16].try_into().unwrap());
            let denomination =
                DenomKey::decode33(&value[16..49].try_into().unwrap()).map_err(|e| {
                    NoteError::StorageError(format!(
                        "Invalid denomination in reserve AVL journal: {}",
                        e
                    ))
                })?;

            updates.push((
                issuer_pubkey,
                note_key,
                denomination,
                timestamp,
                already_redeemed,
            ));
        }

        Ok((updates, malformed))
    }

    /// Test hook (round 7b): write a raw reserve AVL journal entry, a damaged one say.
    #[cfg(test)]
    pub(crate) fn insert_raw_reserve_avl_journal_entry(&self, key: &[u8], value: &[u8]) {
        self.reserve_avl_journal_partition
            .insert(key, value)
            .expect("raw journal entry");
    }
}

impl ReserveStorage {
    /// Open or create a new reserve storage database
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, NoteError> {
        let keyspace = Config::new(path)
            .fsync_ms(Some(JOURNAL_FSYNC_MS))
            .open()
            .map_err(|e| NoteError::StorageError(format!("Failed to open database: {}", e)))?;

        let partition = keyspace
            .open_partition("reserves", PartitionCreateOptions::default())
            .map_err(|e| NoteError::StorageError(format!("Failed to open partition: {}", e)))?;

        let quarantine_partition = keyspace
            .open_partition("quarantined_reserves", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to open quarantine partition: {}", e))
            })?;

        let release_partition = keyspace
            .open_partition("quarantine_releases", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to open quarantine release partition: {}",
                    e
                ))
            })?;

        let removed_partition = keyspace
            .open_partition("removed_reserves", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to open removed reserve partition: {}", e))
            })?;

        let box_nft_partition = keyspace
            .open_partition("reserve_box_nfts", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to open reserve box NFT partition: {}", e))
            })?;

        let nft_emission_partition = keyspace
            .open_partition("reserve_nft_emissions", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to open NFT emission partition: {}", e))
            })?;

        Ok(Self {
            keyspace,
            partition,
            quarantine_partition,
            release_partition,
            removed_partition,
            box_nft_partition,
            nft_emission_partition,
        })
    }

    /// Round 8: remember the reserve NFT of reserve box `box_id`. Only
    /// lower-case hex ids are kept (the scanner's normalized form).
    pub fn store_box_nft(&self, box_id: &str, nft: &str) -> Result<(), NoteError> {
        if !is_lower_hex_id(nft) {
            return Err(NoteError::StorageError(format!(
                "refusing to store {:?} as a reserve NFT id",
                nft.chars().take(80).collect::<String>()
            )));
        }
        let key = storable_key("reserve box id", box_id.as_bytes())?;
        let value = serde_json::to_vec(&StoredBoxNft {
            nft: nft.to_string(),
        })
        .map_err(|e| NoteError::StorageError(format!("Failed to serialize box NFT: {}", e)))?;
        self.box_nft_partition
            .insert(key, &value)
            .map_err(|e| NoteError::StorageError(format!("Failed to store box NFT: {}", e)))
    }

    /// Round 8: forget the reserve NFT of reserve box `box_id`.
    pub fn forget_box_nft(&self, box_id: &str) -> Result<(), NoteError> {
        if !is_storable_key(box_id.as_bytes()) {
            return Ok(());
        }
        self.box_nft_partition
            .remove(box_id.as_bytes())
            .map_err(|e| NoteError::StorageError(format!("Failed to forget box NFT: {}", e)))
    }

    /// Round 8: remember the emission of reserve NFT `nft`.
    pub fn store_nft_emission(&self, nft: &str, emission: u64) -> Result<(), NoteError> {
        if !is_lower_hex_id(nft) {
            return Err(NoteError::StorageError(format!(
                "refusing to store {:?} as a reserve NFT id",
                nft.chars().take(80).collect::<String>()
            )));
        }
        let value = serde_json::to_vec(&StoredNftEmission { emission }).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize NFT emission: {}", e))
        })?;
        self.nft_emission_partition
            .insert(nft.as_bytes(), &value)
            .map_err(|e| NoteError::StorageError(format!("Failed to store NFT emission: {}", e)))
    }

    /// Round 8: forget the emission of reserve NFT `nft`.
    pub fn forget_nft_emission(&self, nft: &str) -> Result<(), NoteError> {
        if !is_storable_key(nft.as_bytes()) {
            return Ok(());
        }
        self.nft_emission_partition
            .remove(nft.as_bytes())
            .map_err(|e| NoteError::StorageError(format!("Failed to forget NFT emission: {}", e)))
    }

    /// Round 8: the NFT facts remembered. An entry that does not read back (a
    /// key or value that is not what [`Self::store_box_nft`] or
    /// [`Self::store_nft_emission`] writes) is removed and counted in
    /// `dropped`, so the scanner asks the node for it again; an error reading
    /// the partitions is an error (the caller starts without the facts).
    pub fn nft_facts(&self) -> Result<NftFacts, NoteError> {
        let mut facts = NftFacts::default();
        let mut damaged: Vec<(&fjall::Partition, Vec<u8>)> = Vec::new();
        for item in self.box_nft_partition.iter() {
            let (key, value) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate box NFTs: {}", e))
            })?;
            let box_id = std::str::from_utf8(&key).ok();
            let stored = serde_json::from_slice::<StoredBoxNft>(&value).ok();
            match (box_id, stored) {
                (Some(box_id), Some(stored)) if is_lower_hex_id(&stored.nft) => {
                    facts.box_nft.insert(box_id.to_string(), stored.nft);
                }
                _ => damaged.push((&self.box_nft_partition, key.to_vec())),
            }
        }
        for item in self.nft_emission_partition.iter() {
            let (key, value) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate NFT emissions: {}", e))
            })?;
            let nft = std::str::from_utf8(&key).ok().filter(|nft| is_lower_hex_id(nft));
            let stored = serde_json::from_slice::<StoredNftEmission>(&value).ok();
            match (nft, stored) {
                (Some(nft), Some(stored)) => {
                    facts.emission.insert(nft.to_string(), stored.emission);
                }
                _ => damaged.push((&self.nft_emission_partition, key.to_vec())),
            }
        }
        facts.dropped = damaged.len();
        for (partition, key) in damaged {
            partition.remove(key).map_err(|e| {
                NoteError::StorageError(format!("Failed to remove a damaged NFT fact: {}", e))
            })?;
        }
        Ok(facts)
    }

    /// Test hook (round 8): write a raw NFT fact, a damaged one say
    /// (`emissions`: the emission partition, else the box NFT one).
    #[cfg(test)]
    pub(crate) fn insert_raw_nft_fact(&self, emissions: bool, key: &[u8], value: &[u8]) {
        let partition = if emissions {
            &self.nft_emission_partition
        } else {
            &self.box_nft_partition
        };
        partition.insert(key, value).expect("raw NFT fact");
    }

    /// Remember a removed reserve box (round 6f).
    pub fn store_removed(&self, removed: &RemovedReserve) -> Result<(), NoteError> {
        let key = storable_key("reserve box id", removed.record.box_id.as_bytes())?;
        let value = serde_json::to_vec(removed).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize removed reserve: {}", e))
        })?;
        self.removed_partition
            .insert(key, &value)
            .map_err(|e| NoteError::StorageError(format!("Failed to store removed reserve: {}", e)))
    }

    /// Forget a removed reserve box (round 6f).
    pub fn forget_removed(&self, box_id: &str) -> Result<(), NoteError> {
        if !is_storable_key(box_id.as_bytes()) {
            return Ok(());
        }
        self.removed_partition
            .remove(box_id.as_bytes())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to forget removed reserve: {}", e))
            })
    }

    /// The removed reserve boxes remembered (round 6f).
    pub fn removed_reserves(&self) -> Result<Vec<RemovedReserve>, NoteError> {
        self.removed_partition
            .iter()
            .map(|item| {
                let (_key, value) = item.map_err(|e| {
                    NoteError::StorageError(format!("Failed to iterate removed reserves: {}", e))
                })?;
                serde_json::from_slice(&value).map_err(|e| {
                    NoteError::StorageError(format!("Failed to deserialize removed reserve: {}", e))
                })
            })
            .collect()
    }

    /// Store a reserve in the database
    pub fn store_reserve(&self, reserve: &ExtendedReserveInfo) -> Result<(), NoteError> {
        // The box id comes from the node's answer.
        let key = storable_key("reserve box id", reserve.box_id.as_bytes())?;
        let value = serde_json::to_vec(reserve)
            .map_err(|e| NoteError::StorageError(format!("Failed to serialize reserve: {}", e)))?;

        self.partition
            .insert(key, &value)
            .map_err(|e| NoteError::StorageError(format!("Failed to store reserve: {}", e)))?;

        Ok(())
    }

    /// Retrieve a reserve by box ID
    pub fn get_reserve(&self, box_id: &str) -> Result<Option<ExtendedReserveInfo>, NoteError> {
        if !is_storable_key(box_id.as_bytes()) {
            return Ok(None);
        }
        match self.partition.get(box_id.as_bytes()) {
            Ok(Some(value_bytes)) => {
                let reserve: ExtendedReserveInfo =
                    serde_json::from_slice(&value_bytes).map_err(|e| {
                        NoteError::StorageError(format!("Failed to deserialize reserve: {}", e))
                    })?;
                Ok(Some(reserve))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to get reserve: {}",
                e
            ))),
        }
    }

    /// Get all reserves from the database
    pub fn get_all_reserves(&self) -> Result<Vec<ExtendedReserveInfo>, NoteError> {
        let mut reserves = Vec::new();

        for item in self.partition.iter() {
            let (_key_bytes, value_bytes) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate partition: {}", e))
            })?;

            let reserve: ExtendedReserveInfo =
                serde_json::from_slice(&value_bytes).map_err(|e| {
                    NoteError::StorageError(format!("Failed to deserialize reserve: {}", e))
                })?;

            reserves.push(reserve);
        }

        Ok(reserves)
    }

    /// Remove a reserve from the database
    pub fn remove_reserve(&self, box_id: &str) -> Result<(), NoteError> {
        if !is_storable_key(box_id.as_bytes()) {
            return Ok(());
        }
        self.partition
            .remove(box_id.as_bytes())
            .map_err(|e| NoteError::StorageError(format!("Failed to remove reserve: {}", e)))?;

        Ok(())
    }

    /// Persist a quarantined reserve box (issue #19).
    pub fn store_quarantined(&self, record: &QuarantinedReserve) -> Result<(), NoteError> {
        let value = serde_json::to_vec(record).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize quarantined reserve: {}", e))
        })?;

        // The box id comes from the node's answer.
        self.quarantine_partition
            .insert(storable_key("reserve box id", record.box_id.as_bytes())?, &value)
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to store quarantined reserve: {}", e))
            })?;

        Ok(())
    }

    /// Retrieve a quarantined reserve box by box ID, if quarantined.
    pub fn get_quarantined(&self, box_id: &str) -> Result<Option<QuarantinedReserve>, NoteError> {
        if !is_storable_key(box_id.as_bytes()) {
            return Ok(None);
        }
        match self.quarantine_partition.get(box_id.as_bytes()) {
            Ok(Some(value_bytes)) => {
                let record: QuarantinedReserve =
                    serde_json::from_slice(&value_bytes).map_err(|e| {
                        NoteError::StorageError(format!(
                            "Failed to deserialize quarantined reserve: {}",
                            e
                        ))
                    })?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to get quarantined reserve: {}",
                e
            ))),
        }
    }

    /// Get all quarantined reserve boxes.
    pub fn get_all_quarantined(&self) -> Result<Vec<QuarantinedReserve>, NoteError> {
        let mut records = Vec::new();

        for item in self.quarantine_partition.iter() {
            let (_key_bytes, value_bytes) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate quarantine partition: {}", e))
            })?;

            let record: QuarantinedReserve = serde_json::from_slice(&value_bytes).map_err(|e| {
                NoteError::StorageError(format!("Failed to deserialize quarantined reserve: {}", e))
            })?;

            records.push(record);
        }

        Ok(records)
    }

    /// Release the quarantined box `box_id` (round 6c): in one batch, journal
    /// the record with the operator's `note` and remove it from quarantine.
    /// `None` when the box is not quarantined.
    pub fn release_quarantined(
        &self,
        box_id: &str,
        note: &str,
        released_at: u64,
    ) -> Result<Option<QuarantineRelease>, NoteError> {
        let Some(record) = self.get_quarantined(box_id)? else {
            return Ok(None);
        };
        let release = QuarantineRelease {
            record,
            note: note.to_string(),
            released_at,
        };
        let value = serde_json::to_vec(&release).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize quarantine release: {}", e))
        })?;
        let key = format!("{:020}:{}", released_at, box_id);
        let mut batch = self.keyspace.batch();
        batch.insert(
            &self.release_partition,
            storable_key("quarantine release key", key.as_bytes())?,
            value,
        );
        batch.remove(&self.quarantine_partition, box_id.as_bytes());
        batch.commit().map_err(|e| {
            NoteError::StorageError(format!("Failed to release quarantined reserve: {}", e))
        })?;
        Ok(Some(release))
    }

    /// The quarantine releases, oldest first.
    pub fn quarantine_releases(&self) -> Result<Vec<QuarantineRelease>, NoteError> {
        self.release_partition
            .iter()
            .map(|item| {
                let (_key, value) = item.map_err(|e| {
                    NoteError::StorageError(format!("Failed to iterate quarantine releases: {}", e))
                })?;
                serde_json::from_slice(&value).map_err(|e| {
                    NoteError::StorageError(format!(
                        "Failed to deserialize quarantine release: {}",
                        e
                    ))
                })
            })
            .collect()
    }
}

impl TrackerStorage {
    /// Open or create a new tracker storage database
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, NoteError> {
        let keyspace = Config::new(path)
            .fsync_ms(Some(JOURNAL_FSYNC_MS))
            .open()
            .map_err(|e| NoteError::StorageError(format!("Failed to open database: {}", e)))?;

        let partition = keyspace
            .open_partition("tracker_metadata", PartitionCreateOptions::default())
            .map_err(|e| NoteError::StorageError(format!("Failed to open partition: {}", e)))?;
        let redemption_journal = keyspace
            .open_partition(REDEMPTION_JOURNAL_PARTITION, PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to open the redemption journal partition: {}",
                    e
                ))
            })?;
        let tree_repairs = keyspace
            .open_partition(RESERVE_TREE_REPAIRS_PARTITION, PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to open the reserve tree repairs partition: {}",
                    e
                ))
            })?;

        let redemption_drops = keyspace
            .open_partition(REDEMPTION_DROPS_PARTITION, PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to open the redemption drops partition: {}",
                    e
                ))
            })?;

        Ok(Self {
            keyspace,
            partition,
            redemption_journal,
            tree_repairs,
            redemption_drops,
            journal_writes: Default::default(),
        })
    }

    /// Remember that an operator dropped `drop.entry` (round 6, review P2-1), synced to disk.
    pub fn record_dropped_redemption(&self, drop: &DroppedRedemption) -> Result<(), NoteError> {
        let key = journal_key(&drop.entry.tx_id)?;
        let value = serde_json::to_vec(drop).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize a dropped redemption: {}", e))
        })?;
        self.redemption_drops
            .insert(key.as_bytes(), value)
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to record a dropped redemption: {}", e))
            })?;
        self.persist_journal()
    }

    /// The drop of `tx_id`, if an operator dropped it (`None` too for an id that is no
    /// transaction id).
    pub fn dropped_redemption(&self, tx_id: &str) -> Result<Option<DroppedRedemption>, NoteError> {
        let Ok(key) = journal_key(tx_id) else {
            return Ok(None);
        };
        match self.redemption_drops.get(key.as_bytes()) {
            Ok(Some(value)) => serde_json::from_slice(&value).map(Some).map_err(|e| {
                NoteError::StorageError(format!("Failed to read dropped redemption {}: {}", key, e))
            }),
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to read the redemption drops: {}",
                e
            ))),
        }
    }

    /// Record a reserve tree repair (round 6, risk 1) and sync it to disk: the record of an
    /// operator's change must survive a power loss like the change itself.
    pub fn record_tree_repair(&self, record: &ReserveTreeRepairRecord) -> Result<(), NoteError> {
        let value = serde_json::to_vec(record).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize a tree repair: {}", e))
        })?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| NoteError::StorageError(format!("Failed to get system time: {}", e)))?
            .as_nanos();
        self.tree_repairs
            .insert(nanos.to_be_bytes(), value)
            .map_err(|e| NoteError::StorageError(format!("Failed to record a tree repair: {}", e)))?;
        self.persist_journal()
    }

    /// Every recorded reserve tree repair, oldest first. A record that cannot be read is skipped
    /// with a warning.
    pub fn tree_repairs(&self) -> Result<Vec<ReserveTreeRepairRecord>, NoteError> {
        let mut records = Vec::new();
        for item in self.tree_repairs.iter() {
            let (_, value) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to read the tree repairs: {}", e))
            })?;
            match serde_json::from_slice::<ReserveTreeRepairRecord>(&value) {
                Ok(record) => records.push(record),
                Err(e) => tracing::warn!("Skipping an unreadable tree repair record: {}", e),
            }
        }
        Ok(records)
    }

    /// Write (or replace) the journal entry of `entry.tx_id`, which must be a transaction id
    /// (64 hex characters; round 5b, F2: an empty or oversized key would panic inside fjall after
    /// its write-ahead log took the write, and again at every restart).
    pub fn journal_redemption(&self, entry: &JournaledRedemption) -> Result<(), NoteError> {
        let key = journal_key(&entry.tx_id)?;
        let value = Self::journal_value(entry)?;
        let _writes = self.lock_journal_writes();
        self.insert_journal_entry(&key, value)
    }

    /// Write back `entry`, read from the journal earlier, ONLY if the journal still has an entry
    /// under its transaction id (round 5b, F8): an entry removed meanwhile (refused at submit,
    /// dropped or applied by an operator) is not brought back. Returns whether it was written.
    pub fn update_journaled_redemption(
        &self,
        entry: &JournaledRedemption,
    ) -> Result<bool, NoteError> {
        let key = journal_key(&entry.tx_id)?;
        let value = Self::journal_value(entry)?;
        let _writes = self.lock_journal_writes();
        let present = self
            .redemption_journal
            .contains_key(key.as_bytes())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to read the redemption journal: {}", e))
            })?;
        if !present {
            return Ok(false);
        }
        self.insert_journal_entry(&key, value)?;
        Ok(true)
    }

    /// The journal entry of `tx_id`, if there is one (`None` too for an id that is no
    /// transaction id: none is ever stored under it).
    pub fn journaled_redemption(
        &self,
        tx_id: &str,
    ) -> Result<Option<JournaledRedemption>, NoteError> {
        let Ok(key) = journal_key(tx_id) else {
            return Ok(None);
        };
        match self.redemption_journal.get(key.as_bytes()) {
            Ok(Some(value)) => serde_json::from_slice(&value).map(Some).map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to read journaled redemption {}: {}",
                    key, e
                ))
            }),
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to read the redemption journal: {}",
                e
            ))),
        }
    }

    /// Every journaled redemption, in transaction id order. An entry that cannot be read is
    /// skipped with a warning.
    pub fn journaled_redemptions(&self) -> Result<Vec<JournaledRedemption>, NoteError> {
        let mut entries = Vec::new();
        for item in self.redemption_journal.iter() {
            let (key, value) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to read the redemption journal: {}", e))
            })?;
            match serde_json::from_slice::<JournaledRedemption>(&value) {
                Ok(entry) => entries.push(entry),
                Err(e) => tracing::warn!(
                    "Skipping an unreadable redemption journal entry {}: {}",
                    String::from_utf8_lossy(&key),
                    e
                ),
            }
        }
        Ok(entries)
    }

    /// Remove the journal entry of `tx_id` (nothing when there is none). `tx_id` must be a
    /// transaction id, as in [`Self::journal_redemption`].
    pub fn remove_journaled_redemption(&self, tx_id: &str) -> Result<(), NoteError> {
        let key = journal_key(tx_id)?;
        let _writes = self.lock_journal_writes();
        self.redemption_journal
            .remove(key.as_bytes())
            .map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to remove a journaled redemption: {}",
                    e
                ))
            })
    }

    /// Sync this storage's journal (the redemption journal with it) to disk (round 5b, F9).
    /// `/redemption/submit` calls it once, after journaling and before broadcasting: a redemption
    /// the node may have must survive a power loss, not only a crash.
    pub fn persist_journal(&self) -> Result<(), NoteError> {
        self.keyspace
            .persist(fjall::PersistMode::SyncAll)
            .map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to sync the redemption journal to disk: {}",
                    e
                ))
            })
    }

    fn journal_value(entry: &JournaledRedemption) -> Result<Vec<u8>, NoteError> {
        serde_json::to_vec(entry).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize a journaled redemption: {}", e))
        })
    }

    fn insert_journal_entry(&self, key: &str, value: Vec<u8>) -> Result<(), NoteError> {
        self.redemption_journal
            .insert(key.as_bytes(), value)
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to journal a redemption: {}", e))
            })
    }

    /// The journal write lock; a panic while it was held leaves nothing half-written (each
    /// write is one fjall insert or removal), so a poisoned lock is taken over.
    fn lock_journal_writes(&self) -> std::sync::MutexGuard<'_, ()> {
        self.journal_writes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Store tracker box information in the database
    pub fn store_tracker_box(&self, tracker_box: &TrackerBoxInfo) -> Result<(), NoteError> {
        // The box id comes from the node's answer.
        let key = storable_key("tracker box id", tracker_box.box_id.as_bytes())?;
        let value = serde_json::to_vec(tracker_box).map_err(|e| {
            NoteError::StorageError(format!("Failed to serialize tracker box: {}", e))
        })?;

        self.partition
            .insert(key, &value)
            .map_err(|e| NoteError::StorageError(format!("Failed to store tracker box: {}", e)))?;

        Ok(())
    }

    /// Retrieve tracker box by box ID
    pub fn get_tracker_box(&self, box_id: &str) -> Result<Option<TrackerBoxInfo>, NoteError> {
        if !is_storable_key(box_id.as_bytes()) {
            return Ok(None);
        }
        match self.partition.get(box_id.as_bytes()) {
            Ok(Some(value_bytes)) => {
                let tracker_box: TrackerBoxInfo =
                    serde_json::from_slice(&value_bytes).map_err(|e| {
                        NoteError::StorageError(format!("Failed to deserialize tracker box: {}", e))
                    })?;
                Ok(Some(tracker_box))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to get tracker box: {}",
                e
            ))),
        }
    }

    /// Get all tracker boxes from the database
    pub fn get_all_tracker_boxes(&self) -> Result<Vec<TrackerBoxInfo>, NoteError> {
        let mut tracker_boxes = Vec::new();

        for item in self.partition.iter() {
            let (_key_bytes, value_bytes) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to iterate partition: {}", e))
            })?;

            let tracker_box: TrackerBoxInfo =
                serde_json::from_slice(&value_bytes).map_err(|e| {
                    NoteError::StorageError(format!("Failed to deserialize tracker box: {}", e))
                })?;

            tracker_boxes.push(tracker_box);
        }

        Ok(tracker_boxes)
    }

    /// Get the latest tracker box ID (highest last_verified_height)
    pub fn get_latest_tracker_box_id(&self) -> Result<Option<String>, NoteError> {
        let tracker_boxes = self.get_all_tracker_boxes()?;

        if tracker_boxes.is_empty() {
            return Ok(None);
        }

        // Find the box with the highest last_verified_height
        let latest_box = tracker_boxes
            .into_iter()
            .max_by_key(|b| b.last_verified_height);

        Ok(latest_box.map(|b| b.box_id))
    }

    /// Remove a tracker box from the database
    pub fn remove_tracker_box(&self, box_id: &str) -> Result<(), NoteError> {
        if !is_storable_key(box_id.as_bytes()) {
            return Ok(());
        }
        self.partition
            .remove(box_id.as_bytes())
            .map_err(|e| NoteError::StorageError(format!("Failed to remove tracker box: {}", e)))?;

        Ok(())
    }
}

impl AcceptancePolicyStorage {
    /// Open or create a new acceptance policy storage database
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, NoteError> {
        let keyspace = Config::new(path)
            .fsync_ms(Some(JOURNAL_FSYNC_MS))
            .open()
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to open policy database: {}", e))
            })?;

        let partition = keyspace
            .open_partition("acceptance_policies", PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!("Failed to open policy partition: {}", e))
            })?;
        let quarantine = keyspace
            .open_partition(POLICY_QUARANTINE_PARTITION, PartitionCreateOptions::default())
            .map_err(|e| {
                NoteError::StorageError(format!(
                    "Failed to open policy quarantine partition: {}",
                    e
                ))
            })?;

        Ok(Self {
            keyspace,
            partition,
            quarantine,
        })
    }

    /// Move the stored policy of `recipient_pubkey`, byte for byte, into the quarantine
    /// partition with `reason`, in one atomic batch (round 5, review 6: the startup re-check
    /// keeps what it refuses instead of deleting it). Returns `false` when no policy is stored.
    ///
    /// Quarantine key: recipient (33 bytes) || quarantined_at (u64 BE, Unix seconds), so a
    /// recipient refused twice keeps both records. Value: reason length (u32 BE) || reason ||
    /// the original record.
    pub fn quarantine_policy(
        &self,
        recipient_pubkey: &PubKey,
        reason: &str,
    ) -> Result<bool, NoteError> {
        let record = match self.partition.get(recipient_pubkey) {
            Ok(Some(record)) => record,
            Ok(None) => return Ok(false),
            Err(e) => {
                return Err(NoteError::StorageError(format!(
                    "Failed to read policy for quarantine: {}",
                    e
                )))
            }
        };
        let mut quarantined_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let key = loop {
            let mut key = Vec::with_capacity(33 + 8);
            key.extend_from_slice(recipient_pubkey);
            key.extend_from_slice(&quarantined_at.to_be_bytes());
            let taken = self.quarantine.contains_key(&key).map_err(|e| {
                NoteError::StorageError(format!("Failed to read policy quarantine: {}", e))
            })?;
            if !taken {
                break key;
            }
            quarantined_at += 1;
        };
        let reason = reason.as_bytes();
        let mut value = Vec::with_capacity(4 + reason.len() + record.len());
        value.extend_from_slice(&(reason.len() as u32).to_be_bytes());
        value.extend_from_slice(reason);
        value.extend_from_slice(&record);

        let mut batch = self.keyspace.batch();
        batch.insert(&self.quarantine, key, value);
        batch.remove(&self.partition, recipient_pubkey.to_vec());
        batch
            .commit()
            .map_err(|e| NoteError::StorageError(format!("Failed to quarantine policy: {}", e)))?;
        Ok(true)
    }

    /// Every quarantined policy, oldest key first; unreadable entries are skipped with a
    /// warning.
    pub fn list_quarantined_policies(&self) -> Result<Vec<QuarantinedPolicy>, NoteError> {
        let mut out = Vec::new();
        for item in self.quarantine.iter() {
            let (key, value) = item.map_err(|e| {
                NoteError::StorageError(format!("Failed to read policy quarantine: {}", e))
            })?;
            let parsed = (|| {
                let recipient_pubkey = PubKey::try_from(key.get(..33)?).ok()?;
                let quarantined_at = u64::from_be_bytes(key.get(33..41)?.try_into().ok()?);
                let reason_len =
                    u32::from_be_bytes(value.get(..4)?.try_into().ok()?) as usize;
                let reason_end = 4usize.checked_add(reason_len)?;
                let reason = String::from_utf8(value.get(4..reason_end)?.to_vec()).ok()?;
                let record = value.get(reason_end..)?.to_vec();
                Some(QuarantinedPolicy {
                    recipient_pubkey,
                    quarantined_at,
                    reason,
                    record,
                })
            })();
            match parsed {
                Some(entry) => out.push(entry),
                None => tracing::warn!(
                    "Skipping an unreadable policy quarantine entry ({} key bytes)",
                    key.len()
                ),
            }
        }
        Ok(out)
    }

    /// Store a signed acceptance policy for a recipient
    ///
    /// Key: recipient_pubkey (33 bytes)
    /// Value: 8 bytes timestamp (u64 BE) + 4 bytes policy_json_len (u32 BE) + policy_json bytes + 4 bytes sig_len (u32 BE) + signature bytes
    pub fn store_policy(
        &self,
        recipient_pubkey: &PubKey,
        policy_json: &str,
        signature: &str,
    ) -> Result<(), NoteError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let policy_json_bytes = policy_json.as_bytes();
        let signature_bytes = signature.as_bytes();

        let mut value =
            Vec::with_capacity(8 + 4 + policy_json_bytes.len() + 4 + signature_bytes.len());
        value.extend_from_slice(&timestamp.to_be_bytes());
        value.extend_from_slice(&(policy_json_bytes.len() as u32).to_be_bytes());
        value.extend_from_slice(policy_json_bytes);
        value.extend_from_slice(&(signature_bytes.len() as u32).to_be_bytes());
        value.extend_from_slice(signature_bytes);

        self.partition
            .insert(recipient_pubkey, &value)
            .map_err(|e| NoteError::StorageError(format!("Failed to store policy: {}", e)))?;

        Ok(())
    }

    /// Retrieve a stored acceptance policy for a recipient
    pub fn get_policy(&self, recipient_pubkey: &PubKey) -> Result<Option<StoredPolicy>, NoteError> {
        match self.partition.get(recipient_pubkey) {
            Ok(Some(value_bytes)) => {
                if value_bytes.len() < 12 {
                    return Err(NoteError::StorageError(
                        "Invalid policy record format (too short)".to_string(),
                    ));
                }

                let mut offset = 0;
                let timestamp =
                    u64::from_be_bytes(value_bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;

                let policy_len =
                    u32::from_be_bytes(value_bytes[offset..offset + 4].try_into().unwrap())
                        as usize;
                offset += 4;

                if value_bytes.len() < offset + policy_len + 4 {
                    return Err(NoteError::StorageError(
                        "Invalid policy record format (policy length mismatch)".to_string(),
                    ));
                }

                let policy_json =
                    String::from_utf8(value_bytes[offset..offset + policy_len].to_vec()).map_err(
                        |e| NoteError::StorageError(format!("Invalid policy JSON encoding: {}", e)),
                    )?;
                offset += policy_len;

                let sig_len =
                    u32::from_be_bytes(value_bytes[offset..offset + 4].try_into().unwrap())
                        as usize;
                offset += 4;

                if value_bytes.len() < offset + sig_len {
                    return Err(NoteError::StorageError(
                        "Invalid policy record format (signature length mismatch)".to_string(),
                    ));
                }

                let signature = String::from_utf8(value_bytes[offset..offset + sig_len].to_vec())
                    .map_err(|e| {
                    NoteError::StorageError(format!("Invalid signature encoding: {}", e))
                })?;

                Ok(Some(StoredPolicy {
                    timestamp,
                    policy_json,
                    signature,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(NoteError::StorageError(format!(
                "Failed to get policy: {}",
                e
            ))),
        }
    }

    /// Remove a stored policy for a recipient
    pub fn remove_policy(&self, recipient_pubkey: &PubKey) -> Result<(), NoteError> {
        self.partition
            .remove(recipient_pubkey)
            .map_err(|e| NoteError::StorageError(format!("Failed to remove policy: {}", e)))?;
        Ok(())
    }

    /// List all stored policies with their recipient pubkeys
    ///
    /// Returns a vector of (recipient_pubkey_hex, timestamp) tuples
    pub fn list_policies(&self) -> Result<Vec<(String, u64)>, NoteError> {
        let mut policies = Vec::new();
        for item in self.partition.iter() {
            match item {
                Ok((key, value)) => {
                    if key.len() == 33 && value.len() >= 8 {
                        let pubkey_hex = hex::encode(&key);
                        let timestamp = u64::from_be_bytes(value[0..8].try_into().unwrap());
                        policies.push((pubkey_hex, timestamp));
                    }
                }
                Err(e) => {
                    tracing::warn!("Error iterating policies: {}", e);
                }
            }
        }
        Ok(policies)
    }
}

#[cfg(test)]
mod redemption_journal_tests {
    use super::*;

    fn entry(tx: &str) -> JournaledRedemption {
        JournaledRedemption {
            tx_id: tx.to_string(),
            reserve_box_id: "ab".repeat(32),
            issuer_pubkey: "02".repeat(33),
            recipient_pubkey: "03".repeat(33),
            denomination: "erg".to_string(),
            redeemed_amount: 100,
            new_already_redeemed: 100,
            data_input_ids: vec!["cd".repeat(32)],
            submitted_at_ms: 1_700_000_000_000,
            ..Default::default()
        }
    }

    /// Round 5 (C8): a tracker_boxes dir written by 6113b8d (only the `tracker_metadata`
    /// partition) opens unchanged with an empty journal; entries are written, replaced, read
    /// and removed by transaction id, and survive a reopen.
    #[test]
    fn a_6113b8d_tracker_dir_opens_with_an_empty_redemption_journal() {
        let dir = tempfile::tempdir().unwrap();
        {
            let keyspace = Config::new(dir.path()).open().unwrap();
            let partition = keyspace
                .open_partition("tracker_metadata", PartitionCreateOptions::default())
                .unwrap();
            partition.insert(b"some-box", b"{}").unwrap();
            keyspace.persist(fjall::PersistMode::SyncAll).unwrap();
        }
        let storage = TrackerStorage::open(dir.path()).unwrap();
        assert!(storage.journaled_redemptions().unwrap().is_empty());

        let (a, b) = ("aa".repeat(32), "BB".repeat(32));
        storage.journal_redemption(&entry(&a)).unwrap();
        storage.journal_redemption(&entry(&b)).unwrap();
        let mut counted = entry(&a);
        counted.missing_checks = 2;
        storage.journal_redemption(&counted).unwrap();
        let entries = storage.journaled_redemptions().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], counted);
        storage.remove_journaled_redemption(&b.to_ascii_lowercase()).unwrap();
        drop(storage);

        let storage = TrackerStorage::open(dir.path()).unwrap();
        assert_eq!(storage.journaled_redemptions().unwrap(), vec![counted]);
        // An entry without the round-5 counters reads with their defaults.
        storage
            .redemption_journal
            .insert(
                "cc".repeat(32).as_bytes(),
                serde_json::json!({
                    "tx_id": "cc".repeat(32), "reserve_box_id": "r", "issuer_pubkey": "i",
                    "recipient_pubkey": "p", "denomination": "erg", "redeemed_amount": 1,
                    "new_already_redeemed": 1, "data_input_ids": [], "submitted_at_ms": 1
                })
                .to_string(),
            )
            .unwrap();
        let read = storage.journaled_redemptions().unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[1].missing_checks, 0);
        assert_eq!(read[1].apply_error, None);
        // ...and without the round-5b fields too.
        assert_eq!(read[1].reserve_tree_timestamp, None);
        assert_eq!(read[1].reserve_r5_digest, None);
        assert_eq!(read[1].digest_mismatch, None);
        assert_eq!(read[1].next_check_at_ms, 0);
        // ...and without the round-6 field.
        assert!(!read[1].detected_on_chain);
    }

    /// Round 6 (review P2-1): dropped entries are remembered by transaction id (any case), survive
    /// a reopen, and a dir written before opens with none.
    #[test]
    fn dropped_redemptions_are_remembered_by_id() {
        let dir = tempfile::tempdir().unwrap();
        {
            let keyspace = Config::new(dir.path()).open().unwrap();
            let partition = keyspace
                .open_partition("tracker_metadata", PartitionCreateOptions::default())
                .unwrap();
            partition.insert(b"some-box", b"{}").unwrap();
            keyspace.persist(fjall::PersistMode::SyncAll).unwrap();
        }
        let storage = TrackerStorage::open(dir.path()).unwrap();
        let tx = "ab".repeat(32);
        assert_eq!(storage.dropped_redemption(&tx).unwrap(), None);
        let dropped = DroppedRedemption {
            dropped_at_ms: 7,
            entry: entry(&tx),
        };
        storage.record_dropped_redemption(&dropped).unwrap();
        drop(storage);
        let storage = TrackerStorage::open(dir.path()).unwrap();
        assert_eq!(
            storage.dropped_redemption(&tx.to_ascii_uppercase()).unwrap(),
            Some(dropped)
        );
        assert_eq!(storage.dropped_redemption("x").unwrap(), None);
        assert!(storage
            .record_dropped_redemption(&DroppedRedemption {
                dropped_at_ms: 1,
                entry: entry("short"),
            })
            .is_err());
    }

    /// Round 6 (risk 1): a tracker_boxes dir written before round 6 opens with no tree repairs;
    /// repairs are recorded in order and survive a reopen; a record without the optional
    /// fields reads with their defaults.
    #[test]
    fn tree_repairs_are_recorded_in_order_and_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let keyspace = Config::new(dir.path()).open().unwrap();
            let partition = keyspace
                .open_partition("tracker_metadata", PartitionCreateOptions::default())
                .unwrap();
            partition.insert(b"some-box", b"{}").unwrap();
            keyspace.persist(fjall::PersistMode::SyncAll).unwrap();
        }
        let storage = TrackerStorage::open(dir.path()).unwrap();
        assert!(storage.tree_repairs().unwrap().is_empty());
        let record = |at: u64, tx_id: Option<String>| ReserveTreeRepairRecord {
            repaired_at_ms: at,
            issuer_pubkey: "02".repeat(33),
            recipient_pubkey: "03".repeat(33),
            denomination: "erg".to_string(),
            reserve_box_id: "ab".repeat(32),
            tx_id,
            repair: crate::ReserveTreeRepair {
                outcome: crate::ReserveTreeRepairOutcome::Repaired,
                before: None,
                after: crate::ReserveTreeValue {
                    timestamp: 5,
                    already_redeemed: 7,
                },
                note_redeemed_before: 0,
                digest_before: "x".to_string(),
                digest_after: "y".to_string(),
                chain_digest: "y".to_string(),
            },
            cleared_marked: vec![],
        };
        let (first, second) = (record(1, Some("cd".repeat(32))), record(2, None));
        storage.record_tree_repair(&first).unwrap();
        storage.record_tree_repair(&second).unwrap();
        drop(storage);
        let storage = TrackerStorage::open(dir.path()).unwrap();
        assert_eq!(storage.tree_repairs().unwrap(), vec![first, second.clone()]);

        let mut bare = serde_json::to_value(&second).unwrap();
        bare.as_object_mut().unwrap().remove("tx_id");
        bare.as_object_mut().unwrap().remove("cleared_marked");
        let read: ReserveTreeRepairRecord = serde_json::from_value(bare).unwrap();
        assert_eq!(read, second);
    }

    /// Round 5b, F8 and F9: a write-back of an entry read earlier lands only while the entry
    /// is still journaled, so an entry removed meanwhile stays removed; one entry reads by id;
    /// the journal syncs to disk on demand.
    #[test]
    fn a_write_back_never_brings_back_a_removed_entry() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TrackerStorage::open(dir.path()).unwrap();
        let tx = "ab".repeat(32);
        let read_earlier = entry(&tx);
        assert!(!storage.update_journaled_redemption(&read_earlier).unwrap());
        assert!(storage.journaled_redemptions().unwrap().is_empty());

        storage.journal_redemption(&read_earlier).unwrap();
        storage.persist_journal().unwrap();
        let mut counted = read_earlier.clone();
        counted.missing_checks = 3;
        assert!(storage.update_journaled_redemption(&counted).unwrap());
        assert_eq!(
            storage.journaled_redemption(&tx.to_ascii_uppercase()).unwrap(),
            Some(counted.clone())
        );

        // Removed (say, refused at submit) while the confirmer was looking at it.
        storage.remove_journaled_redemption(&tx).unwrap();
        counted.missing_checks = 4;
        assert!(!storage.update_journaled_redemption(&counted).unwrap());
        assert!(storage.journaled_redemptions().unwrap().is_empty());
        assert_eq!(storage.journaled_redemption(&tx).unwrap(), None);
        assert_eq!(storage.journaled_redemption("").unwrap(), None);
    }

    /// Round 5b, F2: lsm-tree asserts a key's length only after fjall's write-ahead log took
    /// the write, so an empty or oversized key would panic now and at every restart. The journal
    /// takes transaction ids only, and the box-id keyed partitions (ids from the node) refuse
    /// what fjall cannot hold; nothing reaches the log, and the dir reopens.
    #[test]
    fn keys_from_outside_input_are_checked_before_fjall_sees_them() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TrackerStorage::open(dir.path()).unwrap();
        let huge = "a".repeat(MAX_STORABLE_KEY_LEN + 1);
        for bad in [
            String::new(),
            "ab".repeat(31),
            "ab".repeat(33),
            "zz".repeat(32),
            huge.clone(),
        ] {
            assert!(storage.journal_redemption(&entry(&bad)).is_err(), "{}", bad.len());
            assert!(storage.remove_journaled_redemption(&bad).is_err(), "{}", bad.len());
        }
        for bad in [String::new(), huge.clone()] {
            let tracker_box = TrackerBoxInfo {
                box_id: bad.clone(),
                tracker_pubkey: String::new(),
                state_commitment: String::new(),
                last_verified_height: 1,
                value: 1,
                creation_height: 1,
                tracker_nft_id: String::new(),
            };
            assert!(storage.store_tracker_box(&tracker_box).is_err());
            assert!(storage.get_tracker_box(&bad).unwrap().is_none());
            storage.remove_tracker_box(&bad).unwrap();
        }
        drop(storage);
        let storage = TrackerStorage::open(dir.path()).unwrap();
        assert!(storage.journaled_redemptions().unwrap().is_empty());
        assert!(storage.get_all_tracker_boxes().unwrap().is_empty());

        let reserves_dir = tempfile::tempdir().unwrap();
        let reserves = ReserveStorage::open(reserves_dir.path()).unwrap();
        for bad in [String::new(), huge] {
            let quarantined = QuarantinedReserve {
                box_id: bad.clone(),
                owner_pubkey: String::new(),
                denomination: "ERG".to_string(),
                reason: "test".to_string(),
                quarantined_at: 1,
            };
            assert!(reserves.store_quarantined(&quarantined).is_err());
            assert!(reserves.get_quarantined(&bad).unwrap().is_none());
            assert!(reserves.get_reserve(&bad).unwrap().is_none());
            reserves.remove_reserve(&bad).unwrap();
        }
        drop(reserves);
        let reserves = ReserveStorage::open(reserves_dir.path()).unwrap();
        assert!(reserves.get_all_quarantined().unwrap().is_empty());
    }
}

#[cfg(test)]
mod policy_quarantine_tests {
    use super::*;

    const GOOD: &str = r#"{"root":"a","predicates":[{"type":"no_pending_refund","name":"a"}]}"#;

    /// The record `store_policy` wrote at 6113b8d (and still writes): timestamp (u64 BE),
    /// JSON length (u32 BE), JSON, signature length (u32 BE), signature.
    fn record_6113b8d(timestamp: u64, json: &str, signature: &str) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&timestamp.to_be_bytes());
        value.extend_from_slice(&(json.len() as u32).to_be_bytes());
        value.extend_from_slice(json.as_bytes());
        value.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        value.extend_from_slice(signature.as_bytes());
        value
    }

    /// Round 5, review 6: a policy dir written by 6113b8d (only the `acceptance_policies`
    /// partition) opens unchanged, its policies read as before, and the quarantine partition
    /// is added next to them; a quarantined policy keeps its exact bytes and its reason.
    #[test]
    fn a_6113b8d_policy_dir_opens_and_a_quarantine_keeps_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let (good, bad): (PubKey, PubKey) = ([0x02; 33], [0x03; 33]);
        let bad_record = record_6113b8d(1_700_000_001, r#"{"predicates":[]"#, "sig-b");
        {
            // The 6113b8d layout, written with fjall directly.
            let keyspace = Config::new(dir.path()).open().unwrap();
            let partition = keyspace
                .open_partition("acceptance_policies", PartitionCreateOptions::default())
                .unwrap();
            partition
                .insert(good, record_6113b8d(1_700_000_000, GOOD, "sig-a"))
                .unwrap();
            partition.insert(bad, bad_record.clone()).unwrap();
            keyspace.persist(fjall::PersistMode::SyncAll).unwrap();
        }

        let storage = AcceptancePolicyStorage::open(dir.path()).unwrap();
        let stored = storage.get_policy(&good).unwrap().unwrap();
        assert_eq!(stored.timestamp, 1_700_000_000);
        assert_eq!(stored.policy_json, GOOD);
        assert_eq!(stored.signature, "sig-a");
        assert_eq!(storage.list_policies().unwrap().len(), 2);
        assert!(storage.list_quarantined_policies().unwrap().is_empty());

        assert!(storage.quarantine_policy(&bad, "root missing").unwrap());
        assert!(!storage.quarantine_policy(&bad, "again").unwrap(), "nothing left to move");
        assert!(storage.get_policy(&bad).unwrap().is_none());
        assert!(storage.get_policy(&good).unwrap().is_some());
        let quarantined = storage.list_quarantined_policies().unwrap();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].recipient_pubkey, bad);
        assert_eq!(quarantined[0].reason, "root missing");
        assert_eq!(quarantined[0].record, bad_record);

        // A second refusal of the same recipient keeps both records.
        storage.store_policy(&bad, GOOD, "sig-c").unwrap();
        assert!(storage.quarantine_policy(&bad, "second").unwrap());
        let quarantined = storage.list_quarantined_policies().unwrap();
        assert_eq!(quarantined.len(), 2);
        assert_eq!(quarantined[1].reason, "second");

        // The moves survive a restart.
        drop(storage);
        let storage = AcceptancePolicyStorage::open(dir.path()).unwrap();
        assert_eq!(storage.list_quarantined_policies().unwrap().len(), 2);
        assert_eq!(storage.list_policies().unwrap().len(), 1);
    }
}

#[cfg(test)]
mod quarantine_release_tests {
    use super::*;

    fn record(box_id: &str) -> QuarantinedReserve {
        QuarantinedReserve {
            box_id: box_id.to_string(),
            owner_pubkey: "02".repeat(33),
            denomination: "ERG".to_string(),
            reason: "duplicate reserve box".to_string(),
            quarantined_at: 1_700_000_000_000,
        }
    }

    /// Round 6c (c): a release journals the record with the operator's note and
    /// takes it out of quarantine in one batch; the journal survives a reopen,
    /// oldest first; a box not quarantined (or released already) gives `None`.
    /// A reserve dir without the release partition (round 6b) opens unchanged.
    #[test]
    fn a_release_journals_the_record_and_lifts_the_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        {
            let storage = ReserveStorage::open(dir.path()).unwrap();
            storage
                .store_quarantined(&record(&"aa".repeat(32)))
                .unwrap();
            storage
                .store_quarantined(&record(&"bb".repeat(32)))
                .unwrap();
            let release = storage
                .release_quarantined(&"bb".repeat(32), "checked on chain: owner's top-up", 2_000)
                .unwrap()
                .unwrap();
            assert_eq!(release.record.reason, "duplicate reserve box");
            assert!(storage.get_quarantined(&"bb".repeat(32)).unwrap().is_none());
            assert!(storage.get_quarantined(&"aa".repeat(32)).unwrap().is_some());
            assert!(storage
                .release_quarantined(&"bb".repeat(32), "again", 3_000)
                .unwrap()
                .is_none());
            storage
                .release_quarantined(&"aa".repeat(32), "second", 1_000)
                .unwrap()
                .unwrap();
        }
        let storage = ReserveStorage::open(dir.path()).unwrap();
        let releases = storage.quarantine_releases().unwrap();
        let order: Vec<(&str, u64)> = releases
            .iter()
            .map(|r| (r.note.as_str(), r.released_at))
            .collect();
        assert_eq!(
            order,
            vec![
                ("second", 1_000),
                ("checked on chain: owner's top-up", 2_000)
            ]
        );
        assert!(storage.get_all_quarantined().unwrap().is_empty());
    }
}

#[cfg(test)]
mod removed_reserve_tests {
    use super::*;

    fn removed(box_id: &str, removed_at: u64) -> RemovedReserve {
        RemovedReserve {
            record: ExtendedReserveInfo {
                base_info: crate::ReserveInfo {
                    collateral_amount: 1_000_000_000,
                    last_updated_height: 0,
                    contract_address: "test_p2s".to_string(),
                    tracker_nft_id: "1f".repeat(32),
                    refund_initiation_height: 0,
                    reserve_token_id: String::new(),
                },
                total_debt: 0,
                box_id: box_id.to_string(),
                owner_pubkey: "02".repeat(33),
                last_updated_timestamp: 0,
            },
            nft: Some("4e".repeat(32)),
            removed_at,
            removed_height: None,
        }
    }

    /// Round 6f: removed reserve boxes are kept across a reopen and forgotten
    /// one by one; the reserves and quarantine partitions are untouched, and a
    /// reserve dir from before round 6f opens unchanged.
    /// Round 6f-2: a record stored before `removed_height` existed loads,
    /// without a removal height.
    #[test]
    fn test_a_record_without_removed_height_loads() {
        let mut value = serde_json::to_value(removed(&"5a".repeat(32), 7)).unwrap();
        value.as_object_mut().unwrap().remove("removed_height");
        let loaded: RemovedReserve = serde_json::from_value(value).unwrap();
        assert_eq!(loaded.removed_at, 7);
        assert_eq!(loaded.removed_height, None);
    }

    #[test]
    fn removed_reserves_survive_a_reopen_and_are_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let tracked = removed(&"cc".repeat(32), 0).record;
        {
            let storage = ReserveStorage::open(dir.path()).unwrap();
            storage.store_reserve(&tracked).unwrap();
            assert!(storage.removed_reserves().unwrap().is_empty());
            storage
                .store_removed(&removed(&"aa".repeat(32), 1))
                .unwrap();
            storage
                .store_removed(&removed(&"bb".repeat(32), 2))
                .unwrap();
        }
        let storage = ReserveStorage::open(dir.path()).unwrap();
        let kept = storage.removed_reserves().unwrap();
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].record.box_id, "aa".repeat(32));
        assert_eq!(kept[0].nft.as_deref(), Some("4e".repeat(32).as_str()));
        assert_eq!(kept[1].removed_at, 2);
        storage.forget_removed(&"aa".repeat(32)).unwrap();
        storage.forget_removed(&"dd".repeat(32)).unwrap();
        let kept = storage.removed_reserves().unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].record.box_id, "bb".repeat(32));
        assert_eq!(storage.get_all_reserves().unwrap().len(), 1);
        assert!(storage.get_all_quarantined().unwrap().is_empty());
    }

    /// Round 8: the NFT facts are kept across a reopen and forgotten one by
    /// one; ids that are not lower-case 32-byte hex are refused; a damaged
    /// entry is skipped, removed and counted; the reserves are untouched.
    #[test]
    fn nft_facts_survive_a_reopen_and_damage_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let tracked = removed(&"cc".repeat(32), 0).record;
        {
            let storage = ReserveStorage::open(dir.path()).unwrap();
            assert_eq!(storage.nft_facts().unwrap(), NftFacts::default());
            storage.store_reserve(&tracked).unwrap();
            storage.store_box_nft(&"cc".repeat(32), &"4e".repeat(32)).unwrap();
            storage.store_box_nft(&"dd".repeat(32), &"4f".repeat(32)).unwrap();
            storage.store_nft_emission(&"4e".repeat(32), 1).unwrap();
            assert!(storage.store_box_nft(&"ee".repeat(32), &"4E".repeat(32)).is_err());
            assert!(storage.store_box_nft(&"ee".repeat(32), "4e").is_err());
            assert!(storage.store_nft_emission("x", 1).is_err());
            storage.insert_raw_nft_fact(false, b"ff", b"{\"nft\":1}");
            storage.insert_raw_nft_fact(true, &[0xff; 64], b"{\"emission\":1}");
            storage.insert_raw_nft_fact(true, "50".repeat(32).as_bytes(), b"{}");
        }
        let storage = ReserveStorage::open(dir.path()).unwrap();
        let facts = storage.nft_facts().unwrap();
        assert_eq!(facts.dropped, 3);
        assert_eq!(
            facts.box_nft,
            std::collections::HashMap::from([
                ("cc".repeat(32), "4e".repeat(32)),
                ("dd".repeat(32), "4f".repeat(32)),
            ])
        );
        assert_eq!(
            facts.emission,
            std::collections::HashMap::from([("4e".repeat(32), 1)])
        );
        assert_eq!(storage.nft_facts().unwrap().dropped, 0);
        storage.forget_box_nft(&"dd".repeat(32)).unwrap();
        storage.forget_box_nft("").unwrap();
        storage.forget_nft_emission(&"4e".repeat(32)).unwrap();
        let facts = storage.nft_facts().unwrap();
        assert_eq!(facts.box_nft.len(), 1);
        assert!(facts.emission.is_empty());
        assert_eq!(storage.get_all_reserves().unwrap().len(), 1);
    }

    /// Round 8, rollback: a reserve dir with the two new partitions opens with
    /// only the partitions round 7b opens (the keyspace keeps the others as
    /// they are), and opens again with round 8 afterwards, facts intact.
    #[test]
    fn a_dir_with_the_nft_partitions_opens_without_them() {
        let dir = tempfile::tempdir().unwrap();
        let tracked = removed(&"cc".repeat(32), 0).record;
        {
            let storage = ReserveStorage::open(dir.path()).unwrap();
            storage.store_reserve(&tracked).unwrap();
            storage.store_removed(&removed(&"aa".repeat(32), 1)).unwrap();
            storage.store_box_nft(&"cc".repeat(32), &"4e".repeat(32)).unwrap();
            storage.store_nft_emission(&"4e".repeat(32), 1).unwrap();
        }
        {
            // What `ReserveStorage::open` of round 7b opens.
            let keyspace = Config::new(dir.path()).open().unwrap();
            let reserves = keyspace
                .open_partition("reserves", PartitionCreateOptions::default())
                .unwrap();
            for name in ["quarantined_reserves", "quarantine_releases", "removed_reserves"] {
                keyspace
                    .open_partition(name, PartitionCreateOptions::default())
                    .unwrap();
            }
            assert_eq!(reserves.iter().count(), 1);
            reserves.insert("dd".repeat(32), b"{}").unwrap();
            reserves.remove("dd".repeat(32)).unwrap();
        }
        let storage = ReserveStorage::open(dir.path()).unwrap();
        assert_eq!(storage.get_all_reserves().unwrap().len(), 1);
        assert_eq!(storage.removed_reserves().unwrap().len(), 1);
        let facts = storage.nft_facts().unwrap();
        assert_eq!(facts.box_nft.len(), 1);
        assert_eq!(facts.emission.len(), 1);
    }
}
