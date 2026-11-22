//! `note`: the issuer signs the cumulative debt to the recipient and posts it to `POST /notes`.
//!
//! The note is signed exactly as the tracker and the reserve contract check it: the 80-byte
//! message `debtKey ‖ total (8 bytes BE) ‖ timestamp ms (8 bytes BE) ‖ tracker NFT id`, with
//! `debtKey = blake2b256(issuer ‖ recipient)` for ERG debt, and a Basis Schnorr signature
//! `a ‖ z` made by the tracker's own signer (with its retry for contract-compatible values).

use std::time::{SystemTime, UNIX_EPOCH};

use basis_store::DenomKey;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::keys::FileKey;
use crate::{Context, Report};

/// A note as `GET /notes/issuer/{issuer}/recipient/{recipient}` returns it.
#[derive(Debug, Clone, Deserialize)]
pub struct StoredNote {
    pub issuer_pubkey: String,
    pub recipient_pubkey: String,
    /// Cumulative debt (nanoERG).
    pub amount_collected: u64,
    /// The tracker's record of what was redeemed so far.
    pub amount_redeemed: u64,
    pub timestamp: u64,
    pub signature: String,
    pub tracker_nft_id: String,
    pub denomination: String,
    pub confirmation: Option<NoteConfirmation>,
}

/// On-chain commitment state of a note.
#[derive(Debug, Clone, Deserialize)]
pub struct NoteConfirmation {
    /// `local_only`, `pending` or `confirmed`.
    pub status: String,
    pub confirmed_total_debt: Option<u64>,
    pub pending_total_debt: Option<u64>,
    pub confirmed_box_id: Option<String>,
    pub confirmed_height: Option<u64>,
    pub pending_tx_id: Option<String>,
    pub redeemable: bool,
    pub redeemable_amount: u64,
}

impl StoredNote {
    /// One line: totals, timestamp and commitment state.
    pub fn summary(&self) -> String {
        let confirmation = match &self.confirmation {
            Some(c) => format!(
                "{}, committed total {}, pending total {}, tracker box {}, height {}, redeemable \
                 now {} nanoERG",
                c.status,
                show(c.confirmed_total_debt),
                show(c.pending_total_debt),
                c.confirmed_box_id.as_deref().unwrap_or("-"),
                show(c.confirmed_height),
                c.redeemable_amount
            ),
            None => "no commitment record".to_string(),
        };
        format!(
            "total {} nanoERG at timestamp {}, redeemed {} nanoERG; {confirmation}",
            self.amount_collected, self.timestamp, self.amount_redeemed
        )
    }
}

fn show(v: Option<u64>) -> String {
    v.map_or("-".to_string(), |v| v.to_string())
}

/// The tracker's ERG note from `issuer` to `recipient`, `None` when there is none.
pub async fn fetch_note(
    context: &Context,
    issuer: &[u8; 33],
    recipient: &[u8; 33],
) -> Result<Option<StoredNote>, String> {
    let path = format!(
        "/notes/issuer/{}/recipient/{}?denomination=erg",
        hex::encode(issuer),
        hex::encode(recipient)
    );
    let response = context.tracker.get(&path).await?;
    if response.status == 404 {
        return Ok(None);
    }
    let data = response.data(&format!("GET {path}"), 200)?;
    if data.is_null() {
        return Ok(None);
    }
    serde_json::from_value(data)
        .map(Some)
        .map_err(|e| format!("GET {path}: unexpected note: {e}"))
}

/// The 80-byte message an ERG note (and the redemption of it) is signed over.
pub fn note_message(
    issuer: &[u8; 33],
    recipient: &[u8; 33],
    total: u64,
    timestamp: u64,
    tracker_nft: &[u8; 32],
) -> Result<[u8; 80], String> {
    let message = basis_store::schnorr::signing_message(
        issuer,
        recipient,
        &DenomKey::Erg,
        total,
        timestamp,
        tracker_nft,
    );
    // The tracker and the reserve contract check the same bytes.
    let contract = basis_offchain::signing::redemption_signing_message(
        issuer,
        recipient,
        &DenomKey::Erg,
        total,
        timestamp,
        tracker_nft,
    );
    if message != contract {
        return Err("the note message differs from the contract's redemption message".to_string());
    }
    Ok(contract)
}

/// Milliseconds since the epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What `note` posts.
#[derive(Debug, Clone)]
pub struct NoteRequest {
    pub recipient: [u8; 33],
    /// Cumulative debt, nanoERG.
    pub total: u64,
    /// Timestamp in ms; now when `None`.
    pub timestamp_ms: Option<u64>,
    pub dry_run: bool,
}

/// A tracker co-signature in a `POST /notes` answer, if the tracker returned one.
fn co_signature(data: &Value) -> Option<String> {
    ["tracker_signature", "co_signature", "signature"]
        .iter()
        .find_map(|k| data.get(*k).and_then(Value::as_str).map(str::to_string))
}

/// `note`.
pub async fn note(
    context: &Context,
    issuer: &FileKey,
    request: &NoteRequest,
    report: &mut Report,
) -> Result<(), String> {
    let issuer_pk = issuer.public_key();
    let recipient = request.recipient;
    if recipient == issuer_pk {
        return Err("the recipient is the issuer's own key".to_string());
    }
    if request.total == 0 || request.total > i64::MAX as u64 {
        return Err(format!(
            "--total must be between 1 and {} nanoERG (the contract reads it as a signed Long)",
            i64::MAX
        ));
    }
    report.line(format!(
        "note: issuer {} -> recipient {}, cumulative debt {} nanoERG, tracker NFT {}",
        hex::encode(issuer_pk),
        hex::encode(recipient),
        request.total,
        hex::encode(context.tracker_nft)
    ));

    // The tracker refuses a lower total and a timestamp that is not after the current note's.
    let current = fetch_note(context, &issuer_pk, &recipient).await?;
    match &current {
        Some(n) => report.line(format!("current note: {}", n.summary())),
        None => report.line("current note: none (first note for this pair)"),
    }
    let timestamp = request.timestamp_ms.unwrap_or_else(now_ms);
    if let Some(current) = &current {
        if request.total < current.amount_collected {
            return Err(format!(
                "--total {} is below the current cumulative debt {}: a note states the whole \
                 debt so far, and it never decreases",
                request.total, current.amount_collected
            ));
        }
        if timestamp <= current.timestamp {
            return Err(format!(
                "timestamp {timestamp} is not after the current note's {}",
                current.timestamp
            ));
        }
    }

    let message = note_message(
        &issuer_pk,
        &recipient,
        request.total,
        timestamp,
        &context.tracker_nft,
    )?;
    let signature = issuer.schnorr_sign(&message)?;
    basis_store::schnorr::schnorr_verify(&signature, &message, &issuer_pk)
        .map_err(|e| format!("the new signature does not verify: {e:?}"))?;
    report.line(format!(
        "message (80 bytes: debt key, total, timestamp {timestamp} ms, tracker NFT): {}",
        hex::encode(message)
    ));
    report.line(format!(
        "issuer signature (65 bytes: a, z), verified: {}",
        hex::encode(signature)
    ));

    let body = json!({
        "issuer_pubkey": hex::encode(issuer_pk),
        "recipient_pubkey": hex::encode(recipient),
        "amount": request.total,
        "timestamp": timestamp,
        "signature": hex::encode(signature),
        "tracker_nft_id": hex::encode(context.tracker_nft),
        "denomination": "erg",
    });
    report.line(format!("POST {}/notes {body}", context.tracker.url()));
    if request.dry_run {
        report.line("dry run: nothing posted");
        return Ok(());
    }
    let response = context.tracker.post("/notes", &body).await?;
    report.line(format!("HTTP {}", response.status));
    report.line(response.pretty());
    let data = response.data("POST /notes", 201)?;
    match co_signature(&data) {
        Some(signature) => report.line(format!("tracker co-signature: {signature}")),
        None => report.line(
            "tracker co-signature: none in the answer (POST /notes only acknowledges; the \
             tracker signs a redemption, POST /tracker/signature)",
        ),
    }
    report.line(
        "accepted: the tracker commits the new total in its next tracker box update; `status` \
         shows the note's commitment",
    );
    Ok(())
}
