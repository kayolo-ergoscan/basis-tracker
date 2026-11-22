//! `key-info` (no network) and `status` (the tracker's view of a key).

use crate::keys::FileKey;
use crate::{Context, Report};

/// `key-info`: public key, mainnet P2PK address and ErgoTree of a key file.
pub fn key_info(key: &FileKey, report: &mut Report) -> Result<(), String> {
    report.line(format!("public key: {}", key.public_key_hex()));
    report.line(format!("address:    {}", key.address()?));
    report.line(format!("ErgoTree:   {}", key.p2pk_tree_hex()));
    Ok(())
}

/// The tracker reads `status` prints for `pubkey`, in order.
pub fn status_paths(pubkey: &[u8; 33]) -> Vec<String> {
    let pk = hex::encode(pubkey);
    vec![
        format!("/key-status/{pk}"),
        format!("/notes/issuer/{pk}"),
        format!("/notes/recipient/{pk}"),
        "/tracker/state".to_string(),
        format!("/reserves/issuer/{pk}"),
    ]
}

/// `status`: every read of [`status_paths`] with its HTTP status and body. A failing read is
/// printed and the others still run; the command fails when any of them failed.
pub async fn status(
    context: &Context,
    pubkey: &[u8; 33],
    report: &mut Report,
) -> Result<(), String> {
    report.line(format!(
        "tracker {} for public key {}",
        context.tracker.url(),
        hex::encode(pubkey)
    ));
    let mut failed = Vec::new();
    for path in status_paths(pubkey) {
        match context.tracker.get(&path).await {
            Ok(response) => {
                report.line(format!("GET {path}: HTTP {}", response.status));
                report.line(response.pretty());
                // 404 is an answer here: no note or no reserve yet.
                if !(200..300).contains(&response.status) && response.status != 404 {
                    failed.push(path);
                }
            }
            Err(e) => {
                report.line(format!("GET {path}: {e}"));
                failed.push(path);
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} tracker read(s) failed: {}",
            failed.len(),
            failed.join(", ")
        ))
    }
}
