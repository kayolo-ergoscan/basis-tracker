//! Command line. No option takes a secret: secrets are read from the files named by
//! `--secret-file` and `--api-key-file`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::{DEFAULT_NODE_URL, DEFAULT_TRACKER_URL, LIVE_TRACKER_NFT_ID};

#[derive(Debug, Parser)]
#[command(
    name = "basis_canary",
    version,
    about = "Closed canary of a Basis tracker: create a reserve, post a note, redeem it. Keys are \
             read from files, transactions are signed and validated locally, and --dry-run \
             submits nothing."
)]
pub struct Cli {
    /// Tracker API base URL.
    #[arg(long, global = true, default_value = DEFAULT_TRACKER_URL)]
    pub tracker_url: String,
    /// Ergo node base URL. Only public endpoints are used; no API key is sent.
    #[arg(long, global = true, default_value = DEFAULT_NODE_URL)]
    pub node_url: String,
    /// File holding the tracker API key (sent as the X-API-Key header to the tracker only).
    #[arg(long, global = true, value_name = "PATH")]
    pub api_key_file: Option<PathBuf>,
    /// Tracker NFT id that notes and reserves are bound to (64 hex characters).
    #[arg(long, global = true, default_value = LIVE_TRACKER_NFT_ID)]
    pub tracker_nft_id: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the public key, mainnet P2PK address and ErgoTree of a key file (no network access).
    KeyInfo {
        /// File holding the secret key: 64 hex characters (a 32-byte scalar).
        #[arg(long, value_name = "PATH")]
        secret_file: PathBuf,
    },
    /// Create a reserve owned by the key: the reserve box is the one the tracker's
    /// POST /reserves/create describes, paid from token-free boxes at the key's P2PK address;
    /// the reserve NFT is minted from the first input.
    ReserveCreate {
        /// File holding the owner's secret key.
        #[arg(long, value_name = "PATH")]
        secret_file: PathBuf,
        /// ERG locked in the reserve, in nanoERG.
        #[arg(long)]
        erg_nano: u64,
        /// Print the transaction, sign and validate it locally, and submit nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Sign a note for the cumulative debt of the key to the recipient and post it
    /// to POST /notes.
    Note {
        /// File holding the issuer's (debtor's) secret key.
        #[arg(long, value_name = "PATH")]
        secret_file: PathBuf,
        /// Recipient (creditor) public key: 66 hex characters.
        #[arg(long)]
        recipient_pubkey: String,
        /// Cumulative debt of the issuer to the recipient, in nanoERG.
        #[arg(long)]
        total: u64,
        /// Note timestamp in milliseconds since the epoch (default: now).
        #[arg(long)]
        timestamp_ms: Option<u64>,
        /// Print the signed note and post nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the tracker's view of a public key: key status, notes, reserves, tracker state.
    Status {
        /// Public key to look up: 66 hex characters.
        #[arg(long)]
        pubkey: String,
    },
    /// Redeem part of the issuer's debt to the key from the issuer's reserve, with the
    /// tracker's help (POST /tracker/signature, /redemption/build, /redemption/submit).
    Redeem {
        /// File holding the recipient's (creditor's) secret key.
        #[arg(long, value_name = "PATH")]
        secret_file: PathBuf,
        /// Issuer (debtor, reserve owner) public key: 66 hex characters.
        #[arg(long)]
        issuer_pubkey: String,
        /// Amount to redeem now, in nanoERG: the reserve gives this much, the payout is this
        /// minus the miner fee.
        #[arg(long)]
        amount: u64,
        /// Largest miner fee, in nanoERG, the redemption may take out of the payout.
        #[arg(long, value_name = "NANOERG", default_value_t = crate::tx::FEE)]
        max_fee_nano: u64,
        /// Ask the tracker to build the redemption, print it, prove and validate it locally,
        /// and submit nothing. The build still counts against the tracker's hourly caps, and
        /// the next build request must carry a later request_timestamp (the next run's clock).
        #[arg(long)]
        dry_run: bool,
    },
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn command_line_is_consistent() {
        Cli::command().debug_assert();
    }
}
