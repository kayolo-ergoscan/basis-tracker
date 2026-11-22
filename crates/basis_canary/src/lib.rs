//! `basis_canary`: a closed canary of a Basis tracker, run with test keys whose secrets are read
//! from files.
//!
//! It walks the whole life of a debt on chain, one subcommand per step:
//! 1. `reserve-create`: the owner A locks ERG in a reserve bound to the tracker NFT. The reserve
//!    box is exactly what the tracker's `POST /reserves/create` describes, minted from A's own
//!    boxes and signed with A's key.
//! 2. `note`: A signs the cumulative debt to B (the 80-byte Basis message) and posts it to
//!    `POST /notes`. The tracker commits it in its next tracker box update.
//! 3. `redeem`: B redeems from A's reserve with the tracker's help: `POST /tracker/signature`,
//!    `POST /redemption/build`, a local proof of the reserve input with B's key, full validation,
//!    then `POST /redemption/submit` (or the node, if the tracker refuses).
//!
//! `status` reads the tracker's view of a key and `key-info` prints a key's public key and address.
//!
//! Secrets are only read from files (`--secret-file`, `--api-key-file`). No secret is taken from
//! the command line, printed, logged or put in an error message, and the API key is only ever
//! sent to the tracker, as the `X-API-Key` header. The node gets public requests only.
//!
//! Every transaction is checked before it is signed: ERG in equals ERG out, tokens are preserved
//! except the one expected mint, and every input is locked by an expected key. It is then signed
//! in-process and validated in full against the state context of the node's
//! `GET /blocks/lastHeaders/10` (newest first) before anything is submitted. With `--dry-run` the
//! unsigned transaction, a summary and the exact register hex are printed, the transaction is
//! signed and validated locally, and nothing is submitted.

use std::path::Path;

use basis_server::local_wallet::NodeEndpoint;

pub mod cli;
pub mod keys;
pub mod note;
pub mod redeem;
pub mod reserve;
pub mod status;
pub mod tracker;
pub mod tx;

pub use cli::{Cli, Command};
pub use keys::{ApiKey, FileKey};
pub use tracker::TrackerClient;

/// Default tracker URL: the `basis-tracker` container on the `basis-net` Docker network.
pub const DEFAULT_TRACKER_URL: &str = "http://basis-tracker:3048";
/// Default Ergo node. Only public endpoints are used and no API key is sent.
pub const DEFAULT_NODE_URL: &str = "https://node.ergoscan.me";
/// NFT of the live tracker the canary runs against (minted 22.11.2026).
pub const LIVE_TRACKER_NFT_ID: &str =
    "f5178dc4063042bdf77cd0f4a55d0893d6dbcf0b3d14eb4de25282b2c4e3f29f";

/// What a subcommand prints. With `echo` (the binary) every line also goes to stdout as soon as
/// it is written, so progress shows while the node and the tracker answer; the text is kept for
/// callers that inspect it (tests).
#[derive(Debug, Default)]
pub struct Report {
    text: String,
    echo: bool,
}

impl Report {
    /// A report that prints its lines to stdout when `echo` is set.
    pub fn new(echo: bool) -> Self {
        Self {
            text: String::new(),
            echo,
        }
    }

    /// Append one line (or several, separated by `\n`).
    pub fn line(&mut self, line: impl AsRef<str>) {
        let line = line.as_ref();
        if self.echo {
            println!("{line}");
        }
        self.text.push_str(line);
        self.text.push('\n');
    }

    /// Everything written so far.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// The node and the tracker a run talks to, and the tracker NFT notes and reserves are bound to.
#[derive(Debug)]
pub struct Context {
    pub node: NodeEndpoint,
    pub tracker: TrackerClient,
    pub tracker_nft: [u8; 32],
}

impl Context {
    /// Endpoints from the global options. URLs with credentials in them are refused, so no URL
    /// printed in a report or an error can carry a secret.
    pub fn new(
        tracker_url: &str,
        node_url: &str,
        api_key_file: Option<&Path>,
        tracker_nft_id: &str,
    ) -> Result<Self, String> {
        tracker::check_url("--node-url", node_url)?;
        let api_key = api_key_file.map(ApiKey::read).transpose()?;
        Ok(Self {
            node: NodeEndpoint::new(node_url, None),
            tracker: TrackerClient::new(tracker_url, api_key)?,
            tracker_nft: tx::parse_id("--tracker-nft-id", tracker_nft_id)?,
        })
    }
}

/// Run one subcommand, writing what it does to `report`.
pub async fn run(cli: Cli, report: &mut Report) -> Result<(), String> {
    let context = || {
        Context::new(
            &cli.tracker_url,
            &cli.node_url,
            cli.api_key_file.as_deref(),
            &cli.tracker_nft_id,
        )
    };
    match &cli.command {
        Command::KeyInfo { secret_file } => status::key_info(&FileKey::read(secret_file)?, report),
        Command::ReserveCreate {
            secret_file,
            erg_nano,
            dry_run,
        } => {
            let owner = FileKey::read(secret_file)?;
            reserve::reserve_create(&context()?, &owner, *erg_nano, *dry_run, report).await
        }
        Command::Note {
            secret_file,
            recipient_pubkey,
            total,
            timestamp_ms,
            dry_run,
        } => {
            let issuer = FileKey::read(secret_file)?;
            let recipient = tx::parse_pubkey("--recipient-pubkey", recipient_pubkey)?;
            let note = note::NoteRequest {
                recipient,
                total: *total,
                timestamp_ms: *timestamp_ms,
                dry_run: *dry_run,
            };
            note::note(&context()?, &issuer, &note, report).await
        }
        Command::Status { pubkey } => {
            let pubkey = tx::parse_pubkey("--pubkey", pubkey)?;
            status::status(&context()?, &pubkey, report).await
        }
        Command::Redeem {
            secret_file,
            issuer_pubkey,
            amount,
            dry_run,
        } => {
            let recipient = FileKey::read(secret_file)?;
            let issuer = tx::parse_pubkey("--issuer-pubkey", issuer_pubkey)?;
            redeem::redeem(&context()?, &recipient, &issuer, *amount, *dry_run, report).await
        }
    }
}
