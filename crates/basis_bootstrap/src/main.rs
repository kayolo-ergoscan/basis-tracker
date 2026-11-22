//! `basis_bootstrap`: one-time on-chain setup of a Basis tracker.
//!
//! Reads the same configuration as `basis_server` (`config/basis.toml` in the working
//! directory, `BASIS_*` environment overrides) and signs locally with
//! `ergo.tracker_secret_key`. See `docs/CONFIGURATION.md`, "Bootstrapping the tracker".

use basis_bootstrap::{
    Bootstrap, DEFAULT_NFT_DESCRIPTION, DEFAULT_NFT_NAME, DEFAULT_TRACKER_BOX_VALUE,
};
use basis_server::config::AppConfig;
use basis_server::local_wallet::{self, NodeEndpoint, TrackerKey};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "basis_bootstrap",
    version,
    about = "One-time on-chain setup of a Basis tracker: mint the tracker NFT and create the \
             tracker box. Signs locally with ergo.tracker_secret_key from config/basis.toml and \
             submits through POST /transactions; no node wallet or API key is needed."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the tracker public key, P2PK address and ErgoTree (no network access).
    Address,
    /// Mint the tracker NFT (EIP-4: R4 name, R5 description, R6 decimals "0") into a box at
    /// the tracker address. Pays from token-free boxes at that address.
    MintNft {
        /// EIP-4 name (R4).
        #[arg(long, default_value = DEFAULT_NFT_NAME)]
        name: String,
        /// EIP-4 description (R5).
        #[arg(long, default_value = DEFAULT_NFT_DESCRIPTION)]
        description: String,
        /// Build and print the transaction and register hex without signing or submitting.
        #[arg(long)]
        dry_run: bool,
    },
    /// Turn the box holding the tracker NFT into the tracker box: token 0 = NFT,
    /// R4 = tracker public key, R5 = empty AVL tree, R6 = NFT id.
    InitBox {
        /// Tracker NFT id (64 hex characters), as printed by mint-nft.
        #[arg(long)]
        nft: String,
        /// Value of the tracker box in nanoERG. Commits keep it.
        #[arg(long, default_value_t = DEFAULT_TRACKER_BOX_VALUE)]
        value_nano: u64,
        /// Build and print the transaction and register hex without signing or submitting.
        #[arg(long)]
        dry_run: bool,
    },
}

/// The tracker key from `ergo.tracker_secret_key`, checked against `ergo.tracker_public_key`
/// when that is set. Returns the key and a line about the configured public key.
fn tracker_key(config: &AppConfig) -> Result<(TrackerKey, String), String> {
    let secret = config.tracker_secret_key_bytes().ok_or(
        "ergo.tracker_secret_key is not set or is not 32 bytes of hex (64 hex characters)",
    )?;
    let key = TrackerKey::from_secret_bytes(&secret)?;
    let derived = hex::encode(key.public_key());
    let configured = config
        .tracker_public_key_bytes()
        .map_err(|e| format!("ergo.tracker_public_key is invalid: {e}"))?;
    let note = match configured {
        Some(pk) if pk == key.public_key() => {
            "ergo.tracker_public_key matches ergo.tracker_secret_key".to_string()
        }
        Some(pk) => {
            return Err(format!(
                "ergo.tracker_public_key {} does not belong to ergo.tracker_secret_key (its \
                 public key is {derived}); fix the configuration first",
                hex::encode(pk)
            ))
        }
        None => format!(
            "ergo.tracker_public_key is not set: set it to \"{derived}\" before starting \
             basis_server"
        ),
    };
    Ok((key, note))
}

fn nft_note(config: &AppConfig, nft: Option<&str>) -> Option<String> {
    let configured = config
        .ergo
        .tracker_nft_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())?;
    match nft {
        Some(nft) if configured.eq_ignore_ascii_case(nft.trim()) => None,
        Some(_) => Some(format!(
            "note: ergo.tracker_nft_id is set to {configured}, not to this NFT; basis_server \
             follows the configured one"
        )),
        None => Some(format!(
            "note: ergo.tracker_nft_id is already set to {configured}; this mints another NFT"
        )),
    }
}

async fn run(cli: Cli) -> Result<String, String> {
    let config = AppConfig::load().map_err(|e| format!("cannot load config/basis.toml: {e}"))?;
    let (key, key_note) = tracker_key(&config)?;
    let mut out = format!("{key_note}\n");

    let bootstrap = || {
        let (broadcast_url, broadcast_key) = config.ergo_wallet_node();
        Bootstrap {
            key: key.clone(),
            scanner: NodeEndpoint::new(
                &config.ergo.scanner.node_url,
                config.ergo.scanner.api_key.clone(),
            ),
            broadcast: NodeEndpoint::new(&broadcast_url, broadcast_key),
        }
    };

    match cli.command {
        Command::Address => {
            let pk = key.public_key();
            out.push_str(&format!(
                "tracker public key: {}\ntracker address:    {}\ntracker ErgoTree:   {}\n",
                hex::encode(pk),
                local_wallet::p2pk_address(&pk)?,
                key.p2pk_tree_hex()
            ));
        }
        Command::MintNft {
            name,
            description,
            dry_run,
        } => {
            if let Some(note) = nft_note(&config, None) {
                out.push_str(&format!("{note}\n"));
            }
            out.push_str(&bootstrap().mint_nft(&name, &description, dry_run).await?);
        }
        Command::InitBox {
            nft,
            value_nano,
            dry_run,
        } => {
            if let Some(note) = nft_note(&config, Some(&nft)) {
                out.push_str(&format!("{note}\n"));
            }
            out.push_str(&bootstrap().init_box(&nft, value_nano, dry_run).await?);
        }
    }
    Ok(out)
}

#[tokio::main]
async fn main() {
    match run(Cli::parse()).await {
        Ok(text) => print!("{text}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_the_documented_subcommands() {
        Cli::command().debug_assert();

        let nft = "ab".repeat(32);
        let cli = Cli::try_parse_from([
            "basis_bootstrap",
            "init-box",
            "--nft",
            &nft,
            "--value-nano",
            "2000000",
            "--dry-run",
        ])
        .unwrap();
        match cli.command {
            Command::InitBox {
                nft: parsed,
                value_nano,
                dry_run,
            } => assert_eq!(
                (parsed, value_nano, dry_run),
                (nft.clone(), 2_000_000, true)
            ),
            _ => panic!("expected init-box"),
        }
        let cli = Cli::try_parse_from(["basis_bootstrap", "init-box", "--nft", &nft]).unwrap();
        assert!(matches!(
            cli.command,
            Command::InitBox {
                value_nano: DEFAULT_TRACKER_BOX_VALUE,
                dry_run: false,
                ..
            }
        ));
        assert!(Cli::try_parse_from(["basis_bootstrap", "init-box"]).is_err());

        let cli = Cli::try_parse_from(["basis_bootstrap", "mint-nft", "--name", "T"]).unwrap();
        match cli.command {
            Command::MintNft {
                name,
                description,
                dry_run,
            } => {
                assert_eq!(name, "T");
                assert_eq!(description, DEFAULT_NFT_DESCRIPTION);
                assert!(!dry_run);
            }
            _ => panic!("expected mint-nft"),
        }
        assert!(matches!(
            Cli::try_parse_from(["basis_bootstrap", "address"])
                .unwrap()
                .command,
            Command::Address
        ));
    }
}
