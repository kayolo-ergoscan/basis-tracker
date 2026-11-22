# Basis Tracker Configuration

## Overview

This document describes the configuration options for the Basis Tracker server and CLI.

## Configuration File

The main configuration file is `config/basis.toml`. The server will look for this file in the following locations:

1. Current working directory: `config/basis.toml`
2. Environment variables with `BASIS_` prefix
3. Default values

## Configuration Sections

### Server Configuration

```toml
[server]
host = "0.0.0.0"        # Host address to bind to
port = 3048             # Port to listen on
data_dir = "data"       # Base directory for all on-disk storage (databases, indices, scanner metadata)
database_url = "sqlite:data/basis.db"  # Legacy field, kept for compatibility (currently unused)
# tls_cert_path = "server.crt"  # PEM-encoded TLS certificate chain (enable for production auth)
# tls_key_path = "server.key"   # PEM-encoded TLS private key
```

`data_dir` controls where the server writes all persistent state. It defaults to a `data/` directory relative to the working directory from which the server is launched. You can override it with the `BASIS_SERVER_DATA_DIR` environment variable.

### Server Authentication & TLS

The tracker server supports optional TLS and three authentication modes under
`[server.auth]`:

| Mode | Description |
|---|---|
| `none` | Anonymous requests (default, local development only) |
| `api_key` | Shared secret via `Authorization: Bearer <key>` or `X-API-Key: <key>` |
| `signature` | Per-request secp256k1 Schnorr signatures |

```toml
[server.auth]
mode = "signature"
# api_key = "change-me"            # rejected at startup; use a strong random key
# admin_api_key = "..."            # separate operator credential for Admin routes;
                                   # when set, api_key grants only Write
# allow_insecure_http_non_loopback = false  # refuse auth over plain HTTP off-loopback
# [[server.auth.authorized_clients]]
# pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
# role = "admin"
allowed_origins = []
# With auth enabled and this list empty, NO CORS layer is installed: browsers cannot
# call the tracker cross-origin. There is no wildcard origin.
# auth.mode = "none" is refused on a non-loopback bind address unless:
# allow_anonymous_non_loopback = false
signature_timestamp_tolerance_ms = 30000
```

With `admin_api_key` set, the shared `api_key` grants only Write access; Admin routes
(`/redeem/complete`, `GET /notes`) require the admin key.
Without it, `api_key` keeps its full Admin meaning (a startup warning is printed).

When auth is enabled, configure TLS (`tls_cert_path` / `tls_key_path`) so
credentials and signatures are not sent in plaintext. Clients authenticate with
the same `server_auth_*` fields in `~/.basis/cli.toml`; the MCP server can also
read them from environment variables. See `specs/server/authentication_authorization.md`
for the full signature scheme and RBAC rules.

With `mode = "none"` every request is granted admin access, so the server
refuses to start when `server.host` is not a loopback address (`127.0.0.1`,
`::1`, or `localhost`). In `signature` mode the `X-Signature-Nonce` header is
required on every request.

`allowed_origins` is a CORS allow-list. When it is empty (the default) the
server attaches no CORS layer at all: no CORS headers are emitted and only
same-origin or non-browser clients can connect. Wildcard origins are never
used; list explicit origins to serve browser clients.

In `none` mode the server only accepts requests whose `Host` header is
loopback (`localhost`, `127.0.0.1`, `[::1]`, any port) and CORS is restricted
to loopback origins — this blocks DNS-rebinding attacks against the
unauthenticated local server.

### Ergo Blockchain Configuration

```toml
[ergo]
# Basis reserve contract P2S address
basis_reserve_contract_p2s = "2XoR96YVZfWybxeo7qdMkA1BRhxFivm8gTuLLuKREiW6833XWK4mA43DrJMDCvLqB9AwyduGgHBnGmmg2jrkUZAunRDu7t8718EkwiJTvp9rtEWEXMMJeMStjQB5BeuxsUc9ujW3aCMvxdS8VeYyZ14B8sSGu7CwJFmeaZDHiftsT3tUBqBfgau4wZTvhEtYEsFsqvpwsjcPAe4aGhFzJNSPhKqdSBrFKee3Dg4qFmGhb8Wu6DsdmhTrW6jnucnf17PDi2rQ9pgJvKrfs2KPbeZf9gV89vEga4kZk4u3bbSFTVk3s9EhuoUmfyhvC3ZaNv9DSPtzCcjvnL7x6smyLigsgb4QSEDnzX4HjJg5CfA6mh4Jn9hoL1412EVnY2xb8cYz76VEgU8J12n4DHrVsV9NzYAHxe6ogVNptUbAgykiru81pz3aZ6LfYySJt6ESVVGxm6i49ScGjawqsKCxjykCndh3MNQnRajZMgQMH2qFZhbd9KXCnLQkS6NAjtNfMVcx1KykdiSrLVTu3nphUZhT9MjhfxtZcojSZoQmGAy95zhAJpDMgUXBfuCSoUFUzPAuSMv2pBuEXiUR3wDQC7pDFYUDy68QCtTUTDtn9cYyNgc8EZWQSB76wsKhCNod1Q9RV85piLF5PJDMBXh4M8gjEzsq244xDdW6t2f4W4A2ZVDNw2gdSU3FHYxfB45c5cxkyR5qrXyoJT56c2STfFm3vK1ZfXzvckq48uAE1QRGpM9xALiXtdTx1iQaQjy2LkaURha6ewN5NDufyqntwBPk72NLadL8BDtLyReRtUWqbFZo94h4prjHVT25ABHbAqiJuTCHvmfTqi2V5gDwRW7oLk4gvBwswxJVvKmuKSG6sH5HAzQGoF6Kwcwdvq8Lbv5RbuAnm3N7hLnS1rBUWKXfaJCJjptMkeKxzMPhjfjnZTkMXwW3jSBxhpLeuWxrBrfjTFaVR93erQFVTvF9C1FsULgqUPjzPmcHn5Drp4cp4Y2pjv793k6KdykbugL6M6wt75hmKG5jsmrfsSL6AN13j3"

# Starting block height for scanning (legacy)
start_height = 0

# Tracker NFT ID (hex-encoded) - REQUIRED for reserve creation and redemption
# This NFT identifies the tracker server and must be set in reserve contract R6 register
# Example: tracker_nft_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
tracker_nft_id = ""

# Tracker public key - can be either:
# 1. Hex-encoded compressed public key (33 bytes = 66 hex chars): "02dada811a888cd0dc7a0a41739a3ad9b0f427741fe6ca19700cf1a51200c96bf7"
# 2. Ergo P2PK address: "9fRusAarL1KkrWQVsxSRVYnvWxaAT2A96cKtNn9tvPh5XUyCisr33"
tracker_public_key = ""

# Tracker secret key (32 bytes, hex) - REQUIRED. The server signs tracker box commits and
# redemption signatures in-process with it; it is never sent to a node. Startup is refused
# when it is missing, malformed, zero, or not the secret of tracker_public_key (sk*G != pk).
tracker_secret_key = ""

[ergo.scanner]
node_url = "http://127.0.0.1:9053"   # Scanner node: chain reads, box scanning, fee-box discovery; needs extraIndex = true
# api_key = "hello"                  # Optional: every endpoint the tracker calls is public
timeout_secs = 30                    # Request timeout in seconds

# Optional: separate node that receives the tracker's signed transactions
# (POST /transactions). When the section is unset, the scanner node is used.
# [ergo.wallet]
# node_url = "http://127.0.0.1:9053"
```

The tracker needs neither a node wallet nor a node API key. It calls only public node
endpoints: `GET /info`, `GET /blockchain/*`, `GET /utxo/*`, `GET /blocks/lastHeaders/10`,
`POST /blockchain/box/unspent/byAddress` and `POST /transactions`. Transaction fees are paid
from the token-free boxes at `P2PK(tracker_public_key)`, so fund that address with plain
ERG. Boxes holding any token, such as the tracker box with the tracker NFT, are never spent
for fees.

### Transaction Configuration

```toml
[transaction]
fee = 1000000              # Miner fee in nanoERG for the tracker's own transactions (0.001 ERG)
# change_address = "9..."  # Change of the fee boxes; default: P2PK(tracker_public_key)
# heartbeat_blocks = 720   # Recommit an unchanged digest at this tracker box age; 0 disables
```

The tracker commits its AVL root digest to the tracker box whenever the digest changes.
Reserve contracts open **emergency redemption** (without a tracker signature) once the
tracker box is more than 2160 blocks old, counted from its creation height
(`HEIGHT - tracker.creationInfo._1 > 3 * 720` in `contract/basis.es`). With an unchanged
digest there is nothing to commit, so without a heartbeat a quiet tracker would let its
box age into that window.

`heartbeat_blocks` closes this gap. When the tracker box is at least `heartbeat_blocks`
blocks old (current height minus the box creation height) and no update transaction is
pending, the tracker recommits the same digest through the normal commit path (same
inputs, outputs and fee rules). The new box has a fresh creation height, and note
confirmations do not change.

- Default `720` (about a day); each heartbeat costs one `fee`.
- `0` disables it. The server then warns at startup, and so it does for a value of
  `2160` or more, which cannot keep the box out of the window.
- Keep the tracker address funded: heartbeats are paid from the same token-free boxes
  as every other commit.
- A heartbeat spends the tracker box. A redemption transaction built before it, which
  carries the old tracker box as a data input, has to be rebuilt.

`change_address`, when set, receives the change of the fee boxes. Leave it unset to keep
the change at the tracker address, where the next commit can spend it.

### Redemption Configuration

```toml
[redemption]
# Enforce acceptance-policy compliance on redemption requests (default: true)
enforce_acceptance_policy = true
```

When `enforce_acceptance_policy` is enabled, the tracker checks every redemption
request (`POST /redeem` and `POST /redemption/build`) against the acceptance
policies of the reserve issuer's **other** debt holders before signing:

- The tracker simulates the post-redemption collateralization ratio
  (`(collateral - amount) / (total_debt - amount)`) and rejects the request with
  HTTP 400 `failed_policy_violation` if any other holder's policy would be newly
  violated.
- If **all** other holders' policies are already violated (distressed,
  undercollateralized reserve), a FIFO fallback applies: only the issuer's
  **oldest outstanding note** (minimum timestamp) may be redeemed; other requests
  are rejected with HTTP 400 `failed_not_oldest_note` (the message includes the
  oldest note's timestamp).

Set it to `false` to disable these checks (e.g. for testing). Emergency
redemptions via the contract path bypass the tracker and are never
policy-checked. See `specs/redemption_acceptance_policy.md` for the full design.

### Confirmation Configuration

```toml
[confirmation]
# Minimum on-chain depth (including the inclusion block) before a tracker box
# update is treated as confirmed and pending notes become redeemable
min_depth = 2
```

Presence of the tracker update transaction in a block alone is not treated as
confirmation; the tracker box updater waits until the transaction has
`min_depth` blocks before promoting pending notes to `Confirmed` (making them
redeemable). Box/height fetch failures are retried on the next update cycle.
Note this is only a depth gate — reorg handling beyond it is out of scope
(see `specs/pr12_triage.md`).

### Node HTTP bounds

All outbound Ergo node requests share one bounded client
(`crates/basis_store/src/http.rs`): 3 s connect timeout, 15 s total request
timeout, and a 2 MiB response body cap. These values are currently compile-time
constants, not config keys.

## Tracker NFT Configuration

### What is the Tracker NFT?

The Tracker NFT is a critical component of the Basis system that:

1. **Identifies your tracker server** on the blockchain
2. **Links reserves to your tracker** via the R6 register
3. **Prevents unauthorized redemptions** by verifying tracker identity
4. **Enables multi-tracker support** (future feature)

### How to Set Up Tracker NFT

1. **Mint the NFT and create the tracker box** with `basis_bootstrap` (see
   [Bootstrapping the tracker](#bootstrapping-the-tracker) below). The NFT must be a
   single token (emission 1), unique to your tracker instance.

2. **Configure the NFT ID** in `config/basis.toml`
   ```toml
   tracker_nft_id = "your_nft_token_id_here"
   ```

3. **Use the NFT in reserve creation**
   - When creating reserves, the NFT ID must be set in the R6 register
   - This links the reserve to your specific tracker

### Reserve Contract Registers

When creating a reserve contract box, you must set these registers:

- **R4**: Issuer's public key (GroupElement)
- **R5**: AVL tree tracking cumulative redeemed amounts (initially empty)
  - Stores: `hash(ownerKey || receiverKey) -> cumulativeRedeemedAmount`
  - Updated on each redemption to prevent double-spending
- **R6**: Tracker NFT ID (from your configuration)

## Environment Variables

All configuration options can also be set via environment variables with the `BASIS_` prefix:

```bash
export BASIS_SERVER_HOST="0.0.0.0"
export BASIS_SERVER_PORT=3048
export BASIS_ERGO_BASIS_RESERVE_CONTRACT_P2S="your_reserve_contract_p2s"
export BASIS_ERGO_TRACKER_NFT_ID="your_tracker_nft_id"
export BASIS_ERGO_NODE_URL="http://your-node:9053"
```

## Tracker Public Key Configuration

### What is the Tracker Public Key?

The Tracker Public Key is used by the tracker server to:

1. **Sign and submit transactions** that update the tracker box state commitments on-chain
2. **Identify your tracker server instance** in tracker box R4 register
3. **Enable automated tracker box updates** every 10 minutes

### How to Configure Tracker Public Key

1. **Prepare a compressed secp256k1 public key** (33 bytes)
   - Can be provided as hex string: `02dada811a888cd0dc7a0a41739a3ad9b0f427741fe6ca19700cf1a51200c96bf7`
   - Can be provided as Ergo P2PK address: `9fRusAarL1KkrWQVsxSRVYnvWxaAT2A96cKtNn9tvPh5XUyCisr33`
   - With `tracker_secret_key` set, `basis_bootstrap address` prints the public key, the
     P2PK address and the ErgoTree that belong to it, without network access.

2. **Configure the public key and its secret key** in `config/basis.toml`
   ```toml
   tracker_public_key = "your_public_key_or_p2pk_address_here"
   tracker_secret_key = "64_hex_characters"
   ```

3. **The tracker signs with the secret key in-process** (tracker box updates and redemption
   signatures). The server refuses to start unless `tracker_secret_key·G` equals
   `tracker_public_key`, and it commits only to a tracker box locked by
   `P2PK(tracker_public_key)`.

### Bootstrapping the tracker

`basis_bootstrap` creates the tracker's on-chain state once, before the first start of
`basis_server`. It reads the same `config/basis.toml` (run it from the same working
directory; `BASIS_*` environment overrides apply), signs locally with
`ergo.tracker_secret_key`, reads only public endpoints of `ergo.scanner.node_url` and submits
through `POST /transactions` on the broadcast node (`[ergo.wallet]`, else the scanner). No
node wallet or API key is needed.

```bash
basis_bootstrap address                       # public key, P2PK address, ErgoTree
basis_bootstrap mint-nft --dry-run            # print the transaction, send nothing
basis_bootstrap mint-nft [--name N] [--description D]
basis_bootstrap init-box --nft <NFT id> [--value-nano 1000000] [--dry-run]
```

1. Fund the address printed by `address` with plain ERG (0.01 ERG covers both steps).
2. `mint-nft` mints the NFT into a 0.001 ERG box at the tracker address. The registers follow
   EIP-4: R4 name (default `Basis Tracker`), R5 description, R6 decimals `"0"`, each a
   `Coll[Byte]` of UTF-8 text. The NFT id is the id of the first input box; it is printed.
3. After the mint confirms, `init-box --nft <id>` turns that box into the tracker box:
   token 0 = the NFT, R4 = `07‖tracker public key`, R5 =
   `644ec61f485b98eb87153f7c57db4f5ecd75556fddbc403b41acf8441fde8e160900032000` (the empty
   AVL tree), R6 = `0e20‖NFT id`. The box value (default 0.001 ERG) is kept by every commit.
4. Set `tracker_nft_id` (and `tracker_public_key`, if it is not set yet) and start
   `basis_server`.

Both commands pay a 0.001 ERG fee from token-free boxes at the tracker address and return
the change there; a leftover too small for a box goes to the fee. They refuse to spend a box
holding an unrelated token, and `init-box` refuses a token whose emission is not 1, a box
holding anything besides the NFT, and a box that is already a tracker box (re-initializing
would reset the committed digest). Before signing, every transaction is checked: ERG in
equals ERG out, no token is burned, only the new NFT is minted, and the NFT appears once,
first in output 0. `--dry-run` prints the unsigned transaction JSON and the exact register
hex without signing or submitting.

### Format Options

The tracker public key supports two formats:
- **Hex format**: 66 hexadecimal characters representing 33 bytes (e.g., `02abcd...`)
- **P2PK address**: Base58 encoded Ergo address starting with '9' (mainnet) or '3' (testnet)

## Default Configuration

If no configuration file is found, the server uses these defaults:

```toml
[server]
host = "0.0.0.0"
port = 3048
data_dir = "data"
database_url = "sqlite:data/basis.db"
# tls_cert_path = "server.crt"
# tls_key_path = "server.key"

[server.auth]
mode = "none"
api_key = ""
allowed_origins = []
# With auth enabled and this list empty, NO CORS layer is installed: browsers cannot
# call the tracker cross-origin. There is no wildcard origin.
# auth.mode = "none" is refused on a non-loopback bind address unless:
# allow_anonymous_non_loopback = false
signature_timestamp_tolerance_ms = 30000

[ergo]
basis_reserve_contract_p2s = ""
start_height = 0
tracker_nft_id = ""

[ergo.scanner]
# Any public node works, but note the default is LOCALHOST. A plaintext remote node sees every
# scanning request. No API key is needed: the tracker calls public endpoints only and signs
# locally, so no wallet credential ever crosses the network.
node_url = "http://127.0.0.1:9053"
timeout_secs = 30

# [ergo.wallet]
# node_url = "http://127.0.0.1:9053"

[redemption]
enforce_acceptance_policy = true

[confirmation]
min_depth = 2
```

> **Note:** with these defaults (`mode = "none"` and `host = "0.0.0.0"`) the
> server refuses to start, because anonymous mode grants admin access to every
> request. Either bind to a loopback address (`host = "127.0.0.1"`) or
> configure an authentication mode under `[server.auth]`.

## Verification

To verify your configuration is working:

1. **Start the server**: `cargo run -p basis_server`
2. **Check server logs** for configuration loading messages
3. **Test with CLI**: `basis-cli status`
4. **Verify tracker NFT**: Check that reserves can be created and redeemed

## Troubleshooting

### Common Issues

1. **"Tracker NFT not configured"**
   - Ensure `tracker_nft_id` is set in your configuration
   - The NFT must exist on the blockchain

2. **"Invalid tracker NFT"**
   - Verify the NFT ID is correctly hex-encoded
   - Check that the NFT exists and is owned by you

3. **"Reserve creation failed"**
   - Ensure R6 register contains the correct tracker NFT ID
   - Verify the reserve contract template is correct

### Logging

Enable debug logging to see configuration details:

```bash
RUST_LOG=debug cargo run -p basis_server
```
