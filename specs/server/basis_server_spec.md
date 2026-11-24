# Basis Server Crate Specification

## Overview

The `basis_server` crate is a Rust web server built with the Axum framework that provides an HTTP API for the Basis Tracker system. It serves as the core component for managing IOU notes, tracking reserve events on the Ergo blockchain, providing proof mechanisms for the Basis protocol, and facilitating redemption with tracker signatures.

## Architecture

### Main Components

1. **API Module**: Contains all HTTP route handlers for the web server
2. **Reserve API Module**: Handles reserve-specific endpoints
3. **Models Module**: Defines data structures for API requests/responses
4. **Store Module**: Implements event storage functionality
5. **Auth Middleware**: Authentication middleware supporting anonymous, API-key, and secp256k1-signature modes
6. **Authorization Middleware**: Role-based access control (RBAC) enforcing `Read`, `Write`, and `Admin` privileges per route
7. **Config Module**: Handles application configuration, including TLS and authentication settings
8. **Tracker Thread**: Background task that processes commands via message passing
9. **AVL Tree Manager**: Manages the tracker's AVL tree state and proof generation

### Communication Pattern

The server uses an actor-like pattern with a dedicated tracker thread that processes commands via a channel:

- Web handlers send commands through an MPSC channel
- A blocking thread processes tracker commands
- Results are returned via oneshot channels

### Storage and Shutdown

Every fjall directory under `data_dir` has exactly one opener per process (fjall takes no
directory lock): `notes` the tracker thread, `scanner_metadata` and `reserves` the reserve
scanner, `tracker_scanner_metadata` the tracker scanner at startup, `tracker_boxes` main
(shared by the tracker scanner and the API), `acceptance_policies` main (the API). Each
storage keeps its keyspace open, and every journal is fsynced each second
(`fsync_ms = 1000`): a process crash loses no acknowledged write, a power loss at most about
one second of writes.

On SIGTERM or SIGINT the server stops accepting connections, and the reserve scanner and the
tracker box updater are told to stop after their current cycle. The whole shutdown takes at
most 20 s from the signal. Open connections and both loops get the first 15 s. Then the
tracker thread gets `TrackerCommand::Shutdown`: it handles the commands sent before it, closes
the note store and is joined, within the last 5 s, so the note store is closed even when a
client holds a connection open. Whatever still runs at the deadline is logged and ends with the
process, which exits with status 0. With nothing in flight the shutdown takes about 2 s: each
fjall keyspace waits up to one fsync interval to close.

## Dependencies

- `axum`: Web framework for routing and HTTP handling
- `tokio`: Async runtime for concurrency
- `tracing`: Logging and instrumentation
- `serde/serde_json`: Serialization/deserialization
- `tower-http`: HTTP middleware (CORS, tracing)
- `basis_store`: Core business logic and data structures
- `ergo-lib`: Ergo blockchain interaction

## API Endpoints

### Core Endpoints

- `GET /` - Root endpoint returning "Hello, Basis Tracker API!"
- `POST /notes` - Create a new IOU note. With `server.notes_require_reserve` (default true) the
  issuer needs one active reserve under this tracker in the note's denomination (409 otherwise);
  `server.notes_max_*` caps answer 429 (see `docs/CONFIGURATION.md`)
- `GET /notes` - Get all IOU notes in the system (Admin role)
- `GET /notes/issuer/{pubkey}` - Get all notes issued by a public key
- `GET /notes/recipient/{pubkey}` - Get all notes received by a public key
- `GET /notes/issuer/{issuer_pubkey}/recipient/{recipient_pubkey}` - Get specific note between two parties
- `POST /notes/state` - Get the confirmation state of a single note (`confirmed` / `pending` / `local_only`) and whether it is currently redeemable
- `POST /redeem` - Initiate redemption process
- `POST /redeem/complete` - Complete redemption process (see the caveat below — this endpoint
  advances local state from the request body and does **not** verify against the chain)
- `POST /tracker/signature` - Request tracker signature for redemption (real Schnorr signature generation)
- `POST /redemption/prepare` - Prepare redemption with all necessary data (real AVL proofs + tracker signature)
- `POST /redemption/build` - Tracker-assisted redemption step 1: build the unsigned redemption
  transaction for a recipient-signed request (`request_timestamp`, `receiver_signature` over
  `"basis-build-v1" ‖ trackerNft ‖ issuer ‖ recipient ‖ denominationId ‖ amount ‖ timestamp`);
  ERG reserves pay the miner fee out of the payout (only the reserve is spent, the tracker signs
  nothing, `fee_paid_by: "recipient"`), token reserves use tracker-signed fee inputs
  (`fee_paid_by: "tracker"`)
- `POST /redemption/submit` - Tracker-assisted redemption step 2: journal and broadcast a signed
  redemption transaction. The note and the reserve tree follow once it is in a block,
  `[confirmation] min_depth` deep (the redemption confirmer, every 60 s); meanwhile builds of
  that reserve and exchanges of its issuer answer 409 (round 5 and 5b, see
  `specs/server/redemption_state_spec.md`)
- `GET /redemption/journal` - Admin: the journaled redemptions (round 5b)
- `POST /redemption/journal/drop` - Admin: remove a journaled redemption without applying it
  (round 5b)
- `POST /redemption/journal/apply` - Admin: apply a journaled redemption without waiting for the
  chain (round 5b)
- `POST /redemption/tree/repair` - Admin: set one edge of a reserve tree to the chain's value, only
  when the tree then hashes to R5 of the reserve box (round 6)
- `GET /redemption/tree/repairs` - Admin: the recorded reserve tree repairs (round 6)
- `GET /proof/redemption` - Get redemption-specific proof with tracker state digest

### Tracker State and Proof Endpoints

- `GET /tracker/proof` - Get an AVL lookup proof from the tracker tree for a note
- `GET /tracker/state` - Get the tracker's current state (including the AVL root digest)
- `GET /tracker/pending-tx` - Get the currently pending tracker-box update transaction, if any
- `GET /tracker/latest-box-id` - Get the id of the most recent tracker box
- `GET /reserve/proof` - Get an AVL proof from a reserve's tree, proving `already_redeemed`

### Reserve Endpoints

- `GET /reserves` - Get all reserve information; each reserve's `total_debt` is read through the
  issuer index for the reserves' owners, never by scanning every note, and
  `pending_redemption_amount` notes the part of it that journaled redemptions are about to
  redeem (round 5b)
- `GET /reserves/issuer/{pubkey}` - Get reserves for a specific issuer
- `GET /reserves/{box_id}` - Get a single reserve by its box id

  In all three (round 5), `total_debt` is the outstanding debt of the reserve's owner in the
  reserve's denomination on the notes this tracker holds: the sum of `amount_collected -
  amount_redeemed` over the owner's notes in that denomination (ERG for an ERG reserve, the
  reserve token otherwise), saturating at 2^64-1. It is per (owner, denomination), not per box,
  so two reserves of one owner in one denomination (a state the redemption routes refuse) show
  the same debt. `collateralization_ratio` is `collateral_amount / total_debt`, both in the
  reserve's unit (nanoERG or raw token units), and `null` when `total_debt` is 0.
- `GET /reserves/quarantined` - List reserve boxes rejected by admission control (see `specs/ergo/reserve_admission.md`)
- `POST /reserves/quarantined/release` - Admin (round 6c): take a box out of quarantine after an operator check (`box_id`, `note`); the record is journaled and the scanner judges the box again at its next cycle
- `GET /reserves/quarantined/releases` - Admin (round 6c): the quarantine releases with their notes, oldest first
- `GET /key-status/{pubkey}` - Get status information for a public key
- `POST /reserves/create` - Create a reserve creation payload for Ergo node's `/wallet/payment/send` API (the tracker only tracks the reserve if the creating transaction spends a P2PK input of the R4 owner key — `basis-cli reserve create --submit` guarantees this)

### Acceptance Policy Endpoints

- `POST /acceptance/check` - Check whether a hypothetical note would be accepted by the issuer's policy
- `POST /acceptance/policy` - Upload or replace an acceptance policy. Validated before it is
  stored (round 4, C1): JSON at most 8 KiB, explicit `root`, unique names, a reference tree
  in which every predicate is referenced once and reachable from the root, depth at most 8, at
  most 32 predicates, 16 references per composite and 256 holders. Stored policies are
  re-checked at startup; an invalid or unreadable one is moved, byte for byte and with the
  reason, from the `acceptance_policies` partition to `acceptance_policies_quarantine` (key:
  recipient key ‖ Unix seconds of the move, u64 BE; value: reason length u32 BE ‖ reason ‖ the
  original record) with a warning, instead of being deleted (round 5). The recipient then falls
  back to the global policy until they upload a valid one
- `GET /acceptance/policy/{pubkey}` - Get the stored acceptance policy for a public key

### Configuration Endpoints

- `GET /config/reserve-contract-p2s` - Get the configured reserve contract P2S address
- `GET /config/reserve-token` - Get the configured reserve token id (for token-collateralized reserves)

### Event Tracking

- `GET /events` - Get the 50 most recent tracker events (Admin role)
- `GET /events/paginated?page=0&page_size=20` - Get paginated events, oldest first (Admin role;
  `page_size` 1..=100, a page past the end is empty)

Both event endpoints are Admin-only: the event log names the issuer, recipient and amount of
every note update, the same note graph as `GET /notes`.

> **Endpoint inventory note (2026-09-28).** The list above was verified against the routes
> registered in `crates/basis_server/src/main.rs`. All 30 registered routes are now documented.
> `GET /events/paginated` used to panic on a page past the end and overflow on large
> `page`/`page_size` (`specs/PRODUCTION_READINESS_AUDIT.md`, Issue #3); both are fixed. The event
> store is no longer seeded with demo events at startup (H9): it holds only events the tracker
> observed.

## Data Models

### Tracker Event Types

- `NoteUpdated`: When an IOU note is created/modified
- `ReserveCreated`: When a new reserve box is created
- `ReserveToppedUp`: When collateral is added to a reserve
- `ReserveRedeemed`: When collateral is redeemed from a reserve
- `ReserveSpent`: When a reserve box is spent
- `Commitment`: Commitment to tracker state
- `CollateralAlert`: When collateralization ratio falls below threshold
- `DebtTransfer`: When debt is transferred between creditors (novation)

### Tracker Box Registers

The tracker box uses Ergo registers R4 and R5 to store commitment information:

- **R4**: Contains the tracker public key (33-byte compressed secp256k1 point, serialized as `GroupElement`)
- **R5**: Contains the AVL tree root digest serialized as `SAvlTree` (37 bytes total: `0x64` type byte + 33-byte digest + 1-byte flags + VLQ key length + VLQ value length)

The tracker box must also preserve the tracker NFT token (identified by `tracker_nft_id`) in its assets.

The reserve box uses Ergo registers R4, R5, and R6 to store commitment and identification information:

- **R4**: Contains the issuer's public key (GroupElement / 33-byte compressed secp256k1 point) that identifies the reserve owner
- **R5**: Contains the AVL tree root digest (33-byte commitment)
  - Stores: `hash(ownerKey || receiverKey) -> cumulativeRedeemedAmount`
  - Updated when notes are redeemed
- **R6**: Contains the NFT ID of the tracker server (bytes) - identifies which tracker server this reserve is linked to

### IOU Note Structure

The server handles IOU (I Owe You) notes that represent debt obligations:

For most endpoints:
- `recipient_pubkey`: Public key of the recipient
- `amount_collected`: Total amount collected (cumulative debt)
- `amount_redeemed`: Amount already redeemed
- `timestamp`: Creation timestamp
- `signature`: Cryptographic signature (Schnorr signature on `hash(issuer||recipient) || totalDebt`)

For the `GET /notes` endpoint (all notes), additional fields are included:
- `issuer_pubkey`: Public key of the issuer
- `age_seconds`: Age of the note in seconds (calculated from timestamp)

### Tracker Signature Request Structure

The `/tracker/signature` endpoint accepts requests with the following structure:
- `issuer_pubkey`: Public key of the note issuer (hex-encoded, 33 bytes)
- `recipient_pubkey`: Public key of the note recipient (hex-encoded, 33 bytes)
- `total_debt`: Total cumulative debt amount in nanoERG — must equal the stored note's total debt (rejected with 409 otherwise)
- `timestamp`: Payment timestamp of the note — must equal the stored note's timestamp (rejected with 409 otherwise)
- `emergency`: must be `false` or omitted; `true` is refused with HTTP 400 (an emergency redemption
  needs no tracker signature: after 3 days the contract accepts an empty context var #6)

### Tracker Signature Response Structure

The `/tracker/signature` endpoint returns responses with the following structure:
- `success`: Boolean indicating if the signature generation was successful
- `tracker_signature`: 65-byte Schnorr signature (hex-encoded, 130 characters) proving tracker authorization
- `tracker_pubkey`: Tracker's public key (hex-encoded, 66 characters)
- `message_signed`: The hex-encoded message that was signed
  - `hash(issuerKey||recipientKey) || longToByteArray(totalDebt) || longToByteArray(timestamp) || trackerNftId` (80 bytes)
- `is_emergency`: always `null` (kept for compatibility)

### Redemption Preparation Request Structure

The `/redemption/prepare` endpoint accepts requests with the following structure:
- `issuer_pubkey`: Public key of the note issuer (hex-encoded, 33 bytes)
- `recipient_pubkey`: Public key of the note recipient (hex-encoded, 33 bytes)
- `total_debt`: Total cumulative debt amount in nanoERG

### Redemption Preparation Response Structure

The `/redemption/prepare` endpoint returns responses with the following structure:
- `redemption_id`: Unique identifier for the redemption process
- `tracker_lookup_proof`: AVL tree lookup proof for tracker's tree (context var #8, hex-encoded bytes)
- `reserve_lookup_proof`: AVL tree lookup proof for reserve's tree (context var #7, optional, hex-encoded bytes)
- `reserve_insert_proof`: AVL tree insert/update proof for reserve's tree (context var #5, hex-encoded bytes)
- `tracker_signature`: 65-byte Schnorr signature from tracker (hex-encoded, 130 characters)
- `tracker_pubkey`: Tracker's public key (hex-encoded, 66 characters)
- `tracker_state_digest`: 33-byte AVL tree root digest (hex-encoded, 66 characters) representing current tracker state
- `block_height`: Current blockchain height at time of proof generation
- `is_first_redemption`: Boolean indicating if this is the first redemption (reserve_lookup_proof can be omitted)

### Redemption Proof Response Structure

The `/proof/redemption` endpoint returns responses with the following structure:
- `issuer_pubkey`: Public key of the note issuer (hex-encoded, 66 characters)
- `recipient_pubkey`: Public key of the note recipient (hex-encoded, 66 characters)
- `tracker_lookup_proof`: AVL tree lookup proof for tracker's tree (context var #8, hex-encoded bytes)
- `reserve_lookup_proof`: AVL tree lookup proof for reserve's tree (context var #7, optional, hex-encoded bytes)
- `reserve_insert_proof`: AVL tree insert/update proof for reserve's tree (context var #5, hex-encoded bytes)
- `tracker_state_digest`: 33-byte AVL tree root digest (hex-encoded, 66 characters) representing current tracker state
- `reserve_state_digest`: 33-byte AVL tree root digest (hex-encoded, 66 characters) representing current reserve state
- `block_height`: Current blockchain height at time of proof generation
- `timestamp`: Unix timestamp of the proof generation
- `total_debt`: Total cumulative debt from tracker's tree
- `already_redeemed`: Already redeemed amount from reserve's tree (0 if first redemption)

### Real Cryptographic Implementation

The server signs everything in its own process with `ergo.tracker_secret_key`; it never asks an Ergo node to sign:

#### Schnorr Signature Generation
- **Local Signing (only)**: signatures are generated locally with `ergo.tracker_secret_key`, which is required at startup. There is no `/utils/schnorrSign` fallback; without the key a signature request fails with 500
- **Format**: 65-byte signatures (33 bytes for 'a' component + 32 bytes for 'z' component)
- **Structure**: Properly formatted with compressed public key prefix (0x02 or 0x03) followed by the signature components
- **Implementation**: `/tracker/signature` and `/redeem` sign locally (`/redemption/prepare` is removed: 410 Gone)
- **Message Format**: 
  - Normal and emergency: `blake2b256(issuerKey||recipientKey) || longToByteArray(totalDebt) || longToByteArray(timestamp) || trackerNftId` (80 bytes)
  - Emergency redemption (after 3 days): same 80-byte message format, tracker signature becomes optional

#### AVL Tree Proof Generation
- **Real Proofs**: All proof endpoints now generate actual AVL tree lookup and insert/update proofs from the tracker's and reserve's AVL tree state
- **Format**: Properly formatted proof data that demonstrates existence of key-value pairs in the AVL tree
- **State Commitment**: Tracker state digest properly formatted as 33-byte AVL tree root (1 byte height + 32 bytes hash)
- **Integration**: Proofs are generated by the actual tracker state manager using the AVL tree implementation
- **Context Variables**: Proofs are generated for specific context extension variables:
  - #5: Reserve tree insert/update proof
  - #7: Reserve tree lookup proof (optional)
  - #8: Tracker tree lookup proof (required)

#### Tracker State Management
- **Shared State**: Tracker state is maintained in shared state accessible via `state.shared_tracker_state`
- **Real Digests**: Tracker state digests come from actual AVL tree root, not mock implementations
- **Consistency**: All endpoints return consistent tracker state commitments that match the current AVL tree state
- **Debt Tracking**: Tracker maintains cumulative debt for each (issuer, recipient) pair

### Reserve Creation Payload Structure

The server provides an endpoint to generate reserve creation payloads for Ergo node's `/wallet/payment/send` API:

- `POST /reserves/create` - accepts a request with:
  - `nft_id`: String - the NFT ID to be stored in the reserve box (hex-encoded)
  - `owner_pubkey`: String - the 33-byte compressed public key (hex-encoded) of the reserve owner
  - `erg_amount`: u64 - the amount of ERG to lock in the reserve (in nanoERG)

- Validation rejections (HTTP 400):
  - `nft_id` equal to the configured tracker NFT id
  - `erg_amount` above `server.reserve_creation_max_erg_nano` (default 10 ERG)
  - in token mode, `token_amount` above `server.reserve_creation_max_token_amount` (default 1e9)
  - an `owner_pubkey` that is not a valid secp256k1 curve point
  - an `nft_id` the scanner node knows (`GET /blockchain/token/byId`) as a token whose emission
    is not 1 (round 6d: the scanner admits a reserve only with a singleton NFT); a token the node
    does not know yet, or a node that cannot tell, passes

- HTTP 503 until the tracker box for the configured tracker NFT is confirmed on chain (the
  tracker box updater has found it in the blockchain index, which lists boxes in blocks only).
  The reserve's R6 binds it to that NFT; before the NFT is minted, a reserve would point at a
  tracker that does not exist and could only be refunded.
- The server itself refuses to start with an `ergo.tracker_nft_id` that is not 32 bytes of hex
  or is all zeros (a placeholder, never a minted token).
- HTTP 409 when the owner already has an active reserve in the denomination, or (round 7, N9
  interim guard, `server.reserve_reopen_guard`, default true) when this tracker holds
  redemptions of the owner in the denomination: a new reserve would start with an empty R5 and
  pay those notes again. The answer has `code: "reserve_reopen_blocked"` and an `error` that
  starts with it. HTTP 503 while the tracker has not loaded that history just after a start.
  See `specs/ergo/reserve_admission.md`.

- Returns a JSON response compatible with Ergo's `/wallet/payment/send` API:
  - `requests`: Array of payment requests
    - `address`: Reserve contract P2S address (hardcoded in configuration)
    - `value`: ERG amount from request
    - `assets`: Array containing the NFT asset
      - `token_id`: NFT ID from request (snake_case in the response; the node expects `tokenId`, camelCase)
      - `amount`: Always 1 for NFTs
    - `registers`: Map of register values
      - `R4`: Owner public key from request (GroupElement)
      - `R5`: Initial AVL tree (empty tree for new reserve)
      - `R6`: Tracker NFT ID (bytes) - identifies which tracker server this reserve is linked to
  - `fee`: Transaction fee amount from configuration
  - `change_address`: Owner's P2PK address derived from the request's `owner_pubkey`

There is **no** `/reserves/submit` endpoint (removed in PR #16 B4): the tracker never
broadcasts reserve creations. The owner posts the returned `requests` array to their own
Ergo node's `/wallet/payment/send`; the CLI does this with `reserve create --submit` when
`node_url` is set in `cli.toml`.

### Debt Transfer Support — NOT IMPLEMENTED

**There is no debt-transfer (novation) endpoint on this server.** An earlier revision of this
document described a `POST /debt/transfer` endpoint with a full request schema and stated that
"The server supports debt transfer (novation) operations." That endpoint has never existed in
`crates/basis_server/src/main.rs`; the description was aspirational and has been removed.

For the current design and rollout options for moving a debt obligation between creditors or
between trackers, see [`../cross_tracker_debt_transfer.md`](../cross_tracker_debt_transfer.md).
That document is a design proposal, not a description of shipped behaviour.

Debt obligations are currently moved **off-chain** by creating a new note to the new creditor and
cancelling or reducing the old one, under the ordinary note workflow documented above.

## Configuration

The server supports configuration via:

1. Configuration files (config/basis.toml)
2. Environment variables (with BASIS_ prefix)
3. Default fallback values

Key configuration includes:
- Server host/port
- **`server.data_dir`**: Base directory for all on-disk storage (databases, indices,
  scanner metadata). Defaults to `data` relative to the server's working directory.
  Can be overridden with the `BASIS_SERVER_DATA_DIR` environment variable.
  The legacy `server.database_url` field is kept for compatibility but is currently unused.
- **`server.tls_cert_path` / `server.tls_key_path`**: Paths to PEM-encoded TLS certificate and key.
  When both are set, the server listens on HTTPS. Strongly recommended whenever auth is enabled.
- **`server.auth`**: Authentication and authorization settings:
  - `mode`: `none`, `api_key`, or `signature`.
  - `api_key`: shared secret used when `mode = "api_key"`. Grants `Admin` by default; when
    `admin_api_key` is set it grants only `Write`.
  - `admin_api_key`: optional separate key that grants `Admin` on the operator-only routes
    (`/redeem/complete`, `GET /notes`, `GET /events`, `GET /events/paginated`) when
    `mode = "api_key"`.
  - `authorized_clients`: list of `{ pubkey, role }` entries used when `mode = "signature"`.
  - `allowed_origins`: CORS origin allow-list. Empty (default) disables CORS entirely; wildcard origins are never used.
  - `signature_timestamp_tolerance_ms`: maximum age of a request signature in milliseconds (default 30 s).
- **`server.reserve_creation_max_erg_nano`** / **`server.reserve_creation_max_token_amount`**:
  caps on the collateral a single `/reserves/create` payload may lock (defaults 10 ERG and 1e9
  tokens); larger requests are rejected with HTTP 400.
- **`server.redemption_build_max_per_pair_per_hour`** / **`server.redemption_build_max_per_recipient_per_hour`**:
  per-(issuer, recipient) and per-recipient rate limits on `POST /redemption/build` (defaults 60
  and 30 per hour, rolling window); excess requests get HTTP 429. Only requests whose
  `receiver_signature` verifies and whose note the tracker holds are counted, so nobody but the
  recipient can spend them; they are counted before the committed proof and the cheap checks
  (round 5), so a signed request that fails those still uses one unit.
- **`server.redemption_build_max_per_issuer_per_hour`** / **`server.redemption_build_max_per_hour`**:
  per-issuer and total caps on the builds that get as far as signing tracker fee inputs (token
  reserves only; defaults 6 and 30 per hour, rolling window); excess requests get HTTP 429.
  Requests that fail before signing (no note, no reserve) and ERG-reserve builds (the fee comes out
  of the payout, no tracker input) do not use these budgets.
- **`transaction.commit_reserve_nano`**: token-free nanoERG kept at the tracker address for
  commits and heartbeats (default 0.1 ERG; 0 disables). A build that would leave less there gets
  HTTP 503.
- **Ergo node connection details**: `ergo.scanner.node_url` defaults to `http://127.0.0.1:9053`; point it at your Ergo node (with `extraIndex = true`) for real deployments. Only the `POST /transactions` broadcast goes to `ergo.wallet.node_url`, which falls back to the scanner node when unset; no `/wallet/*` or `/utils/schnorrSign` endpoint is used and no node API key is needed.
- Reserve contract P2S address
- Tracker NFT ID (for tracker scanner registration and state commitment monitoring)
- Tracker public key (for identifying the tracker server)
- Transaction fees

**Critical Requirements**:
1. `ergo.scanner.node_url` defaults to `http://127.0.0.1:9053` (local node); point it at your Ergo node (with `extraIndex = true`) for real deployments. `ergo.wallet.node_url` optionally points at a separate node for the `POST /transactions` broadcast; it falls back to the scanner node when unset.
2. `ergo.tracker_secret_key` must be configured: the tracker signs notes' redemption messages and its own transactions locally. No node wallet and no node API key are needed.
3. The tracker public key must be provided in the configuration, and it must equal `tracker_secret_key·G` (checked at startup).
4. Secrets never reach `Debug` output: every config struct that holds one (`ServerConfig`, `AuthConfig`, `ErgoConfig`, `WalletNodeConfig`, `TrackerBoxUpdateConfig`, and in `basis_store` `NodeConfig` and `TrackerNodeConfig`) implements `Debug` by hand with `basis_store::redact`: a set secret prints as `<redacted>`, an unset one as `None`, and URL credentials as `<redacted>@`.
5. When `server.auth.mode` is not `none`, configure TLS (`server.tls_cert_path` and `server.tls_key_path`) for production deployments so credentials and signatures are not sent in plaintext.

## Blockchain Integration

The server integrates with the Ergo blockchain through:

1. **Ergo Scanner**: Monitors the blockchain for reserve box events
2. **Tracker Scanner**: Monitors tracker state commitment boxes using the tracker NFT ID to enable cross-verification and state synchronization
3. **Reserve Event Processing**: Handles reserve creation, top-ups, and redemptions
4. **Real-time Updates**: Tracks collateralization ratios and reserve status
5. **Scan Registration**: Automatically registers both reserve and tracker scans with the Ergo node using the `/scan` API
6. **AVL Tree Verification**: Verifies on-chain AVL tree commitments match off-chain state

## Event Store

The server maintains an in-memory event store with:
- Sequential ID generation
- Pagination support
- Thread-safe operations using async mutex
- Planned persistence layer

## Error Handling

The server implements comprehensive error handling:

- Validation of hex-encoded public keys and signatures
- Proper HTTP status codes (200, 400, 500)
- Detailed error messages for debugging
- Graceful fallback when blockchain scanner is unavailable
- AVL tree proof validation errors
- Emergency redemption timeout handling
- Acceptance policy enforcement at redemption time: normal redemptions via `POST /redeem` and `POST /redemption/build` are rejected with HTTP 400 when they would newly violate another debt holder's acceptance policy (failure id `failed_policy_violation`) or, on a distressed reserve, when the redeemer does not hold the issuer's oldest outstanding note (failure id `failed_not_oldest_note`). Configurable via `[redemption] enforce_acceptance_policy` (default `true`); see `specs/redemption_acceptance_policy.md`

## Authentication & Authorization

The server supports three authentication modes configured under `[server.auth]`:

- `none`: anonymous access (backward-compatible local development).
- `api_key`: shared secret via `Authorization: Bearer <key>` or `X-API-Key: <key>`.
- `signature`: per-client secp256k1 Schnorr request signatures.

Signature mode uses a canonical message:

```text
<METHOD>\n<PATH>\n<QUERY>\n<TIMESTAMP>\n<NONCE>\n<BODY_HASH>
```

where `BODY_HASH` is the lowercase hex SHA-256 of the raw request body. The server verifies signatures with `basis_offchain::schnorr::schnorr_verify`, enforces a timestamp tolerance (default 30 s), and rejects replayed `(pubkey, nonce)` pairs.

Role-based access control assigns each request a role:

- `Read`: `GET` endpoints and read-only `POST` queries (`/notes/state`, `/acceptance/check`).
- `Write`: state-changing endpoints such as `/notes`, `/redeem`, `/redemption/prepare`, `/tracker/signature`, plus reserve payload creation (`/reserves/create`) and recipient-signed policy uploads (`/acceptance/policy`).
- `Admin`: redemption completion (`/redeem/complete`).

In `none` mode every request receives `Admin`. In `api_key` mode `admin_api_key` is required:
`api_key` grants only `Write` and the admin key grants `Admin`. In `signature` mode the role is taken from the matching
`authorized_clients` entry.

TLS should be enabled (`tls_cert_path` / `tls_key_path`) whenever authentication is used in production, otherwise credentials and signatures travel in plaintext.

For full details see `specs/server/authentication_authorization.md`.

## Security Considerations

- CORS headers only for the explicit `allowed_origins` allow-list; when it is empty (default), no CORS layer is installed at all
- Input validation for all public keys and amounts
- Signature verification for note creation and debt transfer
- Channel-based communication to ensure thread safety
- Remote signature generation to protect private keys
- AVL tree proof verification to prevent fraud
- Authentication and RBAC on all endpoints except the health-check root (`GET /`)

## Blockchain Height Caching

The server implements intelligent blockchain height caching to reduce Ergo node API calls:

- **Cache Storage**: Blockchain height and fetch timestamp stored in `scanner_metadata` database partition
- **TTL**: 10 minutes (600,000 milliseconds)
- **Cache Key**: `"blockchain_height"`
- **Cache Value**: 16 bytes (8 bytes height + 8 bytes timestamp, both big-endian u64)
- **Behavior**: 
  - Returns cached height if < 10 minutes old
  - Fetches from Ergo node `/info` endpoint if cache expired or missing
  - Stores new height with current timestamp after fetching
  - Implemented in both `ergo_scanner.rs` and `tracker_scanner.rs`

## Current State Summary

The basis_server crate is a fully functional HTTP API server that:
- Manages IOU notes and redemption processes
- Monitors Ergo blockchain reserve events
- Provides real AVL tree proof mechanisms for the Basis protocol
- Generates real Schnorr signatures via Ergo node's signing API for redemption transactions
- Implements proper async/await patterns and error handling
- Supports configuration and event storage
- Includes comprehensive API endpoints for all Basis features
- Provides endpoints for real tracker signature generation (`/tracker/signature`)
- Offers redemption preparation with real proofs and signatures (`/redemption/prepare`)
- Supports redemption-specific proof generation (`/proof/redemption`)
- Integrates with shared tracker state for consistent AVL tree root commitments
- Uses secure remote signing via Ergo node API to protect private keys
- Handles emergency redemption after 3-day timeout

This crate serves as the central hub for the Basis Tracker system, connecting the blockchain layer with client applications through a well-defined HTTP interface with real cryptographic operations while maintaining security through remote signing.

## Context Extension Variables Reference

For redemption transactions prepared by the server:

| Variable | Type | Description | Required |
|----------|------|-------------|----------|
| #0 | Byte | Action byte (0x00 for redemption) | Yes |
| #1 | GroupElement | Receiver pubkey | Yes |
| #2 | Coll[Byte] | Reserve owner's signature bytes | Yes |
| #3 | Long | Total debt amount | Yes |
| #5 | Coll[Byte] | AVL proof for reserve tree insert/update | Yes |
| #6 | Coll[Byte] | Tracker's signature bytes | Yes |
| #7 | Coll[Byte] | AVL proof for reserve tree lookup | No (omit for first redemption) |
| #8 | Coll[Byte] | AVL proof for tracker tree lookup | Yes |
