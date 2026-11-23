# The ErgoScan fork of basis-tracker

This is the tracker that has run on Ergo mainnet since 22 November 2026. It works with the Basis wallet at
https://basis.ergoscan.me/wallet/mainnet; the wallet's code is at https://github.com/kayolo-ergoscan/basis-app. It is not
an official Better Money Labs release.

**Branch:** `ergoscan`. It is upstream `43e2173` plus upstream PR #25 (note trees in debt-key order, fixes #24) plus our
commits.

**License:** CC0, the same as upstream. Any of these changes may be taken back upstream.

## What changed

**Keyless operation.** The tracker needs no node wallet and no node API key:
- it finds fee boxes through the node's public `byAddress` index;
- it signs commits and tracker signatures locally (`local_wallet.rs`);
- `/wallet/transaction/sign` and `/utils/schnorrSign` are never called;
- `POST /redemption/prepare` answers 410.

**Startup and shutdown:**
- the tracker refuses to start without a matching tracker key, and commits only to a P2PK box;
- each fjall directory is opened once, and its journals are fsynced every second;
- it shuts down within 20 s of SIGTERM;
- early startup errors print without config values; `Debug` of the config redacts secrets.

**The tracker box:**
- a heartbeat commit every `heartbeat_blocks` (default 720);
- commit fees use token-free boxes with real change, so no token is ever burnt;
- the confirmation depth counts from the commit's inclusion height;
- a pending commit is looked up in the mempool first;
- a skipped first cycle is retried;
- the total commit deferral is capped, and a heartbeat is never held back.

**Notes:**
- `GET /notes` and the event list need the Admin role;
- `POST /notes` needs the issuer's reserve under this tracker (`notes_require_reserve`);
- three note caps per issuer (HTTP 429), including new edges per hour;
- notes no longer rebuild the live tree one by one.

**Acceptance policies:**
- policies are validated before they are stored;
- depth guards fail closed;
- what the startup re-check refuses is quarantined.

**Redemptions:**
- `/redemption/build` must be signed by the recipient. ERG reserves pay the miner fee out of the payout, so the tracker
  pays nothing.
- Budgets per issuer and in total.
- Dust change goes to the fee; the built transaction is checked locally; a fee input holding a token is never signed.
- A redemption journal ties the tracker's state to the chain:
  - a redemption is applied, idempotently and with its build's timestamp, after 2 confirmations;
  - notes and exchanges answer 409 while a redemption of either reserve is waiting;
  - the confirmer drops only what can no longer be mined;
  - admin routes list, drop and apply journal entries.

**Reserves:**
- `/reserves` reports the notes' outstanding debt, the ratio and `pending_redemption_amount`;
- `/reserves/create` writes canonical registers (R7 = `0500`).

**New crates:**
- `basis_bootstrap` mints the tracker NFT and creates the first tracker box;
- `basis_canary` is a closed end-to-end canary with keys read from files, plus an e2e test against the router and a
  mock node.

The commit messages on this branch explain each change; `git log 43e2173..ergoscan` lists them.
