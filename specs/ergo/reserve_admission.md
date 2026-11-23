# Reserve admission control (issue #19)

## Problem

R4 of a reserve box is not authenticated on-chain: anyone can create a box at the
reserve contract address with a victim's public key in R4. Before this change, a dust
duplicate of a victim's reserve was tracked alongside the real one.
`ReserveTracker::resolve_issuer_reserve` then failed closed with
`MultipleReservesForDenomination` (PR #14 C3: a note is not bound to a specific reserve
box, so the tracker refuses ambiguous configurations), and the acceptance predicates,
the redemption build/sign path, and the exchange flow all refused the victim — a
one-dust-box denial of service.

Checking creation-time invariants alone (`R7 == 0`, empty R5 tree — the "C4 setup
checks") cannot distinguish a legitimate root from an attacker's front-run dust box,
because the attacker can satisfy those invariants just as well as the victim can.

## Why naive fixes are wrong

- **"Run the C4 validation on every box"** breaks legitimate operation: every reserve
  action (redemption #0, top-up #1, refund initiation #2) spends the reserve box and
  creates a successor. After a redemption R5 is legitimately non-empty; after refund
  initiation R7 is legitimately set. Successors must not be re-validated against
  creation-time invariants.
- **"Oldest box wins"** hands control to the attacker on every top-up/redemption,
  because each successor is *younger* than a dust box the attacker created after the
  victim's root.
- **"C4-clean root wins"** (the v1 rule) still loses to a front-run: the attacker's
  box passes the same setup checks.

## Admission rules

A scanned box at a reserve contract address is parsed (per-box structural validation:
R4 present and a valid curve point, R6 bound to this tracker's NFT, R7 typed as Long,
token slot shape for token reserves) and then admitted only when one of the following
holds:

1. **Refresh** — the box is the currently tracked box itself.
2. **Root** — no reserve is tracked for its `(owner, denomination)`, the box holds a
   reserve NFT (a 32-byte token with amount 1 at `tokens(0)`; round 6b) that is a true
   singleton (`GET /blockchain/token/byId/{id}` gives `emissionAmount` 1, cached; round
   6c), the C4 setup checks pass (`R7 == 0`, R5 is the empty AVL+ tree), **and the box's
   creating transaction (fetched via `GET /blockchain/transaction/byId/{txId}`) spends at
   least one input locked by the P2PK script of the R4 owner key** (ErgoTree
   `0008cd || owner_pubkey`, checked at any input position). Spending such an input
   requires the owner's signature, so only the owner (or someone they co-signed with)
   can open a root reserve for that key. Round 6c: a fresh reserve can be topped up by
   anyone before the scanner first sees it; then the root is admitted when its NFT leads
   back (input holding it at `tokens(0)` with amount 1, same R4 and R6, at the contract,
   still clean: empty R5, `R7 == 0`, so only top-ups happened) to a box whose creating
   transaction has the owner's P2PK input. Round 6d: or to a reserve box with a pending
   refund (`R7 != 0`) holding the NFT: redemption (#0) and top-up (#1) keep R7 and refund
   initiation (#2) needs `R7 == 0`, so only the owner's refund completion (#3) turns it
   into a clean box.
3. **Successor** — the box holds the reserve NFT of a tracked box of its
   `(owner, denomination)` (the NFT of each tracked box is cached: from the scan, or one
   `GET /blockchain/box/byId` per tracked box; round 6c). A box holding none of them is
   quarantined at once, with no walk and no retry: a newcomer never displaces a tracked
   reserve. For a box holding the tracked box's NFT, `GET /blockchain/box/byId` of the
   tracked box gives the transaction that spent it; when that transaction created the
   box and the NFT is a singleton, it is the successor (no transaction is read, however
   large; round 6d: a NFT that is not a singleton is walked). Otherwise the walk
   goes back from the box through its creating transaction to the input that holds the
   NFT as a reserve box does (`tokens(0)` = (NFT, 1), the same R4 and R6, and the
   tracked box or at the reserve contract; not merely the first input holding the
   token), possibly across missed generations (up to `LINEAGE_WALK_DEPTH = 64`; round
   6c), until that input is the tracked box or was created by the transaction that spent
   it. When the walk gives no verdict (depth used up, a transaction over the 2 MiB body
   cap, a node error), a singleton NFT decides: with the tracked box spent, no other box
   can hold it. Round 6d: so it does when the index does not know the tracked box (a
   reorg dropped the transaction that made it) or still shows it unspent, so a
   successor a reorg dropped never strands the reserve. Otherwise the box is pending
   (retried), never quarantined for that.

   **Round 6d: a completed refund starts anew.** Every step from the tracked box to the
   box (the direct spend, each walked input, the singleton decision) must keep a
   pending refund: when the box before has `R7 != 0` the box after must have the same
   R7. Otherwise the owner completed the refund (#3) and made the box anew, and it is
   judged as a root (C4 setup checks, singleton, owner proof): a box re-created with the
   same NFT, `R7 == 0` and a pre-filled R5 is quarantined.
   The reserve contract keeps the token list, R4 and R6 of the output each reserve input
   names (`selfPreserved` in `contract/basis.es`: `selfOut.tokens == SELF.tokens`; in
   `basis-token.es` the NFT at `tokens(0)` and the token id at `tokens(1)`), so the NFT
   moves with the reserve and a verified successor needs no further validation — and no
   P2PK proof, since reserve actions (redemption, permissionless top-up) legitimately
   have no owner P2PK input. A box without a reserve NFT has no lineage, and a
   transaction whose inputs come without their assets gives no verdict (pending).

   **Round 6b: why the NFT and not "spends the tracked box".** A top-up needs no owner
   signature and the contract only constrains the output the reserve input names
   (`OUTPUTS(index)`). So anyone can spend their own box A and the victim's reserve G
   into G + 0.1 ERG and a box P at the reserve contract with R4 = victim, R6 = this
   tracker's NFT, an empty R5, R7 = 0 and a fresh NFT (A's id). P's creating
   transaction spends G; under the old rule P was a successor, and depending on the
   scan order (box ids, which the attacker can grind) the tracker followed {G + 0.1, P}
   (two reserves: the victim's notes refused) or only P (the genuine reserve quarantined
   for good). Now only the box holding G's NFT continues G; P is quarantined. When one
   spending transaction creates several reserve-contract outputs, only the one holding
   the NFT is the successor.

   **Round 6d: a new reserve in the window of a withdrawal.** When none of the owner's
   tracked boxes in the denomination is in this cycle's scan (the owner withdrew the
   reserve), a box that holds none of their NFTs is not quarantined: it waits, and once
   the spent box is removed it is judged as a root.

Anything else is **quarantined**: it never enters the tracker (so
`resolve_issuer_reserve` never sees a duplicate) and a record (`box_id`, `owner`,
`denomination`, `reason`, timestamp) is persisted in the `quarantined_reserves`
partition and exposed via `GET /reserves/quarantined`. Quarantine is sticky: a box
once quarantined is never re-evaluated, so an attacker cannot regain admission by
timing a box against a legitimate successor in a later scan cycle. Only an operator
release (below) lifts it.

If the proof fetch is inconclusive (node error fetching the creating transaction), the
box is **pending**: it is neither admitted nor quarantined, and the tracked box for
the same `(owner, denomination)` is not removed as spent that cycle — a transient
node error must not orphan the lineage and brick the issuer. Round 6c: only while that
tracked box is the owner's only reserve there; once a successor holding its NFT is
tracked, a pending check never keeps the spent box next to it. Round 6d: only a box that
holds (or may hold) the tracked box's NFT keeps it; a root candidate that is retried
keeps nothing. The lineage and ownership checks share a budget of 512 node requests per
scan cycle; past it a check is pending (a successor with a singleton NFT is still
followed).

**Node requests per cycle (round 6d).** A scan cycle starts by learning the NFT of every
tracked reserve (from the scan, else one `GET /blockchain/box/byId`) and checks first
the tracked boxes, boxes removed in the last day, and boxes holding a tracked NFT; then
the rest. Reading the tracked box and the singleton lookup of a box holding a tracked
NFT are outside the shared budget (bounded by the number of tracked reserves), so no
number of other boxes, in any scan order, can push a successor past the budget. Root
candidates are capped at `MAX_ROOT_CHECKS_PER_CYCLE = 128` per cycle (never-checked
first, then the least recently checked; past the cap they wait for the next cycle). A
transaction or box read once in a cycle is reused by every check of that cycle (errors
too, up to 64 MiB of transaction inputs), so one transaction over the 2 MiB body cap that
makes 512 junk roots costs one request per cycle.

**Spent reserves (round 6c).** A tracked reserve absent from the scan is spent and
removed. When the scan lists no valid box at all, the snapshot is not taken as
authoritative (manually inserted reserves on a local test node), so an absent reserve
is removed only when `GET /blockchain/box/byId` shows it spent: the last reserve, withdrawn
by refund completion, no longer stays tracked for good (which made the owner's next
reserve a quarantined newcomer). Round 6d: and only once that spend is at least
`SPENT_REMOVAL_DEPTH = 10` blocks deep (`spendingHeight` of the box, else the spending
transaction's `inclusionHeight`, against `/info` `fullHeight`). A removed box is
remembered (box id and NFT) for a day, about 720 blocks: when a reorg brings it back to
the scan, it is restored as the tracked box instead of being judged as a root (unless a
tracked box of the owner in the denomination is in the scan too).

**Operator release (round 6c).** `POST /reserves/quarantined/release` (Admin; body
`box_id`, `note`) moves a quarantine record to a journal (`quarantine_releases`,
listed by `GET /reserves/quarantined/releases`) in one batch. The release does not
track the box: at its next cycle the scanner judges it again by the rules of the day,
and a box that still fails them is quarantined again. For boxes an older rule
quarantined (more than 8 actions between two scans before round 6c, say, or a new
reserve that appeared in the same scan cycle in which the owner's withdrawn reserve was
still tracked, before round 6d).

Both ingestion paths go through admission: `ServerState::process_scan_boxes` (the
scanner loop) and the server's background scanner task (which delegates to
`process_scan_boxes` instead of inserting parsed boxes directly).

`resolve_issuer_reserve` keeps its fail-closed `MultipleReservesForDenomination`
error as defense in depth; with admission control it should be unreachable.

A newcomer never displaces a tracked reserve: while the owner has one tracked in a
denomination, every other box of that owner and denomination goes through the successor
rule, and the tracked box leaves the tracker only when the scan no longer lists it (spent)
and no successor check is pending (round 6d: the only exception is a box holding none of
the tracked NFTs while none of the tracked boxes is in the scan, which waits instead of
being quarantined).

## Why the P2PK proof closes the front-run

The v1 lineage-only rule left one residual attack: creating a C4-clean dust reserve
for the victim *before* the victim's first reserve in a denomination, so the attacker's
box became the legitimate root. Under the P2PK-proof rule that is impossible: the
attacker's creating transaction cannot spend a P2PK(victim) input without the victim's
signature, so the front-run box is quarantined. A victim co-signing such a transaction
out-of-band is equivalent to the victim delegating reserve creation and is out of
scope.

## Deployment tooling guarantee

`basis-cli reserve create --submit` (and the TUI wallet flow, both via
`submit_reserve_to_node` in `crates/basis_cli/src/api.rs`) guarantee the proof input
exists:

- if every unspent wallet box is P2PK(owner), any automatic input selection satisfies
  the rule, so the payload goes to `/wallet/payment/send` unchanged;
- otherwise the inputs are pinned via `/wallet/transaction/send` with `inputsRaw`
  (the P2PK(owner) proof box plus funding boxes; strict input/output balance is met
  with an explicit change output to the owner's address);
- if the wallet holds no P2PK(owner) box at all, a pre-deployment transaction first
  sends 0.001 ERG to the owner's own P2PK address; once it appears in the wallet, the
  pinned deployment spends it. If the node wallet does not hold the owner key, the
  pre-deployment UTXO never appears and the command fails with an explicit error.

Manual submission of the `/reserves/create` payload via `/wallet/payment/send` is only
safe when the wallet's boxes all belong to the owner key; otherwise the node may
select inputs with no P2PK(owner) box and the tracker will quarantine the reserve.

## Fresh-resync caveat

The P2PK proof is required only for **root** admission. A tracked reserve that is
spent forward is re-admitted through the successor rule, and the currently tracked box
through the refresh rule, so day-to-day operation never re-checks the proof. But if
the reserve database is wiped and the tracker re-scans from scratch, a reserve whose
current box was created by a later action (top-up/redemption) has no P2PK input in
*its* creating transaction and will be quarantined. Recovery: wipe to a height before
the reserve's creation, or remove the quarantined record and let the lineage walk
re-admit from a synced ancestor. Operators should treat the reserve DB as state worth
backing up.

## Code map

- `crates/basis_store/src/ergo_scanner.rs`
  - `parse_reserve_box` — per-box structural validation only.
  - `admit_reserve_box` — admission decision (lineage for successors, quarantine
    stickiness, restoring a removed box a reorg brought back; round 6d).
  - `admit_root` — the root rules: C4 checks, singleton, P2PK proof, the per-cycle cap.
  - `begin_cycle` — per-cycle state, the tracked NFTs, and the order of the checks
    (round 6d).
  - `p2pk_ergo_tree` / `has_owner_p2pk_input` — the `0008cd || pubkey` proof check.
  - `is_lineage_successor` — the tracked box's spender first, then a bounded backwards
    walk over `/blockchain/transaction/byId` following the reserve NFT (round 6b), with
    the singleton fallback (round 6c).
  - `tracked_nft` / `is_singleton_nft` — the NFT cache and the token index check.
  - `has_owner_root` — the P2PK proof, with the NFT ancestry through top-ups (round 6c).
  - `ingest_scan_box` — parse + admit + track/persist + quarantine persistence.
  - `process_scan_boxes` — removal loop keeps boxes whose proof/lineage check is pending.
- `crates/basis_store/src/persistence.rs` — `QuarantinedReserve`,
  `quarantined_reserves` partition on `ReserveStorage`.
- `crates/basis_server/src/reserve_api.rs` — `GET /reserves/quarantined`,
  `POST /reserves/quarantined/release`, `GET /reserves/quarantined/releases`.
- `crates/basis_cli/src/api.rs` — `submit_reserve_to_node` and helpers
  (`select_deployment_boxes`, `deployment_change`, `create_predeployment_utxo`,
  `send_pinned_deployment`) guaranteeing the P2PK proof input at deployment time.
