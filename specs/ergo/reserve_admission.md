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
   reorg dropped the transaction that made it), so a successor a reorg dropped never
   strands the reserve. Otherwise the box is pending (retried), never quarantined for
   that. Round 6e: a tracked box the index does not know is not on chain, so its R7
   says nothing: the walk goes back to a box removed lately (an earlier box of the
   lineage, on chain) and judges each step from there; an NFT that entered the box itself
   from outside any reserve box (at its own creating transaction) makes it a root (round
   6f: deeper, the walk has only reached the lineage's own root creation, which says
   nothing); otherwise the singleton decides only when R7 equals the tracked box's, and
   the box is pending when it does not. When the index
   shows the tracked box unspent, it lags or the box is an earlier one: only a box the
   walk leads back to the tracked box follows it; otherwise it is pending.

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

**Round 6e: a removed box anchors its successor.** A removed box is remembered with its
record and NFT for a day (below). A box holding that NFT, of the same owner and
denomination, is checked as a successor of the removed box (it goes first in the cycle;
round 6f: of several, the one removed last): the successor of a box the scan missed for a
while is followed, not judged as a root.

If the proof fetch is inconclusive (node error fetching the creating transaction), the
box is **pending**: it is neither admitted nor quarantined, and the tracked box for
the same `(owner, denomination)` is not removed as spent that cycle — a transient
node error must not orphan the lineage and brick the issuer. Round 6c: only while that
tracked box is the owner's only reserve there; once a successor holding its NFT is
tracked, a pending check never keeps the spent box next to it. Round 6d: only a box that
holds (or may hold) the tracked box's NFT keeps it; a root candidate that is retried
keeps nothing. Round 6e: not past the refund either: a tracked box with a pending
refund (`R7 != 0`) whose 43,200 blocks have passed, and whose spend is deep (below), is
removed even while a check is pending; round 6f: so is a tracked box the index has not
known for `SPENT_REMOVAL_DEPTH` blocks (below). The lineage and ownership checks share a budget
of 512 node requests per scan cycle; past it a check is pending (a successor with a
singleton NFT is still followed).

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
makes 512 junk roots costs one request per cycle. Round 6e: a cycle is skipped when
`GET /blockchain/indexedHeight` gives an `indexedHeight` more than `MAX_INDEX_LAG = 2`
blocks behind its `fullHeight` (a lagging index shows spent boxes as unspent; a node
that does not answer it is scanned anyway). The checks on the shared budget stop after
120 s of a cycle (pending). The cached singleton answers are kept only for the NFTs in
the scan and of the tracked and removed boxes. Round 6f: a skipped cycle is logged as a
warning on the first skip and every 30 in a row (the count is `skipped_cycles()`; the
server has no status route to show it on).

**Spent reserves (rounds 6c–6e).** A tracked reserve absent from the scan is removed
only when a box holding its NFT is tracked in the same cycle (its successor), or when
`GET /blockchain/box/byId` shows it spent and the spend is at least
`SPENT_REMOVAL_DEPTH = 10` blocks deep. Round 6e: this holds for every scan. The scan
is read page by page (100 boxes, newest first), so an unspent box can be missing from
it: anyone can push the tracked box past page 0 with 100 boxes at the contract address
and top it up between two page reads, and the address may simply hold more than 100
boxes; before round 6e such a box was removed at once and its successor then judged as
a root (quarantined for good once R5 was used). The scan also reads page 0 again after
the last page, so a box made meanwhile is seen in the same cycle. The spend height is
the spending transaction's `inclusionHeight` (`/blockchain/box/byId` has no spend
height), read from the start of its body, so a transaction over the body cap still
tells it; it is compared with the index height of the cycle, else `/info`
`fullHeight`. A scan with no valid box at all (manually inserted reserves on a local
test node, round 6c) removes nothing the chain does not show spent. A removed box is
remembered (its record and NFT) for about 720 blocks (round 6f-2: index blocks, below): when a reorg brings it back
to the scan, it is restored as the tracked box instead of being judged as a root
(unless a tracked box of the owner in the denomination is in the scan too).

**Round 6f.** The removed boxes are kept in the `removed_reserves` partition (box id ->
record, NFT, time), so they survive a restart; nothing else in the reserve database
changes. A tracked box the index does not know (its block orphaned, its input
double-spent on the winning fork, so it never exists and nothing holds its NFT) is
removed once the index is `SPENT_REMOVAL_DEPTH` blocks past the height where it was
first unknown, and at once when another box of its owner and denomination is tracked
in the cycle. With page 0 read again, one scan can list the spent tracked box (from the
first read) next to its successor or the owner's new box (from the re-read): a listed
box that the index shows spent is gone (asked only when another tracked box of the owner
holds its NFT, or the cycle already read it spent), so the owner's new box waits for the
root check instead of being quarantined, and the spent box leaves next to its successor
in the same cycle. The scan list is deduplicated by box id across the re-read.

**Round 6f-2.** The rules for a box the index does not know (the 10-block rule, the
pending override and the immediate rule next to a sibling) apply only in a cycle whose
index height is known (`GET /blockchain/indexedHeight` answered with both heights), and
both the first-unknown height and the current one are index heights, never `/info`
`fullHeight`: a lagging or rebuilding index does not know boxes that exist, so while
its height is unknown such a box is kept. The first-unknown height of a box is dropped
when the box is listed in the scan again, so it starts anew when the box is next
missing. A removed record expires `REMEMBER_REMOVED_BLOCKS = 720` index blocks after the
removal (the record stores that height, `removed_height`; a record without one counts
from the first cycle with a known index height, and that height is stored), never by
wall-clock: nothing expires in cycles skipped for lag or while the index height is
unknown. A restored box's removed record is forgotten only once the box is stored again
in the reserve database.

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
rule, and the tracked box leaves the tracker only when its successor is tracked, or it is
spent deep and no successor check is pending (round 6d: the only exception is a box holding none of
the tracked NFTs while none of the tracked boxes is in the scan, which waits instead of
being quarantined).

## Round 7: reopening after redemptions (N9), interim guard

**The hole (follow-up review N9).** The reserve contract learns which notes were
redeemed, and for how much, only from R5 of the reserve box being spent. A root reserve
must start with the empty tree in R5 (the C4 rule above). So when an owner completes a
refund (#3) and opens a new reserve in the same denomination, with the same NFT or a
new one, every note of that owner redeemed before has `already_redeemed = 0` against
the new box and can be redeemed from it again.

**Interim guard (operator's choice "b").** Until a new reserve can carry the history in
R5 (upstream PR #27 does that in aea7589 with an R5 built from the tracker's digest and
a `pending_reserve_roots` record per create; not taken here), this tracker refuses to
open a reserve for an (owner, denomination) pair whose redemption history it holds:

- `POST /reserves/create` answers **409** with `code: "reserve_reopen_blocked"` and an
  `error` that starts with `reserve_reopen_blocked: ` (the style of the other coded
  refusals), checked right after the "an active reserve already exists" 409. No
  payload is built.
- The scanner quarantines a new **root** reserve box of such a pair with a reason that
  starts with `reserve_reopen_blocked:`. This is the last root rule in `admit_root`,
  after the C4 checks, the singleton check and the P2PK proof, so it covers all three
  ways a box is judged as a root: an owner with no tracked reserve, a box whose lineage
  from a removed box starts anew, and a box holding the tracked NFT after a completed
  refund. A box another rule quarantines keeps that reason.

**Never touched.** The tracked box (refresh), its successors (top-up, redemption,
refund start: the NFT lineage), a box a reorg brought back (restore) and a box already
in quarantine (sticky) never reach the root rules, so the guard never sees them. A
top-up is a successor, not a root. A restart on the current data keeps every tracked
reserve: the boxes are tracked, and the guard asks nothing of them.

**History source: the tracker's reserve trees.** A pair has history when its reserve
tree in `TrackerStateManager` (per owner = issuer and denomination, the tree whose
digest a reserve's R5 holds) is not the empty tree. Why this one:

- it is exactly what R5 of the pair's reserve held, so "history" means the same thing
  the contract would lose;
- it is persistent: rebuilt at every start from the `reserve_avl_journal` partition of
  `data/notes`, and it survives the reserve's removal from the reserve database;
- it covers every way history gets there: a redemption applied by the tracker
  (`complete_redemption_at` from `/redeem/complete` and the redemption confirmer, via
  `apply_redemption`), the tree repair towards the chain's R5
  (`repair_reserve_tree_value`) and the journal replay at start.

Not used: `amount_redeemed` of the notes (also moved by off-chain `/redeem/complete`
and repairs, and gone with a note), the pending redemption registry (in memory), the
removed boxes (`removed_reserves` expire after 720 blocks).

Only the tracker thread opens `data/notes`, so it publishes the pairs (`ReopenGuard`,
`crates/basis_store/src/reopen_guard.rs`) once it has rebuilt its trees, and records a
pair at every later tree change; the scanner and `/reserves/create` read it. The guard
is shared through the scanner state (`ServerState::reopen_guard`), set in `main.rs`
before the scanner starts.

**Startup.** The scanner starts before the tracker thread has rebuilt its trees. Until
the pairs are published the answer is "unknown": a root waits (`Retry`, or `Deferred`
for a capped root, as when a node check fails), and `/reserves/create` answers **503**
("the tracker has not loaded its redemption history ..."). Nothing is quarantined on a
guess. If the tracker thread never publishes (it failed at start, or the history is
incomplete, below), roots keep waiting and creation keeps answering 503: the guard fails
closed.

**Incomplete history (round 7b, review P2-1).** The pairs are published only when the
start replayed the whole `reserve_avl_journal`. If the journal cannot be read, or an
entry is skipped (malformed, of a note the store does not hold) or fails to replay, the
trees may miss redemptions, and a partial set would open the guard for exactly those
pairs. The tracker then logs an error (`Reserve reopen guard (N9) stays closed: the
redemption history is incomplete (...)`, after `Reserve AVL trees rebuilt with a gap` or
`Failed to rebuild reserve AVL trees`) and publishes nothing: the guard stays "unknown"
for every pair, creation answers 503 and new roots wait, until the journal is repaired
and the tracker restarted, or `reserve_reopen_guard = false`. Such a gap also breaks
the redemption builds of the pairs concerned (the tracker's tree no longer equals R5).

**Fresh resync.** A tracker with no reserve trees (new data) has no pairs, so the guard
blocks nothing beyond the rules above. If only the reserve database is wiped and the
notes are kept, a reserve that was already reopened after redemptions is a root again
and is quarantined with this reason; a release (below) puts it back where it was before
the wipe, a tracked reserve the tracker cannot redeem from. The resync caveat below
applies as before.

**Release.** `POST /reserves/quarantined/release` works as for every reason: the next
cycle judges the box again. The guard lets a root through only when the release
journal (`quarantine_releases`) holds a release of **this box** whose record has the
`reserve_reopen_blocked` reason; a box released from another reason that still has
history is quarantined again, now with this reason, and needs a release of its own.

A release from this quarantine is **not a way to let the owner go on** (review P2-2).
It brings back the round 6f behaviour for that box, which is the trap the guard
exists to avoid:

- the box is tracked: it counts as collateral in `/reserves` and on the site, and the
  owner can write notes on it again (`POST /notes`);
- `/redemption/build` picks only a reserve box whose R5 equals the tracker's tree of the
  pair. The new box has the empty tree in R5 and the tracker's tree holds the history,
  so every build for the owner in that denomination, old notes and new, answers 400
  ("no unspent reserve ... with a reserve tree matching the tracker");
- the tree repair only changes the values of keys, it cannot remove the history, so
  nothing on the tracker side brings the tree back to the empty R5.

New creditors would then accept notes the tracker cannot redeem. The way for the owner
is a **new owner key**: a new key is a new pair without history, so its reserve is
created and tracked as any other. Release from this quarantine only after deciding to
accept all of the above (an operator's own test reserve, say).

**What the guard does not close.** The hole is in the contract and stays there: a note's
tracker signature (`key ‖ totalDebt ‖ timestamp ‖ trackerNftId`) does not name the
reserve box or its NFT. A box made on chain without this tracker (not through
`/reserves/create`) still exists with an empty R5, and an old creditor holding a valid
tracker signature could try to build a redemption of an already redeemed note from it
without the tracker, which also needs a lookup proof against the tracker's current tree
(not verified whether that is practical). The guard keeps such a reserve out of our
wallet, out of the collateral the tracker reports and out of our builds.

**Switch.** `[server] reserve_reopen_guard` (bool, default `true`; a config without
the key gets `true`). `false` is the round 6f behaviour for new boxes: no 409, no 503 for
the history, no new quarantine. A box the guard already quarantined stays quarantined
(the quarantine is sticky, checked before the root rules); only a release lifts it. The
tracker logs the switch and the number of pairs at start.

**Storage.** Unchanged: no new partition, no new key format. The quarantine records
use the existing partition with a new reason text. Rollback to round 6f: the binary
alone; a box quarantined with this reason stays quarantined there (sticky), and
`POST /reserves/quarantined/release` on 6f releases it as any other.

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
  - `admit_root` — the root rules: C4 checks, singleton, P2PK proof, the per-cycle cap,
    and last the reopen guard (`reopen_verdict`, round 7).
  - `begin_cycle` — per-cycle state, the tracked NFTs, and the order of the checks
    (round 6d); `index_height` — the index lag guard (round 6e).
  - `spent_deep` / `fetch_tx_inclusion_height` — the removal depth (rounds 6d/6e), and
    the depth of a box the index does not know (round 6f); `tracked_all_gone` (round 6f).
  - `p2pk_ergo_tree` / `has_owner_p2pk_input` — the `0008cd || pubkey` proof check.
  - `is_lineage_successor` — the tracked box's spender first, then a bounded backwards
    walk over `/blockchain/transaction/byId` following the reserve NFT (round 6b), with
    the singleton fallback (round 6c).
  - `tracked_nft` / `is_singleton_nft` — the NFT cache and the token index check.
  - `has_owner_root` — the P2PK proof, with the NFT ancestry through top-ups (round 6c).
  - `ingest_scan_box` — parse + admit + track/persist + quarantine persistence.
  - `process_scan_boxes` — removal loop keeps boxes whose proof/lineage check is pending.
- `crates/basis_store/src/persistence.rs` — `QuarantinedReserve`,
  `quarantined_reserves` partition on `ReserveStorage`; `RemovedReserve`,
  `removed_reserves` partition (round 6f).
- `crates/basis_store/src/reopen_guard.rs` — `ReopenGuard`, `ReopenCheck`,
  `RESERVE_REOPEN_BLOCKED` (round 7); `TrackerStateManager::redeemed_reserve_pairs` /
  `attach_reopen_guard` in `crates/basis_store/src/lib.rs` publish the pairs.
- `crates/basis_server/src/api.rs` — `create_reserve_payload`: the 409/503 of the
  reopen guard (round 7); `crates/basis_server/src/main.rs` wires the guard.
- `crates/basis_server/src/reserve_api.rs` — `GET /reserves/quarantined`,
  `POST /reserves/quarantined/release`, `GET /reserves/quarantined/releases`.
- `crates/basis_cli/src/api.rs` — `submit_reserve_to_node` and helpers
  (`select_deployment_boxes`, `deployment_change`, `create_predeployment_utxo`,
  `send_pinned_deployment`) guaranteeing the P2PK proof input at deployment time.
