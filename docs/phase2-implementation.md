# Phase 2 local anchor payload: current implementation

The first Phase 2 implementation adds the protocol payload encoder/decoder and
local journal comparison. It follows the 84-byte payload layout in
[anchoring-protocol.md](anchoring-protocol.md).

## Prepare an unsigned payload

After appending audit events, verify a signed manifest, record the
operator's adoption of that release *bound to the manifest*, then prepare
the payload. The binding is the point of issue #11: an acceptance
carries the manifest hash of the exact signed manifest envelope it
adopts, and anchor creation re-verifies that manifest's signature plus
release identity. An acceptance that matches no verified manifest —
including a well-formed forgery for a release that never existed —
fails closed.

```bash
sealrun audit-verify --journal demo/audit.jsonl
sealrun audit-manifest-accepted \
  --journal demo/audit.jsonl \
  --release-seq 3 \
  --release-id demo-release-003 \
  --manifest demo/manifest-signed.json
sealrun anchor-payload \
  --journal demo/audit.jsonl \
  --start-seq 1 \
  --manifest demo/manifest-signed.json \
  --public-key demo/public.pub \
  --output demo/anchor-payload.json
```

`--manifest` may be repeated to supply several envelopes; `--manifest-hash`
is an alternative to `--manifest` on `audit-manifest-accepted` when only
the hash is at hand. If the journal contains any acceptance,
`anchor-payload` requires the manifests plus the trusted manifest-signing
public key; a journal with no acceptance needs neither and anchors
`release_seq = 0`.

`start-seq` is the first event covered by this interval. The anchored
`release_seq` is **derived from the journal**, not supplied by the caller:
it is `max(release_seq)` over bound `manifest_accepted` events with
`seq <= end_seq`, where `end_seq` is the journal length at anchor time.
A journal with no acceptance anchors `release_seq = 0`, meaning "no
release adopted" (so the very first anchor is still usable). There is no
caller override: any override would let a publisher anchor an arbitrary
checkpoint value, which is the gap this derivation closes (issue #9).
Backfilling an acceptance for an old release and re-anchoring is the
operator's job. For a later anchor, supply the previous confirmed anchor
transaction ID using `--prev-txid`; do not guess or invent a transaction ID.

Legacy acceptances recorded before the binding (detail without
`manifest_hash`) fail closed at anchor time: an unbound acceptance is
structurally identical to the forgery the binding closes. Operators
with pre-binding journals start a fresh journal and re-record bound
acceptances.

The output contains `payload_hex`, an 84-byte payload encoded as hex. This is
only prepared data; it is not a signed transaction, broadcast, or on-chain
proof.

## Trust boundary: what acceptance proves

A bound acceptance proves the adopted release corresponds to a real,
signed manifest with matching release identity (`release_id` /
`release_seq`). It does **not** prove who recorded the acceptance:
anyone with journal write access can still record an acceptance that
references a *real* manifest (for example, re-accepting an older
release). Per-event authorization or signatures on acceptance events
are out of scope (issue #11); the operator's journal write access
remains trusted. Consumers should enforce monotonic release policy
(`--min-release-seq`) at verify time, and auditors can follow any
acceptance's `manifest_hash` back to the exact signed manifest it
adopts.

## Compare a journal with the saved payload

```bash
sealrun anchor-verify \
  --journal demo/audit.jsonl \
  --payload demo/anchor-payload.json
```

This verifies the local journal hash chain and compares the event hash at the
anchored end sequence. It detects a missing or shortened journal and changed
history. It does not prove that the payload ever appeared on BSV, authenticate
the transaction input, verify SPV/Merkle inclusion, or independently establish
that the payload came from a trusted anchor. Validating a *sequence* of anchors
as one continuous chain is a separate check — see "Anchor-chain continuity
(issue #8)" below.

To also re-check acceptance binding on verify, supply the same inputs
the anchor was created with:

```bash
sealrun anchor-verify \
  --journal demo/audit.jsonl \
  --payload demo/anchor-payload.json \
  --manifest demo/manifest-signed.json \
  --public-key demo/public.pub
```

With `--manifest` + `--public-key`, verification re-derives the anchored
`release_seq` from bound acceptances and requires it to equal the
payload's checkpoint. Without them, only the head-hash check runs and
the payload's checkpoint is returned as committed, without re-derivation.

## Anchor-chain continuity (issue #8)

`sealrun.anchor.verify_anchor_chain(anchors, genesis_txid)` enforces that a
sequence of anchors forms one continuous, fork-free chain. Each anchor is a
`{"payload": bytes, "txid": str}` entry (or `payload_hex`, or a
`(payload, txid)` tuple); publisher anchor records pass through directly.
Order matters — a reordered list is rejected, not silently re-sorted.

Enforced, fail-closed:

- First anchor's `prev_txid` equals the trusted genesis. An anchor with an
  arbitrary well-formed `prev_txid` — previously accepted by single-anchor
  verification — is rejected.
- First anchor's `start_seq` is 1 (protocol §3: the genesis anchor starts
  at sequence 1).
- Each later anchor's `prev_txid` equals the previous anchor's txid, and its
  `start_seq` equals the previous anchor's `end_seq + 1` (no skipped
  anchors, no gaps, no overlaps).
- No duplicated txid, no duplicated payload.
- No fork: no two anchors build on the same predecessor (no `prev_txid`
  appears twice), including two anchors both claiming genesis. A fork is
  reported as an error, never silently accepted.

`verify_journal_against_anchor_chain(journal, anchors, genesis_txid, ...)`
runs the chain check first, then verifies the journal against *every*
anchor's payload (head hash at its `end_seq`, plus binding re-derivation
when manifests + public key are supplied). The chain check runs first on
purpose: anchors that each match the journal individually can still form
a broken chain, and that must fail verification.

```bash
# Chain-only check: anchor JSON files carry payload_hex + txid, in chain order.
sealrun anchor-chain-verify --genesis-txid <pinned-genesis> \
  --anchor demo/anchor-1.json --anchor demo/anchor-2.json

# Full check: journal against every anchor in the chain.
sealrun anchor-chain-verify --genesis-txid <pinned-genesis> \
  --journal demo/audit.jsonl \
  --anchor demo/anchor-1.json --anchor demo/anchor-2.json

# Check a publisher store's broadcast records (pending/superseded
# drafts are not chain members).
sealrun anchor-chain-verify --genesis-txid <pinned-genesis> \
  --anchor-record demo/anchors.json
```

### Genesis trust assumption

The genesis txid comes from **operator-pinned config, distributed
out-of-band** (same channel as the manifest signing public key), and is
never inferred from the anchor set: passing the txid of an anchor in the
set as genesis is rejected, and a missing genesis fails closed. The zero
txid is a valid pinned genesis meaning "no genesis anchor yet" — the
first anchor's `prev_txid` must then be zeros. The publisher records the
genesis its store was created with and refuses to run under a different
one; on every store load it also re-validates that its broadcast
records form a continuous chain from that genesis, so a tampered store
(refuses every publisher operation) can never seed a new anchor on top
of a broken chain.

### What this does not prove

Continuity is about the *claimed* chain: it proves the anchors link
together from a trusted genesis with no gaps or forks. It does **not**
prove any anchor is really on-chain — Merkle-proof / header-chain /
confirmation (SPV) verification is still out of scope, and
`chain_inclusion_verified` remains `False`.

## Remaining implementation work

1. Add transaction construction, signing, fee funding, broadcast, and retry
   behavior behind a clearly configured publisher adapter.
2. Add independent transaction retrieval and block-header/Merkle proof
   verification, with anchor input signature checks.
3. Validate the complete chain from a separately distributed genesis txid:
   no sequence gaps, overlaps, or unapproved forks. — Done via
   `verify_anchor_chain` (issue #8); see "Anchor-chain continuity" above.
4. Persist and compare the highest anchored release sequence against a trusted
   manifest policy.
5. Add integration tests against a test environment before any mainnet use.

Never put event details, prompts, model bytes, secrets, or private keys on-chain.

## Publisher: anchor-on-release + scheduled checkpoints

`sealrun.publisher.Publisher` turns the design above into running code.
Broadcast stays **disabled by default** and no real broadcaster exists in
this build: the publisher prepares anchor payloads and records them
locally. Nothing is signed, spent, or sent to any network unless the
operator explicitly enables broadcast *and* supplies a broadcaster.

```bash
# One scheduler tick (dry-run): anchor if a release landed or the interval elapsed.
sealrun publish --journal demo/audit.jsonl --anchor-record demo/anchors.json

# Anchor immediately after recording an acceptance.
sealrun publish --journal demo/audit.jsonl --anchor-record demo/anchors.json \
  --mode on-release --manifest demo/manifest-signed.json --public-key demo/public.pub

# Long-running loop: re-reads the manifests directory at every checkpoint.
sealrun publish --journal demo/audit.jsonl --anchor-record demo/anchors.json \
  --mode loop --interval-seconds 3600 \
  --manifest-dir demo/manifests --public-key demo/public.pub
```

`--broadcast` is an explicit opt-in that fails closed: no broadcast
adapter exists in this build, so requesting it without a broadcaster is
refused rather than silently dropped.

### Triggers

- **Anchor-on-release.** A new `manifest_accepted` event since the last
  anchor triggers a checkpoint immediately (via `on_release_accepted()` or
  the scheduler). This is the practical version of "publish journal heads
  where the writer cannot rewrite them": the window in which a release
  acceptance sits unanchored shrinks to the time needed to build the
  payload.
- **Scheduled checkpoints.** When the configured interval (default 3600s)
  elapses since the last anchor, the current head is anchored even with
  no new release, closing the unanchored-tail window between releases.

Deliberate deviation from `anchoring-protocol.md` §8: that section
suggests an every-N-events trigger. The publisher uses release +
time triggers instead — a release acceptance is the event that matters
for the rollback checkpoint, and the time trigger covers event-only
tails. An N-events trigger adds anchor spam without closing a distinct
window.

### Anchor record store

Emitted anchors persist in the `--anchor-record` JSON file (payload +
txid slot + status), written atomically, so a later run resumes from
the last anchor instead of re-anchoring the same range:

- `pending` — payload prepared, not broadcast (the default state).
- `broadcast` — submitted via a broadcaster, txid recorded. Inclusion
  is still **confirmed-unknown**: no SPV/Merkle verifier exists yet,
  so the store never claims `confirmed`.
- `superseded` — a prepared anchor for an older head, replaced when
  the head advanced before anything was broadcast. It stays in the
  store for audit; it anchors nothing on-chain.

### Chaining

`prev_txid` chains to the last **broadcast** anchor's txid, or the
configured genesis txid when nothing has been broadcast yet. A merely
prepared anchor has no txid, so the next anchor still chains to the
last broadcast anchor (or genesis) and covers the full range from there.
The store records the genesis it was created with; running under a
different genesis fails closed (genesis mismatch).

### Fail-closed behavior

The publisher refuses to anchor when the journal fails verification,
when acceptance binding fails (acceptances present but no verified
manifests / trusted public key), when the journal is missing or
malformed, or on genesis mismatch. A journal truncated below the last
broadcast anchor is refused (the next `start_seq` would fall outside
the journal). It never anchors a checkpoint it cannot verify locally.

Broadcast failure is best-effort, per the protocol doc: the anchor is
already saved as `pending`, the scheduler reports the failure in its
decision and retries the *same* record on the next tick — it never
emits a duplicate anchor and never dies on chain unavailability.
Journal/binding failures, by contrast, always raise: a broken journal
must never be silently skipped.

### Manifests for binding checks

`--manifest` supplies fixed envelopes; `--manifest-dir` is re-read at
every checkpoint, so a long-running publisher picks up envelopes for
acceptances that land after startup. A missing directory contributes
zero envelopes (binding still fails closed once an acceptance exists);
a path that exists but is not a directory is a misconfiguration.

### What remains

- Real broadcast: transaction construction, signing, fee funding, and a
  `PublisherAdapter`-based broadcaster behind the explicit opt-in, plus
  tBSV to fund a testnet anchor (both known testnet faucets were dead
  at last check — no funding is attempted by this code).
- SPV verification: Merkle-proof / header-chain / confirmation checks
  before any anchor may be reported `confirmed`.
- The highest anchored `release_seq` is recorded per anchor but not yet
  persisted as a durable rollback checkpoint compared against a trusted
  manifest policy at verify time.
