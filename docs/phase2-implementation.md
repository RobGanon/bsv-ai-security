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
aiguard audit-verify --journal demo/audit.jsonl
aiguard audit-manifest-accepted \
  --journal demo/audit.jsonl \
  --release-seq 3 \
  --release-id demo-release-003 \
  --manifest demo/manifest-signed.json
aiguard anchor-payload \
  --journal demo/audit.jsonl \
  --start-seq 1 \
  --manifest demo/manifest-signed.json \
  --public-key demo/public.pem \
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
aiguard anchor-verify \
  --journal demo/audit.jsonl \
  --payload demo/anchor-payload.json
```

This verifies the local journal hash chain and compares the event hash at the
anchored end sequence. It detects a missing or shortened journal and changed
history. It does not prove that the payload ever appeared on BSV, authenticate
the transaction input, verify SPV/Merkle inclusion, validate the full anchor
chain, or independently establish that the payload came from a trusted anchor.

To also re-check acceptance binding on verify, supply the same inputs
the anchor was created with:

```bash
aiguard anchor-verify \
  --journal demo/audit.jsonl \
  --payload demo/anchor-payload.json \
  --manifest demo/manifest-signed.json \
  --public-key demo/public.pem
```

With `--manifest` + `--public-key`, verification re-derives the anchored
`release_seq` from bound acceptances and requires it to equal the
payload's checkpoint. Without them, only the head-hash check runs and
the payload's checkpoint is returned as committed, without re-derivation.

## Remaining implementation work

1. Add transaction construction, signing, fee funding, broadcast, and retry
   behavior behind a clearly configured publisher adapter.
2. Add independent transaction retrieval and block-header/Merkle proof
   verification, with anchor input signature checks.
3. Validate the complete chain from a separately distributed genesis txid:
   no sequence gaps, overlaps, or unapproved forks.
4. Persist and compare the highest anchored release sequence against a trusted
   manifest policy.
5. Add integration tests against a test environment before any mainnet use.

Never put event details, prompts, model bytes, secrets, or private keys on-chain.
