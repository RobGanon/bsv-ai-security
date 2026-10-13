# Phase 2 local anchor payload: current implementation

The first Phase 2 implementation adds the protocol payload encoder/decoder and
local journal comparison. It follows the 84-byte payload layout in
[anchoring-protocol.md](anchoring-protocol.md).

## Prepare an unsigned payload

After appending audit events, record the operator's adoption of a release,
then prepare the payload:

```bash
aiguard audit-verify --journal demo/audit.jsonl
aiguard audit-manifest-accepted \
  --journal demo/audit.jsonl \
  --release-seq 3 \
  --release-id demo-release-003
aiguard anchor-payload \
  --journal demo/audit.jsonl \
  --start-seq 1 \
  --output demo/anchor-payload.json
```

`start-seq` is the first event covered by this interval. The anchored
`release_seq` is **derived from the journal**, not supplied by the caller:
it is `max(release_seq)` over `manifest_accepted` events with
`seq <= end_seq`, where `end_seq` is the journal length at anchor time.
A journal with no acceptance anchors `release_seq = 0`, meaning "no
release adopted" (so the very first anchor is still usable). There is no
caller override: any override would let a publisher anchor an arbitrary
checkpoint value, which is the gap this derivation closes (issue #9).
Backfilling an acceptance for an old release and re-anchoring is the
operator's job. For a later anchor, supply the previous confirmed anchor
transaction ID using `--prev-txid`; do not guess or invent a transaction ID.

The output contains `payload_hex`, an 84-byte payload encoded as hex. This is
only prepared data; it is not a signed transaction, broadcast, or on-chain
proof.

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
