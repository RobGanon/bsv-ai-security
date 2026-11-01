# BSV AI Security

**Prove what your AI actually ran.**

> Note: the package and CLI were formerly named `aiguard`; renamed to
> `sealrun` on 2026-10-19 to avoid a collision with an unrelated product
> of the same name. The on-chain `AIGUARD1` payload magic is retained
> for anchor-chain continuity.

AI systems run as black boxes: you cannot prove *which* model and
configuration produced an output, or that the audit log describing it was
not rewritten afterwards. When an auditor, a regulator, or a customer
asks "show me exactly what ran," most teams have only their word.

This project gives you the evidence.

> **For the non-technical reader.** Think of it as a tamper-proof logbook
> for your AI. Before a model runs, the tool records a fingerprint of
> everything about to be used — which model, which data, which settings.
> After it runs, every security event goes into a chained record, where
> editing any earlier entry breaks the chain for everything after it. If
> an auditor or regulator ever asks "prove this is what ran," you show
> them the logbook. And if you anchor the fingerprints to a public
> ledger, even the logbook itself can never be quietly rewritten.

## See it work in 2 minutes

SealRun proves what your AI actually ran — not whether it behaved well,
and not whether its outputs were true. Try it, then try breaking it:

1. Clone the repo and `pip install -e .` (no PyPI package or one-command
   install yet — stated, not hidden).
2. Follow the worked example in
   [`docs/using-sealrun.md`](docs/using-sealrun.md): `sealrun keygen`,
   `manifest-create`, `manifest-sign`, `verify`, `launch`.
3. Break it: change `temperature` 0.2 → 0.9 in config.json and launch
   again → `ERROR: artifact integrity mismatch: config.json`, exit code
   1, the AI never starts. Then edit one word in `state/audit.jsonl`
   and run `sealrun audit-verify` →
   `ERROR: audit event hash mismatch at sequence 2`.

That is the whole claim, shown rather than asserted: a changed file stops
the run, and edited history is detectable.

## Who this is for, and who should wait

- For: AI/ML and DevOps teams who get asked "prove what ran," plus
  auditors, regulators, and customers who need checkable evidence rather
  than a team's word.
- Maintained by: Rob Ganon.
- Wait if: you need an independently reviewed, beta-or-better tool today.
  This is a research preview, not beta, not 1.0, not independently
  reviewed, and mainnet anchoring is gated.
- When: no beta/1.0 date is promised.
- Where it runs / where evidence lives: Linux, on the machine running
  the AI, stdlib-only offline core; manifest and journal are files you
  hold locally; anchors (when used) are public on Teratestnet. A public
  anchor is a checkpoint outside the machine's reach: even if someone
  with full access rewrites the whole local journal, it will no longer
  match the anchored fingerprint. Anchoring adds proof that holds up
  against your own administrators, without publishing your data: only
  hashes and sequence numbers go on-chain, never event contents, prompts,
  model data, or keys — though anchor timing does reveal when you anchor.
- Where to get help: public GitHub issues for general feedback; private
  vulnerability reporting only for security findings, under the standard
  model adopted Oct 31. There is no community channel or forum — stated,
  not implied.
- Where it does not reach: closed cloud agents or vendor infrastructure
  you do not control; verification on an already-compromised host proves
  nothing.

## Why use this

- **Prove what ran, not what was supposed to run.** A signed manifest
  pins the exact model, code, data, and config bytes for a release.
  Verification checks the signature *before* launch, so a swapped,
  stale, or tampered artifact fails instead of running.
- **A tamper-evident record of what happened.** Every security event
  goes into a hash-chained audit journal. Editing an earlier entry
  breaks the chain, so rewriting history is detectable.
- **Rollback protection.** Monotonic release sequences reject
  older legitimately-signed releases, so a system cannot be quietly
  rolled back to a vulnerable version.
- **Evidence your auditors already ask for.** The journal and
  manifests map directly onto what compliance requires: logging of
  AI system activity (EU AI Act), change and access evidence
  (SOC 2), and a reproducible record for incident forensics.
- **No blockchain required to start.** The local trust core works
  with zero blockchain. Anchoring (below) is an optional upgrade
  for when you need proof that holds up against your own
  administrators — not a prerequisite for using the tool.

**What this is not.** It does not solve prompt injection, model
safety, data poisoning, adversarial ML, or privacy. It does not
prove that recorded events are truthful or complete — only that
they have not been altered after recording. It is the provenance
pillar of AI security: proving what ran, not whether the model
behaved well.

Status: test suite passing on main (see
[`REVIEW.md`](REVIEW.md) for the current count and evidence), plus
adversarial spot-checks on every feature. Independent security review
is still open
([issue #4](https://github.com/RobGanon/bsv-ai-security/issues/4)) —
we state that plainly because it matters.

New to the tool? [`docs/using-sealrun.md`](docs/using-sealrun.md)
walks the full flow — manifest, sign, launch, journal, proof — with
a worked example you can run in about ten minutes.

## What it saves you in money

No quantified case study exists yet — we will not invent savings
percentages. The mechanisms:

- **Audit and compliance preparation.** Evidence is preassembled
  (signed manifests + chained journal) instead of reconstructed
  after the fact.
- **Incident forensics.** Identify exactly which release produced
  an output, instead of guessing across deployments.
- **Prevented bad runs.** A wrong, stale, or tampered artifact is
  caught before launch, not after it burns a training or
  deployment run.
- **Reproduce instead of retrain.** Hashes identify exactly what
  changed, so unchanged inputs are not retrained.
- **Scoped legal retraining.** If data is disputed, retraining is
  limited to the runs that actually used it.
- **Cheaper disputes.** Independently checkable evidence replaces
  "trust us."

Next step: a pilot with one AI team measuring audit-prep hours
before and after adoption.

## How anchoring works

The local journal proves *order* and detects tampering — but an
administrator with full access could rewrite the whole journal
from scratch. Anchoring closes that hole: periodic journal heads
and rollback checkpoints are committed to a public blockchain,
so anyone holding the journal, the anchor transactions, and block
headers can verify history was never rewritten, even against the
local administrator.

The current anchor backend is BSV, chosen for cost and cadence:
anchors are small and frequent (on release acceptance plus
scheduled checkpoints), and BSV's low fees and native on-chain
data make that practical. Verification is SPV-style — verifiers
check headers, not a full node.

The anchor chain runs on Teratestnet, BSV's test network, using
SPV plus the WhatsOnChain testnet API. SealRun does not run a node
and does not run Teranode; BSV scaling is powered by Teranode.

Honest tradeoff, both ways: BTC has substantially deeper
proof-of-work security today. BSV's case is cost, frequency, and
data fit, not maximum settlement depth. That tradeoff could change
over time: BSV's mechanism is utility driving demand, demand
driving miner revenue, and miner revenue driving hashpower — a
mechanism, not a prediction that BSV overtakes BTC.

Why BSV fits this project, in engineering terms: the original
Bitcoin design was a peer-to-peer electronic cash system, with
payments made directly between parties without a financial
institution. BSV's goal aligns with that payment-system goal. The
project uses BSV for that reason — frequent, cheap,
data-carrying anchors — not as a claim about which chain "is"
Bitcoin.

Anchoring proves history integrity and existence, not
truthfulness or completeness of the journal.

**Current status:** the publisher and broadcaster are live on
Teratestnet. Three anchors are confirmed on-chain: anchor #1
(`4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029`,
block 36722), anchor #2
(`d8407bb7a60f23aadcf021e9cb0098c6ae362a519aa04cbd8536265519c09230`,
block 36723), and anchor #3
(`e3a95a6f1f65651949f8fc6ef1ce22292058502cc6a94aef0fb6a5143ffd28cb`,
block 37163) — anchor #3 was signed by a human through the
offline-signing ceremony below, not by the publisher. See
`docs/anchoring-protocol.md` for the verifier
procedure and what anchoring does and does not prove. Anchor signing
goes through the offline-signing ceremony — the publisher exports an
unsigned tx, a human-side signer signs it, and the publisher verifies
and broadcasts it — documented in
`docs/offline-signing-handoff.md`.

## Training-data provenance

The same mechanism works for training data: record a signed
dataset manifest *before* training, and the manifest + journal +
anchor prove what was in the training set and when it was
recorded. A creator can likewise hash and timestamp their work
before it is ever used.

Hard limits: this proves what was recorded. It does not stop
scraping, enforce consent or licenses, or prove an omitted item
was not secretly used. It helps parties who adopt it *before*
the dispute — it cannot retroactively prove an unrecorded run.

## What makes this different

Hash-chained logs, signed artifacts, and timestamping all have
real precedents — Sigstore/Rekor, in-toto/SLSA, OpenTimestamps,
Certificate Transparency, CloudTrail, systemd journal sealing.
No single product combines all of this specifically for AI
operations: signed manifests pinning model, code, data, and
config bytes; TOCTOU-resistant verified file-descriptor handoff;
journal-derived rollback protection; manifest-bound acceptance;
and chain-continuous anchors.

Contributions welcome — especially security review. If you find something,
open an issue.

---

## Phase 1: Linux trust core (v0.4.0)

This prototype verifies a signed manifest of local AI artifacts and records local
security events in a hash-chained JSONL audit journal. It is intentionally
limited in scope:

- SHA-256 identifies artifact bytes; secp256k1 ECDSA verifies the release manifest.
- The audit journal is append-only under normal operation and hash-chained so
  that any modification of earlier events is detectable.
- The manifest verifier does not itself sandbox a model. `sealrun launch`
  pins the verified bytes across exec, but containment is out of scope.
- The manifest uses relative artifact paths and rejects path traversal/symlinks.

### Quick start

```bash
pip install -e .

# Generate a key pair (demo only — production keys must be offline / HSM).
sealrun keygen --private-key demo/private.wif --public-key demo/public.pub

# Create an unsigned manifest template, then sign it.
sealrun manifest-create \
  --root demo/artifacts \
  --artifact model.bin --artifact config.json \
  --release-id demo-release-001 \
  --release-seq 1 \
  --output demo/manifest.json

sealrun manifest-sign \
  --manifest demo/manifest.json \
  --private-key demo/private.wif \
  --output demo/manifest.signed.json

# Verify (paths relative to --root).
sealrun verify \
  --root demo/artifacts \
  --manifest demo/manifest.signed.json \
  --public-key demo/public.pub

# Optional rollback protection: reject any manifest older than sequence 1.
sealrun verify \
  --root demo/artifacts \
  --manifest demo/manifest.signed.json \
  --public-key demo/public.pub \
  --min-release-seq 1

# Launch against the verified handles instead of reopening paths.
sealrun launch \
  --root demo/artifacts \
  --manifest demo/manifest.signed.json \
  --public-key demo/public.pub \
  -- /bin/sh -c 'cat "$SEALRUN_ARTIFACT_MODEL_BIN"'
```

## Launching with verified handles

`sealrun verify` proves the manifest, then exits — a caller that launches
the model *by path* reopens the artifacts, leaving a window for a path
swap between check and use. `sealrun launch` closes that window: it runs
the same verification, keeps the verified descriptors open, and hands
them to the command via `SEALRUN_ARTIFACT_*` environment variables
pointing at `/proc/self/fd/N`.

- `--seal` copies each artifact into a sealed `memfd` first, so the child
  reads a frozen snapshot even if a writer mutates the original (costs a
  copy in RAM; opt-in).
- `--uid`/`--gid` drop privilege before exec, so a launcher started as
  root can make the model run unprivileged. If the drop is not permitted
  the command does not run; `--uid` alone uses the target user's primary
  group and supplementary groups are cleared.
- The launcher pins *what bytes are launched*; it does not sandbox the
  child. See [`docs/launcher.md`](docs/launcher.md) for the contract and
  the residual limits.

## Audit journal

```bash
sealrun audit-append --journal demo/audit.jsonl --event-type "verification" --detail "demo check"
sealrun audit-verify --journal demo/audit.jsonl
```

The journal is hash-chained but not protected against an administrator who can
rewrite the entire file. Anchor periodic roots externally (on BSV) and retain
inclusion proofs/checkpoints separately — see "How anchoring works" above and
`docs/anchoring-protocol.md`.

On Unix platforms the append path takes an exclusive advisory lock
(`fcntl.flock`) across the verify-then-write critical section. Concurrent
writers are serialised; platforms without `fcntl` fall back to the
single-writer assumption.

Event `detail` is limited to 4096 UTF-8 bytes and the journal is limited to
1 000 000 events. Exceeding either limit raises `VerificationError`.
All stored hashes are normalised to lowercase; mixed-case input is accepted
and compared case-insensitively.

## Tests

```bash
pytest -q
```

Tests are not claimed to have passed until you run them in your environment.
Reviewing? See `docs/reviewer-brief.md` for a 15-minute orientation and
`docs/reviewer-quickstart.md` for the 5-minute path.

## Manifest format

The signed payload is canonical JSON (UTF-8, sorted keys, compact separators).
The signature is deterministic secp256k1 ECDSA (RFC 6979, low-S normalized,
DER-encoded) over SHA-256 of the exact canonical payload bytes, encoded as
base64. Example:

```json
{
  "schema": "sealrun-manifest-v1",
  "release_id": "demo-release-001",
  "release_seq": 1,
  "artifacts": [
    {
      "path": "artifacts/model.bin",
      "sha256": "REPLACE_WITH_64_HEX_CHARACTERS",
      "size": 123
    }
  ]
}
```

The signed envelope generated by `manifest-sign` looks like:

```json
{
  "payload": { "...": "..." },
  "signature": "BASE64_DER_SIGNATURE"
}
```

The trusted public key is supplied out of band. A public key shipped alongside an
untrusted manifest is not a trust anchor.

## Rollback protection

Each manifest carries a monotonic `release_seq` integer inside the signed
payload. `verify --min-release-seq N` rejects any manifest older than N,
which defeats rollback attacks (an older legitimately-signed manifest
verifying cleanly). The mechanism is implemented; the *policy* — where the
caller obtains and stores the highest accepted sequence — is left to the
integrating system (on-chain anchors checkpoint it; see
`docs/anchoring-protocol.md`).

## Phase 2: BSV anchoring (implemented)

`docs/anchoring-protocol.md` specifies how the audit journal and rollback
checkpoint get anchored to BSV for independent verifiability — including the
exact 84-byte OP_RETURN payload layout, the on-chain anchor chaining via
`prev_txid`, the independent verifier procedure, and an explicit list of
what anchoring does and does not prove. The publisher, broadcaster, and
verifiers (SPV inclusion, BUMP, BEEF, header-chain, anchor-input
signatures) are implemented and tested.

## Pilot program

We are looking for one AI team to run a 30-day pilot on one real
pipeline. Details: [`docs/pilot-brief.md`](docs/pilot-brief.md).

## Roadmap (high level)

1. Independent review of Phase 1 (in progress — see `REVIEW.md`).
2. ~~Implement Phase 2 payload creation + local verification~~ — done.
3. ~~Implement publishing interfaces with explicit network selection
   (testnet default; mainnet behind separate confirmation)~~ — done.
4. ~~Independent SPV / header-chain verification~~ — done.
5. ~~Migrate manifest signing from Ed25519 to secp256k1~~ — done.
6. ~~Privileged launcher that consumes verified artifact handles~~ — done
   (`sealrun launch`; see `docs/launcher.md`).

## License

MIT
