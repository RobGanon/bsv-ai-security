# BSV AI Security

**Prove what your AI actually ran.**

AI systems run as black boxes: you cannot prove *which* model and
configuration produced an output, or that the audit log describing it was
not rewritten afterwards. When an auditor, a regulator, or a customer
asks "show me exactly what ran," most teams have only their word.

This project gives you the evidence.

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

Status: 191 tests passing on main, plus adversarial spot-checks on
every feature. Independent security review is still open
([issue #4](https://github.com/RobGanon/bsv-ai-security/issues/4)) —
we state that plainly because it matters.

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

The current anchor backend is Bitcoin SV, chosen for cost and
cadence: anchors are small and frequent (on release acceptance
plus scheduled checkpoints), and BSV's low fees and native
on-chain data make that practical. Verification is SPV-style —
verifiers check headers, not a full node.

Honest tradeoff: Bitcoin has substantially deeper proof-of-work
security. BSV's case is cost, frequency, and data fit, not
maximum settlement depth.

**Current status:** the publisher prepares checkpoints, but
broadcast is still a stub — no anchor has been confirmed on-chain
yet. The tagline says "anchoring to," not "anchored to," until
the first real anchor confirms.

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

## Phase 1: Linux trust core (v0.3.0)

This prototype verifies a signed manifest of local AI artifacts and records local
security events in a hash-chained JSONL audit journal. It is intentionally
limited in scope:

- SHA-256 identifies artifact bytes; Ed25519 verifies the release manifest.
- The audit journal is append-only under normal operation and hash-chained so
  that any modification of earlier events is detectable.
- The manifest verifier does not itself sandbox or launch a model. Do not use
  this as a complete AI runtime security solution.
- The manifest uses relative artifact paths and rejects path traversal/symlinks.

### Quick start

```bash
pip install -e .
# or: pip install cryptography

# Generate a key pair (demo only — production keys must be offline / HSM).
aiguard keygen --private demo/private.pem --public demo/public.pem

# Create an unsigned manifest template, then sign it.
aiguard manifest-create \
  --root demo/artifacts \
  --paths model.bin config.json \
  --release-id demo-release-001 \
  --release-seq 1 \
  --output demo/manifest.json

aiguard manifest-sign \
  --manifest demo/manifest.json \
  --private demo/private.pem \
  --output demo/manifest.signed.json

# Verify (paths relative to --root).
aiguard verify \
  --root demo/artifacts \
  --manifest demo/manifest.signed.json \
  --public demo/public.pem

# Optional rollback protection: reject any manifest older than sequence 1.
aiguard verify \
  --root demo/artifacts \
  --manifest demo/manifest.signed.json \
  --public demo/public.pem \
  --min-release-seq 1
```

## Audit journal

```bash
aiguard audit-append --journal demo/audit.jsonl --event-type "verification" --detail "demo check"
aiguard audit-verify --journal demo/audit.jsonl
```

The journal is hash-chained but not protected against an administrator who can
rewrite the entire file. In a later phase, anchor periodic roots externally (for
example, on BSV) and retain inclusion proofs/checkpoints separately.

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

## Manifest format

The signed payload is canonical JSON (UTF-8, sorted keys, compact separators).
The signature is Ed25519 over the exact canonical payload bytes, encoded as
base64. Example:

```json
{
  "schema": "aiguard-manifest-v1",
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
  "signature": "BASE64_ED25519_SIGNATURE"
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
integrating system (and later to on-chain anchors).

## Phase 2 design: BSV anchoring

`docs/anchoring-protocol.md` specifies how the audit journal and rollback
checkpoint get anchored to BSV for independent verifiability — including the
exact 84-byte OP_RETURN payload layout, the on-chain anchor chaining via
`prev_txid`, the independent verifier procedure, and an explicit list of
what anchoring does and does not prove.

## Pilot program

We are looking for one AI team to run a 30-day pilot on one real
pipeline. Details: [`docs/pilot-brief.md`](docs/pilot-brief.md).

## Roadmap (high level)

1. Independent review of Phase 1 (this request).
2. Implement Phase 2 payload creation + local verification (in progress).
3. Implement publishing interfaces with explicit network selection
   (testnet default; mainnet behind separate confirmation).
4. Independent SPV / header-chain verification.
5. Migrate manifest signing from Ed25519 to secp256k1 (recommended before
   production).
6. Privileged launcher that consumes verified artifact handles.

## License

MIT
