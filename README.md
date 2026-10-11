# BSV AI Security

**Verifiable AI operations, anchored to Bitcoin SV.**

AI systems run as black boxes: you cannot prove *which* model and
configuration produced an output, or that the audit log describing it was
not rewritten afterwards. This project fixes that in two layers:

1. **Local trust core** (working, tested): signed manifests pin the exact
   approved model and config bytes; verification runs against the signature
   before launch; every security event goes into a hash-chained audit
   journal. Rollback protection via monotonic release sequences, and a
   TOCTOU-resistant API that hands the launcher open, verified file
   descriptors instead of paths.
2. **BSV anchoring** ([design](docs/anchoring-protocol.md)): journal heads
   and rollback checkpoints are committed on-chain, so anyone holding the
   journal, the anchor transactions, and block headers can independently
   verify history was never rewritten — even against the local
   administrator.

Honest scope: this does not stop a compromised administrator in real time,
and anchoring proves *when* a log entry was committed, never that the entry
was true. See [Security boundaries](#security-boundaries) and the
[anchoring protocol](docs/anchoring-protocol.md) for the explicit claims.

Contributions welcome — especially security review. If you find something,
open an issue.

---

## Phase 1: Linux trust core (v0.3.0)

This prototype verifies a signed manifest of local AI artifacts and records local
security events in a hash-chained JSONL audit journal. It is intentionally
blockchain-independent: no BSV transaction is submitted in Phase 1.

## Security boundaries

- SHA-256 identifies artifact bytes; Ed25519 verifies the release manifest.
- The private signing key is for development/demo only. Keep production signing
  keys outside the AI runtime and preferably in hardware-backed/OS-managed storage.
- The audit chain detects edits to the journal when checked against a trusted
  checkpoint. A local administrator can rewrite both the journal and checkpoint;
  this prototype does not defeat a fully compromised host.
- The manifest verifier does not itself sandbox or launch a model. Do not use
  it as a complete security boundary until a separate, least-privilege launcher
  is implemented and tested.
- The manifest uses relative artifact paths and rejects path traversal/symlinks.

## Install

Python 3.10+ recommended.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[test]'
```

## Create a demo workspace and signing key

From this directory:

```bash
mkdir -p demo/artifacts
printf 'demo model bytes - not a real model\n' > demo/artifacts/model.bin
printf '{"temperature":0}\n' > demo/artifacts/config.json

# Generate a development signing key and public key.
aiguard keygen --private-key demo/dev-signing-key.pem --public-key demo/trusted-release-key.pem

# Create an unsigned manifest template, then sign it.
aiguard manifest-create \
  --root demo \
  --artifact artifacts/model.bin \
  --artifact artifacts/config.json \
  --release-seq 1 \
  --output demo/manifest.json

aiguard manifest-sign \
  --manifest demo/manifest.json \
  --private-key demo/dev-signing-key.pem \
  --output demo/manifest.signed.json

aiguard verify \
  --root demo \
  --manifest demo/manifest.signed.json \
  --public-key demo/trusted-release-key.pem

# Optional rollback protection: reject any manifest older than sequence 1.
# Persist the highest sequence you have accepted (in protected storage, or
# anchored externally later) and pass it here on every verification.
aiguard verify \
  --root demo \
  --manifest demo/manifest.signed.json \
  --public-key demo/trusted-release-key.pem \
  --min-release-seq 1
```

**Important:** this demo keeps the private key beside the demo data for convenience.
For a real deployment, create the signing key on a separate trusted machine or
hardware token, do not give it to the AI process, and distribute the public key
through a separately authenticated channel.

## Audit journal

```bash
aiguard audit-append --journal demo/audit.jsonl --event-type "verification" --detail "demo check"
aiguard audit-verify --journal demo/audit.jsonl
```

The journal is hash-chained but not protected against an administrator who can
rewrite the entire file. In a later phase, anchor periodic roots externally (for
example, on BSV) and retain inclusion proofs/checkpoints separately.

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
  "created_utc": "2026-01-01T00:00:00Z",
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
minimum comes from — is yours: persist the highest sequence you have ever
accepted in protected storage (a local file the AI process cannot write, or
an external anchor later), and pass it on every verification.

## TOCTOU-resistant verification for launchers

`aiguard verify` hashes files and returns, which leaves a window between the
check and a later use of the paths. Programmatic consumers that need the
verified bytes themselves (the future launcher) should use
`aiguard.core.verified_artifacts()` instead: it opens each artifact with
`O_NOFOLLOW`, confirms a regular file via `fstat()`, hashes from the open
descriptor, and yields handles positioned at offset 0. Bytes read from those
handles are exactly the verified bytes. Handles are closed automatically when
the context exits.

## Phase 2 design: BSV anchoring

`docs/anchoring-protocol.md` specifies how the audit journal and rollback
checkpoint get anchored to BSV for independent verifiability — including the
exact 84-byte OP_RETURN payload layout, the on-chain anchor chaining via
`prev_txid`, the independent verifier procedure, and an explicit list of
what anchoring does and does not prove. It is written directly against the
three weaknesses found in the Phase 1 review (journal truncation, journal
deletion, checkpoint rewind).

## Current limitations / next steps

1. Add a separately privileged policy enforcement gateway.
2. Add container/VM launch profiles with no host mounts except explicitly allowed
   read-only model files, no network by default, non-root UID, dropped capabilities,
   read-only root filesystem, resource limits, and default seccomp/AppArmor.
   The launcher should consume `verified_artifacts()` handles (or fexecve) so
   verification and execution are a single atomic step.
3. Persist the rollback checkpoint durably: anchor the highest accepted
   `release_seq` (and audit roots) externally, e.g. on BSV, so a local
   administrator cannot roll the checkpoint back either.
4. Implement the BSV publisher adapter and verifier from
   `docs/anchoring-protocol.md` (payload layout and verification procedure
   specified; needs a BSV library + node/mAPI access). Never put prompts,
   secrets, raw logs, or private keys on-chain.
5. Migrate manifest signing from Ed25519 to secp256k1 (recommended before
   anchoring implementation, so the system uses one signature scheme).
6. Add key rotation/revocation and a signed policy update workflow.
