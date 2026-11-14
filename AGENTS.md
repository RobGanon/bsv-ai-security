# AGENTS.md — SealRun

SealRun verifies an AI run before it starts and proves it afterwards: a signed manifest pins the exact model, code, data, and config bytes; verification checks the signature before launch; every security event goes into a hash-chained audit journal. Optional anchoring on BSV (testnet) adds a checkpoint outside the machine's reach.

## Status (read first)

Research preview, not beta, not 1.0. The v2 launch flow hasn't had an independent review yet, and mainnet anchoring is gated. No beta/1.0 date is promised.

## Install

```bash
git clone https://github.com/RobGanon/bsv-ai-security.git
cd bsv-ai-security
pip install -e .
```

No PyPI package yet. Python >= 3.10, zero dependencies (stdlib only). Linux.

## The flow (worked example: docs/using-sealrun.md)

```bash
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

# Verify, then launch against the verified handles.
sealrun verify \
  --root demo/artifacts \
  --manifest demo/manifest.signed.json \
  --public-key demo/public.pub

sealrun launch \
  --root demo/artifacts \
  --manifest demo/manifest.signed.json \
  --public-key demo/public.pub \
  -- <command>
```

`sealrun launch` verifies first, keeps the verified descriptors open, and hands them to the command as `SEALRUN_ARTIFACT_*` environment variables (`/proc/self/fd/N`). Verify with one command and launch by path with another reopens the check-to-use window — always launch through `sealrun launch`. `--seal` copies artifacts into a sealed memfd first (opt-in). `--uid`/`--gid` drop privilege before exec.

## Audit journal

```bash
sealrun audit-append --journal demo/audit.jsonl --event-type "verification" --detail "demo check"
sealrun audit-verify --journal demo/audit.jsonl
```

Editing an earlier entry breaks the chain. The journal alone does not protect against an administrator rewriting the whole file — anchor roots externally (see docs/anchoring-protocol.md).

## What it proves, and what it does not

Proves: the exact bytes that were launched (signed manifest, checked before launch); that the journal hasn't been edited since (hash chain); rollback protection via monotonic release sequences.

Does not prove: good behavior, output truthfulness, intent, or that every action was captured. It does not sandbox the child, does not solve prompt injection, and verification on an already-compromised host proves nothing.

## Docs

- README.md — overview and quick start
- docs/using-sealrun.md — worked example
- docs/launcher.md — launch contract and residual limits
- docs/anchoring-protocol.md — BSV anchoring
- docs/technical-writeup.md — design writeup
- Landing page: https://robganon.github.io/bsv-ai-security/
- Demo (19s): https://youtu.be/6z6a17UsD4g

## Contributing

Work on a branch, never commit directly to main. Run the test suite before opening a PR. General feedback goes to public GitHub issues; security findings via private vulnerability reporting only.
