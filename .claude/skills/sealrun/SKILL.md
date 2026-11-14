---
name: sealrun
description: Verify an AI run before it starts and prove it afterwards with SealRun. Use when the user asks to seal, verify, or prove a run, or when starting any AI session whose bytes should be checked first.
---

# SealRun — sealrun your session

SealRun pins the exact bytes of a run in a signed manifest, verifies the signature before launch, and records security events in a hash-chained audit journal. Research preview; the v2 launch flow hasn't had an independent review yet.

## Install (once)

```bash
git clone https://github.com/RobGanon/bsv-ai-security.git
cd bsv-ai-security
pip install -e .
```

No PyPI package yet. Python >= 3.10, zero dependencies.

## Seal a run

```bash
sealrun keygen --private-key demo/private.wif --public-key demo/public.pub   # demo keys only; production keys stay offline
sealrun manifest-create --root <artifacts> --artifact <file>... --release-id <id> --release-seq <n> --output manifest.json
sealrun manifest-sign --manifest manifest.json --private-key demo/private.wif --output manifest.signed.json
sealrun launch --root <artifacts> --manifest manifest.signed.json --public-key demo/public.pub -- <command>
```

Launch verifies first and refuses to start on a tampered artifact (`ERROR: artifact integrity mismatch`, exit 1). Verified artifacts reach the command as `SEALRUN_ARTIFACT_*` env vars. Never verify with one command and launch by path with another — that reopens the check-to-use window.

## Check a run afterwards

```bash
sealrun audit-verify --journal <audit.jsonl>
```

An edited entry fails with the sequence where the chain broke.

## What it proves, and what it does not

Proves what bytes ran and that the journal wasn't edited since. Does not prove good behavior, output truth, intent, or complete capture. It doesn't sandbox the child. Full details: `docs/using-sealrun.md` and `docs/launcher.md` in the repo.
