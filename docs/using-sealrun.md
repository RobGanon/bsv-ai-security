# User guide — using SealRun with your AI

This guide walks the full flow end to end with a small worked example:
point SealRun at the files that define one AI run, sign them, launch
your AI through SealRun so only the approved bytes can run, record the
run in the audit journal, and hand someone else the proof later.

Everything below was run against the current code. You can follow
along exactly — the "AI" in the example is a toy script, but every
sealrun command is the real one you would use with a real model.

## What you need

- Linux, Python 3.10 or newer.
- Your AI's files: whatever defines the run. Typically the model
  file, its config, a system prompt, and the code that runs it. If a
  file's bytes would change what the AI does, it belongs in the
  manifest.
- About ten minutes.

## Install

```bash
pip install -e .
```

## The example setup

A toy support agent in a folder called `my-ai/`:

- `model.bin` — the model (here, 2 KB of stand-in bytes)
- `config.json` — its settings (`temperature`, `max_tokens`, …)
- `system-prompt.txt` — the system prompt
- `infer.py` — the program that runs it. It reads the model, config,
  and prompt through the `SEALRUN_ARTIFACT_*` environment variables
  SealRun sets (explained in step 3) instead of opening file paths.

Keys and state live outside the artifact folder, in `keys/` and
`state/`.

## Step 1 — Generate a signing key

```bash
sealrun keygen --private-key keys/private.wif --public-key keys/public.pub
```

```
Development keypair generated. Protect the private key.
```

The private key is written with owner-only permissions (0600). Whoever
holds it can sign manifests as you, so treat it like any other signing
key. `keygen` is for development and this walkthrough; for production,
generate the key offline and keep it off the machine that runs the AI.

## Step 2 — Fingerprint the run and sign it

Create a manifest listing the artifacts. SealRun hashes each file's
exact bytes with SHA-256.

```bash
sealrun manifest-create \
  --root my-ai \
  --artifact model.bin --artifact config.json --artifact system-prompt.txt \
  --release-id support-agent-v3 --release-seq 1 \
  --output state/manifest.json
```

```
Unsigned manifest written: state/manifest.json
```

`--release-seq` is a counter you increase with every release. It is
what lets a verifier reject an older, legitimately signed release
later (rollback protection).

Sign it:

```bash
sealrun manifest-sign \
  --manifest state/manifest.json \
  --private-key keys/private.wif \
  --output state/manifest.signed.json
```

```
Signed manifest written: state/manifest.signed.json
```

## Step 3 — Launch your AI through SealRun

You can check a manifest without running anything:

```bash
sealrun verify \
  --root my-ai \
  --manifest state/manifest.signed.json \
  --public-key keys/public.pub
```

```
VERIFIED: 3 artifact(s): model.bin, config.json, system-prompt.txt
```

But `verify` alone leaves a gap: it checks the files and exits, and
your program then opens the files by path — something could swap them
in between. `launch` closes that gap. It verifies, keeps the verified
files open, and starts your command with the open files handed to it:

```bash
sealrun launch \
  --root my-ai \
  --manifest state/manifest.signed.json \
  --public-key keys/public.pub \
  -- python3 my-ai/infer.py
```

```
model loaded: 2048 bytes, temperature=0.2
system prompt: You are a support agent. Be concise. Never invent prices.
answer: (toy model output)
```

How your program receives the artifacts: SealRun sets one environment
variable per artifact, named `SEALRUN_ARTIFACT_` + the file name in
upper case with dots and dashes as underscores (`model.bin` →
`SEALRUN_ARTIFACT_MODEL_BIN`). Each variable holds a path to the
already-open, already-verified file, so your program reads the exact
bytes that were checked — never a path that could have been swapped
after the check.

Add `--seal` and SealRun first copies each artifact into a sealed,
frozen snapshot in memory, so the running program is insulated even
if a writer keeps changing the original files during the run:

```bash
sealrun launch --seal \
  --root my-ai \
  --manifest state/manifest.signed.json \
  --public-key keys/public.pub \
  -- python3 my-ai/infer.py
```

From here on, your AI runs exactly as before. SealRun does not wrap,
sandbox, or slow down the model itself — it guards the door, not the
room.

## Step 4 — Record the run in the audit journal

The journal is a hash-chained log: every entry contains the hash of
the one before it, so editing any earlier entry breaks the chain.

Record that you adopted this release. The acceptance is bound to the
signed manifest's hash, so it names exactly which bytes were adopted.
The manifest's signature is checked against your public key *before*
the acceptance is recorded, so both are required:

```bash
sealrun audit-manifest-accepted \
  --journal state/audit.jsonl \
  --release-seq 1 --release-id support-agent-v3 \
  --manifest state/manifest.signed.json \
  --public-key keys/public.pub
```

```
Manifest acceptance recorded: seq=1 hash=4b7be6fb…
```

Append operational events as they happen:

```bash
sealrun audit-append \
  --journal state/audit.jsonl \
  --event-type model-run \
  --detail "support-agent-v3 answered ticket #4821"
```

```
Audit event appended: seq=2 hash=32b7869a…
```

Verify the chain any time:

```bash
sealrun audit-verify --journal state/audit.jsonl
```

```
AUDIT OK: 2 event(s)
```

## Step 5 — Prove it later

Months from now, someone asks: *which model and settings produced
that answer?* You hand them three things — the signed manifest, the
public key, and the journal. They run the same two commands
(`sealrun verify` and `sealrun audit-verify`) against the artifact
folder. They do not need your private key, your word, or access to
your systems: the signature proves the manifest is yours, the hashes
prove the files are the ones it names, and the journal proves the
record was not edited afterwards.

If you serve many verifiers, `--min-release-seq` on `verify` and
`launch` rejects any manifest older than the sequence you name, so a
stale but validly signed release cannot be quietly rolled back in.

## Try breaking it

Two one-minute experiments, so you can watch it fail closed instead
of taking the claim on faith:

**1. Change one setting.** Edit `config.json` (for example,
`temperature` 0.2 → 0.9) and launch again:

```
ERROR: artifact integrity mismatch: config.json
```

Exit code 1 — the AI never starts. Restore the file and the launch
succeeds again.

**2. Rewrite the journal.** Edit any word in an entry in
`state/audit.jsonl` and run `sealrun audit-verify` again:

```
ERROR: audit event hash mismatch at sequence 2
```

Editing history is detectable, always, because every entry is chained
to the next.

## Optional — anchor the journal to a public ledger

Everything above is local: it proves the record was not altered
*since it was written*, to anyone holding the journal. A local
administrator with full access could still rewrite the whole journal
from scratch and re-chain it. Anchoring closes that last hole: the
journal's head hash is periodically committed to a blockchain (BSV),
so the history is pinned to something no local administrator
controls.

Anchoring is an upgrade, not a prerequisite — start without it. When
you want it, anchor signing goes through a human, not the machine:
the publisher prepares an unsigned transaction, a person reviews and
signs it with their own credentials, and only then is it broadcast.
See [`docs/anchoring-protocol.md`](anchoring-protocol.md) for the
design, [`docs/offline-signing-handoff.md`](offline-signing-handoff.md)
for the flow, and
[`docs/ceremony-tester-walkthrough.md`](ceremony-tester-walkthrough.md)
to run the whole ceremony yourself on testnet play money.

## What SealRun does not do

- It does not prove the recorded events are *true* or *complete* —
  only that they were not altered after being recorded.
- It does not sandbox the AI or judge its outputs. It proves what
  ran, not whether the model behaved well.
- It does not stop prompt injection, data poisoning, or scraping.
  Those are different problems; this is the provenance layer.

## Where to go next

- [`docs/launcher.md`](launcher.md) — the `launch` contract in
  detail, including privilege dropping and residual limits.
- [`docs/reviewer-quickstart.md`](reviewer-quickstart.md) — verify
  this repository itself in about five minutes.
- [`REVIEW.md`](../REVIEW.md) — the scoped request for independent
  security review, including known limitations.
- [`SECURITY.md`](../SECURITY.md) — how to report a vulnerability
  privately.
