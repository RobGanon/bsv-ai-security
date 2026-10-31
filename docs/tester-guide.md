# Tester guide — try SealRun end to end, and try to break it

This guide is for an independent tester, not a code reviewer. You do
not need to read the source. You need Linux, Python 3.10 or newer,
`git`, and about 30 minutes (plus about 30 more if you do the
optional testnet anchor ceremony at the end).

> **For the non-technical reader.** SealRun is a tamper-proof
> logbook for an AI run. Before a model runs, it records a
> fingerprint of everything about to be used — which model, which
> data, which settings. After it runs, every event goes into a
> chained record, where editing any earlier entry breaks the chain
> for everything after it. This guide lets you check those claims
> yourself, with a toy AI, instead of taking them on faith.

## Before you start: what you are — and are not — testing

**This guide describes `main` behaviour.** The protections below
are in `main` now, so test `main` as-is and report what you find
there:

- Fetch-side payload binding: a fetched transaction is checked
  against the requested txid.
- Generic `audit-append --event-type manifest_accepted` is refused;
  use `audit-manifest-accepted` instead.
- Adversarial-review fixes: scheduler trust, hostile SPV blocks,
  infinite-value handling, plus WoC network checks, HTTPS
  enforcement, strict broadcast replies, exact satoshi conversion,
  and signer bounds.
- Publisher tip-txid binding: a stored broadcast record is checked
  against its stored transaction bytes before chaining.

**What SealRun does not do** (also true on `main`): it does not
prove recorded events are true or complete — only that they were
not altered after recording. It does not sandbox the AI, judge its
outputs, or stop prompt injection. It proves what ran, not whether
the model behaved well. Independent security review is still open
(see `REVIEW.md`); this guide is a hands-on test, not a review.

**Known limitations — please do not re-report these as findings:**
see `REVIEW.md` ("Known limitations"), including that the anchor
key sits on the same machine as the publisher in the testnet demo,
and that SPV header-chain verification without `--daa mainnet`
does not validate difficulty-retarget rules or cumulative work.

## Step 0 — Install

Clone the repository, then install into a fresh virtual
environment. The package is stdlib-only: it has no runtime
dependencies, so nothing else is downloaded.

```bash
git clone https://github.com/RobGanon/bsv-ai-security.git
cd bsv-ai-security
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/sealrun --help
```

Expected: the help text lists the commands
(`keygen`, `manifest-create`, `manifest-sign`, `verify`,
`launch`, `audit-append`, `audit-verify`,
`audit-manifest-accepted`, `anchor-payload`, `anchor-verify`,
`anchor-chain-verify`, `publish`, `signer`).

If you prefer not to install at all, every command below also
works as `python3 -m sealrun.cli …` from the repository root —
that is the no-install sanity check used in the ceremony
walkthrough.

From here on, this guide writes `sealrun` for the installed
command. If you skipped the install, read it as
`python3 -m sealrun.cli`.

> **Work in a scratch folder.** Every file below is a toy you
> create for this test. Nothing here touches a real model, a real
> key, or real money.

## Step 1 — Make a toy AI

```bash
mkdir -p tester/my-ai tester/keys tester/state
cd tester
printf 'x%.0s' $(seq 1 2048) > my-ai/model.bin
printf '{"temperature": 0.2, "max_tokens": 100}\n' > my-ai/config.json
printf 'You are a support agent. Be concise. Never invent prices.\n' > my-ai/system-prompt.txt
```

And a tiny program that reads the verified files through the
environment variables SealRun sets (see Step 4):

```bash
cat > my-ai/infer.py << 'EOF'
import os
print("model loaded:", len(open(os.environ["SEALRUN_ARTIFACT_MODEL_BIN"], "rb").read()), "bytes")
print("answer: (toy model output)")
EOF
```

## Step 2 — Generate a test signing key

```bash
sealrun keygen --private-key keys/private.wif --public-key keys/public.pub
```

Expected:

```
Development keypair generated. Protect the private key.
```

This is a **test key**. Whoever holds the private key can sign
manifests as you, so treat it like any signing key — and never
use a test key for anything real. Check the permissions:
`ls -l keys/private.wif` should show owner-only access (`-rw-------`).

## Step 3 — Fingerprint the run and sign it

SealRun hashes each file's exact bytes with SHA-256:

```bash
sealrun manifest-create \
  --root my-ai \
  --artifact model.bin --artifact config.json --artifact system-prompt.txt \
  --release-id support-agent-v3 --release-seq 1 \
  --output state/manifest.json
```

Expected:

```
Unsigned manifest written: state/manifest.json
```

`--release-seq` is a counter you increase with every release. It
is what lets a verifier reject an older, legitimately signed
release later (rollback protection).

Sign it:

```bash
sealrun manifest-sign \
  --manifest state/manifest.json \
  --private-key keys/private.wif \
  --output state/manifest.signed.json
```

Expected:

```
Signed manifest written: state/manifest.signed.json
```

## Step 4 — Verify, then launch through SealRun

Check the manifest without running anything:

```bash
sealrun verify \
  --root my-ai \
  --manifest state/manifest.signed.json \
  --public-key keys/public.pub
```

Expected (exit code 0):

```
VERIFIED: 3 artifact(s): model.bin, config.json, system-prompt.txt
```

`verify` alone leaves a gap: it checks the files and exits, and
your program then opens the files by path — something could swap
them in between. `launch` closes that gap. It verifies, keeps the
verified files open, and starts your command with the open files
handed to it:

```bash
sealrun launch \
  --root my-ai \
  --manifest state/manifest.signed.json \
  --public-key keys/public.pub \
  -- python3 my-ai/infer.py
```

Expected (exit code 0):

```
model loaded: 2048 bytes
answer: (toy model output)
```

How your program receives the artifacts: SealRun sets one
environment variable per artifact, named `SEALRUN_ARTIFACT_` +
the file name in upper case with dots and dashes as underscores
(`model.bin` → `SEALRUN_ARTIFACT_MODEL_BIN`). Each variable
holds a path to the already-open, already-verified file, so your
program reads the exact bytes that were checked.

## Step 5 — Record the run in the audit journal

The journal is a hash-chained log: every entry contains the hash
of the one before it, so editing any earlier entry breaks the
chain.

Record that you adopted this release. The acceptance is bound to
the signed manifest's hash, so it names exactly which bytes were
adopted. The manifest's signature is checked against your public
key *before* the acceptance is recorded:

```bash
sealrun audit-manifest-accepted \
  --journal state/audit.jsonl \
  --release-seq 1 --release-id support-agent-v3 \
  --manifest state/manifest.signed.json \
  --public-key keys/public.pub
```

Expected (the hash will differ on your run):

```
Manifest acceptance recorded: seq=1 hash=…
```

Append an operational event:

```bash
sealrun audit-append \
  --journal state/audit.jsonl \
  --event-type model-run \
  --detail "support-agent-v3 answered ticket #4821"
```

Expected:

```
Audit event appended: seq=2 hash=…
```

Verify the chain any time:

```bash
sealrun audit-verify --journal state/audit.jsonl
```

Expected (exit code 0):

```
AUDIT OK: 2 event(s)
```

## Step 6 — Try to break it (three experiments)

### Experiment 1: change one setting

Edit `config.json` (`temperature` 0.2 → 0.9) and launch again:

```bash
printf '{"temperature": 0.9, "max_tokens": 100}\n' > my-ai/config.json
sealrun launch \
  --root my-ai \
  --manifest state/manifest.signed.json \
  --public-key keys/public.pub \
  -- python3 my-ai/infer.py
```

Expected — **failure, exit code 1, and the AI never starts:**

```
ERROR: artifact integrity mismatch: config.json
```

Restore the file and the launch succeeds again:

```bash
printf '{"temperature": 0.2, "max_tokens": 100}\n' > my-ai/config.json
```

**What a real failure looks like here:** if the launch succeeds
with the tampered config, that is a finding. Report it with the
exact commands you ran.

### Experiment 2: rewrite the journal

Edit any word in an entry in `state/audit.jsonl` (for example,
change the ticket number) and verify again:

```bash
sealrun audit-verify --journal state/audit.jsonl
```

Expected — **failure, exit code 1:**

```
ERROR: audit event hash mismatch at sequence 2
```

Restore the journal before continuing (re-run Steps 5's two
commands into a fresh file, or restore from your backup).

### Experiment 3: delete the last journal entry (read this one carefully)

Copy the journal, delete its last line, and verify the copy:

```bash
head -n 1 state/audit.jsonl > /tmp/audit-truncated.jsonl
sealrun audit-verify --journal /tmp/audit-truncated.jsonl
```

Expected — **this one passes:**

```
AUDIT OK: 1 event(s)
```

That is honest, not a bug in the demo: a hash chain detects
*edits* to entries it still holds, but it cannot tell you an
entry at the end was deleted, because the remaining entries
still chain correctly. This is exactly the hole anchoring closes:
an anchor commits the journal's head hash and sequence range to
a public ledger, so a verifier holding the anchor can see that
the journal is supposed to have 2 events, not 1. If you expected
truncation to fail here, you have found the reason anchoring
exists — not a finding against `audit-verify` alone.

## Step 7 — Build an anchor checkpoint (no broadcast, no money)

This step prepares an anchor without sending anything. It needs
the signed manifest and public key, because the journal contains
an acceptance and its binding must be checked:

```bash
sealrun publish \
  --journal state/audit.jsonl \
  --anchor-record state/anchors.json \
  --manifest state/manifest.signed.json \
  --public-key keys/public.pub \
  --mode once
```

Expected (exit code 0). The output includes:

```
DRY RUN: broadcast disabled — payloads prepared, nothing broadcast.
```

And `state/anchors.json` holds one record with `"status":
"pending"` and `"txid": null`, covering `start_seq: 1` to
`end_seq: 2`. Running the same command again reports
`"action": "none", "reason": "already-anchored"` — the same
head is never anchored twice.

**Common mistake:** leaving out `--manifest` and `--public-key`
fails with:

```
ERROR: anchor creation refused: cannot verify acceptance binding
without manifests and a trusted public key …
```

That is the tool refusing to anchor an acceptance it cannot
check, not a broken install. Add the two flags and re-run.

## Optional Step 8 — Anchor on testnet (play money only, ~30 minutes)

Only if you want to see a real on-chain anchor. Follow
[`docs/ceremony-tester-walkthrough.md`](ceremony-tester-walkthrough.md)
end to end: build a journal, fund a fresh testnet address from
the faucet, export an unsigned anchor transaction, run the
negative test (a tampered transaction the signer must refuse),
sign the real one with your own password + authenticator app,
broadcast it, and verify it on-chain.

Rules for this step, with no exceptions:

- **Testnet only, play money only.** The signer refuses mainnet
  unconditionally. Never fund an anchor address with real money
  for this test.
- **Your key never leaves your machine.** The ceremony's whole
  point is that a human, not the machine, approves the exact
  transaction. If any step asks you to paste a private key
  somewhere else, stop.
- **The negative test matters.** Do not skip the tampered-transaction
  refusal — it is the check that the signer actually verifies what
  it signs.

## Step 9 — Prove it later (the handover test)

Months from now, someone asks: *which model and settings produced
that answer?* Hand a second person three things — the signed
manifest, the public key, and the journal — and nothing else
(no private key, no access to your machine). They should be able
to run `sealrun verify` and `sealrun audit-verify` against the
artifact folder and get the same "VERIFIED" and "AUDIT OK"
results. If they cannot, that is a finding: the proof was not
self-contained.

## Report template

Copy this into your report (issue #4, or a PR) and fill it in.
A report without the branch and commit is hard to reproduce.

```
Branch / commit tested:
OS and Python version:
Install method used (pip install . / pip install -e . / no install):
Steps completed (1–9, and which experiments):
Expected vs actual, per step (paste the exact output where it differed):
Finding, if any (what should have been refused but was accepted,
or what should have passed but failed):
```

There is no bug bounty. Time estimate: about 30 minutes for
Steps 0–7, about 30 more for the optional testnet ceremony.

## Where to go next

- [`docs/using-sealrun.md`](using-sealrun.md) — the full user
  guide, including `--seal` (frozen in-memory snapshots) and
  `--min-release-seq` (rollback rejection).
- [`docs/reviewer-quickstart.md`](reviewer-quickstart.md) — verify
  this repository itself in about five minutes, and the live
  Teratestnet anchors.
- [`docs/ceremony-tester-walkthrough.md`](ceremony-tester-walkthrough.md) — the full testnet signing ceremony.
- [`REVIEW.md`](../REVIEW.md) — the scoped request for independent
  security review, including known limitations.
- [`SECURITY.md`](../SECURITY.md) — how to report a vulnerability
  privately.
