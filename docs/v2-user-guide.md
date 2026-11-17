# User guide — SealRun v2 launch flow (DRAFT)

**Status: DRAFT, 2026-11-16.** Written from the frozen v2 design and the project's
own testing; not yet walked through by an outside tester. The dogfood is the
test that corrects this guide: Round 1 (Codex) and Round 2 (Antigravity CLI)
both blocked on sudo and forced a restructure of the demo layout, and
verifying the Round 2 report against the code caught a step-order bug in the
tamper test. If a step below does not work as written, that is a bug in the
guide, the product, or both — report it.

**What this is:** research preview, not beta, not 1.0. The v2 launch flow has not
had an independent review yet, and mainnet anchoring is gated. No beta/1.0 date
is promised.

**What v2 adds over v1:** the launch is accepted only if the run is anchored —
payload binding plus the anchor transaction's signature plus proof the anchor
transaction is really inside its claimed block, checked against a header chain
to a pinned checkpoint. There are no signed pins, and v2 does not promise
freshness (it cannot tell you the anchor is recent, only that it exists and
matches). A checkpoint cache records the anchored minimum; a launch below it
refuses.

**What v2 proves, and what it does not:** it proves the exact bytes that were
launched (signed manifest, checked before launch), that the journal has not been
edited since (hash chain), and that the run is anchored outside the machine.
It does not prove good behavior, output truthfulness, or intent. It does not
sandbox the child and does not solve prompt injection. Verification on an
already-compromised host proves nothing.

## What you need

- Linux, Python 3.10 or newer.
- `sudo` — only the v2 launch and the bootstrap need it. The launcher must run
  privileged so it can drop the child to a different user. Steps 1–3 (toy,
  key, manifest), Step 6 (publish dry-run), and Step 9 (verify afterwards)
  run without sudo.

**Privileges — read this before you start.** Every `sudo` command below needs
a session that can actually use sudo. Two separate facts, both found by the
dogfood (Codex round, then Antigravity round, 2026-11-16):

- Agent sandboxes block sudo. `no_new_privileges` is the standard posture of
  almost all containerized agent runtimes and sandbox runtimes (Bubblewrap,
  Docker seccomp, systemd sandboxes) — not a quirk of one app. If your agent
  runs sandboxed, `sudo` fails outright.
- Even unsandboxed, `sudo` needs an interactive password prompt. A
  non-interactive agent session cannot type a password, so it stalls. A human
  must run the `sudo` steps (the launches and the bootstrap) in a terminal,
  or the agent must run in a terminal session where a human types the
  password.

The unprivileged steps (1–3, 6, 9) can run in an agent session. The privileged
steps cannot. This is a real constraint, not a bug: the privilege drop is what
makes the launch safe.
- A workload: a script and the files it needs. This guide uses a toy AI, the
  same shape as the v1 tester guide — a small script that writes a marker file.
  (A real model works the same way; see "Using a real model" at the end.)
- About 30–60 minutes the first time, including the optional testnet anchor.

## Install

Work from a repo checkout. You are testing the code in the repo, not the
release — the installed package is the release, not your branch.

```bash
git clone https://github.com/RobGanon/bsv-ai-security.git
cd bsv-ai-security
python3 -m venv .venv
.venv/bin/python -m sealrun.cli --version
```

You should see `sealrun 0.5.0rc1`. Run the commands below from this directory.

**Command names:** in every command below, `sealrun` means
`.venv/bin/python -m sealrun.cli` run from the repo directory. The `sudo`
steps take the same substitution — `sudo .venv/bin/python -m sealrun.cli
launch ...`.

**Alternative — the released package.** `sealrun 0.5.0rc1` is on PyPI
(verified 2026-11-16). If you are testing the release rather than the repo,
install it and write `sealrun` wherever this guide writes
`.venv/bin/python -m sealrun.cli`:

```bash
pip install sealrun==0.5.0rc1
sealrun --version
```

Note: on Arch Linux, system Python ships with no pip (`pip: command not
found`, and `python3 -m pip` reports no module named pip). Install the
`python-pip` package, or use the venv above (`.venv/bin/pip` exists). If a
`pip install` reports it cannot find the package, your network or sandbox is
blocking PyPI — the package is published; use the checkout instead.

## The demo layout — read this first

Only the state paths are subject to the v2 ownership rule. The launcher
(running as root) refuses a journal or checkpoint cache that is not owned by
the launcher and not writable by the child — but that rule applies ONLY to
the journal and the checkpoint cache (and the cache key). The workload, the
keys, and the manifest can live anywhere the launcher can read. So only the
state goes under `/srv`; everything else stays in your home directory, where
you can work on it without sudo:

```bash
mkdir -p ~/sealrun-v2-demo/work ~/sealrun-v2-demo/keys
chmod 1777 ~/sealrun-v2-demo/work
chmod 700 ~/sealrun-v2-demo/keys
sudo mkdir -p /srv/sealrun-v2-demo/state
```

- `~/sealrun-v2-demo/work/` — the sealed workload. Mode 1777
  (world-writable, sticky) so the dropped child (`nobody`) can write its
  output file there. The manifest, not the directory, is what protects the
  bytes — Step 4 proves it: anyone who can write to this directory still
  cannot change a sealed byte without the launch refusing.
- `~/sealrun-v2-demo/keys/` — the demo manifest key pair, mode 0700 (NOT the
  anchor key). `keygen` sets the private key to 0600.
- `~/sealrun-v2-demo/` — the manifest (`manifest.json`,
  `manifest.signed.json`), the anchor record, and the anchor file from the
  ceremony. User-owned; the launcher (root) can read them.
- `/srv/sealrun-v2-demo/state/` — the journal and the checkpoint cache ONLY.
  Root-owned, because the v2 isolation rule requires the state paths to be
  owned by the launcher (root). Only the launch and the bootstrap touch
  these.

If you put the journal or the checkpoint cache under your home directory, the
launch will refuse with an ownership error. That refusal is the rule working,
not a bug — but it will waste your time, so keep the state under `/srv`.

**Home directory must be traversable.** The dropped child (`nobody`) reaches
the demo tree through your home directory, so the home directory itself must
allow traversal — check with `stat -c '%a %n' ~`. If it prints `700`, the
launch fails with permission denied even though the files are readable; run
`chmod 0711 ~`. That allows traversal to a known path only (not listing), and
the keys stay protected — `keys/` is 0700 and the private key is 0600. Found
live 2026-11-16: a 700 home blocked the first Step 5 launch.

(An earlier draft put the whole demo tree under `/srv` and forced `sudo` onto
every step, including writing a toy script and generating a keypair. That was
wrong — it trained operators to manage private keys as root and blocked agents
from the unprivileged steps. Corrected after the Antigravity dogfood round,
2026-11-16.)

## Step 1 — Make a toy AI

```bash
cat > ~/sealrun-v2-demo/work/infer.py <<'EOF'
#!/usr/bin/env python3
"""Toy workload: writes a marker file so the run is visible."""
from pathlib import Path

out = Path(__file__).with_name("output.txt")
out.write_text("model ran\n")
print("wrote", out)
EOF
cat > ~/sealrun-v2-demo/work/config.json <<'EOF'
{"model": "toy-001", "max_tokens": 16}
EOF
cat > ~/sealrun-v2-demo/work/system-prompt.txt <<'EOF'
You are a toy model. Write a short greeting.
EOF
```

**Paste gotcha (confirmed live 2026-11-16 on the T480):** a multi-line heredoc
paste can collapse onto one line, so the heredoc never closes and the shell
waits at the `.` continuation prompt. If that happens, press Ctrl+C to abort
and write the files with single-line `printf` commands instead — a paste
cannot mangle those:

```bash
printf '%s\n' '{"model": "toy-001", "max_tokens": 16}' > ~/sealrun-v2-demo/work/config.json
printf '%s\n' 'You are a toy model. Write a short greeting.' > ~/sealrun-v2-demo/work/system-prompt.txt
printf '%s\n' '#!/usr/bin/env python3' '"""Toy workload: writes a marker file so the run is visible."""' 'from pathlib import Path' '' 'out = Path(__file__).with_name("output.txt")' 'out.write_text("model ran\n")' 'print("wrote", out)' > ~/sealrun-v2-demo/work/infer.py
```

## Step 2 — Generate a signing key

```bash
sealrun keygen \
  --private-key ~/sealrun-v2-demo/keys/demo.wif \
  --public-key ~/sealrun-v2-demo/keys/demo.pub
```

Keep the private key private. The public key is what the launcher trusts.
Generating it as your own user, not as root, is deliberate — a signing key
should never be root-owned unless a daemon requires it.

## Step 3 — Fingerprint the run and sign it

```bash
sealrun manifest-create \
  --root ~/sealrun-v2-demo/work \
  --artifact infer.py --artifact config.json --artifact system-prompt.txt \
  --release-id demo-v2-001 --release-seq 1 \
  --output ~/sealrun-v2-demo/manifest.json
sealrun manifest-sign \
  --manifest ~/sealrun-v2-demo/manifest.json \
  --private-key ~/sealrun-v2-demo/keys/demo.wif \
  --output ~/sealrun-v2-demo/manifest.signed.json
sealrun verify \
  --root ~/sealrun-v2-demo/work \
  --manifest ~/sealrun-v2-demo/manifest.signed.json \
  --public-key ~/sealrun-v2-demo/keys/demo.pub
```

The manifest pins the exact bytes of every artifact. Change one byte after
signing and the verify refuses.

## Step 4 — Try to break it (before the first launch)

Change one line of the workload after signing, then launch against a fresh
journal:

```bash
echo "# tampered" >> ~/sealrun-v2-demo/work/infer.py
sudo sealrun launch --mode v2 \
  --journal /srv/sealrun-v2-demo/state/journal.jsonl \
  --min-release-seq 0 \
  --root ~/sealrun-v2-demo/work \
  --manifest ~/sealrun-v2-demo/manifest.signed.json \
  --public-key ~/sealrun-v2-demo/keys/demo.pub \
  --uid nobody \
  -- python3 ~/sealrun-v2-demo/work/infer.py
```

The launch must refuse with an artifact integrity mismatch, and the workload
must not run — no new `output.txt` write, no model output.

This step runs BEFORE the first successful launch, and that order matters.
Once a launch succeeds, the journal carries a nonce-bearing v2 event and
every later launch requires a checkpoint cache; without one, the launch
refuses on the cache before it ever checks the artifacts, and the tamper
would be masked. A refused launch records only a nonce-less failure event,
so it does not seed the journal — the next step still takes the first-launch
path.

Restore the original file (remove the line you added) so the sealed bytes
match the manifest again:

```bash
sed -i '/^# tampered$/d' ~/sealrun-v2-demo/work/infer.py
```

## Step 5 — First v2 launch (seeding)

This is the first launch against a fresh journal, with no checkpoint cache.
There is nothing anchored yet, so the launch proceeds under the seeding
exception: it prints a NOTICE, runs with checkpoint 0, and the journal gains
a nonce-bearing `v2_launch` event. That event is what later steps build on —
a journal with no nonce-bearing v2 event cannot be bootstrapped or verified.
(No `--checkpoint-cache` here: on a fresh journal the cache argument is not
needed. Once the journal is seeded, it becomes mandatory — see the
troubleshooting note.)

```bash
sudo sealrun launch --mode v2 \
  --journal /srv/sealrun-v2-demo/state/journal.jsonl \
  --min-release-seq 0 \
  --root ~/sealrun-v2-demo/work \
  --manifest ~/sealrun-v2-demo/manifest.signed.json \
  --public-key ~/sealrun-v2-demo/keys/demo.pub \
  --uid nobody \
  -- python3 ~/sealrun-v2-demo/work/infer.py
```

Check the output file appeared: `cat ~/sealrun-v2-demo/work/output.txt`.
It should read `model ran`. The child ran as `nobody`, not as root — the
launcher dropped privilege before exec.

**If this first launch fails after the seeding NOTICE prints** — for example
the child cannot start — the journal is already seeded even though nothing
ran, and the next launch will refuse demanding a checkpoint cache that does
not exist yet. Do not bootstrap (there is no anchor yet); delete the journal
and retry Step 5:

```bash
sudo rm /srv/sealrun-v2-demo/state/journal.jsonl
```

then re-run the launch above. Found live 2026-11-16: a permission-denied
child seeded the journal, and the retry after deleting it succeeded.

(Adding `--seal` copies the artifacts into sealed memory first, so the child
reads them from descriptors it cannot re-open after a swap. It is opt-in.)

## Step 6 — Anchor the journal (dry run first, no money)

The publisher prepares the anchor payload for the journal head. By default it
never broadcasts — it prepares payloads and stops:

```bash
sealrun publish \
  --journal /srv/sealrun-v2-demo/state/journal.jsonl \
  --anchor-record ~/sealrun-v2-demo/anchor-record.json \
  --mode once
```

You should see `DRY RUN: broadcast disabled — payloads prepared, nothing
broadcast.` The payload is 84 bytes and starts with the `AIGUARD1` magic.
Nothing has been spent and nothing has left the machine. (The journal is
readable without sudo — the launcher creates it mode 0644 — so the publisher
runs as your own user.)

**Optional — anchor on testnet (play money only).** Broadcasting needs a
funded testnet anchor key and the signing ceremony: the publisher exports an
unsigned transaction (`--export-unsigned`), a human reviews the decoded
transaction and signs it with username/password + second factor, and the
publisher broadcasts the signed transaction (`--broadcast-signed`) only after
rebuilding the expected unsigned transaction independently and requiring a
byte-for-byte match. Do not skip the ceremony — the key must never reach the
machine that builds the transaction. Full steps:
`docs/ceremony-tester-walkthrough.md`. Testnet coins have no value; mainnet
is refused by the signer unconditionally and must never be used here.

## Step 7 — Bootstrap the checkpoint cache

Once an anchor exists (from Step 6's broadcast), bootstrap the cache from it.
The publisher writes the anchor into a record file
(`~/sealrun-v2-demo/anchor-record.json`) that wraps it in an `anchors` list.
The bootstrap (and the verify in Step 9) want the single anchor object, not
the wrapper — pointing them at the record fails with
`anchor JSON must contain payload_hex and txid`. Extract it first:

```bash
jq .anchors[0] ~/sealrun-v2-demo/anchor-record.json > ~/sealrun-v2-demo/anchor-1.json
```

The genesis txid is the **zero txid** — the first anchor's `prev_txid`, not
its txid. (An earlier version of this project's own test plan got this wrong;
the code requires genesis to equal the first anchor's `prev_txid` and to
differ from every anchor txid.)

```bash
sudo sealrun bootstrap \
  --journal /srv/sealrun-v2-demo/state/journal.jsonl \
  --checkpoint-cache /srv/sealrun-v2-demo/state/checkpoint.jsonl \
  --genesis-txid 0000000000000000000000000000000000000000000000000000000000000000 \
  --anchor ~/sealrun-v2-demo/anchor-1.json \
  --spv --anchor-pubkey <trusted anchor pubkey> \
  --checkpoint-hash <anchor block hash> --checkpoint-height <anchor block height> \
  --uid nobody
```

`<trusted anchor pubkey>` is the 66-character compressed pubkey of the anchor
key, pinned out-of-band. `<anchor block hash>` and `<anchor block height>` are
the block the anchor transaction is in — find them from the broadcast
transaction on a testnet explorer. Expect:
`CHECKPOINT BOOTSTRAPPED: release_seq=0 ... checkpoint_seq=1`.

## Step 8 — Second v2 launch, anchored minimum enforced

Repeat Step 5, this time with the cache. The launch now enforces the anchored
minimum recorded in Step 7:

```bash
sudo sealrun launch --mode v2 \
  --journal /srv/sealrun-v2-demo/state/journal.jsonl \
  --checkpoint-cache /srv/sealrun-v2-demo/state/checkpoint.jsonl \
  --min-release-seq 0 \
  --root ~/sealrun-v2-demo/work \
  --manifest ~/sealrun-v2-demo/manifest.signed.json \
  --public-key ~/sealrun-v2-demo/keys/demo.pub \
  --uid nobody \
  -- python3 ~/sealrun-v2-demo/work/infer.py
```

(Adding `--require-v2` refuses a v1 invocation outright — useful on a
deployment that must never run v1 by accident.)

## Step 9 — Prove it afterwards

```bash
sealrun anchor-chain-verify --v2 \
  --genesis-txid 0000000000000000000000000000000000000000000000000000000000000000 \
  --anchor ~/sealrun-v2-demo/anchor-1.json \
  --anchor-sig --anchor-pubkey <trusted anchor pubkey> \
  --spv --header-chain \
  --checkpoint-hash <anchor block hash> --checkpoint-height <anchor block height> \
  --journal /srv/sealrun-v2-demo/state/journal.jsonl
sealrun audit-verify --journal /srv/sealrun-v2-demo/state/journal.jsonl
```

What to look for: `accepted: true` on the chain verify, and a clean
audit-verify. One reading trips people up: after seeding, `tip_inside_anchor`
reports `false` with unanchored seed events. That is the correct report — the
seed events happened after the anchored prefix — not a failure.

## Using a real model

Replace `infer.py` with a script that calls your model, and add the model
identity to the manifest (a `model.json` with the model id, endpoint, and
generation params). Two honest limits:

- **Local models** (weights on disk): the model file can be sealed like any
  other artifact. Large weights are slow to hash; that cost is paid once at
  manifest creation.
- **Cloud models** (weights on someone else's server): SealRun can seal the
  script, the config, and the declared model name, and journal the run — but
  it cannot verify the model itself, because the bytes are not on the machine.
  The provider could swap the model behind the same API name and SealRun
  would not know.

The child runs dropped to `--uid nobody`. If your model needs the network
(a local API on loopback, or a cloud endpoint), confirm the dropped child can
reach it before you record a demo or report a failure — a connection refused
from the child is a permissions problem, not a SealRun refusal.

## Troubleshooting

- **Launch refuses with an ownership error:** a state path is not owned by the
  launcher (root, under `sudo`). Keep the journal and the checkpoint cache
  under `/srv` as above, and do not point `--journal` or `--checkpoint-cache`
  at a path under your home directory. The workload, keys, and manifest may
  be user-owned.
- **Launch refuses with an artifact integrity mismatch:** a sealed file changed
  after signing. Re-create and re-sign the manifest, or restore the file.
- **Launch refuses on the checkpoint cache on a seeded journal:** once
  the journal carries a nonce-bearing v2 event, every launch requires a
  checkpoint cache. A missing cache on a seeded journal refuses — a missing
  cache is never read as checkpoint 0. Which fix applies depends on how the
  journal got seeded: if the first launch *succeeded*, bootstrap from the
  anchor (Step 7) before launching again; if the first launch *failed after
  the seeding NOTICE* (the child never ran), there is no anchor to bootstrap
  from — delete the journal and retry Step 5 (see the Step 5 note). If you
  are testing a tamper refusal, do it before the first successful launch
  (Step 4).
- **Bootstrap or chain-verify refuses at the identity step:** the journal has
  no nonce-bearing v2 event. Run Step 5 (the seeding launch) first — a
  pristine journal cannot be bootstrapped.
- **Chain-verify rejects the genesis txid:** it must be the zero txid (the
  first anchor's `prev_txid`), not the first anchor's own txid.
- **A launch refuses and nothing is obviously wrong:** check the journal with
  `audit-verify` and re-read the refusal — v2 fails closed, and the refusal
  message names the check that failed.
- **The child cannot write its output file:** the workload directory must be
  writable by the dropped child. This guide sets `work/` to mode 1777 for
  that reason. If you changed it, restore it with
  `chmod 1777 ~/sealrun-v2-demo/work`.
- **The cache is bricked (duplicate checkpoint):** a known low-severity issue
  (append race, no lock yet) — the cache refuses reads until repaired. Do not
  delete the cache to work around it; report it.

## What SealRun does not do

It does not sandbox the child, cap CPU or memory, or stop a runaway workload
(a separate power-management project is planned for that). It does not prove
the output is true, the behavior was good, or the intent was honest. It does
not protect a journal on a machine whose administrator rewrites the whole
file — that is what the external anchor is for.

## Where to go next

- Report problems and findings as public GitHub issues; security findings go
  through private vulnerability reporting only.
- The design reference is `docs/launch-flow-v2-design-FROZEN.md` (frozen) and
  `docs/anchoring-protocol.md`.
- The signing ceremony in full: `docs/ceremony-tester-walkthrough.md`.
