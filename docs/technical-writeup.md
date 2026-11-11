# SealRun: verify an AI run before it starts, prove it afterwards

AI agents run code. They load models, read configs, follow prompts — and
then they act. If any of those bytes were tampered with before the run,
you usually find out after the damage is done, if you find out at all.

Most agent-security tools record what happened and let you verify it
afterwards. That is worth doing. But the check that matters most happens
*before* anything runs: if the bytes don't match what was approved,
nothing should start.

SealRun is built on that idea.

## What it does

SealRun has three parts, and they work in order:

**1. Verify before launch.** A signed manifest lists the exact bytes of
every artifact a run will use — model, config, system prompt — each with
its SHA-256. Before the child process starts, SealRun verifies the
manifest signature and re-hashes every artifact. If anything differs,
the launch is refused and the child never runs. Not "logged and allowed"
— refused.

**2. Record while it runs.** Every launch and finish is appended to a
hash-chained audit journal: each event commits to the hash of the one
before it, so deleting or reordering an event breaks the chain. A forged
finish event — one an attacker hand-appends to claim a run completed —
fails verification because its hash doesn't match the chain.

**3. Anchor the history.** The journal head can be anchored on-chain
(currently BSV, via an 84-byte OP_RETURN) so the history is not just
internally consistent but publicly timestamped and tamper-evident. The
anchor proves the history existed and hasn't been rewritten; it does not
prove the history is truthful — that's a different claim, and SealRun
doesn't make it.

The whole thing is stdlib-only Python, zero dependencies, runs locally.
No server, no account, no network call at launch time once a checkpoint
is bootstrapped.

## How the refusal works

Three mechanisms do the heavy lifting:

- **Descriptors, not paths.** The child receives each artifact as an
  already-open file descriptor (`/proc/self/fd/N`), not a pathname it
  re-opens. Swapping the file at the path mid-run — a new inode at the
  same name — cannot touch what the child reads. Overwriting the bytes
  in place is a different attack, and that's what `--seal` is for: it
  freezes the artifact bytes so even an in-place mutation mid-run can't
  change what the child sees.
- **Writer isolation.** The launcher runs privileged and drops the child
  to an unprivileged user (`--uid nobody`). The child can't write the
  journal, the checkpoint cache, or the artifacts it reads. Only the
  launcher appends journal events.
- **Anchored rollback checkpoint.** A checkpoint cache records the
  highest release sequence the anchor chain has actually accepted. A
  launch below that checkpoint refuses. A missing cache refuses rather
  than silently treating it as zero — except for the very first launch
  of a fresh journal, which seeds the journal identity and says so
  loudly.

These aren't theoretical. Each one has a test that demonstrates it
failing closed: a tampered artifact, a tampered manifest, a forged
finish, a path swap mid-run, a script passed off as a verified
executable (refused — verified binding is ELF-only).

## What it does not do

Honesty matters more than a clean story, so here are the limits:

- **Truncation to a valid prefix is undetectable alone.** If someone
  truncates the journal (or the checkpoint cache) back to an older
  internally-valid state, audit-verify still says OK — it can't tell a
  truncated journal from a shorter real one. Only an external reference
  (the anchored head hash, or a trusted high-water mark) catches it.
  This is documented, not hidden.
- **It proves integrity and existence, not truthfulness.** Anchoring
  proves the history hasn't been rewritten. It doesn't prove the
  recorded events describe what really happened, or that a run that
  "completed" actually did useful work.
- **It's a research preview.** About 1,000 tests, dogfooded on the
  author's own machine, real testnet anchors — but no independent
  security review yet, and no external tester has run it. Mainnet spend
  is gated. The scope is frozen until review and testing are done.

## Try it

The fastest way to see the point is the runnable demo in the repo.
It builds its own layout and proves the three refusals in about
20 seconds:

```bash
git clone https://github.com/RobGanon/bsv-ai-security
cd bsv-ai-security
python3 -m venv .venv
bash examples/run-demo.sh
```

Expected output:

```
CASE A1 (tampered artifact, child must never run): PASS
CASE A2 (tampered manifest, one hex digit):        PASS
CASE A6 (forged finish, 64-zero event_hash):       PASS

ALL 3 CASES PASS
```

Repo: https://github.com/RobGanon/bsv-ai-security
Landing page: https://robganon.github.io/bsv-ai-security/

## Why this, why now

Agents are being given more to do — more tools, more autonomy, more
trust. The question "did it run what I approved?" is becoming the
question, and "we logged it" is not an answer to it. Verification
before launch is the missing half of agent security: the part that
stops a tampered run instead of documenting it.

SealRun is one attempt at that half. It's early, it's honest about
what it can't do, and it needs reviewers and testers more than it
needs stars. If you run AI and this problem bothers you, try the demo,
read the code, and tell us where it's wrong.
