# Independent review — what we're asking for

**Project in one line:** Prove what your AI actually ran.

This repo is a Linux-local verifier plus a BSV anchoring layer. Signed
manifests pin the exact model/code/data/config bytes of a run; a
hash-chained journal records acceptance events; anchor transactions on
Teratestnet checkpoint the journal head so history can't be rewritten
after the fact. It proves history integrity and existence — not
truthfulness. See `README.md` and `docs/anchoring-protocol.md`.

This document scopes the independent review requested in
[issue #4](https://github.com/RobGanon/bsv-ai-security/issues/4).
It is a peer review ask, not a paid audit.

**New here?** Start with [`docs/reviewer-brief.md`](docs/reviewer-brief.md)
— a 15-minute orientation (claims, trusted base, adversaries, known gaps,
where to spend your first hour). This file is the formal scope.

## Scope

The manifest verifier, the journal, and the anchor checks:

- `sealrun/core.py` — manifest verification, TOCTOU-resistant fd handoff
- `sealrun/launcher.py` — privileged launcher: verify, pin handles across
  exec, optional sealed-memfd freeze, privilege drop
- `sealrun/publisher.py`, `sealrun/publishing.py` — acceptance + anchor prep
- `sealrun/anchor.py` — anchor-chain verification (continuity, signatures)
- `sealrun/bsv.py` — minimal BSV primitives: secp256k1, tx build/sign,
  BIP 143 `SIGHASH_ALL|FORKID` sighash
- `sealrun/broadcast.py` — signer interface, WoC-TTN broadcaster
- `sealrun/spv.py` — inclusion (Merkle recomputation), header-chain walk
- `sealrun/beef.py` — BEEF envelope parse/verify (inclusion + ancestry +
  amount conservation; no script evaluation)
- `sealrun/cli.py` — the `verify`/`launch`/`anchor-chain-verify` surfaces

About 8,753 lines of production Python, 12,076 lines of tests,
651 tests passing on `main`.

These counts are the single source of truth for test and line counts
in this repo — other docs point here instead of copying the numbers,
so a count update touches this file only.

## What "good" looks like

The review succeeds if it finds — or rules out — any of these:

1. A case where the verifier **accepts what it should reject**
   (bad manifest, tampered journal, broken chain, forged anchor).
2. A soundness bug in the sighash, Merkle, or header-chain verification.
3. A journal or rollback hole (tail truncation, replay, gap, fork).
4. An unsafe failure mode (a check that fails open instead of closed).

## Out of scope

- Mainnet. Everything chain-related is Teratestnet play money.
- BUMP / BEEF scope boundaries (not findings) — BUMP (BRC-74) parse/verify/build
  + `anchor-chain-verify --bump-file`, and BEEF (BRC-62) envelope
  parse/verify + `anchor-chain-verify --beef-file`, are implemented;
  no public source serves BUMPs or BEEF, so proofs/envelopes are
  operator-supplied. BEEF verification covers inclusion + ancestry +
  amount conservation; it does NOT evaluate scripts, so an unmined
  tx's signatures are not checked. Do not re-report these scope
  boundaries as findings.
- Performance, UX, and the separate BRC-166 paid-endpoint harness.
- Whether BSV is the "right" chain. The review is about this code's
  correctness, not the choice of backend.

## How to verify in minutes

```sh
git clone https://github.com/RobGanon/bsv-ai-security.git
cd bsv-ai-security
python3 -m pytest -q          # expect: 651 passed
```

Full path for reviewers: `docs/reviewer-quickstart.md`.

Live anchors on Teratestnet (public on-chain data, verify against
`https://woc-ttn.bsvblockchain.tech`):

- Anchor #1: `4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029`
  (block 36722), journal seq 1–3, genesis `prev_txid`
- Anchor #2: `d8407bb7a60f23aadcf021e9cb0098c6ae362a519aa04cbd8536265519c09230`
  (block 36723), journal seq 4, `prev_txid` = anchor #1
- Anchor #3: `e3a95a6f1f65651949f8fc6ef1ce22292058502cc6a94aef0fb6a5143ffd28cb`
  (block 37163), journal seq 5, `prev_txid` = anchor #2 — signed by a
  human through the offline-signing ceremony (see
  `docs/offline-signing-handoff.md`), not by the publisher
- Checkpoint block 36721:
  `0000000048cb33f8f96e4927e4e8066742076b180d7091c013e7e36d4b246eae`
- Anchor pubkey:
  `0397315d0180c5f4cf1ea2cd19d683becdb4a978827ab6d8c6cb74b18df29eb58d`

`anchor-chain-verify` with `--spv --anchor-sig --header-chain`
checks inclusion, input signature, and the header chain back to the
checkpoint. The journal and record store for the live chain are
reproducible from the anchor transactions themselves.

## Verification already done (not independent)

What was actually executed, by the author (with AI assistance):

- Adversarial probes against every PR — scenario-based attacks
  (sequence gaps, anchor fuzz, torn appends, successive anchors,
  tampered headers, checkpoint mismatch, over-cap walks, fetch
  errors). Zero cases found of the verifier accepting what it
  should reject. The probes are scenario-based, not exhaustive,
  and zero cases found is not evidence of soundness; there is no
  formal verification.
- Adversarial BSV verification pass (152 executed probes over
  anchor/sighash/Merkle/BUMP/header-chain/BEEF/CLI/decimal/
  broadcaster): no false-accept found. 5 findings, all
  robustness/scope gaps — exception escapes from fail-closed
  verifiers, CLI exit code 0 on failed checks, BEEF ancestry
  accepting consensus-invalid unmined txs, negative `prev_index`
  reading `vout[-1]`, and prev-txid not validated (already known,
  still deferred). The first four were fixed in PR #33 with 31
  regression tests; the prev-txid gap stays deferred pending a
  complete prev-tx fixture.
- Full suite runs on exact merged bytes: 369 tests passing on
  `main` @ `137de50`.

What was **not** counted as executed testing:

- Another AI proposed additional adversarial scenarios but did not
  run the test suite (its own account: partial review only).
  Proposed scenarios are not coverage, so they are not claimed here.
- Another session's test-reporting tooling (PR #15) was never
  executed independently in its environment, and was closed
  unmerged.

The counts above reflect executed tests only. The author's own
testing above is not independent review — which is why this
document exists. Independent review has begun (see below) and is
still in progress.

## Independent review so far

- TruthMachine (Oct 2026) cloned the repo, ran the suite, and found
  a real validation gap: `AnchorSignatureVerifier` did not compare
  the reconstructed txid against the requested txid. Reproduced,
  fixed with an explicit check + regression test. He also flagged
  float-based satoshi parsing; replaced with exact Decimal parsing
  in all three spots (anchor verification ×2, broadcaster ×1).

## Known limitations (please don't re-report these as findings)

- Interrupted journal writes fail closed; there is no automated
  repair path.
- The anchor key sits on the same machine as the publisher, which
  weakens protocol §7. Acceptable for a Teratestnet demo, stated
  in the docs.
- The signer ceremony's recorded expectation (`signer expect`:
  expected payload, previous txid, funding UTXO) lives in the
  signer config as a plain local file, so the expectation the
  human approval is checked against is not itself authenticated
  (A8, accepted). The config sits in the same trust domain as
  the signer binary and its key file: an attacker who can write
  the signer's config is already inside the perimeter the
  ceremony assumes (a dedicated signer machine and user), and
  authenticating the expectation would add a second key to the
  ceremony to defend a surface that perimeter already covers.
  The ceremony's other hard rules (single input, payload
  binding to the journal head, change back to the anchor
  address, one transaction per approval) are enforced from the
  transaction and the journal, not from the config. A
  command-line `--expected-payload` at sign time is an override
  of the recorded expectation and now requires the explicit
  `--override-expected` acknowledgment flag (A9).
- WoC-TTN's unspent index is broken; funding spends a known outpoint
  explicitly.
- SPV header-chain verification validates each header's proof
  of work against that header's own declared `bits`. With
  `--daa mainnet` it additionally validates the difficulty
  schedule: every block above the pinned checkpoint must declare
  exactly the bits the BSV cash DAA (per-block, 144-block
  window, active since height 504032) computes from its
  preceding window inside the walk, and the walk extends 146
  headers below the checkpoint as authenticated inputs so the
  validation is inductive from the pin. Without `--daa`, a
  fabricated chain extending the checkpoint could still declare
  easier targets — the schedule check is required before any
  mainnet reliance, and it is opt-in per network because only
  mainnet's parameters are confirmed (Teratestnet's are not, so
  TTN walks remain linkage + proof-of-work). Cumulative work is
  still not compared across competing chains: a single-source
  walk has nothing to compare against, and detecting a
  schedule-valid fork remains the pinned checkpoint's job.
  (Finding B, surfaced by an outside AI review pass, Oct 2026;
  the fix is verified against the BSV node source and real
  mainnet header windows, including the DAA activation
  boundary.)
- The three live anchors were created manually, ad hoc — the demo
  is not yet anchored on the protocol's §8 cadence
  (`anchor_every_n_events` / `anchor_every_t_seconds`), so the
  unanchored-tail window described in §8 is longer than the policy
  intends. Anchor timing itself is not yet in review scope.

## How to report

File findings on issue #4, or open a PR. There is no bug bounty.
A clean pass is worth reporting too — "no findings in this scope"
is evidence, and we want it distinguished from "never reviewed".
Time estimate (rough): a few hours for the core verifier,
about a day for the full scope above.
