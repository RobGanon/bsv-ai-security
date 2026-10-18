# Reviewer quickstart — verify this repo in about 5 minutes

No trust needed: run it yourself.

## 1. Run the suite (2 minutes)

```sh
git clone https://github.com/RobGanon/bsv-ai-security.git
cd bsv-ai-security
python3 -m pip install -e ".[test]"
python3 -m pytest -q          # expect: 362 passed
```

Python 3.10+. CI runs the same suite on 3.10, 3.11, and 3.12 on
every pull request (`.github/workflows/tests.yml`). Tests are not
claimed to have passed until you run them in your environment — if
the suite does not pass in yours, that is a finding too; report it.

## 2. Know what you are looking at

- `REVIEW.md` — the review ask: scope, what "good" looks like, and
  known limitations (please don't re-report those as findings).
- `docs/anchoring-protocol.md` — the protocol: what an anchor proves
  (history integrity and existence — NOT truthfulness).
- The verifier core: `aiguard/core.py` (manifests, journal), `aiguard/publisher.py`
  and `aiguard/publishing.py` (acceptance + anchor prep),
  `aiguard/anchor.py` (anchor-chain checks), `aiguard/bsv.py` (minimal
  BSV primitives, BIP 143 sighash), `aiguard/spv.py` (Merkle inclusion,
  header-chain walk, BUMP proofs), `aiguard/beef.py` (BEEF envelope
  parse/verify), `aiguard/cli.py` (the `anchor-chain-verify` surface).

## 3. Try to break it

Pick one case from `REVIEW.md` ("What 'good' looks like"): craft an
input the verifier should reject — a bad manifest, a tampered
journal, a broken chain, a forged anchor — and see whether it accepts
it. A verifier that accepts what it should reject is the finding that
matters. The tests in `tests/` show the shape of these probes.

## 4. Spot-check the live anchors (optional)

Two real Teratestnet anchors (public on-chain data, viewable at
`https://woc-ttn.bsvblockchain.tech`):

- Anchor #1: `4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029`
  (block 36722), journal seq 1–3, genesis `prev_txid`
- Anchor #2: `d8407bb7a60f23aadcf021e9cb0098c6ae362a519aa04cbd8536265519c09230`
  (block 36723), journal seq 4, `prev_txid` = anchor #1
- Checkpoint block 36721:
  `0000000048cb33f8f96e4927e4e8066742076b180d7091c013e7e36d4b246eae`

Confirm the transactions exist with the stated blocks. Note the
honest limit: the full `anchor-chain-verify` CLI check needs the
operator's journal and record store, which are not in this repo —
so the explorer check is the reproducible part from outside.

## 5. Report

File findings on
[issue #4](https://github.com/RobGanon/bsv-ai-security/issues/4),
or open a PR. There is no bug bounty. Time estimate (rough): a few
hours for the core verifier, about a day for the full scope in
`REVIEW.md`.
