# Pilot program: prove what your AI actually ran

## The problem

After the fact, AI teams can't show exactly what code, model, data, and
config a run used — or that the record describing it wasn't rewritten
afterwards. When an auditor, a customer, or your own future self asks
"show me exactly what ran," most teams have only their word.

## The pilot

Run the signed-manifest verifier + tamper-evident journal + rollback
protection on one real pipeline for 30 days. No blockchain required to
start — the local trust core works on its own. Anchoring is an optional
upgrade later, for proof that holds up against your own administrators.

## What we measure, before and after

- Hours to assemble audit evidence for one run.
- Time to reconstruct what a past run actually used.
- Time to scope what a bad run touched.

## What the pilot team gets

A working setup on their pipeline, the before/after measurements, and a
written summary they can use internally.

## Honest limits

- 316 tests passing.
- Independent security review still open (issue #4).
- Two live anchors confirmed on Teratestnet (demo chain); mainnet
  anchoring is a later step, not part of the pilot.
- Proves what ran — does *not* certify compliance, and does not stop
  data scraping.
- No quantified case study exists until a pilot measures one.

## The ask

One AI team willing to run it on one pipeline for 30 days and share the
before/after numbers. Pilot length and any support terms are agreed
with the team — nothing is promised here beyond the pilot as described.

Interested? Open an issue on this repository.
