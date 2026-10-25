# Reviewer brief — the 15-minute orientation

This is the fast path into [issue #4](https://github.com/RobGanon/bsv-ai-security/issues/4):
what the system claims, what it must be trusted with, what an attacker
would have to break, and where to spend your first hour. It complements
[`REVIEW.md`](../REVIEW.md) (the formal ask and scope) — read this first,
then `REVIEW.md`.

You do not need to trust us. Clone it, run `pytest -q` (see
[`REVIEW.md`](../REVIEW.md) for the expected passing count), and try
to break a claim below.

## What it is, in one paragraph

A Linux-local verifier for AI artifacts plus an optional BSV anchoring
layer. A signed manifest pins the exact model / code / data / config bytes
of a release; a hash-chained journal records events; anchor transactions
commit journal heads and rollback checkpoints to a public chain. A
privileged launcher runs a command against the *verified descriptors* so
there is no re-open-by-path window. The whole claim is about **integrity,
order, and existence** — never truthfulness.

## What it proves (and does not)

| Claim | Mechanism | Weaker than it sounds because |
| --- | --- | --- |
| The launched bytes are the manifest's bytes | SHA-256 over artifact bytes; secp256k1 ECDSA over SHA-256 of the canonical payload; descriptors pinned across `exec` | The key must be trusted out of band; the child can still open other files itself |
| The journal was not edited after an event | `event_hash = sha256(canonical(event))`, chained via `previous_hash` | Says nothing about whether an event is *true* |
| History was not rewritten after anchoring | Anchor commits a head hash; recomputation + on-chain `prev_txid` chaining | Only as strong as your out-of-band trust in the checkpoint |
| An old release cannot be quietly reinstated | Monotonic `release_seq`, anchored checkpoint | The *policy* for the highest accepted seq is the integrator's |

Explicitly **out of scope for the claim**: truthfulness/completeness of
events, sandboxing or containment of the child, privacy (anchored data is
public), private-key protection on the AI host, anchor-publisher liveness,
mainnet (all chain activity here is Teratestnet play money).

## Trusted computing base

A successful attack must not need to compromise anything outside this box;
if it does, that is a trust-assumption question, not a finding (call it out
anyway).

- The verifier binary and Python runtime **on the verifying host**. A local
  administrator can replace these; verification on a compromised host
  proves nothing (stated in `docs/anchoring-protocol.md` §intro).
- The pinned manifest public key, supplied **out of band**. A key shipped
  beside an untrusted manifest is not a trust anchor.
- The pinned block checkpoint (a block hash the verifier walks back to).
- Correctness of SHA-256 and the pure-Python secp256k1 in
  `sealrun/bsv.py` (RFC 6979 signing; low-S enforced on the manifest path).
- BSV proof-of-work, for the anchoring layer's history-integrity claim.

## Adversaries we designed against

1. **Local unprivileged attacker with write access to the artifact tree.**
   Path swaps, symlink/fifo substitution, check-to-use races. Countered by
   signed hashes, `O_NOFOLLOW` opens + `fstat` regular-file checks, and the
   launcher's descriptor handoff.
2. **Local administrator (root) who can rewrite the journal and local
   storage.** Countered *only* by anchoring plus an independent verifier
   with out-of-band anchors. A root attacker on the verifying host wins by
   definition.
3. **Network attacker / malicious WoC endpoint.** Broadcast and block
   fetches go over HTTPS, and an explicit non-HTTPS WoC base URL is
   refused (HTTP only for a loopback host, for tests/dev); inclusion
   is re-verified (SPV / BUMP / BEEF / header chain), so the provider
   is not trusted for correctness.
4. **Holder of a signing key.** Can sign arbitrary manifests; key
   management is out of scope.
5. **Supply chain** (this repo, CI, dependencies). Dependencies are zero by
   design (`dependencies = []`), which keeps this surface small.

## Known gaps — please don't re-report these

`REVIEW.md` §"Out of scope" lists the accepted boundaries (mainnet, BUMP/
BEEF scope, no script evaluation in BEEF, UX/perf, chain choice). In
addition, two things we state plainly so they are not mistaken for novel
findings:

- **The `O_NOFOLLOW` per-component directory walk is incomplete.** A swap
  of an *intermediate* directory component between the walk in
  `_validated_entries` and the open in `_open_verified_fd` is not closed.
  This is defense-in-depth hygiene, **not a content-integrity bypass**:
  acceptance is gated on the signed hash of the bytes actually read, so a
  redirected path can only ever resolve to a file with the expected bytes.
- **Events carry no timestamp.** Ordering is the chain's `seq`;
  authoritative time comes from the confirming block, never the local clock.

## Where to spend your first hour

| File | Why it matters |
| --- | --- |
| `sealrun/core.py` | Manifest verification, canonical JSON, journal chain, `verified_artifacts()` fd handoff |
| `sealrun/launcher.py` | Privileged path: verify → exec on pinned descriptors, sealed-memfd freeze, setuid/setgid drop, env contract |
| `sealrun/bsv.py` | secp256k1, tx build/sign, BIP 143 `SIGHASH_ALL\|FORKID` sighash |
| `sealrun/anchor.py` | Anchor-chain continuity, payload binding, signatures |
| `sealrun/spv.py` / `sealrun/beef.py` | Merkle inclusion, header-chain walk, BUMP/BEEF parsing |
| `sealrun/cli.py` | The `verify` / `launch` / `anchor-*` surfaces (exit codes, fail-closed behavior) |

## High-value attacks to try

Aim at the four success criteria in `REVIEW.md` — the highest-value
finding is **a verifier that accepts what it should reject**. Concretely:

- **Manifest / core:** mutate an artifact; re-spell a base64 signature;
  duplicate a JSON key; path traversal or a symlinked/fifo directory
  component; a manifest with mixed-case or overlong hashes.
- **Journal:** truncate the tail; delete the whole file; reorder or splice
  events; append to an already-corrupt journal; a missing trailing newline.
- **Anchoring:** forge or reorder `prev_txid`; a BUMP/BEEF that claims
  inclusion it cannot prove; a header chain that disagrees with the pinned
  checkpoint; a rolled-back `release_seq` presented as current.
- **Launcher:** artifact paths that collide into one env variable; fd
  leakage into the child; a path swapped after verification; a `--seal`
  bypass; a privilege drop that leaves the child in root's group or with
  root's supplementary groups.

## How to report

File on [issue #4](https://github.com/RobGanon/bsv-ai-security/issues/4) or
open a PR. There is no bug bounty. A minimal reproduction — the input, the
command, and what you expected versus what happened — is worth more than a
prose description. See `docs/reviewer-quickstart.md` for the run-it-yourself
path.
