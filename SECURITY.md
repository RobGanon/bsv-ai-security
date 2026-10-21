# Security Policy

## Supported versions

This project is pre-1.0 and has no tagged releases yet. Security fixes
land on `main`, and only the current `main` branch is supported. If you
are testing the project, please test against the latest `main`.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**
Public issues are for bugs and review discussion that are not
security-sensitive.

Use GitHub's private vulnerability reporting instead:
[Report a vulnerability](https://github.com/RobGanon/bsv-ai-security/security/advisories/new).
Only the maintainer sees the report, and we can work on a fix before
anything is public.

A useful report includes:

- the commit hash you tested (`git rev-parse HEAD`)
- the affected component (verifier, launcher, signer, publisher,
  SPV/BEEF verification, key handling)
- what you did, step by step, and what happened
- what you expected to happen instead
- the impact as you see it — what an attacker gains if you are right

## What to expect

- An acknowledgement within 7 days.
- If the report checks out, a fix on `main`, regression tests that fail
  without it, and credit for you in the fix and in REVIEW.md (unless you
  would rather stay anonymous).
- Coordinated disclosure: the details go public once a fix is merged, or
  sooner if we agree on it together.

If your review found nothing, that is still worth hearing about — a
short note saying what you checked and that it held up helps the project
almost as much as a finding. Open a normal issue for that.

## Scope

In scope: anything that breaks a guarantee this project makes in its
README or REVIEW.md — for example, a verification bypass, a forged or
mutated artifact passing verification, a gap in the journal or anchor
chain, a signer rule that can be talked around, or private key material
being read, written, or exposed unsafely.

Out of scope: the limitations already documented in REVIEW.md. Those are
known and stated on purpose — for example, BEEF verification does not
evaluate scripts, and the journal proves a record was not altered, not
that what was recorded is true.

## Testing safely

Test against the Teratestnet (TTN) demo setup described in the docs —
it uses play money only. Please do not test against mainnet, and do not
use real funds or real keys in a test report.
