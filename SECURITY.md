# Security Policy

## Supported versions

This project is pre-1.0. A research preview is tagged
`v0.4.0-preview`. Security fixes land on `main`, and only the
current `main` branch is supported. If you are testing the project,
please test against the latest `main`.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**
Public issues are for bugs and review discussion that are not
security-sensitive — and only after triage (see below).

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

## Reporting other testing feedback

During the research preview, general testing feedback also starts
private, because a tester cannot always tell a security flaw from
an ordinary bug before reporting it.

Invited testers: report bugs, install problems, unclear docs, UX
friction, and feature requests in the private tester repository,
[bsv-ai-security-testers](https://github.com/RobGanon/bsv-ai-security-testers)
(invite-only; the link works only for invited testers). Do not post
security findings there — use private vulnerability reporting above.

An item moves to the public repo only after the maintainer has
triaged it (reproduced, confirmed it is not a security issue, and,
where credit is involved, confirmed the reporter's consent).

## What to expect

- All reports — security and general testing feedback — are
  handled best-effort, with no promised response time.
- If a security report checks out, a fix on `main`, regression
  tests that fail without it, and credit under the credit policy
  below (unless you would rather stay anonymous).
- Coordinated disclosure: the details go public once a fix is
  merged, or sooner if we agree on it together.

If your review found nothing, that is still worth hearing about — a
short note saying what you checked and that it held up helps the
project almost as much as a finding. During the preview, send that
note through the private tester repository, not a public issue.

## Credit

Credit is attribution only — not payment, employment, or
endorsement. See the full credit policy in
[docs/feedback-and-credit-policy.md](docs/feedback-and-credit-policy.md).
In short: a verified contribution earns a listing only with the
contributor's approval, using the name/handle they choose, and
approval is per venue. No one adds themselves to the list. The
maintainer may amend or remove an entry for a false or
misattributed contribution, gaming, misuse of the listing,
withdrawn approval, or a plain error; removal reasons are recorded
privately, not aired publicly.

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
