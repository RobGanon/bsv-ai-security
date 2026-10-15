# Test and security validation history

This file records notable test and security-validation runs. Detailed per-run evidence is attached to GitHub Actions runs as `test-evidence-python-*` artifacts (retained for 90 days).

## Recording rules

- Record only runs that actually executed; never infer a pass from a PR description.
- Include UTC date, commit SHA, environment, exact counts, workflow link, and test categories.
- Distinguish CI runs, local runs, and independent reviews.
- Skipped or unexecuted tests are not passes. Preserve failure history and document fixes.
- Test count is not a security score. Do not include private keys, credentials, real user data, prompts, or model artifacts.

## History

Rows below come from actual test reports, not estimates.

| Date (UTC) | Commit SHA | Environment | Reported | Passed | Failed | Errors | Skipped | Categories / notes | Evidence |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| 2026-10-15 | 4fef0615ce9e9e070c0da8f16faca340c7703094 | Local run — Linux (x86_64), Python 3.12.3, `python3 -m pytest -q` | 191 | 191 | 0 | 0 | 0 | Local run (not CI, not an independent review). Categories exercised: unit and integration tests; manifest signatures, hashes, and artifact validation; audit-journal integrity, tampering, and rollback protection; manifest acceptance and release-sequence binding; anchor payload encoding and anchor-chain continuity; adversarial and malformed-input tests; publishing safeguards and explicit failure when broadcasting is unsupported. Independent on-chain inclusion/header verification NOT covered (not implemented). | Local run, no CI workflow |

## Coverage categories to track

- Unit and integration tests
- Manifest signatures, hashes, and artifact validation
- Audit-journal integrity, tampering, and rollback protection
- Manifest acceptance and release-sequence binding
- Anchor payload encoding and anchor-chain continuity
- Independent on-chain inclusion/header verification (when implemented)
- Adversarial and malformed-input tests
- Publishing safeguards and explicit failure when broadcasting is unsupported

A category is covered only when identifiable tests exercise it. Passing tests do not prove the entire project is secure.
