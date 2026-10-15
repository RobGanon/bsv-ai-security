# Test and security validation history

This file records notable test and security-validation runs. Detailed per-run evidence is attached to GitHub Actions runs as `test-evidence-python-*` artifacts (retained for 90 days).

## Recording rules

- Record only runs that actually executed; never infer a pass from a PR description.
- Include UTC date, commit SHA, environment, exact counts, workflow link, and test categories.
- Distinguish CI runs, local runs, and independent reviews.
- Skipped or unexecuted tests are not passes. Preserve failure history and document fixes.
- Test count is not a security score. Do not include private keys, credentials, real user data, prompts, or model artifacts.

## History

No verified run is recorded here yet. Populate this table from an actual test report, not an estimate.

| Date (UTC) | Commit SHA | Environment | Reported | Passed | Failed | Errors | Skipped | Categories / notes | Evidence |
|---|---|---|---:|---:|---:|---:|---:|---|---|
| _No verified runs recorded yet._ | — | — | — | — | — | — | — | Add a row after reviewing an actual run. | — |

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
