# Test reporting

## Automatic reports

The GitHub Actions `Tests` workflow runs pytest on Python 3.10, 3.11, and 3.12. For each run it writes JUnit XML, generates a Markdown summary with the commit SHA, timestamp, environment, counts, and workflow URL, adds the summary to the Actions run, and uploads the XML and report as an artifact for 90 days, including when tests fail.

Open **GitHub → Actions → Tests → a specific run**. Review each Python-version job, the summary, and its `test-evidence-python-*` artifact. A missing result file is marked incomplete, not passing.

## Durable history

After reviewing a run, add a row to [TEST_VALIDATION_HISTORY.md](../TEST_VALIDATION_HISTORY.md) for notable validation milestones or release candidates. Copy counts from the actual run and include the commit SHA and workflow URL. Preserve failures and explain follow-up fixes. Do not copy counts from an unverified PR description.

## Local runs

For a local run, record the actual command, Python version, commit SHA, UTC date, and counts. Do not label a local run as CI or an independent review.

## Security interpretation

Passing tests show that assertions in those tests passed for that code and environment. They do not establish that the project is secure, and they do not replace independent review or missing protocol features such as independent verification of on-chain transaction inclusion.
