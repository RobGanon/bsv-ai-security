#!/usr/bin/env python3
"""Create a Markdown summary from pytest JUnit XML."""
from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    results_path = Path(os.environ.get("TEST_RESULT_FILE", "test-results.xml"))
    report_path = Path(os.environ.get("TEST_REPORT_FILE", "test-report.md"))
    sha = os.environ.get("GITHUB_SHA", "unknown")
    repository = os.environ.get("GITHUB_REPOSITORY", "unknown")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"{server}/{repository}/actions/runs/{run_id}" if run_id else "Not running in GitHub Actions"
    python_version = os.environ.get("PYTHON_VERSION", sys.version.split()[0])
    runner_os = os.environ.get("RUNNER_OS", sys.platform)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report = ["# Automated test report", "", f"- **Timestamp (UTC):** {timestamp}",
              f"- **Repository:** {repository}", f"- **Commit:** `{sha}`",
              f"- **Python:** {python_version}", f"- **Runner OS:** {runner_os}",
              f"- **Workflow run:** {run_url}", ""]

    if not results_path.is_file():
        report.extend(["- **Status:** INCOMPLETE — JUnit results file was not produced.",
                       "- **Test counts:** unavailable; no tests are counted as passing.", ""])
        report_path.write_text("\n".join(report), encoding="utf-8")
        print("\n".join(report))
        return 0
    try:
        root = ET.parse(results_path).getroot()
    except (ET.ParseError, OSError) as exc:
        report.extend([f"- **Status:** INCOMPLETE — unable to parse JUnit results ({type(exc).__name__}).",
                       "- **Test counts:** unavailable; no tests are counted as passing.", ""])
        report_path.write_text("\n".join(report), encoding="utf-8")
        print("\n".join(report))
        return 0

    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    tests = sum(int(s.get("tests", 0)) for s in suites)
    failures = sum(int(s.get("failures", 0)) for s in suites)
    errors = sum(int(s.get("errors", 0)) for s in suites)
    skipped = sum(int(s.get("skipped", 0)) for s in suites)
    passed = max(0, tests - failures - errors - skipped)
    status = "PASS" if tests > 0 and failures == 0 and errors == 0 else "FAIL"
    if tests == 0:
        status = "INCOMPLETE — zero tests reported"
    report.extend([f"- **Status:** {status}", f"- **Tests reported:** {tests}",
                   f"- **Passed:** {passed}", f"- **Failed:** {failures}",
                   f"- **Errors:** {errors}", f"- **Skipped:** {skipped}", "",
                   "## Interpretation and limitations", "",
                   "- Counts come from pytest JUnit XML for this run and Python version.",
                   "- Passing tests are evidence only for the checks executed; they do not prove the software secure.",
                   "- Test categories are not yet separately tagged, so this report does not claim category-level coverage.",
                   "- Missing or unreadable results are incomplete, never a pass.", ""])
    report_path.write_text("\n".join(report), encoding="utf-8")
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
