#!/usr/bin/env python3
"""Create a Markdown summary and a machine-readable JSON report from pytest JUnit XML.

The Markdown report is the human-readable evidence; the JSON report
(``sealrun-verification-report-v1``) carries the same counts and
status, plus per-test outcomes, for machine consumers. Both are
written on every run, including incomplete ones: missing or
unreadable results are INCOMPLETE, never PASS, and reporting itself
never fails the build (the pytest step is the gate, not this script).

A consumer that cannot parse the JSON must treat the report as
INCOMPLETE, not fall back to the Markdown counts. A CI report is
evidence from a GitHub Actions run for a commit, not a cryptographic
proof: it can be reproduced by running the suite locally at the same
commit, and it does not prove the software secure.
"""
from __future__ import annotations

import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "sealrun-verification-report-v1"

LIMITATIONS = [
    "Counts come from pytest JUnit XML for this run and Python version.",
    "Passing tests are evidence only for the checks executed; they do not prove the software secure.",
    "Test categories are not yet separately tagged, so this report does not claim category-level coverage.",
    "Missing or unreadable results are incomplete, never a pass.",
    "This report is evidence from a GitHub Actions run for a commit, not a cryptographic proof; it can be reproduced by running the suite locally at the same commit.",
    "A consumer that cannot parse this JSON must treat the report as INCOMPLETE, not fall back to the Markdown counts.",
]


def _collect_tests(root: ET.Element) -> list[dict]:
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    tests: list[dict] = []
    for suite in suites:
        for case in suite.iter("testcase"):
            name = case.get("name", "")
            classname = case.get("classname", "")
            full_name = f"{classname}::{name}" if classname else name
            if case.find("skipped") is not None:
                outcome = "skipped"
            elif case.find("error") is not None:
                outcome = "error"
            elif case.find("failure") is not None:
                outcome = "failed"
            else:
                outcome = "passed"
            try:
                duration = float(case.get("time", 0) or 0)
            except ValueError:
                duration = 0.0
            tests.append({"name": full_name, "outcome": outcome, "time": duration})
    return tests


def main() -> int:
    results_path = Path(os.environ.get("TEST_RESULT_FILE", "test-results.xml"))
    report_path = Path(os.environ.get("TEST_REPORT_FILE", "test-report.md"))
    json_path = Path(os.environ.get("TEST_JSON_REPORT_FILE", "verification-report.json"))
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

    json_doc: dict = {
        "schema": SCHEMA,
        "repository": repository,
        "commit": sha,
        "workflow_run": {
            "url": run_url if run_id else None,
            "id": run_id if run_id else None,
        },
        "timestamp_utc": timestamp,
        "runner_os": runner_os,
        "python_version": python_version,
        "limitations": list(LIMITATIONS),
    }

    def _write_json(status: str, counts: dict, tests: list[dict], detail: str | None) -> None:
        doc = dict(json_doc)
        doc["status"] = status
        doc["counts"] = counts
        doc["tests"] = tests
        if detail is not None:
            doc["detail"] = detail
        json_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if not results_path.is_file():
        report.extend(["- **Status:** INCOMPLETE — JUnit results file was not produced.",
                       "- **Test counts:** unavailable; no tests are counted as passing.", ""])
        report_path.write_text("\n".join(report), encoding="utf-8")
        _write_json("INCOMPLETE",
                    {"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0},
                    [], "JUnit results file was not produced")
        print("\n".join(report))
        return 0
    try:
        root = ET.parse(results_path).getroot()
    except (ET.ParseError, OSError) as exc:
        report.extend([f"- **Status:** INCOMPLETE — unable to parse JUnit results ({type(exc).__name__}).",
                       "- **Test counts:** unavailable; no tests are counted as passing.", ""])
        report_path.write_text("\n".join(report), encoding="utf-8")
        _write_json("INCOMPLETE",
                    {"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0},
                    [], f"unable to parse JUnit results ({type(exc).__name__})")
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
    json_status = "INCOMPLETE" if tests == 0 else status
    _write_json(json_status,
                {"total": tests, "passed": passed, "failed": failures,
                 "errors": errors, "skipped": skipped},
                _collect_tests(root),
                "zero tests reported" if tests == 0 else None)
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
