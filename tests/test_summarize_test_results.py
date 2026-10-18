"""Tests for scripts/summarize_test_results.py (CI evidence reporter).

The reporter is load-bearing for CI evidence: it turns pytest JUnit XML
into a per-version Markdown report. It must never claim a pass it does
not have — missing or unreadable results are INCOMPLETE, never PASS —
and reporting itself must never fail the build (the pytest step is the
gate, not this script).
"""
import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "summarize_test_results.py"

SUITE_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" errors="{errors}" failures="{failures}" skipped="{skipped}" tests="{tests}" time="0.5" timestamp="2026-10-17T00:00:00">
</testsuite>
"""


def load_module():
    spec = importlib.util.spec_from_file_location("summarize_test_results", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_report(monkeypatch, tmp_path, junit_text=None, extra_env=None):
    """Run main() with TEST_RESULT_FILE / TEST_REPORT_FILE pointed at tmp files."""
    module = load_module()
    results_path = tmp_path / "test-results.xml"
    report_path = tmp_path / "test-report.md"
    if junit_text is not None:
        results_path.write_text(junit_text, encoding="utf-8")
    monkeypatch.setenv("TEST_RESULT_FILE", str(results_path))
    monkeypatch.setenv("TEST_REPORT_FILE", str(report_path))
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_REPOSITORY", "RobGanon/bsv-ai-security")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_RUN_ID", "999")
    monkeypatch.setenv("RUNNER_OS", "Linux")
    monkeypatch.setenv("PYTHON_VERSION", "3.12")
    for key, value in (extra_env or {}).items():
        monkeypatch.setenv(key, value)
    return module.main(), report_path


def test_pass_report_counts_passed_minus_skipped(monkeypatch, tmp_path):
    junit = SUITE_TEMPLATE.format(tests=5, failures=0, errors=0, skipped=1)
    rc, report_path = run_report(monkeypatch, tmp_path, junit)
    report = report_path.read_text(encoding="utf-8")
    assert rc == 0
    assert "- **Status:** PASS" in report
    assert "- **Tests reported:** 5" in report
    assert "- **Passed:** 4" in report
    assert "- **Skipped:** 1" in report
    assert "https://github.com/RobGanon/bsv-ai-security/actions/runs/999" in report


def test_fail_report_counts_failures_and_errors(monkeypatch, tmp_path):
    junit = SUITE_TEMPLATE.format(tests=10, failures=2, errors=1, skipped=0)
    rc, report_path = run_report(monkeypatch, tmp_path, junit)
    report = report_path.read_text(encoding="utf-8")
    assert rc == 0  # reporting never fails the build; the pytest step is the gate
    assert "- **Status:** FAIL" in report
    assert "- **Tests reported:** 10" in report
    assert "- **Passed:** 7" in report
    assert "- **Failed:** 2" in report
    assert "- **Errors:** 1" in report


def test_zero_tests_is_incomplete_not_pass(monkeypatch, tmp_path):
    junit = SUITE_TEMPLATE.format(tests=0, failures=0, errors=0, skipped=0)
    rc, report_path = run_report(monkeypatch, tmp_path, junit)
    report = report_path.read_text(encoding="utf-8")
    assert rc == 0
    assert "INCOMPLETE — zero tests reported" in report
    assert "- **Tests reported:** 0" in report
    assert "- **Status:** PASS" not in report


def test_missing_results_file_is_incomplete(monkeypatch, tmp_path):
    rc, report_path = run_report(monkeypatch, tmp_path, junit_text=None)
    report = report_path.read_text(encoding="utf-8")
    assert rc == 0
    assert "INCOMPLETE — JUnit results file was not produced" in report
    assert "unavailable; no tests are counted as passing" in report


def test_corrupt_xml_is_incomplete(monkeypatch, tmp_path):
    rc, report_path = run_report(monkeypatch, tmp_path, junit_text="this is not xml {{{")
    report = report_path.read_text(encoding="utf-8")
    assert rc == 0
    assert "INCOMPLETE — unable to parse JUnit results (ParseError)" in report
    assert "unavailable; no tests are counted as passing" in report


def test_testsuites_wrapper_sums_across_suites(monkeypatch, tmp_path):
    junit = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="a" errors="0" failures="1" skipped="0" tests="3" time="0.1" />
  <testsuite name="b" errors="1" failures="0" skipped="2" tests="4" time="0.1" />
</testsuites>
"""
    rc, report_path = run_report(monkeypatch, tmp_path, junit)
    report = report_path.read_text(encoding="utf-8")
    assert rc == 0
    assert "- **Status:** FAIL" in report
    assert "- **Tests reported:** 7" in report
    assert "- **Passed:** 3" in report
    assert "- **Failed:** 1" in report
    assert "- **Errors:** 1" in report
    assert "- **Skipped:** 2" in report


def test_no_github_run_id_reports_not_running_in_actions(monkeypatch, tmp_path):
    junit = SUITE_TEMPLATE.format(tests=1, failures=0, errors=0, skipped=0)
    # Empty run id -> "Not running in GitHub Actions".
    rc, report_path = run_report(monkeypatch, tmp_path, junit, extra_env={"GITHUB_RUN_ID": ""})
    report = report_path.read_text(encoding="utf-8")
    assert rc == 0
    assert "Not running in GitHub Actions" in report
