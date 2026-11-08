"""Tests for launch-flow v2 plan item 7: run-state verdicts (§5.5).

Exactly four verdicts exist. "Completed" is claimed only when the finish
event is inside an authenticated anchor prefix AND journal-writer
isolation is established, and its wording covers only the direct child's
exit (never setsid/double-fork descendants).
"""

import uuid
from pathlib import Path

import pytest

from sealrun.core import (
    DIRECT_CHILD_SURVIVOR_QUALIFICATION,
    RUN_STATE_COMPLETED,
    RUN_STATE_FAILED_LAUNCH,
    RUN_STATE_INCOMPLETE_UNVERIFIED,
    RUN_STATE_INTERNALLY_CONSISTENT,
    RUN_STATES,
    V2_FINISH_EVENT_TYPE,
    V2_LAUNCH_EVENT_TYPE,
    V2_LAUNCH_FAILED_EVENT_TYPE,
    VerificationError,
    append_audit_event,
    append_v2_event,
    classify_run_states,
    read_journal_prefix,
    verify_run_states,
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def launch_detail(run_id: str | None = None, **overrides) -> dict:
    detail = {
        "launch_mode": "v2",
        "run_id": run_id or str(uuid.uuid4()),
        "journal_nonce": "a" * 32,
        "manifest_hash": "b" * 64,
        "artifact_count": 1,
        "argv_fingerprint": "c" * 64,
        "env_fingerprint": "d" * 64,
        "executable": "true",
        "cwd": "/tmp",
        "seal": False,
        "uid": 12345,
        "gid": 12345,
    }
    detail.update(overrides)
    return detail


def finish_detail(run_id: str | None = None, **overrides) -> dict:
    detail = {
        "launch_mode": "v2",
        "run_id": run_id or str(uuid.uuid4()),
        "exit_code": 0,
        "launcher_signal": 0,
        "escalated": False,
        "duration_ms": 1,
    }
    detail.update(overrides)
    return detail


def failed_detail(run_id: str | None = None, **overrides) -> dict:
    detail = {
        "launch_mode": "v2",
        "run_id": run_id or str(uuid.uuid4()),
        "stage": "exec",
        "reason": "cannot launch 'true'",
    }
    detail.update(overrides)
    return detail


def append_journal(
    journal: Path,
    *,
    terminal: str | None = "finish",
    exit_code: int = 0,
) -> str:
    run_id = str(uuid.uuid4())
    append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, launch_detail(run_id))
    if terminal == "finish":
        append_v2_event(
            journal,
            V2_FINISH_EVENT_TYPE,
            finish_detail(run_id, exit_code=exit_code),
        )
    elif terminal == "failed":
        append_v2_event(
            journal,
            V2_LAUNCH_FAILED_EVENT_TYPE,
            failed_detail(run_id),
        )
    return run_id


# --------------------------------------------------------------------------
# exactly four states
# --------------------------------------------------------------------------

def test_exactly_four_run_states_exist():
    assert RUN_STATES == {
        RUN_STATE_COMPLETED,
        RUN_STATE_INTERNALLY_CONSISTENT,
        RUN_STATE_FAILED_LAUNCH,
        RUN_STATE_INCOMPLETE_UNVERIFIED,
    }
    assert RUN_STATE_COMPLETED == "completed"
    assert RUN_STATE_INTERNALLY_CONSISTENT == "internally consistent, not proven"
    assert RUN_STATE_FAILED_LAUNCH == "failed launch"
    assert RUN_STATE_INCOMPLETE_UNVERIFIED == "incomplete/unverified"


# --------------------------------------------------------------------------
# completed
# --------------------------------------------------------------------------

def test_completed_requires_authenticated_prefix_and_isolation(tmp_path):
    journal = tmp_path / "audit.jsonl"
    run_id = append_journal(journal, exit_code=7)

    result = verify_run_states(
        journal,
        authenticated_prefix_end=2,
        writer_isolation_established=True,
    )

    assert result["run_count"] == 1
    run = result["runs"][0]
    assert run["run_id"] == run_id
    assert run["state"] == RUN_STATE_COMPLETED
    assert run["proven"] is True
    assert run["authenticated_prefix"] is True
    assert run["writer_isolation"] is True
    assert run["terminal_seq"] == 2
    assert run["exit_code"] == 7
    assert "direct child exited with rc 7" in run["summary"]
    assert "isolated launcher attested" in run["summary"]
    assert DIRECT_CHILD_SURVIVOR_QUALIFICATION in run["summary"]
    assert "setsid/double-fork" in run["summary"]
    assert "all work stopped" not in run["summary"]


def test_signal_terminated_child_keeps_the_negative_return_code(tmp_path):
    journal = tmp_path / "audit.jsonl"
    run_id = append_journal(journal, terminal=None)
    append_v2_event(
        journal,
        V2_FINISH_EVENT_TYPE,
        finish_detail(run_id, exit_code=-9, launcher_signal=2, escalated=True),
    )

    run = verify_run_states(
        journal,
        authenticated_prefix_end=2,
        writer_isolation_established=True,
    )["runs"][0]

    assert run["state"] == RUN_STATE_COMPLETED
    assert run["exit_code"] == -9
    assert run["launcher_signal"] == 2
    assert "terminated by signal 9" in run["summary"]
    assert "recorded rc -9" in run["summary"]
    assert "launcher recorded signal 2" in run["summary"]
    assert DIRECT_CHILD_SURVIVOR_QUALIFICATION in run["summary"]


def test_completed_is_not_claimed_without_authenticated_prefix(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_journal(journal)

    run = verify_run_states(
        journal,
        authenticated_prefix_end=1,
        writer_isolation_established=True,
    )["runs"][0]

    assert run["state"] == RUN_STATE_INTERNALLY_CONSISTENT
    assert run["proven"] is False
    assert run["authenticated_prefix"] is False
    assert any("outside any authenticated anchor prefix" in r
               for r in run["reasons"])
    assert "direct child exited with rc 0" in run["summary"]
    assert "not proven" in run["summary"]
    assert DIRECT_CHILD_SURVIVOR_QUALIFICATION in run["summary"]


def test_completed_is_not_claimed_without_writer_isolation(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_journal(journal)

    run = verify_run_states(
        journal,
        authenticated_prefix_end=2,
        writer_isolation_established=False,
    )["runs"][0]

    assert run["state"] == RUN_STATE_INTERNALLY_CONSISTENT
    assert run["proven"] is False
    assert run["writer_isolation"] is False
    assert any("journal-writer isolation is not established" in r
               for r in run["reasons"])


def test_completed_requires_no_pending_fragment_to_upgrade_anything(
    tmp_path,
):
    journal = tmp_path / "audit.jsonl"
    append_journal(journal, exit_code=3)
    with journal.open("ab") as handle:
        handle.write(b'{"seq":3,"event_type":"v2_finish"')

    result = verify_run_states(
        journal,
        authenticated_prefix_end=2,
        writer_isolation_established=True,
    )

    assert result["fragment_bytes"] > 0
    assert result["runs"][0]["state"] == RUN_STATE_COMPLETED


# --------------------------------------------------------------------------
# failed launch
# --------------------------------------------------------------------------

def test_failed_launch_is_one_of_the_four_states_and_reports_proof(
    tmp_path,
):
    journal = tmp_path / "audit.jsonl"
    append_journal(journal, terminal="failed")

    proven = verify_run_states(
        journal,
        authenticated_prefix_end=2,
        writer_isolation_established=True,
    )["runs"][0]
    assert proven["state"] == RUN_STATE_FAILED_LAUNCH
    assert proven["proven"] is True
    assert "no child ran" in proven["summary"]
    assert "isolated launcher attested" in proven["summary"]

    unproven = verify_run_states(
        journal,
        authenticated_prefix_end=1,
        writer_isolation_established=True,
    )["runs"][0]
    assert unproven["state"] == RUN_STATE_FAILED_LAUNCH
    assert unproven["proven"] is False
    assert "not proven as launcher-attested" in unproven["summary"]


# --------------------------------------------------------------------------
# incomplete / unverified
# --------------------------------------------------------------------------

def test_launch_without_a_terminal_is_incomplete_unverified(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_journal(journal, terminal=None)

    result = verify_run_states(
        journal,
        authenticated_prefix_end=1,
        writer_isolation_established=True,
    )

    run = result["runs"][0]
    assert run["state"] == RUN_STATE_INCOMPLETE_UNVERIFIED
    assert run["terminal_seq"] is None
    assert run["proven"] is False
    assert "Incomplete/unverified" in run["summary"]
    assert "completed-but-unrecorded" in run["summary"]


def test_a_torn_terminal_does_not_upgrade_a_launch_to_completed(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_journal(journal, terminal=None)
    with journal.open("ab") as handle:
        handle.write(b'{"seq":2,"event_type":"v2_finish","detail":')

    result = verify_run_states(
        journal,
        authenticated_prefix_end=2,
        writer_isolation_established=True,
    )

    assert result["fragment_bytes"] > 0
    assert result["runs"][0]["state"] == RUN_STATE_INCOMPLETE_UNVERIFIED


# --------------------------------------------------------------------------
# linkage and namespacing
# --------------------------------------------------------------------------

def test_duplicate_launch_run_id_is_a_verification_failure(tmp_path):
    journal = tmp_path / "audit.jsonl"
    run_id = str(uuid.uuid4())
    append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, launch_detail(run_id))
    append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, launch_detail(run_id))

    with pytest.raises(VerificationError, match="duplicate v2 launch run id"):
        verify_run_states(journal)


def test_orphan_terminal_event_is_a_verification_failure(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_v2_event(
        journal, V2_FINISH_EVENT_TYPE, finish_detail(str(uuid.uuid4()))
    )

    with pytest.raises(VerificationError, match="orphan v2 terminal event"):
        verify_run_states(journal)


def test_second_terminal_event_is_a_verification_failure(tmp_path):
    journal = tmp_path / "audit.jsonl"
    run_id = append_journal(journal)
    append_v2_event(
        journal, V2_LAUNCH_FAILED_EVENT_TYPE, failed_detail(run_id)
    )

    with pytest.raises(VerificationError, match="second terminal event"):
        verify_run_states(journal)


def test_legacy_free_form_finish_is_not_a_v2_terminal(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "finish", "legacy pre-v2 event")
    run_id = append_journal(journal)

    result = verify_run_states(
        journal,
        authenticated_prefix_end=3,
        writer_isolation_established=True,
    )

    assert result["run_count"] == 1
    assert result["runs"][0]["run_id"] == run_id
    assert result["runs"][0]["state"] == RUN_STATE_COMPLETED


def test_multiple_runs_are_classified_separately_and_filterable(tmp_path):
    journal = tmp_path / "audit.jsonl"
    completed_run = append_journal(journal)
    incomplete_run = append_journal(journal, terminal=None)

    result = verify_run_states(
        journal,
        authenticated_prefix_end=2,
        writer_isolation_established=True,
    )
    states = {run["run_id"]: run["state"] for run in result["runs"]}
    assert states == {
        completed_run: RUN_STATE_COMPLETED,
        incomplete_run: RUN_STATE_INCOMPLETE_UNVERIFIED,
    }

    filtered = verify_run_states(
        journal,
        authenticated_prefix_end=2,
        writer_isolation_established=True,
        run_id=incomplete_run,
    )
    assert filtered["run_count"] == 1
    assert filtered["runs"][0]["run_id"] == incomplete_run


def test_unknown_run_id_is_a_verification_failure(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_journal(journal)

    with pytest.raises(VerificationError, match="no v2 run with run id"):
        verify_run_states(journal, run_id=str(uuid.uuid4()))


def test_classify_accepts_already_parsed_events(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_journal(journal)
    events, fragment = read_journal_prefix(journal)
    assert fragment is None

    runs = classify_run_states(
        events,
        authenticated_prefix_end=2,
        writer_isolation_established=True,
    )
    assert runs[0]["state"] == RUN_STATE_COMPLETED


# --------------------------------------------------------------------------
# input validation
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value", [-1, True, "2", 1.5])
def test_authenticated_prefix_end_must_be_a_sequence(tmp_path, value):
    journal = tmp_path / "audit.jsonl"
    append_journal(journal)

    with pytest.raises(VerificationError, match="authenticated_prefix_end"):
        verify_run_states(journal, authenticated_prefix_end=value)


@pytest.mark.parametrize("value", [1, "true", None])
def test_writer_isolation_flag_must_be_boolean(tmp_path, value):
    journal = tmp_path / "audit.jsonl"
    append_journal(journal)

    with pytest.raises(VerificationError, match="writer_isolation_established"):
        verify_run_states(journal, writer_isolation_established=value)
