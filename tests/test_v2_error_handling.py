"""Launch-flow v2 plan item 11: launch error handling.

A ``PermissionError`` raised while starting a v2 child can mean two very
different failures:

- the credential drop failed (``exc.filename is None``), or
- the executable could not be executed (``exc.filename`` names it).

The launcher classifies by ``exc.filename``, not by errno, and records
different ``v2_launch_failed`` stages and reasons for each. Both failures
are still fail-closed: the child never runs.
"""

import json
import secrets
import subprocess
from pathlib import Path

import pytest
from sealrun.bsv import PrivKey

import sealrun.launcher as launcher
from sealrun.checkpoint_cache import (
    append_checkpoint_cache,
    cache_key_path,
    load_cache_key,
    write_cache_key,
)
from sealrun.core import (
    V2_LAUNCH_EVENT_TYPE,
    V2_LAUNCH_FAILED_EVENT_TYPE,
    VerificationError,
    create_manifest,
    journal_genesis_identity,
    journal_has_genesis_nonce,
    read_journal_prefix,
    sign_manifest,
    verify_audit_journal,
)
from sealrun.launcher import launch


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def setup_artifacts(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    root.mkdir()
    (root / "model.bin").write_bytes(b"model-v1")
    return root


def make_signed(root: Path, release_seq: int = 0):
    private = PrivKey.generate()
    payload = create_manifest(
        root, ["model.bin"], "error-test-release", release_seq
    )
    return private, sign_manifest(payload, private)


def bypass_isolation(monkeypatch) -> None:
    monkeypatch.setattr(
        launcher, "assert_journal_writer_isolation", lambda *args, **kwargs: None
    )
    # The cache is a second trust store checked under the same §5.7 rules;
    # those also need a privileged launcher, so bypass them together.
    monkeypatch.setattr(
        launcher, "assert_checkpoint_cache_isolation", lambda *args, **kwargs: None
    )


def deployment_key(cache: Path) -> bytes:
    """The deployment key for a fixture cache, beside it like bootstrap writes."""
    key_path = cache_key_path(cache)
    if key_path.exists():
        return load_cache_key(key_path)
    key = secrets.token_bytes(32)
    write_cache_key(key_path, key)
    return key


def write_checkpoint(tmp_path: Path, journal: Path) -> Path:
    path = tmp_path / "checkpoint.jsonl"
    events, _fragment = read_journal_prefix(journal)
    if not journal_has_genesis_nonce(events):
        # No v2 identity yet: the cache cannot exist (§7 decision d), so
        # the launch below takes the first-launch exception.
        return path
    append_checkpoint_cache(
        path,
        release_seq=0,
        anchor_end_seq=len(events),
        head_hash=events[-1]["event_hash"] if events else "0" * 64,
        key=deployment_key(path),
        journal_identity=journal_genesis_identity(events)["identity"],
    )
    return path


def install_raising_child(monkeypatch, exc: BaseException) -> None:
    def run_v2_child(argv, *, pass_fds, child_env, uid, gid, drop_groups,
                     signals, exec_hook=None):
        raise exc

    monkeypatch.setattr(launcher, "_run_v2_child", run_v2_child)


def read_events(journal: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in journal.read_text(encoding="utf-8").splitlines()
    ]


def failed_event(journal: Path) -> dict:
    events = read_events(journal)
    assert [event["event_type"] for event in events] == [
        V2_LAUNCH_EVENT_TYPE,
        V2_LAUNCH_FAILED_EVENT_TYPE,
    ]
    assert verify_audit_journal(journal) == len(events)
    return json.loads(events[-1]["detail"])


def run_with_error(tmp_path, monkeypatch, exc: BaseException):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    journal = tmp_path / "audit.jsonl"
    bypass_isolation(monkeypatch)
    install_raising_child(monkeypatch, exc)
    with pytest.raises(VerificationError) as raised:
        launch(
            root,
            envelope,
            private.pubkey_compressed(),
            ["does-not-matter"],
            mode="v2",
            journal=journal,
            uid=12345,
            gid=12345,
            min_release_seq=0,
            checkpoint_cache=write_checkpoint(tmp_path, journal),
        )
    return raised.value, failed_event(journal)


# --------------------------------------------------------------------------
# PermissionError classification
# --------------------------------------------------------------------------

def test_permission_error_without_filename_is_a_privilege_drop_failure(
    tmp_path, monkeypatch
):
    exc = PermissionError(1, "Operation not permitted")
    assert exc.filename is None

    error, failed = run_with_error(tmp_path, monkeypatch, exc)

    assert "cannot drop privileges" in str(error)
    assert "cannot launch" not in str(error)
    assert failed["stage"] == "privilege_drop"
    assert "cannot drop privileges" in failed["reason"]
    assert "cannot launch" not in failed["reason"]


def test_permission_error_with_filename_is_an_exec_failure(
    tmp_path, monkeypatch
):
    exc = PermissionError(13, "Permission denied", "does-not-matter")
    assert exc.filename == "does-not-matter"

    error, failed = run_with_error(tmp_path, monkeypatch, exc)

    assert "cannot launch 'does-not-matter'" in str(error)
    assert "cannot drop privileges" not in str(error)
    assert failed["stage"] == "exec"
    assert "cannot launch 'does-not-matter'" in failed["reason"]
    assert "cannot drop privileges" not in failed["reason"]


def test_classification_uses_filename_not_errno(tmp_path, monkeypatch):
    """Same errno, opposite stages: only ``exc.filename`` distinguishes them."""
    drop_base = tmp_path / "drop"
    drop_base.mkdir()
    exec_base = tmp_path / "exec"
    exec_base.mkdir()

    drop = PermissionError(13, "Permission denied")
    assert drop.errno == 13 and drop.filename is None
    drop_error, drop_failed = run_with_error(drop_base, monkeypatch, drop)

    exec_exc = PermissionError(13, "Permission denied", "does-not-matter")
    exec_error, exec_failed = run_with_error(exec_base, monkeypatch, exec_exc)

    assert drop_failed["stage"] == "privilege_drop"
    assert exec_failed["stage"] == "exec"
    assert drop_failed["reason"] != exec_failed["reason"]
    assert "cannot drop privileges" in str(drop_error)
    assert "cannot launch" in str(exec_error)


def test_exec_permission_error_reports_the_requested_command(
    tmp_path, monkeypatch
):
    exc = PermissionError(13, "Permission denied", "/srv/release/model")
    _error, failed = run_with_error(tmp_path, monkeypatch, exc)

    assert failed["stage"] == "exec"
    assert failed["reason"].startswith("cannot launch 'does-not-matter'")
    assert "Permission denied" in failed["reason"]


def test_non_permission_oserror_still_classifies_as_exec(tmp_path, monkeypatch):
    exc = FileNotFoundError(2, "No such file or directory", "does-not-matter")
    error, failed = run_with_error(tmp_path, monkeypatch, exc)

    assert failed["stage"] == "exec"
    assert "cannot launch 'does-not-matter'" in failed["reason"]
    assert "cannot drop privileges" not in str(error)
