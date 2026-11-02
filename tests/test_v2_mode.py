"""Tests for launch-flow v2 plan items 1-3.

Item 1 — the explicit per-launch mode toggle (v1 preserved exactly).
Item 2 — namespaced, strictly-validated launch/finish/launch-failed events.
Item 3 — the §5.7 journal-writer isolation predicate.

The launcher tests stand in for subprocess.run, exactly as
tests/test_launcher.py does, so the launch contract can be observed
without executing a child. Isolation is monkeypatched only where a real
privileged launcher is required; the predicate itself is tested directly.
"""

import hashlib
import json
import os
import subprocess
import types
import uuid
from pathlib import Path

import pytest
from sealrun.bsv import PrivKey

import sealrun.core as core
import sealrun.launcher as launcher
from sealrun.cli import main
from sealrun.core import (
    V2_FINISH_EVENT_TYPE,
    V2_LAUNCH_EVENT_TYPE,
    V2_LAUNCH_FAILED_EVENT_TYPE,
    VerificationError,
    append_audit_event,
    append_v2_event,
    assert_journal_writer_isolation,
    create_manifest,
    generate_keypair,
    load_private_key,
    manifest_hash,
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
    (root / "config.json").write_text('{"safe":true}\n', encoding="utf-8")
    return root


def make_signed(root: Path, release_id="test-release", release_seq: int = 1):
    private = PrivKey.generate()
    payload = create_manifest(
        root, ["model.bin", "config.json"], release_id, release_seq
    )
    return private, sign_manifest(payload, private)


class _RunSpy:
    def __init__(self, returncode: int = 0):
        self.returncode = returncode
        self.argv = None
        self.env = None
        self.pass_fds = ()
        self.user = None
        self.group = None
        self.extra_groups = None

    def __call__(self, argv, *, pass_fds=(), env=None, user=None, group=None,
                 extra_groups=None, check=False):
        self.argv = list(argv)
        self.pass_fds = tuple(pass_fds)
        self.env = env
        self.user = user
        self.group = group
        self.extra_groups = extra_groups
        return subprocess.CompletedProcess(argv, self.returncode)


class _RaisingSpy:
    def __init__(self, exc: BaseException):
        self.exc = exc

    def __call__(self, *args, **kwargs):
        raise self.exc


def install_spy(monkeypatch, spy) -> None:
    monkeypatch.setattr(launcher, "subprocess", types.SimpleNamespace(run=spy))

    # v2 launches go through the explicit signal-handling wait loop (item 4),
    # not subprocess.run; route them to the same spy.
    def run_v2_child(argv, *, pass_fds, child_env, uid, gid, drop_groups, signals):
        completed = spy(
            argv, pass_fds=pass_fds, env=child_env, user=uid, group=gid,
            extra_groups=drop_groups, check=False,
        )
        return launcher._V2RunResult(completed.returncode, 0, False)

    monkeypatch.setattr(launcher, "_run_v2_child", run_v2_child)


def bypass_isolation(monkeypatch) -> None:
    monkeypatch.setattr(
        launcher, "assert_journal_writer_isolation", lambda *args, **kwargs: None
    )


def read_events(journal: Path) -> list[dict]:
    return [
        json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()
    ]


def launch_detail(run_id=None, **overrides) -> dict:
    detail = {
        "launch_mode": "v2",
        "run_id": run_id or str(uuid.uuid4()),
        "journal_nonce": "a" * 32,
        "manifest_hash": "b" * 64,
        "artifact_count": 2,
        "argv_fingerprint": "c" * 64,
        "env_fingerprint": "d" * 64,
        "executable": "python3",
        "cwd": "/tmp",
        "seal": False,
        "uid": 12345,
        "gid": 12345,
    }
    detail.update(overrides)
    return detail


def finish_detail(run_id=None, **overrides) -> dict:
    detail = {
        "launch_mode": "v2",
        "run_id": run_id or str(uuid.uuid4()),
        "exit_code": 0,
        "launcher_signal": 0,
        "escalated": False,
        "duration_ms": 12,
    }
    detail.update(overrides)
    return detail


def append_raw_event(
    journal: Path, event_type: str, detail_obj, seq: int = 1,
    previous: str | None = None,
) -> None:
    """Append a hand-built event with a valid chain hash.

    Used to prove that the verifier, not just the append path, enforces
    the v2 schema.
    """
    detail = (
        detail_obj
        if isinstance(detail_obj, str)
        else json.dumps(detail_obj, sort_keys=True, separators=(",", ":"))
    )
    event = {
        "seq": seq,
        "event_type": event_type,
        "detail": detail,
        "previous_hash": previous or "0" * 64,
    }
    event["event_hash"] = hashlib.sha256(
        json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    with journal.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        )


# --------------------------------------------------------------------------
# Item 1 — v2 mode toggle
# --------------------------------------------------------------------------

def test_invalid_mode_is_refused(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    with pytest.raises(VerificationError, match="mode"):
        launch(
            root, envelope, private.pubkey_compressed(), ["true"],
            mode="v3",
        )


def test_v1_mode_is_default_and_writes_no_v2_events(tmp_path, monkeypatch):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    spy = _RunSpy()

    def forbidden(*args, **kwargs):
        raise AssertionError("v1 launch must not emit a v2 event")

    install_spy(monkeypatch, spy)
    monkeypatch.setattr(launcher, "append_v2_event", forbidden)
    rc = launch(root, envelope, private.pubkey_compressed(), ["true"])
    assert rc == 0
    assert spy.argv == ["true"]


def test_v1_refuses_a_journal_path(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    with pytest.raises(VerificationError, match="only valid with --mode v2"):
        launch(
            root, envelope, private.pubkey_compressed(), ["true"],
            mode="v1", journal=tmp_path / "audit.jsonl",
        )


def test_v1_refuses_when_deployment_requires_v2(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    with pytest.raises(VerificationError, match="requires v2"):
        launch(
            root, envelope, private.pubkey_compressed(), ["true"],
            mode="v1", require_v2=True,
        )


def test_v2_requires_a_journal(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    with pytest.raises(VerificationError, match="requires --journal"):
        launch(
            root, envelope, private.pubkey_compressed(), ["true"],
            mode="v2", uid=12345, gid=12345,
        )


def test_v2_launch_is_refused_without_isolation(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    journal = tmp_path / "audit.jsonl"
    with pytest.raises(VerificationError):
        launch(
            root, envelope, private.pubkey_compressed(), ["true"],
            mode="v2", journal=journal, uid=12345, gid=12345,
        )
    assert not journal.exists()


def test_v2_mode_writes_launch_and_finish(tmp_path, monkeypatch):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, release_seq=7)
    journal = tmp_path / "audit.jsonl"
    spy = _RunSpy(returncode=7)
    bypass_isolation(monkeypatch)
    install_spy(monkeypatch, spy)

    rc = launch(
        root, envelope, private.pubkey_compressed(), ["python3", "child.py"],
        mode="v2", journal=journal, uid=12345, gid=12345,
    )

    assert rc == 7
    assert spy.user == 12345
    assert spy.group == 12345
    events = read_events(journal)
    assert [event["event_type"] for event in events] == [
        V2_LAUNCH_EVENT_TYPE, V2_FINISH_EVENT_TYPE
    ]
    assert verify_audit_journal(journal) == 2

    recorded = json.loads(events[0]["detail"])
    assert recorded["launch_mode"] == "v2"
    assert recorded["manifest_hash"] == manifest_hash(envelope)
    assert recorded["artifact_count"] == 2
    assert recorded["seal"] is False
    assert recorded["uid"] == 12345
    assert recorded["gid"] == 12345
    assert recorded["executable"] == "python3"
    assert recorded["run_id"] == json.loads(events[1]["detail"])["run_id"]

    finished = json.loads(events[1]["detail"])
    assert finished["exit_code"] == 7
    assert finished["duration_ms"] >= 0


def test_v2_launch_event_is_durable_before_exec(tmp_path, monkeypatch):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    journal = tmp_path / "audit.jsonl"
    bypass_isolation(monkeypatch)

    observed = {}

    class ObservingSpy(_RunSpy):
        def __call__(self, *args, **kwargs):
            observed["events_at_exec"] = [
                event["event_type"] for event in read_events(journal)
            ]
            return super().__call__(*args, **kwargs)

    install_spy(monkeypatch, ObservingSpy())
    rc = launch(
        root, envelope, private.pubkey_compressed(), ["true"],
        mode="v2", journal=journal, uid=12345, gid=12345,
    )
    assert rc == 0
    assert observed["events_at_exec"] == [V2_LAUNCH_EVENT_TYPE]


# --------------------------------------------------------------------------
# Item 2 — journal event schema and namespacing
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "event_type", sorted(core.V2_EVENT_TYPES) + ["v2_custom", "v2_"]
)
def test_audit_append_refuses_the_v2_namespace(tmp_path, event_type):
    journal = tmp_path / "audit.jsonl"
    with pytest.raises(VerificationError, match="reserved v2_ namespace"):
        append_audit_event(journal, event_type, "{}")
    assert not journal.exists()


def test_append_v2_event_refuses_unknown_types(tmp_path):
    journal = tmp_path / "audit.jsonl"
    with pytest.raises(VerificationError, match="unknown v2 event type"):
        append_v2_event(journal, "v2_something", launch_detail())


def test_append_v2_event_refuses_to_create_a_missing_parent(tmp_path):
    with pytest.raises(VerificationError, match="must already exist"):
        append_v2_event(
            tmp_path / "missing" / "audit.jsonl",
            V2_LAUNCH_EVENT_TYPE,
            launch_detail(),
        )


def test_append_v2_event_accepts_launch_and_finish(tmp_path):
    journal = tmp_path / "audit.jsonl"
    run_id = str(uuid.uuid4())
    append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, launch_detail(run_id))
    append_v2_event(journal, V2_FINISH_EVENT_TYPE, finish_detail(run_id))
    assert verify_audit_journal(journal) == 2


@pytest.mark.parametrize(
    "mutator, match",
    [
        (lambda d: d.update({"unexpected": "field"}), "unknown field"),
        (lambda d: d.pop("manifest_hash"), "missing required"),
        (lambda d: d.update({"launch_mode": "v1"}), "launch_mode 'v2'"),
        (lambda d: d.update({"run_id": "not-a-uuid"}), "run_id"),
        (lambda d: d.update({"journal_nonce": "abc"}), "journal_nonce"),
        (lambda d: d.update({"artifact_count": True}), "integer"),
        (lambda d: d.update({"uid": 0}), "between 1"),
        (lambda d: d.update({"argv_fingerprint": "xyz"}), "64-character hex"),
        (lambda d: d.update({"seal": "no"}), "boolean"),
    ],
)
def test_launch_detail_schema_is_strict(tmp_path, mutator, match):
    journal = tmp_path / "audit.jsonl"
    detail = launch_detail()
    mutator(detail)
    with pytest.raises(VerificationError, match=match):
        append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, detail)
    assert not journal.exists()


@pytest.mark.parametrize(
    "detail, match",
    [
        (finish_detail(exit_code="0"), "exit_code"),
        (finish_detail(exit_code=256), "between -255 and 255"),
        (finish_detail(duration_ms=-1), "duration_ms"),
        (finish_detail(launch_mode="v1"), "launch_mode 'v2'"),
        (
            {"launch_mode": "v2", "run_id": str(uuid.uuid4()),
             "stage": "guess", "reason": "x"},
            "stage must be one of",
        ),
        (
            {"launch_mode": "v2", "run_id": str(uuid.uuid4()),
             "stage": "exec", "reason": ""},
            "reason",
        ),
    ],
)
def test_finish_and_failed_schemas_are_strict(tmp_path, detail, match):
    journal = tmp_path / "audit.jsonl"
    event_type = (
        V2_FINISH_EVENT_TYPE
        if "exit_code" in detail or "duration_ms" in detail
        else V2_LAUNCH_FAILED_EVENT_TYPE
    )
    with pytest.raises(VerificationError, match=match):
        append_v2_event(journal, event_type, detail)
    assert not journal.exists()


def test_verifier_rejects_hand_minted_invalid_v2_detail(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_raw_event(journal, V2_LAUNCH_EVENT_TYPE, launch_detail(artifact_count=True))
    with pytest.raises(VerificationError, match="artifact_count"):
        verify_audit_journal(journal)


def test_verifier_rejects_unknown_v2_event_type(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_raw_event(journal, "v2_custom", {"launch_mode": "v2"})
    with pytest.raises(VerificationError, match="unknown v2 event type"):
        verify_audit_journal(journal)


def test_verifier_rejects_duplicate_keys_in_v2_detail(tmp_path):
    journal = tmp_path / "audit.jsonl"
    run_id = str(uuid.uuid4())
    detail = json.dumps(launch_detail(run_id), separators=(",", ":"))
    detail = detail[:-1] + ',"launch_mode":"v2"}'
    append_raw_event(journal, V2_LAUNCH_EVENT_TYPE, detail)
    with pytest.raises(VerificationError, match="duplicate"):
        verify_audit_journal(journal)


def test_legacy_freeform_launch_and_finish_are_not_v2_events(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "launch", "legacy pre-v2 event")
    append_audit_event(journal, "finish", "legacy pre-v2 event")
    assert verify_audit_journal(journal) == 2


def test_legacy_event_without_event_type_still_verifies(tmp_path):
    """V1 never inspected event_type, so v2 must not start rejecting it."""
    journal = tmp_path / "audit.jsonl"
    event = {
        "seq": 1,
        "detail": "pre-v2 record",
        "previous_hash": "0" * 64,
    }
    event["event_hash"] = hashlib.sha256(
        json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    journal.write_text(
        json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    assert verify_audit_journal(journal) == 1


def test_mixed_legacy_and_v2_journal_verifies(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "finish", "legacy pre-v2 event")
    run_id = str(uuid.uuid4())
    append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, launch_detail(run_id))
    append_v2_event(journal, V2_FINISH_EVENT_TYPE, finish_detail(run_id))
    assert verify_audit_journal(journal) == 3


def test_launch_failed_event_is_written_and_reason_preserved(tmp_path, monkeypatch):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    journal = tmp_path / "audit.jsonl"
    bypass_isolation(monkeypatch)
    install_spy(monkeypatch, _RaisingSpy(OSError(2, "No such file or directory")))

    with pytest.raises(VerificationError, match="cannot launch"):
        launch(
            root, envelope, private.pubkey_compressed(), ["missing-binary"],
            mode="v2", journal=journal, uid=12345, gid=12345,
        )

    events = read_events(journal)
    assert [event["event_type"] for event in events] == [
        V2_LAUNCH_EVENT_TYPE, V2_LAUNCH_FAILED_EVENT_TYPE
    ]
    failed = json.loads(events[1]["detail"])
    assert failed["stage"] == "exec"
    assert failed["reason"]
    assert verify_audit_journal(journal) == 2


def test_cli_audit_append_refuses_v2_type(tmp_path, capsys):
    journal = tmp_path / "audit.jsonl"
    rc = main([
        "audit-append",
        "--journal", str(journal),
        "--event-type", "v2_launch",
        "--detail", "{}",
    ])
    assert rc == 1
    assert "reserved v2_ namespace" in capsys.readouterr().err


# --------------------------------------------------------------------------
# Item 1/2 — CLI toggle plumbing
# --------------------------------------------------------------------------

def _write_signed_bundle(tmp_path: Path):
    root = setup_artifacts(tmp_path)
    priv = tmp_path / "private.wif"
    pub = tmp_path / "public.pub"
    generate_keypair(priv, pub)
    payload = create_manifest(root, ["model.bin", "config.json"], "cli-release", 1)
    envelope = sign_manifest(payload, load_private_key(priv))
    manifest = tmp_path / "manifest.signed.json"
    manifest.write_text(json.dumps(envelope), encoding="utf-8")
    return root, manifest, pub


def test_cli_v1_refuses_journal_flag(tmp_path, capsys):
    root, manifest, pub = _write_signed_bundle(tmp_path)
    rc = main([
        "launch",
        "--root", str(root),
        "--manifest", str(manifest),
        "--public-key", str(pub),
        "--journal", str(tmp_path / "audit.jsonl"),
        "--", "true",
    ])
    assert rc == 1
    assert "only valid with --mode v2" in capsys.readouterr().err


def test_cli_require_v2_refuses_v1_invocation(tmp_path, capsys):
    root, manifest, pub = _write_signed_bundle(tmp_path)
    rc = main([
        "launch",
        "--root", str(root),
        "--manifest", str(manifest),
        "--public-key", str(pub),
        "--require-v2",
        "--", "true",
    ])
    assert rc == 1
    assert "requires v2" in capsys.readouterr().err


def test_cli_v2_requires_journal(tmp_path, capsys):
    root, manifest, pub = _write_signed_bundle(tmp_path)
    rc = main([
        "launch",
        "--root", str(root),
        "--manifest", str(manifest),
        "--public-key", str(pub),
        "--mode", "v2",
        "--uid", "12345",
        "--gid", "12345",
        "--", "true",
    ])
    assert rc == 1
    assert "requires --journal" in capsys.readouterr().err


# --------------------------------------------------------------------------
# Item 3 — journal-writer isolation
# --------------------------------------------------------------------------

def isolated_paths(tmp_path, monkeypatch):
    isolated = tmp_path / "isolated"
    isolated.mkdir(mode=0o700)
    journal = isolated / "audit.jsonl"
    journal.write_text("", encoding="utf-8")
    journal.chmod(0o600)
    monkeypatch.setattr(core, "_ancestor_directories", lambda path: [])
    monkeypatch.setattr(core, "_filesystem_type", lambda path: "btrfs")
    return isolated, journal


def test_isolation_predicate_accepts_a_safe_placement(tmp_path, monkeypatch):
    _, journal = isolated_paths(tmp_path, monkeypatch)
    assert_journal_writer_isolation(journal, 65534, launcher_euid=0)


def test_isolation_refuses_unprivileged_launcher(tmp_path, monkeypatch):
    _, journal = isolated_paths(tmp_path, monkeypatch)
    with pytest.raises(VerificationError, match="privileged launcher"):
        assert_journal_writer_isolation(journal, 65534, launcher_euid=1000)


def test_isolation_refuses_missing_child_uid(tmp_path, monkeypatch):
    _, journal = isolated_paths(tmp_path, monkeypatch)
    with pytest.raises(VerificationError, match="requires --uid"):
        assert_journal_writer_isolation(journal, None, launcher_euid=0)


def test_isolation_refuses_child_uid_zero(tmp_path, monkeypatch):
    _, journal = isolated_paths(tmp_path, monkeypatch)
    with pytest.raises(VerificationError, match="uid of 0"):
        assert_journal_writer_isolation(journal, 0, launcher_euid=0)


def test_isolation_refuses_child_uid_equal_to_file_owner(tmp_path, monkeypatch):
    _, journal = isolated_paths(tmp_path, monkeypatch)
    owner = journal.stat().st_uid
    with pytest.raises(VerificationError, match="owned by the child uid"):
        assert_journal_writer_isolation(journal, owner, launcher_euid=0)


def test_isolation_refuses_group_or_world_writable_journal(tmp_path, monkeypatch):
    _, journal = isolated_paths(tmp_path, monkeypatch)
    journal.chmod(0o666)
    with pytest.raises(VerificationError, match="group- or world-writable"):
        assert_journal_writer_isolation(journal, 65534, launcher_euid=0)


def test_isolation_refuses_group_or_world_writable_directory(tmp_path, monkeypatch):
    isolated, journal = isolated_paths(tmp_path, monkeypatch)
    isolated.chmod(0o777)
    with pytest.raises(VerificationError, match="group- or world-writable"):
        assert_journal_writer_isolation(journal, 65534, launcher_euid=0)


def test_isolation_refuses_a_writable_ancestor(tmp_path, monkeypatch):
    _, journal = isolated_paths(tmp_path, monkeypatch)
    bad = tmp_path / "ancestor"
    bad.mkdir(mode=0o777)
    bad.chmod(0o777)
    monkeypatch.setattr(core, "_ancestor_directories", lambda path: [bad])
    with pytest.raises(VerificationError, match="journal ancestor"):
        assert_journal_writer_isolation(journal, 65534, launcher_euid=0)


def test_isolation_refuses_a_symlink_journal(tmp_path, monkeypatch):
    isolated, journal = isolated_paths(tmp_path, monkeypatch)
    journal.unlink()
    journal.symlink_to(isolated / "real.jsonl")
    with pytest.raises(VerificationError, match="symlink"):
        assert_journal_writer_isolation(journal, 65534, launcher_euid=0)


def test_isolation_refuses_a_missing_journal_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "_ancestor_directories", lambda path: [])
    monkeypatch.setattr(core, "_filesystem_type", lambda path: "btrfs")
    journal = tmp_path / "missing" / "audit.jsonl"
    with pytest.raises(VerificationError, match="must already exist"):
        assert_journal_writer_isolation(journal, 65534, launcher_euid=0)


def test_isolation_refuses_acl_bearing_paths(tmp_path, monkeypatch):
    _, journal = isolated_paths(tmp_path, monkeypatch)

    def fake_getxattr(path, name):
        if name in core._ACL_XATTRS:
            return b"acl"
        raise OSError(61, "No data")

    monkeypatch.setattr(core.os, "getxattr", fake_getxattr)
    with pytest.raises(VerificationError, match="ACL"):
        assert_journal_writer_isolation(journal, 65534, launcher_euid=0)


@pytest.mark.parametrize("filesystem", ["nfs", "nfs4", "fuse", "cifs", None])
def test_isolation_refuses_non_ownership_enforcing_filesystems(
    tmp_path, monkeypatch, filesystem
):
    _, journal = isolated_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(core, "_filesystem_type", lambda path: filesystem)
    with pytest.raises(VerificationError, match="filesystem type"):
        assert_journal_writer_isolation(journal, 65534, launcher_euid=0)


def test_real_filesystem_type_is_ownership_enforcing(tmp_path):
    filesystem = core._filesystem_type(tmp_path)
    assert filesystem in core.OWNERSHIP_ENFORCING_FILESYSTEMS


def test_mountinfo_lookup_prefers_the_longest_mount(tmp_path):
    # Pure parser check: nested mount points must not shadow the journal's
    # own filesystem. The fabricated input mirrors /proc/self/mountinfo's
    # field layout and uses a nested path.
    mountinfo = (
        "1 0 0:1 / / rw - overlay overlay rw\n"
        "2 1 0:2 / /tmp rw - tmpfs tmpfs rw\n"
        "3 2 0:3 / /tmp/nested rw - btrfs /dev/x rw\n"
    )
    original = Path.read_text

    def fake_read_text(self, *args, **kwargs):
        if str(self) == "/proc/self/mountinfo":
            return mountinfo
        return original(self, *args, **kwargs)

    monkeypatched = pytest.MonkeyPatch()
    monkeypatched.setattr(Path, "read_text", fake_read_text)
    try:
        assert core._filesystem_type(Path("/tmp/nested/journal")) == "btrfs"
        assert core._filesystem_type(Path("/tmp/other")) == "tmpfs"
    finally:
        monkeypatched.undo()
