"""Tests for launch-flow v2 plan item 6: journal durability (§6.1).

Covers directory fsync on journal creation, the detached channel-list write
protocol and its verification (missing means missing, never reconstructed),
the torn-line rule and torn-tolerant prefix primitive, reading prior events
from the locked descriptor plus the pre-open inode rule, and the launch cap
that reserves two slots for launch + finish.
"""

import hashlib
import json
import os
import uuid
from pathlib import Path

import pytest

import sealrun.core as core
import sealrun.launcher as launcher
from sealrun.checkpoint_cache import append_checkpoint_cache
from sealrun.cli import main
from sealrun.core import (
    V2_FINISH_EVENT_TYPE,
    V2_LAUNCH_EVENT_TYPE,
    VerificationError,
    append_audit_event,
    append_v2_event,
    canonical_json_bytes,
    create_manifest,
    generate_keypair,
    load_channel_list,
    load_private_key,
    pin_journal_identity,
    read_journal_prefix,
    sign_manifest,
    verify_audit_journal,
    verify_audit_journal_report,
    verify_audit_prefix,
    write_detached_channel_list,
)
from sealrun.launcher import artifact_env_name, launch


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


def read_events(journal: Path) -> list[tuple[str, dict]]:
    return [
        (event["event_type"], json.loads(event["detail"]))
        for event in map(json.loads, journal.read_text(encoding="utf-8").splitlines())
    ]


class _RunSpy:
    def __init__(self, returncode: int = 0):
        self.returncode = returncode
        self.pass_fds = ()

    def __call__(self, argv, *, pass_fds, child_env, uid, gid, drop_groups,
                 signals, exec_hook=None):
        self.pass_fds = tuple(pass_fds)
        return launcher._V2RunResult(self.returncode, 0, False)


class Bundle:
    def __init__(self, base: Path, files: dict[str, bytes], uid: int, gid: int):
        self.base = base
        self.root = base / "root"
        self.root.mkdir(parents=True)
        for relative, data in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.private_path = base / "private.wif"
        self.public = base / "public.pub"
        generate_keypair(self.private_path, self.public)
        self.private = load_private_key(self.private_path)
        payload = create_manifest(
            self.root, list(files), "journal-durability-release", 1
        )
        self.envelope = sign_manifest(payload, self.private)
        self.journal = base / "audit.jsonl"
        self.checkpoint = base / "checkpoint.jsonl"
        self.uid = uid
        self.gid = gid

    def _write_checkpoint(self) -> None:
        events, _fragment = read_journal_prefix(self.journal)
        append_checkpoint_cache(
            self.checkpoint,
            release_seq=0,
            anchor_end_seq=len(events),
            head_hash=events[-1]["event_hash"] if events else "0" * 64,
        )

    def run(self, command=("true",), **kwargs):
        self._write_checkpoint()
        return launch(
            self.root,
            self.envelope,
            self.private.pubkey_compressed(),
            list(command),
            mode="v2",
            journal=self.journal,
            uid=self.uid,
            gid=self.gid,
            min_release_seq=0,
            checkpoint_cache=self.checkpoint,
            env={"PATH": "/usr/bin:/bin"},
            **kwargs,
        )


@pytest.fixture
def make_bundle(tmp_path, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("the fake child runs as the test uid; v2 refuses child uid 0")
    monkeypatch.setattr(
        launcher, "assert_journal_writer_isolation", lambda *args, **kwargs: None
    )
    # The cache is a second trust store checked under the same §5.7 rules;
    # those also need a privileged launcher, so bypass them together.
    monkeypatch.setattr(
        launcher, "assert_checkpoint_cache_isolation", lambda *args, **kwargs: None
    )
    spy = _RunSpy()
    monkeypatch.setattr(launcher, "_run_v2_child", spy)
    counter = 0

    def make(files: dict[str, bytes]) -> Bundle:
        nonlocal counter
        counter += 1
        return Bundle(
            tmp_path / f"bundle{counter}",
            files,
            child_uid_other_than_owner(),
            os.getgid() + 1,
        )

    make.spy = spy
    return make


def child_uid_other_than_owner() -> int:
    return os.getuid() + 1


# --------------------------------------------------------------------------
# directory durability
# --------------------------------------------------------------------------

def test_new_journal_creation_fsyncs_its_directory(tmp_path, monkeypatch):
    journal = tmp_path / "audit.jsonl"
    synced: list[Path] = []
    monkeypatch.setattr(core, "_fsync_directory", synced.append)

    append_audit_event(journal, "test", "created")

    assert journal.exists()
    assert journal.parent in synced


def test_launch_creation_fsyncs_the_journal_directory(make_bundle, monkeypatch):
    bundle = make_bundle({"model.bin": b"model"})
    synced: list[Path] = []
    monkeypatch.setattr(core, "_fsync_directory", synced.append)

    assert bundle.run() == 0

    assert bundle.journal.parent in synced


def test_pin_creation_fsyncs_the_journal_directory(tmp_path, monkeypatch):
    journal = tmp_path / "audit.jsonl"
    synced: list[Path] = []
    monkeypatch.setattr(core, "_fsync_directory", synced.append)

    identity = pin_journal_identity(journal, create=True)

    assert journal.exists()
    assert identity.file_inode == journal.stat().st_ino
    assert journal.parent in synced


# --------------------------------------------------------------------------
# append atomicity: locked fd and pre-open inode rule
# --------------------------------------------------------------------------

def test_prior_events_are_read_from_the_locked_fd_not_the_path(
    tmp_path, monkeypatch
):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")

    def forbidden(path):
        raise AssertionError("append must not re-read the journal by path")

    monkeypatch.setattr(core, "_read_jsonl", forbidden)
    append_audit_event(journal, "test", "two")

    events, fragment = read_journal_prefix(journal)
    assert [event["detail"] for event in events] == ["one", "two"]
    assert fragment is None


def test_pinned_identity_refuses_a_pre_open_journal_replacement(
    tmp_path, monkeypatch
):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "original")
    identity = pin_journal_identity(journal)

    replacement = tmp_path / "replacement.jsonl"
    append_audit_event(replacement, "test", "replacement")
    os.replace(replacement, journal)

    with pytest.raises(VerificationError, match="replaced after it was pinned"):
        append_v2_event(
            journal,
            V2_FINISH_EVENT_TYPE,
            finish_detail(),
            journal_identity=identity,
        )
    assert "v2_finish" not in journal.read_text(encoding="utf-8")


def test_pinned_identity_refuses_a_pre_open_parent_replacement(
    tmp_path, monkeypatch
):
    isolated = tmp_path / "isolated"
    isolated.mkdir()
    journal = isolated / "audit.jsonl"
    append_audit_event(journal, "test", "original")
    identity = pin_journal_identity(journal)

    isolated.rename(tmp_path / "old")
    isolated.mkdir()
    append_audit_event(journal, "test", "replacement")

    with pytest.raises(VerificationError, match="directory .* was replaced"):
        append_v2_event(
            journal,
            V2_FINISH_EVENT_TYPE,
            finish_detail(),
            journal_identity=identity,
        )


def test_pinned_identity_refuses_a_journal_that_appeared_after_the_check(
    tmp_path, monkeypatch
):
    journal = tmp_path / "audit.jsonl"
    identity = pin_journal_identity(journal)
    assert identity.file_inode is None
    append_audit_event(journal, "test", "appeared")

    with pytest.raises(VerificationError, match="appeared after the isolation check"):
        append_v2_event(
            journal,
            V2_FINISH_EVENT_TYPE,
            finish_detail(),
            journal_identity=identity,
        )


def test_pinned_journal_vanishing_at_open_is_not_recreated(
    tmp_path, monkeypatch
):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "original")
    identity = pin_journal_identity(journal)

    real_check = core._assert_journal_identity_before_open

    def check_then_vanish(path, pinned):
        must_create = real_check(path, pinned)
        path.unlink()
        return must_create

    monkeypatch.setattr(
        core, "_assert_journal_identity_before_open", check_then_vanish
    )

    with pytest.raises(VerificationError):
        append_v2_event(
            journal,
            V2_FINISH_EVENT_TYPE,
            finish_detail(),
            journal_identity=identity,
        )
    assert not journal.exists()


# --------------------------------------------------------------------------
# torn-line rule and torn-tolerant prefix primitive
# --------------------------------------------------------------------------

def test_complete_json_without_a_trailing_newline_is_an_event(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    append_audit_event(journal, "test", "two")
    journal.write_bytes(journal.read_bytes()[:-1])

    events, fragment = read_journal_prefix(journal)
    assert len(events) == 2
    assert fragment is None
    assert verify_audit_journal(journal) == 2
    assert verify_audit_prefix(journal)["events"] == 2


def test_incomplete_final_json_is_a_fragment_not_an_event(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    append_audit_event(journal, "test", "two")
    with journal.open("ab") as handle:
        handle.write(b'{"seq":3,"event_type":"test"')

    events, fragment = read_journal_prefix(journal)
    assert len(events) == 2
    assert fragment == b'{"seq":3,"event_type":"test"'
    assert verify_audit_prefix(journal)["fragment_bytes"] == len(fragment)
    assert verify_audit_journal_report(journal)["fragment_bytes"] == len(fragment)

    # The strict verifier still refuses an incomplete line; only the
    # prefix primitive tolerates it.
    with pytest.raises(VerificationError, match="invalid JSON"):
        verify_audit_journal(journal)


def test_anchor_prefix_verification_reports_a_torn_tail_without_raising(
    tmp_path,
):
    from sealrun.anchor import create_anchor_payload, verify_journal_against_anchor

    journal = tmp_path / "audit.jsonl"
    for detail in ("one", "two", "three"):
        append_audit_event(journal, "test", detail)
    payload = bytes.fromhex(create_anchor_payload(journal, start_seq=1)["payload_hex"])
    with journal.open("ab") as handle:
        handle.write(b'{"seq":4,"event_type":')

    result = verify_journal_against_anchor(journal, payload)
    assert result["verified"] is True
    assert result["journal_events"] == 3
    assert result["journal_fragment_bytes"] > 0


# --------------------------------------------------------------------------
# channel list: inline versus detached, protocol, verification
# --------------------------------------------------------------------------

def test_small_channel_list_is_inline_and_verifies(make_bundle):
    files = {"model.bin": b"model-v1", "config.json": b'{"safe":true}\n'}
    bundle = make_bundle(files)
    assert bundle.run() == 0

    launch_event, _ = read_events(bundle.journal)
    recorded = launch_event[1]
    assert "channel_list" in recorded
    assert "channel_list_sha256" not in recorded
    assert "channel_list_file" not in recorded
    assert len(recorded["channel_list"]) == 2
    for record in recorded["channel_list"]:
        assert set(record) == {"path", "env", "sha256", "fd"}
        assert record["env"] == artifact_env_name(record["path"])
        assert record["sha256"] == hashlib.sha256(files[record["path"]]).hexdigest()
        assert record["fd"] in make_bundle.spy.pass_fds

    report = verify_audit_journal_report(bundle.journal)
    assert report["channel_lists"][0]["present"] is True
    assert report["channel_lists"][0]["inline"] is True
    assert len(report["channel_lists"][0]["records"]) == 2


def test_large_channel_list_is_detached_and_verifies(make_bundle):
    files = {f"artifact-{index:02d}.bin": f"value-{index}".encode()
             for index in range(40)}
    bundle = make_bundle(files)
    assert bundle.run() == 0

    launch_event, _ = read_events(bundle.journal)
    recorded = launch_event[1]
    assert "channel_list" not in recorded
    assert recorded["channel_list_file"] == (
        f"{bundle.journal.name}.channels.{recorded['run_id']}.json"
    )
    side_file = bundle.journal.parent / recorded["channel_list_file"]
    side_bytes = side_file.read_bytes()
    assert hashlib.sha256(side_bytes).hexdigest() == recorded["channel_list_sha256"]
    side_records = json.loads(side_bytes)
    assert len(side_records) == 40
    assert {record["path"] for record in side_records} == set(files)

    report = verify_audit_journal_report(bundle.journal)
    entry = report["channel_lists"][0]
    assert entry["present"] is True
    assert entry["inline"] is False
    assert len(entry["records"]) == 40


def test_missing_detached_channel_list_is_reported_not_reconstructed(
    make_bundle, capsys
):
    files = {f"artifact-{index:02d}.bin": f"value-{index}".encode()
             for index in range(40)}
    bundle = make_bundle(files)
    assert bundle.run() == 0
    recorded = read_events(bundle.journal)[0][1]
    (bundle.journal.parent / recorded["channel_list_file"]).unlink()

    # The hash chain is intact; the map is simply gone.
    assert verify_audit_journal(bundle.journal) == 2
    report = verify_audit_journal_report(bundle.journal)
    entry = report["channel_lists"][0]
    assert entry["present"] is False
    assert entry["records"] is None
    assert "missing" in entry["reason"]

    assert main(["audit-verify", "--journal", str(bundle.journal)]) == 0
    output = capsys.readouterr().out
    assert "CHANNEL LIST MISSING" in output
    assert "not reconstructable" in output


def test_detached_map_refuses_a_directory_that_became_child_writable(
    make_bundle,
):
    files = {f"artifact-{index:02d}.bin": f"value-{index}".encode()
             for index in range(40)}
    bundle = make_bundle(files)
    assert bundle.run() == 0
    bundle.journal.parent.chmod(0o777)

    with pytest.raises(VerificationError, match="group- or world-writable"):
        verify_audit_journal_report(bundle.journal)


def test_detached_channel_list_write_protocol(tmp_path):
    journal = tmp_path / "audit.jsonl"
    journal.write_text("", encoding="utf-8")
    journal.chmod(0o600)
    run_id = str(uuid.uuid4())
    records = [
        {
            "path": "model.bin",
            "env": "SEALRUN_ARTIFACT_MODEL_BIN",
            "sha256": "a" * 64,
            "fd": 3,
        }
    ]
    name, digest = write_detached_channel_list(
        journal,
        run_id,
        records,
        child_uid=child_uid_other_than_owner(),
    )

    path = journal.parent / name
    assert name == f"{journal.name}.channels.{run_id}.json"
    assert digest == hashlib.sha256(canonical_json_bytes(records)).hexdigest()
    assert path.read_bytes() == canonical_json_bytes(records)
    assert stat_mode(path) & 0o022 == 0

    with pytest.raises(VerificationError, match="cannot create"):
        write_detached_channel_list(
            journal,
            run_id,
            records,
            child_uid=child_uid_other_than_owner(),
        )


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_replacing_the_side_file_during_the_write_does_not_commit_it(
    tmp_path, monkeypatch
):
    journal = tmp_path / "audit.jsonl"
    journal.write_text("", encoding="utf-8")
    run_id = str(uuid.uuid4())
    records = [
        {
            "path": "model.bin",
            "env": "SEALRUN_ARTIFACT_MODEL_BIN",
            "sha256": "a" * 64,
            "fd": 3,
        }
    ]
    original_digest = hashlib.sha256(canonical_json_bytes(records)).hexdigest()

    real_write_all = core._write_all_fd

    def write_then_replace(fd, data):
        real_write_all(fd, data)
        path = journal.parent / f"{journal.name}.channels.{run_id}.json"
        path.write_bytes(b"attacker replacement")

    monkeypatch.setattr(core, "_write_all_fd", write_then_replace)

    name, digest = write_detached_channel_list(
        journal, run_id, records, child_uid=child_uid_other_than_owner()
    )
    assert digest == original_digest

    detail = {
        "artifact_count": 1,
        "run_id": run_id,
        "channel_list_file": name,
        "channel_list_sha256": digest,
    }
    with pytest.raises(VerificationError, match="hash does not match"):
        load_channel_list(journal, detail)


def test_detached_channel_list_refuses_a_child_writable_directory(tmp_path):
    isolated = tmp_path / "isolated"
    isolated.mkdir()
    isolated.chmod(0o777)
    journal = isolated / "audit.jsonl"
    journal.write_text("", encoding="utf-8")

    with pytest.raises(VerificationError, match="group- or world-writable"):
        write_detached_channel_list(
            journal,
            str(uuid.uuid4()),
            [
                {
                    "path": "model.bin",
                    "env": "SEALRUN_ARTIFACT_MODEL_BIN",
                    "sha256": "a" * 64,
                    "fd": 3,
                }
            ],
            child_uid=child_uid_other_than_owner(),
        )


def test_detached_channel_list_verification_refuses_a_hash_mismatch(
    make_bundle,
):
    files = {f"artifact-{index:02d}.bin": f"value-{index}".encode()
             for index in range(40)}
    bundle = make_bundle(files)
    assert bundle.run() == 0
    recorded = read_events(bundle.journal)[0][1]
    side_file = bundle.journal.parent / recorded["channel_list_file"]
    side_file.write_bytes(b"rewritten")

    with pytest.raises(VerificationError, match="hash does not match"):
        verify_audit_journal_report(bundle.journal)


def test_detached_channel_list_filename_must_match_the_run(make_bundle):
    files = {f"artifact-{index:02d}.bin": f"value-{index}".encode()
             for index in range(40)}
    bundle = make_bundle(files)
    assert bundle.run() == 0
    recorded = read_events(bundle.journal)[0][1]
    recorded["channel_list_file"] = "elsewhere.json"
    with pytest.raises(VerificationError, match="channel_list_file must be"):
        load_channel_list(bundle.journal, recorded)


@pytest.mark.parametrize(
    "mutator, match",
    [
        (lambda d: d.update({"channel_list": [{"path": "x"}]}), "missing field"),
        (
            lambda d: d.update(
                {
                    "channel_list": [
                        {
                            "path": "x",
                            "env": "SEALRUN_ARTIFACT_X",
                            "sha256": "a" * 64,
                            "fd": 3,
                        },
                        {
                            "path": "y",
                            "env": "SEALRUN_ARTIFACT_Y",
                            "sha256": "b" * 64,
                            "fd": 4,
                        },
                    ]
                }
            ),
            "artifact_count",
        ),
        (
            lambda d: d.update(
                {
                    "channel_list": [],
                    "channel_list_sha256": "a" * 64,
                    "channel_list_file": "x.json",
                }
            ),
            "both",
        ),
        (
            lambda d: d.update({"channel_list_sha256": "a" * 64}),
            "missing required detached",
        ),
        (
            lambda d: d.update(
                {
                    "channel_list_sha256": "a" * 64,
                    "channel_list_file": "../escape.json",
                }
            ),
            "bare filename",
        ),
    ],
)
def test_channel_list_schema_is_strict(tmp_path, mutator, match):
    journal = tmp_path / "audit.jsonl"
    detail = launch_detail()
    mutator(detail)
    with pytest.raises(VerificationError, match=match):
        append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, detail)
    assert not journal.exists()


# --------------------------------------------------------------------------
# journal cap
# --------------------------------------------------------------------------

def test_launch_refuses_when_fewer_than_two_slots_remain(
    tmp_path, make_bundle, monkeypatch
):
    bundle = make_bundle({"model.bin": b"model"})
    monkeypatch.setattr(core, "MAX_JOURNAL_EVENTS", 3)
    append_audit_event(bundle.journal, "test", "one")
    append_audit_event(bundle.journal, "test", "two")

    with pytest.raises(VerificationError, match="fewer than 2"):
        bundle.run()

    assert len(read_journal_prefix(bundle.journal)[0]) == 2
    assert verify_audit_journal(bundle.journal) == 2


def test_launch_is_allowed_when_exactly_two_slots_remain(
    tmp_path, make_bundle, monkeypatch
):
    bundle = make_bundle({"model.bin": b"model"})
    monkeypatch.setattr(core, "MAX_JOURNAL_EVENTS", 3)
    append_audit_event(bundle.journal, "test", "one")

    assert bundle.run() == 0
    assert verify_audit_journal(bundle.journal) == 3


def test_practical_operating_limit_is_stated():
    assert core.PRACTICAL_JOURNAL_EVENT_LIMIT == 100_000
    docs = Path(__file__).resolve().parents[1] / "docs" / "launcher.md"
    text = docs.read_text(encoding="utf-8")
    assert "100,000" in text
    assert "1.25" in text and "113" in text
