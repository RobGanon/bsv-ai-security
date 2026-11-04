"""Tests for launch-flow v2 plan item 5: executable binding (§5.3).

Two modes are covered separately:

* record-only (the default) records the executable as given, the effective
  ``PATH``, and the candidate list, and makes no claim about the bytes;
* verified executes a manifest ELF through its verified descriptor with
  ``execveat(AT_EMPTY_PATH)``, records that artifact on its own, and refuses
  rather than falling back to pathname execution.

Most tests run real v2 launches (Popen, preexec, journal writes). The §5.7
isolation predicate is bypassed because it needs real root; item 3 tests it
directly. Children run as the test's own uid, so no privilege is needed.
"""

import ctypes
import errno
import hashlib
import json
import os
import sys
import types
from pathlib import Path

import pytest

import sealrun.launcher as launcher
from sealrun.cli import main
from sealrun.core import (
    V2_FINISH_EVENT_TYPE,
    V2_LAUNCH_EVENT_TYPE,
    V2_LAUNCH_FAILED_EVENT_TYPE,
    VerificationError,
    append_v2_event,
    create_manifest,
    generate_keypair,
    load_private_key,
    sign_manifest,
    verify_audit_journal,
)
from sealrun.launcher import launch

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the v2 lifecycle is Linux-only (prctl, execveat, /proc)",
)

TRUE_BYTES = Path("/bin/true").read_bytes()
FALSE_BYTES = Path("/bin/false").read_bytes()
PYTHON_BYTES = Path(sys.executable).read_bytes()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def read_events(journal: Path) -> list[tuple[str, dict]]:
    return [
        (event["event_type"], json.loads(event["detail"]))
        for event in map(json.loads, journal.read_text(encoding="utf-8").splitlines())
    ]


def terminal_event(journal: Path, expected_type: str) -> dict:
    events = read_events(journal)
    assert [event_type for event_type, _ in events] == [
        V2_LAUNCH_EVENT_TYPE, expected_type
    ]
    assert events[0][1]["run_id"] == events[1][1]["run_id"]
    assert verify_audit_journal(journal) == 2
    return events[1][1]


class Bundle:
    def __init__(self, base: Path, files: dict[str, bytes], uid: int, gid: int):
        self.base = base
        self.root = base / "root"
        self.root.mkdir(parents=True)
        for relative, data in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            if data[:4] == b"\x7fELF":
                # execveat enforces the inode's execute bit, exactly as a
                # pathname exec would; manifest artifacts are not executable
                # by default.
                path.chmod(0o755)
        self.private_path = base / "private.wif"
        self.public = base / "public.pub"
        generate_keypair(self.private_path, self.public)
        self.private = load_private_key(self.private_path)
        self.payload = create_manifest(
            self.root, list(files), "executable-binding-release", 1
        )
        self.envelope = sign_manifest(self.payload, self.private)
        self.manifest = base / "manifest.signed.json"
        self.manifest.write_text(json.dumps(self.envelope), encoding="utf-8")
        self.journal = base / "audit.jsonl"
        self.uid = uid
        self.gid = gid

    def run(self, command, **kwargs):
        kwargs.setdefault("env", {"PATH": "/usr/bin:/bin"})
        return launch(
            self.root,
            self.envelope,
            self.private.pubkey_compressed(),
            command,
            mode="v2",
            journal=self.journal,
            uid=self.uid,
            gid=self.gid,
            **kwargs,
        )


@pytest.fixture
def child_ids():
    if os.geteuid() == 0:
        pytest.skip("children run as the test's own uid; v2 refuses a child uid of 0")
    return os.getuid(), os.getgid()


@pytest.fixture
def make_bundle(tmp_path, child_ids, monkeypatch):
    monkeypatch.setattr(
        launcher, "assert_journal_writer_isolation", lambda *args, **kwargs: None
    )
    child_uid, child_gid = child_ids
    counter = 0

    def make(files: dict[str, bytes]) -> Bundle:
        nonlocal counter
        counter += 1
        return Bundle(tmp_path / f"bundle{counter}", files, child_uid, child_gid)

    return make


# --------------------------------------------------------------------------
# record-only (default)
# --------------------------------------------------------------------------

def test_record_only_records_path_and_candidates_but_no_executable_claim(
    make_bundle, tmp_path
):
    first = tmp_path / "path-first"
    second = tmp_path / "path-second"
    first.mkdir()
    second.mkdir()
    # First candidate is not executable; execvp must skip it and run the
    # second, while the record keeps both candidates and the effective PATH
    # (F4: no false "actual path" claim).
    (first / "hello").write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    (first / "hello").chmod(0o644)
    (second / "hello").write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    (second / "hello").chmod(0o755)

    bundle = make_bundle({"model.bin": b"model-v1"})
    path = f"{first}{os.pathsep}{second}"
    assert bundle.run(["hello"], env={"PATH": path}) == 7

    launch_event = read_events(bundle.journal)[0][1]
    assert launch_event["executable"] == "hello"
    assert launch_event["executable_binding"] == "record-only"
    assert launch_event["executable_path"] == path
    assert launch_event["executable_candidates"] == [
        str(first / "hello"),
        str(second / "hello"),
    ]
    assert launch_event["executable_artifact"] is None
    assert launch_event["executable_sha256"] is None
    assert launch_event["executable_fd"] is None
    assert terminal_event(bundle.journal, V2_FINISH_EVENT_TYPE)["exit_code"] == 7


def test_record_only_does_not_claim_a_manifest_artifact(make_bundle):
    bundle = make_bundle({"tool": b"#!/bin/sh\nexit 0\n", "model.bin": b"m"})
    (bundle.root / "tool").chmod(0o755)
    # Resolve by pathname, not by descriptor, even when argv[0] also names a
    # manifest artifact exactly.
    assert bundle.run(
        ["tool"], env={"PATH": str(bundle.root)}
    ) == 0
    launch_event = read_events(bundle.journal)[0][1]
    assert launch_event["executable_binding"] == "record-only"
    assert launch_event["executable_artifact"] is None


# --------------------------------------------------------------------------
# mode selection and CLI plumbing
# --------------------------------------------------------------------------

def test_verified_binding_requires_v2(make_bundle):
    bundle = make_bundle({"true.elf": TRUE_BYTES})
    with pytest.raises(VerificationError, match="requires --mode v2"):
        launch(
            bundle.root,
            bundle.envelope,
            bundle.private.pubkey_compressed(),
            ["true.elf"],
            executable_binding="verified",
        )


def test_executable_artifact_requires_verified_binding(make_bundle):
    bundle = make_bundle({"true.elf": TRUE_BYTES})
    with pytest.raises(VerificationError, match="requires --executable-binding verified"):
        bundle.run(
            ["true.elf"],
            executable_binding="record-only",
            executable_artifact="true.elf",
        )


def test_invalid_executable_binding_is_refused(make_bundle):
    bundle = make_bundle({"model.bin": b"m"})
    with pytest.raises(VerificationError, match="executable_binding must be"):
        bundle.run(["true"], executable_binding="guess")


def test_cli_refuses_executable_artifact_without_verified(make_bundle, capsys):
    bundle = make_bundle({"true.elf": TRUE_BYTES})
    rc = main([
        "launch",
        "--root", str(bundle.root),
        "--manifest", str(bundle.manifest),
        "--public-key", str(bundle.public),
        "--executable-artifact", "true.elf",
        "--", "true.elf",
    ])
    assert rc == 1
    assert "requires --executable-binding verified" in capsys.readouterr().err


def test_cli_refuses_verified_binding_without_v2(make_bundle, capsys):
    bundle = make_bundle({"true.elf": TRUE_BYTES})
    rc = main([
        "launch",
        "--root", str(bundle.root),
        "--manifest", str(bundle.manifest),
        "--public-key", str(bundle.public),
        "--executable-binding", "verified",
        "--", "true.elf",
    ])
    assert rc == 1
    assert "requires --mode v2" in capsys.readouterr().err


def test_cli_verified_binding_launches_the_artifact_fd(make_bundle):
    bundle = make_bundle({"true.elf": TRUE_BYTES})
    rc = main([
        "launch",
        "--root", str(bundle.root),
        "--manifest", str(bundle.manifest),
        "--public-key", str(bundle.public),
        "--mode", "v2",
        "--journal", str(bundle.journal),
        "--uid", str(bundle.uid),
        "--gid", str(bundle.gid),
        "--executable-binding", "verified",
        "--", "true.elf",
    ])
    assert rc == 0
    events = read_events(bundle.journal)
    assert [event_type for event_type, _ in events] == [
        V2_LAUNCH_EVENT_TYPE,
        V2_FINISH_EVENT_TYPE,
    ]
    launch_event = events[0][1]
    assert launch_event["executable_binding"] == "verified"
    assert launch_event["executable_artifact"] == "true.elf"
    assert launch_event["executable_sha256"] == hashlib.sha256(TRUE_BYTES).hexdigest()
    assert events[1][1]["exit_code"] == 0


# --------------------------------------------------------------------------
# verified execution: argv[0] mapping, explicit artifact, refusal
# --------------------------------------------------------------------------

def test_verified_argv0_matching_an_artifact_executes_the_fd(make_bundle):
    bundle = make_bundle({"true.elf": TRUE_BYTES, "model.bin": b"model-v1"})
    assert bundle.run(["true.elf"], executable_binding="verified") == 0

    launch_event = read_events(bundle.journal)[0][1]
    assert launch_event["executable"] == "true.elf"
    assert launch_event["executable_binding"] == "verified"
    assert launch_event["executable_artifact"] == "true.elf"
    assert launch_event["executable_sha256"] == hashlib.sha256(TRUE_BYTES).hexdigest()
    assert isinstance(launch_event["executable_fd"], int)
    assert launch_event["executable_fd"] >= 0
    assert launch_event["executable_candidates"] == []
    finished = terminal_event(bundle.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == 0


def test_verified_explicit_artifact_allows_a_different_argv0(make_bundle):
    bundle = make_bundle({"bin/true.elf": TRUE_BYTES})
    assert bundle.run(
        ["not-the-artifact-name"],
        executable_binding="verified",
        executable_artifact="bin/true.elf",
    ) == 0

    launch_event = read_events(bundle.journal)[0][1]
    assert launch_event["executable"] == "not-the-artifact-name"
    assert launch_event["executable_artifact"] == "bin/true.elf"
    assert launch_event["executable_sha256"] == hashlib.sha256(TRUE_BYTES).hexdigest()


def test_verified_refuses_an_unmatched_argv0_instead_of_guessing(make_bundle):
    bundle = make_bundle({"bin/true.elf": TRUE_BYTES})
    with pytest.raises(VerificationError, match="does not match a manifest artifact"):
        bundle.run(["true.elf"], executable_binding="verified")
    assert not bundle.journal.exists()


def test_verified_refuses_an_ambiguous_explicit_artifact(make_bundle):
    bundle = make_bundle({"a/true.elf": TRUE_BYTES, "b/true.elf": TRUE_BYTES})
    with pytest.raises(VerificationError, match="does not name exactly one"):
        bundle.run(
            ["anything"],
            executable_binding="verified",
            executable_artifact="true.elf",  # basename, not an exact path
        )
    assert not bundle.journal.exists()


def test_verified_refuses_a_script_artifact(make_bundle):
    bundle = make_bundle({"script.sh": b"#!/bin/sh\nexit 0\n"})
    with pytest.raises(VerificationError, match="ELF only"):
        bundle.run(["script.sh"], executable_binding="verified")
    assert not bundle.journal.exists()


def test_verified_refuses_an_artifact_without_the_execute_bit(make_bundle):
    bundle = make_bundle({"true.elf": TRUE_BYTES})
    (bundle.root / "true.elf").chmod(0o644)
    with pytest.raises(VerificationError, match="child setup before exec failed"):
        bundle.run(["true.elf"], executable_binding="verified")
    failed = terminal_event(bundle.journal, V2_LAUNCH_FAILED_EVENT_TYPE)
    assert failed["stage"] == "exec"


def test_verified_refuses_a_non_executable_elf_object(make_bundle):
    # ELF magic + class/data, but e_type=ET_REL (1), not ET_EXEC/ET_DYN.
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[16:18] = (1).to_bytes(2, "little")
    bundle = make_bundle({"object.o": bytes(header)})
    with pytest.raises(VerificationError, match="not an executable object"):
        bundle.run(["object.o"], executable_binding="verified")


def test_verified_execveat_failure_refuses_instead_of_pathname_fallback(
    make_bundle, monkeypatch
):
    bundle = make_bundle({"true.elf": TRUE_BYTES})

    def failing_execveat(fd, path, argv, envp, flags):
        ctypes.set_errno(errno.ENOSYS)
        return -1

    monkeypatch.setattr(launcher, "_EXECVEAT", failing_execveat)
    # /bin/true would succeed if the launcher fell back to argv[0]'s pathname.
    with pytest.raises(VerificationError, match="child setup before exec failed"):
        bundle.run(
            ["/bin/true"],
            executable_binding="verified",
            executable_artifact="true.elf",
        )

    failed = terminal_event(bundle.journal, V2_LAUNCH_FAILED_EVENT_TYPE)
    assert failed["stage"] == "exec"
    assert "exec" in failed["reason"]


def test_verified_unavailable_execveat_refuses_before_any_event(
    make_bundle, monkeypatch
):
    bundle = make_bundle({"true.elf": TRUE_BYTES})
    monkeypatch.setattr(launcher, "_EXECVEAT", None)
    with pytest.raises(VerificationError, match="execveat"):
        bundle.run(["true.elf"], executable_binding="verified")
    assert not bundle.journal.exists()


# --------------------------------------------------------------------------
# sealed memfd execution and vm.memfd_noexec
# --------------------------------------------------------------------------

@pytest.mark.parametrize("sysctl", [1, 2])
def test_verified_sealed_memfd_refuses_when_memfd_noexec_blocks_it(
    make_bundle, monkeypatch, sysctl
):
    bundle = make_bundle({"true.elf": TRUE_BYTES})
    monkeypatch.setattr(launcher, "_read_memfd_noexec", lambda: sysctl)
    with pytest.raises(VerificationError, match="memfd_noexec"):
        bundle.run(["true.elf"], executable_binding="verified", seal=True)
    assert not bundle.journal.exists()


def test_verified_sealed_memfd_executes_when_allowed(make_bundle, monkeypatch):
    bundle = make_bundle({"true.elf": TRUE_BYTES})
    monkeypatch.setattr(launcher, "_read_memfd_noexec", lambda: 0)
    assert bundle.run(
        ["true.elf"], executable_binding="verified", seal=True
    ) == 0
    launch_event = read_events(bundle.journal)[0][1]
    assert launch_event["seal"] is True
    assert launch_event["executable_artifact"] == "true.elf"
    assert launch_event["executable_sha256"] == hashlib.sha256(TRUE_BYTES).hexdigest()


# --------------------------------------------------------------------------
# the executed bytes are the fd, not the path
# --------------------------------------------------------------------------

def test_replacing_the_artifact_path_before_exec_cannot_change_the_image(
    make_bundle, monkeypatch
):
    bundle = make_bundle({"true.elf": TRUE_BYTES})
    false_copy = bundle.base / "false.elf"
    false_copy.write_bytes(FALSE_BYTES)
    real_execveat = launcher._execveat

    def replace_then_exec(fd, argv, env):
        os.replace(false_copy, bundle.root / "true.elf")
        return real_execveat(fd, argv, env)

    monkeypatch.setattr(launcher, "_execveat", replace_then_exec)
    # The fd still pins /bin/true, so this must exit 0, not /bin/false's 1.
    assert bundle.run(["true.elf"], executable_binding="verified") == 0
    launch_event = read_events(bundle.journal)[0][1]
    assert launch_event["executable_sha256"] == hashlib.sha256(TRUE_BYTES).hexdigest()


# --------------------------------------------------------------------------
# fd inheritance across the execveat path
# --------------------------------------------------------------------------

def test_verified_exec_propagates_the_artifact_fds_and_no_unrelated_fd(
    make_bundle, tmp_path
):
    bundle = make_bundle({"python.elf": PYTHON_BYTES, "model.bin": b"model-v1"})
    report = tmp_path / "child-report.json"
    high_fd = 200
    code = (
        "import json, os, sys\n"
        "report = {}\n"
        "for key, value in os.environ.items():\n"
        "    if key.startswith('SEALRUN_ARTIFACT_'):\n"
        "        try:\n"
        "            with open(value, 'rb') as handle:\n"
        "                report[key] = handle.read().decode('utf-8', 'replace')\n"
        "        except OSError as exc:\n"
        "            report[key] = type(exc).__name__\n"
        "report['fds'] = sorted(\n"
        "    int(name) for name in os.listdir('/proc/self/fd') if name.isdigit()\n"
        ")\n"
        "try:\n"
        f"    os.fstat({high_fd})\n"
        "    report['unrelated_fd_open'] = True\n"
        "except OSError:\n"
        "    report['unrelated_fd_open'] = False\n"
        "report['sys_executable'] = sys.executable\n"
        "report['proc_exe'] = os.readlink('/proc/self/exe')\n"
        "with open(sys.argv[1], 'w') as handle:\n"
        "    json.dump(report, handle)\n"
    )

    unrelated = os.open(bundle.base / "unrelated", os.O_RDWR | os.O_CREAT, 0o600)
    os.dup2(unrelated, high_fd)
    try:
        assert bundle.run(
            [sys.executable, "-c", code, str(report)],
            executable_binding="verified",
            executable_artifact="python.elf",
        ) == 0
    finally:
        os.close(unrelated)
        os.close(high_fd)

    child = json.loads(report.read_text(encoding="utf-8"))
    assert child["SEALRUN_ARTIFACT_MODEL_BIN"] == "model-v1"
    launch_event = read_events(bundle.journal)[0][1]
    assert launch_event["executable_fd"] in child["fds"]
    assert child["unrelated_fd_open"] is False
    # This project's AI workloads are interpreters: a Python child launched
    # from the verified descriptor must still locate itself. On a sealed
    # memfd, /proc/self/exe is the memfd; it must not be empty.
    assert child["sys_executable"]
    assert child["proc_exe"]


def test_sealed_memfd_python_child_reports_its_self_location(
    make_bundle, monkeypatch, tmp_path
):
    monkeypatch.setattr(launcher, "_read_memfd_noexec", lambda: 0)
    bundle = make_bundle({"python.elf": PYTHON_BYTES})
    report = tmp_path / "sealed-report.json"
    code = (
        "import json, os, sys\n"
        "with open(sys.argv[1], 'w') as handle:\n"
        "    json.dump({'exe': sys.executable,"
        " 'proc': os.readlink('/proc/self/exe')}, handle)\n"
    )
    assert bundle.run(
        [sys.executable, "-c", code, str(report)],
        executable_binding="verified",
        executable_artifact="python.elf",
        seal=True,
    ) == 0
    child = json.loads(report.read_text(encoding="utf-8"))
    assert child["exe"]
    assert child["proc"]
    assert "memfd" in child["proc"]


# --------------------------------------------------------------------------
# memfd sealing helpers and schema
# --------------------------------------------------------------------------

def test_f_seal_seal_fallback_is_the_correct_value(monkeypatch):
    fake_fcntl = types.SimpleNamespace(
        F_SEAL_WRITE=0x0008, F_SEAL_SHRINK=0x0002, F_SEAL_GROW=0x0004
    )
    monkeypatch.setattr(launcher, "fcntl", fake_fcntl)
    bits = launcher._seal_bits()
    assert bits & 0x0001
    assert not bits & 0x1000


def test_seal_fd_wraps_a_raw_oserror_in_verification_error(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"data")
    src_fd = os.open(source, os.O_RDONLY)

    def failing_memfd_create(*args, **kwargs):
        raise OSError(errno.ENOSYS, "memfd_create unavailable")

    monkeypatch.setattr(launcher.os, "memfd_create", failing_memfd_create)
    try:
        with pytest.raises(VerificationError, match="memfd"):
            launcher._seal_fd(src_fd)
    finally:
        os.close(src_fd)


def launch_detail(**overrides) -> dict:
    detail = {
        "launch_mode": "v2",
        "run_id": "6f1c7f38-6c02-4a4e-9a40-6b9b6f0f2a11",
        "journal_nonce": "a" * 32,
        "manifest_hash": "b" * 64,
        "artifact_count": 2,
        "argv_fingerprint": "c" * 64,
        "env_fingerprint": "d" * 64,
        "executable": "true.elf",
        "cwd": "/tmp",
        "seal": False,
        "uid": 12345,
        "gid": 12345,
        "executable_binding": "record-only",
        "executable_path": "/usr/bin:/bin",
        "executable_candidates": ["/usr/bin/true.elf", "/bin/true.elf"],
        "executable_artifact": None,
        "executable_sha256": None,
        "executable_fd": None,
    }
    detail.update(overrides)
    return detail


def verified_detail(**overrides) -> dict:
    detail = launch_detail(
        executable_binding="verified",
        executable_candidates=[],
        executable_artifact="true.elf",
        executable_sha256="e" * 64,
        executable_fd=7,
    )
    detail.update(overrides)
    return detail


def test_binding_fields_are_optional_for_older_v2_launch_events(tmp_path):
    journal = tmp_path / "audit.jsonl"
    old = launch_detail()
    for field in launcher_binding_fields():
        old.pop(field)
    append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, old)
    assert verify_audit_journal(journal) == 1


def launcher_binding_fields() -> tuple[str, ...]:
    return (
        "executable_binding",
        "executable_path",
        "executable_candidates",
        "executable_artifact",
        "executable_sha256",
        "executable_fd",
    )


@pytest.mark.parametrize("detail", [launch_detail(), verified_detail()])
def test_binding_fields_are_accepted(tmp_path, detail):
    journal = tmp_path / "audit.jsonl"
    append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, detail)
    assert verify_audit_journal(journal) == 1


@pytest.mark.parametrize(
    "detail, match",
    [
        (launch_detail(executable_binding="guess"), "record-only.*verified"),
        (launch_detail(executable_artifact="true.elf"), "must not claim"),
        (launch_detail(executable_sha256="e" * 64), "must not claim"),
        (launch_detail(executable_fd=3), "must not claim"),
        (verified_detail(executable_artifact=None), "executable_artifact"),
        (verified_detail(executable_sha256=None), "executable_sha256"),
        (verified_detail(executable_fd=None), "executable_fd"),
        (verified_detail(executable_sha256="not-hex"), "64-character hex"),
        (verified_detail(executable_fd=-1), "between 0"),
        (launch_detail(executable_candidates="not-a-list"), "array of strings"),
        (launch_detail(executable_candidates=[""]), "array of strings"),
        (launch_detail(executable_path=1), "executable_path"),
    ],
)
def test_binding_field_schema_is_strict(tmp_path, detail, match):
    journal = tmp_path / "audit.jsonl"
    with pytest.raises(VerificationError, match=match):
        append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, detail)
    assert not journal.exists()


def test_partial_binding_group_is_refused(tmp_path):
    journal = tmp_path / "audit.jsonl"
    detail = launch_detail()
    detail.pop("executable_sha256")
    with pytest.raises(VerificationError, match="missing required executable-binding"):
        append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, detail)
    assert not journal.exists()
