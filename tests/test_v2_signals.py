"""Tests for launch-flow v2 plan item 4: the signal-handling wait loop.

Real signals need a real launcher process, so most tests run the CLI in a
driver subprocess. The driver replaces only the §5.7 isolation predicate
(it needs real root; the item 3 tests exercise it directly) and shortens
the forward timeout. Popen, preexec_fn, the wait loop, the journal writes,
and the final re-raise are all production code. Children run as the test's
own uid, so no privilege is needed. The privileged-drop test at the end
needs real root and is skipped otherwise.
"""

import contextlib
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import sys
import termios
import threading
import time
from pathlib import Path

import pytest

import sealrun.launcher as launcher
from sealrun.core import (
    V2_FINISH_EVENT_TYPE,
    V2_LAUNCH_EVENT_TYPE,
    V2_LAUNCH_FAILED_EVENT_TYPE,
    VerificationError,
    append_v2_event,
    create_manifest,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_manifest,
    verify_audit_journal,
)
from sealrun.launcher import launch

REPO_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the v2 lifecycle is Linux-only (prctl, /proc)",
)

DRIVER = r'''
import os
import signal
import sys

import sealrun.launcher as launcher

launcher.assert_journal_writer_isolation = lambda *args, **kwargs: None
launcher.V2_SIGNAL_FORWARD_TIMEOUT = float(os.environ["TEST_FORWARD_TIMEOUT"])
signal.signal(signal.SIGINT, signal.default_int_handler)
for name in ("SIGHUP", "SIGTERM", "SIGCHLD"):
    signal.signal(getattr(signal, name), signal.SIG_DFL)
for name in os.environ.get("TEST_IGNORE_SIGNALS", "").split():
    signal.signal(getattr(signal, name), signal.SIG_IGN)

hook = os.environ.get("TEST_HOOK", "")
if hook == "signal-after-launch-event":
    real_append = launcher.append_v2_event

    def append(journal, event_type, detail):
        event = real_append(journal, event_type, detail)
        if event_type == "v2_launch":
            os.kill(os.getpid(), signal.SIGTERM)
        return event

    launcher.append_v2_event = append
elif hook == "default-signal-action-suppressed":
    signal.raise_signal = lambda signum: None
elif hook == "no-parent-death-signal":
    launcher._PRCTL = lambda *args: 0
elif hook == "worker-thread":
    import threading
    import time

    def worker():
        while not os.path.exists(os.environ["TEST_READY"]):
            time.sleep(0.01)

    threading.Thread(target=worker).start()

from sealrun.cli import main

sys.exit(main(sys.argv[1:]))
'''

CHILD = r'''
import ctypes
import json
import os
import signal
import subprocess
import sys
import time

mode, ready = sys.argv[1], sys.argv[2]


def mark(path, text):
    with open(path + ".tmp", "w") as handle:
        handle.write(text)
    os.replace(path + ".tmp", path)


def graceful(signum, frame):
    mark(ready + ".graceful", str(signum))
    sys.exit(0)


if mode == "graceful":
    signal.signal(signal.SIGINT, graceful)
    signal.signal(signal.SIGTERM, graceful)
elif mode == "ignore":
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, signal.SIG_IGN)
elif mode == "report":
    pdeathsig = ctypes.c_int()
    ctypes.CDLL(None).prctl(2, ctypes.byref(pdeathsig), 0, 0, 0)
    mark(ready, json.dumps({
        "pid": os.getpid(), "pgid": os.getpgid(0), "sid": os.getsid(0),
        "ppid": os.getppid(), "pdeathsig": pdeathsig.value,
    }))
    sys.exit(0)
elif mode == "exit":
    sys.exit(int(sys.argv[3]))
elif mode == "self-signal":
    os.kill(os.getpid(), signal.SIGTERM)
elif mode == "exit-later":
    mark(ready, str(os.getpid()))
    time.sleep(float(sys.argv[3]))
    mark(ready + ".survived", "1")
    sys.exit(int(sys.argv[4]))
elif mode in ("grandchild", "escaped-grandchild"):
    code = (
        "import os, signal, time\n"
        "for s in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):\n"
        "    signal.signal(s, signal.SIG_IGN)\n"
        f"open({ready!r} + '.grandchild.tmp', 'w').write(str(os.getpid()))\n"
        f"os.replace({ready!r} + '.grandchild.tmp', {ready!r} + '.grandchild')\n"
        "time.sleep(60)\n"
    )
    subprocess.Popen(
        [sys.executable, "-c", code],
        start_new_session=(mode == "escaped-grandchild"),
    )
    while not os.path.exists(ready + ".grandchild"):
        time.sleep(0.01)
    signal.signal(signal.SIGINT, graceful)
    signal.signal(signal.SIGTERM, graceful)

mark(ready, str(os.getpid()))
time.sleep(60)
'''


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def write_bundle(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "model.bin").write_bytes(b"model-v1")
    private = tmp_path / "private.wif"
    public = tmp_path / "public.pub"
    generate_keypair(private, public)
    payload = create_manifest(root, ["model.bin"], "signal-release", 1)
    envelope = sign_manifest(payload, load_private_key(private))
    manifest = tmp_path / "manifest.signed.json"
    manifest.write_text(json.dumps(envelope), encoding="utf-8")
    return root, manifest, public, envelope


def read_events(journal: Path) -> list[tuple[str, dict]]:
    return [
        (event["event_type"], json.loads(event["detail"]))
        for event in map(json.loads, journal.read_text(encoding="utf-8").splitlines())
    ]


def terminal_event(journal: Path, expected_type: str) -> dict:
    """Assert the journal is exactly launch + one terminal event of one run."""
    events = read_events(journal)
    assert [event_type for event_type, _ in events] == [
        V2_LAUNCH_EVENT_TYPE, expected_type
    ]
    assert events[0][1]["run_id"] == events[1][1]["run_id"]
    assert verify_audit_journal(journal) == 2
    return events[1][1]


def process_state(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return None


def is_alive(pid: int) -> bool:
    return process_state(pid) not in (None, "Z", "X")


def wait_until(predicate, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def wait_gone(pid: int, timeout: float = 15.0) -> bool:
    return wait_until(lambda: not is_alive(pid), timeout)


class V2Harness:
    """Run ``sealrun launch --mode v2`` in a driver process and observe it."""

    def __init__(self, tmp_path: Path, child_ids: tuple[int, int]):
        self.tmp_path = tmp_path
        self.uid, self.gid = child_ids
        self.root, self.manifest, self.public, self.envelope = write_bundle(tmp_path)
        self.journal = tmp_path / "audit.jsonl"
        self.ready = tmp_path / "ready"
        self.proc: subprocess.Popen | None = None
        self.master: int | None = None
        self._pty_output: list[bytes] = []
        self._pids: list[int] = []

    def child(self, mode: str, *args) -> list[str]:
        script = self.tmp_path / "child.py"
        script.write_text(CHILD, encoding="utf-8")
        return [sys.executable, str(script), mode, str(self.ready), *map(str, args)]

    def start(self, *command, timeout=0.5, hook="", ignore_signals="", pty=False):
        driver = self.tmp_path / "driver.py"
        driver.write_text(DRIVER, encoding="utf-8")
        argv = [
            sys.executable, str(driver), "launch",
            "--root", str(self.root),
            "--manifest", str(self.manifest),
            "--public-key", str(self.public),
            "--mode", "v2",
            "--journal", str(self.journal),
            "--uid", str(self.uid),
            "--gid", str(self.gid),
            "--", *command,
        ]
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(REPO_ROOT),
            "TEST_FORWARD_TIMEOUT": str(timeout),
            "TEST_HOOK": hook,
            "TEST_IGNORE_SIGNALS": ignore_signals,
            "TEST_READY": str(self.ready),
        }
        if pty:
            self.master, slave = os.openpty()
            self.proc = subprocess.Popen(
                argv, env=env, stdin=slave, stdout=slave, stderr=slave,
                start_new_session=True,
                preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0),
            )
            os.close(slave)
            threading.Thread(target=self._drain_pty, daemon=True).start()
        else:
            with open(self.tmp_path / "launcher.err", "wb") as err:
                self.proc = subprocess.Popen(
                    argv, env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=err,
                )
        return self.proc

    def _drain_pty(self) -> None:
        while True:
            try:
                data = os.read(self.master, 4096)
            except OSError:
                return
            if not data:
                return
            self._pty_output.append(data)

    def output(self) -> str:
        if self.master is not None:
            return b"".join(self._pty_output).decode(errors="replace")
        path = self.tmp_path / "launcher.err"
        return path.read_text(errors="replace") if path.exists() else ""

    def wait_for(self, path: Path) -> str:
        def ready() -> bool:
            if path.exists():
                return True
            if self.proc.poll() is not None:
                pytest.fail(
                    f"launcher exited early with {self.proc.returncode}: {self.output()}"
                )
            return False

        if not wait_until(ready):
            pytest.fail(f"timed out waiting for {path.name}: {self.output()}")
        return path.read_text(encoding="utf-8")

    def wait_ready(self) -> int:
        pid = int(self.wait_for(self.ready).strip())
        self.track(pid)
        return pid

    def track(self, pid: int) -> None:
        self._pids.append(pid)

    def finish(self, timeout: float = 20.0) -> int:
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pytest.fail(f"launcher did not exit: {self.output()}")

    def cleanup(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        for pid in self._pids:
            if is_alive(pid):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
        if self.master is not None:
            with contextlib.suppress(OSError):
                os.close(self.master)


@pytest.fixture
def child_ids():
    if os.geteuid() == 0:
        pytest.skip("children run as the test's own uid; v2 refuses a child uid of 0")
    return os.getuid(), os.getgid()


@pytest.fixture
def v2(tmp_path, child_ids):
    harness = V2Harness(tmp_path, child_ids)
    yield harness
    harness.cleanup()


@pytest.fixture
def in_process(tmp_path, child_ids, monkeypatch):
    """A real in-process v2 launch (no signals involved)."""
    monkeypatch.setattr(
        launcher, "assert_journal_writer_isolation", lambda *args, **kwargs: None
    )
    harness = V2Harness(tmp_path, child_ids)

    def run(mode, *args):
        return launch(
            harness.root, harness.envelope, load_public_key(harness.public),
            harness.child(mode, *args),
            mode="v2", journal=harness.journal, uid=harness.uid, gid=harness.gid,
        )

    harness.run = run
    yield harness
    harness.cleanup()


# --------------------------------------------------------------------------
# forward first, escalate after the timeout, record, then re-raise
# --------------------------------------------------------------------------

def test_sigint_is_forwarded_first_so_the_child_can_exit_cleanly(v2):
    v2.start(*v2.child("graceful"), timeout=5.0)
    child_pid = v2.wait_ready()

    os.kill(v2.proc.pid, signal.SIGINT)

    assert v2.finish() == -signal.SIGINT, v2.output()
    assert v2.wait_for(Path(f"{v2.ready}.graceful")) == str(int(signal.SIGINT))
    assert wait_gone(child_pid)
    finished = terminal_event(v2.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == 0
    assert finished["launcher_signal"] == signal.SIGINT
    assert finished["escalated"] is False
    assert finished["duration_ms"] < 5000


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_child_ignoring_the_forwarded_signal_is_killed_after_the_timeout(v2, signum):
    v2.start(*v2.child("ignore"), timeout=0.5)
    child_pid = v2.wait_ready()

    sent = time.monotonic()
    os.kill(v2.proc.pid, signum)

    # WIFSIGNALED with the launcher's own signal: not 241, not 128+N.
    assert v2.finish() == -signum, v2.output()
    assert time.monotonic() - sent >= 0.49
    assert wait_gone(child_pid)
    finished = terminal_event(v2.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == -signal.SIGKILL
    assert finished["launcher_signal"] == signum
    assert finished["escalated"] is True


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_forwarded_signal_kills_a_default_child_and_the_launcher_re_raises(v2, signum):
    v2.start(*v2.child("default"), timeout=5.0)
    child_pid = v2.wait_ready()

    os.kill(v2.proc.pid, signum)

    assert v2.finish() == -signum, v2.output()
    assert wait_gone(child_pid)
    finished = terminal_event(v2.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == -signum
    assert finished["launcher_signal"] == signum
    assert finished["escalated"] is False


def test_group_member_left_behind_is_killed_at_escalation(v2):
    v2.start(*v2.child("grandchild"), timeout=0.5)
    v2.wait_ready()
    grandchild = int(v2.wait_for(Path(f"{v2.ready}.grandchild")))
    v2.track(grandchild)

    os.kill(v2.proc.pid, signal.SIGINT)

    assert v2.finish() == -signal.SIGINT, v2.output()
    assert Path(f"{v2.ready}.graceful").exists()
    assert wait_gone(grandchild)
    finished = terminal_event(v2.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == 0
    assert finished["escalated"] is True


def test_descendant_that_leaves_the_process_group_escapes_escalation(v2):
    """The documented §5.4 residual: group cleanup is not containment."""
    v2.start(*v2.child("escaped-grandchild"), timeout=0.5)
    v2.wait_ready()
    escaped = int(v2.wait_for(Path(f"{v2.ready}.grandchild")))
    v2.track(escaped)

    os.kill(v2.proc.pid, signal.SIGINT)

    assert v2.finish() == -signal.SIGINT, v2.output()
    finished = terminal_event(v2.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == 0
    assert finished["escalated"] is False
    time.sleep(0.3)
    assert is_alive(escaped)


def test_signal_ignored_when_the_launcher_started_stays_ignored(v2):
    v2.start(*v2.child("default"), ignore_signals="SIGINT")
    child_pid = v2.wait_ready()

    os.kill(v2.proc.pid, signal.SIGINT)
    time.sleep(0.5)
    assert v2.proc.poll() is None
    assert is_alive(child_pid)

    os.kill(v2.proc.pid, signal.SIGTERM)
    assert v2.finish() == -signal.SIGTERM, v2.output()
    finished = terminal_event(v2.journal, V2_FINISH_EVENT_TYPE)
    assert finished["launcher_signal"] == signal.SIGTERM
    assert finished["exit_code"] == -signal.SIGTERM


def test_signal_before_the_child_starts_records_launch_failed_and_re_raises(v2):
    v2.start(*v2.child("graceful"), hook="signal-after-launch-event")

    assert v2.finish() == -signal.SIGTERM, v2.output()
    assert not v2.ready.exists()
    failed = terminal_event(v2.journal, V2_LAUNCH_FAILED_EVENT_TYPE)
    assert failed["stage"] == "launch"
    assert "SIGTERM" in failed["reason"]


def test_re_raise_falls_back_to_128_plus_n_when_the_default_action_is_suppressed(v2):
    """E.g. a PID-namespace init, which the kernel shields from SIG_DFL."""
    v2.start(*v2.child("default"), hook="default-signal-action-suppressed")
    v2.wait_ready()

    os.kill(v2.proc.pid, signal.SIGTERM)

    assert v2.finish() == 128 + signal.SIGTERM, v2.output()
    terminal_event(v2.journal, V2_FINISH_EVENT_TYPE)


# --------------------------------------------------------------------------
# parent death, process group, threads
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "hook, child_survives",
    [("", False), ("no-parent-death-signal", True)],
    ids=["parent-death-signal", "control-without-it"],
)
def test_sigkilled_launcher_child_dies_by_the_parent_death_signal(v2, hook, child_survives):
    v2.start(*v2.child("ignore"), hook=hook)
    child_pid = v2.wait_ready()

    os.kill(v2.proc.pid, signal.SIGKILL)

    assert v2.finish() == -signal.SIGKILL
    if child_survives:
        # Control: the same child outlives the launcher without the
        # parent-death signal, so the production case is not vacuous.
        time.sleep(0.5)
        assert is_alive(child_pid)
    else:
        assert wait_gone(child_pid)
    # A SIGKILLed launcher writes nothing more: the run stays incomplete.
    assert [event_type for event_type, _ in read_events(v2.journal)] == [
        V2_LAUNCH_EVENT_TYPE
    ]


def test_worker_thread_exit_does_not_kill_the_child(v2):
    """The parent-death signal follows the spawning (main) thread only."""
    v2.start(*v2.child("exit-later", 1.0, 0), hook="worker-thread")

    assert v2.finish() == 0, v2.output()
    assert Path(f"{v2.ready}.survived").exists()
    finished = terminal_event(v2.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == 0
    assert finished["launcher_signal"] == 0
    assert finished["escalated"] is False


def test_child_has_its_own_group_in_the_same_session_and_a_parent_death_signal(in_process):
    handled = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGCHLD)
    before = {signum: signal.getsignal(signum) for signum in handled}

    assert in_process.run("report") == 0

    report = json.loads(in_process.ready.read_text(encoding="utf-8"))
    assert report["pgid"] == report["pid"] != os.getpgid(0)
    assert report["sid"] == os.getsid(0)
    assert report["ppid"] == os.getpid()
    assert report["pdeathsig"] == signal.SIGKILL
    finished = terminal_event(in_process.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == 0
    assert finished["launcher_signal"] == 0
    assert finished["escalated"] is False
    assert {signum: signal.getsignal(signum) for signum in handled} == before


def test_child_signal_death_is_recorded_as_a_negative_exit_code(in_process):
    # subprocess's negative-returncode mapping is preserved, never turned
    # into a fabricated exit status (§5.4).
    assert in_process.run("self-signal") == -signal.SIGTERM
    finished = terminal_event(in_process.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == -signal.SIGTERM
    assert finished["launcher_signal"] == 0
    assert finished["escalated"] is False


def test_inherited_ignored_sigchld_does_not_fabricate_an_exit_status(in_process):
    previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    try:
        assert in_process.run("exit", 7) == 7
        assert signal.getsignal(signal.SIGCHLD) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGCHLD, previous)
    assert terminal_event(in_process.journal, V2_FINISH_EVENT_TYPE)["exit_code"] == 7


def test_v2_launch_off_the_main_thread_is_refused_before_any_event(in_process):
    errors: list[BaseException] = []

    def target():
        try:
            in_process.run("exit", 0)
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    worker = threading.Thread(target=target)
    worker.start()
    worker.join()

    assert len(errors) == 1 and isinstance(errors[0], VerificationError)
    assert "main thread" in str(errors[0])
    assert not in_process.journal.exists()


def test_v2_launch_without_parent_death_support_is_refused(in_process, monkeypatch):
    monkeypatch.setattr(launcher, "_PRCTL", None)
    with pytest.raises(VerificationError, match="PR_SET_PDEATHSIG"):
        in_process.run("exit", 0)
    assert not in_process.journal.exists()


@pytest.mark.parametrize(
    "parent_offset, uid_offset",
    [(None, 0), (0, 1)],
    ids=["launcher-gone-before-prctl", "credentials-not-dropped-first"],
)
def test_preexec_refuses_to_exec_an_unsupervised_child(tmp_path, parent_offset, uid_offset):
    """The fork-to-prctl window and the credential-ordering guard."""
    marker = tmp_path / "ran"
    parent = -1 if parent_offset is None else os.getpid()
    uid, gid = os.getuid() + uid_offset, os.getgid()
    with pytest.raises(subprocess.SubprocessError, match="preexec_fn"):
        subprocess.Popen(
            [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"],
            preexec_fn=lambda: launcher._v2_preexec(parent, uid, gid, None),
        )
    assert not marker.exists()


def test_preexec_failure_is_journalled_as_a_launch_failure(in_process, monkeypatch):
    def failing_preexec(parent_pid, uid, gid, drop_groups):
        raise RuntimeError("simulated: the credential drop did not precede preexec_fn")

    monkeypatch.setattr(launcher, "_v2_preexec", failing_preexec)
    with pytest.raises(VerificationError, match="child setup before exec failed"):
        in_process.run("exit", 0)
    failed = terminal_event(in_process.journal, V2_LAUNCH_FAILED_EVENT_TYPE)
    assert failed["stage"] == "exec"
    assert not in_process.ready.exists()


# --------------------------------------------------------------------------
# terminal policy: own process group, NOT the foreground group
# --------------------------------------------------------------------------

def test_terminal_ctrl_c_reaches_the_child_through_the_launcher(v2):
    v2.start(*v2.child("graceful"), timeout=5.0, pty=True)
    child_pid = v2.wait_ready()
    assert os.getpgid(child_pid) == child_pid
    # Terminal loss accepted: the launcher's group keeps the terminal.
    assert os.tcgetpgrp(v2.master) == os.getpgid(v2.proc.pid) != child_pid

    os.write(v2.master, b"\x03")

    assert v2.finish() == -signal.SIGINT, v2.output()
    assert v2.wait_for(Path(f"{v2.ready}.graceful")) == str(int(signal.SIGINT))
    finished = terminal_event(v2.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == 0
    assert finished["launcher_signal"] == signal.SIGINT
    assert finished["escalated"] is False


def test_child_reading_the_terminal_is_stopped_then_terminated_on_ctrl_c(v2):
    command = [
        "/bin/sh", "-c", 'echo $$ > "$1.tmp" && mv "$1.tmp" "$1" && exec cat',
        "sh", str(v2.ready),
    ]
    v2.start(*command, timeout=5.0, pty=True)
    child_pid = v2.wait_ready()

    # A background-group read of the controlling terminal: SIGTTIN stop.
    assert wait_until(lambda: process_state(child_pid) == "T"), process_state(child_pid)

    os.write(v2.master, b"\x03")

    # The forward is followed by SIGCONT, so the stopped child acts on it.
    assert v2.finish() == -signal.SIGINT, v2.output()
    finished = terminal_event(v2.journal, V2_FINISH_EVENT_TYPE)
    assert finished["exit_code"] == -signal.SIGINT
    assert finished["launcher_signal"] == signal.SIGINT
    assert finished["escalated"] is False


# --------------------------------------------------------------------------
# finish-event schema: the termination fields
# --------------------------------------------------------------------------

def finish_detail(**overrides) -> dict:
    detail = {
        "launch_mode": "v2",
        "run_id": "6f1c7f38-6c02-4a4e-9a40-6b9b6f0f2a11",
        "exit_code": -9,
        "launcher_signal": 2,
        "escalated": True,
        "duration_ms": 5012,
    }
    detail.update(overrides)
    return detail


def test_finish_with_termination_fields_is_accepted(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_v2_event(journal, V2_FINISH_EVENT_TYPE, finish_detail())
    assert verify_audit_journal(journal) == 1


@pytest.mark.parametrize(
    "detail, match",
    [
        (finish_detail(launcher_signal=9), "launcher_signal must be 0"),
        (finish_detail(launcher_signal="2"), "launcher_signal must be an integer"),
        (finish_detail(launcher_signal=True), "launcher_signal must be an integer"),
        (finish_detail(escalated="yes"), "escalated must be a boolean"),
        (finish_detail(escalated=True, launcher_signal=0), "escalated requires"),
        (
            {k: v for k, v in finish_detail().items() if k != "launcher_signal"},
            "missing required field",
        ),
    ],
)
def test_finish_termination_fields_are_strict(tmp_path, detail, match):
    journal = tmp_path / "audit.jsonl"
    with pytest.raises(VerificationError, match=match):
        append_v2_event(journal, V2_FINISH_EVENT_TYPE, detail)
    assert not journal.exists()


def test_verifier_rejects_a_hand_minted_escalation_without_a_signal(tmp_path):
    journal = tmp_path / "audit.jsonl"
    event = {
        "seq": 1,
        "event_type": V2_FINISH_EVENT_TYPE,
        "detail": json.dumps(
            finish_detail(launcher_signal=0), sort_keys=True, separators=(",", ":")
        ),
        "previous_hash": "0" * 64,
    }
    event["event_hash"] = hashlib.sha256(
        json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    journal.write_text(
        json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(VerificationError, match="escalated requires"):
        verify_audit_journal(journal)


# --------------------------------------------------------------------------
# privileged drop (real root only)
# --------------------------------------------------------------------------

@pytest.mark.skipif(
    os.geteuid() != 0,
    reason="needs real root: plan item 4 requires this on every supported "
           "CPython version, run as real root",
)
def test_privileged_drop_reports_dropped_credentials_and_child_dies_with_parent():
    """Popen(user/group/extra_groups) + preexec credential report + PDEATHSIG.

    The preexec callback reports the credentials it observes (the ordering
    is version-dependent, so it is measured, not assumed); then the
    launcher process is SIGKILLed and the child must die.
    """
    target = 65534
    report_r, report_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(report_r)
            real_preexec, real_wait = launcher._v2_preexec, launcher._wait_v2_child

            def reporting_preexec(parent_pid, uid, gid, drop_groups):
                creds = [os.getuid(), os.geteuid(), os.getgid(), os.getegid(),
                         sorted(os.getgroups())]
                os.write(report_w, (json.dumps({"creds": creds}) + "\n").encode())
                real_preexec(parent_pid, uid, gid, drop_groups)

            def reporting_wait(proc, signals):
                os.write(report_w, (json.dumps({"child": proc.pid}) + "\n").encode())
                return real_wait(proc, signals)

            launcher._v2_preexec = reporting_preexec
            launcher._wait_v2_child = reporting_wait
            launcher._run_v2_child(
                ["sleep", "60"], pass_fds=(), child_env={"PATH": "/usr/bin:/bin"},
                uid=target, gid=target, drop_groups=(), signals=[],
            )
        finally:
            os._exit(0)
    os.close(report_w)
    reports: dict = {}
    buffer = b""
    deadline = time.monotonic() + 15
    while len(reports) < 2 and time.monotonic() < deadline:
        chunk = os.read(report_r, 4096)
        if not chunk:
            break
        buffer += chunk
        *lines, buffer = buffer.split(b"\n")
        for line in lines:
            reports.update(json.loads(line))
    os.close(report_r)
    try:
        assert reports.get("creds") == [target, target, target, target, []], reports
        child = reports["child"]
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        assert wait_gone(child)
    finally:
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        if "child" in reports and is_alive(reports["child"]):
            os.kill(reports["child"], signal.SIGKILL)
