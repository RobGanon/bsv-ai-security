"""Privileged launcher: run a command against verified artifact handles.

``sealrun verify`` proves a signed manifest before launch, but a caller
that then launches the model *by path* re-opens the artifacts, leaving a
check-to-use window: an attacker with write access to the artifact tree
can swap bytes between verification and the model's ``open()``. The
launcher closes that window by consuming :func:`core.verified_artifacts`
handles and handing the launched process the *open file descriptors*,
which pin the inodes that were verified. The child never has to reopen a
path.

The launcher is meant to be *started* privileged (root), so it can read
the trusted key and the artifacts; it can then drop to an unprivileged
uid/gid before exec, so the model itself never runs with privileged
access. This module does not ship a setuid binary — the operator starts
it under sudo/systemd and passes ``--uid``/``--gid``.

Environment contract for the child::

    SEALRUN_MANIFEST_HASH   sha256 over the verified signed envelope
    SEALRUN_RELEASE_ID      release_id from the verified payload
    SEALRUN_RELEASE_SEQ     release_seq from the verified payload
    SEALRUN_ARTIFACT_<P>    /proc/self/fd/<N> for each artifact, where
                            <P> is the artifact path upper-cased with
                            every run of non-alphanumeric characters
                            collapsed to a single underscore

Two artifact paths that collapse to the same environment variable name
would make the contract ambiguous, so the launcher refuses to run rather
than guess.

``seal=True`` copies each verified artifact into a sealed memfd
(``F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL``) before
exec, so the child reads a frozen snapshot: even a writer with access to
the original inode cannot change what the model sees. The copy is
re-hashed as it is made and compared against the manifest before
sealing, so a mutation that lands between verification and the copy
aborts the launch instead of reaching the child. Sealing costs a
copy of every artifact into RAM, so it is opt-in.

**Executable binding.** By default a launch is *record-only* with respect
to the executable: the v2 launch record names the command as given, the
effective ``PATH``, and every ``PATH`` candidate the launcher considered.
That is deliberately not a claim about which candidate ``execvp`` used or
what bytes ran. The opt-in ``executable_binding="verified"`` mode executes
a manifest artifact through its verified descriptor with Linux
``execveat(AT_EMPTY_PATH)``, and the launch record names that artifact on
its own. The claim covers the main ELF image only: the dynamic loader and
shared libraries are still loaded by path, and scripts stay record-only.
Verified mode refuses (never downgrades to pathname execution) when the
artifact is not an ELF, when ``execveat`` is unavailable, or when a sealed
memfd could not be executed because ``vm.memfd_noexec`` is 1 or 2.

Residual limits are stated plainly because they matter:

* Without ``seal`` the fd pins the *inode*, not its contents — a writer
  with access to the verified inode can still mutate it after hashing,
  so the child may read changed bytes. ``seal=True`` removes this: the
  sealed copy is verified against the manifest, and a change after the
  copy cannot reach the frozen snapshot.
* A swap of an *intermediate directory* component between the
  per-component walk in :func:`core._validated_entries` and the open in
  :func:`core._open_verified_fd` remains a narrow race; closing it fully
  needs opening each component with ``O_NOFOLLOW``.
* The launcher pins *what bytes are launched*; it does not sandbox the
  child. Containment (namespaces, seccomp, cgroups) is out of scope.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import os
import platform
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from subprocess import SubprocessError
from typing import Callable, Mapping, NamedTuple, NoReturn, Sequence

from .checkpoint_cache import (
    read_checkpoint_cache,
    verify_checkpoint_against_journal,
)
from .checkpoint_seq import validate_checkpoint_seq
from .core import (
    MAX_EVENT_DETAIL_BYTES,
    V2_FINISH_EVENT_TYPE,
    V2_LAUNCH_EVENT_TYPE,
    V2_LAUNCH_FAILED_EVENT_TYPE,
    JournalIdentity,
    VerificationError,
    VerifiedArtifact,
    append_v2_event,
    assert_journal_writer_isolation,
    canonical_json_bytes,
    fingerprint_argv,
    fingerprint_environment,
    manifest_hash,
    pin_journal_identity,
    verified_artifacts,
    write_detached_channel_list,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix platforms
    fcntl = None  # type: ignore[assignment]

_ENV_PREFIX = "SEALRUN_ARTIFACT_"
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")

#: Seconds a v2 child's process group gets, after the launcher forwards a
#: termination signal to it, before the launcher sends the group SIGKILL
#: (§5.4: forward first, escalate after a stated timeout).
V2_SIGNAL_FORWARD_TIMEOUT = 5.0

#: Termination signals a v2 launcher records and forwards instead of dying
#: on. A signal that was ignored when the launcher started stays ignored.
_V2_FORWARDED_SIGNALS = tuple(
    getattr(signal, name)
    for name in ("SIGHUP", "SIGINT", "SIGTERM")
    if hasattr(signal, name)
)
_V2_WAIT_POLL_INTERVAL = 0.05
_PR_SET_PDEATHSIG = 1

#: execveat(2) flag: execute the file referred to by the descriptor itself,
#: with an empty pathname (§5.3 verified executable binding).
_AT_EMPTY_PATH = 0x1000

#: Linux execveat syscall numbers, used only when libc does not expose the
#: wrapper. An unknown architecture falls back to refusing verified mode.
_EXECVEAT_SYSCALLS = {
    "x86_64": 322,
    "amd64": 322,
    "i386": 358,
    "i486": 358,
    "i586": 358,
    "i686": 358,
    "aarch64": 281,
    "arm64": 281,
    "armv7l": 387,
    "armv6l": 387,
    "riscv64": 281,
    "ppc64": 362,
    "ppc64le": 362,
    "s390x": 322,
}

_MEMFD_NOEXEC_PATH = Path("/proc/sys/vm/memfd_noexec")


def _load_prctl():
    """Return libc's ``prctl`` on Linux, or ``None`` where it is unavailable.

    Resolved once at import so the child's ``preexec_fn`` does no dynamic
    loading between fork and exec.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        prctl = ctypes.CDLL(None, use_errno=True).prctl
    except (OSError, AttributeError):
        return None
    prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    prctl.restype = ctypes.c_int
    return prctl


_PRCTL = _load_prctl()


def _load_execveat():
    """Return libc's ``execveat`` (or a syscall wrapper), or ``None``.

    Python has no ``os.execveat`` (§5.3 stdlib gap), so the verified
    executable path uses a raw call. Resolution happens at import time so
    the child's ``preexec_fn`` does no dynamic loading between fork and
    exec. A libc without the ``execveat`` wrapper falls back to the
    architecture's ``syscall`` number; an unknown architecture refuses
    verified mode rather than guessing.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None
    try:
        execveat = libc.execveat
    except AttributeError:
        try:
            number = _EXECVEAT_SYSCALLS[platform.machine().lower()]
        except KeyError:
            return None
        try:
            syscall = libc.syscall
        except AttributeError:
            return None
        syscall.restype = ctypes.c_long

        def call(fd, path, argv, envp, flags):
            return syscall(
                ctypes.c_long(number),
                ctypes.c_int(fd),
                path,
                argv,
                envp,
                ctypes.c_int(flags),
            )

        return call
    execveat.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.c_int,
    ]
    execveat.restype = ctypes.c_int
    return execveat


_EXECVEAT = _load_execveat()

# F_SEAL_* values (linux/memfd.h). The fallbacks let the module import on
# platforms whose fcntl lacks them; ``_seal_fd`` refuses at call time.
# F_SEAL_SEAL is 0x0001 (not 0x1000); the fallback is part of the §5.3
# memfd requirement.
def _seal_bits() -> int:
    return (
        getattr(fcntl, "F_SEAL_WRITE", 0x0008)
        | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
        | getattr(fcntl, "F_SEAL_GROW", 0x0004)
        | getattr(fcntl, "F_SEAL_SEAL", 0x0001)
    )


_SEAL_BITS = _seal_bits()


def _read_memfd_noexec() -> int | None:
    """Return ``vm.memfd_noexec`` (0, 1 or 2), or ``None`` if unreadable."""
    try:
        text = _MEMFD_NOEXEC_PATH.read_text(encoding="ascii").strip()
    except OSError:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def artifact_env_name(path: str) -> str:
    """Map an artifact path to its child environment variable name.

    ``"model.bin"`` -> ``SEALRUN_ARTIFACT_MODEL_BIN``. The mapping is
    many-to-one; callers detect collisions before launch.
    """
    collapsed = _NON_ALNUM.sub("_", path).strip("_").upper()
    return f"{_ENV_PREFIX}{collapsed}"


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _seal_fd(src_fd: int, *, expected_sha256: str | None = None,
             expected_size: int | None = None,
             chunk: int = 1 << 20) -> int:
    """Copy the bytes at ``src_fd`` into a sealed memfd; return its fd.

    The returned descriptor reads the frozen snapshot: it rejects
    ``write``, ``ftruncate``, and further ``F_ADD_SEALS`` calls. The
    caller owns the descriptor and must close it.

    When ``expected_sha256`` / ``expected_size`` are given (the values
    the manifest verified), the copy is hashed as it is made and
    compared before sealing: verification hashed the source earlier,
    and a writer with access to the source inode could mutate it
    between that hash and this copy. A mismatch aborts with
    :class:`VerificationError` — the mutated bytes are never sealed
    for the child.
    """
    if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
        raise VerificationError("sealing requires memfd_create (Linux)")
    if fcntl is None or not hasattr(fcntl, "F_ADD_SEALS"):
        raise VerificationError("sealing requires fcntl.F_ADD_SEALS (Linux)")
    try:
        os.lseek(src_fd, 0, os.SEEK_SET)
    except OSError as exc:
        raise VerificationError(
            f"cannot rewind the artifact descriptor for sealing: {exc}"
        ) from exc
    try:
        mem_fd = os.memfd_create("sealrun-artifact", os.MFD_ALLOW_SEALING)
    except OSError as exc:
        raise VerificationError(
            f"cannot create a sealed memfd copy of the artifact: {exc}"
        ) from exc
    try:
        digest = hashlib.sha256()
        copied = 0
        while True:
            data = os.read(src_fd, chunk)
            if not data:
                break
            digest.update(data)
            copied += len(data)
            _write_all(mem_fd, data)
        if expected_size is not None and copied != expected_size:
            raise VerificationError(
                "sealed copy size does not match the verified artifact: "
                f"{copied} != {expected_size}"
            )
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            raise VerificationError(
                "sealed copy hash does not match the verified artifact: "
                "the source changed between verification and sealing"
            )
        fcntl.fcntl(mem_fd, fcntl.F_ADD_SEALS, _SEAL_BITS)
        os.lseek(mem_fd, 0, os.SEEK_SET)
        return mem_fd
    except VerificationError:
        with contextlib.suppress(OSError):
            os.close(mem_fd)
        raise
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.close(mem_fd)
        raise VerificationError(
            f"cannot create a sealed copy of the artifact: {exc}"
        ) from exc
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(mem_fd)
        raise


def _artifact_environment(
    channels: Sequence[tuple[str, int]],
) -> dict[str, str]:
    """Build the ``SEALRUN_ARTIFACT_*`` variables, refusing collisions."""
    env: dict[str, str] = {}
    seen: dict[str, str] = {}
    for path, fd in channels:
        var = artifact_env_name(path)
        if var in seen and seen[var] != path:
            raise VerificationError(
                f"artifact paths {seen[var]!r} and {path!r} both map to the "
                f"child environment variable {var}; refusing an ambiguous launch"
            )
        seen[var] = path
        env[var] = f"/proc/self/fd/{fd}"
    return env


def build_child_environment(
    envelope: dict,
    channels: Sequence[tuple[str, int]],
    base: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the environment for the launched child.

    Starts from a clean environment (or ``base`` if explicitly provided)
    and overlays only the verified-manifest provenance and artifact
    descriptors.

    ``PATH`` is carried over from the caller when ``base`` is not
    supplied: the launcher resolves the command to run through
    ``subprocess``, which looks a relative ``argv[0]`` up in the
    *child's* ``PATH``. Without it, a command named rather than given
    by absolute path would only be found in ``os.defpath``
    (``/bin:/usr/bin``). ``PATH`` is the one variable carried over:
    it names executables, not the operator's secrets.
    """
    if base is None:
        env = {}
        caller_path = os.environ.get("PATH")
        if caller_path:
            env["PATH"] = caller_path
    else:
        env = dict(base)
    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    env["SEALRUN_MANIFEST_HASH"] = manifest_hash(envelope)
    if isinstance(payload, dict):
        release_id = payload.get("release_id")
        if isinstance(release_id, str) and release_id:
            env["SEALRUN_RELEASE_ID"] = release_id
        release_seq = payload.get("release_seq")
        if isinstance(release_seq, int) and not isinstance(release_seq, bool):
            env["SEALRUN_RELEASE_SEQ"] = str(release_seq)
    env.update(_artifact_environment(channels))
    return env


def _executable_search_path(child_env: Mapping[str, str]) -> list[str]:
    """The PATH entry list ``execvp`` would search for this child."""
    return list(os.get_exec_path(dict(child_env)))


def _record_only_executable_fields(
    argv0: str, child_env: Mapping[str, str]
) -> tuple[str, list[str]]:
    """Return ``(effective PATH, candidate list)`` for a record-only launch.

    The list is every pathname the launcher considered, in search order.
    It deliberately does not claim which candidate ``execvp`` actually
    executed (§5.3 record-only).
    """
    search_path = _executable_search_path(child_env)
    if os.sep in argv0 or (os.altsep is not None and os.altsep in argv0):
        candidates = [argv0]
    else:
        candidates = [os.path.join(entry, argv0) for entry in search_path]
    return os.pathsep.join(search_path), candidates


def _select_executable_artifact(
    artifacts: Sequence[VerifiedArtifact],
    argv: Sequence[str],
    explicit: str | None,
) -> VerifiedArtifact:
    """Resolve the manifest artifact to execute, never guessing (§5.3).

    An explicit ``--executable-artifact`` must be the artifact's exact
    manifest path. Otherwise ``argv[0]`` must match one exactly. A
    basename match, a ``PATH`` match, or any other "looks like" match is
    not accepted: ambiguity is refused rather than resolved by guesswork.
    """
    if explicit is not None:
        matches = [artifact for artifact in artifacts if artifact.path == explicit]
        if len(matches) != 1:
            raise VerificationError(
                f"--executable-artifact {explicit!r} does not name exactly one "
                "verified manifest artifact; refusing to guess"
            )
        return matches[0]
    matches = [artifact for artifact in artifacts if artifact.path == argv[0]]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise VerificationError(
            f"argv[0] {argv[0]!r} matches more than one manifest artifact; "
            "name the executable artifact explicitly"
        )
    raise VerificationError(
        f"argv[0] {argv[0]!r} does not match a manifest artifact path exactly; "
        "name the executable artifact with --executable-artifact "
        "(a verified-executable launch is never guessed)"
    )


def _assert_elf_executable(fd: int, path: str) -> None:
    """Refuse a verified executable that is not an executable ELF image."""
    try:
        header = os.pread(fd, 64, 0)
    except OSError as exc:
        raise VerificationError(
            f"cannot inspect executable artifact {path!r}: {exc}"
        ) from exc
    if len(header) < 18 or header[:4] != b"\x7fELF":
        raise VerificationError(
            f"verified executable binding is Linux ELF only; artifact {path!r} "
            "is not an ELF image (scripts stay record-only)"
        )
    data_encoding = header[5]
    if data_encoding not in (1, 2):
        raise VerificationError(
            f"artifact {path!r} has an unsupported ELF data encoding"
        )
    byte_order = "little" if data_encoding == 1 else "big"
    e_type = int.from_bytes(header[16:18], byte_order)
    if e_type not in (2, 3):  # ET_EXEC, ET_DYN
        raise VerificationError(
            f"artifact {path!r} is an ELF image but not an executable object "
            f"(e_type={e_type}); scripts and relocatable objects stay record-only"
        )


def _execveat(fd: int, argv: Sequence[str], env: Mapping[str, str]) -> NoReturn:
    """Replace the current child with the ELF image at ``fd``.

    The descriptor, not a pathname or ``argv[0]``, supplies the executed
    bytes (``AT_EMPTY_PATH``). On failure this raises; it never returns
    and never falls back to pathname execution.
    """
    if _EXECVEAT is None:
        raise VerificationError(
            "verified executable binding requires Linux execveat(AT_EMPTY_PATH); "
            "it is unavailable on this platform"
        )
    argv_bytes = [os.fsencode(value) for value in argv]
    env_bytes = [os.fsencode(f"{key}={value}") for key, value in env.items()]
    argv_array = (ctypes.c_char_p * (len(argv_bytes) + 1))(*argv_bytes, None)
    env_array = (ctypes.c_char_p * (len(env_bytes) + 1))(*env_bytes, None)
    result = _EXECVEAT(
        ctypes.c_int(fd), b"", argv_array, env_array, _AT_EMPTY_PATH
    )
    errno = ctypes.get_errno()
    if result != 0 and errno:
        raise OSError(errno, f"execveat failed: {os.strerror(errno)}")
    raise VerificationError(
        "execveat returned without executing the verified artifact"
    )


def _resolve_id(value, *, kind: str):
    """Resolve a name or numeric id to an int, or None."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise VerificationError(f"{kind} must be a name or numeric id")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        raise VerificationError(f"{kind} must be a name or numeric id")
    if text.isdigit():
        return int(text)
    if kind == "uid":
        import pwd

        try:
            return pwd.getpwnam(text).pw_uid
        except KeyError as exc:
            raise VerificationError(f"unknown user: {text}") from exc
    import grp

    try:
        return grp.getgrnam(text).gr_gid
    except KeyError as exc:
        raise VerificationError(f"unknown group: {text}") from exc


def resolve_uid(value) -> int | None:
    """Resolve ``--uid`` (user name or numeric id) to an int, or None."""
    return _resolve_id(value, kind="uid")


def resolve_gid(value) -> int | None:
    """Resolve ``--gid`` (group name or numeric id) to an int, or None."""
    return _resolve_id(value, kind="gid")


def _primary_gid(uid: int) -> int:
    """Return the passwd primary group for ``uid``.

    Dropping only the uid would leave the process in the caller's primary
    group (root's, in the privileged case), so a uid without an explicit
    gid defaults to the user's own group. A uid with no passwd entry has
    no safe default and fails closed.
    """
    import pwd

    try:
        return pwd.getpwuid(uid).pw_gid
    except KeyError as exc:
        raise VerificationError(
            f"uid {uid} has no passwd entry; pass an explicit --gid so the "
            f"launched process does not keep the caller's group"
        ) from exc


def _current_working_directory() -> str:
    try:
        return os.getcwd()
    except OSError as exc:
        raise VerificationError(
            f"cannot determine the current working directory for the launch record: {exc}"
        ) from exc


def _v2_launch_detail(
    envelope: dict,
    channels: Sequence[tuple[str, int]],
    channel_records: Sequence[Mapping[str, object]],
    argv: Sequence[str],
    child_env: Mapping[str, str],
    *,
    run_id: str,
    journal_nonce: str,
    seal: bool,
    uid: int,
    gid: int,
    executable_binding: str,
    executable_path: str,
    executable_candidates: Sequence[str],
    executable_artifact: str | None,
    executable_sha256: str | None,
    executable_fd: int | None,
) -> dict:
    return {
        "launch_mode": "v2",
        "run_id": run_id,
        "journal_nonce": journal_nonce,
        "manifest_hash": manifest_hash(envelope),
        "artifact_count": len(channels),
        "channel_list": [dict(record) for record in channel_records],
        "argv_fingerprint": fingerprint_argv(argv),
        "env_fingerprint": fingerprint_environment(child_env),
        "executable": argv[0],
        "cwd": _current_working_directory(),
        "seal": bool(seal),
        "uid": uid,
        "gid": gid,
        "executable_binding": executable_binding,
        "executable_path": executable_path,
        "executable_candidates": list(executable_candidates),
        "executable_artifact": executable_artifact,
        "executable_sha256": executable_sha256,
        "executable_fd": executable_fd,
    }


def _commit_channel_list(
    journal: Path,
    run_id: str,
    detail: dict,
    *,
    child_uid: int,
    journal_identity: JournalIdentity | None,
) -> dict:
    """Keep the channel list inline when it fits, otherwise detach it.

    The launch event is limited to ``MAX_EVENT_DETAIL_BYTES``. When the
    full descriptor map would exceed that, its canonical bytes are written
    to a §5.7-isolated side file (fsynced, directory fsynced) and the
    launch event commits only the filename and hash, before the append.
    """
    if "channel_list" not in detail:
        return detail
    if len(canonical_json_bytes(detail)) <= MAX_EVENT_DETAIL_BYTES:
        return detail
    records = detail.pop("channel_list")
    name, digest = write_detached_channel_list(
        journal,
        run_id,
        records,
        child_uid=child_uid,
        journal_identity=journal_identity,
    )
    detail["channel_list_sha256"] = digest
    detail["channel_list_file"] = name
    if len(canonical_json_bytes(detail)) > MAX_EVENT_DETAIL_BYTES:
        raise VerificationError(
            "launch event detail still exceeds the maximum after detaching "
            "the channel list; refusing to launch"
        )
    return detail


def _record_launch_failed(
    journal: Path,
    run_id: str,
    stage: str,
    reason: str,
    original: BaseException | None = None,
    *,
    journal_identity: JournalIdentity | None = None,
) -> None:
    detail = {
        "launch_mode": "v2",
        "run_id": run_id,
        "stage": stage,
        "reason": (reason or "launch failed")[:3000],
    }
    try:
        append_v2_event(
            journal,
            V2_LAUNCH_FAILED_EVENT_TYPE,
            detail,
            journal_identity=journal_identity,
        )
    except VerificationError as exc:
        raise VerificationError(
            f"launch failed ({reason}) and the launch-failed journal event "
            f"also failed: {exc}"
        ) from (original or exc)


def _enforce_v2_rollback(
    journal: Path,
    run_id: str,
    envelope: dict,
    min_release_seq: int | None,
    checkpoint_cache: Path | None,
    *,
    journal_identity: JournalIdentity | None,
) -> int:
    """Apply the v2 anchored-checkpoint rollback rule (§8).

    Returns the effective minimum sequence handed to verification. Every
    refusal is recorded as ``v2_launch_failed`` (stage ``launch``) before
    the exception escapes, so a refused launch never runs the child and
    leaves a durable explanation. A missing cache is never read as 0.
    """

    def refuse(reason: str, original: BaseException | None = None) -> NoReturn:
        _record_launch_failed(
            journal,
            run_id,
            "launch",
            reason,
            original,
            journal_identity=journal_identity,
        )
        raise VerificationError(reason) from (original or None)

    if min_release_seq is None:
        refuse(
            "v2 launch requires --min-release-seq: an explicit pinned "
            "minimum is mandatory in v2 mode"
        )
    try:
        minimum = validate_checkpoint_seq(min_release_seq)
    except ValueError as exc:
        refuse(f"invalid --min-release-seq: {exc}", exc)

    if checkpoint_cache is None:
        refuse(
            "v2 launch requires --checkpoint-cache: the anchored release "
            "checkpoint is mandatory, and a missing cache is not checkpoint 0"
        )
    try:
        record = read_checkpoint_cache(checkpoint_cache)
        checkpoint = verify_checkpoint_against_journal(record, journal)
    except VerificationError as exc:
        refuse(f"rollback check refused the launch: {exc}", exc)

    if minimum < checkpoint:
        refuse(
            f"rollback rejected: --min-release-seq {minimum} is below the "
            f"anchored release checkpoint {checkpoint}"
        )

    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    manifest_seq_raw = payload.get("release_seq") if isinstance(payload, dict) else None
    try:
        manifest_seq = validate_checkpoint_seq(manifest_seq_raw)
    except ValueError as exc:
        refuse(f"manifest release_seq is invalid: {exc}", exc)
    if manifest_seq < checkpoint:
        refuse(
            f"rollback rejected: manifest release_seq {manifest_seq} is "
            f"older than the anchored release checkpoint {checkpoint}"
        )

    return max(minimum, checkpoint)


def _signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except ValueError:
        return f"signal {signum}"


def _require_v2_supervision() -> None:
    """Refuse a v2 launch whose child could not be supervised (§5.4)."""
    if threading.current_thread() is not threading.main_thread():
        raise VerificationError(
            "--mode v2 must launch from the main thread: signal handling "
            "needs it, and the child's parent-death signal fires when the "
            "thread that started it exits"
        )
    if _PRCTL is None:
        raise VerificationError(
            "--mode v2 requires Linux prctl(PR_SET_PDEATHSIG) so the child "
            "is killed if the launcher dies; it is unavailable here"
        )


def _mark_unintended_fds_close_on_exec(keep_fds: Sequence[int]) -> None:
    """Close every inherited descriptor outside stdio and ``keep_fds``.

    Verified execution calls ``execveat`` from ``preexec_fn``, which is
    *before* CPython's own ``close_fds`` step: returning from the hook
    would let that step run, but the process is replaced instead. Popen's
    descriptor hygiene would therefore be skipped, leaking every fd the
    launcher happened to hold. ``execveat`` still honours close-on-exec,
    so marking the rest of the table closes them on a successful exec
    while leaving Popen's error pipe open if the exec fails (close-on-exec
    only acts on success).
    """
    if fcntl is None:
        raise VerificationError(
            "verified executable binding requires fcntl.FD_CLOEXEC to close "
            "unintended inherited descriptors before exec"
        )
    keep = {0, 1, 2, *keep_fds}
    try:
        names = os.listdir("/proc/self/fd")
    except OSError as exc:
        # Refuse rather than silently inherit an unknown descriptor table.
        raise VerificationError(
            f"verified executable binding cannot enumerate the inherited "
            f"descriptors to close them before exec: {exc}"
        ) from exc
    for name in names:
        if not name.isdigit():
            continue
        fd = int(name)
        if fd in keep:
            continue
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
        except OSError:
            # A descriptor that closed while walking the table is fine.
            continue


def _v2_preexec(
    parent_pid: int,
    uid: int,
    gid: int,
    drop_groups: tuple[int, ...] | None,
    exec_hook: Callable[[], None] | None = None,
    keep_fds: Sequence[int] = (),
) -> None:
    """Child-side setup between fork and exec (``preexec_fn``).

    The frozen design asserts no universal ordering between ``preexec_fn``
    and CPython's ``user=``/``group=``/``extra_groups=`` handling, and the
    kernel clears the parent-death signal on any later euid/egid change. So
    this hook first checks that the drop already happened and refuses
    otherwise, rather than assuming it. It then makes the child its own
    process-group leader (same session), installs
    ``PR_SET_PDEATHSIG(SIGKILL)``, and re-checks ``getppid()``: a launcher
    that died before ``prctl`` has already reparented the child, which must
    not exec unsupervised. Any failure raises, so ``Popen`` reports it and
    the command never runs.

    ``exec_hook`` is the verified-executable path's ``execveat`` call. It
    must replace the process; if it returns, this raises rather than
    letting ``Popen`` fall back to pathname execution. Because that exec
    happens before ``Popen`` closes its inherited descriptors, the
    verified path closes them itself with close-on-exec, preserving
    ``keep_fds`` (the verified artifact descriptors).
    """
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (uid, uid, gid, gid):
        raise RuntimeError("the credential drop did not precede preexec_fn")
    if drop_groups is not None and sorted(os.getgroups()) != sorted(drop_groups):
        raise RuntimeError("supplementary groups were not reset before preexec_fn")
    os.setpgid(0, 0)
    if _PRCTL is None or _PRCTL(_PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot install the parent-death signal")
    if os.getppid() != parent_pid:
        raise RuntimeError("the launcher exited before the child was supervised")
    if exec_hook is not None:
        _mark_unintended_fds_close_on_exec(keep_fds)
        exec_hook()
        raise RuntimeError("the verified-executable hook returned without exec")


class _V2SignalGuard:
    """Record the launcher's termination signals for one v2 run.

    While active, SIGHUP/SIGINT/SIGTERM are recorded instead of raising
    KeyboardInterrupt or killing the launcher, so a signal can delay the
    launch -> child -> terminal-event sequence but never cut it short.
    SIGCHLD is reset to its default for the run: an inherited ``SIG_IGN``
    makes the kernel reap the child itself and discard its exit status.
    """

    def __init__(self) -> None:
        self.signals: list[int] = []
        self._previous: dict[int, object] = {}

    def _record(self, signum: int, _frame) -> None:
        self.signals.append(signum)

    def __enter__(self) -> "_V2SignalGuard":
        try:
            for signum in _V2_FORWARDED_SIGNALS:
                previous = signal.getsignal(signum)
                if previous == signal.SIG_IGN:
                    continue
                self._previous[signum] = previous
                signal.signal(signum, self._record)
            self._previous[signal.SIGCHLD] = signal.getsignal(signal.SIGCHLD)
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        except BaseException:
            self._restore()
            raise
        return self

    def __exit__(self, *exc_info) -> None:
        self._restore()

    def _restore(self) -> None:
        for signum, previous in self._previous.items():
            signal.signal(signum, signal.SIG_DFL if previous is None else previous)
        self._previous.clear()


class _V2RunResult(NamedTuple):
    returncode: int
    #: First termination signal the launcher received and forwarded, or 0.
    launcher_signal: int
    #: Whether the launcher sent the child's process group SIGKILL after
    #: V2_SIGNAL_FORWARD_TIMEOUT.
    escalated: bool


def _signal_process_group(pgid: int, signum: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pgid, signum)


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _reap_v2_child(proc: subprocess.Popen) -> int | None:
    """Return the child's returncode once it has exited, else ``None``.

    ``Popen.poll`` reports 0 when the status has been lost (ECHILD); a v2
    finish event must never record a status the launcher did not observe.
    """
    try:
        pid, status = os.waitpid(proc.pid, os.WNOHANG)
    except ChildProcessError as exc:
        raise VerificationError(
            "the v2 child's exit status is unavailable (it was reaped outside "
            "the launcher); refusing to record a status that was not observed"
        ) from exc
    if pid == 0:
        return None
    proc.returncode = os.waitstatus_to_exitcode(status)
    return proc.returncode


def _wait_v2_child(proc: subprocess.Popen, signals: list[int]) -> _V2RunResult:
    """The explicit v2 wait loop (§5.4).

    Each recorded launcher signal is forwarded to the child's process group,
    followed by SIGCONT so a stopped child can act on it. If the group has
    not exited V2_SIGNAL_FORWARD_TIMEOUT seconds after the first forward,
    it is sent SIGKILL. With no launcher signal, the loop returns as soon as
    the direct child exits and leaves any descendants alone; after a signal,
    it also waits (up to the deadline) for the rest of the group.
    """
    pgid = proc.pid
    returncode: int | None = None
    launcher_signal = 0
    forwarded = 0
    deadline: float | None = None
    escalated = False
    while True:
        if returncode is None:
            returncode = _reap_v2_child(proc)
        while forwarded < len(signals):
            signum = signals[forwarded]
            forwarded += 1
            launcher_signal = launcher_signal or signum
            if not escalated:
                _signal_process_group(pgid, signum)
                _signal_process_group(pgid, signal.SIGCONT)
                if deadline is None:
                    deadline = time.monotonic() + V2_SIGNAL_FORWARD_TIMEOUT
        if returncode is not None and (
            not launcher_signal or escalated or not _process_group_exists(pgid)
        ):
            return _V2RunResult(returncode, launcher_signal, escalated)
        if deadline is not None and not escalated and time.monotonic() >= deadline:
            _signal_process_group(pgid, signal.SIGKILL)
            escalated = True
            continue
        time.sleep(_V2_WAIT_POLL_INTERVAL)


def _run_v2_child(
    argv: Sequence[str],
    *,
    pass_fds: tuple[int, ...],
    child_env: Mapping[str, str],
    uid: int,
    gid: int,
    drop_groups: tuple[int, ...] | None,
    signals: list[int],
    exec_hook: Callable[[], None] | None = None,
) -> _V2RunResult:
    """Start the v2 child and supervise it until it exits.

    ``subprocess.run`` is not used: on KeyboardInterrupt it kills the child
    and re-raises, so the finish event could never be written. Failures
    starting the child propagate exactly as ``Popen`` raises them. Once the
    child runs, any failure kills its process group and surfaces as
    :class:`VerificationError`, never as a launch failure.

    Terminal policy: the child gets its own process group in the
    launcher's session and is NOT made the terminal's foreground group (no
    ``tcsetpgrp``); terminal loss is accepted. Terminal-generated signals
    reach the launcher, which forwards them; a child that reads the
    controlling terminal is stopped by SIGTTIN until the launcher is
    signalled. Descendants that leave the process group (e.g. ``setsid``)
    escape both forwarding and escalation, and a SIGKILLed launcher writes
    nothing: its child dies by the parent-death signal unless it escaped.

    With ``exec_hook`` set, the child executes the verified descriptor in
    ``preexec_fn`` instead of letting ``Popen`` exec ``argv[0]`` by path.
    """
    parent_pid = os.getpid()
    if exec_hook is None:
        preexec = lambda: _v2_preexec(parent_pid, uid, gid, drop_groups)
    else:
        preexec = lambda: _v2_preexec(
            parent_pid, uid, gid, drop_groups, exec_hook, pass_fds
        )
    proc = subprocess.Popen(
        list(argv),
        pass_fds=pass_fds,
        env=dict(child_env),
        user=uid,
        group=gid,
        extra_groups=drop_groups,
        preexec_fn=preexec,
    )
    try:
        return _wait_v2_child(proc, signals)
    except BaseException as exc:
        _signal_process_group(proc.pid, signal.SIGKILL)
        with contextlib.suppress(Exception):
            for _ in range(100):
                if proc.returncode is not None or _reap_v2_child(proc) is not None:
                    break
                time.sleep(_V2_WAIT_POLL_INTERVAL)
        if isinstance(exc, VerificationError) or not isinstance(exc, Exception):
            raise
        raise VerificationError(f"lost supervision of the v2 child: {exc}") from exc


def _launch_v2(
    journal: Path,
    run_id: str,
    launch_detail: dict,
    argv: Sequence[str],
    *,
    pass_fds: tuple[int, ...],
    child_env: Mapping[str, str],
    uid: int,
    gid: int,
    drop_groups: tuple[int, ...] | None,
    exec_hook: Callable[[], None] | None = None,
    journal_identity: JournalIdentity | None = None,
) -> tuple[int | None, int]:
    """Journal the launch, run the child, journal its terminal event.

    Returns ``(returncode, signal_to_reraise)``. ``returncode`` is ``None``
    when a termination signal arrived before the child was started; the
    child is then never started and a ``v2_launch_failed`` event records
    why. ``signal_to_reraise`` is 0 when the launcher received no signal.
    """
    with _V2SignalGuard() as guard:
        # The launch event is fsynced by append_v2_event before the child
        # is created (§6.1).
        append_v2_event(
            journal,
            V2_LAUNCH_EVENT_TYPE,
            launch_detail,
            journal_identity=journal_identity,
        )
        if journal_identity is not None:
            # The first append may have created the journal. Re-pin the
            # resulting inode so the terminal append is checked against the
            # file this launch actually wrote, not the pre-creation state.
            journal_identity = pin_journal_identity(journal)
        if guard.signals:
            signum = guard.signals[0]
            _record_launch_failed(
                journal,
                run_id,
                "launch",
                f"launcher received {_signal_name(signum)} before the child "
                f"was started",
                journal_identity=journal_identity,
            )
            return None, signum
        started = time.monotonic()
        run_kwargs = {
            "pass_fds": pass_fds,
            "child_env": child_env,
            "uid": uid,
            "gid": gid,
            "drop_groups": drop_groups,
            "signals": guard.signals,
        }
        if exec_hook is not None:
            run_kwargs["exec_hook"] = exec_hook
        try:
            result = _run_v2_child(argv, **run_kwargs)
        except PermissionError as exc:
            # ``PermissionError`` covers both a failed credential drop and a
            # failed exec (e.g. a non-executable file). CPython sets
            # ``filename`` for the exec failure but leaves it ``None`` for
            # the drop, so classify by that field rather than errno alone.
            if exc.filename is None:
                reason = (
                    f"cannot drop privileges to uid={uid} gid={gid}: {exc}"
                )
                _record_launch_failed(
                    journal,
                    run_id,
                    "privilege_drop",
                    reason,
                    exc,
                    journal_identity=journal_identity,
                )
                raise VerificationError(reason) from exc
            reason = f"cannot launch {argv[0]!r}: {exc}"
            _record_launch_failed(
                journal, run_id, "exec", reason, exc,
                journal_identity=journal_identity,
            )
            raise VerificationError(reason) from exc
        except OSError as exc:
            _record_launch_failed(
                journal, run_id, "exec", f"cannot launch {argv[0]!r}: {exc}", exc,
                journal_identity=journal_identity,
            )
            raise VerificationError(f"cannot launch {argv[0]!r}: {exc}") from exc
        except SubprocessError as exc:
            reason = (
                f"cannot launch {argv[0]!r}: child setup before exec failed "
                f"(credential check, process group, parent-death signal, or "
                f"verified-executable hook): {exc}"
            )
            _record_launch_failed(journal, run_id, "exec", reason, exc,
                                  journal_identity=journal_identity)
            raise VerificationError(reason) from exc
        duration_ms = max(0, int((time.monotonic() - started) * 1000))
        try:
            append_v2_event(
                journal,
                V2_FINISH_EVENT_TYPE,
                {
                    "launch_mode": "v2",
                    "run_id": run_id,
                    "exit_code": result.returncode,
                    "launcher_signal": result.launcher_signal,
                    "escalated": result.escalated,
                    "duration_ms": duration_ms,
                },
                journal_identity=journal_identity,
            )
        except VerificationError as exc:
            raise VerificationError(
                f"child exited with status {result.returncode} but "
                f"the v2 finish event could not be recorded: {exc}"
            ) from exc
        reraise = guard.signals[0] if guard.signals else 0
    return result.returncode, reraise


def _reraise_signal(signum: int) -> NoReturn:
    """Die by ``signum`` so a supervisor sees WIFSIGNALED (freeze decision 5).

    An 8-bit exit code would collide with a legal child status. If the
    default action is not applied — the kernel shields a PID namespace's
    init process from it — fall back to the shell's 128+N convention.
    """
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.flush()
    signal.signal(signum, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signum})
    signal.raise_signal(signum)
    os._exit(128 + signum)


def launch(
    root: Path,
    envelope: dict,
    public_key: bytes,
    command: Sequence[str],
    *,
    min_release_seq: int | None = None,
    checkpoint_cache: Path | None = None,
    seal: bool = False,
    uid: int | None = None,
    gid: int | None = None,
    env: Mapping[str, str] | None = None,
    mode: str = "v1",
    journal: Path | None = None,
    require_v2: bool = False,
    executable_binding: str = "record-only",
    executable_artifact: str | None = None,
) -> int:
    """Verify a manifest and run ``command`` against the verified handles.

    Returns the child's exit status. Raises :class:`VerificationError` if
    the manifest, its signature, an artifact, or the launch itself fails
    — in every failure case the command is *not* run.

    ``mode`` is the explicit per-launch v2 toggle (§5.0). The default is
    ``"v1"``, which preserves the existing behaviour exactly and writes no
    journal record. ``"v2"`` requires ``journal`` and a privileged launcher
    that drops the child to a different uid; it writes strictly-validated
    ``v2_launch`` / ``v2_finish`` / ``v2_launch_failed`` events around the
    child. ``require_v2`` makes a v2-only deployment refuse a v1 invocation
    at the point of invocation, rather than trying to infer compliance
    from records later.

    A v2 launch also requires both ``min_release_seq`` and
    ``checkpoint_cache`` (§8, freeze decision 4). ``checkpoint_cache`` is
    the append-only anchored checkpoint store read by
    :func:`sealrun.checkpoint_cache.read_checkpoint_cache`; the launcher
    binds its anchored prefix to the journal and requires the manifest's
    sequence to be at least the anchored ``release_seq``. Omitting either
    value, or supplying ``min_release_seq`` below the anchored checkpoint,
    refuses the launch and records ``v2_launch_failed`` without running the
    child. A missing cache is never treated as checkpoint 0.

    ``executable_binding`` is ``"record-only"`` by default (§5.3): the v2
    launch record names the executable as given, the effective ``PATH``,
    and the candidates considered, but claims nothing about which bytes
    ran. ``"verified"`` (v2 only) executes a manifest artifact through its
    verified descriptor with Linux ``execveat(AT_EMPTY_PATH)``; it requires
    an ELF image, refuses when ``execveat`` is unavailable or fails, and
    never falls back to pathname execution. ``argv[0]`` must match a
    manifest artifact path exactly unless ``executable_artifact`` names
    the artifact explicitly. Scripts remain record-only.

    A v2 launch must run on the main thread. If the launcher receives
    SIGHUP, SIGINT, or SIGTERM during the run, it forwards the signal to
    the child's process group, sends the group SIGKILL if it has not exited
    within :data:`V2_SIGNAL_FORWARD_TIMEOUT` seconds, records the
    termination in the finish event, and then kills the calling process
    with that same signal instead of returning, so a supervisor sees
    WIFSIGNALED.

    The child does **not** inherit the caller's environment: it gets
    only the ``SEALRUN_*`` provenance and artifact-descriptor variables,
    plus ``PATH`` (so a command named rather than given by absolute
    path can be found). Pass ``env`` to supply a different base
    environment instead; it replaces that default entirely.
    """
    if mode not in ("v1", "v2"):
        raise VerificationError(f"launch mode must be 'v1' or 'v2', not {mode!r}")
    if executable_binding not in ("record-only", "verified"):
        raise VerificationError(
            "executable_binding must be 'record-only' or 'verified', "
            f"not {executable_binding!r}"
        )
    if executable_artifact is not None and executable_binding != "verified":
        raise VerificationError(
            "--executable-artifact requires --executable-binding verified; "
            "a record-only launch makes no executable-artifact claim"
        )
    if executable_binding == "verified" and mode != "v2":
        raise VerificationError(
            "verified executable binding requires --mode v2 so the launch "
            "record names the artifact it executed"
        )
    if mode == "v1":
        if require_v2:
            raise VerificationError(
                "this deployment requires v2, but the launch was invoked in "
                "v1 mode; pass --mode v2 (v1 is never a silent downgrade)"
            )
        if journal is not None:
            raise VerificationError(
                "--journal is only valid with --mode v2; v1 launches write "
                "no journal record"
            )
        if checkpoint_cache is not None:
            raise VerificationError(
                "--checkpoint-cache is only valid with --mode v2; v1 "
                "launches consume no anchored release checkpoint"
            )
    else:
        if journal is None:
            raise VerificationError(
                "--mode v2 requires --journal (the launch, finish, and "
                "launch-failed events are mandatory)"
            )
        journal = Path(journal)

    argv = [arg for arg in command]
    while argv and argv[0] == "--":
        argv.pop(0)
    if not argv:
        raise VerificationError(
            "launch requires a command to run (use '-- CMD [ARGS...]')"
        )

    # A uid without a gid would leave the process in the caller's primary
    # group; default to the target user's own group (fail closed if it has
    # no passwd entry).
    if uid is not None and gid is None:
        gid = _primary_gid(uid)

    # When dropping privilege from a privileged caller, also clear
    # supplementary groups, or the child keeps root's group memberships.
    # Clearing them requires privilege, so only do it when we have it.
    drop_groups: tuple[int, ...] | None = None
    if (uid is not None or gid is not None) and os.geteuid() == 0:
        drop_groups = ()

    run_id: str | None = None
    journal_nonce: str | None = None
    journal_identity: JournalIdentity | None = None
    effective_min_release_seq = min_release_seq
    if mode == "v2":
        # Refuse an unisolated v2 invocation before any verification work:
        # a v2 run-state claim is unavailable without the §5.7 predicate.
        assert_journal_writer_isolation(journal, uid)
        _require_v2_supervision()
        # Pin the directory and (if present) the journal inode now, so an
        # append cannot extend a journal renamed over the path later.
        journal_identity = pin_journal_identity(journal)
        run_id = str(uuid.uuid4())
        journal_nonce = uuid.uuid4().hex
        assert journal is not None
        effective_min_release_seq = _enforce_v2_rollback(
            journal,
            run_id,
            envelope,
            min_release_seq,
            checkpoint_cache,
            journal_identity=journal_identity,
        )

    reraise_signal = 0
    with verified_artifacts(
        root, envelope, public_key, effective_min_release_seq
    ) as artifacts:
        channels: list[tuple[str, int]] = []
        channel_records: list[dict[str, object]] = []
        sealed_fds: list[int] = []
        try:
            for artifact in artifacts:
                if seal:
                    fd = _seal_fd(
                        artifact.handle.fileno(),
                        expected_sha256=artifact.sha256,
                        expected_size=artifact.size,
                    )
                    sealed_fds.append(fd)
                else:
                    fd = artifact.handle.fileno()
                channels.append((artifact.path, fd))
                channel_records.append(
                    {
                        "path": artifact.path,
                        "env": artifact_env_name(artifact.path),
                        "sha256": artifact.sha256,
                        "fd": fd,
                    }
                )
            child_env = build_child_environment(envelope, channels, env)
            pass_fds = tuple(fd for _, fd in channels)
            if mode == "v2":
                assert journal is not None and run_id is not None
                assert uid is not None and gid is not None
                assert journal_nonce is not None
                executable_path = ""
                executable_candidates: list[str] = []
                executable_artifact_path: str | None = None
                executable_sha256: str | None = None
                executable_fd: int | None = None
                exec_hook: Callable[[], None] | None = None
                if executable_binding == "record-only":
                    executable_path, executable_candidates = (
                        _record_only_executable_fields(argv[0], child_env)
                    )
                else:
                    if _EXECVEAT is None:
                        raise VerificationError(
                            "verified executable binding requires Linux "
                            "execveat(AT_EMPTY_PATH); it is unavailable here"
                        )
                    memfd_noexec = _read_memfd_noexec()
                    if seal and memfd_noexec in (1, 2):
                        raise VerificationError(
                            "verified executable binding with --seal is "
                            "unavailable: vm.memfd_noexec is "
                            f"{memfd_noexec}, so a sealed memfd copy is not "
                            "executable (refusing rather than downgrading)"
                        )
                    selected = _select_executable_artifact(
                        artifacts, argv, executable_artifact
                    )
                    channel_by_path = {path: fd for path, fd in channels}
                    executable_fd = channel_by_path[selected.path]
                    _assert_elf_executable(executable_fd, selected.path)
                    executable_path = os.pathsep.join(
                        _executable_search_path(child_env)
                    )
                    executable_artifact_path = selected.path
                    executable_sha256 = selected.sha256
                    exec_hook = lambda: _execveat(  # noqa: E731
                        executable_fd, argv, child_env
                    )
                launch_detail = _v2_launch_detail(
                    envelope,
                    channels,
                    channel_records,
                    argv,
                    child_env,
                    run_id=run_id,
                    journal_nonce=journal_nonce,
                    seal=seal,
                    uid=uid,
                    gid=gid,
                    executable_binding=executable_binding,
                    executable_path=executable_path,
                    executable_candidates=executable_candidates,
                    executable_artifact=executable_artifact_path,
                    executable_sha256=executable_sha256,
                    executable_fd=executable_fd,
                )
                launch_detail = _commit_channel_list(
                    journal,
                    run_id,
                    launch_detail,
                    child_uid=uid,
                    journal_identity=journal_identity,
                )
                returncode, reraise_signal = _launch_v2(
                    journal,
                    run_id,
                    launch_detail,
                    argv,
                    pass_fds=pass_fds,
                    child_env=child_env,
                    uid=uid,
                    gid=gid,
                    drop_groups=drop_groups,
                    exec_hook=exec_hook,
                    journal_identity=journal_identity,
                )
            else:
                try:
                    completed = subprocess.run(
                        argv,
                        pass_fds=pass_fds,
                        env=child_env,
                        user=uid,
                        group=gid,
                        extra_groups=drop_groups,
                        check=False,
                    )
                except PermissionError as exc:
                    raise VerificationError(
                        f"cannot drop privileges to uid={uid} gid={gid}: {exc}"
                    ) from exc
                except OSError as exc:
                    raise VerificationError(f"cannot launch {argv[0]!r}: {exc}") from exc
                returncode = completed.returncode
        finally:
            for fd in sealed_fds:
                with contextlib.suppress(OSError):
                    os.close(fd)
    if reraise_signal:
        # Only now — terminal event durable, launcher resources released.
        _reraise_signal(reraise_signal)
    return returncode
