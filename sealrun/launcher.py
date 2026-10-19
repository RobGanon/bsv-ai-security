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
the original inode cannot change what the model sees. Sealing costs a
copy of every artifact into RAM, so it is opt-in.

Residual limits are stated plainly because they matter:

* Without ``seal`` the fd pins the *inode*, not its contents — a writer
  with access to the verified inode can still mutate it after hashing,
  so the child may read changed bytes. ``seal=True`` removes this.
* A swap of an *intermediate directory* component between the
  per-component walk in :func:`core._validated_entries` and the open in
  :func:`core._open_verified_fd` remains a narrow race; closing it fully
  needs opening each component with ``O_NOFOLLOW``.
* The launcher pins *what bytes are launched*; it does not sandbox the
  child. Containment (namespaces, seccomp, cgroups) is out of scope.
"""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

from .core import (
    VerificationError,
    manifest_hash,
    verified_artifacts,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix platforms
    fcntl = None  # type: ignore[assignment]

_ENV_PREFIX = "SEALRUN_ARTIFACT_"
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")

# F_SEAL_* values (linux/memfd.h). The fallbacks let the module import on
# platforms whose fcntl lacks them; ``_seal_fd`` refuses at call time.
_SEAL_BITS = (
    getattr(fcntl, "F_SEAL_WRITE", 0x0008)
    | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
    | getattr(fcntl, "F_SEAL_GROW", 0x0004)
    | getattr(fcntl, "F_SEAL_SEAL", 0x1000)
)


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


def _seal_fd(src_fd: int, *, chunk: int = 1 << 20) -> int:
    """Copy the bytes at ``src_fd`` into a sealed memfd; return its fd.

    The returned descriptor reads the frozen snapshot: it rejects
    ``write``, ``ftruncate``, and further ``F_ADD_SEALS`` calls. The
    caller owns the descriptor and must close it.
    """
    if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
        raise VerificationError("sealing requires memfd_create (Linux)")
    if fcntl is None or not hasattr(fcntl, "F_ADD_SEALS"):
        raise VerificationError("sealing requires fcntl.F_ADD_SEALS (Linux)")
    os.lseek(src_fd, 0, os.SEEK_SET)
    mem_fd = os.memfd_create("sealrun-artifact", os.MFD_ALLOW_SEALING)
    try:
        while True:
            data = os.read(src_fd, chunk)
            if not data:
                break
            _write_all(mem_fd, data)
        fcntl.fcntl(mem_fd, fcntl.F_ADD_SEALS, _SEAL_BITS)
        os.lseek(mem_fd, 0, os.SEEK_SET)
        return mem_fd
    except BaseException:
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

    Starts from ``base`` (default: the launcher's own environment) and
    overlays the verified-manifest provenance and artifact descriptors.
    """
    env = dict(os.environ if base is None else base)
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


def launch(
    root: Path,
    envelope: dict,
    public_key: bytes,
    command: Sequence[str],
    *,
    min_release_seq: int | None = None,
    seal: bool = False,
    uid: int | None = None,
    gid: int | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    """Verify a manifest and run ``command`` against the verified handles.

    Returns the child's exit status. Raises :class:`VerificationError` if
    the manifest, its signature, an artifact, or the launch itself fails
    — in every failure case the command is *not* run. The caller's
    environment is inherited unless ``env`` supplies a replacement base.
    """
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

    with verified_artifacts(root, envelope, public_key, min_release_seq) as artifacts:
        channels: list[tuple[str, int]] = []
        sealed_fds: list[int] = []
        try:
            for artifact in artifacts:
                if seal:
                    fd = _seal_fd(artifact.handle.fileno())
                    sealed_fds.append(fd)
                else:
                    fd = artifact.handle.fileno()
                channels.append((artifact.path, fd))
            child_env = build_child_environment(envelope, channels, env)
            try:
                completed = subprocess.run(
                    argv,
                    pass_fds=tuple(fd for _, fd in channels),
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
            return completed.returncode
        finally:
            for fd in sealed_fds:
                with contextlib.suppress(OSError):
                    os.close(fd)
