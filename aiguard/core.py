from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix platforms
    fcntl = None  # type: ignore[assignment]

HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")

# Limits for the local audit journal (Phase 1 DoS hardening).
MAX_EVENT_DETAIL_BYTES = 4096
MAX_JOURNAL_EVENTS = 1_000_000

# O_NOFOLLOW makes open(2) fail on a trailing symlink instead of following it.
# It is Unix-only; where unavailable the per-component symlink walk in
# _validated_entries() and the fstat() regular-file check in _open_verified_fd()
# still apply.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class VerificationError(ValueError):
    """Raised when a manifest or artifact fails verification."""


@dataclasses.dataclass
class VerifiedArtifact:
    """An artifact whose bytes have been verified against a signed manifest.

    `handle` is an open binary file object positioned at offset 0. It was
    opened with O_NOFOLLOW (where available), confirmed by fstat() to be a
    regular file, and hashed from the open descriptor *before* being handed
    out. Bytes read from `handle` are therefore exactly the verified bytes,
    which closes the check-to-use window that exists when a consumer
    re-opens the artifact path after verification. The consumer (or the
    `verified_artifacts()` context manager) must close the handle.
    """

    path: str
    sha256: str
    size: int
    handle: BinaryIO


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _sha256_fd(fd: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def generate_keypair(private_path: Path, public_path: Path) -> None:
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Best-effort restrictive permissions; umask is also applied by the OS.
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_bytes)
    public_path.write_bytes(public_bytes)
    try:
        os.chmod(private_path, 0o600)
        os.chmod(public_path, 0o644)
    except OSError:
        pass


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise VerificationError("private key is not Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationError("public key is not Ed25519")
    return key


def _check_release_seq(value: Any, *, field: str = "release_seq") -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise VerificationError(f"invalid {field}: must be a non-negative integer")
    return value


def create_manifest(
    root: Path, relative_paths: list[str], release_id: str, release_seq: int
) -> dict:
    if not isinstance(release_id, str) or not release_id:
        raise VerificationError("release_id must be a non-empty string")
    release_seq = _check_release_seq(release_seq)
    artifacts = []
    for raw in relative_paths:
        rel = _safe_relative_path(raw)
        full = root / rel
        if full.is_symlink() or not full.is_file():
            raise VerificationError(f"artifact must be a regular non-symlink file: {raw}")
        digest, size = sha256_file(full)
        artifacts.append({"path": rel.as_posix(), "sha256": digest, "size": size})
    return {
        "schema": "aiguard-manifest-v1",
        "release_id": release_id,
        "release_seq": release_seq,
        "artifacts": artifacts,
    }


def sign_manifest(payload: dict, private_key: Ed25519PrivateKey) -> dict:
    signature = private_key.sign(canonical_json_bytes(payload))
    return {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}


def _load_verified_payload(envelope: dict, public_key: Ed25519PublicKey) -> dict:
    """Validate envelope shape/schema and the Ed25519 signature; return payload."""
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise VerificationError("invalid signed envelope fields")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or payload.get("schema") != "aiguard-manifest-v1":
        raise VerificationError("unsupported manifest schema")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        public_key.verify(signature, canonical_json_bytes(payload))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise VerificationError("manifest signature invalid") from exc
    return payload


def _check_rollback_policy(payload: dict, min_release_seq: int | None) -> int:
    """Validate release identity and enforce the caller\'s minimum sequence.

    Returns the manifest\'s release_seq. The caller supplies min_release_seq
    from its own trusted state (e.g. the highest sequence it has ever
    accepted, persisted in protected storage or anchored externally);
    without it, an older legitimately-signed manifest would verify fine,
    which is a rollback attack.
    """
    release_id = payload.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        raise VerificationError("invalid release_id in manifest")
    release_seq = _check_release_seq(payload.get("release_seq"))
    if min_release_seq is not None:
        _check_release_seq(min_release_seq, field="min_release_seq")
        if release_seq < min_release_seq:
            raise VerificationError(
                f"rollback rejected: manifest release_seq={release_seq} "
                f"is older than minimum accepted {min_release_seq}"
            )
    return release_seq


def _validated_entries(root: Path, payload: dict) -> list[tuple[Path, str, int]]:
    """Validate artifact entries and return (relative path, hash, size) tuples.

    Performs all structural checks plus the per-component symlink walk, but
    does not hash file contents; callers hash via path or open descriptor.
    """
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise VerificationError("manifest must contain at least one artifact")

    entries = []
    seen = set()
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise VerificationError("invalid artifact entry")
        rel = _safe_relative_path(item["path"])
        if rel.as_posix() in seen:
            raise VerificationError("duplicate artifact path")
        seen.add(rel.as_posix())
        expected_hash = item["sha256"]
        expected_size = item["size"]
        if not isinstance(expected_hash, str) or not HEX_64.fullmatch(expected_hash):
            raise VerificationError(f"invalid SHA-256 for {rel}")
        expected_hash = expected_hash.lower()
        if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
            raise VerificationError(f"invalid size for {rel}")

        full = root / rel
        # Reject symlinks at any component, not just the final file.
        current = root
        for part in rel.parts:
            current = current / part
            if current.is_symlink():
                raise VerificationError(f"symlink path is not allowed: {rel}")
        if not full.is_file():
            raise VerificationError(f"artifact missing or not a file: {rel}")
        entries.append((rel, expected_hash, expected_size))
    return entries


def verify_manifest(
    root: Path,
    envelope: dict,
    public_key: Ed25519PublicKey,
    min_release_seq: int | None = None,
) -> list[str]:
    """Verify manifest signature, rollback policy, and artifact hashes.

    Returns the verified relative artifact paths. Note the check-to-use
    caveat: this hashes files and returns, so a consumer that re-opens the
    paths afterwards has a window for tampering. Consumers that need the
    verified bytes themselves should use `verified_artifacts()` instead.
    """
    payload = _load_verified_payload(envelope, public_key)
    _check_rollback_policy(payload, min_release_seq)
    verified = []
    for rel, expected_hash, expected_size in _validated_entries(root, payload):
        actual_hash, actual_size = sha256_file(root / rel)
        if actual_hash != expected_hash or actual_size != expected_size:
            raise VerificationError(f"artifact integrity mismatch: {rel.as_posix()}")
        verified.append(rel.as_posix())
    return verified


def _open_verified_fd(path: Path) -> int:
    """Open a file descriptor without following a trailing symlink.

    The descriptor is confirmed by fstat() to reference a regular file, so a
    symlink (or fifo/device) swapped in at the final component cannot slip
    through. A swapped *intermediate* directory component between the walk in
    _validated_entries() and this open remains a residual race; closing it
    fully requires opening each component with O_NOFOLLOW, which is left to
    the future privileged launcher.
    """
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | _O_NOFOLLOW)
    except OSError as exc:
        raise VerificationError(
            f"cannot open artifact without following symlinks: {path}"
        ) from exc
    try:
        mode = os.fstat(fd).st_mode
    except OSError as exc:
        os.close(fd)
        raise VerificationError(f"cannot stat artifact: {path}") from exc
    if not stat.S_ISREG(mode):
        os.close(fd)
        raise VerificationError(f"artifact is not a regular file: {path}")
    return fd


@contextlib.contextmanager
def verified_artifacts(
    root: Path,
    envelope: dict,
    public_key: Ed25519PublicKey,
    min_release_seq: int | None = None,
) -> Iterator[list[VerifiedArtifact]]:
    """Verify a manifest and yield open handles to the verified artifact bytes.

    This is the TOCTOU-resistant verification API: each artifact is opened
    with O_NOFOLLOW, confirmed to be a regular file, hashed *from the open
    descriptor*, and yielded positioned at offset 0. A consumer (e.g. the
    future launcher) that reads or executes from these handles gets exactly
    the bytes that were verified, with no window for replacement between the
    check and the use. All handles are closed when the context exits,
    including on verification failure part-way through.
    """
    payload = _load_verified_payload(envelope, public_key)
    _check_rollback_policy(payload, min_release_seq)
    opened: list[VerifiedArtifact] = []
    try:
        for rel, expected_hash, expected_size in _validated_entries(root, payload):
            fd = _open_verified_fd(root / rel)
            try:
                actual_hash, actual_size = _sha256_fd(fd)
            except OSError as exc:
                os.close(fd)
                raise VerificationError(
                    f"error reading artifact: {rel.as_posix()}"
                ) from exc
            if actual_hash != expected_hash or actual_size != expected_size:
                os.close(fd)
                raise VerificationError(
                    f"artifact integrity mismatch: {rel.as_posix()}"
                )
            os.lseek(fd, 0, os.SEEK_SET)
            opened.append(
                VerifiedArtifact(
                    path=rel.as_posix(),
                    sha256=actual_hash,
                    size=actual_size,
                    handle=os.fdopen(fd, "rb"),
                )
            )
        yield opened
    finally:
        for artifact in opened:
            try:
                artifact.handle.close()
            except OSError:
                pass


def _safe_relative_path(raw: str) -> Path:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise VerificationError("artifact path must be a non-empty string")
    # Treat paths as POSIX-style manifest paths for portable validation.
    if raw.startswith("/") or "\\" in raw:
        raise VerificationError(f"absolute or non-portable path rejected: {raw}")
    parts = raw.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise VerificationError(f"path traversal or empty component rejected: {raw}")
    return Path(*parts)


def append_audit_event(journal: Path, event_type: str, detail: str) -> dict:
    """Append an event only when the existing journal is valid.

    This prevents the normal append path from silently extending a journal
    whose earlier events have already been modified or truncated.

    On platforms that support it, an exclusive advisory lock is held across
    the verify-then-write critical section so concurrent writers cannot race.
    """
    if not isinstance(event_type, str) or not event_type:
        raise VerificationError("event_type must be a non-empty string")
    if not isinstance(detail, str):
        raise VerificationError("detail must be a string")
    detail_bytes = detail.encode("utf-8")
    if len(detail_bytes) > MAX_EVENT_DETAIL_BYTES:
        raise VerificationError(
            f"detail exceeds maximum of {MAX_EVENT_DETAIL_BYTES} UTF-8 bytes"
        )

    journal.parent.mkdir(parents=True, exist_ok=True)
    if journal.is_symlink():
        raise VerificationError("audit journal must be a regular non-symlink file")

    # Open with create + append so we can lock the same FD used for writing.
    # O_NOFOLLOW makes the open itself fail on a trailing symlink instead of
    # following it, closing the check-then-open race on the is_symlink()
    # pre-check above for an attacker racing a parent-directory swap.
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | _O_NOFOLLOW
    try:
        fd = os.open(os.fspath(journal), flags, 0o644)
    except OSError as exc:
        raise VerificationError(
            "audit journal must be a regular non-symlink file"
        ) from exc
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)

        # Re-check after acquiring the lock (symlink / non-regular race).
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode):
            raise VerificationError("audit journal must be a regular non-symlink file")

        prior: list[dict] = []
        size = os.fstat(fd).st_size
        if size:
            # Read existing content via a separate text handle on the same path
            # (the locked FD is binary). The lock serialises concurrent writers.
            prior = _read_jsonl(journal)
            _verify_audit_events(prior)

        if len(prior) >= MAX_JOURNAL_EVENTS:
            raise VerificationError(
                f"journal already contains the maximum of {MAX_JOURNAL_EVENTS} events"
            )

        previous = prior[-1]["event_hash"].lower() if prior else "0" * 64
        next_seq = prior[-1]["seq"] + 1 if prior else 1
        event = {
            "seq": next_seq,
            "event_type": event_type,
            "detail": detail,
            "previous_hash": previous,
        }
        event["event_hash"] = hashlib.sha256(canonical_json_bytes(event)).hexdigest()
        # Serialize with the same canonical form the hash was computed over
        # (UTF-8, sorted keys, no whitespace, ensure_ascii=False), so the
        # stored bytes match the hashed bytes for independent verifiers.
        line = canonical_json_bytes(event).decode("utf-8") + "\n"
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
        return event
    finally:
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def verify_audit_journal(journal: Path) -> int:
    if journal.is_symlink():
        raise VerificationError("audit journal must be a regular non-symlink file")
    if not journal.exists():
        return 0
    if not journal.is_file():
        raise VerificationError("audit journal must be a regular non-symlink file")
    return _verify_audit_events(_read_jsonl(journal))


def _verify_audit_events(events: list[dict]) -> int:
    previous = "0" * 64
    expected_seq = 1
    for event in events:
        if not isinstance(event, dict) or "event_hash" not in event:
            raise VerificationError("malformed audit event")
        event_hash = event["event_hash"]
        if not isinstance(event_hash, str) or not HEX_64.fullmatch(event_hash):
            raise VerificationError(f"malformed audit event hash at sequence {expected_seq}")
        body = {k: v for k, v in event.items() if k != "event_hash"}
        try:
            actual = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        except (TypeError, ValueError) as exc:
            raise VerificationError(f"malformed audit event at sequence {expected_seq}") from exc
        # Accept mixed-case stored hashes; always compare in lowercase.
        if actual != event_hash.lower():
            raise VerificationError(f"audit event hash mismatch at sequence {expected_seq}")
        prev = event.get("previous_hash")
        if not isinstance(prev, str) or not HEX_64.fullmatch(prev) or prev.lower() != previous:
            raise VerificationError(f"audit chain broken at sequence {expected_seq}")
        seq = event.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq != expected_seq:
            raise VerificationError(f"audit sequence mismatch at sequence {expected_seq}")
        previous = event_hash.lower()
        expected_seq += 1
    return len(events)


def _read_jsonl(path: Path) -> list[dict]:
    events = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                raise VerificationError(f"blank line in audit journal at line {line_no}")
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise VerificationError(f"invalid JSON at audit line {line_no}") from exc
            if not isinstance(event, dict):
                raise VerificationError(f"audit event must be a JSON object at line {line_no}")
            events.append(event)
    return events
