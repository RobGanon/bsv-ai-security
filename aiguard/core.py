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

UINT32_MAX = (1 << 32) - 1

# O_NOFOLLOW makes open(2) fail on a trailing symlink instead of following it.
# It is Unix-only; where unavailable the per-component symlink walk in
# _validated_entries() and the fstat() regular-file check in _open_verified_fd()
# still apply.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class VerificationError(ValueError):
    """Raised when a manifest or artifact fails verification."""


@dataclasses.dataclass
class VerifiedArtifact:
    """An artifact whose bytes have been verified against a signed manifest.

    `handle` is an open binary file object positioned at offset 0. It was
    opened with O_NOFOLLOW (where available), confirmed by fstat() to be a
    regular file, and hashed from the open descriptor *before* being handed
    out. The handle pins the inode, which closes the check-to-use window
    that exists when a consumer re-opens the artifact path after
    verification (no path-swap race). It does NOT freeze the bytes: a
    writer with write access to the same inode can still mutate the
    file after hashing, and reads from `handle` would then return the
    new bytes. Consumers that need a frozen snapshot must copy the
    bytes themselves; a sealed memfd copy is a possible follow-up,
    not implemented here. The consumer (or the
    `verified_artifacts()` context manager) must close the handle.
    """

    path: str
    sha256: str
    size: int
    handle: BinaryIO


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
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
    # Refuse aliased output paths before creating or truncating either file.
    # resolve(strict=False) also catches distinct path spellings that point
    # at the same destination.
    if private_path.resolve() == public_path.resolve():
        raise ValueError("private and public key paths must be different")

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
    # Refuse trailing symlinks at open time (not just via a pre-check), so
    # an output path cannot redirect key material into a symlink target.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW
    fd = os.open(private_path, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_bytes)
    fd = os.open(public_path, flags, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(public_bytes)
    try:
        os.chmod(private_path, 0o600)
        os.chmod(public_path, 0o644)
    except OSError:
        pass


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        raise VerificationError(f"cannot stat private key: {path}") from exc
    if mode & 0o077:
        raise VerificationError(
            f"private key must not be group- or world-readable: {path}"
        )
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise VerificationError("private key is not Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationError("public key is not Ed25519")
    return key


def manifest_hash(envelope: dict) -> str:
    """Hash of a signed manifest envelope: SHA-256 over its canonical JSON.

    The hash covers both the payload and the Ed25519 signature. The
    signature is normalized to canonical base64 before hashing, so
    different spellings of the same signature (base64 has several
    valid spellings per signature — the low bits of the last data
    character are padding) hash identically. The hash therefore
    identifies one exact signed manifest. Acceptance events carry
    this hash (see :func:`record_manifest_acceptance`); anchor-time
    derivation re-verifies the envelope's signature and checks the
    acceptance's ``release_id`` / ``release_seq`` against the
    manifest's own fields, so an acceptance cannot be rebound to a
    different release.
    """
    if not isinstance(envelope, dict):
        raise VerificationError("manifest envelope must be a JSON object")
    normalized = dict(envelope)
    signature = normalized.get("signature")
    if signature is not None:
        if not isinstance(signature, str):
            raise VerificationError("manifest signature must be base64 text")
        try:
            raw = base64.b64decode(signature, validate=True)
        except ValueError as exc:
            raise VerificationError(
                "manifest signature is not valid base64"
            ) from exc
        normalized["signature"] = base64.b64encode(raw).decode("ascii")
    return hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()


def _check_manifest_hash(value: Any, *, field: str = "manifest_hash") -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise VerificationError(
            f"invalid {field}: must be 64 hexadecimal characters"
        )
    return value.lower()


def _check_release_seq(value: Any, *, field: str = "release_seq") -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= UINT32_MAX
    ):
        raise VerificationError(
            f"invalid {field}: must be an unsigned 32-bit integer"
        )
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

    The descriptor is confirmed by fstat() to reference a regular file.
    With O_NOFOLLOW, a symlink (or fifo/device) swapped in at the final
    component cannot slip through; the open itself fails on a trailing
    symlink, and fstat() rejects fifos and devices. Where O_NOFOLLOW
    is unavailable, fstat() still rejects fifos and devices, but a
    symlink to a regular file would pass fstat() — the per-component
    walk in _validated_entries() is then the remaining defense, and a
    swap between the walk and this open is a residual race. A swapped
    *intermediate* directory component between the walk in
    _validated_entries() and this open remains a residual race;
    closing it fully requires opening each component with O_NOFOLLOW,
    which is left to the future privileged launcher.

    The open uses O_NONBLOCK so a FIFO swapped in between the caller's
    ``is_file()`` check and this open cannot block the open forever;
    non-blocking mode is cleared once the descriptor is confirmed to
    be a regular file.
    """
    try:
        fd = os.open(
            os.fspath(path), os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK
        )
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
    if fcntl is not None and _O_NONBLOCK:
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~_O_NONBLOCK)
        except OSError as exc:
            os.close(fd)
            raise VerificationError(
                f"cannot clear non-blocking mode: {path}"
            ) from exc
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
    descriptor*, and yielded positioned at offset 0. The handle pins the
    inode, so there is no window for path-based replacement between the
    check and the use. It does NOT freeze the bytes: a writer with write
    access to the same inode can still mutate the file after hashing,
    and reads from the handle would then return the new bytes.
    Consumers that need a frozen snapshot must copy the bytes
    themselves. All handles are closed when the context exits,
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
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                handle = os.fdopen(fd, "rb")
            except OSError as exc:
                os.close(fd)
                raise VerificationError(
                    f"error opening artifact: {rel.as_posix()}"
                ) from exc
            opened.append(
                VerifiedArtifact(
                    path=rel.as_posix(),
                    sha256=actual_hash,
                    size=actual_size,
                    handle=handle,
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


MANIFEST_ACCEPTED_EVENT_TYPE = "manifest_accepted"


def _check_release_seq_uint32(value: Any, *, field: str = "release_seq") -> int:
    return _check_release_seq(value, field=field)


def record_manifest_acceptance(
    journal: Path, release_seq: int, release_id: str, manifest_hash_value: str
) -> dict:
    """Record an operator's adoption of a release as a typed audit event.

    Adoption is an explicit operator action, not something inferred from the
    verify path: the operator has decided this release is the one to run,
    and the acceptance event is what later anchors commit to. The
    ``release_seq`` in an anchor payload is derived from these events
    (see ``aiguard.anchor.create_anchor_payload``); it is never supplied
    by the anchoring caller, so a publisher cannot anchor an arbitrary
    checkpoint value.

    The acceptance is bound to one exact signed manifest via
    ``manifest_hash`` — ``sha256(canonical_json(envelope))`` over the
    signed manifest envelope (see :func:`manifest_hash`). Anchor-time
    derivation re-verifies the envelope's Ed25519 signature against a
    trusted public key and requires the acceptance's ``release_id`` /
    ``release_seq`` to match the manifest's own fields. An acceptance
    whose hash matches no verified manifest, or whose release identity
    does not match its manifest, fails closed at anchor time.

    What this binding proves and does not prove (trust boundary): it
    proves the accepted release corresponds to a real, signed manifest
    with matching release identity — a forged acceptance for a
    nonexistent or mismatched manifest is rejected. It does NOT prove
    who recorded the acceptance: anyone with journal write access can
    still record an acceptance that references a *real* manifest (e.g.
    re-accepting an older release). Per-event authorization/signatures
    on acceptance events are out of scope (issue #11); the operator's
    journal write access remains trusted, and consumers should enforce
    monotonic release policy (``--min-release-seq``) at verify time.

    The event detail is canonical JSON ``{"release_seq": N, "release_id":
    "...", "manifest_hash": "<64-hex>"}``. The append goes through the
    normal locked :func:`append_audit_event` path, so flock, O_NOFOLLOW,
    size limits, and canonical serialization all apply.

    Recording only stores the claim; the binding is enforced when an
    anchor is created, not at record time.
    """
    release_seq = _check_release_seq_uint32(release_seq)
    if not isinstance(release_id, str) or not release_id:
        raise VerificationError("release_id must be a non-empty string")
    manifest_hash_value = _check_manifest_hash(manifest_hash_value)
    detail = canonical_json_bytes(
        {
            "release_seq": release_seq,
            "release_id": release_id,
            "manifest_hash": manifest_hash_value,
        }
    ).decode("utf-8")
    return append_audit_event(journal, MANIFEST_ACCEPTED_EVENT_TYPE, detail)


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


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict:
    """``json.loads`` object hook that rejects duplicate keys.

    The default ``json.loads`` keeps the last duplicate, so a file
    could parse differently under another implementation. The
    signature/hash checks would reject such a divergence (fail
    closed), but rejecting duplicates at parse time is the strictest
    defense and removes the ambiguity entirely. Used in the
    trust-critical parse paths (journal, manifest/anchor/record
    loading); WoC-response parsing relies on downstream hash/txid
    checks instead.
    """
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key!r}")
        obj[key] = value
    return obj


def _read_jsonl(path: Path) -> list[dict]:
    events = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                raise VerificationError(f"blank line in audit journal at line {line_no}")
            try:
                event = json.loads(line, object_pairs_hook=_no_duplicate_object)
            except ValueError as exc:
                raise VerificationError(
                    f"invalid JSON at audit line {line_no}: {exc}"
                ) from exc
            if not isinstance(event, dict):
                raise VerificationError(f"audit event must be a JSON object at line {line_no}")
            events.append(event)
    return events
