from __future__ import annotations

import base64
import contextlib
import dataclasses
import errno
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Mapping, Sequence

from .bsv import PrivKey, _pubkey_point, sign_digest, verify_sig

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix platforms
    fcntl = None  # type: ignore[assignment]

HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")

#: Signed-manifest payload schema. ``sealrun-manifest-v1`` is current
#: (secp256k1/ECDSA: RFC 6979, low-S, DER over SHA-256 of the
#: canonical payload bytes), format-identical to legacy
#: ``aiguard-manifest-v2`` (still accepted for existing manifests).
#: The original ``aiguard-manifest-v1`` (Ed25519) envelopes fail
#: closed with "unsupported schema".
MANIFEST_SCHEMA = "sealrun-manifest-v1"
LEGACY_MANIFEST_SCHEMA = "aiguard-manifest-v2"

# Limits for the local audit journal (Phase 1 DoS hardening).
MAX_EVENT_DETAIL_BYTES = 4096
MAX_JOURNAL_EVENTS = 1_000_000

#: Practical operating limit for one journal, stated from measured cost
#: (§9, launch-flow v2 §6.1). Every append re-reads and re-verifies the
#: whole journal, so the mandatory pre-exec launch write pays O(n) before
#: each exec. Measured on the reference host: one append at 100k events
#: took 1.25 s and 113 MB RSS; 300k took 3.8 s and 302 MB; extrapolating
#: near the 1,000,000 hard cap gives roughly 13 s and 1 GB per launch.
#: Rotate/compact the journal (or start a new one) well before this; the
#: hard cap below remains a refusal boundary, not an operating target.
PRACTICAL_JOURNAL_EVENT_LIMIT = 100_000

UINT32_MAX = (1 << 32) - 1

#: Per-event namespacing for v2 run-state events [frozen design §6.2].
#: The ``v2_`` namespace is reserved: ``append_audit_event`` refuses it so
#: in-process callers cannot mint a run-state event outside the strict
#: schema, and audit verification refuses unknown types in the namespace.
V2_LAUNCH_EVENT_TYPE = "v2_launch"
V2_FINISH_EVENT_TYPE = "v2_finish"
V2_LAUNCH_FAILED_EVENT_TYPE = "v2_launch_failed"
V2_EVENT_TYPES = frozenset(
    {V2_LAUNCH_EVENT_TYPE, V2_FINISH_EVENT_TYPE, V2_LAUNCH_FAILED_EVENT_TYPE}
)
V2_EVENT_TYPE_PREFIX = "v2_"

#: The only four run-state verdicts [frozen design §5.5]. "Completed" is
#: deliberately narrow: it means only that the isolated launcher attested
#: this direct child return code, with the terminal event inside an
#: authenticated anchor prefix. It is not a claim that the work was true,
#: complete, or that descendants stopped.
RUN_STATE_COMPLETED = "completed"
RUN_STATE_INTERNALLY_CONSISTENT = "internally consistent, not proven"
RUN_STATE_FAILED_LAUNCH = "failed launch"
RUN_STATE_INCOMPLETE_UNVERIFIED = "incomplete/unverified"
RUN_STATES = frozenset(
    {
        RUN_STATE_COMPLETED,
        RUN_STATE_INTERNALLY_CONSISTENT,
        RUN_STATE_FAILED_LAUNCH,
        RUN_STATE_INCOMPLETE_UNVERIFIED,
    }
)

#: A finish event follows the direct child only. A setsid or double-fork
#: descendant can keep running (and reading its descriptors) after the
#: finish is written, so every finish-derived verdict carries this wording.
DIRECT_CHILD_SURVIVOR_QUALIFICATION = (
    "This covers only the direct child's exit; setsid/double-fork "
    "descendants may still be running and are not covered."
)
_V2_STAGES = frozenset({"launch", "privilege_drop", "exec"})
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")

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


@dataclasses.dataclass(frozen=True)
class JournalIdentity:
    """The journal parent directory and file inode pinned before a v2 launch.

    ``file_device`` / ``file_inode`` are ``None`` when the journal does not
    exist yet; in that case only the pinned parent may create it. Re-checked
    immediately before and after the append open, so a journal renamed over
    the path after the §5.7 isolation check is refused rather than extended.
    """

    parent_device: int
    parent_inode: int
    file_device: int | None
    file_inode: int | None


def pin_journal_identity(
    journal: Path, *, create: bool = False
) -> JournalIdentity:
    """Pin the journal parent directory and current inode (§6.1).

    The parent must be a real directory (never a symlink) and, if the
    journal exists, a regular non-symlink file. The returned identity is
    passed to :func:`append_v2_event` so the append path can refuse a
    replacement that happened before ``os.open``.

    With ``create=True`` a missing journal is created (``O_EXCL``,
    ``O_NOFOLLOW``), fsynced, and its directory fsynced, so the pinned
    identity names a durable inode before the launch record is written.
    """
    journal = Path(os.path.abspath(os.fspath(journal)))
    parent = journal.parent
    try:
        parent_info = os.lstat(parent)
    except OSError as exc:
        raise VerificationError(
            f"cannot pin the audit journal directory {parent}: {exc}"
        ) from exc
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise VerificationError("audit journal parent must be a real directory")
    file_device: int | None = None
    file_inode: int | None = None
    try:
        file_info = os.lstat(journal)
    except FileNotFoundError:
        if create:
            try:
                fd = os.open(
                    os.fspath(journal),
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
                    0o644,
                )
            except OSError as exc:
                raise VerificationError(
                    f"cannot create the audit journal {journal}: {exc}"
                ) from exc
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            _fsync_directory(parent)
            try:
                file_info = os.lstat(journal)
            except OSError as exc:
                raise VerificationError(
                    f"cannot pin the new audit journal inode {journal}: {exc}"
                ) from exc
        else:
            file_info = None
    except OSError as exc:
        raise VerificationError(
            f"cannot pin the audit journal inode {journal}: {exc}"
        ) from exc
    if file_info is not None:
        if stat.S_ISLNK(file_info.st_mode) or not stat.S_ISREG(file_info.st_mode):
            raise VerificationError(
                "audit journal must be a regular non-symlink file"
            )
        file_device = file_info.st_dev
        file_inode = file_info.st_ino
    return JournalIdentity(
        parent_device=parent_info.st_dev,
        parent_inode=parent_info.st_ino,
        file_device=file_device,
        file_inode=file_inode,
    )


def _assert_parent_identity(parent: Path, identity: JournalIdentity) -> None:
    try:
        info = os.lstat(parent)
    except OSError as exc:
        raise VerificationError(
            f"audit journal directory {parent} changed after it was pinned: {exc}"
        ) from exc
    if (info.st_dev, info.st_ino) != (
        identity.parent_device,
        identity.parent_inode,
    ):
        raise VerificationError(
            f"audit journal directory {parent} was replaced after it was pinned"
        )
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise VerificationError("audit journal parent must be a real directory")


def _assert_journal_identity_before_open(
    journal: Path, identity: JournalIdentity
) -> bool:
    """Check the pinned identity and return whether the journal must be created."""
    _assert_parent_identity(journal.parent, identity)
    try:
        info = os.lstat(journal)
    except FileNotFoundError:
        if identity.file_inode is not None:
            raise VerificationError(
                "audit journal disappeared after it was pinned; refusing to "
                "create a replacement"
            )
        return True
    except OSError as exc:
        raise VerificationError(
            f"cannot inspect the pinned audit journal: {exc}"
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise VerificationError("audit journal must be a regular non-symlink file")
    if identity.file_inode is None:
        raise VerificationError(
            "audit journal appeared after the isolation check; refusing to "
            "extend an unpinned file"
        )
    if (info.st_dev, info.st_ino) != (
        identity.file_device,
        identity.file_inode,
    ):
        raise VerificationError(
            "audit journal was replaced after it was pinned; refusing to "
            "extend the replacement"
        )
    return False


def _assert_journal_fd_identity(
    fd: int,
    journal: Path,
    identity: JournalIdentity,
    *,
    created: bool,
) -> None:
    """Check the opened descriptor and the path still name the pinned inode."""
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise VerificationError("audit journal must be a regular non-symlink file")
    if identity.file_inode is not None:
        if (info.st_dev, info.st_ino) != (
            identity.file_device,
            identity.file_inode,
        ):
            raise VerificationError(
                "audit journal was replaced after it was pinned; refusing to "
                "extend the replacement"
            )
    elif not created:
        raise VerificationError(
            "audit journal appeared after the isolation check; refusing to "
            "extend an unpinned file"
        )
    _assert_parent_identity(journal.parent, identity)
    try:
        path_info = os.lstat(journal)
    except OSError as exc:
        raise VerificationError(
            f"audit journal vanished during the append open: {exc}"
        ) from exc
    if (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino):
        raise VerificationError(
            "audit journal path was replaced during the append open"
        )


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def fingerprint_value(value: Any) -> str:
    """SHA-256 over a canonical JSON encoding of ``value``.

    V2 records fingerprints by default rather than verbatim argv/env
    (§6.3). The encoding is the same canonical form the journal uses, so
    a third party can recompute it from the recorded structure.
    """
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def fingerprint_argv(argv: Sequence[str]) -> str:
    """Return the v2 argv fingerprint (SHA-256 over canonical argv JSON)."""
    return fingerprint_value(list(argv))


def fingerprint_environment(env: Mapping[str, str]) -> str:
    """Return the v2 environment fingerprint (SHA-256 over canonical JSON)."""
    return fingerprint_value(dict(env))


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


def generate_keypair(private_path: Path, public_path: Path, force: bool = False) -> None:
    # Refuse aliased output paths before creating or truncating either file.
    # resolve(strict=False) also catches distinct path spellings that point
    # at the same destination.
    if private_path.resolve() == public_path.resolve():
        raise ValueError("private and public key paths must be different")

    # Check both paths before writing either one so refusal cannot leave a
    # partial keypair behind. lexists also counts dangling symlinks.
    if not force:
        for path in (private_path, public_path):
            if os.path.lexists(path):
                raise ValueError(f"key file already exists: {path}")

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    key = PrivKey.generate()
    # Private key: WIF text with the testnet version byte (the project
    # default; load_private_key accepts either network — manifest keys
    # are not chain keys). The base58check checksum catches a corrupted
    # key file at load time. Public key: 33-byte compressed point as hex.
    # Both files are plain text ending in a newline; loaders strip it.
    private_bytes = (key.wif(network="testnet") + "\n").encode("ascii")
    public_bytes = (key.pubkey_compressed().hex() + "\n").encode("ascii")
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


_HEX_COMPRESSED_PUBKEY = re.compile(r"[0-9a-fA-F]{66}")


def load_private_key(path: Path) -> PrivKey:
    """Load a manifest-signing private key from a WIF text file.

    Refuses a key that is group- or world-readable. WIF is used as the
    container for its checksum; the network version byte is not
    meaningful for off-chain manifest signing, so both known version
    bytes are accepted (chain use validates the network itself).

    The file is opened once (O_NOFOLLOW where available) and the
    permission check runs with fstat() on that descriptor, so the
    bytes read are the bytes whose permissions were checked — no
    stat-then-read window for a path swap between check and use.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise VerificationError(f"cannot open private key: {path}") from exc
    try:
        mode = os.fstat(fd).st_mode
    except OSError as exc:
        os.close(fd)
        raise VerificationError(f"cannot stat private key: {path}") from exc
    if not stat.S_ISREG(mode):
        os.close(fd)
        raise VerificationError(f"private key is not a regular file: {path}")
    if mode & 0o077:
        os.close(fd)
        raise VerificationError(
            f"private key must not be group- or world-readable: {path}"
        )
    try:
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise VerificationError(f"cannot read private key: {path}") from exc
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise VerificationError("private key is not valid WIF") from exc
    try:
        return PrivKey.from_wif_any(text)
    except ValueError as exc:
        raise VerificationError("private key is not valid WIF") from exc


def load_public_key(path: Path) -> bytes:
    """Load a compressed secp256k1 public key from a hex text file.

    Accepts 66 hex characters (02/03 prefix + x-coordinate); the point
    is validated against the curve so a bad key fails here with a clear
    error, not later as a confusing signature failure.
    """
    try:
        text = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise VerificationError(f"cannot read public key: {path}") from exc
    if not _HEX_COMPRESSED_PUBKEY.fullmatch(text):
        raise VerificationError(
            "public key must be 66 hex characters (compressed secp256k1)"
        )
    pubkey = bytes.fromhex(text)
    try:
        _pubkey_point(pubkey)
    except ValueError as exc:
        raise VerificationError("public key is not a valid secp256k1 point") from exc
    return pubkey


def manifest_hash(envelope: dict) -> str:
    """Hash of a signed manifest envelope: SHA-256 over its canonical JSON.

    The hash covers both the payload and the ECDSA signature. The
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
        "schema": MANIFEST_SCHEMA,
        "release_id": release_id,
        "release_seq": release_seq,
        "artifacts": artifacts,
    }


def sign_manifest(payload: dict, private_key: PrivKey) -> dict:
    """Sign a manifest payload: RFC 6979 ECDSA (secp256k1, low-S) over
    SHA-256 of the exact canonical payload bytes; signature DER-encoded
    as base64 in the envelope."""
    digest = hashlib.sha256(canonical_json_bytes(payload)).digest()
    signature = sign_digest(private_key, digest)
    return {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}


def _load_verified_payload(envelope: dict, public_key: bytes) -> dict:
    """Validate envelope shape/schema and the secp256k1 signature; return payload."""
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise VerificationError("invalid signed envelope fields")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or payload.get("schema") not in (MANIFEST_SCHEMA, LEGACY_MANIFEST_SCHEMA):
        raise VerificationError("unsupported manifest schema")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        digest = hashlib.sha256(canonical_json_bytes(payload)).digest()
    except (ValueError, TypeError) as exc:
        raise VerificationError("manifest signature invalid") from exc
    # require_low_s pins the canonical signature form: ECDSA verifies both
    # s and N - s, and the manifest hash covers the signature bytes, so
    # without it one payload would hash as two "exact" manifests.
    if not verify_sig(public_key, digest, signature, require_low_s=True):
        raise VerificationError("manifest signature invalid")
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
    public_key: bytes,
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
    public_key: bytes,
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
    (see ``sealrun.anchor.create_anchor_payload``); it is never supplied
    by the anchoring caller, so a publisher cannot anchor an arbitrary
    checkpoint value.

    The acceptance is bound to one exact signed manifest via
    ``manifest_hash`` — ``sha256(canonical_json(envelope))`` over the
    signed manifest envelope (see :func:`manifest_hash`). Anchor-time
    derivation re-verifies the envelope's secp256k1 signature against a
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


_V2_EXECUTABLE_BINDING_FIELDS = frozenset(
    {
        "executable_binding",
        "executable_path",
        "executable_candidates",
        "executable_artifact",
        "executable_sha256",
        "executable_fd",
    }
)
_V2_CHANNEL_FIELDS = frozenset({"path", "env", "sha256", "fd"})
_V2_CHANNEL_LIST_DETACHED_FIELDS = frozenset(
    {"channel_list_sha256", "channel_list_file"}
)
_V2_CHANNEL_LIST_FIELDS = frozenset({"channel_list"}) | (
    _V2_CHANNEL_LIST_DETACHED_FIELDS
)
_V2_LAUNCH_FIELDS = frozenset(
    {
        "launch_mode",
        "run_id",
        "journal_nonce",
        "manifest_hash",
        "artifact_count",
        "argv_fingerprint",
        "env_fingerprint",
        "executable",
        "cwd",
        "seal",
        "uid",
        "gid",
    }
)
_V2_LAUNCH_ALLOWED_FIELDS = (
    _V2_LAUNCH_FIELDS
    | _V2_EXECUTABLE_BINDING_FIELDS
    | _V2_CHANNEL_LIST_FIELDS
)
_V2_FINISH_FIELDS = frozenset(
    {
        "launch_mode",
        "run_id",
        "exit_code",
        "launcher_signal",
        "escalated",
        "duration_ms",
    }
)
#: 0 (no signal) or a termination signal the v2 launcher forwards:
#: SIGHUP, SIGINT, SIGTERM (POSIX numbering, so verification does not
#: depend on the verifying host's signal module).
_V2_LAUNCHER_SIGNALS = frozenset({0, 1, 2, 15})
_V2_LAUNCH_FAILED_FIELDS = frozenset(
    {"launch_mode", "run_id", "stage", "reason"}
)


def _v2_exact_fields(
    detail: Any,
    required: frozenset[str],
    event_type: str,
    *,
    allowed: frozenset[str] | None = None,
) -> dict:
    if not isinstance(detail, dict):
        raise VerificationError(f"{event_type} detail must be a JSON object")
    allowed = required if allowed is None else allowed
    keys = set(detail)
    missing = sorted(required - keys)
    unknown = sorted(keys - allowed)
    if missing:
        raise VerificationError(
            f"{event_type} detail is missing required field(s): {', '.join(missing)}"
        )
    if unknown:
        raise VerificationError(
            f"{event_type} detail has unknown field(s): {', '.join(unknown)}"
        )
    return detail


def _v2_check_launch_mode(value: Any, event_type: str) -> None:
    if value != "v2":
        raise VerificationError(
            f"{event_type} detail must record launch_mode 'v2'"
        )


def _v2_string(
    value: Any, field: str, *, max_length: int = 4096, allow_empty: bool = False
) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise VerificationError(f"{field} must be a non-empty string")
    if len(value) > max_length:
        raise VerificationError(f"{field} exceeds maximum length of {max_length}")
    return value


def _v2_string_list(value: Any, field: str, *, max_length: int = 4096) -> list[str]:
    if not isinstance(value, list):
        raise VerificationError(f"{field} must be an array of strings")
    if len(value) > max_length:
        raise VerificationError(f"{field} exceeds maximum length of {max_length}")
    for item in value:
        if not isinstance(item, str) or not item:
            raise VerificationError(f"{field} must be an array of strings")
    return value


def _v2_uuid(value: Any) -> str:
    text = _v2_string(value, "run_id", max_length=64)
    if not _UUID_RE.fullmatch(text):
        raise VerificationError("run_id must be a canonical lowercase UUID")
    return text


def _v2_hex64(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise VerificationError(f"{field} must be a 64-character hex string")
    return value


def _v2_nonce(value: Any) -> str:
    if not isinstance(value, str) or not _NONCE_RE.fullmatch(value):
        raise VerificationError("journal_nonce must be 32 lowercase hex characters")
    return value


def _v2_int(
    value: Any, field: str, *, minimum: int, maximum: int
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise VerificationError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise VerificationError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return value


def _v2_validate_executable_binding(detail: dict) -> None:
    """Validate the optional v2 executable-binding group (§5.3).

    Older v2 launch events have no binding fields; when any field is
    present, the whole group is required so a partial claim cannot be
    mistaken for a complete one.
    """
    binding = detail["executable_binding"]
    if binding not in ("record-only", "verified"):
        raise VerificationError(
            "executable_binding must be 'record-only' or 'verified'"
        )
    _v2_string(detail["executable_path"], "executable_path", allow_empty=True)
    _v2_string_list(
        detail["executable_candidates"], "executable_candidates"
    )
    artifact = detail["executable_artifact"]
    sha256 = detail["executable_sha256"]
    fd = detail["executable_fd"]
    if binding == "record-only":
        if artifact is not None or sha256 is not None or fd is not None:
            raise VerificationError(
                "record-only executable_binding must not claim an executed "
                "artifact"
            )
        return
    _v2_string(artifact, "executable_artifact")
    _v2_hex64(sha256, "executable_sha256")
    _v2_int(fd, "executable_fd", minimum=0, maximum=UINT32_MAX)


def _v2_validate_channel_records(
    records: Any,
    artifact_count: int,
    *,
    field: str = "channel_list",
) -> list[dict]:
    """Validate a descriptor channel list (path -> env var -> hash -> fd)."""
    if not isinstance(records, list):
        raise VerificationError(f"{field} must be an array of channel records")
    if len(records) != artifact_count:
        raise VerificationError(
            f"{field} has {len(records)} record(s) but artifact_count is "
            f"{artifact_count}"
        )
    seen_paths: set[str] = set()
    seen_envs: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise VerificationError(f"{field} entries must be JSON objects")
        keys = set(record)
        missing = sorted(_V2_CHANNEL_FIELDS - keys)
        unknown = sorted(keys - _V2_CHANNEL_FIELDS)
        if missing:
            raise VerificationError(
                f"{field} entry is missing field(s): {', '.join(missing)}"
            )
        if unknown:
            raise VerificationError(
                f"{field} entry has unknown field(s): {', '.join(unknown)}"
            )
        path = _v2_string(record["path"], f"{field} path")
        env = _v2_string(record["env"], f"{field} env")
        _v2_hex64(record["sha256"], f"{field} sha256")
        _v2_int(
            record["fd"], f"{field} fd", minimum=0, maximum=UINT32_MAX
        )
        if path in seen_paths:
            raise VerificationError(
                f"{field} names artifact path {path!r} more than once"
            )
        if env in seen_envs:
            raise VerificationError(
                f"{field} names channel {env!r} more than once"
            )
        seen_paths.add(path)
        seen_envs.add(env)
    return records


def _v2_channel_list_filename(value: Any) -> str:
    name = _v2_string(value, "channel_list_file", max_length=255)
    if (
        os.path.basename(name) != name
        or name in (".", "..")
        or "/" in name
        or "\\" in name
        or os.path.isabs(name)
    ):
        raise VerificationError(
            "channel_list_file must be a bare filename in the journal directory"
        )
    return name


def _v2_check_launch_channel_list(detail: dict) -> None:
    present = _V2_CHANNEL_LIST_FIELDS & detail.keys()
    if not present:
        # Older v2 launch events make no channel-map claim at all.
        return
    if "channel_list" in detail:
        if _V2_CHANNEL_LIST_DETACHED_FIELDS & detail.keys():
            raise VerificationError(
                "a launch event cannot record both an inline channel_list and "
                "a detached channel list"
            )
        _v2_validate_channel_records(
            detail["channel_list"], detail["artifact_count"]
        )
        return
    missing = sorted(_V2_CHANNEL_LIST_DETACHED_FIELDS - detail.keys())
    if missing:
        raise VerificationError(
            f"v2_launch detail is missing required detached channel-list "
            f"field(s): {', '.join(missing)}"
        )
    _v2_hex64(detail["channel_list_sha256"], "channel_list_sha256")
    _v2_channel_list_filename(detail["channel_list_file"])


def _validate_v2_event_detail(event_type: str, detail: Any) -> None:
    """Strictly validate one v2 run-state event's ``detail`` object.

    Unknown keys are refused as well as missing ones: the schema is
    additive only by a code change here, so a hand-written journal cannot
    smuggle an unvalidated field past ``audit-verify``.
    """
    if event_type == V2_LAUNCH_EVENT_TYPE:
        detail = _v2_exact_fields(
            detail,
            _V2_LAUNCH_FIELDS,
            event_type,
            allowed=_V2_LAUNCH_ALLOWED_FIELDS,
        )
        _v2_check_launch_mode(detail["launch_mode"], event_type)
        _v2_uuid(detail["run_id"])
        _v2_nonce(detail["journal_nonce"])
        _v2_hex64(detail["manifest_hash"], "manifest_hash")
        _v2_int(detail["artifact_count"], "artifact_count",
                minimum=0, maximum=UINT32_MAX)
        _v2_check_launch_channel_list(detail)
        _v2_hex64(detail["argv_fingerprint"], "argv_fingerprint")
        _v2_hex64(detail["env_fingerprint"], "env_fingerprint")
        _v2_string(detail["executable"], "executable")
        _v2_string(detail["cwd"], "cwd")
        if not isinstance(detail["seal"], bool):
            raise VerificationError("seal must be a boolean")
        _v2_int(detail["uid"], "uid", minimum=1, maximum=UINT32_MAX)
        _v2_int(detail["gid"], "gid", minimum=0, maximum=UINT32_MAX)
        if _V2_EXECUTABLE_BINDING_FIELDS & detail.keys():
            missing = sorted(_V2_EXECUTABLE_BINDING_FIELDS - detail.keys())
            if missing:
                raise VerificationError(
                    f"{event_type} detail is missing required executable-binding "
                    f"field(s): {', '.join(missing)}"
                )
            _v2_validate_executable_binding(detail)
        return
    if event_type == V2_FINISH_EVENT_TYPE:
        detail = _v2_exact_fields(detail, _V2_FINISH_FIELDS, event_type)
        _v2_check_launch_mode(detail["launch_mode"], event_type)
        _v2_uuid(detail["run_id"])
        _v2_int(detail["exit_code"], "exit_code", minimum=-255, maximum=255)
        launcher_signal = _v2_int(
            detail["launcher_signal"], "launcher_signal", minimum=0, maximum=255
        )
        if launcher_signal not in _V2_LAUNCHER_SIGNALS:
            raise VerificationError(
                "launcher_signal must be 0 (none), 1 (SIGHUP), 2 (SIGINT) or 15 (SIGTERM)"
            )
        if not isinstance(detail["escalated"], bool):
            raise VerificationError("escalated must be a boolean")
        if detail["escalated"] and not launcher_signal:
            raise VerificationError(
                "escalated requires a launcher_signal: the launcher only "
                "escalates after forwarding a signal it received"
            )
        _v2_int(detail["duration_ms"], "duration_ms",
                minimum=0, maximum=(1 << 63) - 1)
        return
    if event_type == V2_LAUNCH_FAILED_EVENT_TYPE:
        detail = _v2_exact_fields(detail, _V2_LAUNCH_FAILED_FIELDS, event_type)
        _v2_check_launch_mode(detail["launch_mode"], event_type)
        _v2_uuid(detail["run_id"])
        if detail["stage"] not in _V2_STAGES:
            raise VerificationError(
                f"stage must be one of: {', '.join(sorted(_V2_STAGES))}"
            )
        _v2_string(detail["reason"], "reason", max_length=3000)
        return
    raise VerificationError(f"unknown v2 event type: {event_type!r}")


def append_v2_event(
    journal: Path,
    event_type: str,
    detail: dict,
    *,
    journal_identity: JournalIdentity | None = None,
) -> dict:
    """Append one strictly-validated v2 run-state event.

    The event type must be in the reserved ``v2_`` namespace and the
    ``detail`` object must match that type's exact schema. The detail is
    serialised canonically before hashing, exactly as
    :func:`append_audit_event` does for legacy events.

    ``journal_identity`` is the identity pinned before a v2 launch. When
    supplied, the append refuses a journal parent or inode that no longer
    matches it, closing the pre-``os.open`` replacement window (§6.1).

    A launch event reserves two slots: the launch itself and the terminal
    finish event. At fewer than two slots remaining the launch is refused
    before anything is written, so a completed run cannot be forced into
    the cap-cliff "incomplete" state.
    """
    if event_type not in V2_EVENT_TYPES:
        raise VerificationError(f"unknown v2 event type: {event_type!r}")
    _validate_v2_event_detail(event_type, detail)
    serialized = canonical_json_bytes(detail).decode("utf-8")
    reserve_slots = 2 if event_type == V2_LAUNCH_EVENT_TYPE else 1
    return _append_audit_event(
        journal,
        event_type,
        serialized,
        create_parent=False,
        journal_identity=journal_identity,
        reserve_slots=reserve_slots,
    )


def append_audit_event(journal: Path, event_type: str, detail: str) -> dict:
    """Append an event only when the existing journal is valid.

    This prevents the normal append path from silently extending a journal
    whose earlier events have already been modified or truncated.

    The ``v2_`` event-type namespace is reserved for the strictly-validated
    v2 run-state schema (:func:`append_v2_event`). Refusing it here — in
    ``core``, not only in the CLI — stops in-process callers from minting
    a run-state event that bypasses that schema.

    On platforms that support it, an exclusive advisory lock is held across
    the verify-then-write critical section so concurrent writers cannot race.
    """
    if not isinstance(event_type, str) or not event_type:
        raise VerificationError("event_type must be a non-empty string")
    if event_type.startswith(V2_EVENT_TYPE_PREFIX):
        raise VerificationError(
            f"event type {event_type!r} is in the reserved v2_ namespace; "
            "use append_v2_event with the strict run-state schema"
        )
    if not isinstance(detail, str):
        raise VerificationError("detail must be a string")
    return _append_audit_event(journal, event_type, detail)


def _write_all_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written == 0:
            raise VerificationError("short write")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    """fsync a directory so a newly created entry survives a crash (§6.1)."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _O_NOFOLLOW
    try:
        fd = os.open(os.fspath(path), flags)
    except OSError as exc:
        raise VerificationError(
            f"cannot open directory {path} for fsync: {exc}"
        ) from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise VerificationError(
            f"cannot fsync directory {path}: {exc}"
        ) from exc
    finally:
        os.close(fd)


def _ensure_journal_parent(journal: Path, *, create_parent: bool) -> list[Path]:
    """Create the parent if allowed; return the directories that were created."""
    parent = journal.parent
    if not create_parent:
        if not parent.is_dir():
            raise VerificationError("audit journal directory must already exist")
        return []
    missing: list[Path] = []
    current = parent
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    parent.mkdir(parents=True, exist_ok=True)
    return missing


def _parse_jsonl_bytes(data: bytes) -> list[dict]:
    events: list[dict] = []
    if not data:
        return events
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for line_no, raw in enumerate(lines, 1):
        if not raw.strip():
            raise VerificationError(f"blank line in audit journal at line {line_no}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError(
                f"invalid UTF-8 at audit line {line_no}: {exc}"
            ) from exc
        try:
            event = json.loads(text, object_pairs_hook=_no_duplicate_object)
        except ValueError as exc:
            raise VerificationError(
                f"invalid JSON at audit line {line_no}: {exc}"
            ) from exc
        if not isinstance(event, dict):
            raise VerificationError(
                f"audit event must be a JSON object at line {line_no}"
            )
        events.append(event)
    return events


def _read_jsonl_fd(fd: int) -> list[dict]:
    """Read and parse the journal from the already-locked descriptor.

    Reading from the same (locked) fd used for the append closes the window
    in which a path swap between verification and writing could make the
    chain check inspect a different file (§6.1 append atomicity).
    """
    chunks: list[bytes] = []
    offset = 0
    while True:
        chunk = os.pread(fd, 1 << 20, offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    return _parse_jsonl_bytes(b"".join(chunks))


def _split_complete_and_fragment(data: bytes) -> tuple[list[dict], bytes | None]:
    """Split a journal into complete events and a trailing torn fragment.

    A final complete JSON object is an event even without a trailing
    newline; only an unterminated, unparseable final segment is a fragment
    (§6.1 torn-line rule). Corruption before the final segment still fails.
    """
    if not data:
        return [], None
    if data.endswith(b"\n"):
        return _parse_jsonl_bytes(data), None
    body, separator, tail = data.rpartition(b"\n")
    complete = _parse_jsonl_bytes(body + b"\n" if separator else b"")
    if not tail.strip():
        raise VerificationError(
            f"blank line in audit journal at line {len(complete) + 1}"
        )
    try:
        text = tail.decode("utf-8")
    except UnicodeDecodeError:
        return complete, tail
    try:
        event = json.loads(text, object_pairs_hook=_no_duplicate_object)
    except ValueError:
        return complete, tail
    if not isinstance(event, dict):
        raise VerificationError(
            f"audit event must be a JSON object at line {len(complete) + 1}"
        )
    complete.append(event)
    return complete, None


def read_journal_prefix(journal: Path) -> tuple[list[dict], bytes | None]:
    """Return the complete-event prefix and any trailing torn fragment."""
    journal = Path(journal)
    if journal.is_symlink():
        raise VerificationError("audit journal must be a regular non-symlink file")
    if not journal.exists():
        return [], None
    if not journal.is_file():
        raise VerificationError("audit journal must be a regular non-symlink file")
    return _split_complete_and_fragment(journal.read_bytes())


def verify_audit_prefix(journal: Path) -> dict:
    """Verify the complete-event prefix and report a torn tail separately.

    This is the torn-tolerant primitive used to compare a journal prefix
    against an anchor: the chain is verified over complete events only, and
    an incomplete trailing fragment is reported rather than raised before
    the comparison can run.
    """
    events, fragment = read_journal_prefix(journal)
    count = _verify_audit_events(events)
    return {
        "events": count,
        "fragment": fragment.decode("utf-8", "replace") if fragment else None,
        "fragment_bytes": len(fragment) if fragment else 0,
    }


def journal_has_genesis_nonce(events: Sequence[dict]) -> bool:
    """Return whether any v2 event in ``events`` carries a journal nonce.

    This is the shared "does this journal have a v2 identity seed?" scan.
    The launcher's first-launch exception and
    :func:`journal_genesis_identity` both use it, so they agree on which
    events seed a v2 identity. A ``v2_launch_failed`` event carries no
    ``journal_nonce``, so failed launches never seed an identity.
    """
    for event in events:
        if event.get("event_type") not in V2_EVENT_TYPES:
            continue
        detail = _run_event_detail(event)
        if detail.get("journal_nonce") is not None:
            return True
    return False


def journal_genesis_identity(events: Sequence[dict]) -> dict:
    """Return the v2 journal identity: genesis hash plus its genesis nonce.

    A bare genesis hash is not an identity (frozen design §6.5): journal
    events carry no timestamp, so two journals can share a repeatable first
    event. V2 therefore requires the first v2 event to carry a unique
    ``journal_nonce``; the identity hashes the genesis event hash together
    with that nonce, never the bare hash. The first event may be a legacy
    event, so the nonce is taken from the first v2 event in the journal.
    """
    _verify_audit_events(list(events))
    if not events:
        raise VerificationError(
            "cannot derive a v2 journal identity from an empty journal"
        )
    genesis_hash = str(events[0]["event_hash"]).lower()
    if not journal_has_genesis_nonce(events):
        raise VerificationError(
            "journal has no v2 event with a genesis nonce; a bare genesis "
            "hash is not a v2 journal identity"
        )
    for event in events:
        if event.get("event_type") not in V2_EVENT_TYPES:
            continue
        detail = _run_event_detail(event)
        nonce = detail.get("journal_nonce")
        if nonce is None:
            raise VerificationError(
                "the first v2 event has no journal_nonce; a v2 journal "
                "identity requires a unique genesis nonce"
            )
        nonce = _v2_nonce(nonce)
        identity = hashlib.sha256(
            canonical_json_bytes(
                {"genesis_hash": genesis_hash, "genesis_nonce": nonce}
            )
        ).hexdigest()
        return {
            "identity": identity,
            "genesis_hash": genesis_hash,
            "genesis_event_seq": events[0]["seq"],
            "genesis_nonce": nonce,
            "genesis_nonce_seq": event["seq"],
            "journal_events": len(events),
        }
    raise VerificationError(
        "journal has no v2 event with a genesis nonce; a bare genesis hash "
        "is not a v2 journal identity"
    )


def journal_genesis_identity_for_path(journal: Path) -> dict:
    """Read and verify a journal, then return its v2 genesis identity."""
    journal = Path(journal)
    if journal.is_symlink() or not journal.exists() or not journal.is_file():
        raise VerificationError("journal missing or not a regular non-symlink file")
    events, _fragment = read_journal_prefix(journal)
    return journal_genesis_identity(events)


def _append_audit_event(
    journal: Path,
    event_type: str,
    detail: str,
    *,
    create_parent: bool = True,
    journal_identity: JournalIdentity | None = None,
    reserve_slots: int = 1,
) -> dict:
    detail_bytes = detail.encode("utf-8")
    if len(detail_bytes) > MAX_EVENT_DETAIL_BYTES:
        raise VerificationError(
            f"detail exceeds maximum of {MAX_EVENT_DETAIL_BYTES} UTF-8 bytes"
        )
    if reserve_slots < 1:
        raise VerificationError("reserve_slots must be at least 1")

    created_directories = _ensure_journal_parent(
        journal, create_parent=create_parent
    )
    if journal.is_symlink():
        raise VerificationError("audit journal must be a regular non-symlink file")

    must_create = False
    if journal_identity is not None:
        must_create = _assert_journal_identity_before_open(
            journal, journal_identity
        )

    # Open with create + append so we can lock the same FD used for writing.
    # O_NOFOLLOW makes the open itself fail on a trailing symlink instead of
    # following it, closing the check-then-open race on the is_symlink()
    # pre-check above for an attacker racing a parent-directory swap.
    common_flags = os.O_RDWR | os.O_APPEND | _O_NOFOLLOW
    created = False
    try:
        if must_create:
            fd = os.open(
                os.fspath(journal),
                common_flags | os.O_CREAT | os.O_EXCL,
                0o644,
            )
            created = True
        elif journal_identity is not None:
            # The pinned inode must still exist. Do not O_CREAT here: if the
            # path vanished between the identity check and the open, creating
            # a fresh empty journal would discard the pinned chain (and leave
            # the replacement behind after the identity check below refuses).
            fd = os.open(os.fspath(journal), common_flags)
        else:
            try:
                fd = os.open(
                    os.fspath(journal),
                    common_flags | os.O_CREAT | os.O_EXCL,
                    0o644,
                )
                created = True
            except FileExistsError:
                fd = os.open(
                    os.fspath(journal), common_flags | os.O_CREAT, 0o644
                )
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
        if journal_identity is not None:
            _assert_journal_fd_identity(
                fd, journal, journal_identity, created=created
            )

        prior: list[dict] = []
        size = os.fstat(fd).st_size
        if size:
            # Read from the locked fd, never the path: a path swap between
            # this read and the write cannot make the chain check inspect a
            # different file (§6.1 append atomicity).
            prior = _read_jsonl_fd(fd)
            _verify_audit_events(prior)
            # The journal must end with a newline: otherwise the new line
            # would concatenate onto the last line and corrupt two lines.
            # A journal missing only its terminator still verifies (its
            # content is intact), so this refuses to append rather than
            # treating the journal as corrupt.
            if not _fd_ends_with_newline(fd, size):
                raise VerificationError(
                    "audit journal does not end with a newline; "
                    "refusing to append"
                )

        remaining = MAX_JOURNAL_EVENTS - len(prior)
        if remaining < reserve_slots:
            if reserve_slots > 1:
                raise VerificationError(
                    f"journal has {remaining} slot(s) remaining; a v2 launch "
                    "needs at least 2 (launch + finish), so fewer than 2 "
                    "slots remain and the launch is refused"
                )
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
        # Loop until every byte is written: os.write may write short
        # (signals, disk pressure), and a torn line would brick the
        # journal on the next verification.
        try:
            _write_all_fd(fd, line.encode("utf-8"))
        except OSError as exc:
            raise VerificationError(
                f"failed writing to audit journal: {exc}"
            ) from exc
        os.fsync(fd)
        if created:
            # The directory entry naming a newly created journal is not
            # durable until the directory itself is fsynced (§6.1).
            _fsync_directory(journal.parent)
            for directory in created_directories:
                _fsync_directory(directory.parent)
        return event
    finally:
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def _fd_ends_with_newline(fd: int, size: int) -> bool:
    if size <= 0:
        return True
    return os.pread(fd, 1, size - 1) == b"\n"


def verify_audit_journal(journal: Path) -> int:
    if journal.is_symlink():
        raise VerificationError("audit journal must be a regular non-symlink file")
    if not journal.exists():
        return 0
    if not journal.is_file():
        raise VerificationError("audit journal must be a regular non-symlink file")
    return _verify_audit_events(_read_jsonl(journal))


def verify_audit_journal_report(journal: Path) -> dict:
    """Verify the complete-event prefix and report torn tails and channel maps.

    Unlike :func:`verify_audit_journal`, this tolerates an incomplete final
    fragment (it is reported, never auto-repaired) and resolves each v2
    launch event's descriptor channel list. A missing detached side file is
    reported as ``present: False``; the map is never reconstructed from its
    hash (§6.1).
    """
    events, fragment = read_journal_prefix(journal)
    count = _verify_audit_events(events)
    channel_lists: list[dict] = []
    for event in events:
        if event.get("event_type") != V2_LAUNCH_EVENT_TYPE:
            continue
        detail = event.get("detail")
        if not isinstance(detail, str):
            continue
        parsed = json.loads(detail, object_pairs_hook=_no_duplicate_object)
        resolved = load_channel_list(journal, parsed)
        channel_lists.append(
            {
                "seq": event.get("seq"),
                "run_id": parsed.get("run_id"),
                **resolved,
            }
        )
    return {
        "events": count,
        "fragment": fragment.decode("utf-8", "replace") if fragment else None,
        "fragment_bytes": len(fragment) if fragment else 0,
        "channel_lists": channel_lists,
    }


def _run_event_detail(event: dict) -> dict:
    """Return a v2 event's parsed detail object without trusting its type."""
    detail = event.get("detail")
    if isinstance(detail, dict):
        return detail
    if not isinstance(detail, str):
        raise VerificationError("malformed v2 event detail")
    try:
        parsed = json.loads(detail, object_pairs_hook=_no_duplicate_object)
    except ValueError as exc:
        raise VerificationError(f"invalid v2 event detail: {exc}") from exc
    if not isinstance(parsed, dict):
        raise VerificationError("v2 event detail must be a JSON object")
    return parsed


def _validate_run_state_inputs(
    authenticated_prefix_end: int | None,
    writer_isolation_established: bool,
) -> None:
    if authenticated_prefix_end is not None:
        if (
            isinstance(authenticated_prefix_end, bool)
            or not isinstance(authenticated_prefix_end, int)
            or authenticated_prefix_end < 0
            or authenticated_prefix_end > UINT32_MAX
        ):
            raise VerificationError(
                "authenticated_prefix_end must be a non-negative integer "
                "sequence or None"
            )
    if not isinstance(writer_isolation_established, bool):
        raise VerificationError(
            "writer_isolation_established must be a boolean"
        )


def _finish_summary(detail: dict, *, completed: bool, reasons: list[str]) -> str:
    exit_code = detail["exit_code"]
    launcher_signal = detail["launcher_signal"]
    if exit_code < 0:
        child = (
            f"the direct child was terminated by signal {-exit_code} "
            f"(recorded rc {exit_code})"
        )
    else:
        child = f"the direct child exited with rc {exit_code}"
    if launcher_signal:
        child += f" after the launcher recorded signal {launcher_signal}"
    if completed:
        text = f"Completed: the isolated launcher attested that {child}."
    else:
        text = (
            f"Internally consistent, not proven: {child}, but completion "
            f"is not proven ({'; '.join(reasons)})."
        )
    return f"{text} {DIRECT_CHILD_SURVIVOR_QUALIFICATION}"


def _failed_launch_summary(detail: dict, *, proven: bool, reasons: list[str]) -> str:
    stage = detail.get("stage", "unknown")
    reason = detail.get("reason", "")
    text = (
        f"Failed launch: no child ran (stage {stage}"
        + (f": {reason}" if reason else "")
        + ")."
    )
    if proven:
        text += " The isolated launcher attested this failure."
    else:
        text += (
            " The record is not proven as launcher-attested "
            f"({'; '.join(reasons)})."
        )
    return text


def classify_run_states(
    events: Sequence[dict],
    *,
    authenticated_prefix_end: int | None = None,
    writer_isolation_established: bool = False,
    run_id: str | None = None,
) -> list[dict]:
    """Classify v2 runs into the four §5.5 run states.

    ``authenticated_prefix_end`` is the last journal sequence covered by an
    anchored prefix that satisfied the full anchor acceptance predicate.
    Item 7 deliberately does not authenticate anchors itself; the caller
    must pass only a sequence it has already established as authenticated.
    A terminal event at or below that sequence is "inside" the prefix.

    ``writer_isolation_established`` is the same caller-established fact
    for the §5.7 journal-writer isolation predicate. Completion requires
    both; without them a finish becomes "internally consistent, not
    proven". A launch-failed record remains a "failed launch" but reports
    whether it was proven. A launch with no terminal is always
    "incomplete/unverified".

    Only namespaced v2 events participate. Legacy free-form events are not
    run-state evidence, so an old free-form "finish" cannot become an
    orphan terminal event. Malformed v2 linkage (duplicate launch, orphan
    terminal, or a second terminal for one run id) is a verification
    failure.
    """
    _validate_run_state_inputs(
        authenticated_prefix_end, writer_isolation_established
    )
    if run_id is not None:
        _v2_uuid(run_id)

    runs: dict[str, dict] = {}
    order: list[str] = []
    for event in events:
        event_type = event.get("event_type")
        if event_type not in V2_EVENT_TYPES:
            continue
        detail = _run_event_detail(event)
        _validate_v2_event_detail(event_type, detail)
        event_run_id = detail["run_id"]
        seq = event.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise VerificationError("v2 event seq must be an integer")

        if event_type == V2_LAUNCH_EVENT_TYPE:
            if event_run_id in runs:
                raise VerificationError(
                    f"duplicate v2 launch run id {event_run_id!r} at "
                    f"sequence {seq}"
                )
            runs[event_run_id] = {
                "run_id": event_run_id,
                "launch_seq": seq,
                "launch_detail": detail,
                "terminal_seq": None,
                "terminal_event_type": None,
                "terminal_detail": None,
            }
            order.append(event_run_id)
            continue

        run = runs.get(event_run_id)
        if run is None:
            raise VerificationError(
                f"orphan v2 terminal event for run id {event_run_id!r} at "
                f"sequence {seq}: no v2 launch event precedes it"
            )
        if run["terminal_seq"] is not None:
            raise VerificationError(
                f"second terminal event for v2 run id {event_run_id!r} at "
                f"sequence {seq}; the first was at "
                f"sequence {run['terminal_seq']}"
            )
        run["terminal_seq"] = seq
        run["terminal_event_type"] = event_type
        run["terminal_detail"] = detail

    results: list[dict] = []
    for event_run_id in order:
        if run_id is not None and event_run_id != run_id:
            continue
        run = runs[event_run_id]
        terminal_seq = run["terminal_seq"]
        terminal_type = run["terminal_event_type"]
        terminal_detail = run["terminal_detail"]
        authenticated = (
            terminal_seq is not None
            and authenticated_prefix_end is not None
            and terminal_seq <= authenticated_prefix_end
        )
        reasons: list[str] = []
        if terminal_seq is None:
            state = RUN_STATE_INCOMPLETE_UNVERIFIED
            summary = (
                "Incomplete/unverified: a v2 launch event is present but no "
                "terminal event follows. The journal cannot distinguish an "
                "interrupted launcher from a completed-but-unrecorded run."
            )
            exit_code = None
            launcher_signal = None
        elif terminal_type == V2_LAUNCH_FAILED_EVENT_TYPE:
            state = RUN_STATE_FAILED_LAUNCH
            proven = authenticated and writer_isolation_established
            if not authenticated:
                reasons.append(
                    "the terminal event is outside any authenticated anchor "
                    "prefix"
                )
            if not writer_isolation_established:
                reasons.append("journal-writer isolation is not established")
            summary = _failed_launch_summary(
                terminal_detail, proven=proven, reasons=reasons
            )
            exit_code = None
            launcher_signal = None
        else:
            exit_code = terminal_detail["exit_code"]
            launcher_signal = terminal_detail["launcher_signal"]
            if not authenticated:
                reasons.append(
                    "the finish event is outside any authenticated anchor "
                    "prefix"
                )
            if not writer_isolation_established:
                reasons.append("journal-writer isolation is not established")
            completed = not reasons
            state = (
                RUN_STATE_COMPLETED
                if completed
                else RUN_STATE_INTERNALLY_CONSISTENT
            )
            summary = _finish_summary(
                terminal_detail, completed=completed, reasons=reasons
            )

        results.append(
            {
                "run_id": event_run_id,
                "state": state,
                "launch_seq": run["launch_seq"],
                "terminal_seq": terminal_seq,
                "terminal_event_type": terminal_type,
                "exit_code": exit_code,
                "launcher_signal": launcher_signal,
                "authenticated_prefix": authenticated,
                "writer_isolation": writer_isolation_established,
                "proven": state == RUN_STATE_COMPLETED
                or (
                    state == RUN_STATE_FAILED_LAUNCH
                    and authenticated
                    and writer_isolation_established
                ),
                "reasons": reasons,
                "summary": summary,
            }
        )

    if run_id is not None and not results:
        raise VerificationError(
            f"no v2 run with run id {run_id!r} was found in the journal"
        )
    return results


def verify_run_states(
    journal: Path,
    *,
    authenticated_prefix_end: int | None = None,
    writer_isolation_established: bool = False,
    run_id: str | None = None,
) -> dict:
    """Verify a journal and return one §5.5 verdict per v2 run.

    The complete-event prefix is verified (torn tail reported separately,
    never treated as an event), then run linkage and the four-state verdict
    are computed. ``authenticated_prefix_end`` and
    ``writer_isolation_established`` are caller-established facts: only a
    full anchor-predicate composition may set the former, and only the
    §5.7 predicate may set the latter.
    """
    events, fragment = read_journal_prefix(journal)
    _verify_audit_events(events)
    runs = classify_run_states(
        events,
        authenticated_prefix_end=authenticated_prefix_end,
        writer_isolation_established=writer_isolation_established,
        run_id=run_id,
    )
    return {
        "runs": runs,
        "run_count": len(runs),
        "authenticated_prefix_end": authenticated_prefix_end,
        "writer_isolation_established": writer_isolation_established,
        "fragment": fragment.decode("utf-8", "replace") if fragment else None,
        "fragment_bytes": len(fragment) if fragment else 0,
    }


def _channel_list_name(journal: Path, run_id: str) -> str:
    return f"{journal.name}.channels.{run_id}.json"


def write_detached_channel_list(
    journal: Path,
    run_id: str,
    records: Sequence[Mapping[str, Any]],
    *,
    child_uid: int,
    journal_identity: JournalIdentity | None = None,
) -> tuple[str, str]:
    """Write a detached channel list and return ``(filename, sha256)``.

    Implements the §6.1 write protocol: the canonical bytes are hashed in
    memory (never re-read from the path), created inside the §5.7-isolated
    journal directory with ``O_CREAT|O_EXCL|O_NOFOLLOW``, fsynced, and the
    directory fsynced before the caller journals the hash. The file itself
    is re-checked against the isolation predicate after creation.
    """
    journal = Path(journal)
    _v2_uuid(run_id)
    records = list(records)
    _v2_validate_channel_records(records, len(records))
    payload = canonical_json_bytes(records)
    digest = hashlib.sha256(payload).hexdigest()

    parent = journal.parent
    if journal_identity is not None:
        _assert_parent_identity(parent, journal_identity)
    _check_isolated_path(
        parent, child_uid, role="journal directory", require_directory=True
    )

    name = _channel_list_name(journal, run_id)
    path = parent / name
    try:
        fd = os.open(
            os.fspath(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
            0o600,
        )
    except OSError as exc:
        raise VerificationError(
            f"cannot create detached channel list {path}: {exc}"
        ) from exc
    try:
        try:
            _write_all_fd(fd, payload)
        except OSError as exc:
            raise VerificationError(
                f"cannot write detached channel list {path}: {exc}"
            ) from exc
        os.fsync(fd)
        _check_isolated_path(
            path, child_uid, role="channel list file", require_directory=False
        )
        _fsync_directory(parent)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    else:
        os.close(fd)
    return name, digest


def load_channel_list(journal: Path, launch_detail: dict) -> dict:
    """Resolve a v2 launch event's descriptor channel list.

    Inline records are returned as recorded. For a detached map the side
    file is opened from the journal directory, its bytes are hashed and
    compared with the committed hash, and the records are schema-checked.
    A missing side file is reported as ``present: False`` — the map is not
    reconstructed from the hash, because the hash cannot recover it.
    """
    artifact_count = launch_detail["artifact_count"]
    if "channel_list" in launch_detail:
        records = _v2_validate_channel_records(
            launch_detail["channel_list"], artifact_count
        )
        return {
            "present": True,
            "inline": True,
            "records": records,
            "sha256": hashlib.sha256(canonical_json_bytes(records)).hexdigest(),
            "reason": None,
        }
    if "channel_list_sha256" not in launch_detail:
        return {
            "present": False,
            "inline": False,
            "records": None,
            "sha256": None,
            "reason": "launch event records no channel list",
        }

    journal = Path(journal)
    run_id = launch_detail["run_id"]
    expected_name = _channel_list_name(journal, run_id)
    name = launch_detail["channel_list_file"]
    if name != expected_name:
        raise VerificationError(
            f"channel_list_file must be {expected_name!r} for this journal "
            "and run id"
        )
    # The side file is a second store and must still satisfy §5.7. The
    # child uid is recorded in the launch event; use it to refuse a
    # journal directory the child could have written since the launch.
    child_uid = launch_detail.get("uid")
    isolated_child_uid = (
        child_uid
        if isinstance(child_uid, int) and not isinstance(child_uid, bool)
        else None
    )
    if isolated_child_uid is not None:
        _check_isolated_path(
            journal.parent,
            isolated_child_uid,
            role="journal directory",
            require_directory=True,
        )
        filesystem = _filesystem_type(journal.parent)
        if filesystem not in OWNERSHIP_ENFORCING_FILESYSTEMS:
            raise VerificationError(
                f"journal directory {journal.parent} is on filesystem type "
                f"{filesystem!r}; ownership-enforcing local filesystems only"
            )

    path = journal.parent / name
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {
            "present": False,
            "inline": False,
            "records": None,
            "sha256": launch_detail["channel_list_sha256"],
            "reason": "detached channel list file is missing",
        }
    except OSError as exc:
        raise VerificationError(
            f"cannot inspect detached channel list {path}: {exc}"
        ) from exc
    if stat.S_ISLNK(info.st_mode):
        raise VerificationError(f"detached channel list {path} is a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise VerificationError(
            f"detached channel list {path} is not a regular file"
        )
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise VerificationError(
            f"detached channel list {path} is group- or world-writable"
        )
    try:
        parent_info = os.lstat(journal.parent)
    except OSError as exc:
        raise VerificationError(
            f"cannot inspect journal directory {journal.parent}: {exc}"
        ) from exc
    if info.st_uid != parent_info.st_uid:
        raise VerificationError(
            f"detached channel list {path} is not owned by the journal "
            "directory owner"
        )
    _refuse_acl(path, "channel list file")

    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | _O_NOFOLLOW)
    except OSError as exc:
        raise VerificationError(
            f"cannot open detached channel list {path}: {exc}"
        ) from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise VerificationError(
                f"detached channel list {path} was replaced while opening it"
            )
        chunks: list[bytes] = []
        offset = 0
        while True:
            chunk = os.pread(fd, 1 << 20, offset)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)

    actual = hashlib.sha256(data).hexdigest()
    if actual != launch_detail["channel_list_sha256"]:
        raise VerificationError(
            "detached channel list hash does not match the launch event; "
            "the committed map cannot be trusted"
        )
    try:
        parsed = json.loads(
            data.decode("utf-8"), object_pairs_hook=_no_duplicate_object
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise VerificationError(
            f"invalid detached channel list {path}: {exc}"
        ) from exc
    records = _v2_validate_channel_records(parsed, artifact_count)
    return {
        "present": True,
        "inline": False,
        "records": records,
        "sha256": actual,
        "reason": None,
    }


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
        event_type = event.get("event_type")
        if isinstance(event_type, str) and event_type.startswith(V2_EVENT_TYPE_PREFIX):
            if event_type not in V2_EVENT_TYPES:
                raise VerificationError(
                    f"unknown v2 event type at sequence {expected_seq}: "
                    f"{event_type!r}"
                )
            detail = event.get("detail")
            if not isinstance(detail, str):
                raise VerificationError(
                    f"malformed v2 event detail at sequence {expected_seq}"
                )
            try:
                parsed = json.loads(detail, object_pairs_hook=_no_duplicate_object)
            except ValueError as exc:
                raise VerificationError(
                    f"invalid v2 event detail at sequence {expected_seq}: {exc}"
                ) from exc
            _validate_v2_event_detail(event_type, parsed)
        # Legacy free-form events are not run-state events (§6.2). Their
        # event_type is not constrained by the v2 schema, and v1's
        # verification behaviour (which never inspected it) is preserved.
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
    return _parse_jsonl_bytes(Path(path).read_bytes())


#: Filesystems on which the kernel enforces the ownership and mode bits the
#: §5.7 isolation predicate relies on. Network and FUSE filesystems are
#: deliberately absent: there the local uid/mode view is not authoritative.
#: An unknown type refuses (fail closed) rather than being assumed safe.
OWNERSHIP_ENFORCING_FILESYSTEMS = frozenset(
    {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "tmpfs", "ramfs", "overlay"}
)

_ACL_XATTRS = ("system.posix_acl_access", "system.posix_acl_default")
_ACL_ABSENT_ERRNOS = frozenset(
    value
    for value in (
        errno.ENODATA,
        getattr(errno, "ENOATTR", errno.ENODATA),
        errno.ENOTSUP,
        getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
    )
)


def _mountinfo_unescape(field: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 8))

    return re.sub(r"\\([0-7]{3})", replace, field)


def _filesystem_type(path: Path) -> str | None:
    """Return the mount filesystem type for ``path``, or ``None``.

    Reads ``/proc/self/mountinfo`` directly because the standard library
    exposes no filesystem-type call. The longest matching mount point wins,
    which handles nested mounts. Unknown or unreadable mountinfo returns
    ``None`` so the caller refuses.
    """
    try:
        lines = Path("/proc/self/mountinfo").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return None
    target = os.path.abspath(os.fspath(path))
    best_mount = None
    best_type = None
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < 5 or not right_fields:
            continue
        mount_point = _mountinfo_unescape(left_fields[4])
        prefix = mount_point.rstrip("/") + "/"
        if target == mount_point or target.startswith(prefix):
            if best_mount is None or len(mount_point) > len(best_mount):
                best_mount = mount_point
                best_type = right_fields[0]
    return best_type


def _refuse_acl(path: Path, role: str) -> None:
    for name in _ACL_XATTRS:
        try:
            os.getxattr(os.fspath(path), name)
        except OSError as exc:
            if exc.errno in _ACL_ABSENT_ERRNOS:
                continue
            raise VerificationError(
                f"cannot inspect ACLs on {role} {path}: {exc}"
            ) from exc
        raise VerificationError(
            f"{role} {path} carries an ACL; v2 journal isolation "
            "refuses ACL-bearing paths"
        )


def _check_isolated_path(
    path: Path, child_uid: int, *, role: str, require_directory: bool
) -> None:
    """Apply the ownership/mode/ACL checks for one journal path component."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise VerificationError(f"cannot inspect {role} {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise VerificationError(f"{role} {path} is a symlink; refusing")
    if require_directory:
        if not stat.S_ISDIR(info.st_mode):
            raise VerificationError(f"{role} {path} is not a directory")
    elif not stat.S_ISREG(info.st_mode):
        raise VerificationError(f"{role} {path} is not a regular file")
    if info.st_uid == child_uid:
        raise VerificationError(
            f"{role} {path} is owned by the child uid {child_uid}; "
            "the child could write or replace it"
        )
    # Group/other write is refused even when the child's gid differs: the
    # rule is a property of the path, not of a guess about group membership.
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise VerificationError(
            f"{role} {path} is group- or world-writable; the child could "
            "alter the journal store"
        )
    _refuse_acl(path, role)


def _ancestor_directories(path: Path) -> list[Path]:
    current = Path(os.path.abspath(os.fspath(path)))
    ancestors = []
    while True:
        ancestors.append(current)
        if current.parent == current:
            break
        current = current.parent
    return ancestors


def assert_journal_writer_isolation(
    journal: Path,
    child_uid: int | None,
    *,
    launcher_euid: int | None = None,
) -> None:
    """Refuse a v2 journal placement the dropped child could write.

    Implements the §5.7 launcher decision procedure: privileged launcher,
    explicit non-root drop uid different from every journal path owner,
    pre-existing journal directory, no group/other write bit on the file,
    its directory, or any ancestor, no ACLs, and an ownership-enforcing
    local filesystem. Anything unverifiable fails closed.

    ``launcher_euid`` is injectable so the predicate can be unit-tested
    without real privilege; production callers omit it.
    """
    if launcher_euid is None:
        launcher_euid = os.geteuid()
    if launcher_euid != 0:
        raise VerificationError(
            "v2 journal isolation requires a privileged launcher (euid 0) "
            "that can drop the child to a different uid"
        )
    if child_uid is None:
        raise VerificationError(
            "v2 journal isolation requires --uid so the child runs as a "
            "different user than the journal owner"
        )
    if isinstance(child_uid, bool) or not isinstance(child_uid, int):
        raise VerificationError("v2 child uid must be an integer")
    if child_uid == 0:
        raise VerificationError(
            "v2 journal isolation refuses a child uid of 0"
        )

    journal = Path(journal)
    parent = journal.parent
    if not parent.exists():
        raise VerificationError(
            f"v2 journal directory {parent} must already exist; the launcher "
            "will not create it (an unisolated parent cannot be repaired "
            "after the fact)"
        )

    _check_isolated_path(
        parent, child_uid, role="journal directory", require_directory=True
    )
    for ancestor in _ancestor_directories(parent.parent):
        _check_isolated_path(
            ancestor, child_uid, role="journal ancestor", require_directory=True
        )
    if journal.exists() or journal.is_symlink():
        _check_isolated_path(
            journal, child_uid, role="journal file", require_directory=False
        )

    filesystem = _filesystem_type(parent)
    if filesystem not in OWNERSHIP_ENFORCING_FILESYSTEMS:
        raise VerificationError(
            f"v2 journal directory {parent} is on filesystem type "
            f"{filesystem!r}; ownership-enforcing local filesystems only "
            "(NFS/FUSE/unknown refuse)"
        )
