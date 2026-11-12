"""Anchored release checkpoint cache consumed by v2 launches (§8).

A v2 launch must be tied to the release checkpoint the operator has
already anchored, not to a value the launcher invents. The cache is an
append-only JSONL file of checkpoint snapshots produced by the
deployment-time :func:`bootstrap_checkpoint` workflow (after the anchor
chain passes the item 8 anchor-only predicate while the network is
available):

    {"anchor_end_seq": 42, "checkpoint_seq": 1, "head_hash": "<64 hex>",
     "release_seq": 10}

``checkpoint_seq`` is the cache's own monotonic 1-based sequence. It is
validated with :func:`sealrun.checkpoint_seq.validate_checkpoint_seq`,
as is ``release_seq``. ``anchor_end_seq`` names the journal prefix the
checkpoint was anchored at and ``head_hash`` pins that prefix's event
hash. The launcher re-reads the journal and refuses a cache whose prefix
does not match, whose anchored prefix is missing (journal truncation),
or whose ``release_seq`` is not the max over the ``manifest_accepted``
events inside that prefix.

Trust boundary: this module checks structural integrity and consistency
with the journal. It does not verify an on-chain anchor, and it does not
re-check that each acceptance is bound to a signed manifest — that is
the anchor workflow's job. The cache must therefore live in protected
storage the child cannot write.

Rollback limits, stated plainly: the reader refuses a cache whose
``checkpoint_seq`` is not contiguous from 1 or whose ``release_seq``
decreases, so an *appended* older checkpoint is detected. Truncating the
file back to an older, internally valid prefix cannot be detected here
without an external trusted high-water mark; that residual limitation is
inherent to a local cache.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import core as _core
from .checkpoint_seq import validate_checkpoint_seq
from .core import (
    MANIFEST_ACCEPTED_EVENT_TYPE,
    VerificationError,
    _check_manifest_hash,
    _no_duplicate_object,
    _parse_jsonl_bytes,
    _verify_audit_events,
    canonical_json_bytes,
    read_journal_prefix,
)

_CACHE_FIELDS = frozenset(
    {"checkpoint_seq", "release_seq", "anchor_end_seq", "head_hash"}
)
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_ZERO_HASH = "0" * 64
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _seq(value: Any, field: str) -> int:
    """Validate one cache sequence with the shared helper."""
    try:
        return validate_checkpoint_seq(value)
    except ValueError as exc:
        raise VerificationError(
            f"checkpoint cache {field} is invalid: {exc}"
        ) from exc


def _head_hash(value: Any) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise VerificationError(
            "checkpoint cache head_hash must be 64 lowercase hex characters"
        )
    return value


def _read_records(path: Path) -> list[dict[str, Any]]:
    path = Path(path)
    if path.is_symlink():
        raise VerificationError("checkpoint cache must be a regular non-symlink file")
    if not path.exists():
        raise VerificationError(
            "anchored checkpoint cache is missing; a v2 launch refuses "
            "rather than treating a missing cache as checkpoint 0"
        )
    if not path.is_file():
        raise VerificationError("checkpoint cache must be a regular non-symlink file")
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | _O_NOFOLLOW)
    except OSError as exc:
        raise VerificationError(f"cannot open checkpoint cache: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise VerificationError(
                "checkpoint cache must be a regular non-symlink file"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if not data:
        raise VerificationError(
            "anchored checkpoint cache is empty; a v2 launch refuses "
            "rather than treating an empty cache as checkpoint 0"
        )
    if not data.endswith(b"\n"):
        raise VerificationError(
            "checkpoint cache does not end with a newline; refusing a torn "
            "or ambiguous cache"
        )
    try:
        records = _parse_jsonl_bytes(data)
    except VerificationError as exc:
        raise VerificationError(f"checkpoint cache is invalid: {exc}") from exc
    if not records:
        raise VerificationError(
            "anchored checkpoint cache contains no checkpoint records"
        )
    previous: dict[str, Any] | None = None
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise VerificationError("checkpoint cache record must be a JSON object")
        missing = sorted(_CACHE_FIELDS - set(record))
        unknown = sorted(set(record) - _CACHE_FIELDS)
        if missing or unknown:
            detail = []
            if missing:
                detail.append(f"missing field(s): {', '.join(missing)}")
            if unknown:
                detail.append(f"unknown field(s): {', '.join(unknown)}")
            raise VerificationError(
                f"checkpoint cache record {index} is invalid: {'; '.join(detail)}"
            )
        checkpoint_seq = _seq(record["checkpoint_seq"], "checkpoint_seq")
        release_seq = _seq(record["release_seq"], "release_seq")
        anchor_end_seq = _seq(record["anchor_end_seq"], "anchor_end_seq")
        head_hash = _head_hash(record["head_hash"])
        if checkpoint_seq != index:
            raise VerificationError(
                "checkpoint cache sequence is not monotonic: expected "
                f"checkpoint_seq {index}, got {checkpoint_seq}"
            )
        if previous is not None:
            if release_seq < previous["release_seq"]:
                raise VerificationError(
                    "checkpoint cache rollback detected: release_seq "
                    f"decreased from {previous['release_seq']} to {release_seq}"
                )
            if anchor_end_seq < previous["anchor_end_seq"]:
                raise VerificationError(
                    "checkpoint cache rollback detected: anchor_end_seq "
                    f"decreased from {previous['anchor_end_seq']} to "
                    f"{anchor_end_seq}"
                )
        previous = {
            "checkpoint_seq": checkpoint_seq,
            "release_seq": release_seq,
            "anchor_end_seq": anchor_end_seq,
            "head_hash": head_hash,
        }
    assert previous is not None
    return records


def read_checkpoint_cache(path: Path) -> dict[str, Any]:
    """Return the latest validated checkpoint record from ``path``.

    The whole file is validated, not only the last line, so a tampered or
    rolled-back earlier record is not silently ignored. Raises
    :class:`VerificationError` for a missing, empty, torn, malformed, or
    non-monotonic cache.
    """
    records = _read_records(path)
    record = records[-1]
    return {
        "checkpoint_seq": record["checkpoint_seq"],
        "release_seq": record["release_seq"],
        "anchor_end_seq": record["anchor_end_seq"],
        "head_hash": record["head_hash"],
    }


def anchored_release_seq(events: Sequence[dict], end_seq: int) -> int:
    """Derive the checkpoint from bound-acceptance candidates in a prefix.

    Only ``manifest_accepted`` events advance the checkpoint. Launch and
    finish events (and every other event type) are ignored, so a journal
    full of v2 run-state events does not move the release checkpoint.

    Acceptance parsing is fail-closed and agrees with the anchor
    derivation (:func:`sealrun.anchor._derive_release_seq`): a detail
    that is not a JSON string, is not valid JSON or has duplicate keys,
    is not a JSON object, lacks ``manifest_hash``, has a malformed
    ``manifest_hash`` or ``release_id``, or has an invalid ``release_seq``
    raises :class:`VerificationError` rather than being skipped or
    counted. An unbound acceptance is structurally identical to the
    forgery the manifest binding closes, so it fails closed here too.

    What this function still cannot do is verify the ``manifest_hash``
    against a signed manifest: it takes no manifests or public key. That
    full verification stays with the anchor derivation and
    :func:`bootstrap_checkpoint`; this fix closes the structural
    divergence only.
    """
    end_seq = _seq(end_seq, "anchor_end_seq")
    if end_seq > len(events):
        raise VerificationError(
            f"anchored prefix end {end_seq} is beyond the journal's "
            f"{len(events)} complete event(s): the journal was truncated "
            "below the anchored checkpoint"
        )
    maximum = 0
    for index, event in enumerate(events[:end_seq], 1):
        if event.get("event_type") != MANIFEST_ACCEPTED_EVENT_TYPE:
            continue
        seq = event.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            seq = index
        detail = event.get("detail")
        if not isinstance(detail, str):
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "detail must be a JSON string"
            )
        try:
            parsed = json.loads(detail, object_pairs_hook=_no_duplicate_object)
        except ValueError as exc:
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "detail is not valid JSON or has duplicate keys"
            ) from exc
        if not isinstance(parsed, dict):
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "detail must be a JSON object"
            )
        if "manifest_hash" not in parsed:
            raise VerificationError(
                f"legacy unbound manifest_accepted detail at sequence {seq}: "
                "detail has no manifest_hash; pre-#11 acceptances fail closed "
                "and must be re-recorded with a manifest binding"
            )
        try:
            value = validate_checkpoint_seq(parsed.get("release_seq"))
        except ValueError as exc:
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                f"release_seq is invalid: {exc}"
            ) from exc
        release_id = parsed.get("release_id")
        if not isinstance(release_id, str) or not release_id:
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "release_id must be a non-empty string"
            )
        _check_manifest_hash(parsed.get("manifest_hash"))
        if value > maximum:
            maximum = value
    return maximum


def verify_checkpoint_against_journal(
    record: dict[str, Any], journal: Path
) -> int:
    """Bind a cache record to the journal and return its checkpoint.

    The anchored prefix must still exist, its head hash must match, and
    the cache's ``release_seq`` must equal the max accepted sequence in
    that prefix. Any mismatch refuses.
    """
    events, _fragment = read_journal_prefix(journal)
    try:
        _verify_audit_events(events)
    except VerificationError as exc:
        raise VerificationError(
            f"cannot verify the journal against the checkpoint cache: {exc}"
        ) from exc
    end_seq = record["anchor_end_seq"]
    if end_seq > len(events):
        raise VerificationError(
            f"anchored prefix end {end_seq} is beyond the journal's "
            f"{len(events)} complete event(s): the journal was truncated "
            "below the anchored checkpoint"
        )
    expected_head = events[end_seq - 1]["event_hash"].lower() if end_seq else _ZERO_HASH
    if record["head_hash"] != expected_head:
        raise VerificationError(
            "checkpoint cache does not match the journal: anchored head hash "
            "differs from the event at anchor_end_seq"
        )
    derived = anchored_release_seq(events, end_seq)
    if record["release_seq"] != derived:
        raise VerificationError(
            "checkpoint cache does not match the journal: anchored release_seq "
            f"{record['release_seq']} is not the max accepted sequence "
            f"({derived}) inside the anchored prefix"
        )
    return record["release_seq"]


def assert_checkpoint_cache_isolation(
    path: Path,
    child_uid: int | None,
    *,
    launcher_euid: int | None = None,
) -> None:
    """Refuse a checkpoint cache the dropped child could write (§5.7).

    The cache is a second trust store, so it follows the same placement
    rules as the journal: a privileged deployment, an explicit non-root
    child uid, an existing parent directory, no path owned by the child,
    no group/other write bit, no ACLs, and an ownership-enforcing local
    filesystem. A missing cache file is allowed (bootstrap creates it),
    but its directory must already be isolated.
    """
    if launcher_euid is None:
        launcher_euid = os.geteuid()
    if launcher_euid != 0:
        raise VerificationError(
            "checkpoint cache isolation requires a privileged launcher "
            "(euid 0) that can drop the child to a different uid"
        )
    if child_uid is None:
        raise VerificationError(
            "checkpoint cache isolation requires --uid so the child runs "
            "as a different user than the cache owner"
        )
    if isinstance(child_uid, bool) or not isinstance(child_uid, int):
        raise VerificationError("checkpoint cache child uid must be an integer")
    if child_uid == 0:
        raise VerificationError(
            "checkpoint cache isolation refuses a child uid of 0"
        )

    path = Path(path)
    parent = path.parent
    if not parent.exists():
        raise VerificationError(
            f"checkpoint cache directory {parent} must already exist; the "
            "bootstrap will not create an unisolated parent"
        )
    _core._check_isolated_path(
        parent,
        child_uid,
        role="checkpoint cache directory",
        require_directory=True,
    )
    for ancestor in _core._ancestor_directories(parent.parent):
        _core._check_isolated_path(
            ancestor,
            child_uid,
            role="checkpoint cache ancestor",
            require_directory=True,
        )
    if path.exists() or path.is_symlink():
        _core._check_isolated_path(
            path,
            child_uid,
            role="checkpoint cache file",
            require_directory=False,
        )

    filesystem = _core._filesystem_type(parent)
    if filesystem not in _core.OWNERSHIP_ENFORCING_FILESYSTEMS:
        raise VerificationError(
            f"checkpoint cache directory {parent} is on filesystem type "
            f"{filesystem!r}; ownership-enforcing local filesystems only "
            "(NFS/FUSE/unknown refuse)"
        )


def _has_manifest_acceptance(
    events: Sequence[dict], end_seq: int
) -> bool:
    return any(
        event.get("event_type") == MANIFEST_ACCEPTED_EVENT_TYPE
        for event in events[:end_seq]
    )


def bootstrap_checkpoint(
    journal: Path,
    cache_path: Path,
    anchors: Any,
    genesis_txid: Any,
    *,
    payload_fetcher: Any,
    signature_verifier: Any,
    inclusion: str,
    inclusion_verifier: Any,
    header_verifier: Any,
    bumps: Mapping[str, Any] | None = None,
    beef: Any = None,
    manifests: Any = None,
    public_key: Any = None,
    expected_journal_identity: str | None = None,
    terminal_seq: int | None = None,
    child_uid: int | None,
    launcher_euid: int | None = None,
    require_isolation: bool = True,
) -> dict[str, Any]:
    """Verify an anchor chain online and record its checkpoint offline.

    This is the deployment-time half of freeze decision 4. The anchor
    chain is authenticated with the item 8 anchor-only predicate
    (:func:`sealrun.v2_anchor.verify_v2_anchor_chain`); only when the
    full predicate accepts does the anchored prefix's bound
    ``manifest_accepted`` release sequence become a cache record. Launch
    and finish events never advance the checkpoint, and an anchored
    prefix that contains an acceptance which cannot be re-derived from a
    signed manifest is refused rather than counted.

    The cache record is written with
    :func:`append_checkpoint_cache`, so the cache stays append-only with
    a contiguous ``checkpoint_seq`` and non-decreasing ``release_seq`` /
    ``anchor_end_seq``. When ``require_isolation`` is true (the default)
    the cache directory and file are checked against the §5.7 rules
    before and after the append.
    """
    journal = Path(journal)
    cache_path = Path(cache_path)
    if require_isolation:
        assert_checkpoint_cache_isolation(
            cache_path, child_uid, launcher_euid=launcher_euid
        )

    # Imported lazily so the cache reader stays importable without the
    # network-facing anchor verifier stack.
    from .v2_anchor import verify_v2_anchor_chain

    result = verify_v2_anchor_chain(
        journal,
        anchors,
        genesis_txid,
        payload_fetcher=payload_fetcher,
        signature_verifier=signature_verifier,
        inclusion=inclusion,
        inclusion_verifier=inclusion_verifier,
        header_verifier=header_verifier,
        bumps=bumps,
        beef=beef,
        manifests=manifests,
        public_key=public_key,
        expected_journal_identity=expected_journal_identity,
        terminal_seq=terminal_seq,
    )
    acceptance = result.get("acceptance")
    if not isinstance(acceptance, dict):
        raise VerificationError(
            "bootstrap refused: the anchor verifier returned no acceptance"
        )
    if not acceptance.get("accepted"):
        reasons = "; ".join(acceptance.get("reasons") or [])
        raise VerificationError(
            "bootstrap refused: anchor authentication withheld"
            + (f" ({reasons})" if reasons else "")
        )

    chain = result.get("chain")
    if not isinstance(chain, dict):
        raise VerificationError(
            "bootstrap refused: the anchor verifier returned no chain result"
        )
    last_seq = chain.get("last_seq")
    if (
        isinstance(last_seq, bool)
        or not isinstance(last_seq, int)
        or last_seq < 0
    ):
        raise VerificationError(
            "bootstrap refused: the anchored prefix end is not a sequence"
        )
    anchored_release = chain.get("last_release_seq")
    if (
        isinstance(anchored_release, bool)
        or not isinstance(anchored_release, int)
        or anchored_release < 0
    ):
        raise VerificationError(
            "bootstrap refused: the anchor has no usable release_seq"
        )

    events, _fragment = read_journal_prefix(journal)
    try:
        _verify_audit_events(events)
    except VerificationError as exc:
        raise VerificationError(
            f"bootstrap cannot verify the journal: {exc}"
        ) from exc
    if last_seq > len(events):
        raise VerificationError(
            f"bootstrap refused: anchored prefix end {last_seq} is beyond "
            f"the journal's {len(events)} complete event(s)"
        )

    has_acceptance = _has_manifest_acceptance(events, last_seq)
    if has_acceptance and (manifests is None or public_key is None):
        raise VerificationError(
            "bootstrap refused: the anchored prefix contains "
            "manifest_accepted events, but --manifest and --public-key were "
            "not supplied to prove the acceptance binding; only bound "
            "acceptances may advance the checkpoint"
        )
    if has_acceptance:
        per_anchor = result.get("anchors")
        if (
            not isinstance(per_anchor, list)
            or not per_anchor
            or not isinstance(per_anchor[-1], dict)
            or not per_anchor[-1].get("release_seq_rederived")
        ):
            raise VerificationError(
                "bootstrap refused: the anchored release_seq was not "
                "re-derived from bound manifest_accepted events"
            )

    derived = anchored_release_seq(events, last_seq)
    if derived != anchored_release:
        raise VerificationError(
            "bootstrap refused: anchor release_seq "
            f"{anchored_release} is not the max bound manifest_accepted "
            f"sequence ({derived}) inside the anchored prefix"
        )

    head_hash = (
        events[last_seq - 1]["event_hash"].lower()
        if last_seq
        else _ZERO_HASH
    )
    chain_anchors = chain.get("anchors")
    if isinstance(chain_anchors, list) and chain_anchors:
        last_anchor = chain_anchors[-1]
        if isinstance(last_anchor, dict) and last_anchor.get("head_hash"):
            if last_anchor["head_hash"].lower() != head_hash:
                raise VerificationError(
                    "bootstrap refused: anchor head hash does not match the "
                    "journal event at the anchored prefix end"
                )

    record = append_checkpoint_cache(
        cache_path,
        release_seq=derived,
        anchor_end_seq=last_seq,
        head_hash=head_hash,
    )
    if require_isolation:
        assert_checkpoint_cache_isolation(
            cache_path, child_uid, launcher_euid=launcher_euid
        )
    stored = read_checkpoint_cache(cache_path)
    verify_checkpoint_against_journal(stored, journal)
    return {
        "checkpoint": record,
        "acceptance": acceptance,
        "chain": chain,
        "journal_identity": result.get("journal_identity"),
        "verifier_result": result,
    }


#: Backwards/forwards-friendly alias for the deployment-time entry point.
bootstrap_checkpoint_cache = bootstrap_checkpoint


def append_checkpoint_cache(
    path: Path,
    *,
    release_seq: int,
    anchor_end_seq: int,
    head_hash: str,
) -> dict[str, Any]:
    """Append one checkpoint snapshot, preserving the monotonic sequence.

    This is the producer primitive for the anchoring workflow. It refuses
    a new checkpoint older than the current one, which is what makes an
    *appended* rollback detectable. It cannot detect deletion of the whole
    file or truncation to an older prefix; see the module docstring.
    """
    path = Path(path)
    release_seq = _seq(release_seq, "release_seq")
    anchor_end_seq = _seq(anchor_end_seq, "anchor_end_seq")
    head_hash = _head_hash(head_hash)
    try:
        existing = _read_records(path)
    except VerificationError as exc:
        if not path.exists() and "is missing" in str(exc):
            existing = []
        else:
            raise
    if existing:
        last = existing[-1]
        checkpoint_seq = last["checkpoint_seq"] + 1
        if release_seq < last["release_seq"]:
            raise VerificationError(
                "refusing to append a checkpoint older than the cache's "
                f"current release_seq {last['release_seq']}"
            )
        if anchor_end_seq < last["anchor_end_seq"]:
            raise VerificationError(
                "refusing to append a checkpoint whose anchored prefix ends "
                "before the cache's current anchor_end_seq"
            )
    else:
        checkpoint_seq = 1
    record = {
        "checkpoint_seq": checkpoint_seq,
        "release_seq": release_seq,
        "anchor_end_seq": anchor_end_seq,
        "head_hash": head_hash,
    }
    line = canonical_json_bytes(record).decode("utf-8") + "\n"
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_NOFOLLOW
    try:
        fd = os.open(os.fspath(path), flags, 0o644)
    except OSError as exc:
        raise VerificationError(f"cannot open checkpoint cache for append: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise VerificationError(
                "checkpoint cache must be a regular non-symlink file"
            )
        data = line.encode("utf-8")
        while data:
            written = os.write(fd, data)
            if written == 0:
                raise VerificationError("short write appending to checkpoint cache")
            data = data[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    return record
