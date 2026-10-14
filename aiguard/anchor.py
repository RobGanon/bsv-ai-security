from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .core import (
    MANIFEST_ACCEPTED_EVENT_TYPE,
    VerificationError,
    _check_manifest_hash,
    _load_verified_payload,
    _read_jsonl,
    _verify_audit_events,
    manifest_hash as compute_manifest_hash,
)

MAGIC = b"AIGUARD1"
PAYLOAD_SIZE = 84
ZERO_TXID = "0" * 64
HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")
UINT32_MAX = (1 << 32) - 1


def _uint32(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= UINT32_MAX:
        raise VerificationError(f"{field} must be an unsigned 32-bit integer")
    return value


def encode_anchor_payload(
    *,
    head_hash: str,
    start_seq: int,
    end_seq: int,
    release_seq: int,
    prev_txid: str = ZERO_TXID,
) -> bytes:
    """Encode the protocol's exact 84-byte payload; this does not create a transaction."""
    if not isinstance(head_hash, str) or not HEX_64.fullmatch(head_hash):
        raise VerificationError("head_hash must be 64 hexadecimal characters")
    if not isinstance(prev_txid, str) or not HEX_64.fullmatch(prev_txid):
        raise VerificationError("prev_txid must be 64 hexadecimal characters")
    # Normalize to lowercase so core and anchor agree on representation.
    head_hash = head_hash.lower()
    prev_txid = prev_txid.lower()
    start_seq = _uint32(start_seq, "start_seq")
    end_seq = _uint32(end_seq, "end_seq")
    release_seq = _uint32(release_seq, "release_seq")
    if start_seq < 1:
        raise VerificationError("start_seq must be at least 1")
    if end_seq < start_seq:
        raise VerificationError("end_seq must be greater than or equal to start_seq")
    return (
        MAGIC
        + bytes.fromhex(head_hash)
        + start_seq.to_bytes(4, "big")
        + end_seq.to_bytes(4, "big")
        + release_seq.to_bytes(4, "big")
        + bytes.fromhex(prev_txid)
    )


def decode_anchor_payload(payload: bytes) -> dict[str, Any]:
    """Parse and validate an exact protocol payload."""
    if not isinstance(payload, bytes) or len(payload) != PAYLOAD_SIZE:
        raise VerificationError(f"anchor payload must be exactly {PAYLOAD_SIZE} bytes")
    if payload[:8] != MAGIC:
        raise VerificationError("unsupported anchor payload magic/version")
    start_seq = int.from_bytes(payload[40:44], "big")
    end_seq = int.from_bytes(payload[44:48], "big")
    release_seq = int.from_bytes(payload[48:52], "big")
    if start_seq < 1:
        raise VerificationError("start_seq must be at least 1")
    if end_seq < start_seq:
        raise VerificationError("end_seq must be greater than or equal to start_seq")
    return {
        "magic": MAGIC.decode("ascii"),
        "head_hash": payload[8:40].hex(),
        "start_seq": start_seq,
        "end_seq": end_seq,
        "release_seq": release_seq,
        "prev_txid": payload[52:84].hex(),
        "payload_hex": payload.hex(),
    }


def _verified_manifest_map(manifests: Any, public_key: Any) -> dict[str, dict]:
    """Verify each supplied manifest envelope and index it by its hash.

    Every envelope's Ed25519 signature is verified against ``public_key``
    via :func:`core._load_verified_payload`, so caller-supplied manifests
    are safe: a publisher cannot smuggle in a forged manifest without
    the signing key. Returns ``{manifest_hash: payload}`` where payload
    is the verified manifest payload (with ``release_id`` /
    ``release_seq`` validated). Manifests whose payload lacks valid
    release identity are rejected.
    """
    if public_key is None or manifests is None:
        raise VerificationError(
            "cannot verify acceptance binding without manifests and a "
            "trusted public key: supply the signed manifest envelopes and "
            "the manifest-signing public key to check acceptances against"
        )
    manifest_list = list(manifests)
    if not manifest_list:
        raise VerificationError(
            "cannot verify acceptance binding without manifests: "
            "supply the signed manifest envelopes to check acceptances against"
        )
    by_hash: dict[str, dict] = {}
    for envelope in manifest_list:
        if not isinstance(envelope, dict):
            raise VerificationError("manifest envelope must be a JSON object")
        payload = _load_verified_payload(envelope, public_key)
        release_id = payload.get("release_id")
        if not isinstance(release_id, str) or not release_id:
            raise VerificationError("invalid release_id in manifest")
        release_seq = payload.get("release_seq")
        if (
            not isinstance(release_seq, int)
            or isinstance(release_seq, bool)
            or not 0 <= release_seq <= UINT32_MAX
        ):
            raise VerificationError("invalid release_seq in manifest")
        by_hash[compute_manifest_hash(envelope)] = payload
    return by_hash


def _derive_release_seq(
    events: list[dict],
    end_seq: int,
    manifests: Any = None,
    public_key: Any = None,
) -> int:
    """Derive the anchored ``release_seq`` from bound journal acceptance events.

    Returns ``max(release_seq)`` over ``manifest_accepted`` events with
    ``seq <= end_seq``, or ``0`` ("no release adopted") when the covered
    range contains no acceptance. Every acceptance in the covered range
    must be *bound* to a verified manifest:

    - The detail must parse as a JSON object with ``release_seq``,
      ``release_id``, and ``manifest_hash`` (64-hex).
    - The ``manifest_hash`` must match a supplied manifest envelope
      whose Ed25519 signature verifies against ``public_key``.
    - The acceptance's ``release_id`` / ``release_seq`` must equal the
      manifest's own fields, so an acceptance cannot be rebound to a
      different release.

    Fail-closed rules: a malformed detail, a legacy acceptance without
    ``manifest_hash``, an acceptance whose hash matches no verified
    manifest, a release-identity mismatch, or any acceptance present
    without ``manifests`` + ``public_key`` to check it against all
    raise :class:`VerificationError` and anchoring fails closed.

    Legacy acceptances (pre-#11 detail without ``manifest_hash``) fail
    closed rather than being silently counted or ignored: an unbound
    acceptance is structurally identical to the forgery this binding
    closes. Operators with pre-#11 journals start a fresh journal and
    re-record bound acceptances.

    There is intentionally no caller override: any override would
    reintroduce the D2 gap the derivation closes.
    """
    acceptances: list[tuple[int, dict]] = []
    for event in events:
        seq = event.get("seq")
        if (
            not isinstance(seq, int)
            or isinstance(seq, bool)
            or seq > end_seq
            or event.get("event_type") != MANIFEST_ACCEPTED_EVENT_TYPE
        ):
            continue
        detail = event.get("detail")
        if not isinstance(detail, str):
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "detail must be a JSON string"
            )
        try:
            parsed = json.loads(detail)
        except json.JSONDecodeError as exc:
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "detail is not valid JSON"
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
        release_seq = _uint32(parsed.get("release_seq"), "release_seq")
        release_id = parsed.get("release_id")
        if not isinstance(release_id, str) or not release_id:
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "release_id must be a non-empty string"
            )
        manifest_hash_value = _check_manifest_hash(parsed.get("manifest_hash"))
        acceptances.append((seq, {
            "release_seq": release_seq,
            "release_id": release_id,
            "manifest_hash": manifest_hash_value,
        }))
    if not acceptances:
        return 0
    verified = _verified_manifest_map(manifests, public_key)
    derived = 0
    for seq, acceptance in acceptances:
        manifest = verified.get(acceptance["manifest_hash"])
        if manifest is None:
            raise VerificationError(
                f"unbound manifest_accepted detail at sequence {seq}: "
                "manifest_hash matches no verified manifest; "
                "forged acceptance for a nonexistent manifest is rejected"
            )
        if (
            manifest.get("release_id") != acceptance["release_id"]
            or manifest.get("release_seq") != acceptance["release_seq"]
        ):
            raise VerificationError(
                f"manifest_accepted detail at sequence {seq}: "
                "release identity does not match the bound manifest; "
                "an acceptance cannot be rebound to a different release"
            )
        derived = max(derived, acceptance["release_seq"])
    return derived


def create_anchor_payload(
    journal: Path,
    *,
    start_seq: int,
    prev_txid: str = ZERO_TXID,
    manifests: Any = None,
    public_key: Any = None,
) -> dict[str, Any]:
    """Create an unsigned anchor payload from a verified local journal.

    The anchored ``release_seq`` is derived from the journal itself:
    ``max(release_seq)`` over bound ``manifest_accepted`` events with
    ``seq <= end_seq`` (``0`` when the journal contains no acceptance,
    meaning "no release adopted"). It is never taken from the caller, so a
    publisher cannot anchor an arbitrary checkpoint value.

    Binding (issue #11): when the covered range contains any acceptance,
    ``manifests`` (the signed manifest envelopes to check acceptances
    against) and ``public_key`` (the trusted manifest-signing key) are
    required. Each acceptance's ``manifest_hash`` must match a manifest
    whose signature verifies, with matching release identity; otherwise
    anchoring fails closed. Journals with no acceptance need neither.

    This only prepares commitment bytes. It does not sign, broadcast, or prove
    inclusion of a Bitcoin SV transaction.
    """
    if journal.is_symlink() or not journal.exists() or not journal.is_file():
        raise VerificationError("journal must exist as a regular non-symlink file")
    events = _read_jsonl(journal)
    _verify_audit_events(events)
    end_seq = len(events)
    start_seq = _uint32(start_seq, "start_seq")
    if end_seq < 1:
        raise VerificationError("cannot anchor an empty journal")
    if start_seq < 1 or start_seq > end_seq:
        raise VerificationError("start_seq must identify an event in the journal")
    if end_seq > UINT32_MAX:
        raise VerificationError("journal sequence exceeds the protocol's uint32 limit")
    release_seq = _derive_release_seq(events, end_seq, manifests, public_key)
    head_hash = events[end_seq - 1]["event_hash"].lower()
    payload = encode_anchor_payload(
        head_hash=head_hash,
        start_seq=start_seq,
        end_seq=end_seq,
        release_seq=release_seq,
        prev_txid=prev_txid,
    )
    return decode_anchor_payload(payload)


def verify_journal_against_anchor(
    journal: Path,
    payload: bytes,
    manifests: Any = None,
    public_key: Any = None,
) -> dict[str, Any]:
    """Check that a local journal contains the head committed by an anchor payload.

    Always verifies the hash chain and that the event hash at the
    anchored end sequence matches the payload's head hash, and detects a
    missing or shortened journal.

    When ``manifests`` and ``public_key`` are both supplied, additionally
    re-derives the anchored ``release_seq`` from bound acceptances (same
    fail-closed binding rules as creation) and requires it to equal the
    payload's ``release_seq``. When either is omitted, the payload's
    ``release_seq`` is returned as committed, without re-derivation —
    the head-hash check alone does not prove the checkpoint was honestly
    derived. Verifiers that need the full binding check must supply both.
    """
    fields = decode_anchor_payload(payload)
    if journal.is_symlink() or not journal.exists() or not journal.is_file():
        raise VerificationError("journal missing or not a regular non-symlink file")
    events = _read_jsonl(journal)
    _verify_audit_events(events)
    end_seq = fields["end_seq"]
    if len(events) < end_seq:
        raise VerificationError(
            f"journal truncation detected: anchor covers sequence {end_seq}, "
            f"journal has only {len(events)} event(s)"
        )
    actual_head = events[end_seq - 1]["event_hash"].lower()
    if actual_head != fields["head_hash"].lower():
        raise VerificationError(
            f"journal does not match anchor at sequence {end_seq}"
        )
    if (manifests is None) != (public_key is None):
        raise VerificationError(
            "manifests and public_key must be supplied together for "
            "binding re-verification"
        )
    if manifests is not None:
        rederived = _derive_release_seq(events, end_seq, manifests, public_key)
        if rederived != fields["release_seq"]:
            raise VerificationError(
                f"anchor release_seq {fields['release_seq']} does not match "
                f"the journal-derived bound release_seq {rederived}"
            )
    return {
        "verified": True,
        "anchored_start_seq": fields["start_seq"],
        "anchored_end_seq": end_seq,
        "anchored_release_seq": fields["release_seq"],
        "journal_events": len(events),
        "head_hash": actual_head,
        "prev_txid": fields["prev_txid"].lower(),
        "chain_inclusion_verified": False,
    }
