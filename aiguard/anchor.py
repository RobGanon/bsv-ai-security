from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .core import VerificationError, _read_jsonl, _verify_audit_events

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


def create_anchor_payload(
    journal: Path,
    *,
    start_seq: int,
    release_seq: int,
    prev_txid: str = ZERO_TXID,
) -> dict[str, Any]:
    """Create an unsigned anchor payload from a verified local journal.

    This only prepares commitment bytes. It does not sign, broadcast, or prove
    inclusion of a Bitcoin SV transaction.
    """
    if journal.is_symlink() or not journal.exists() or not journal.is_file():
        raise VerificationError("journal must exist as a regular non-symlink file")
    events = _read_jsonl(journal)
    _verify_audit_events(events)
    end_seq = len(events)
    start_seq = _uint32(start_seq, "start_seq")
    release_seq = _uint32(release_seq, "release_seq")
    if end_seq < 1:
        raise VerificationError("cannot anchor an empty journal")
    if start_seq < 1 or start_seq > end_seq:
        raise VerificationError("start_seq must identify an event in the journal")
    if end_seq > UINT32_MAX:
        raise VerificationError("journal sequence exceeds the protocol's uint32 limit")
    head_hash = events[end_seq - 1]["event_hash"].lower()
    payload = encode_anchor_payload(
        head_hash=head_hash,
        start_seq=start_seq,
        end_seq=end_seq,
        release_seq=release_seq,
        prev_txid=prev_txid,
    )
    return decode_anchor_payload(payload)


def verify_journal_against_anchor(journal: Path, payload: bytes) -> dict[str, Any]:
    """Check that a local journal contains the head committed by an anchor payload."""
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
