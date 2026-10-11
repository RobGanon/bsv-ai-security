import json
from pathlib import Path

import pytest

from aiguard.anchor import (
    MAGIC,
    PAYLOAD_SIZE,
    ZERO_TXID,
    create_anchor_payload,
    decode_anchor_payload,
    encode_anchor_payload,
    verify_journal_against_anchor,
)
from aiguard.core import VerificationError, append_audit_event


def make_journal(path: Path, count: int = 3) -> Path:
    for number in range(count):
        append_audit_event(path, "test", f"event-{number + 1}")
    return path


def test_payload_has_protocol_layout_and_round_trips(tmp_path):
    journal = make_journal(tmp_path / "audit.jsonl")
    fields = create_anchor_payload(
        journal, start_seq=1, release_seq=7, prev_txid=ZERO_TXID
    )
    payload = bytes.fromhex(fields["payload_hex"])

    assert len(payload) == PAYLOAD_SIZE == 84
    assert payload[:8] == MAGIC
    assert decode_anchor_payload(payload) == fields
    assert fields["start_seq"] == 1
    assert fields["end_seq"] == 3
    assert fields["release_seq"] == 7
    assert fields["prev_txid"] == ZERO_TXID


def test_anchor_verification_accepts_unchanged_journal(tmp_path):
    journal = make_journal(tmp_path / "audit.jsonl")
    fields = create_anchor_payload(journal, start_seq=2, release_seq=4)
    result = verify_journal_against_anchor(journal, bytes.fromhex(fields["payload_hex"]))

    assert result["verified"] is True
    assert result["anchored_start_seq"] == 2
    assert result["anchored_end_seq"] == 3
    assert result["anchored_release_seq"] == 4
    assert result["chain_inclusion_verified"] is False


def test_anchor_verification_rejects_modified_journal(tmp_path):
    journal = make_journal(tmp_path / "audit.jsonl")
    fields = create_anchor_payload(journal, start_seq=1, release_seq=0)
    append_audit_event(journal, "test", "later event")
    lines = journal.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[1])
    event["detail"] = "rewritten"
    lines[1] = json.dumps(event)
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(VerificationError):
        verify_journal_against_anchor(journal, bytes.fromhex(fields["payload_hex"]))


def test_anchor_verification_detects_truncated_tail(tmp_path):
    journal = make_journal(tmp_path / "audit.jsonl")
    fields = create_anchor_payload(journal, start_seq=1, release_seq=0)
    lines = journal.read_text(encoding="utf-8").splitlines()
    journal.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

    with pytest.raises(VerificationError, match="truncation"):
        verify_journal_against_anchor(journal, bytes.fromhex(fields["payload_hex"]))


def test_anchor_verification_rejects_deleted_journal(tmp_path):
    journal = make_journal(tmp_path / "audit.jsonl")
    fields = create_anchor_payload(journal, start_seq=1, release_seq=0)
    journal.unlink()

    with pytest.raises(VerificationError, match="missing"):
        verify_journal_against_anchor(journal, bytes.fromhex(fields["payload_hex"]))


@pytest.mark.parametrize("payload", [b"", b"x" * 83, b"x" * 85])
def test_decoder_rejects_wrong_payload_size(payload):
    with pytest.raises(VerificationError, match="84 bytes"):
        decode_anchor_payload(payload)


def test_decoder_rejects_wrong_magic():
    payload = b"BADMAGIC" + bytes(76)
    assert len(payload) == PAYLOAD_SIZE
    with pytest.raises(VerificationError, match="magic"):
        decode_anchor_payload(payload)


@pytest.mark.parametrize("start_seq, end_seq, release_seq", [
    (0, 1, 0),
    (2, 1, 0),
    (1, 1, -1),
    (1, 1, True),
    (1, 1, 2**32),
])
def test_encoder_rejects_invalid_sequence_values(start_seq, end_seq, release_seq):
    with pytest.raises(VerificationError):
        encode_anchor_payload(
            head_hash="a" * 64,
            start_seq=start_seq,
            end_seq=end_seq,
            release_seq=release_seq,
        )


def test_encoder_rejects_invalid_hash_and_txid():
    with pytest.raises(VerificationError, match="head_hash"):
        encode_anchor_payload(head_hash="xyz", start_seq=1, end_seq=1, release_seq=0)
    with pytest.raises(VerificationError, match="prev_txid"):
        encode_anchor_payload(
            head_hash="a" * 64, start_seq=1, end_seq=1, release_seq=0, prev_txid="xyz"
        )


def test_create_payload_rejects_empty_journal(tmp_path):
    journal = tmp_path / "empty.jsonl"
    journal.write_text("", encoding="utf-8")
    with pytest.raises(VerificationError, match="empty journal"):
        create_anchor_payload(journal, start_seq=1, release_seq=0)
