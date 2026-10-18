import pytest
from pathlib import Path

from aiguard.bsv import PrivKey

from aiguard.anchor import (
    create_anchor_payload,
    decode_anchor_payload,
    encode_anchor_payload,
    verify_journal_against_anchor,
)
from aiguard.core import (
    VerificationError,
    append_audit_event,
    manifest_hash,
    record_manifest_acceptance,
    sign_manifest,
)


def write_journal(path: Path, count: int = 3):
    for number in range(count):
        append_audit_event(path, "test", f"event-{number + 1}")
    return path


def test_payload_has_protocol_layout_and_round_trips(tmp_path):
    journal = write_journal(tmp_path / "audit.jsonl")
    key = PrivKey.generate()
    payload = {
        "schema": "aiguard-manifest-v2",
        "release_id": "release-7",
        "release_seq": 7,
        "artifacts": [{"path": "a.txt", "sha256": "a" * 64, "size": 1}],
    }
    envelope = sign_manifest(payload, key)
    record_manifest_acceptance(journal, 7, "release-7", manifest_hash(envelope))
    result = create_anchor_payload(
        journal, start_seq=1, manifests=[envelope], public_key=key.pubkey_compressed()
    )
    assert result["start_seq"] == 1
    assert result["end_seq"] == 4  # 3 test events + 1 acceptance event
    assert result["release_seq"] == 7
    assert len(result["head_hash"]) == 64
    assert len(result["prev_txid"]) == 64
    payload = bytes.fromhex(result["payload_hex"])
    assert len(payload) == 84
    assert decode_anchor_payload(payload)["head_hash"] == result["head_hash"]


def test_anchor_verification_accepts_unchanged_journal(tmp_path):
    journal = write_journal(tmp_path / "audit.jsonl")
    result = create_anchor_payload(journal, start_seq=1)
    payload = bytes.fromhex(result["payload_hex"])
    verified = verify_journal_against_anchor(journal, payload)
    assert verified["verified"] is True
    assert verified["chain_inclusion_verified"] is False


def test_anchor_verification_rejects_modified_journal(tmp_path):
    journal = write_journal(tmp_path / "audit.jsonl")
    result = create_anchor_payload(journal, start_seq=1)
    payload = bytes.fromhex(result["payload_hex"])
    append_audit_event(journal, "test", "later event")
    # Tamper the first event
    lines = journal.read_text(encoding="utf-8").splitlines()
    event = __import__("json").loads(lines[0])
    event["detail"] = "rewritten"
    lines[0] = __import__("json").dumps(event, sort_keys=True, separators=(",", ":"))
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(VerificationError):
        verify_journal_against_anchor(journal, payload)


def test_anchor_verification_detects_truncated_tail(tmp_path):
    journal = write_journal(tmp_path / "audit.jsonl", count=4)
    result = create_anchor_payload(journal, start_seq=1)
    payload = bytes.fromhex(result["payload_hex"])
    lines = journal.read_text(encoding="utf-8").splitlines()[:2]
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(VerificationError, match="truncation"):
        verify_journal_against_anchor(journal, payload)


def test_anchor_verification_rejects_deleted_journal(tmp_path):
    journal = write_journal(tmp_path / "audit.jsonl")
    result = create_anchor_payload(journal, start_seq=1)
    payload = bytes.fromhex(result["payload_hex"])
    journal.unlink()
    with pytest.raises(VerificationError, match="missing"):
        verify_journal_against_anchor(journal, payload)


@pytest.mark.parametrize("payload", [b"", b"x" * 83, b"x" * 85])
def test_decoder_rejects_wrong_payload_size(payload):
    with pytest.raises(VerificationError, match="exactly 84"):
        decode_anchor_payload(payload)


def test_decoder_rejects_wrong_magic():
    bad = b"BADMAGIC" + b"\x00" * 76
    with pytest.raises(VerificationError, match="magic"):
        decode_anchor_payload(bad)


@pytest.mark.parametrize(
    "start_seq, end_seq, release_seq",
    [(0, 1, 1), (2, 1, 1), (1, 1, -1)],
)
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
        encode_anchor_payload(head_hash="zz", start_seq=1, end_seq=1, release_seq=1)
    with pytest.raises(VerificationError, match="prev_txid"):
        encode_anchor_payload(
            head_hash="a" * 64, start_seq=1, end_seq=1, release_seq=1, prev_txid="zz"
        )


def test_create_payload_rejects_empty_journal(tmp_path):
    journal = tmp_path / "empty.jsonl"
    journal.write_text("", encoding="utf-8")
    with pytest.raises(VerificationError, match="empty"):
        create_anchor_payload(journal, start_seq=1)


def test_encoder_accepts_uppercase_hex_and_stores_lowercase():
    from aiguard.anchor import encode_anchor_payload, decode_anchor_payload
    upper = "A" * 64
    payload = encode_anchor_payload(
        head_hash=upper,
        start_seq=1,
        end_seq=1,
        release_seq=1,
        prev_txid=upper,
    )
    fields = decode_anchor_payload(payload)
    assert fields["head_hash"] == "a" * 64
    assert fields["prev_txid"] == "a" * 64
