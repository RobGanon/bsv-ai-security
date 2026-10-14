"""Issue #9: anchored release_seq is derived from journal acceptance events.

Covers every acceptance test in the issue #9 session plan. The anchoring
caller never supplies release_seq; create_anchor_payload derives
max(release_seq) over manifest_accepted events with seq <= end_seq, or 0
when the journal contains no acceptance.
"""

import hashlib
import json

import pytest

from aiguard.anchor import (
    create_anchor_payload,
    decode_anchor_payload,
    encode_anchor_payload,
    verify_journal_against_anchor,
)
from aiguard.cli import main
from aiguard.core import (
    VerificationError,
    append_audit_event,
    canonical_json_bytes,
    record_manifest_acceptance,
    verify_audit_journal,
)


def _write_chained_journal(path, raw_events):
    """Write hand-crafted events with a valid hash chain (for malformed-detail tests)."""
    previous = "0" * 64
    lines = []
    for seq, (event_type, detail) in enumerate(raw_events, 1):
        body = {
            "seq": seq,
            "event_type": event_type,
            "detail": detail,
            "previous_hash": previous,
        }
        event_hash = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        lines.append(canonical_json_bytes({**body, "event_hash": event_hash}).decode("utf-8"))
        previous = event_hash
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("bad_seq", [True, -1, 2**32, "3", None])
def test_record_acceptance_rejects_bad_release_seq(tmp_path, bad_seq):
    journal = tmp_path / "audit.jsonl"
    with pytest.raises(VerificationError):
        record_manifest_acceptance(journal, bad_seq, "r-1")
    assert not journal.exists() or verify_audit_journal(journal) == 0


@pytest.mark.parametrize("bad_id", ["", None, 123, b"r-1"])
def test_record_acceptance_rejects_bad_release_id(tmp_path, bad_id):
    journal = tmp_path / "audit.jsonl"
    with pytest.raises(VerificationError):
        record_manifest_acceptance(journal, 1, bad_id)
    assert not journal.exists() or verify_audit_journal(journal) == 0


def test_acceptance_detail_is_canonical_json_and_round_trips(tmp_path):
    journal = tmp_path / "audit.jsonl"
    event = record_manifest_acceptance(journal, 3, "release-3")
    assert event["event_type"] == "manifest_accepted"
    stored = journal.read_text(encoding="utf-8").rstrip("\n")
    assert stored == canonical_json_bytes(event).decode("utf-8")
    detail = json.loads(event["detail"])
    assert detail == {"release_seq": 3, "release_id": "release-3"}
    assert verify_audit_journal(journal) == 1


def test_anchor_derives_max_release_seq(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    record_manifest_acceptance(journal, 2, "r-2")
    append_audit_event(journal, "test", "two")
    record_manifest_acceptance(journal, 5, "r-5")
    record_manifest_acceptance(journal, 3, "r-3")
    result = create_anchor_payload(journal, start_seq=1)
    assert result["release_seq"] == 5
    assert result["end_seq"] == 5


def test_anchor_with_no_acceptance_derives_zero(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    append_audit_event(journal, "test", "two")
    result = create_anchor_payload(journal, start_seq=1)
    assert result["release_seq"] == 0


def test_acceptance_after_end_seq_not_counted(tmp_path):
    # A valid prefix journal is itself a valid journal: anchor the prefix
    # and the later acceptance must not leak into the derived checkpoint.
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    record_manifest_acceptance(journal, 5, "r-5")
    append_audit_event(journal, "test", "two")
    record_manifest_acceptance(journal, 9, "r-9")
    full_lines = journal.read_text(encoding="utf-8").splitlines()
    prefix = tmp_path / "prefix.jsonl"
    prefix.write_text("\n".join(full_lines[:3]) + "\n", encoding="utf-8")
    assert verify_audit_journal(prefix) == 3
    result = create_anchor_payload(prefix, start_seq=1)
    assert result["end_seq"] == 3
    assert result["release_seq"] == 5  # not 9: seq-4 acceptance is out of range
    # The full journal still derives the max.
    assert create_anchor_payload(journal, start_seq=1)["release_seq"] == 9


def test_tampered_acceptance_refuses_anchor(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    record_manifest_acceptance(journal, 4, "r-4")
    lines = journal.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[1])
    event["detail"] = json.dumps(
        {"release_seq": 99, "release_id": "forged"}, sort_keys=True, separators=(",", ":")
    )
    lines[1] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(VerificationError):
        verify_audit_journal(journal)
    with pytest.raises(VerificationError):
        create_anchor_payload(journal, start_seq=1)


@pytest.mark.parametrize(
    "bad_detail",
    [
        "not json {",
        '{"release_seq": -1, "release_id": "r"}',
        '{"release_seq": true, "release_id": "r"}',
        '{"release_seq": 4294967296, "release_id": "r"}',
        '{"release_seq": "3", "release_id": "r"}',
        '{"release_id": "r"}',
        '{"release_seq": 3}',
        '{"release_seq": 3, "release_id": ""}',
        '{"release_seq": 3, "release_id": 7}',
        '["not", "an", "object"]',
        "42",
    ],
)
def test_malformed_acceptance_detail_fails_closed(tmp_path, bad_detail):
    journal = _write_chained_journal(
        tmp_path / "audit.jsonl",
        [("test", "one"), ("manifest_accepted", bad_detail)],
    )
    # The hash chain itself is valid, so the failure must come from derivation.
    assert verify_audit_journal(journal) == 2
    with pytest.raises(VerificationError):
        create_anchor_payload(journal, start_seq=1)


def test_malformed_acceptance_detail_non_string_fails_closed(tmp_path):
    journal = _write_chained_journal(
        tmp_path / "audit.jsonl",
        [("test", "one")],
    )
    # Append a manifest_accepted event whose detail is a JSON object, not a string.
    previous = json.loads(journal.read_text(encoding="utf-8").splitlines()[-1])["event_hash"]
    body = {
        "seq": 2,
        "event_type": "manifest_accepted",
        "detail": {"release_seq": 1, "release_id": "r"},
        "previous_hash": previous,
    }
    event_hash = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    line = canonical_json_bytes({**body, "event_hash": event_hash}).decode("utf-8")
    with open(journal, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    assert verify_audit_journal(journal) == 2
    with pytest.raises(VerificationError):
        create_anchor_payload(journal, start_seq=1)


def test_old_style_call_raises_type_error(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    with pytest.raises(TypeError):
        create_anchor_payload(journal, start_seq=1, release_seq=5)


def test_end_to_end_acceptance_anchor_verify(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    record_manifest_acceptance(journal, 4, "release-4")
    append_audit_event(journal, "test", "two")
    result = create_anchor_payload(journal, start_seq=1)
    assert result["release_seq"] == 4
    payload = bytes.fromhex(result["payload_hex"])
    assert len(payload) == 84
    verified = verify_journal_against_anchor(journal, payload)
    assert verified["verified"] is True
    assert verified["anchored_release_seq"] == 4
    assert decode_anchor_payload(payload)["release_seq"] == 4


def test_old_anchors_still_decode_and_verify(tmp_path):
    # An anchor created with the old caller-supplied value is just bytes:
    # creation changed, decoding/verifying did not.
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    append_audit_event(journal, "test", "two")
    old_payload = encode_anchor_payload(
        head_hash="b" * 64,
        start_seq=1,
        end_seq=2,
        release_seq=99999,
        prev_txid="c" * 64,
    )
    fields = decode_anchor_payload(old_payload)
    assert fields["release_seq"] == 99999
    # A payload built from the journal's real head still verifies locally.
    record_manifest_acceptance(journal, 6, "r-6")
    result = create_anchor_payload(journal, start_seq=1)
    assert result["release_seq"] == 6
    assert verify_journal_against_anchor(
        journal, bytes.fromhex(result["payload_hex"])
    )["verified"] is True


def test_cli_audit_manifest_accepted_and_anchor(tmp_path, capsys):
    journal = tmp_path / "audit.jsonl"
    payload_file = tmp_path / "anchor.json"
    assert (
        main(["audit-append", "--journal", str(journal), "--event-type", "test", "--detail", "one"])
        == 0
    )
    assert (
        main([
            "audit-manifest-accepted",
            "--journal", str(journal),
            "--release-seq", "7",
            "--release-id", "release-7",
        ])
        == 0
    )
    assert "Manifest acceptance recorded" in capsys.readouterr().out
    assert (
        main([
            "anchor-payload",
            "--journal", str(journal),
            "--start-seq", "1",
            "--output", str(payload_file),
        ])
        == 0
    )
    payload = json.loads(payload_file.read_text(encoding="utf-8"))
    assert payload["release_seq"] == 7


def test_cli_anchor_payload_rejects_release_seq_flag(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    with pytest.raises(SystemExit):
        main([
            "anchor-payload",
            "--journal", str(journal),
            "--start-seq", "1",
            "--release-seq", "5",
            "--output", str(tmp_path / "anchor.json"),
        ])


def test_cli_audit_manifest_accepted_rejects_bad_seq(tmp_path):
    journal = tmp_path / "audit.jsonl"
    assert (
        main([
            "audit-manifest-accepted",
            "--journal", str(journal),
            "--release-seq", "-1",
            "--release-id", "r",
        ])
        == 1
    )
    assert not journal.exists() or verify_audit_journal(journal) == 0
