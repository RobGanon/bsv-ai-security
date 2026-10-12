import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aiguard.core import (
    VerificationError,
    append_audit_event,
    create_manifest,
    sha256_file,
    sign_manifest,
    verify_audit_journal,
    verify_manifest,
    verified_artifacts,
)


def setup_artifacts(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "model.bin").write_bytes(b"model-v1")
    (root / "config.json").write_text('{"safe":true}\n', encoding="utf-8")
    return root


def make_signed(root: Path, private=None, release_seq: int = 1):
    private = private or Ed25519PrivateKey.generate()
    payload = create_manifest(root, ["model.bin", "config.json"], "test-release", release_seq)
    return private, sign_manifest(payload, private)


def test_valid_manifest_passes(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    assert verify_manifest(root, envelope, private.public_key()) == ["model.bin", "config.json"]


def test_modified_artifact_is_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    (root / "model.bin").write_bytes(b"modified")
    with pytest.raises(VerificationError, match="integrity mismatch"):
        verify_manifest(root, envelope, private.public_key())


def test_wrong_public_key_rejects_manifest(tmp_path):
    root = setup_artifacts(tmp_path)
    _, envelope = make_signed(root)
    other = Ed25519PrivateKey.generate()
    with pytest.raises(VerificationError, match="signature invalid"):
        verify_manifest(root, envelope, other.public_key())


def test_payload_tampering_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    envelope["payload"]["release_id"] = "attacker-release"
    with pytest.raises(VerificationError, match="signature invalid"):
        verify_manifest(root, envelope, private.public_key())


def test_path_traversal_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private = Ed25519PrivateKey.generate()
    payload = {
        "schema": "aiguard-manifest-v1",
        "release_id": "bad",
        "release_seq": 1,
        "artifacts": [{"path": "../outside", "sha256": "0" * 64, "size": 0}],
    }
    envelope = sign_manifest(payload, private)
    with pytest.raises(VerificationError, match="path traversal"):
        verify_manifest(root, envelope, private.public_key())


def test_missing_artifact_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    (root / "model.bin").unlink()
    with pytest.raises(VerificationError, match="missing"):
        verify_manifest(root, envelope, private.public_key())


def test_audit_chain_round_trip_and_tamper_detection(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    append_audit_event(journal, "test", "two")
    assert verify_audit_journal(journal) == 2

    events = [json.loads(line) for line in journal.read_text().splitlines()]
    events[0]["detail"] = "tampered"
    journal.write_text("".join(json.dumps(e) + "\n" for e in events))
    with pytest.raises(VerificationError):
        verify_audit_journal(journal)


def test_audit_chain_detects_deletion(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    append_audit_event(journal, "test", "two")
    lines = journal.read_text().splitlines()
    journal.write_text(lines[1] + "\n")
    with pytest.raises(VerificationError):
        verify_audit_journal(journal)


def test_empty_audit_is_valid(tmp_path):
    assert verify_audit_journal(tmp_path / "not-created.jsonl") == 0


def test_empty_existing_audit_file_can_be_appended(tmp_path):
    journal = tmp_path / "audit.jsonl"
    journal.write_text("")
    event = append_audit_event(journal, "test", "first")
    assert event["seq"] == 1
    assert verify_audit_journal(journal) == 1


def test_rollback_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, release_seq=1)
    with pytest.raises(VerificationError, match="rollback"):
        verify_manifest(root, envelope, private.public_key(), min_release_seq=2)


def test_current_release_accepted_with_min_seq(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, release_seq=2)
    assert verify_manifest(root, envelope, private.public_key(), min_release_seq=2) == [
        "model.bin",
        "config.json",
    ]


def test_release_seq_tampering_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, release_seq=1)
    envelope["payload"]["release_seq"] = 99
    with pytest.raises(VerificationError, match="signature invalid"):
        verify_manifest(root, envelope, private.public_key())


def test_missing_release_seq_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private = Ed25519PrivateKey.generate()
    payload = create_manifest(root, ["model.bin"], "test-release", 1)
    del payload["release_seq"]
    envelope = sign_manifest(payload, private)
    with pytest.raises(VerificationError, match="release_seq"):
        verify_manifest(root, envelope, private.public_key())


def test_verified_artifacts_yields_readable_handles(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, release_seq=3)
    with verified_artifacts(root, envelope, private.public_key()) as arts:
        assert [a.path for a in arts] == ["model.bin", "config.json"]
        assert arts[0].handle.read() == b"model-v1"
        assert arts[0].sha256 == hashlib.sha256(b"model-v1").hexdigest()
        assert arts[0].size == len(b"model-v1")
    # Handles are closed when the context exits.
    with pytest.raises(ValueError):
        arts[0].handle.read()


def test_verified_artifacts_detects_tampering(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, release_seq=1)
    (root / "model.bin").write_bytes(b"modified")
    with pytest.raises(VerificationError, match="integrity mismatch"):
        with verified_artifacts(root, envelope, private.public_key()):
            pass


def test_verified_artifacts_rejects_symlink(tmp_path):
    root = setup_artifacts(tmp_path)
    (root / "link.bin").symlink_to("model.bin")
    private = Ed25519PrivateKey.generate()
    digest, size = sha256_file(root / "model.bin")
    payload = {
        "schema": "aiguard-manifest-v1",
        "release_id": "test-release",
        "release_seq": 1,
        "artifacts": [{"path": "link.bin", "sha256": digest, "size": size}],
    }
    envelope = sign_manifest(payload, private)
    with pytest.raises(VerificationError):
        with verified_artifacts(root, envelope, private.public_key()):
            pass


def test_verified_artifacts_enforces_rollback(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, release_seq=1)
    with pytest.raises(VerificationError, match="rollback"):
        with verified_artifacts(root, envelope, private.public_key(), min_release_seq=5):
            pass


def test_audit_append_refuses_tampered_existing_journal(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "original")
    event = json.loads(journal.read_text().splitlines()[0])
    event["detail"] = "tampered"
    journal.write_text(json.dumps(event) + "\n")

    with pytest.raises(VerificationError, match="hash mismatch"):
        append_audit_event(journal, "test", "new event")


@pytest.mark.parametrize("invalid_event_type", ["", None, 123])
def test_audit_append_rejects_invalid_event_type(tmp_path, invalid_event_type):
    with pytest.raises(VerificationError, match="event_type"):
        append_audit_event(tmp_path / "audit.jsonl", invalid_event_type, "detail")


def test_audit_append_rejects_non_string_detail(tmp_path):
    with pytest.raises(VerificationError, match="detail"):
        append_audit_event(tmp_path / "audit.jsonl", "test", {"unexpected": "object"})


@pytest.mark.parametrize("json_value", ["[]", "null", '"text"', "42", "true"])
def test_audit_verify_rejects_non_object_jsonl_records(tmp_path, json_value):
    journal = tmp_path / "audit.jsonl"
    journal.write_text(json_value + "\n", encoding="utf-8")

    with pytest.raises(VerificationError, match="JSON object"):
        verify_audit_journal(journal)


def test_audit_verify_rejects_boolean_sequence_number(tmp_path):
    journal = tmp_path / "audit.jsonl"
    event = {
        "seq": True,
        "event_type": "test",
        "detail": "bad sequence",
        "previous_hash": "0" * 64,
    }
    event["event_hash"] = hashlib.sha256(
        json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    journal.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(VerificationError, match="sequence mismatch"):
        verify_audit_journal(journal)


def test_audit_verify_rejects_symlink_journal(tmp_path):
    target = tmp_path / "real.jsonl"
    target.write_text("", encoding="utf-8")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(target)

    with pytest.raises(VerificationError, match="non-symlink"):
        verify_audit_journal(link)


def test_audit_verify_rejects_dangling_symlink_journal(tmp_path):
    link = tmp_path / "audit.jsonl"
    link.symlink_to(tmp_path / "missing.jsonl")

    with pytest.raises(VerificationError, match="non-symlink"):
        verify_audit_journal(link)


def test_audit_append_rejects_dangling_symlink_journal(tmp_path):
    link = tmp_path / "audit.jsonl"
    link.symlink_to(tmp_path / "missing.jsonl")

    with pytest.raises(VerificationError, match="non-symlink"):
        append_audit_event(link, "test", "detail")


def test_concurrent_appends_keep_journal_valid(tmp_path):
    import threading

    journal = tmp_path / "audit.jsonl"

    def writer(n):
        for i in range(25):
            append_audit_event(journal, "test", f"writer-{n}-{i}")

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert verify_audit_journal(journal) == 100


def test_appended_line_matches_canonical_hash_bytes(tmp_path):
    from aiguard.core import canonical_json_bytes

    journal = tmp_path / "audit.jsonl"
    event = append_audit_event(journal, "test", "données ✓ 温度")
    stored_line = journal.read_bytes().decode("utf-8").rstrip("\n")
    # The stored line must use the canonical serialization (no \uXXXX
    # escapes), so independent verifiers hashing raw bytes agree.
    assert stored_line == canonical_json_bytes(event).decode("utf-8")
    assert "\\u" not in stored_line
    assert verify_audit_journal(journal) == 1
