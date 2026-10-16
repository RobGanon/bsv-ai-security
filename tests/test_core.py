import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aiguard.core import (
    VerificationError,
    append_audit_event,
    create_manifest,
    generate_keypair,
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
    envelope["payload"]["release_id"] = "tampered"
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
    with pytest.raises(VerificationError, match="path traversal|absolute|empty component"):
        verify_manifest(root, envelope, private.public_key())


def test_missing_artifact_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    (root / "model.bin").unlink()
    with pytest.raises(VerificationError, match="missing or not a file"):
        verify_manifest(root, envelope, private.public_key())


def test_audit_chain_round_trip_and_tamper_detection(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    append_audit_event(journal, "test", "two")
    assert verify_audit_journal(journal) == 2
    events = [json.loads(line) for line in journal.read_text().splitlines()]
    events[0]["detail"] = "tampered"
    journal.write_text("\n".join(json.dumps(e, sort_keys=True, separators=(",", ":")) for e in events) + "\n")
    with pytest.raises(VerificationError, match="hash mismatch|chain broken"):
        verify_audit_journal(journal)


def test_audit_chain_detects_deletion(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "one")
    append_audit_event(journal, "test", "two")
    lines = journal.read_text().splitlines()
    journal.write_text(lines[0] + "\n")
    # Truncating to a valid prefix leaves an intact chain of length 1.
    assert verify_audit_journal(journal) == 1


def test_empty_audit_is_valid(tmp_path):
    journal = tmp_path / "audit.jsonl"
    assert verify_audit_journal(journal) == 0


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
    private, envelope = make_signed(root, release_seq=5)
    assert verify_manifest(root, envelope, private.public_key(), min_release_seq=5) == [
        "model.bin",
        "config.json",
    ]


def test_release_seq_tampering_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    envelope["payload"]["release_seq"] = 99
    with pytest.raises(VerificationError, match="signature invalid"):
        verify_manifest(root, envelope, private.public_key())


def test_missing_release_seq_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private = Ed25519PrivateKey.generate()
    payload = create_manifest(root, ["model.bin"], "r", 1)
    del payload["release_seq"]
    envelope = sign_manifest(payload, private)
    with pytest.raises(VerificationError):
        verify_manifest(root, envelope, private.public_key())


def test_verified_artifacts_yields_readable_handles(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    with verified_artifacts(root, envelope, private.public_key()) as arts:
        assert len(arts) == 2
        assert arts[0].path == "model.bin"
        assert arts[0].handle.read() == b"model-v1"
        assert arts[0].size == len(b"model-v1")


def test_verified_artifacts_detects_tampering(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    (root / "model.bin").write_bytes(b"tampered")
    with pytest.raises(VerificationError, match="integrity mismatch"):
        with verified_artifacts(root, envelope, private.public_key()):
            pass


def test_verified_artifacts_rejects_symlink(tmp_path):
    root = setup_artifacts(tmp_path)
    private = Ed25519PrivateKey.generate()
    digest, size = sha256_file(root / "model.bin")
    (root / "link.bin").symlink_to("model.bin")
    payload = {
        "schema": "aiguard-manifest-v1",
        "release_id": "r",
        "release_seq": 1,
        "artifacts": [{"path": "link.bin", "sha256": digest, "size": size}],
    }
    envelope = sign_manifest(payload, private)
    with pytest.raises(VerificationError, match="symlink"):
        with verified_artifacts(root, envelope, private.public_key()):
            pass


def test_verified_artifacts_enforces_rollback(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, release_seq=1)
    with pytest.raises(VerificationError, match="rollback"):
        with verified_artifacts(root, envelope, private.public_key(), min_release_seq=2):
            pass


def test_audit_append_refuses_tampered_existing_journal(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "original")
    event = json.loads(journal.read_text().splitlines()[0])
    event["detail"] = "tampered"
    journal.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(VerificationError):
        append_audit_event(journal, "test", "new event")


@pytest.mark.parametrize("invalid_event_type", ["", None, 123])
def test_audit_append_rejects_invalid_event_type(tmp_path, invalid_event_type):
    with pytest.raises(VerificationError, match="event_type"):
        append_audit_event(tmp_path / "audit.jsonl", invalid_event_type, "detail")


def test_audit_append_rejects_non_string_detail(tmp_path):
    with pytest.raises(VerificationError, match="detail"):
        append_audit_event(tmp_path / "audit.jsonl", "test", {"unexpected": "object"})


@pytest.mark.parametrize("json_value", ["null", "[]", "\"string\"", "42"])
def test_audit_verify_rejects_non_object_jsonl_records(tmp_path, json_value):
    journal = tmp_path / "audit.jsonl"
    journal.write_text(json_value + "\n")
    with pytest.raises(VerificationError):
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
        json.dumps({k: v for k, v in event.items() if k != "event_hash"}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    journal.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(VerificationError, match="sequence"):
        verify_audit_journal(journal)


def test_audit_verify_rejects_symlink_journal(tmp_path):
    real = tmp_path / "real.jsonl"
    real.write_text("")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(real)
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


def test_audit_append_rejects_oversized_detail(tmp_path):
    journal = tmp_path / "audit.jsonl"
    oversized = "x" * 4097
    with pytest.raises(VerificationError, match="detail exceeds maximum"):
        append_audit_event(journal, "test", oversized)


def test_audit_append_accepts_detail_at_limit(tmp_path):
    journal = tmp_path / "audit.jsonl"
    detail = "x" * 4096
    event = append_audit_event(journal, "test", detail)
    assert event["detail"] == detail
    assert verify_audit_journal(journal) == 1


def test_audit_accepts_uppercase_stored_event_hash(tmp_path):
    """Mixed-case event_hash / previous_hash still verify after normalization."""
    journal = tmp_path / "audit.jsonl"
    event = append_audit_event(journal, "test", "one")
    # Force uppercase into the stored file.
    lines = journal.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[0])
    obj["event_hash"] = obj["event_hash"].upper()
    obj["previous_hash"] = obj["previous_hash"].upper()
    journal.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    assert verify_audit_journal(journal) == 1
    # Appending after an uppercase prior still works and produces lowercase.
    event2 = append_audit_event(journal, "test", "two")
    assert event2["previous_hash"] == event2["previous_hash"].lower()
    assert event2["event_hash"] == event2["event_hash"].lower()
    assert verify_audit_journal(journal) == 2


def test_manifest_accepts_uppercase_sha256(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    # Uppercase the stored hash; verification should still succeed.
    art = envelope["payload"]["artifacts"][0]
    art["sha256"] = art["sha256"].upper()
    # Re-sign so the signature matches the modified payload.
    envelope = sign_manifest(envelope["payload"], private)
    assert verify_manifest(root, envelope, private.public_key()) == ["model.bin", "config.json"]


def test_sequential_locked_appends_produce_valid_chain(tmp_path):
    journal = tmp_path / "audit.jsonl"
    for i in range(5):
        append_audit_event(journal, "test", f"event-{i}")
    assert verify_audit_journal(journal) == 5


def test_appended_line_matches_canonical_hash_bytes(tmp_path):
    from aiguard.core import canonical_json_bytes

    journal = tmp_path / "audit.jsonl"
    event = append_audit_event(journal, "test", "données ✓ 温度")
    stored_line = journal.read_bytes().decode("utf-8").rstrip("\n")
    # Stored bytes must equal the canonical hash-input bytes (no \uXXXX
    # escapes), so independent verifiers hashing raw bytes agree.
    assert stored_line == canonical_json_bytes(event).decode("utf-8")
    assert "\\u" not in stored_line
    assert verify_audit_journal(journal) == 1



def test_generate_keypair_rejects_same_private_and_public_path(tmp_path):
    key_path = tmp_path / "key.pem"

    with pytest.raises(ValueError, match="different|distinct|same"):
        generate_keypair(key_path, key_path)

    # A rejected call must not leave a public key where a private key was expected.
    if key_path.exists():
        assert b"PRIVATE KEY" not in key_path.read_bytes()


@pytest.mark.parametrize("which_path", ["private", "public"])
def test_generate_keypair_rejects_symlink_output_without_overwriting_target(
    tmp_path, which_path
):
    target = tmp_path / "target.txt"
    original = b"preserve this file"
    target.write_bytes(original)

    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    selected = private_path if which_path == "private" else public_path
    selected.symlink_to(target)

    with pytest.raises(OSError):
        generate_keypair(private_path, public_path)

    assert target.read_bytes() == original
