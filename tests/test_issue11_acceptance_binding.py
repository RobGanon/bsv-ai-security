"""Issue #11: manifest acceptance events are bound to manifests.

An acceptance carries the manifest_hash of one exact signed manifest
envelope (SHA-256 over canonical envelope JSON). Anchor-time derivation
verifies the envelope's Ed25519 signature against a trusted public key
and requires the acceptance's release_id / release_seq to match the
manifest's own fields. Forged acceptances — unknown hash, mismatched
identity, bad signature, or missing binding inputs — fail closed.

Authorization (who recorded the acceptance) is explicitly OUT of scope:
binding stops forged/nonexistent releases, not an operator with journal
write access re-accepting a real manifest. See the trust-boundary note
in docs/phase2-implementation.md.
"""

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aiguard.anchor import create_anchor_payload, verify_journal_against_anchor
from aiguard.cli import main
from aiguard.core import (
    VerificationError,
    append_audit_event,
    canonical_json_bytes,
    manifest_hash,
    record_manifest_acceptance,
    sign_manifest,
)


def _write_chained_journal(path, raw_events):
    """Write hand-crafted events with a valid hash chain."""
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


def _envelope(key, release_seq, release_id):
    payload = {
        "schema": "aiguard-manifest-v1",
        "release_id": release_id,
        "release_seq": release_seq,
        "artifacts": [{"path": "a.txt", "sha256": "a" * 64, "size": 1}],
    }
    return sign_manifest(payload, key)


def _accept(journal, key, manifests, release_seq, release_id):
    envelope = _envelope(key, release_seq, release_id)
    manifests.append(envelope)
    return record_manifest_acceptance(
        journal, release_seq, release_id, manifest_hash(envelope)
    )


def _anchor(journal, key, manifests):
    return create_anchor_payload(
        journal, start_seq=1, manifests=manifests, public_key=key.public_key()
    )


# --- manifest_hash helper ---


def test_manifest_hash_covers_payload_and_signature():
    key = Ed25519PrivateKey.generate()
    envelope = _envelope(key, 1, "r-1")
    digest = manifest_hash(envelope)
    assert digest == hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()
    # A different signature over the same payload hashes differently.
    # (Ed25519 is deterministic, so the same key + payload re-signs
    # identically — use a different key for a different signature.)
    other = _envelope(Ed25519PrivateKey.generate(), 1, "r-1")
    assert manifest_hash(other) != digest
    # A tampered payload hashes differently.
    tampered = json.loads(json.dumps(envelope))
    tampered["payload"]["release_seq"] = 2
    assert manifest_hash(tampered) != digest
    with pytest.raises(VerificationError):
        manifest_hash("not a dict")


# --- happy path ---


def test_bound_acceptance_anchors(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key, manifests, 4, "release-4")
    assert _anchor(journal, key, manifests)["release_seq"] == 4


def test_duplicate_acceptance_of_same_manifest_derives_same_value(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    envelope = _envelope(key, 3, "r-3")
    record_manifest_acceptance(journal, 3, "r-3", manifest_hash(envelope))
    record_manifest_acceptance(journal, 3, "r-3", manifest_hash(envelope))
    assert _anchor(journal, key, [envelope])["release_seq"] == 3


def test_multiple_manifests_max_wins(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key, manifests, 2, "r-2")
    _accept(journal, key, manifests, 9, "r-9")
    _accept(journal, key, manifests, 5, "r-5")
    assert _anchor(journal, key, manifests)["release_seq"] == 9


def test_acceptance_from_different_signing_key_verifies_with_its_key(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key_a, manifests, 1, "r-1")
    _accept(journal, key_b, manifests, 2, "r-2")
    # Neither key alone verifies both acceptances.
    with pytest.raises(VerificationError):
        create_anchor_payload(
            journal, start_seq=1, manifests=manifests, public_key=key_a.public_key()
        )
    with pytest.raises(VerificationError):
        create_anchor_payload(
            journal, start_seq=1, manifests=manifests, public_key=key_b.public_key()
        )


# --- forged acceptances fail closed ---


def test_forged_acceptance_unknown_hash_rejected(tmp_path):
    # The exact #11 demo shape: well-formed acceptance, hash of nothing.
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    real = _envelope(key, 1, "r-1")
    record_manifest_acceptance(journal, 999, "rel-never-existed", "c" * 64)
    with pytest.raises(VerificationError, match="unbound"):
        create_anchor_payload(
            journal, start_seq=1, manifests=[real], public_key=key.public_key()
        )


def test_forged_acceptance_rebound_to_different_release_rejected(tmp_path):
    # Real manifest's hash, but the acceptance claims a different release.
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    envelope = _envelope(key, 3, "r-3")
    record_manifest_acceptance(journal, 999, "rel-never-existed", manifest_hash(envelope))
    with pytest.raises(VerificationError, match="does not match"):
        create_anchor_payload(
            journal, start_seq=1, manifests=[envelope], public_key=key.public_key()
        )


def test_forged_acceptance_mismatched_release_seq_rejected(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    envelope = _envelope(key, 3, "r-3")
    record_manifest_acceptance(journal, 4, "r-3", manifest_hash(envelope))
    with pytest.raises(VerificationError, match="does not match"):
        create_anchor_payload(
            journal, start_seq=1, manifests=[envelope], public_key=key.public_key()
        )


def test_acceptance_without_manifests_fails_closed(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key, manifests, 2, "r-2")
    with pytest.raises(VerificationError, match="without manifests"):
        create_anchor_payload(journal, start_seq=1)
    with pytest.raises(VerificationError, match="without manifests"):
        create_anchor_payload(
            journal, start_seq=1, manifests=[], public_key=key.public_key()
        )


def test_acceptance_without_public_key_fails_closed(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key, manifests, 2, "r-2")
    with pytest.raises(VerificationError, match="public key"):
        create_anchor_payload(journal, start_seq=1, manifests=manifests)


def test_manifest_with_bad_signature_rejected(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    envelope = _envelope(key, 2, "r-2")
    record_manifest_acceptance(journal, 2, "r-2", manifest_hash(envelope))
    # Corrupt the signature; anchoring against the corrupted envelope
    # must fail at signature verification, before any acceptance matches.
    corrupted = json.loads(json.dumps(envelope))
    sig = bytearray(base64.b64decode(corrupted["signature"]))
    sig[0] ^= 0xFF
    corrupted["signature"] = base64.b64encode(bytes(sig)).decode("ascii")
    # Anchor against the corrupted envelope: signature verification fails.
    with pytest.raises(VerificationError, match="signature"):
        create_anchor_payload(
            journal, start_seq=1, manifests=[corrupted], public_key=key.public_key()
        )


def test_manifest_with_wrong_schema_rejected(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    envelope = _envelope(key, 2, "r-2")
    envelope["payload"] = dict(envelope["payload"], schema="something-else-v9")
    record_manifest_acceptance(journal, 2, "r-2", manifest_hash(envelope))
    with pytest.raises(VerificationError, match="schema"):
        create_anchor_payload(
            journal, start_seq=1, manifests=[envelope], public_key=key.public_key()
        )


def test_legacy_acceptance_without_manifest_hash_fails_closed(tmp_path):
    journal = _write_chained_journal(
        tmp_path / "audit.jsonl",
        [("manifest_accepted", '{"release_seq": 3, "release_id": "r-3"}')],
    )
    with pytest.raises(VerificationError, match="legacy"):
        create_anchor_payload(journal, start_seq=1)


def test_acceptance_with_malformed_manifest_hash_fails_closed(tmp_path):
    for bad_hash in ["zz", "a" * 63, 42, None]:
        journal = _write_chained_journal(
            tmp_path / "audit.jsonl",
            [(
                "manifest_accepted",
                json.dumps(
                    {"release_seq": 3, "release_id": "r-3", "manifest_hash": bad_hash}
                ),
            )],
        )
        with pytest.raises(VerificationError):
            create_anchor_payload(journal, start_seq=1)


# --- verify path ---


def test_verify_with_binding_rederivation(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key, manifests, 4, "release-4")
    result = _anchor(journal, key, manifests)
    payload = bytes.fromhex(result["payload_hex"])
    verified = verify_journal_against_anchor(
        journal, payload, manifests, key.public_key()
    )
    assert verified["verified"] is True
    assert verified["anchored_release_seq"] == 4


def test_verify_with_binding_rejects_mismatched_checkpoint(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key, manifests, 4, "release-4")
    result = _anchor(journal, key, manifests)
    # Forge a payload with the same head but a different release_seq.
    from aiguard.anchor import encode_anchor_payload

    forged = encode_anchor_payload(
        head_hash=result["head_hash"],
        start_seq=result["start_seq"],
        end_seq=result["end_seq"],
        release_seq=999,
        prev_txid=result["prev_txid"],
    )
    with pytest.raises(VerificationError, match="does not match"):
        verify_journal_against_anchor(journal, forged, manifests, key.public_key())


def test_verify_without_binding_inputs_keeps_head_check_only(tmp_path):
    # Backward compat: without manifests + key, verify checks the head
    # hash only (documented) and does not re-derive the checkpoint.
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key, manifests, 4, "release-4")
    result = _anchor(journal, key, manifests)
    assert (
        verify_journal_against_anchor(
            journal, bytes.fromhex(result["payload_hex"])
        )["verified"]
        is True
    )
    with pytest.raises(VerificationError):
        verify_journal_against_anchor(
            journal, bytes.fromhex(result["payload_hex"]), manifests, None
        )


# --- CLI ---


def test_cli_anchor_payload_requires_binding_inputs_for_acceptances(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key, manifests, 2, "r-2")
    # No --manifest/--public-key: anchor fails closed.
    assert (
        main([
            "anchor-payload",
            "--journal", str(journal),
            "--start-seq", "1",
            "--output", str(tmp_path / "anchor.json"),
        ])
        == 1
    )


def test_cli_audit_accepted_hash_flag_and_anchor_verify_with_binding(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    envelope = _envelope(key, 6, "r-6")
    envelope_file = tmp_path / "envelope.json"
    envelope_file.write_text(json.dumps(envelope), encoding="utf-8")
    pub = tmp_path / "pub.pem"
    # Export this test key's public PEM directly (keygen path is covered
    # by the issue #9 CLI test).
    from cryptography.hazmat.primitives import serialization

    pub.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assert (
        main([
            "audit-manifest-accepted",
            "--journal", str(journal),
            "--release-seq", "6",
            "--release-id", "r-6",
            "--manifest-hash", manifest_hash(envelope),
        ])
        == 0
    )
    payload_file = tmp_path / "anchor.json"
    assert (
        main([
            "anchor-payload",
            "--journal", str(journal),
            "--start-seq", "1",
            "--manifest", str(envelope_file),
            "--public-key", str(pub),
            "--output", str(payload_file),
        ])
        == 0
    )
    assert (
        main([
            "anchor-verify",
            "--journal", str(journal),
            "--payload", str(payload_file),
            "--manifest", str(envelope_file),
            "--public-key", str(pub),
        ])
        == 0
    )
