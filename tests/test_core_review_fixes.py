"""Regression tests for the core.py review fixes (PR: security/core-review-fixes).

Fix 1: manifest_hash canonicalizes the base64 signature spelling.
Fix 2: release_seq is capped at uint32 on the manifest side too.
Fix 3: _open_verified_fd does not hang on a FIFO.
Fix 4: verified_artifacts closes the fd when lseek/fdopen fails.
Fix 5: load_private_key refuses group/world-readable key files.
Fix 6: duplicate JSON keys are rejected in trust-critical parse paths.
"""

import base64
import hashlib
import json
import os
import string
import threading
from pathlib import Path

import pytest
from sealrun.bsv import PrivKey

from sealrun.cli import _read_json
from sealrun.core import (
    VerificationError,
    _open_verified_fd,
    canonical_json_bytes,
    create_manifest,
    generate_keypair,
    load_private_key,
    manifest_hash,
    sha256_file,
    sign_manifest,
    verify_audit_journal,
    verify_manifest,
    verified_artifacts,
)

_B64_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"


def _respelled_signature(canonical: str) -> str:
    """Return a different base64 spelling of the same signature bytes.

    Base64's spare zero bits live in the final data character whenever
    the string ends in ``=`` padding: with ``==`` the last char carries
    2 data bits, with ``=`` it carries 4. Flipping a low bit yields a
    different spelling that decodes to identical bytes. (A DER signature
    whose length is a multiple of 3 has no padding and no spare bits;
    the test below picks a release_seq whose signature does.)
    """
    assert canonical.endswith("=")
    last_data = len(canonical) - 1
    while canonical[last_data] == "=":
        last_data -= 1
    idx = _B64_ALPHABET.index(canonical[last_data])
    return canonical[:last_data] + _B64_ALPHABET[idx ^ 1] + canonical[last_data + 1:]


def test_manifest_hash_canonicalizes_signature_spelling():
    # Fixed key + RFC 6979 make the signature deterministic, so this
    # test's spelling is stable run to run. ECDSA DER signatures are
    # 70-72 bytes and only some lengths leave base64 padding bits, so
    # try a few release_seqs until one does.
    private = PrivKey.from_bytes(b"\x11" * 32)
    for release_seq in (1, 2, 3, 4):
        payload = {
            "schema": "sealrun-manifest-v1",
            "release_id": "r1",
            "release_seq": release_seq,
            "artifacts": [],
        }
        envelope = sign_manifest(payload, private)
        if envelope["signature"].endswith("="):
            break
    else:
        raise AssertionError("no signature with base64 padding in four attempts")
    respelled = _respelled_signature(envelope["signature"])
    assert respelled != envelope["signature"]
    assert base64.b64decode(respelled, validate=True) == base64.b64decode(
        envelope["signature"], validate=True
    )
    alt_envelope = {"payload": payload, "signature": respelled}
    assert manifest_hash(alt_envelope) == manifest_hash(envelope)


def test_manifest_hash_rejects_invalid_base64_signature():
    with pytest.raises(VerificationError):
        manifest_hash({"payload": {}, "signature": "!!!not-base64!!!"})
    with pytest.raises(VerificationError):
        manifest_hash({"payload": {}, "signature": 12345})


def test_create_manifest_rejects_huge_release_seq(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"x")
    with pytest.raises(VerificationError):
        create_manifest(root, ["a.txt"], "r1", 2**32)


def test_verify_manifest_rejects_huge_release_seq(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"x")
    digest, size = sha256_file(root / "a.txt")
    private = PrivKey.generate()
    payload = {
        "schema": "sealrun-manifest-v1",
        "release_id": "r1",
        "release_seq": 2**32,
        "artifacts": [{"path": "a.txt", "sha256": digest, "size": size}],
    }
    envelope = sign_manifest(payload, private)
    with pytest.raises(VerificationError):
        verify_manifest(root, envelope, private.pubkey_compressed())


def test_open_verified_fd_fifo_does_not_hang(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    result: dict = {}

    def target():
        try:
            _open_verified_fd(fifo)
            result["outcome"] = "returned"
        except VerificationError:
            result["outcome"] = "rejected"
        except Exception as exc:  # noqa: BLE001 - record unexpected failures
            result["outcome"] = f"other: {exc!r}"

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive(), "open on FIFO blocked (hang)"
    assert result.get("outcome") == "rejected"


def test_verified_artifacts_lseek_failure_closes_fd(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"x")
    digest, size = sha256_file(root / "a.txt")
    private = PrivKey.generate()
    payload = {
        "schema": "sealrun-manifest-v1",
        "release_id": "r1",
        "release_seq": 1,
        "artifacts": [{"path": "a.txt", "sha256": digest, "size": size}],
    }
    envelope = sign_manifest(payload, private)
    fds_before = len(os.listdir("/proc/self/fd"))

    def bad_lseek(fd, *args, **kwargs):
        raise OSError("boom")

    monkeypatch.setattr(os, "lseek", bad_lseek)
    with pytest.raises(VerificationError):
        with verified_artifacts(root, envelope, private.pubkey_compressed()):
            pass
    assert len(os.listdir("/proc/self/fd")) == fds_before


@pytest.mark.parametrize("mode", [0o644, 0o640])
def test_load_private_key_refuses_loose_permissions(tmp_path, mode):
    priv_path = tmp_path / "priv.wif"
    pub_path = tmp_path / "pub.pub"
    generate_keypair(priv_path, pub_path)
    os.chmod(priv_path, mode)
    with pytest.raises(VerificationError):
        load_private_key(priv_path)


def test_load_private_key_accepts_0600(tmp_path):
    priv_path = tmp_path / "priv.wif"
    pub_path = tmp_path / "pub.pub"
    generate_keypair(priv_path, pub_path)
    os.chmod(priv_path, 0o600)
    assert load_private_key(priv_path) is not None


def test_load_private_key_refuses_symlink(tmp_path):
    """Regression (outside review, 2026-10-20): no stat-then-read window.

    The loader opens the key once with O_NOFOLLOW and fstat()s that
    descriptor, so a symlink in place of the key file is refused
    outright instead of being checked at one path and read at another.
    """
    priv_path = tmp_path / "priv.wif"
    pub_path = tmp_path / "pub.pub"
    generate_keypair(priv_path, pub_path)
    os.chmod(priv_path, 0o600)
    link = tmp_path / "linked.wif"
    link.symlink_to(priv_path)
    with pytest.raises(VerificationError):
        load_private_key(link)


def test_journal_duplicate_keys_rejected(tmp_path):
    body = {
        "seq": 1,
        "event_type": "test",
        "detail": "x",
        "previous_hash": "0" * 64,
    }
    event_hash = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    # Duplicate "seq" key: last-wins parsing yields the same dict the
    # event_hash was computed over, so only duplicate rejection fails it.
    line = (
        '{"seq": 1, "seq": 1, "event_type": "test", "detail": "x", '
        f'"previous_hash": "{"0" * 64}", "event_hash": "{event_hash}"}}\n'
    )
    journal = tmp_path / "audit.jsonl"
    journal.write_text(line, encoding="utf-8")
    with pytest.raises(VerificationError):
        verify_audit_journal(journal)


def test_manifest_file_duplicate_keys_rejected(tmp_path):
    path = tmp_path / "m.json"
    path.write_text('{"payload": {}, "payload": {}}', encoding="utf-8")
    with pytest.raises(VerificationError):
        _read_json(path)


def test_json_without_duplicates_still_parses(tmp_path):
    path = tmp_path / "ok.json"
    path.write_text('{"payload": {"a": 1}}', encoding="utf-8")
    assert _read_json(path) == {"payload": {"a": 1}}
