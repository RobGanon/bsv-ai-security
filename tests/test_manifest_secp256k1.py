"""Manifest signing on secp256k1 (schema v2): migration hazards.

Manifest signing moved from Ed25519 to the same RFC 6979 ECDSA used for
anchor inputs, so the whole system has one signature scheme and one
audit surface. The keys stay distinct (release approval vs. history
attestation). These tests pin the migration-specific fail-closed rules:

* ECDSA is malleable — (r, s) and (r, N - s) are both valid — and the
  manifest hash covers the signature bytes, so verification pins the
  canonical low-S form. Without that, one payload would hash as two
  "exact signed manifests".
* Legacy schema-v1 (Ed25519) envelopes fail closed.
* Key files are plain text (WIF private / compressed-hex public) and
  every malformed shape is rejected at load time, loudly.
"""

import base64
import hashlib

import pytest

from aiguard.bsv import (
    _N,
    _P,
    _der_decode_signature,
    _der_encode_signature,
    base58check_encode,
    PrivKey,
    sign_digest,
    verify_sig,
)
from aiguard.core import (
    MANIFEST_SCHEMA,
    VerificationError,
    canonical_json_bytes,
    generate_keypair,
    load_private_key,
    load_public_key,
    manifest_hash,
    sign_manifest,
    verify_manifest,
)


def setup_artifacts(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "model.bin").write_bytes(b"model-v1")
    return root


def make_payload(release_seq=1):
    return {
        "schema": MANIFEST_SCHEMA,
        "release_id": "r1",
        "release_seq": release_seq,
        "artifacts": [{"path": "model.bin", "sha256": "a" * 64, "size": 7}],
    }


# --- low-S pinning (ECDSA malleability) --------------------------------------


def test_sign_manifest_produces_low_s_canonical_signature():
    private = PrivKey.generate()
    envelope = sign_manifest(make_payload(), private)
    r, s = _der_decode_signature(base64.b64decode(envelope["signature"]))
    assert s <= _N // 2  # the signer emits the canonical low-S form


def test_high_s_malleated_envelope_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private = PrivKey.generate()
    payload = make_payload()
    envelope = sign_manifest(payload, private)
    r, s = _der_decode_signature(base64.b64decode(envelope["signature"]))
    malleated = _der_encode_signature(r, _N - s)
    digest = hashlib.sha256(canonical_json_bytes(payload)).digest()

    # The malleated form IS a valid ECDSA signature — that is the
    # malleability — so only the explicit low-S policy stops it.
    assert verify_sig(private.pubkey_compressed(), digest, malleated) is True
    assert (
        verify_sig(private.pubkey_compressed(), digest, malleated,
                   require_low_s=True)
        is False
    )

    bad_envelope = {
        "payload": payload,
        "signature": base64.b64encode(malleated).decode("ascii"),
    }
    # Without pinning, one payload would hash as two "exact" manifests;
    # verification rejects the high-S spelling instead.
    assert manifest_hash(bad_envelope) != manifest_hash(envelope)
    with pytest.raises(VerificationError, match="signature invalid"):
        verify_manifest(root, bad_envelope, private.pubkey_compressed())


def test_on_chain_input_verification_still_accepts_high_s():
    # Consensus compatibility: anchor input signatures are checked as
    # any valid on-chain signature (the chain permits high-S), so the
    # low-S pin stays a manifest-envelope rule, not a chain rule.
    private = PrivKey.generate()
    digest = hashlib.sha256(b"anchor input").digest()
    r, s = _der_decode_signature(sign_digest(private, digest))
    high_s = _der_encode_signature(r, _N - s)
    assert verify_sig(private.pubkey_compressed(), digest, high_s) is True


# --- schema versioning --------------------------------------------------------


def test_legacy_v1_envelope_rejected(tmp_path):
    root = setup_artifacts(tmp_path)
    private = PrivKey.generate()
    legacy_payload = {**make_payload(), "schema": "aiguard-manifest-v1"}
    envelope = sign_manifest(legacy_payload, private)  # perfectly signed
    with pytest.raises(VerificationError, match="unsupported manifest schema"):
        verify_manifest(root, envelope, private.pubkey_compressed())


# --- sign/verify round-trip determinism ---------------------------------------


def test_sign_manifest_is_deterministic():
    # Acceptance binding relies on re-signing identically (RFC 6979).
    private = PrivKey.from_bytes(b"\x11" * 32)
    payload = make_payload()
    assert sign_manifest(payload, private) == sign_manifest(payload, private)


# --- private key files ---------------------------------------------------------


def test_keygen_writes_loadable_wif_and_hex_pair(tmp_path):
    priv_path = tmp_path / "priv.wif"
    pub_path = tmp_path / "pub.pub"
    generate_keypair(priv_path, pub_path)

    private = load_private_key(priv_path)
    public = load_public_key(pub_path)
    # The two files are one keypair, and the WIF round-trips.
    assert public == private.pubkey_compressed()
    reloaded = PrivKey.from_wif_any(priv_path.read_text().strip())
    assert reloaded.secret == private.secret
    # Both files are single-line text.
    assert priv_path.read_text().endswith("\n")
    assert pub_path.read_text().endswith("\n")


@pytest.mark.parametrize("content", [
    "not a key at all",
    "5HueCGU8rMjxEXxiPuD5BDuYvDQFA9xHJPzBDe"[:-4] + "XXXX",  # bad checksum
    "00" * 32,  # raw hex private key (not WIF)
    "64" * 32,  # raw hex private key with whitespace (not WIF)
    "",
])
def test_load_private_key_rejects_non_wif(tmp_path, content):
    key_path = tmp_path / "priv.wif"
    key_path.write_text(content, encoding="ascii")
    key_path.chmod(0o600)
    with pytest.raises(VerificationError, match="not valid WIF"):
        load_private_key(key_path)


def test_load_private_key_rejects_zero_secret_wif(tmp_path):
    # Structurally valid WIF whose secret is out of range fails closed.
    wif = base58check_encode(0xEF, (0).to_bytes(32, "big") + b"\x01")
    key_path = tmp_path / "priv.wif"
    key_path.write_text(wif, encoding="ascii")
    key_path.chmod(0o600)
    with pytest.raises(VerificationError, match="not valid WIF"):
        load_private_key(key_path)


def test_load_private_key_accepts_mainnet_wif(tmp_path):
    # Manifest keys are not chain keys: either network's WIF loads.
    wif = PrivKey.generate().wif(network="mainnet")
    key_path = tmp_path / "priv.wif"
    key_path.write_text(wif, encoding="ascii")
    key_path.chmod(0o600)
    assert load_private_key(key_path).wif(network="mainnet") == wif


# --- public key files ----------------------------------------------------------


def test_load_public_key_accepts_uppercase_hex(tmp_path):
    private = PrivKey.generate()
    pub_path = tmp_path / "pub.pub"
    pub_path.write_text(private.pubkey_compressed().hex().upper(), encoding="ascii")
    assert load_public_key(pub_path) == private.pubkey_compressed()


@pytest.mark.parametrize("content,match", [
    ("02" + "zz" * 32, "66 hex"),        # non-hex characters
    ("02" + "ab" * 31, "66 hex"),        # short
    ("02" + "ab" * 33, "66 hex"),        # long
    ("", "66 hex"),
    ("04" + "ab" * 32, "not a valid"),    # uncompressed prefix
    ("02" + "ff" * 32, "not a valid"),   # x >= field prime P
])
def test_load_public_key_rejects_malformed(tmp_path, content, match):
    pub_path = tmp_path / "pub.pub"
    pub_path.write_text(content, encoding="ascii")
    with pytest.raises(VerificationError, match=match):
        load_public_key(pub_path)


def test_load_public_key_rejects_point_not_on_curve(tmp_path):
    # Find an x whose curve equation has no solution (quadratic non-residue).
    for x in range(1, 100):
        y_sq = (pow(x, 3, _P) + 7) % _P
        if y_sq and pow(y_sq, (_P - 1) // 2, _P) != 1:
            pub_path = tmp_path / "pub.pub"
            pub_path.write_text(
                "02" + x.to_bytes(32, "big").hex(), encoding="ascii"
            )
            with pytest.raises(VerificationError, match="not a valid"):
                load_public_key(pub_path)
            return
    raise AssertionError("no non-residue x found in range")


def test_sign_and_verify_through_loaded_key_files(tmp_path):
    # End-to-end: keygen files -> load -> sign -> verify.
    root = setup_artifacts(tmp_path)
    priv_path = tmp_path / "priv.wif"
    pub_path = tmp_path / "pub.pub"
    generate_keypair(priv_path, pub_path)

    payload = {
        "schema": MANIFEST_SCHEMA,
        "release_id": "r-1",
        "release_seq": 1,
        "artifacts": [{"path": "model.bin", "sha256": "b" * 64, "size": 7}],
    }
    envelope = sign_manifest(payload, load_private_key(priv_path))
    # Tamper with the payload after signing: rejected.
    with pytest.raises(VerificationError, match="signature invalid"):
        verify_manifest(
            root, {**envelope, "payload": {**payload, "release_id": "r-2"}},
            load_public_key(pub_path),
        )
