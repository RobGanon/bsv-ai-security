"""Tests for the payload-binding + review fixes (PR: security/payload-binding).

Fix 1: the claimed anchor payload must equal the OP_RETURN output of the
fetched on-chain tx — a forged payload paired with a real txid must fail.
Fix 2: release_seq non-decreasing across anchors.
Fix 3: unanchored tail reported.
Fix 4: release_seq_rederived flag.
Fix 5: duplicate keys rejected in _derive_release_seq detail parsing.
Fix 6: os.write partial-write loop in append_audit_event.
Fix 7: missing-trailing-newline guard in append_audit_event.
Fix 8: DER minimal-encoding checks.
Fix 9: pubkey x >= P rejected.
Fix 10: self-verify after signing.
"""
import copy
import json

import pytest

from sealrun.anchor import (
    _derive_release_seq,
    apply_payload_binding,
    decode_anchor_payload,
    encode_anchor_payload,
    extract_anchor_op_return,
    verify_anchor_chain,
    verify_journal_against_anchor,
    verify_journal_against_anchor_chain,
)
from sealrun.bsv import (
    _P,
    _der_decode_signature,
    _pubkey_point,
    PrivKey,
    sign_digest,
    verify_sig,
)
from sealrun.cli import main
from sealrun.core import (
    VerificationError,
    _read_jsonl,
    _verify_audit_events,
    append_audit_event,
    sign_manifest,
)
from test_anchor_signature import (
    ANCHOR1_TX,
    ANCHOR_PUBKEY,
    FAUCET_TX_JSON,
    FAUCET_TX,
    TX1,
    TX2,
)

ZERO_TXID = "0" * 64


class FakeFetcher:
    """fetch_tx_full backed by a dict; optionally raises."""

    def __init__(self, by_txid=None, exc=None):
        self.by_txid = by_txid or {}
        self.exc = exc

    def fetch_tx_full(self, txid):
        if self.exc is not None:
            raise self.exc
        return self.by_txid[txid]


def _real_anchor1_payload() -> bytes:
    script = bytes.fromhex(ANCHOR1_TX["vout"][0]["scriptPubKey"]["hex"])
    assert script[:3] == bytes.fromhex("6a4c54")
    return script[3:]


def _journal_with_events(path, details):
    for detail in details:
        append_audit_event(path, "test", detail)
    return path


# --- Fix 1: OP_RETURN extraction -------------------------------------------


def test_extract_op_return_real_anchor1():
    payload = extract_anchor_op_return(ANCHOR1_TX)
    assert len(payload) == 84
    fields = decode_anchor_payload(payload)
    assert fields["start_seq"] == 1
    assert fields["end_seq"] == 3
    assert fields["release_seq"] == 0
    assert fields["prev_txid"] == ZERO_TXID


def test_extract_op_return_no_op_return():
    tx = copy.deepcopy(ANCHOR1_TX)
    tx["vout"] = [tx["vout"][1]]  # P2PKH only
    with pytest.raises(VerificationError):
        extract_anchor_op_return(tx)


def test_extract_op_return_two_op_returns():
    tx = copy.deepcopy(ANCHOR1_TX)
    tx["vout"] = [tx["vout"][0], tx["vout"][0]]
    with pytest.raises(VerificationError):
        extract_anchor_op_return(tx)


def test_extract_op_return_truncated_push():
    tx = copy.deepcopy(ANCHOR1_TX)
    # OP_RETURN + PUSHDATA1 claiming 0x54 bytes but carrying only 10.
    tx["vout"][0]["scriptPubKey"]["hex"] = "6a4c54" + "00" * 10
    with pytest.raises(VerificationError):
        extract_anchor_op_return(tx)


def test_extract_op_return_pushdata4_rejected():
    tx = copy.deepcopy(ANCHOR1_TX)
    tx["vout"][0]["scriptPubKey"]["hex"] = "6a4e54000000" + "00" * 84
    with pytest.raises(VerificationError):
        extract_anchor_op_return(tx)


def test_extract_op_return_trailing_bytes():
    tx = copy.deepcopy(ANCHOR1_TX)
    tx["vout"][0]["scriptPubKey"]["hex"] = "6a4c54" + "00" * 84 + "ff"
    with pytest.raises(VerificationError):
        extract_anchor_op_return(tx)


# --- Fix 1: binding ----------------------------------------------------------


def test_binding_passes_matching_payload():
    payload = _real_anchor1_payload()
    result = verify_anchor_chain([(payload, TX1)], ZERO_TXID)
    bound = apply_payload_binding(
        result, FakeFetcher({TX1.lower(): ANCHOR1_TX})
    )
    assert bound["payload_binding_verified"] is True
    assert bound["anchors"][0]["payload_binding_verified"] is True


def test_binding_repro_forged_payload_real_txid_fails(tmp_path):
    # The demonstrated hole: forged payload + real txid + rewritten
    # journal verifies True at the chain/journal layer...
    journal = _journal_with_events(
        tmp_path / "journal.jsonl",
        ["attacker event one", "attacker event two", "attacker event three"],
    )
    events = _read_jsonl(journal)
    forged = encode_anchor_payload(
        head_hash=events[2]["event_hash"],
        start_seq=1,
        end_seq=3,
        release_seq=0,
        prev_txid=ZERO_TXID,
    )
    chain = verify_journal_against_anchor_chain(
        journal, [(forged, TX1)], ZERO_TXID
    )
    assert chain["verified"] is True  # the hole: unbound payload verifies
    # ...but the binding check must fail: the real tx never contained it.
    bound = apply_payload_binding(
        chain, FakeFetcher({TX1.lower(): ANCHOR1_TX})
    )
    assert bound["payload_binding_verified"] is False
    assert bound["chain"]["anchors"][0]["payload_binding_verified"] is False
    assert "does not match" in bound["chain"]["anchors"][0]["payload_binding"]["reason"]


def test_binding_no_op_return_fails():
    payload = _real_anchor1_payload()
    tx = copy.deepcopy(ANCHOR1_TX)
    tx["vout"] = [tx["vout"][1]]
    result = verify_anchor_chain([(payload, TX1)], ZERO_TXID)
    bound = apply_payload_binding(result, FakeFetcher({TX1.lower(): tx}))
    assert bound["payload_binding_verified"] is False


def test_binding_fetch_failure_fails_closed():
    payload = _real_anchor1_payload()
    result = verify_anchor_chain([(payload, TX1)], ZERO_TXID)
    bound = apply_payload_binding(
        result, FakeFetcher(exc=RuntimeError("boom"))
    )
    assert bound["payload_binding_verified"] is False
    assert "fetch failed" in bound["anchors"][0]["payload_binding"]["reason"]


# --- Fix 1: CLI wiring --------------------------------------------------------


class _FakeWoC:
    def __init__(self, base_url=None):
        pass

    def fetch_tx_full(self, txid):
        if txid.lower() == TX1.lower():
            return ANCHOR1_TX
        if txid.lower() == FAUCET_TX.lower():
            return FAUCET_TX_JSON
        raise KeyError(txid)


def _write_anchor_json(path, payload_hex, txid):
    path.write_text(
        json.dumps({"payload_hex": payload_hex, "txid": txid}),
        encoding="utf-8",
    )


def test_cli_binding_failure_exits_1_and_suppresses_banners(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setattr("sealrun.cli.WoCBlockFetcher", _FakeWoC)
    journal = _journal_with_events(
        tmp_path / "journal.jsonl",
        ["attacker event one", "attacker event two", "attacker event three"],
    )
    events = _read_jsonl(journal)
    forged = encode_anchor_payload(
        head_hash=events[2]["event_hash"],
        start_seq=1,
        end_seq=3,
        release_seq=0,
        prev_txid=ZERO_TXID,
    )
    anchor_file = tmp_path / "anchor.json"
    _write_anchor_json(anchor_file, forged.hex(), TX1)
    rc = main([
        "anchor-chain-verify",
        "--anchor", str(anchor_file),
        "--journal", str(journal),
        "--genesis-txid", ZERO_TXID,
        "--anchor-sig",
        "--anchor-pubkey", ANCHOR_PUBKEY,
    ])
    out = capsys.readouterr().out
    assert rc == 1
    assert "PAYLOAD BINDING CHECK FAILED" in out
    assert "ANCHOR SIGNATURES VERIFIED" not in out


def test_cli_binding_passes_and_sig_banner_prints(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setattr("sealrun.cli.WoCBlockFetcher", _FakeWoC)
    # Chain-only path (no journal): claimed payload is the real anchor #1
    # payload, which the fetched tx's OP_RETURN equals, so binding passes
    # and the signature banner prints.
    anchor_file = tmp_path / "anchor.json"
    _write_anchor_json(anchor_file, _real_anchor1_payload().hex(), TX1)
    rc = main([
        "anchor-chain-verify",
        "--anchor", str(anchor_file),
        "--genesis-txid", ZERO_TXID,
        "--anchor-sig",
        "--anchor-pubkey", ANCHOR_PUBKEY,
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ANCHOR SIGNATURES VERIFIED" in out
    assert "PAYLOAD BINDING CHECK FAILED" not in out


def test_cli_unanchored_tail_note(tmp_path, capsys):
    journal = _journal_with_events(
        tmp_path / "journal.jsonl", ["one", "two", "three", "four"]
    )
    events = _read_jsonl(journal)
    payload = encode_anchor_payload(
        head_hash=events[2]["event_hash"],
        start_seq=1,
        end_seq=3,
        release_seq=0,
        prev_txid=ZERO_TXID,
    )
    anchor_file = tmp_path / "anchor.json"
    _write_anchor_json(anchor_file, payload.hex(), TX1)
    rc = main([
        "anchor-chain-verify",
        "--anchor", str(anchor_file),
        "--journal", str(journal),
        "--genesis-txid", ZERO_TXID,
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 journal event(s) after the last anchor are not yet anchored" in out


# --- Fix 2: release_seq monotonicity ----------------------------------------


def _chain_payload(head_byte, start, end, release_seq, prev):
    return encode_anchor_payload(
        head_hash=head_byte * 32,
        start_seq=start,
        end_seq=end,
        release_seq=release_seq,
        prev_txid=prev,
    )


def test_release_seq_decreasing_rejected():
    a1 = _chain_payload("aa", 1, 3, 5, ZERO_TXID)
    a2 = _chain_payload("bb", 4, 6, 3, TX1)
    with pytest.raises(VerificationError):
        verify_anchor_chain([(a1, TX1), (a2, TX2)], ZERO_TXID)


def test_release_seq_equal_and_increasing_accepted():
    a1 = _chain_payload("aa", 1, 3, 5, ZERO_TXID)
    a2 = _chain_payload("bb", 4, 6, 5, TX1)
    a3 = _chain_payload("cc", 7, 9, 6, TX2)
    result = verify_anchor_chain([(a1, TX1), (a2, TX2), (a3, "cc" * 32)], ZERO_TXID)
    assert result["verified"] is True


# --- Fix 3: unanchored tail ---------------------------------------------------


def test_unanchored_tail_reported(tmp_path):
    journal = _journal_with_events(
        tmp_path / "journal.jsonl", ["1", "2", "3", "4", "5"]
    )
    events = _read_jsonl(journal)
    payload = _chain_payload("aa", 1, 3, 0, ZERO_TXID)
    # Rebuild with the journal's real head at seq 3.
    payload = encode_anchor_payload(
        head_hash=events[2]["event_hash"],
        start_seq=1,
        end_seq=3,
        release_seq=0,
        prev_txid=ZERO_TXID,
    )
    result = verify_journal_against_anchor_chain(
        journal, [(payload, TX1)], ZERO_TXID
    )
    assert result["unanchored_events"] == 2


def test_unanchored_tail_zero_when_fully_anchored(tmp_path):
    journal = _journal_with_events(tmp_path / "journal.jsonl", ["1", "2", "3"])
    events = _read_jsonl(journal)
    payload = encode_anchor_payload(
        head_hash=events[2]["event_hash"],
        start_seq=1,
        end_seq=3,
        release_seq=0,
        prev_txid=ZERO_TXID,
    )
    result = verify_journal_against_anchor_chain(
        journal, [(payload, TX1)], ZERO_TXID
    )
    assert result["unanchored_events"] == 0


# --- Fix 4: release_seq_rederived flag -----------------------------------------


def test_rederived_flag_false_without_manifests(tmp_path):
    journal = _journal_with_events(tmp_path / "journal.jsonl", ["1", "2"])
    events = _read_jsonl(journal)
    payload = encode_anchor_payload(
        head_hash=events[1]["event_hash"],
        start_seq=1,
        end_seq=2,
        release_seq=0,
        prev_txid=ZERO_TXID,
    )
    result = verify_journal_against_anchor(journal, payload)
    assert result["release_seq_rederived"] is False


def test_rederived_flag_true_with_manifests(tmp_path):
    key = PrivKey.generate()
    envelope = sign_manifest(
        {
            "schema": "sealrun-manifest-v1",
            "release_id": "r",
            "release_seq": 1,
            "artifacts": [{"path": "a.txt", "sha256": "a" * 64, "size": 1}],
        },
        key,
    )
    journal = _journal_with_events(tmp_path / "journal.jsonl", ["1", "2"])
    events = _read_jsonl(journal)
    payload = encode_anchor_payload(
        head_hash=events[1]["event_hash"],
        start_seq=1,
        end_seq=2,
        release_seq=0,
        prev_txid=ZERO_TXID,
    )
    result = verify_journal_against_anchor(
        journal, payload, manifests=[envelope], public_key=key.pubkey_compressed()
    )
    assert result["release_seq_rederived"] is True


# --- Fix 5: duplicate keys in _derive_release_seq ------------------------------


def test_derive_release_seq_rejects_duplicate_keys():
    # Duplicate keys with IDENTICAL values: pre-fix this parses fine
    # (last wins) and binding succeeds; post-fix it must be rejected.
    key = PrivKey.generate()
    envelope = sign_manifest(
        {
            "schema": "sealrun-manifest-v1",
            "release_id": "r",
            "release_seq": 1,
            "artifacts": [{"path": "a.txt", "sha256": "a" * 64, "size": 1}],
        },
        key,
    )
    from sealrun.core import manifest_hash

    detail = (
        '{"release_seq": 1, "release_seq": 1, "release_id": "r", '
        '"manifest_hash": "' + manifest_hash(envelope) + '"}'
    )
    events = [
        {"seq": 1, "event_type": "manifest_accepted", "detail": detail}
    ]
    with pytest.raises(VerificationError):
        _derive_release_seq(
            events, 1, manifests=[envelope], public_key=key.pubkey_compressed()
        )


# --- Fix 6: partial-write loop ---------------------------------------------------


def test_append_survives_short_writes(tmp_path, monkeypatch):
    import os

    journal = tmp_path / "journal.jsonl"
    real_write = os.write
    calls = {"n": 0}

    def short_write(fd, data):
        calls["n"] += 1
        if calls["n"] <= 2:
            return real_write(fd, data[:1])
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", short_write)
    event = append_audit_event(journal, "test", "hello")
    assert event["seq"] == 1
    assert calls["n"] > 2
    events = _read_jsonl(journal)
    _verify_audit_events(events)
    assert events[0]["detail"] == "hello"


# --- Fix 7: missing-newline guard ------------------------------------------------


def test_append_refuses_journal_missing_trailing_newline(tmp_path):
    journal = _journal_with_events(tmp_path / "journal.jsonl", ["one", "two"])
    raw = journal.read_bytes()
    assert raw.endswith(b"\n")
    journal.write_bytes(raw[:-1])  # strip only the terminator
    # Content is intact: verification still succeeds.
    events = _read_jsonl(journal)
    _verify_audit_events(events)
    with pytest.raises(VerificationError):
        append_audit_event(journal, "test", "three")


# --- Fix 8: DER minimal encoding --------------------------------------------------


def _der_int(raw: bytes) -> bytes:
    return b"\x02" + bytes([len(raw)]) + raw


def _der_sig(r_raw: bytes, s_raw: bytes) -> bytes:
    body = _der_int(r_raw) + _der_int(s_raw)
    return b"\x30" + bytes([len(body)]) + body


def _minimal_int_bytes(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return raw


def _valid_sig_parts():
    from sealrun.bsv import PrivKey

    key = PrivKey.from_bytes(bytes(range(1, 33)))
    digest = bytes(range(32))
    der = sign_digest(key, digest)
    r, s = _der_decode_signature(der)
    return key, digest, der, r, s


def test_der_nonminimal_r_rejected():
    key, digest, _, r, s = _valid_sig_parts()
    r_raw = _minimal_int_bytes(r)
    if r_raw[0] & 0x80:
        pytest.skip("r has high bit set; covered by negative test")
    crafted = _der_sig(b"\x00" + r_raw, _minimal_int_bytes(s))
    with pytest.raises(ValueError):
        _der_decode_signature(crafted)
    assert verify_sig(key.pubkey_compressed(), digest, crafted) is False


def test_der_negative_r_rejected():
    # Find a signature whose r has the high bit set.
    from sealrun.bsv import PrivKey

    base_key = PrivKey.from_bytes(bytes(range(1, 33)))
    found = None
    for i in range(64):
        digest = bytes([i]) * 32
        der = sign_digest(base_key, digest)
        r, s = _der_decode_signature(der)
        if r.to_bytes((r.bit_length() + 7) // 8, "big")[0] & 0x80:
            found = (digest, r, s)
            break
    assert found is not None
    digest, r, s = found
    r_raw = r.to_bytes((r.bit_length() + 7) // 8, "big")  # high bit set, no pad
    crafted = _der_sig(r_raw, _minimal_int_bytes(s))
    with pytest.raises(ValueError):
        _der_decode_signature(crafted)
    assert verify_sig(base_key.pubkey_compressed(), digest, crafted) is False


def test_der_nonminimal_s_rejected():
    key, digest, _, r, s = _valid_sig_parts()
    s_raw = _minimal_int_bytes(s)
    if s_raw[0] & 0x80:
        pytest.skip("s has high bit set; minimal form already has the pad")
    crafted = _der_sig(_minimal_int_bytes(r), b"\x00" + s_raw)
    with pytest.raises(ValueError):
        _der_decode_signature(crafted)
    assert verify_sig(key.pubkey_compressed(), digest, crafted) is False


def test_der_zero_length_rejected():
    _, _, _, r, s = _valid_sig_parts()
    crafted = _der_sig(b"", _minimal_int_bytes(s))
    with pytest.raises(ValueError):
        _der_decode_signature(crafted)


def test_der_minimal_high_bit_still_accepted():
    # A leading 0x00 before a high-bit-set integer IS minimal and must pass.
    from sealrun.bsv import PrivKey

    base_key = PrivKey.from_bytes(bytes(range(1, 33)))
    for i in range(64):
        digest = bytes([i]) * 32
        der = sign_digest(base_key, digest)
        r, s = _der_decode_signature(der)
        if r.to_bytes((r.bit_length() + 7) // 8, "big")[0] & 0x80:
            assert verify_sig(base_key.pubkey_compressed(), digest, der) is True
            return
    pytest.skip("no high-bit r found in 64 tries")


# --- Fix 9: pubkey x >= P ---------------------------------------------------------


def test_pubkey_x_at_or_above_p_rejected():
    # x == P is already rejected (7 is not a QR), so use x = P + v where
    # v is small and v^3 + 7 IS a quadratic residue: pre-fix this
    # decompresses to the (v, y) point and is accepted; post-fix the
    # range check rejects it.
    v = None
    for candidate in range(1, 10000):
        y_sq = (pow(candidate, 3, _P) + 7) % _P
        if pow(y_sq, (_P - 1) // 2, _P) == 1:
            v = candidate
            break
    assert v is not None
    y_sq = (pow(v, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    assert (y * y - y_sq) % _P == 0
    x_bad = _P + v
    assert x_bad < 2**256  # fits in a 33-byte compressed pubkey
    pubkey = bytes([0x02 if y % 2 == 0 else 0x03]) + x_bad.to_bytes(32, "big")
    with pytest.raises(ValueError):
        _pubkey_point(pubkey)
    _, _, der, _, _ = _valid_sig_parts()
    assert verify_sig(pubkey, bytes(range(32)), der) is False


# --- Fix 10: self-verify after signing ----------------------------------------------


def test_sign_digest_self_verify_failure_raises(monkeypatch):
    from sealrun.bsv import PrivKey
    import sealrun.bsv as bsv_mod

    monkeypatch.setattr(bsv_mod, "verify_sig", lambda *a: False)
    key = PrivKey.from_bytes(bytes(range(1, 33)))
    with pytest.raises(ValueError):
        sign_digest(key, bytes(range(32)))


def test_sign_digest_produces_verifiable_signature():
    from sealrun.bsv import PrivKey

    key = PrivKey.from_bytes(bytes(range(1, 33)))
    digest = bytes(range(32))
    der = sign_digest(key, digest)
    assert verify_sig(key.pubkey_compressed(), digest, der) is True
