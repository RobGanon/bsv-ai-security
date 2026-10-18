"""Tests for anchor input signature verification (protocol §6, step 1).

Fixtures: the real live anchor #1 transaction (Teratestnet, fetched
from WoC-TTN 2026-10-16) spending the faucet payout, plus the faucet
tx's spent output. The anchor pubkey below is public on-chain data
(it appears in anchor #1's scriptSig).
"""
import copy
import json

import pytest

from aiguard.anchor import (
    AnchorSignatureVerifier,
    _tx_from_woc_json,
    apply_anchor_signatures,
    encode_anchor_payload,
    parse_p2pkh_script_sig,
    verify_anchor_chain,
    verify_anchor_tx_signature,
)
from aiguard.core import VerificationError
from aiguard.spv import SPVUnavailable

ANCHOR_PUBKEY = "0397315d0180c5f4cf1ea2cd19d683becdb4a978827ab6d8c6cb74b18df29eb58d"
TX1 = "4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029"
TX2 = "d8407bb7a60f23aadcf021e9cb0098c6ae362a519aa04cbd8536265519c09230"
FAUCET_TX = "2aa2442b25ecd79bcaf6b2ce025fd179f1e72aef90213a6e3c2516e6188aae7a"

ANCHOR1_TX = {
    "version": 1,
    "locktime": 0,
    "vin": [
        {
            "txid": FAUCET_TX,
            "vout": 0,
            "scriptSig": {
                "hex": "47304402200140f503848c4679ddc8f2302afe5530a74fdf16f96ccce23614d89c8a388d630220472178eae8005c1ddd52815b970c2b0dd9df105b382b2d90a2391645f013fcd6"
                       "41210397315d0180c5f4cf1ea2cd19d683becdb4a978827ab6d8c6cb74b18df29eb58d"
            },
            "sequence": 4294967295,
        }
    ],
    "vout": [
        {
            "value": 0,
            "scriptPubKey": {
                "hex": "6a4c54414947554152443133b68172be75577a2a7b16a433bfb5b38c7b8b8818b79f3a34408a68c3e769ca0000000100000003000000000000000000000000000000000000000000000000000000000000000000000000"
            },
        },
        {
            "value": 0.000995,
            "scriptPubKey": {
                "hex": "76a9142e640e26bcb812790c2517d49d660c44e1b3ae6c88ac"
            },
        },
    ],
}

FAUCET_TX_JSON = {
    "version": 1,
    "locktime": 0,
    "vin": [],
    "vout": [
        {
            "value": 0.001,
            "scriptPubKey": {
                "hex": "76a9142e640e26bcb812790c2517d49d660c44e1b3ae6c88ac"
            },
        },
        {
            "value": 0.03057933,
            "scriptPubKey": {
                "hex": "76a914894cca9faa0e1bb08830c8c9b4e27c8f4a68ba2f88ac"
            },
        },
    ],
}


# --- scriptSig parsing -----------------------------------------------------


def test_parse_p2pkh_script_sig_real_input():
    der, sighash, pubkey = parse_p2pkh_script_sig(
        bytes.fromhex(ANCHOR1_TX["vin"][0]["scriptSig"]["hex"])
    )
    assert sighash == 0x41
    assert pubkey.hex() == ANCHOR_PUBKEY
    assert der.hex().startswith("3044")


def test_parse_p2pkh_script_sig_rejects_malformed():
    for bad in (b"", b"\x00", b"\x01\x02", b"\x47" + b"\x00" * 70,
                b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" + b"\x00" * 32 + b"\x00"):
        with pytest.raises(Exception):
            parse_p2pkh_script_sig(bad)


# --- pure signature check --------------------------------------------------


def test_real_anchor1_input_verifies():
    result = verify_anchor_tx_signature(ANCHOR1_TX, FAUCET_TX_JSON, ANCHOR_PUBKEY)
    assert result["verified"] is True
    assert result["pubkey"] == ANCHOR_PUBKEY


def test_wrong_trusted_pubkey_rejected():
    other = "02" + "00" * 32
    result = verify_anchor_tx_signature(ANCHOR1_TX, FAUCET_TX_JSON, other)
    assert result["verified"] is False
    assert "pubkey" in result["reason"]


def test_tampered_signature_rejected():
    tx = copy.deepcopy(ANCHOR1_TX)
    sig_hex = tx["vin"][0]["scriptSig"]["hex"]
    # Flip a byte inside the DER signature (R value), not the push lengths.
    tampered = sig_hex[:12] + ("00" if sig_hex[12:14] != "00" else "ff") + sig_hex[14:]
    tx["vin"][0]["scriptSig"]["hex"] = tampered
    assert tampered != sig_hex
    result = verify_anchor_tx_signature(tx, FAUCET_TX_JSON, ANCHOR_PUBKEY)
    assert result["verified"] is False
    assert "signature" in result["reason"]


def test_tampered_payload_rejected():
    tx = copy.deepcopy(ANCHOR1_TX)
    script = tx["vout"][0]["scriptPubKey"]["hex"]
    tx["vout"][0]["scriptPubKey"]["hex"] = script[:-2] + ("00" if script[-2:] != "00" else "ff")
    result = verify_anchor_tx_signature(tx, FAUCET_TX_JSON, ANCHOR_PUBKEY)
    assert result["verified"] is False
    assert "signature" in result["reason"]


def test_tampered_prev_output_script_rejected():
    prev = copy.deepcopy(FAUCET_TX_JSON)
    script = prev["vout"][0]["scriptPubKey"]["hex"]
    prev["vout"][0]["scriptPubKey"]["hex"] = script[:-2] + ("00" if script[-2:] != "00" else "ff")
    result = verify_anchor_tx_signature(ANCHOR1_TX, prev, ANCHOR_PUBKEY)
    assert result["verified"] is False
    assert "P2PKH" in result["reason"]


def test_tampered_prev_value_rejected():
    prev = copy.deepcopy(FAUCET_TX_JSON)
    prev["vout"][0]["value"] = 0.002
    result = verify_anchor_tx_signature(ANCHOR1_TX, prev, ANCHOR_PUBKEY)
    assert result["verified"] is False
    assert "signature" in result["reason"]


def test_wrong_sighash_byte_rejected():
    tx = copy.deepcopy(ANCHOR1_TX)
    sig_hex = tx["vin"][0]["scriptSig"]["hex"]
    # scriptSig layout: 0x47 <71-byte push: DER + sighash> 0x21 <pubkey>.
    # The sighash byte is the last byte of the first push, at offset 1+71.
    assert sig_hex[2 + 71 * 2 - 2 : 2 + 71 * 2] == "41"
    tampered = sig_hex[: 2 + 71 * 2 - 2] + "01" + sig_hex[2 + 71 * 2 :]
    tx["vin"][0]["scriptSig"]["hex"] = tampered
    result = verify_anchor_tx_signature(tx, FAUCET_TX_JSON, ANCHOR_PUBKEY)
    assert result["verified"] is False
    assert "sighash" in result["reason"]


def test_two_inputs_rejected():
    tx = copy.deepcopy(ANCHOR1_TX)
    tx["vin"].append(copy.deepcopy(tx["vin"][0]))
    result = verify_anchor_tx_signature(tx, FAUCET_TX_JSON, ANCHOR_PUBKEY)
    assert result["verified"] is False
    assert "exactly 1 input" in result["reason"]


def test_empty_script_sig_rejected():
    tx = copy.deepcopy(ANCHOR1_TX)
    tx["vin"][0]["scriptSig"]["hex"] = ""
    result = verify_anchor_tx_signature(tx, FAUCET_TX_JSON, ANCHOR_PUBKEY)
    assert result["verified"] is False


def test_malformed_trusted_pubkey_rejected():
    for bad in ("", "02" + "00" * 31, "04" + "00" * 32, "zz" * 33, None):
        result = verify_anchor_tx_signature(ANCHOR1_TX, FAUCET_TX_JSON, bad)
        assert result["verified"] is False


def test_prev_tx_missing_output_rejected():
    prev = copy.deepcopy(FAUCET_TX_JSON)
    prev["vout"] = prev["vout"][1:]
    # Anchor spends vout 0; with only one output left at index 0 the
    # script belongs to a different address, so the check must fail.
    result = verify_anchor_tx_signature(ANCHOR1_TX, prev, ANCHOR_PUBKEY)
    assert result["verified"] is False


# --- verifier + apply ------------------------------------------------------


class FakeTxFetcher:
    def __init__(self, *, fail_on=()):
        self.fail_on = set(fail_on)

    def fetch_tx_full(self, txid):
        if txid in self.fail_on:
            raise SPVUnavailable("boom")
        if txid == TX1:
            return copy.deepcopy(ANCHOR1_TX)
        if txid == FAUCET_TX:
            return copy.deepcopy(FAUCET_TX_JSON)
        raise SPVUnavailable(f"unknown txid {txid}")


def test_verifier_accepts_real_anchor1():
    result = AnchorSignatureVerifier(FakeTxFetcher(), ANCHOR_PUBKEY).verify_signature(TX1)
    assert result.verified is True
    assert result.pubkey == ANCHOR_PUBKEY


def test_verifier_fails_closed_fetch_error():
    result = AnchorSignatureVerifier(
        FakeTxFetcher(fail_on={TX1}), ANCHOR_PUBKEY
    ).verify_signature(TX1)
    assert result.verified is False
    assert "fetch failed" in result.reason


def test_verifier_fails_closed_prev_fetch_error():
    result = AnchorSignatureVerifier(
        FakeTxFetcher(fail_on={FAUCET_TX}), ANCHOR_PUBKEY
    ).verify_signature(TX1)
    assert result.verified is False
    assert "fetch failed" in result.reason


def test_verifier_rejects_wrong_pubkey():
    result = AnchorSignatureVerifier(
        FakeTxFetcher(), "02" + "00" * 32
    ).verify_signature(TX1)
    assert result.verified is False


def _two_anchor_chain():
    genesis = "0" * 64
    anchors = [
        {
            "payload_hex": encode_anchor_payload(
                head_hash="11" * 32, start_seq=1, end_seq=3,
                release_seq=0, prev_txid=genesis,
            ).hex(),
            "txid": TX1,
        },
        {
            "payload_hex": encode_anchor_payload(
                head_hash="22" * 32, start_seq=4, end_seq=4,
                release_seq=0, prev_txid=TX1,
            ).hex(),
            "txid": TX2,
        },
    ]
    return verify_anchor_chain(anchors, genesis)


def test_apply_anchor_signatures_plain_shape():
    verifier = AnchorSignatureVerifier(FakeTxFetcher(), ANCHOR_PUBKEY)
    result = apply_anchor_signatures(_two_anchor_chain(), verifier)
    # TX1 verifies; TX2 is unknown to the fake fetcher -> fails closed.
    assert result["anchor_signatures_verified"] is False
    assert result["anchors"][0]["anchor_signature_verified"] is True
    assert result["anchors"][1]["anchor_signature_verified"] is False


def test_apply_anchor_signatures_journal_shape():
    chain = _two_anchor_chain()
    journal_shaped = {
        "verified": True,
        "chain": chain,
        "anchors": [{"verified": True}],
        "chain_inclusion_verified": False,
    }
    verifier = AnchorSignatureVerifier(FakeTxFetcher(), ANCHOR_PUBKEY)
    result = apply_anchor_signatures(journal_shaped, verifier)
    assert result["anchor_signatures_verified"] is False
    assert result["chain"]["anchors"][0]["anchor_signature_verified"] is True


# --- CLI -------------------------------------------------------------------


def test_cli_anchor_sig_verifies_and_prints_line(tmp_path, capsys, monkeypatch):
    from aiguard import cli as cli_module

    class FakeWoC:
        def __init__(self, base_url=None):
            self.inner = FakeTxFetcher()

        def fetch_tx_full(self, txid):
            return self.inner.fetch_tx_full(txid)

    monkeypatch.setattr(cli_module, "WoCBlockFetcher", FakeWoC)
    anchor1 = tmp_path / "a1.json"
    genesis = "0" * 64
    anchor1.write_text(json.dumps({
        "payload_hex": encode_anchor_payload(
            head_hash="11" * 32, start_seq=1, end_seq=3,
            release_seq=0, prev_txid=genesis,
        ).hex(),
        "txid": TX1,
    }))
    cli_module.main([
        "anchor-chain-verify", "--genesis-txid", genesis,
        "--anchor", str(anchor1),
        "--anchor-sig", "--anchor-pubkey", ANCHOR_PUBKEY,
    ])
    out = capsys.readouterr().out
    assert "ANCHOR SIGNATURES VERIFIED: 1 anchor(s)" in out
    assert '"anchor_signature_verified": true' in out


def test_cli_anchor_sig_without_pubkey_is_rejected(tmp_path, capsys):
    from aiguard import cli as cli_module

    anchor1 = tmp_path / "a1.json"
    genesis = "0" * 64
    anchor1.write_text(json.dumps({
        "payload_hex": encode_anchor_payload(
            head_hash="11" * 32, start_seq=1, end_seq=3,
            release_seq=0, prev_txid=genesis,
        ).hex(),
        "txid": TX1,
    }))
    assert cli_module.main([
        "anchor-chain-verify", "--genesis-txid", genesis,
        "--anchor", str(anchor1), "--anchor-sig",
    ]) == 1
    assert "ERROR" in capsys.readouterr().err


# --- txid consistency (independent review finding, TruthMachine) -----------


class MismatchedTxFetcher:
    """Returns anchor #1 no matter which txid was requested."""

    def fetch_tx_full(self, txid):
        if txid == FAUCET_TX:
            return copy.deepcopy(FAUCET_TX_JSON)
        return copy.deepcopy(ANCHOR1_TX)


def test_verifier_rejects_transaction_with_mismatched_requested_txid():
    result = AnchorSignatureVerifier(
        MismatchedTxFetcher(), ANCHOR_PUBKEY
    ).verify_signature("00" * 32)
    assert result.verified is False
    assert "does not match requested txid" in result.reason


# --- exact satoshi parsing (independent review hardening) ------------------


def _tx_json_with_values(values):
    return {
        "version": 1,
        "locktime": 0,
        "vin": [],
        "vout": [
            {"value": value, "scriptPubKey": {"hex": "00"}}
            for value in values
        ],
    }


def test_tx_from_woc_json_parses_decimal_values_exactly():
    tx = _tx_from_woc_json(
        _tx_json_with_values([0, 0.000995, 0.001, 0.03057933, 1])
    )
    assert [out.value for out in tx.outputs] == [0, 99500, 100000, 3057933, 100000000]


def test_tx_from_woc_json_rejects_sub_satoshi_value():
    with pytest.raises(VerificationError):
        _tx_from_woc_json(_tx_json_with_values([0.000000001]))


def test_tx_from_woc_json_rejects_negative_value():
    with pytest.raises(VerificationError):
        _tx_from_woc_json(_tx_json_with_values([-0.001]))


def test_prev_value_sub_satoshi_rejected():
    prev = copy.deepcopy(FAUCET_TX_JSON)
    prev["vout"][0]["value"] = 0.000000001
    result = verify_anchor_tx_signature(ANCHOR1_TX, prev, ANCHOR_PUBKEY)
    assert result["verified"] is False


def test_prev_value_negative_rejected():
    prev = copy.deepcopy(FAUCET_TX_JSON)
    prev["vout"][0]["value"] = -0.001
    result = verify_anchor_tx_signature(ANCHOR1_TX, prev, ANCHOR_PUBKEY)
    assert result["verified"] is False
