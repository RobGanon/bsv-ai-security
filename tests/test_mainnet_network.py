"""Mainnet readiness: explicit network selection, never by accident.

Mainnet is never the default and never implicit:
- a WIF's version byte must match the declared network (cross-network
  use is refused);
- the publishing config requires a separate confirmation value for
  mainnet;
- the CLI requires --confirm-mainnet for a mainnet broadcast, and
  --woc-base defaults from --network.

No test here touches a live network: the broadcaster test injects a
fake request_fn, and the CLI tests use a stub broadcaster.
"""
import json

import pytest

from sealrun.anchor import encode_anchor_payload
from sealrun.broadcast import (
    FundingUTXO,
    WIFSigner,
    WoCBroadcaster,
    WOC_MAINNET_BASE,
    WOC_TTN_BASE,
)
from sealrun.bsv import (
    PrivKey,
    build_p2pkh_script_for_address,
    parse_tx,
    sighash_forkid,
    verify_sig,
)
from sealrun.cli import main
from sealrun.core import append_audit_event

# Private key 1: the canonical key-1 vector. Compressed pubkey ->
# mainnet address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH.
KEY1_MAINNET_ADDRESS = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"


def _key1_mainnet_wif():
    return PrivKey(1).wif(network="mainnet")


def _key1_testnet_wif():
    return PrivKey(1).wif(network="testnet")


# --- keys ----------------------------------------------------------------


def test_privkey_mainnet_vector():
    key = PrivKey.from_wif(_key1_mainnet_wif(), network="mainnet")
    assert key.secret == 1
    assert key.address(network="mainnet") == KEY1_MAINNET_ADDRESS
    assert key.wif(network="mainnet") == _key1_mainnet_wif()
    # The mainnet address round-trips through base58check decoding.
    from sealrun.bsv import base58check_decode, hash160

    version, payload = base58check_decode(KEY1_MAINNET_ADDRESS)
    assert version == 0x00
    assert payload == hash160(key.pubkey_compressed())


def test_base58_encode_pads_leading_zero_bytes_with_ones():
    # Regression: base58_encode padded leading zero bytes with "0"
    # (not a base58 character) instead of "1". Testnet never hit it
    # (nonzero version bytes); every mainnet address (version 0x00)
    # would have been mis-encoded.
    from sealrun.bsv import base58_decode, base58_encode

    assert base58_encode(b"\x00") == "1"
    assert base58_encode(b"\x00\x00\x01") == "112"
    assert base58_decode("112") == b"\x00\x00\x01"
    assert base58_decode(base58_encode(b"\x00\x00\xab\xcd")) == b"\x00\x00\xab\xcd"


def test_privkey_cross_network_wif_refused():
    # A mainnet WIF must never be accepted for testnet use, and a
    # testnet WIF must never be accepted for mainnet use: the version
    # byte must match the declared network.
    with pytest.raises(ValueError, match="network"):
        PrivKey.from_wif(_key1_mainnet_wif(), network="testnet")
    with pytest.raises(ValueError, match="network"):
        PrivKey.from_wif(_key1_mainnet_wif())
    with pytest.raises(ValueError, match="network"):
        PrivKey.from_wif(_key1_testnet_wif(), network="mainnet")


def test_privkey_rejects_unknown_network():
    with pytest.raises(ValueError, match="network"):
        PrivKey.from_wif(_key1_testnet_wif(), network="bogus")
    with pytest.raises(ValueError, match="network"):
        PrivKey(1).address(network="bogus")
    with pytest.raises(ValueError, match="network"):
        PrivKey(1).wif(network="bogus")


def test_address_versions_by_network():
    testnet_address = PrivKey(1).address(network="testnet")
    mainnet_address = PrivKey(1).address(network="mainnet")
    assert testnet_address != mainnet_address
    assert mainnet_address.startswith("1")
    assert testnet_address[0] in ("m", "n")


# --- scripts + tx building -----------------------------------------------


def test_p2pkh_script_for_address_network():
    mainnet_script = build_p2pkh_script_for_address(
        KEY1_MAINNET_ADDRESS, network="mainnet"
    )
    assert mainnet_script.hex().startswith("76a914")
    assert mainnet_script.hex().endswith("88ac")
    # A mainnet address is refused for testnet use and vice versa.
    with pytest.raises(ValueError, match="network"):
        build_p2pkh_script_for_address(KEY1_MAINNET_ADDRESS, network="testnet")
    testnet_address = PrivKey(1).address(network="testnet")
    with pytest.raises(ValueError, match="network"):
        build_p2pkh_script_for_address(testnet_address, network="mainnet")


def test_build_anchor_mainnet_change_signature_verifies():
    from sealrun.bsv import Tx

    key = PrivKey(1)
    signer = WIFSigner.from_wif(_key1_mainnet_wif(), network="mainnet")
    change_address = signer.address(network="mainnet")
    prev_script = build_p2pkh_script_for_address(
        change_address, network="mainnet"
    )
    payload = encode_anchor_payload(
        head_hash="ab" * 32, start_seq=1, end_seq=1, release_seq=0
    )
    tx = Tx.build_anchor(
        funding=FundingUTXO(
            txid="cc" * 32, vout=0, value=100000, script_hex=prev_script.hex()
        ),
        payload=payload,
        change_address=change_address,
        fee_sats=500,
        signer=signer,
        network="mainnet",
    )
    assert len(tx.outputs) == 2
    assert tx.outputs[1].value == 100000 - 500
    assert tx.outputs[1].script == prev_script
    # The mainnet-built tx carries a valid FORKID signature.
    script_sig = tx.inputs[0].script_sig
    n1 = script_sig[0]
    der = script_sig[1 : 1 + n1][:-1]
    pub_start = 1 + n1
    n2 = script_sig[pub_start]
    pubkey = script_sig[pub_start + 1 : pub_start + 1 + n2]
    digest = sighash_forkid(tx, 0, prev_script, 100000)
    assert verify_sig(pubkey, digest, der)


def test_build_anchor_rejects_mismatched_change_address():
    from sealrun.bsv import Tx

    signer = WIFSigner.from_wif(_key1_testnet_wif(), network="testnet")
    payload = encode_anchor_payload(
        head_hash="ab" * 32, start_seq=1, end_seq=1, release_seq=0
    )
    funding = FundingUTXO(
        txid="cc" * 32, vout=0, value=100000, script_hex="76a914" + "00" * 20 + "88ac"
    )
    with pytest.raises(ValueError, match="network"):
        Tx.build_anchor(
            funding=funding,
            payload=payload,
            change_address=KEY1_MAINNET_ADDRESS,
            fee_sats=500,
            signer=signer,
            network="testnet",
        )
    with pytest.raises(ValueError, match="network"):
        Tx.build_anchor(
            funding=funding,
            payload=payload,
            change_address=PrivKey(1).address(network="testnet"),
            fee_sats=500,
            signer=signer,
            network="mainnet",
        )


# --- signer + broadcaster ------------------------------------------------


def test_wif_signer_network():
    signer = WIFSigner.from_wif(_key1_mainnet_wif(), network="mainnet")
    assert signer.address(network="mainnet") == KEY1_MAINNET_ADDRESS
    # Default is testnet: a mainnet WIF without an explicit network is refused.
    with pytest.raises(ValueError, match="network"):
        WIFSigner.from_wif(_key1_mainnet_wif())


def test_broadcaster_mainnet_builds_mainnet_change():
    signer = WIFSigner.from_wif(_key1_mainnet_wif(), network="mainnet")
    change_address = signer.address(network="mainnet")
    prev_script = build_p2pkh_script_for_address(
        change_address, network="mainnet"
    )
    posted = {}

    def fake_request(method, url, body):
        if method == "GET" and "/tx/hash/" in url:
            return 200, json.dumps(
                {"vout": [{"scriptPubKey": {"hex": prev_script.hex()}, "value": 0.001}]}
            ).encode()
        if method == "POST" and url.endswith("/tx/raw"):
            posted["hex"] = json.loads(body)["txhex"]
            from sealrun.bsv import parse_tx
            try:
                return 200, json.dumps(parse_tx(bytes.fromhex(posted["hex"])).txid()).encode()
            except Exception:
                return 200, json.dumps('ff'*32).encode()
        raise AssertionError(f"unexpected request {method} {url}")

    broadcaster = WoCBroadcaster(
        base_url=WOC_MAINNET_BASE,
        network="mainnet",
        signer=signer,
        fee_sats=500,
        funding=FundingUTXO(txid="cc" * 32, vout=0, value=0, script_hex=""),
        request_fn=fake_request,
    )
    assert broadcaster.network == "mainnet"
    payload = encode_anchor_payload(
        head_hash="ab" * 32, start_seq=1, end_seq=1, release_seq=0
    )
    from sealrun.bsv import parse_tx
    txid = broadcaster.broadcast(payload.hex())
    assert txid == parse_tx(bytes.fromhex(posted["hex"])).txid()
    tx = parse_tx(bytes.fromhex(posted["hex"]))
    assert len(tx.outputs) == 2
    assert tx.outputs[1].value == 100000 - 500
    assert tx.outputs[1].script == prev_script


def test_broadcaster_default_is_testnet():
    signer = WIFSigner.from_wif(_key1_testnet_wif())
    broadcaster = WoCBroadcaster(
        base_url=WOC_TTN_BASE,
        signer=signer,
        funding=FundingUTXO(txid="cc" * 32, vout=0, value=0, script_hex=""),
    )
    assert broadcaster.network == "testnet"


@pytest.mark.parametrize("network,base_url", [
    ("testnet", WOC_MAINNET_BASE),
    ("mainnet", WOC_TTN_BASE),
])
def test_broadcaster_rejects_opposite_network_base(network, base_url):
    signer = WIFSigner(PrivKey(1))
    with pytest.raises(ValueError, match="does not match selected network"):
        WoCBroadcaster(
            base_url=base_url,
            network=network,
            signer=signer,
            funding=FundingUTXO(txid="cc" * 32, vout=0, value=0, script_hex=""),
            request_fn=lambda *args: pytest.fail("unexpected network request"),
        )


# --- CLI -------------------------------------------------------------------


def _publish_args(tmp_path, *extra):
    return [
        "publish",
        "--journal",
        str(tmp_path / "audit.jsonl"),
        "--anchor-record",
        str(tmp_path / "anchors.json"),
        *extra,
    ]


def test_cli_publish_mainnet_broadcast_requires_confirm(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setenv("ANCHOR_WIF", _key1_mainnet_wif())
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    assert (
        main(
            _publish_args(
                tmp_path,
                "--network",
                "mainnet",
                "--broadcast",
                "--funding-txid",
                "aa" * 32,
            )
        )
        == 1
    )
    assert "--confirm-mainnet" in capsys.readouterr().err


def test_cli_publish_mainnet_broadcast_wires_mainnet(tmp_path, monkeypatch):
    captured = {}

    class FakeBroadcaster:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def broadcast(self, payload_hex):
            return "bb" * 32

    monkeypatch.setattr("sealrun.cli.WoCBroadcaster", FakeBroadcaster)
    monkeypatch.setenv("ANCHOR_WIF", _key1_mainnet_wif())
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    assert (
        main(
            _publish_args(
                tmp_path,
                "--network",
                "mainnet",
                "--broadcast",
                "--confirm-mainnet",
                "--funding-txid",
                "aa" * 32,
            )
        )
        == 0
    )
    assert captured["network"] == "mainnet"
    assert captured["base_url"] == WOC_MAINNET_BASE
    assert captured["signer"].address(network="mainnet") == KEY1_MAINNET_ADDRESS


def test_cli_publish_testnet_broadcast_stays_testnet(tmp_path, monkeypatch):
    captured = {}

    class FakeBroadcaster:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def broadcast(self, payload_hex):
            return "bb" * 32

    monkeypatch.setattr("sealrun.cli.WoCBroadcaster", FakeBroadcaster)
    monkeypatch.setenv("ANCHOR_WIF", _key1_testnet_wif())
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    assert (
        main(
            _publish_args(
                tmp_path,
                "--broadcast",
                "--funding-txid",
                "aa" * 32,
            )
        )
        == 0
    )
    assert captured["network"] == "testnet"
    assert captured["base_url"] == WOC_TTN_BASE


def test_cli_publish_mainnet_dry_run_needs_no_confirm(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    assert main(_publish_args(tmp_path, "--network", "mainnet")) == 0


def test_cli_publish_mainnet_broadcast_refuses_testnet_wif(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setenv("ANCHOR_WIF", _key1_testnet_wif())
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    assert (
        main(
            _publish_args(
                tmp_path,
                "--network",
                "mainnet",
                "--broadcast",
                "--confirm-mainnet",
                "--funding-txid",
                "aa" * 32,
            )
        )
        == 1
    )
    assert "network" in capsys.readouterr().err.lower()


def test_cli_publish_explicit_woc_base_wins(tmp_path, monkeypatch):
    captured = {}

    class FakeBroadcaster:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def broadcast(self, payload_hex):
            return "bb" * 32

    monkeypatch.setattr("sealrun.cli.WoCBroadcaster", FakeBroadcaster)
    monkeypatch.setenv("ANCHOR_WIF", _key1_mainnet_wif())
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    assert (
        main(
            _publish_args(
                tmp_path,
                "--network",
                "mainnet",
                "--broadcast",
                "--confirm-mainnet",
                "--woc-base",
                "https://example.invalid",
                "--funding-txid",
                "aa" * 32,
            )
        )
        == 0
    )
    assert captured["base_url"] == "https://example.invalid"
    assert captured["network"] == "mainnet"


def test_cli_publish_rejects_unknown_network(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    with pytest.raises(SystemExit):
        main(_publish_args(tmp_path, "--network", "bogus"))
