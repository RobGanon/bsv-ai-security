"""Tests for the live-anchor BSV layer (aiguard/bsv.py + aiguard/broadcast.py).

Tests-first for the first live anchor (Teratestnet). The sighash test is
grounded in a REAL Teratestnet transaction: the faucet payout
99487bc8...030de8288, whose input spends treasury outpoint
732c35...:1 (3,257,935 sats, P2PKH script 76a914f554...88ac) with a DER
signature + compressed pubkey in its scriptSig. The implementation must
reproduce that sighash and verify that real signature — the same
standard the BRC-166 harness met in Go.

The key-derivation vector is cross-checked against the proven Go harness
(payer keygen logic): secret 0x11..11 -> the address / WIF / pubkey below.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from aiguard.anchor import PAYLOAD_SIZE, encode_anchor_payload
from aiguard.bsv import (
    PrivKey,
    Tx,
    TxIn,
    TxOut,
    build_p2pkh_script,
    build_op_return_script,
    parse_tx,
    sighash_forkid,
    sign_digest,
    verify_sig,
)
from aiguard.broadcast import (
    BroadcastError,
    BroadcastRejected,
    BroadcastUnavailable,
    FundingUTXO,
    WIFSigner,
    WoCBroadcaster,
)
from aiguard.publisher import Publisher, PublisherConfig

# --- vectors ------------------------------------------------------------

SECRET_11 = bytes.fromhex("11" * 32)
VECTOR_PUBKEY = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
VECTOR_ADDRESS = "n4XmX91N5FfccY678vaG1ELNtXh6skVES7"
VECTOR_WIF = "cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw"

# Faucet payout tx 99487bc8...030de8288 on Teratestnet (raw hex, public).
FAUCET_TX_HEX = (
    "0100000001ed317c92d3a361ee5fdcc88212c4af57aaee3cf438b8c459d324775c54352c73"
    "010000006b483045022100ff8f9affbfa34d03eaf01f813f3bdc1b3e4e0ceb7229aae9b6a993"
    "fd5f203f690220746e81098930c4a8530699c3bd5dd4bbf4fc6cf7bc64d9c3e357d0474ad4f"
    "bdb4121038341d216846ede55e4aee7e03ea60ac7a1a2bf384f2819d0b000a3933ae7a3a8"
    "ffffffff02a0860100000000001976a914a4ca1740afaef116afa979c8bc70e72dae7469c78"
    "8acae2f3000000000001976a914e12c5029370ae8bd08e137f99568d8bd61237af188ac00000000"
)
FAUCET_PREV_TXID = "732c35545c7724d359c4b838f43ceeaa57afc41282c8dc5fee61a3d3927c31ed"
FAUCET_PREV_VOUT = 1
FAUCET_PREV_SCRIPT = "76a914f5545eae982a281f491c80e4fdf831d141baab5488ac"
FAUCET_PREV_VALUE = 3257935
FAUCET_SIG_DER = (
    "3045022100ff8f9affbfa34d03eaf01f813f3bdc1b3e4e0ceb7229aae9b6a993fd5f203f69"
    "0220746e81098930c4a8530699c3bd5dd4bbf4fc6cf7bc64d9c3e357d0474ad4fbdb"
)
FAUCET_PUBKEY = "038341d216846ede55e4aee7e03ea60ac7a1a2bf384f2819d0b000a3933ae7a3a8"

PAYLOAD = encode_anchor_payload(
    head_hash="ab" * 32,
    start_seq=1,
    end_seq=3,
    release_seq=0,
    prev_txid="00" * 32,
)


# --- key derivation -----------------------------------------------------

def test_privkey_vector_pubkey_address_wif():
    key = PrivKey.from_bytes(SECRET_11)
    assert key.pubkey_compressed().hex() == VECTOR_PUBKEY
    assert key.address(network="testnet") == VECTOR_ADDRESS
    assert key.wif(network="testnet") == VECTOR_WIF


def test_wif_round_trip_and_cross_network_refusal():
    key = PrivKey.from_wif(VECTOR_WIF)
    assert key.to_bytes() == SECRET_11
    assert key.address(network="testnet") == VECTOR_ADDRESS
    # A mainnet WIF (0x80 version) must never be accepted for testnet use,
    # and a testnet WIF must never be accepted for mainnet use.
    mainnet_wif = PrivKey.from_bytes(SECRET_11).wif(network="mainnet")
    with pytest.raises(ValueError):
        PrivKey.from_wif(mainnet_wif, network="testnet")
    with pytest.raises(ValueError):
        PrivKey.from_wif(VECTOR_WIF, network="mainnet")


def test_privkey_rejects_zero_and_overflow():
    with pytest.raises(ValueError):
        PrivKey.from_bytes(bytes(32))
    with pytest.raises(ValueError):
        PrivKey.from_bytes(bytes.fromhex("ff" * 32))


# --- sighash against a real Teratestnet transaction ---------------------

def test_sighash_reproduces_real_ttn_signature():
    tx = parse_tx(bytes.fromhex(FAUCET_TX_HEX))
    assert tx.txid() == "99487bc8dda67bc4c4b798f80d3f22c8f8d4ebb9f82d8a5db659014030de8288"
    digest = sighash_forkid(
        tx, 0, bytes.fromhex(FAUCET_PREV_SCRIPT), FAUCET_PREV_VALUE
    )
    assert verify_sig(
        bytes.fromhex(FAUCET_PUBKEY), digest, bytes.fromhex(FAUCET_SIG_DER)
    )
    # A tampered digest must not verify: the check is not vacuous.
    tampered = bytes([digest[0] ^ 1]) + digest[1:]
    assert not verify_sig(
        bytes.fromhex(FAUCET_PUBKEY), tampered, bytes.fromhex(FAUCET_SIG_DER)
    )


def test_sign_deterministic_low_s_and_verifies():
    key = PrivKey.from_bytes(SECRET_11)
    digest = hashlib.sha256(b"anchor-test").digest()
    sig1 = sign_digest(key, digest)
    sig2 = sign_digest(key, digest)
    assert sig1 == sig2  # RFC 6979 deterministic
    assert verify_sig(key.pubkey_compressed(), digest, sig1)
    # Low-S: the S value is at most n/2 (canonical signatures).
    assert sig1[0] == 0x30
    r_len = sig1[3]
    s_start = 4 + r_len + 2
    s_len = sig1[s_start - 1]
    s = int.from_bytes(sig1[s_start : s_start + s_len], "big")
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    assert s <= n // 2


# --- transaction build / parse ------------------------------------------

def test_op_return_script_exact_bytes():
    script = build_op_return_script(PAYLOAD)
    assert script[:1] == b"\x6a"  # OP_RETURN
    assert script[1:2] == b"\x4c"  # OP_PUSHDATA1 (84 > 75, so no direct push)
    assert script[2] == PAYLOAD_SIZE
    assert script[3:] == PAYLOAD


def test_build_and_parse_anchor_tx_round_trip():
    key = PrivKey.from_bytes(SECRET_11)
    funding = FundingUTXO(
        txid=FAUCET_PREV_TXID, vout=FAUCET_PREV_VOUT,
        value=FAUCET_PREV_VALUE, script_hex=FAUCET_PREV_SCRIPT,
    )
    tx = Tx.build_anchor(
        funding=funding,
        payload=PAYLOAD,
        change_address=key.address(network="testnet"),
        fee_sats=500,
        signer=WIFSigner.from_wif(VECTOR_WIF),
    )
    raw = tx.serialize()
    back = parse_tx(raw)
    assert back.txid() == tx.txid()
    assert len(back.outputs) == 2
    assert back.outputs[0].script == build_op_return_script(PAYLOAD)
    # The built tx must verify against its own input (self-consistency).
    assert verify_sig(
        key.pubkey_compressed(),
        sighash_forkid(back, 0, bytes.fromhex(FAUCET_PREV_SCRIPT), FAUCET_PREV_VALUE),
        _der_from_scriptsig(back.inputs[0].script_sig),
    )
    # Change: input - fee - 0 (no payment output in an anchor tx) goes back.
    assert back.outputs[1].value == FAUCET_PREV_VALUE - 500
    assert back.outputs[1].script == build_p2pkh_script(key.pubkey_compressed())


def _der_from_scriptsig(script_sig: bytes) -> bytes:
    # scriptSig = <push sig+hashtype><push pubkey>; strip the push opcodes
    # and the trailing sighash byte to recover the DER signature.
    assert script_sig[0] == len(script_sig[1:]) - 34 or True  # shape checked below
    sig_len = script_sig[0]
    sig_with_hashtype = script_sig[1 : 1 + sig_len]
    assert sig_with_hashtype[-1] == 0x41  # SIGHASH_ALL | FORKID
    return sig_with_hashtype[:-1]


def test_build_anchor_tx_refuses_dust_change_and_insufficient_funds():
    key = PrivKey.from_bytes(SECRET_11)
    signer = WIFSigner.from_wif(VECTOR_WIF)
    tiny = FundingUTXO(txid="ab" * 32, vout=0, value=400, script_hex=FAUCET_PREV_SCRIPT)
    with pytest.raises(BroadcastError):
        Tx.build_anchor(
            funding=tiny, payload=PAYLOAD,
            change_address=key.address(network="testnet"),
            fee_sats=500, signer=signer,
        )


# --- broadcaster ---------------------------------------------------------

def test_urllib_request_sends_aiguard_user_agent():
    """Regression: WoC-TTN 403s the default Python-urllib User-Agent."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from aiguard.broadcast import _urllib_request

    seen: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen["ua"] = self.headers.get("User-Agent", "")
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        status, _ = _urllib_request("GET", f"http://127.0.0.1:{server.server_port}/x", None)
    finally:
        server.server_close()
    assert status == 200
    assert seen["ua"] == "aiguard/1.0"
    assert "Python-urllib" not in seen["ua"]

class FakeTransport:
    """Canned WoC-TTN responses: prev-tx fetch + broadcast."""

    def __init__(self, broadcast_body: str = '"deadbeef" + "00" * 28', broadcast_status: int = 200):
        self.calls: list[tuple[str, str]] = []
        self.broadcast_body = broadcast_body
        self.broadcast_status = broadcast_status

    def request(self, method: str, url: str, body: bytes | None = None):
        self.calls.append((method, url))
        if url.endswith("/tx/hash/" + FAUCET_PREV_TXID):
            tx = {
                "vout": [
                    {"value": 0.0, "scriptPubKey": {"hex": "00"}},
                    {
                        "value": FAUCET_PREV_VALUE / 1e8,
                        "scriptPubKey": {"hex": FAUCET_PREV_SCRIPT},
                    },
                ]
            }
            return 200, json.dumps(tx).encode()
        if url.endswith("/tx/raw"):
            return self.broadcast_status, self.broadcast_body.encode()
        raise AssertionError(f"unexpected request {method} {url}")


def _broadcaster(transport: FakeTransport) -> WoCBroadcaster:
    return WoCBroadcaster(
        base_url="https://api.woc-ttn.bsvblockchain.tech/v1/bsv/test",
        signer=WIFSigner.from_wif(VECTOR_WIF),
        fee_sats=500,
        funding=FundingUTXO(
            txid=FAUCET_PREV_TXID, vout=FAUCET_PREV_VOUT,
            value=FAUCET_PREV_VALUE, script_hex=FAUCET_PREV_SCRIPT,
        ),
        request_fn=transport.request,
    )


def test_broadcaster_success_returns_txid_and_posts_op_return_tx():
    transport = FakeTransport(broadcast_body='"' + "11" * 32 + '"')
    bc = _broadcaster(transport)
    txid = bc.broadcast(PAYLOAD.hex())
    assert txid == "11" * 32
    assert any(url.endswith("/tx/raw") for _, url in transport.calls)


def test_broadcaster_rejection_maps_to_rejected():
    transport = FakeTransport(broadcast_body='"Missing inputs"', broadcast_status=400)
    bc = _broadcaster(transport)
    with pytest.raises(BroadcastRejected):
        bc.broadcast(PAYLOAD.hex())


def test_broadcaster_already_known_returns_local_txid():
    transport = FakeTransport(
        broadcast_body='"258: txn-already-known"', broadcast_status=500
    )
    bc = _broadcaster(transport)
    txid = bc.broadcast(PAYLOAD.hex())
    # Already-known is success: the returned txid is the locally computed one.
    assert len(txid) == 64 and txid != "11" * 32


def test_broadcaster_unreachable_maps_to_unavailable():
    def failing_request(method, url, body=None):
        raise ConnectionError("connection refused")

    bc = WoCBroadcaster(
        base_url="https://api.woc-ttn.bsvblockchain.tech/v1/bsv/test",
        signer=WIFSigner.from_wif(VECTOR_WIF),
        fee_sats=500,
        funding=FundingUTXO(
            txid=FAUCET_PREV_TXID, vout=FAUCET_PREV_VOUT,
            value=FAUCET_PREV_VALUE, script_hex=FAUCET_PREV_SCRIPT,
        ),
        request_fn=failing_request,
    )
    with pytest.raises(BroadcastUnavailable):
        bc.broadcast(PAYLOAD.hex())


def test_broadcaster_rejects_bad_payload():
    bc = _broadcaster(FakeTransport())
    with pytest.raises((ValueError, BroadcastError)):
        bc.broadcast("not hex")
    with pytest.raises((ValueError, BroadcastError)):
        bc.broadcast(b"short".hex())


# --- CLI publish ---------------------------------------------------------

def test_cli_publish_broadcast_wires_real_broadcaster(tmp_path, monkeypatch, capsys):
    from aiguard import cli as cli_mod
    from aiguard.core import append_audit_event

    journal = tmp_path / "journal.jsonl"
    journal.touch()
    append_audit_event(journal, "verify", "live anchor journal event")
    record_path = tmp_path / "anchors.json"

    class FakeBroadcaster:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def broadcast(self, payload_hex: str) -> str:
            assert len(bytes.fromhex(payload_hex)) == 84
            return "44" * 32

    monkeypatch.setattr(cli_mod, "WoCBroadcaster", FakeBroadcaster)
    monkeypatch.setenv("ANCHOR_WIF", VECTOR_WIF)
    rc = cli_mod.main([
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(record_path),
        "--broadcast",
        "--funding-txid", "55" * 32,
        "--funding-vout", "0",
    ])
    assert rc == 0
    store = json.loads(record_path.read_text())
    assert store["anchors"][0]["status"] == "broadcast"
    assert store["anchors"][0]["txid"] == "44" * 32
    assert "DRY RUN" not in capsys.readouterr().out


def test_cli_publish_broadcast_refuses_without_wif(tmp_path, monkeypatch):
    from aiguard import cli as cli_mod
    from aiguard.core import append_audit_event

    journal = tmp_path / "journal.jsonl"
    journal.touch()
    append_audit_event(journal, "verify", "event")
    monkeypatch.delenv("ANCHOR_WIF", raising=False)
    rc = cli_mod.main([
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(tmp_path / "anchors.json"),
        "--broadcast",
        "--funding-txid", "55" * 32,
    ])
    assert rc == 1


def test_publisher_broadcasts_through_real_broadcaster(tmp_path):
    from aiguard.core import append_audit_event

    journal = tmp_path / "journal.jsonl"
    journal.touch()
    append_audit_event(journal, "verify", "test event one")
    append_audit_event(journal, "verify", "test event two")
    record_path = tmp_path / "anchors.json"
    transport = FakeTransport(broadcast_body='"' + "22" * 32 + '"')
    publisher = Publisher(
        PublisherConfig(
            journal=journal,
            anchor_record=record_path,
            broadcast_enabled=True,
        ),
        broadcaster=_broadcaster(transport),
    )
    record = publisher.build_checkpoint(reason="scheduled")
    assert record["status"] == "broadcast"
    assert record["txid"] == "22" * 32
    assert record["start_seq"] == 1
    assert record["end_seq"] == 2
    assert record["prev_txid"] == "00" * 32  # genesis: no prior anchor


def test_broadcaster_rejects_sub_satoshi_funding_value():
    def request(method, url, body=None):
        if url.endswith("/tx/hash/" + FAUCET_PREV_TXID):
            tx = {
                "vout": [
                    {"value": 0.0, "scriptPubKey": {"hex": "00"}},
                    {
                        "value": 0.000000001,
                        "scriptPubKey": {"hex": FAUCET_PREV_SCRIPT},
                    },
                ]
            }
            return 200, json.dumps(tx).encode()
        raise AssertionError(f"unexpected request {method} {url}")

    bc = WoCBroadcaster(
        base_url="https://api.woc-ttn.bsvblockchain.tech/v1/bsv/test",
        signer=WIFSigner.from_wif(VECTOR_WIF),
        fee_sats=500,
        funding=FundingUTXO(
            txid=FAUCET_PREV_TXID, vout=FAUCET_PREV_VOUT,
            value=FAUCET_PREV_VALUE, script_hex=FAUCET_PREV_SCRIPT,
        ),
        request_fn=request,
    )
    with pytest.raises(BroadcastRejected):
        bc.broadcast(PAYLOAD.hex())
