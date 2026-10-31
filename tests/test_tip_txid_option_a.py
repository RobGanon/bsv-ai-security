"""Tip-txid binding (Option A): the recorded txid must be proved by
the stored transaction bytes, not trusted as a 64-hex string.

Each test here fails on pre-fix code (the forged tip is accepted and
the next anchor chains to it) and passes post-fix (refused, or the
bytes are stored and chaining works). No test weakens validation to
make the suite pass: the fakes below build real anchor-shaped txs.
"""

import hashlib
import json

import pytest

from sealrun.bsv import (
    PrivKey,
    Tx,
    TxIn,
    TxOut,
    build_op_return_script,
    build_p2pkh_script,
    parse_tx,
    sighash_forkid,
    sign_digest,
)
from sealrun.broadcast import FundingUTXO, WIFSigner, WoCBroadcaster
from sealrun.core import append_audit_event
from sealrun.publisher import Publisher, PublisherConfig, PublisherError

_TEST_KEY = PrivKey(12345)


def _config(tmp_path, *, broadcast=False):
    return PublisherConfig(
        journal=tmp_path / "audit.jsonl",
        anchor_record=tmp_path / "anchors.json",
        genesis_txid="0" * 64,
        checkpoint_interval_seconds=3600,
        broadcast_enabled=broadcast,
        manifests=(),
        public_key=None,
    )


def _anchor_tx(payload_hex, *, prev_txid="0" * 64):
    """A real anchor-shaped tx carrying payload_hex; returns (txid, hex)."""
    tx = Tx(
        inputs=[TxIn(prev_txid, 0)],
        outputs=[
            TxOut(0, build_op_return_script(bytes.fromhex(payload_hex))),
            TxOut(1000, build_p2pkh_script(_TEST_KEY.pubkey_compressed())),
        ],
    )
    return tx.txid(), tx.serialize().hex()


class _TxBytesBroadcaster:
    """Tx-bytes path: returns (txid, tx_hex) for a real anchor tx.

    It also implements the txid-only ``broadcast`` shape returning
    the same txid, so the pre-fix code path (which knows nothing
    about broadcast_with_tx) can still broadcast — and the forged-tip
    test then fails pre-fix by acceptance, not by a missing method.
    """

    def broadcast(self, payload_hex):
        return _anchor_tx(payload_hex)[0]

    def broadcast_with_tx(self, payload_hex):
        return _anchor_tx(payload_hex)


class _StrOnlyBroadcaster:
    """Txid-only path: returns a fake txid string and no bytes."""

    def broadcast(self, payload_hex):
        return hashlib.sha256(("str-only:" + payload_hex).encode()).hexdigest()


def _publisher(tmp_path, broadcaster):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    return Publisher(_config(tmp_path, broadcast=True), broadcaster=broadcaster)


def _read_store(tmp_path):
    return json.loads((tmp_path / "anchors.json").read_text(encoding="utf-8"))


def _rewrite_store(tmp_path, store):
    (tmp_path / "anchors.json").write_text(json.dumps(store, indent=2) + "\n")


def _honest_tip(tmp_path):
    """One broadcast anchor via the tx-bytes path; returns (pub, record).

    Deliberately does NOT assert tx_hex here: the forgery tests below
    must fail pre-fix by acceptance (the tampered anchor is built on),
    not by a missing-field KeyError. Capture of tx_hex is asserted
    separately, in the capture-path tests."""
    publisher = _publisher(tmp_path, _TxBytesBroadcaster())
    record = publisher.build_checkpoint("scheduled")
    assert record["status"] == "broadcast"
    return publisher, record


def test_forged_tip_txid_refused(tmp_path):
    """BB's repro: honest tip, only the txid edited to ff..ff, next
    anchor must be refused — pre-fix it chained to ff..ff. This test
    deliberately does NOT assert tx_hex up front, so its pre-fix
    failure mode is acceptance (no raise), not a missing-field
    KeyError: it discriminates the vulnerability itself."""
    publisher = _publisher(tmp_path, _TxBytesBroadcaster())
    publisher.build_checkpoint("scheduled")
    store = _read_store(tmp_path)
    store["anchors"][-1]["txid"] = "ff" * 32
    _rewrite_store(tmp_path, store)
    append_audit_event(tmp_path / "audit.jsonl", "test", "second")
    with pytest.raises(PublisherError, match="stored transaction"):
        publisher.build_checkpoint("scheduled")


def test_forged_tx_hex_wrong_payload_refused(tmp_path):
    """Txid recomputation alone is not enough: a tx whose txid is
    correct for its bytes but whose OP_RETURN is a different payload
    must still be refused."""
    publisher, record = _honest_tip(tmp_path)
    other_txid, other_hex = _anchor_tx("00" * 84)
    store = _read_store(tmp_path)
    store["anchors"][-1]["txid"] = other_txid
    store["anchors"][-1]["tx_hex"] = other_hex
    _rewrite_store(tmp_path, store)
    append_audit_event(tmp_path / "audit.jsonl", "test", "second")
    with pytest.raises(PublisherError, match="anchor payload"):
        publisher.build_checkpoint("scheduled")


def test_tx_hex_txid_mismatch_refused(tmp_path):
    """Same payload, different transaction: the stored bytes' txid
    does not match the record txid, so the tip must be refused even
    though the payload check alone would pass."""
    publisher, record = _honest_tip(tmp_path)
    other_txid, other_hex = _anchor_tx(record["payload_hex"], prev_txid="11" * 32)
    store = _read_store(tmp_path)
    store["anchors"][-1]["tx_hex"] = other_hex
    _rewrite_store(tmp_path, store)
    append_audit_event(tmp_path / "audit.jsonl", "test", "second")
    with pytest.raises(PublisherError, match="does not match its stored"):
        publisher.build_checkpoint("scheduled")


def test_tx_hex_noncanonical_serialization_refused(tmp_path):
    """Trailing junk appended to stored bytes must be refused: the
    stored tx must re-serialize canonically, not merely parse."""
    publisher, record = _honest_tip(tmp_path)
    store = _read_store(tmp_path)
    store["anchors"][-1]["tx_hex"] = record["tx_hex"] + "00"
    _rewrite_store(tmp_path, store)
    append_audit_event(tmp_path / "audit.jsonl", "test", "second")
    with pytest.raises(PublisherError):
        publisher.build_checkpoint("scheduled")


def test_str_only_broadcast_record_cannot_be_extended_but_dedupe_intact(tmp_path):
    """A new broadcast record without tx_hex stays readable and its
    own head still dedupes, but a new anchor chaining to it is
    refused."""
    publisher = _publisher(tmp_path, _StrOnlyBroadcaster())
    first = publisher.build_checkpoint("scheduled")
    assert first["status"] == "broadcast"
    assert first.get("tx_hex") is None
    decision = publisher.run_once()
    assert decision["action"] == "none"
    assert decision["reason"] == "already-anchored"
    append_audit_event(tmp_path / "audit.jsonl", "test", "second")
    with pytest.raises(PublisherError, match="no stored transaction bytes"):
        publisher.build_checkpoint("scheduled")


def test_legacy_record_without_tx_hex_key_readable_but_not_predecessor(tmp_path):
    """A pre-upgrade store file has no tx_hex key at all (not even
    null). It must still load and dedupe for its own head, but must
    never be extended."""
    publisher = _publisher(tmp_path, _StrOnlyBroadcaster())
    publisher.build_checkpoint("scheduled")
    store = _read_store(tmp_path)
    # Simulate the pre-upgrade file format: no tx_hex key at all.
    # .pop (not del) so the test also runs on pre-fix code, where the
    # key was never written — and then fails there by acceptance.
    store["anchors"][-1].pop("tx_hex", None)
    _rewrite_store(tmp_path, store)
    decision = publisher.run_once()
    assert decision["action"] == "none"
    assert decision["reason"] == "already-anchored"
    append_audit_event(tmp_path / "audit.jsonl", "test", "second")
    with pytest.raises(PublisherError, match="no stored transaction bytes"):
        publisher.build_checkpoint("scheduled")


# --- capture paths -------------------------------------------------------
#
# The two real capture paths must both store tx_hex, and a second
# anchor must chain to the stored tip. The fake WoC endpoint and the
# signing helpers below mirror tests/test_publisher_export.py (same
# synthetic key, same funding outpoint, no real key material).

_SIGN_KEY = PrivKey(int.from_bytes(b"\x22" * 32, "big"))
_SIGN_ADDRESS = WIFSigner(_SIGN_KEY).address(network="testnet")
_FUNDING_SCRIPT_HEX = build_p2pkh_script(_SIGN_KEY.pubkey_compressed()).hex()
_FUNDING_TXID = "aa" * 32
_FUNDING_VOUT = 0
_FUNDING_VALUE = 100_000
_FEE_SATS = 500


class _FakeWoC:
    def __init__(self):
        self.posts = []

    def request(self, method, url, body=None):
        if method == "GET" and url.endswith("/tx/hash/" + _FUNDING_TXID):
            tx = {
                "vout": [
                    {
                        "value": _FUNDING_VALUE / 1e8,
                        "scriptPubKey": {"hex": _FUNDING_SCRIPT_HEX},
                    }
                ]
            }
            return 200, json.dumps(tx).encode()
        if method == "POST" and url.endswith("/tx/raw"):
            txhex = json.loads(body)["txhex"]
            self.posts.append(txhex)
            return 200, json.dumps(
                parse_tx(bytes.fromhex(txhex)).txid()
            ).encode()
        raise AssertionError(f"unexpected request {method} {url}")


def test_woc_broadcaster_stores_tx_hex_and_chains(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    woc = _FakeWoC()
    broadcaster = WoCBroadcaster(
        base_url="https://woc.example",
        network="testnet",
        signer=WIFSigner(_SIGN_KEY),
        fee_sats=_FEE_SATS,
        funding=FundingUTXO(
            txid=_FUNDING_TXID,
            vout=_FUNDING_VOUT,
            value=_FUNDING_VALUE,
            script_hex=_FUNDING_SCRIPT_HEX,
        ),
        request_fn=woc.request,
    )
    publisher = Publisher(_config(tmp_path, broadcast=True), broadcaster=broadcaster)
    first = publisher.build_checkpoint("scheduled")
    assert first["status"] == "broadcast"
    assert first.get("tx_hex") is not None
    assert parse_tx(bytes.fromhex(first["tx_hex"])).txid() == first["txid"]
    assert woc.posts[-1] == first["tx_hex"]
    append_audit_event(journal, "test", "second")
    second = publisher.build_checkpoint("scheduled")
    assert second["prev_txid"] == first["txid"]
    assert second["status"] == "broadcast"
    assert second.get("tx_hex") is not None


def _sign(unsigned_hex):
    tx = parse_tx(bytes.fromhex(unsigned_hex))
    digest = sighash_forkid(
        tx, 0, bytes.fromhex(_FUNDING_SCRIPT_HEX), _FUNDING_VALUE
    )
    der = sign_digest(_SIGN_KEY, digest)
    pubkey = _SIGN_KEY.pubkey_compressed()
    tx.inputs[0].script_sig = (
        bytes([len(der) + 1]) + der + bytes([0x41])
        + bytes([len(pubkey)]) + pubkey
    )
    return tx.serialize().hex()


def test_broadcast_signed_stores_tx_hex_and_chains(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    publisher = Publisher(_config(tmp_path))
    woc = _FakeWoC()
    exported = publisher.export_unsigned(
        funding_txid=_FUNDING_TXID,
        funding_vout=_FUNDING_VOUT,
        change_address=_SIGN_ADDRESS,
        fee_sats=_FEE_SATS,
        woc_base="https://woc.example",
        request_fn=woc.request,
    )
    signed_hex = _sign(exported["unsigned_hex"])
    first = publisher.broadcast_signed(
        signed_hex=signed_hex,
        funding_txid=_FUNDING_TXID,
        funding_vout=_FUNDING_VOUT,
        change_address=_SIGN_ADDRESS,
        fee_sats=_FEE_SATS,
        woc_base="https://woc.example",
        request_fn=woc.request,
    )
    assert first["status"] == "broadcast"
    assert first.get("tx_hex") == signed_hex
    assert parse_tx(bytes.fromhex(first["tx_hex"])).txid() == first["txid"]
    append_audit_event(journal, "test", "second")
    exported2 = publisher.export_unsigned(
        funding_txid=_FUNDING_TXID,
        funding_vout=_FUNDING_VOUT,
        change_address=_SIGN_ADDRESS,
        fee_sats=_FEE_SATS,
        woc_base="https://woc.example",
        request_fn=woc.request,
    )
    assert exported2["record"]["prev_txid"] == first["txid"]
    signed_hex2 = _sign(exported2["unsigned_hex"])
    second = publisher.broadcast_signed(
        signed_hex=signed_hex2,
        funding_txid=_FUNDING_TXID,
        funding_vout=_FUNDING_VOUT,
        change_address=_SIGN_ADDRESS,
        fee_sats=_FEE_SATS,
        woc_base="https://woc.example",
        request_fn=woc.request,
    )
    assert second["prev_txid"] == first["txid"]
    assert second.get("tx_hex") == signed_hex2
