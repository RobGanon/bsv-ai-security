"""Publisher unsigned-tx export + signed-tx broadcast (offline signing ceremony).

The publisher half of the ceremony: export builds the unsigned anchor
tx from the journal + record store and stops (never signs, never
broadcasts); broadcast-signed verifies a signed tx against a freshly
rebuilt unsigned tx and only then broadcasts it. Tests use synthetic
keys / UTXOs only — no real key material anywhere in this file.
"""

import json

import pytest

from sealrun.anchor import decode_anchor_payload
from sealrun.bsv import (
    PrivKey,
    Tx,
    build_p2pkh_script,
    parse_tx,
    sighash_forkid,
    sign_digest,
)
from sealrun.broadcast import FundingUTXO, WIFSigner, WOC_MAINNET_BASE
from sealrun.core import append_audit_event
from sealrun.publisher import Publisher, PublisherConfig, PublisherError

# Synthetic test key (secret 0x22..22) — a throwaway fixture, never a
# real key. Its P2PKH script is the funding output in these tests.
TEST_KEY = PrivKey(int.from_bytes(b"\x22" * 32, "big"))
TEST_PUBKEY = TEST_KEY.pubkey_compressed()
TEST_ADDRESS = WIFSigner(TEST_KEY).address(network="testnet")
FUNDING_SCRIPT_HEX = build_p2pkh_script(TEST_PUBKEY).hex()

FUNDING_TXID = "aa" * 32
FUNDING_VOUT = 0
FUNDING_VALUE = 100_000
FEE_SATS = 500

# Curve order, for building a malleated (high-S) signature in one test.
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _config(tmp_path, *, broadcast=False):
    return PublisherConfig(
        journal=tmp_path / "audit.jsonl",
        anchor_record=tmp_path / "anchors.json",
        genesis_txid="0" * 64,
        checkpoint_interval_seconds=3600,
        broadcast_enabled=broadcast,
    )


def _journal(tmp_path):
    journal = tmp_path / "audit.jsonl"
    journal.touch()
    append_audit_event(journal, "verify", "ceremony export test event")
    return journal


def _publisher(tmp_path):
    _journal(tmp_path)
    return Publisher(_config(tmp_path))


class _FakeWoC:
    """Fake WhatsOnChain: serves the funding prev-output, records POSTs."""

    def __init__(self, *, post_status=200, post_body=None):
        self.posts: list[str] = []
        self.gets: list[str] = []
        self.post_status = post_status
        self.post_body = post_body

    def request(self, method, url, body=None):
        if method == "GET" and url.endswith("/tx/hash/" + FUNDING_TXID):
            self.gets.append(url)
            tx = {
                "vout": [
                    {
                        "value": FUNDING_VALUE / 1e8,
                        "scriptPubKey": {"hex": FUNDING_SCRIPT_HEX},
                    }
                ]
            }
            return 200, json.dumps(tx).encode()
        if method == "POST" and url.endswith("/tx/raw"):
            self.posts.append(json.loads(body)["txhex"])
            if self.post_body is not None:
                return self.post_status, self.post_body.encode()
            # A real endpoint echoes the txid of the submitted tx.
            return 200, json.dumps(
                parse_tx(bytes.fromhex(json.loads(body)["txhex"])).txid()
            ).encode()
        raise AssertionError(f"unexpected request {method} {url}")


def _export(publisher, woc, *, change_address=TEST_ADDRESS, fee_sats=FEE_SATS):
    return publisher.export_unsigned(
        funding_txid=FUNDING_TXID,
        funding_vout=FUNDING_VOUT,
        change_address=change_address,
        fee_sats=fee_sats,
        woc_base="https://woc.example",
        request_fn=woc.request,
    )


def _sign(unsigned_hex, *, key=TEST_KEY):
    """Sign an unsigned tx hex with a test key; return the signed hex."""
    tx = parse_tx(bytes.fromhex(unsigned_hex))
    assert len(tx.inputs) == 1 and tx.inputs[0].script_sig == b""
    digest = sighash_forkid(
        tx, 0, bytes.fromhex(FUNDING_SCRIPT_HEX), FUNDING_VALUE
    )
    der = sign_digest(key, digest)
    pubkey = key.pubkey_compressed()
    tx.inputs[0].script_sig = (
        bytes([len(der) + 1]) + der + bytes([0x41])
        + bytes([len(pubkey)]) + pubkey
    )
    return tx.serialize().hex()


def _malleate_sig(signed_hex):
    """Re-sign with the high-S form of the same signature (malleated txid).

    ECDSA verifies both s and N - s, so this is a second VALID signed
    tx for the same unsigned template, with a different txid.
    """
    tx = parse_tx(bytes.fromhex(signed_hex))
    script_sig = tx.inputs[0].script_sig
    # script_sig = push(der + 0x41) + push(pubkey)
    der_len = script_sig[0] - 1
    der = script_sig[1:1 + der_len]
    assert script_sig[1 + der_len] == 0x41  # SIGHASH_ALL|FORKID
    assert script_sig[1 + der_len + 1] == 33  # pubkey push length
    pubkey = script_sig[1 + der_len + 2:]
    # DER: 30 total 02 rlen r 02 slen s
    assert der[0] == 0x30 and der[2] == 0x02
    r_len = der[3]
    r = int.from_bytes(der[4:4 + r_len], "big")
    s_pos = 4 + r_len
    assert der[s_pos] == 0x02
    s_len = der[s_pos + 1]
    s = int.from_bytes(der[s_pos + 2:s_pos + 2 + s_len], "big")
    s2 = _N - s

    def _der_int(x):
        raw = x.to_bytes((x.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    body = _der_int(r) + _der_int(s2)
    der2 = b"\x30" + bytes([len(body)]) + body
    tx.inputs[0].script_sig = (
        bytes([len(der2) + 1]) + der2 + bytes([0x41])
        + bytes([len(pubkey)]) + pubkey
    )
    return tx.serialize().hex()


# --- build-unsigned -------------------------------------------------------


def test_build_anchor_unsigned_equals_signed_minus_signature():
    from sealrun.anchor import encode_anchor_payload
    from sealrun.broadcast import FundingUTXO as FU

    payload = encode_anchor_payload(
        head_hash="11" * 32, start_seq=1, end_seq=1, release_seq=0,
        prev_txid="00" * 32,
    )
    funding = FU(
        txid=FUNDING_TXID, vout=FUNDING_VOUT,
        value=FUNDING_VALUE, script_hex=FUNDING_SCRIPT_HEX,
    )
    signed = Tx.build_anchor(
        funding=funding, payload=payload, change_address=TEST_ADDRESS,
        fee_sats=FEE_SATS, signer=WIFSigner(TEST_KEY), network="testnet",
    )
    unsigned = Tx.build_anchor_unsigned(
        funding=funding, payload=payload, change_address=TEST_ADDRESS,
        fee_sats=FEE_SATS, network="testnet",
    )
    assert unsigned.inputs[0].script_sig == b""
    assert unsigned.version == signed.version
    assert unsigned.locktime == signed.locktime
    assert len(unsigned.inputs) == len(signed.inputs) == 1
    assert unsigned.inputs[0].prev_txid == signed.inputs[0].prev_txid
    assert unsigned.inputs[0].prev_index == signed.inputs[0].prev_index
    assert unsigned.outputs == signed.outputs


def test_build_anchor_unsigned_rejects_bad_payload_and_fee():
    from sealrun.broadcast import FundingUTXO as FU

    funding = FU(
        txid=FUNDING_TXID, vout=FUNDING_VOUT,
        value=FUNDING_VALUE, script_hex=FUNDING_SCRIPT_HEX,
    )
    with pytest.raises(Exception, match="84 bytes"):
        Tx.build_anchor_unsigned(
            funding=funding, payload=b"short", change_address=TEST_ADDRESS,
            fee_sats=FEE_SATS, network="testnet",
        )
    with pytest.raises(Exception, match="insufficient funds"):
        Tx.build_anchor_unsigned(
            funding=funding, payload=b"\x00" * 84,
            change_address=TEST_ADDRESS,
            fee_sats=FUNDING_VALUE + 1, network="testnet",
        )


# --- export ---------------------------------------------------------------


def test_export_returns_unsigned_hex_and_summary(tmp_path):
    woc = _FakeWoC()
    result = _export(_publisher(tmp_path), woc)
    unsigned = parse_tx(bytes.fromhex(result["unsigned_hex"]))
    assert len(unsigned.inputs) == 1
    assert unsigned.inputs[0].script_sig == b""
    assert unsigned.inputs[0].prev_txid == FUNDING_TXID
    assert unsigned.inputs[0].prev_index == FUNDING_VOUT
    assert len(unsigned.outputs) == 2
    # OP_RETURN payload + change back to the anchor address.
    assert unsigned.outputs[0].value == 0
    assert unsigned.outputs[1].value == FUNDING_VALUE - FEE_SATS
    assert unsigned.outputs[1].script.hex() == FUNDING_SCRIPT_HEX
    # Summary the human cross-checks against the signer display.
    assert result["unsigned_txid"] == unsigned.txid()
    assert result["payload"]["head_hash"] == result["record"]["head_hash"]
    assert result["payload"]["start_seq"] == result["record"]["start_seq"]
    assert result["payload"]["end_seq"] == result["record"]["end_seq"]
    assert result["fee_sats"] == FEE_SATS
    assert result["change_address"] == TEST_ADDRESS
    assert result["network"] == "testnet"
    # The checkpoint is recorded as pending; nothing was broadcast.
    assert result["record"]["status"] == "pending"
    assert woc.posts == []


def test_export_never_broadcasts(tmp_path):
    # No broadcaster is involved at all: the Publisher is constructed
    # without one, and export performs only a GET for the funding output.
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    assert publisher.broadcaster is None
    _export(publisher, woc)
    assert woc.posts == []
    assert woc.gets != []


def test_export_refuses_mainnet(tmp_path):
    woc = _FakeWoC()
    with pytest.raises(PublisherError, match="mainnet"):
        _publisher(tmp_path).export_unsigned(
            funding_txid=FUNDING_TXID, funding_vout=FUNDING_VOUT,
            change_address=TEST_ADDRESS, fee_sats=FEE_SATS,
            woc_base="https://woc.example", network="mainnet",
            request_fn=woc.request,
        )


@pytest.mark.parametrize("base_url,reason", [
    (WOC_MAINNET_BASE, "does not match selected network"),
    ("http://attacker.invalid", "https"),
])
def test_offline_paths_validate_endpoint_before_mutation_or_io(
    tmp_path, base_url, reason
):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    with pytest.raises(PublisherError, match=reason):
        publisher.export_unsigned(
            funding_txid=FUNDING_TXID, funding_vout=FUNDING_VOUT,
            change_address=TEST_ADDRESS, fee_sats=FEE_SATS,
            woc_base=base_url, network="testnet", request_fn=woc.request,
        )
    with pytest.raises(PublisherError, match=reason):
        publisher.broadcast_signed(
            signed_hex="00", funding_txid=FUNDING_TXID,
            funding_vout=FUNDING_VOUT, change_address=TEST_ADDRESS,
            fee_sats=FEE_SATS, woc_base=base_url, network="testnet",
            request_fn=woc.request,
        )
    assert woc.gets == []
    assert woc.posts == []
    assert not (tmp_path / "anchors.json").exists()


def test_export_refuses_funding_not_paying_to_change_address(tmp_path):
    woc = _FakeWoC()
    other = WIFSigner(PrivKey(int.from_bytes(b"\x33" * 32, "big")))
    with pytest.raises(PublisherError, match="does not pay to"):
        _export(
            _publisher(tmp_path), woc,
            change_address=other.address(network="testnet"),
        )


def test_export_refuses_insufficient_funding(tmp_path):
    woc = _FakeWoC()
    with pytest.raises(PublisherError, match="insufficient funds"):
        _export(_publisher(tmp_path), woc, fee_sats=FUNDING_VALUE + 1)


# --- broadcast-signed -----------------------------------------------------


def _broadcast(publisher, woc, signed_hex, *, fee_sats=FEE_SATS):
    return publisher.broadcast_signed(
        signed_hex=signed_hex,
        funding_txid=FUNDING_TXID,
        funding_vout=FUNDING_VOUT,
        change_address=TEST_ADDRESS,
        fee_sats=fee_sats,
        woc_base="https://woc.example",
        request_fn=woc.request,
    )


def test_broadcast_signed_happy_path_broadcasts_exact_hex(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc)
    signed_hex = _sign(exported["unsigned_hex"])
    expected_txid = parse_tx(bytes.fromhex(signed_hex)).txid()
    record = _broadcast(publisher, woc, signed_hex)
    assert record["status"] == "broadcast"
    assert record["txid"] == expected_txid
    assert woc.posts == [signed_hex]
    # The store agrees with the returned record.
    store = json.loads((tmp_path / "anchors.json").read_text())
    assert store["anchors"][-1]["status"] == "broadcast"
    assert store["anchors"][-1]["txid"] == expected_txid


def test_broadcast_signed_refuses_outputs_differ(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc)
    tx = parse_tx(bytes.fromhex(_sign(exported["unsigned_hex"])))
    tx.outputs[1].value += 1  # tamper: change value no longer matches
    with pytest.raises(PublisherError, match="does not match"):
        _broadcast(publisher, woc, tx.serialize().hex())
    assert woc.posts == []


def test_broadcast_signed_refuses_wrong_utxo(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc)
    tx = parse_tx(bytes.fromhex(_sign(exported["unsigned_hex"])))
    tx.inputs[0].prev_txid = "bb" * 32  # spends a different outpoint
    with pytest.raises(PublisherError, match="does not match"):
        _broadcast(publisher, woc, tx.serialize().hex())
    assert woc.posts == []


def test_broadcast_signed_refuses_wrong_change_address(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc)
    tx = parse_tx(bytes.fromhex(_sign(exported["unsigned_hex"])))
    other_key = PrivKey(int.from_bytes(b"\x33" * 32, "big"))
    tx.outputs[1].script = build_p2pkh_script(other_key.pubkey_compressed())
    with pytest.raises(PublisherError, match="does not match"):
        _broadcast(publisher, woc, tx.serialize().hex())
    assert woc.posts == []


def test_broadcast_signed_refuses_bad_signature(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc)
    tx = parse_tx(bytes.fromhex(_sign(exported["unsigned_hex"])))
    # Flip a byte inside the DER signature: still parses, no longer valid.
    sig = bytearray(tx.inputs[0].script_sig)
    sig[-40] ^= 0x01
    tx.inputs[0].script_sig = bytes(sig)
    with pytest.raises(PublisherError, match="signature"):
        _broadcast(publisher, woc, tx.serialize().hex())
    assert woc.posts == []


def test_broadcast_signed_refuses_wrong_sighash_type(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc)
    tx = parse_tx(bytes.fromhex(_sign(exported["unsigned_hex"])))
    # Replace the SIGHASH_ALL|FORKID byte with plain SIGHASH_ALL.
    sig = bytearray(tx.inputs[0].script_sig)
    # script_sig = push(der + hashtype) + push(pubkey); hashtype sits
    # right before the pubkey push length byte.
    sig[1 + sig[0] - 1] = 0x01
    tx.inputs[0].script_sig = bytes(sig)
    with pytest.raises(PublisherError, match="sighash"):
        _broadcast(publisher, woc, tx.serialize().hex())
    assert woc.posts == []


def test_broadcast_signed_refuses_malformed_hex(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    _export(publisher, woc)
    for bad in ("not hex", "00", "abcd", "zz" * 10):
        with pytest.raises(PublisherError):
            _broadcast(publisher, woc, bad)
    # Valid tx plus trailing bytes.
    exported = _export(publisher, woc)
    with pytest.raises(PublisherError):
        _broadcast(publisher, woc, _sign(exported["unsigned_hex"]) + "00")
    assert woc.posts == []


def test_broadcast_signed_refuses_mainnet(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc)
    signed_hex = _sign(exported["unsigned_hex"])
    with pytest.raises(PublisherError, match="mainnet"):
        publisher.broadcast_signed(
            signed_hex=signed_hex,
            funding_txid=FUNDING_TXID, funding_vout=FUNDING_VOUT,
            change_address=TEST_ADDRESS, fee_sats=FEE_SATS,
            woc_base="https://woc.example", network="mainnet",
            request_fn=woc.request,
        )
    assert woc.posts == []


def test_broadcast_signed_retry_is_idempotent(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc)
    signed_hex = _sign(exported["unsigned_hex"])
    expected_txid = parse_tx(bytes.fromhex(signed_hex)).txid()
    first = _broadcast(publisher, woc, signed_hex)
    second = _broadcast(publisher, woc, signed_hex)
    assert first["txid"] == second["txid"] == expected_txid
    assert woc.posts == [signed_hex, signed_hex]


def test_broadcast_signed_refuses_different_tx_for_broadcast_head(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc)
    signed_hex = _sign(exported["unsigned_hex"])
    _broadcast(publisher, woc, signed_hex)
    # A malleated signature is valid for the same unsigned tx but yields
    # a different txid — refusing it proves the idempotency guard keys
    # on the txid, not just on the unsigned template.
    with pytest.raises(PublisherError, match="already broadcast"):
        _broadcast(publisher, woc, _malleate_sig(signed_hex))
    assert len(woc.posts) == 1


def test_broadcast_signed_refuses_echoed_txid_mismatch(tmp_path):
    # The network echoes a txid that is not the verified tx's txid:
    # the publisher must not record a txid that is not the tx it
    # verified, so it refuses and leaves the record pending.
    woc = _FakeWoC(post_body='"' + "dd" * 32 + '"')
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc)
    signed_hex = _sign(exported["unsigned_hex"])
    with pytest.raises(PublisherError, match="match"):
        _broadcast(publisher, woc, signed_hex)
    store = json.loads((tmp_path / "anchors.json").read_text())
    assert store["anchors"][-1]["status"] == "pending"
    assert store["anchors"][-1]["txid"] is None


def test_broadcast_signed_refuses_fee_mismatch_with_export(tmp_path):
    woc = _FakeWoC()
    publisher = _publisher(tmp_path)
    exported = _export(publisher, woc, fee_sats=500)
    signed_hex = _sign(exported["unsigned_hex"])
    # Broadcast with a different fee rebuilds a different expected
    # unsigned tx, so the signed tx no longer matches.
    with pytest.raises(PublisherError, match="does not match"):
        _broadcast(publisher, woc, signed_hex, fee_sats=600)
    assert woc.posts == []


# --- CLI ------------------------------------------------------------------


def test_cli_export_writes_unsigned_hex_and_prints_summary(
    tmp_path, monkeypatch, capsys
):
    from sealrun import cli as cli_mod
    from sealrun import broadcast as broadcast_mod

    journal = _journal(tmp_path)
    record_path = tmp_path / "anchors.json"
    out_file = tmp_path / "unsigned.hex"
    woc = _FakeWoC()
    monkeypatch.setattr(broadcast_mod, "_urllib_request", woc.request)
    rc = cli_mod.main([
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(record_path),
        "--export-unsigned", str(out_file),
        "--funding-txid", FUNDING_TXID,
        "--funding-vout", str(FUNDING_VOUT),
        "--change-address", TEST_ADDRESS,
        "--woc-base", "https://woc.example",
    ])
    assert rc == 0
    unsigned_hex = out_file.read_text().strip()
    unsigned = parse_tx(bytes.fromhex(unsigned_hex))
    assert unsigned.inputs[0].script_sig == b""
    out = capsys.readouterr().out
    assert unsigned.txid() in out
    assert "head_hash" in out
    assert woc.posts == []


def test_cli_export_refuses_signing_material(tmp_path, monkeypatch):
    from sealrun import cli as cli_mod

    journal = _journal(tmp_path)
    monkeypatch.setenv("ANCHOR_WIF", "cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw")
    rc = cli_mod.main([
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(tmp_path / "anchors.json"),
        "--export-unsigned", str(tmp_path / "unsigned.hex"),
        "--funding-txid", FUNDING_TXID,
        "--change-address", TEST_ADDRESS,
    ])
    assert rc == 1


def test_cli_export_refuses_mainnet_and_broadcast_combo(tmp_path, monkeypatch):
    from sealrun import cli as cli_mod

    journal = _journal(tmp_path)
    base = [
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(tmp_path / "anchors.json"),
        "--export-unsigned", str(tmp_path / "unsigned.hex"),
        "--funding-txid", FUNDING_TXID,
        "--change-address", TEST_ADDRESS,
    ]
    monkeypatch.delenv("ANCHOR_WIF", raising=False)
    assert cli_mod.main(base + ["--network", "mainnet"]) == 1
    monkeypatch.setenv("ANCHOR_WIF", "cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw")
    assert cli_mod.main(base + ["--broadcast"]) == 1


def test_cli_broadcast_signed_broadcasts_and_records(
    tmp_path, monkeypatch, capsys
):
    from sealrun import cli as cli_mod
    from sealrun import broadcast as broadcast_mod

    journal = _journal(tmp_path)
    record_path = tmp_path / "anchors.json"
    unsigned_file = tmp_path / "unsigned.hex"
    signed_file = tmp_path / "signed.hex"
    woc = _FakeWoC()
    monkeypatch.setattr(broadcast_mod, "_urllib_request", woc.request)
    monkeypatch.delenv("ANCHOR_WIF", raising=False)
    assert cli_mod.main([
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(record_path),
        "--export-unsigned", str(unsigned_file),
        "--funding-txid", FUNDING_TXID,
        "--funding-vout", str(FUNDING_VOUT),
        "--change-address", TEST_ADDRESS,
        "--woc-base", "https://woc.example",
    ]) == 0
    signed_hex = _sign(unsigned_file.read_text().strip())
    expected_txid = parse_tx(bytes.fromhex(signed_hex)).txid()
    signed_file.write_text(signed_hex)
    rc = cli_mod.main([
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(record_path),
        "--broadcast-signed", str(signed_file),
        "--funding-txid", FUNDING_TXID,
        "--funding-vout", str(FUNDING_VOUT),
        "--change-address", TEST_ADDRESS,
        "--woc-base", "https://woc.example",
    ])
    assert rc == 0
    store = json.loads(record_path.read_text())
    assert store["anchors"][-1]["status"] == "broadcast"
    assert store["anchors"][-1]["txid"] == expected_txid
    out = capsys.readouterr().out
    assert expected_txid in out


def test_cli_broadcast_signed_refuses_signing_material(tmp_path, monkeypatch):
    from sealrun import cli as cli_mod

    journal = _journal(tmp_path)
    monkeypatch.setenv("ANCHOR_WIF", "cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw")
    rc = cli_mod.main([
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(tmp_path / "anchors.json"),
        "--broadcast-signed", str(tmp_path / "signed.hex"),
        "--funding-txid", FUNDING_TXID,
        "--change-address", TEST_ADDRESS,
    ])
    assert rc == 1


def test_export_payload_summary_matches_decoded_record(tmp_path):
    woc = _FakeWoC()
    result = _export(_publisher(tmp_path), woc)
    decoded = decode_anchor_payload(bytes.fromhex(result["record"]["payload_hex"]))
    assert result["payload"] == decoded
