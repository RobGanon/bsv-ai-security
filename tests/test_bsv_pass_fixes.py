"""Regression tests for the BSV adversarial-pass findings F1–F4.

F1: exception escapes from fail-closed verifiers — hostile fetcher data
must yield verified=False / fail-closed errors, never a raw exception.
F2: CLI anchor-chain-verify must exit 1 on failed checks and on a
vacuous (0-anchor) verification, and must warn when acceptance binding
was not re-checked.
F3: BEEF ancestry must reject consensus-invalid unmined txs.
F4: negative prev_index must not read vout[-1].

F5 (prev-txid not validated) stays deferred and is NOT covered here.
"""

import copy
import json
import struct

import pytest

from sealrun.anchor import (
    AnchorSignatureVerifier,
    _tx_from_woc_json,
    encode_anchor_payload,
    verify_anchor_tx_signature,
)
from sealrun.beef import Beef, BeefTx, BeefVerifier
from sealrun.broadcast import (
    BroadcastRejected,
    FundingUTXO,
    WoCBroadcaster,
)
from sealrun.bsv import (
    Tx,
    TxIn,
    TxOut,
    _der_decode_signature,
    sats_from_btc_decimal,
    sighash_forkid,
)
from sealrun.cli import main
from sealrun.core import VerificationError, append_audit_event
from sealrun.spv import (
    BlockHeader,
    HeaderChainVerifier,
    SPVVerifier,
    verify_chain_to_checkpoint,
    verify_header,
    verify_header_chain,
)
from test_anchor_signature import (
    ANCHOR_PUBKEY,
    ANCHOR1_TX,
    FAUCET_TX,
    FAUCET_TX_JSON,
)

GENESIS = "aa" * 32
TXID_A = "11" * 32
TXID_B = "22" * 32
MAX_SATS = 2_100_000_000_000_000  # 21M BTC in satoshis


def _tx(vin_txids=("00" * 32,), vouts=(0,)):
    return Tx(
        1,
        [TxIn(t, 0, b"", 0xFFFFFFFF) for t in vin_txids],
        [TxOut(v, b"") for v in vouts],
        0,
    )


def _anchor_file(tmp_path, txid=TXID_A):
    payload = encode_anchor_payload(
        head_hash="ab" * 32, start_seq=1, end_seq=1,
        release_seq=0, prev_txid=GENESIS,
    )
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps({"payload_hex": payload.hex(), "txid": txid}))
    return path


class _FakeFetcher:
    """First fetch returns the anchor tx; later fetches return the prev tx.

    Mirrors verify_signature's flow (anchor fetch, then prev-tx fetch).
    """

    def __init__(self, anchor_tx, prev_tx):
        self.anchor_tx = anchor_tx
        self.prev_tx = prev_tx
        self.calls = 0

    def fetch_tx_full(self, txid):
        self.calls += 1
        if self.calls == 1:
            return copy.deepcopy(self.anchor_tx)
        return copy.deepcopy(self.prev_tx)


# ---------------------------------------------------------------------------
# F1 — exception escapes
# ---------------------------------------------------------------------------


def test_f1_der_decode_rejects_oversized_r_len():
    # total=8, len=10, sig[2]==0x02, r_len=250 -> s_pos=254, out of bounds.
    bad = b"\x30\x08\x02\xfa" + b"\x00" * 6
    assert len(bad) == 10
    with pytest.raises(ValueError):
        _der_decode_signature(bad)


def test_f1_sighash_rejects_negative_prev_value():
    with pytest.raises(ValueError):
        sighash_forkid(_tx(), 0, b"", -1)


def test_f1_sighash_rejects_prev_value_above_consensus_max():
    with pytest.raises(ValueError):
        sighash_forkid(_tx(), 0, b"", MAX_SATS + 1)
    with pytest.raises(ValueError):
        sighash_forkid(_tx(), 0, b"", 10**26)


def test_f1_sats_rejects_above_consensus_max():
    with pytest.raises(ValueError):
        sats_from_btc_decimal(10**18)
    with pytest.raises(ValueError):
        sats_from_btc_decimal("21000000.00000001")
    assert sats_from_btc_decimal("21000000") == MAX_SATS


@pytest.mark.parametrize("value", [
    "-1e-999999999",
    "0.000000009999999999999999999999999999999999",
    "21000000.000000000000000000000000000000000001",
    "1e999999999",
])
def test_f1_sats_never_rounds_invalid_values_into_range(value):
    with pytest.raises(ValueError):
        sats_from_btc_decimal(value)


def test_f1_tx_from_woc_json_rejects_out_of_range_ints():
    base = copy.deepcopy(ANCHOR1_TX)
    bad = copy.deepcopy(base)
    bad["version"] = 2**40
    with pytest.raises(VerificationError):
        _tx_from_woc_json(bad)
    bad = copy.deepcopy(base)
    bad["locktime"] = 2**40
    with pytest.raises(VerificationError):
        _tx_from_woc_json(bad)
    bad = copy.deepcopy(base)
    bad["vin"][0]["sequence"] = -1
    with pytest.raises(VerificationError):
        _tx_from_woc_json(bad)
    bad = copy.deepcopy(base)
    bad["vin"][0]["vout"] = -1
    with pytest.raises(VerificationError):
        _tx_from_woc_json(bad)
    bad = copy.deepcopy(base)
    bad["vin"][0]["vout"] = 2**32
    with pytest.raises(VerificationError):
        _tx_from_woc_json(bad)


@pytest.mark.parametrize("field", ["version", "locktime", "vout", "sequence"])
def test_f1_signature_apis_fail_closed_on_infinite_integer_fields(field):
    anchor = copy.deepcopy(ANCHOR1_TX)
    if field in ("version", "locktime"):
        anchor[field] = float("inf")
    else:
        anchor["vin"][0][field] = float("inf")

    direct = verify_anchor_tx_signature(anchor, FAUCET_TX_JSON, ANCHOR_PUBKEY)
    assert direct["verified"] is False
    wrapped = AnchorSignatureVerifier(
        _FakeFetcher(anchor, FAUCET_TX_JSON), ANCHOR_PUBKEY
    ).verify_signature(TXID_A)
    assert wrapped.verified is False


def test_f1_verifier_signature_returns_false_on_huge_version():
    anchor = copy.deepcopy(ANCHOR1_TX)
    anchor["version"] = 2**40
    verifier = AnchorSignatureVerifier(
        _FakeFetcher(anchor, FAUCET_TX_JSON), ANCHOR_PUBKEY
    )
    result = verifier.verify_signature(TXID_A)
    assert result.verified is False


def test_f1_verifier_signature_returns_false_on_huge_locktime():
    anchor = copy.deepcopy(ANCHOR1_TX)
    anchor["locktime"] = 2**40
    verifier = AnchorSignatureVerifier(
        _FakeFetcher(anchor, FAUCET_TX_JSON), ANCHOR_PUBKEY
    )
    result = verifier.verify_signature(TXID_A)
    assert result.verified is False


def test_f1_verifier_signature_returns_false_on_nonhex_prev_txid():
    anchor = copy.deepcopy(ANCHOR1_TX)
    anchor["vin"][0]["txid"] = "zz" * 32
    verifier = AnchorSignatureVerifier(
        _FakeFetcher(anchor, FAUCET_TX_JSON), ANCHOR_PUBKEY
    )
    result = verifier.verify_signature(TXID_A)
    assert result.verified is False


def test_f1_verifier_signature_returns_false_on_bad_der_sig():
    anchor = copy.deepcopy(ANCHOR1_TX)
    bad_der = b"\x30\x08\x02\xfa" + b"\x00" * 6
    pubkey = bytes.fromhex(ANCHOR_PUBKEY)
    script_sig = bytes([len(bad_der) + 1]) + bad_der + b"\x41"
    script_sig += bytes([len(pubkey)]) + pubkey
    anchor["vin"][0]["scriptSig"]["hex"] = script_sig.hex()
    # Request the recomputed txid so the PR #31 txid check passes and
    # the DER path is actually exercised.
    anchor_txid = _tx_from_woc_json(anchor).txid()
    verifier = AnchorSignatureVerifier(
        _FakeFetcher(anchor, FAUCET_TX_JSON), ANCHOR_PUBKEY
    )
    result = verifier.verify_signature(anchor_txid)
    assert result.verified is False


def test_f1_header_chain_rejects_huge_version():
    header = BlockHeader(
        version=2**32, prev_hash="00" * 32, merkle_root="00" * 32,
        time=0, bits=0x1D00FFFF, nonce=0, height=1, hash="00" * 32,
    )
    assert verify_header_chain([header]) is False


def test_f1_verify_header_rejects_none_expected_hash():
    assert verify_header(b"\x00" * 80, None, 0x1D00FFFF) is False


def test_f1_chain_to_checkpoint_rejects_none_tip_hash():
    verified, checked, _reason = verify_chain_to_checkpoint(
        None, tip_height=1, tip_hash=None,
        checkpoint_hash="00" * 32, checkpoint_height=1,
    )
    assert verified is False
    assert checked == 0


def test_f1_spv_rejects_noninteger_blockheight():
    class Fetcher:
        def fetch_tx(self, txid):
            return {"blockheight": "abc", "blockhash": "00" * 32}

        def fetch_block(self, height):
            raise AssertionError("must not be reached")

    result = SPVVerifier(Fetcher()).verify_inclusion(TXID_A)
    assert result.verified is False


def test_f1_spv_rejects_nonhex_block_txids():
    # The target txid IS present, so the index lookup succeeds and the
    # Merkle path builder must touch the non-hex sibling entry.
    header = BlockHeader(
        version=1, prev_hash="00" * 32, merkle_root=TXID_A,
        time=0, bits=0x1D00FFFF, nonce=0, height=1, hash="11" * 32,
    )

    class Fetcher:
        def fetch_tx(self, txid):
            return {"blockheight": 1, "blockhash": "11" * 32}

        def fetch_block(self, height):
            return header, [TXID_A, "not-hex!!"]

    result = SPVVerifier(Fetcher()).verify_inclusion(TXID_A)
    assert result.verified is False


def test_f1_spv_rejects_nonhex_prev_hash():
    # Single-tx block: merkle root == txid, so the Merkle check passes
    # and the header serialization (which reads prev_hash) is reached.
    header = BlockHeader(
        version=1, prev_hash="zz-non-hex", merkle_root=TXID_A,
        time=0, bits=0x1D00FFFF, nonce=0, height=1, hash="11" * 32,
    )

    class Fetcher:
        def fetch_tx(self, txid):
            return {"blockheight": 1, "blockhash": "11" * 32}

        def fetch_block(self, height):
            return header, [TXID_A]

    result = SPVVerifier(Fetcher()).verify_inclusion(TXID_A)
    assert result.verified is False


def test_f1_header_chain_verifier_rejects_noninteger_blockheight():
    class Fetcher:
        def fetch_tx(self, txid):
            return {"blockheight": "abc", "blockhash": "00" * 32}

    result = HeaderChainVerifier(
        Fetcher(), checkpoint_hash="00" * 32, checkpoint_height=1
    ).verify_chain_for_tx(TXID_A)
    assert result.verified is False


def _payload_hex():
    payload = encode_anchor_payload(
        head_hash="ab" * 32, start_seq=1, end_seq=1,
        release_seq=0, prev_txid=GENESIS,
    )
    return payload.hex()


def _broadcaster(funding, request_fn):
    class StubSigner:
        def sign(self, digest):
            return b"\x00" * 71

        def pubkey_compressed(self):
            return bytes.fromhex(ANCHOR_PUBKEY)

        def address(self, network="testnet"):
            return "mjkFEqit3Ns7eH29kT2qWNpVwnNqNTJsFV"

    return WoCBroadcaster(
        base_url="http://127.0.0.1:9",
        network="testnet",
        signer=StubSigner(),
        funding=funding,
        request_fn=request_fn,
    )


def test_f1_broadcaster_rejects_negative_funding_vout():
    def request_fn(method, url, body):
        assert method == "GET"
        return 200, json.dumps({
            "vout": [{
                "value": 0.001,
                "scriptPubKey": {"hex": "76a9142e640e26bcb812790c2517d49d660c44e1b3ae6c88ac"},
            }],
        }).encode()

    broadcaster = _broadcaster(
        FundingUTXO(txid=FAUCET_TX, vout=-1, value=0, script_hex=""),
        request_fn,
    )
    with pytest.raises(BroadcastRejected):
        broadcaster.broadcast(_payload_hex())


def test_f1_broadcaster_enforces_https_base():
    """Regression (A31): WoCBroadcaster accepted plaintext HTTP, so
    broadcast prev-tx fetches could travel unencrypted."""

    class StubSigner:
        def sign(self, digest):
            return b"\x00" * 71

        def pubkey_compressed(self):
            return bytes.fromhex(ANCHOR_PUBKEY)

        def address(self, network="testnet"):
            return "mjkFEqit3Ns7eH29kT2qWNpVwnNqNTJsFV"

    def request_fn(method, url, body):
        raise AssertionError("unreachable")

    funding = FundingUTXO(txid=FAUCET_TX, vout=0, value=0, script_hex="")
    with pytest.raises(ValueError, match="https"):
        WoCBroadcaster(
            base_url="http://api.example.com/v1",
            network="testnet",
            signer=StubSigner(),
            funding=funding,
            request_fn=request_fn,
        )
    ok = WoCBroadcaster(
        base_url="https://api.example.com/v1",
        network="testnet",
        signer=StubSigner(),
        funding=funding,
        request_fn=request_fn,
    )
    assert ok.base_url == "https://api.example.com/v1"


def test_f1_cli_returns_1_not_traceback_on_struct_error(monkeypatch):
    import sealrun.cli as cli_mod

    class BoomFetcher:
        def __init__(self, base_url=None):
            pass

        def fetch_tx(self, txid):
            raise struct.error("boom")

        def fetch_block(self, height):
            raise AssertionError("unreachable")

    monkeypatch.setattr(cli_mod, "WoCBlockFetcher", BoomFetcher)
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        anchor = os.path.join(tmp, "anchor.json")
        with open(anchor, "w", encoding="utf-8") as fh:
            payload = encode_anchor_payload(
                head_hash="ab" * 32, start_seq=1, end_seq=1,
                release_seq=0, prev_txid=GENESIS,
            )
            json.dump({"payload_hex": payload.hex(), "txid": TXID_A}, fh)
        assert main([
            "anchor-chain-verify",
            "--genesis-txid", GENESIS,
            "--anchor", anchor,
            "--spv",
        ]) == 1


# ---------------------------------------------------------------------------
# F2 — CLI exit codes / warnings
# ---------------------------------------------------------------------------


def test_f2_cli_sig_failure_returns_1(tmp_path, capsys):
    anchor = _anchor_file(tmp_path)
    assert main([
        "anchor-chain-verify",
        "--genesis-txid", GENESIS,
        "--anchor", str(anchor),
        "--anchor-sig",
        "--anchor-pubkey", ANCHOR_PUBKEY,
        "--woc-base", "http://127.0.0.1:9",
    ]) == 1
    assert "ANCHOR SIGNATURE CHECK FAILED" in capsys.readouterr().out


def test_f2_cli_spv_failure_returns_1(tmp_path, capsys):
    anchor = _anchor_file(tmp_path)
    assert main([
        "anchor-chain-verify",
        "--genesis-txid", GENESIS,
        "--anchor", str(anchor),
        "--spv",
        "--woc-base", "http://127.0.0.1:9",
    ]) == 1


def test_f2_cli_bump_failure_returns_1(tmp_path, capsys):
    anchor = _anchor_file(tmp_path)
    bump_file = tmp_path / "bump.json"
    bump_file.write_text(json.dumps({TXID_A: {}}))
    assert main([
        "anchor-chain-verify",
        "--genesis-txid", GENESIS,
        "--anchor", str(anchor),
        "--bump-file", str(bump_file),
    ]) == 1
    assert "BUMP INCLUSION CHECK FAILED" in capsys.readouterr().out


def test_f2_cli_header_chain_failure_returns_1(tmp_path, capsys):
    anchor = _anchor_file(tmp_path)
    assert main([
        "anchor-chain-verify",
        "--genesis-txid", GENESIS,
        "--anchor", str(anchor),
        "--header-chain",
        "--checkpoint-hash", "00" * 32,
        "--checkpoint-height", "1",
        "--woc-base", "http://127.0.0.1:9",
    ]) == 1
    assert "HEADER CHAIN CHECK FAILED" in capsys.readouterr().out


def test_f2_cli_empty_anchor_list_returns_1(capsys):
    assert main(["anchor-chain-verify", "--genesis-txid", GENESIS]) == 1
    assert "no anchors" in capsys.readouterr().err.lower()


def test_f2_cli_valid_chain_still_returns_0(tmp_path):
    anchor = _anchor_file(tmp_path)
    assert main([
        "anchor-chain-verify",
        "--genesis-txid", GENESIS,
        "--anchor", str(anchor),
    ]) == 0


def test_f2_cli_journal_without_binding_warns(tmp_path, capsys):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    from sealrun.anchor import create_anchor_payload

    payload = create_anchor_payload(journal, start_seq=1, prev_txid=GENESIS)
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps({
        "payload_hex": payload["payload_hex"], "txid": TXID_A,
    }))
    assert main([
        "anchor-chain-verify",
        "--genesis-txid", GENESIS,
        "--anchor", str(anchor),
        "--journal", str(journal),
    ]) == 0
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "binding" in out.lower()


def test_f2_cli_anchor_verify_without_binding_warns(tmp_path, capsys):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    payload_file = tmp_path / "payload.json"
    assert main([
        "anchor-payload",
        "--journal", str(journal),
        "--start-seq", "1",
        "--output", str(payload_file),
    ]) == 0
    capsys.readouterr()
    assert main([
        "anchor-verify",
        "--journal", str(journal),
        "--payload", str(payload_file),
    ]) == 0
    assert "WARNING" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# F3 — BEEF ancestry consensus-validity
# ---------------------------------------------------------------------------


def _beef_with(anchor_txid, extra_txs):
    """Envelope: mined anchor (with BUMP) + the given unmined txs."""
    from test_beef import _ttn_beef

    from sealrun.spv import build_bump
    from test_spv import BLOCK_36722

    bump = build_bump(BLOCK_36722["tx"], [2], block_height=36722)
    beef0, _a, _c = _ttn_beef()
    txs = (beef0.txs[0],) + tuple(
        BeefTx(raw=tx.serialize(), txid=tx.txid(), bump_index=None)
        for tx in extra_txs
    )
    return Beef(bumps=(bump,), txs=txs)


def test_f3_beef_rejects_duplicate_inputs():
    script = bytes.fromhex("76a9142e640e26bcb812790c2517d49d660c44e1b3ae6c88ac")
    anchor_txid = "4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029"
    # Child spends the same anchor output twice; conservation holds
    # (2x99500 == 199000) only because the input is double-counted.
    child = Tx(
        1, [TxIn(anchor_txid, 1, b"", 0xFFFFFFFF),
            TxIn(anchor_txid, 1, b"", 0xFFFFFFFF)],
        [TxOut(199000, script)], 0,
    )
    verdict = BeefVerifier(_HeaderFetcher()).verify_beef(_beef_with(anchor_txid, [child]))
    assert verdict.verified is False


def test_f3_beef_rejects_zero_input_zero_output():
    beef = _beef_with("00" * 32, [Tx(1, [], [], 0)])
    verdict = BeefVerifier(_HeaderFetcher()).verify_beef(beef)
    assert verdict.verified is False


def test_f3_beef_rejects_negative_output():
    from test_beef import _ttn_beef

    script = bytes.fromhex("76a9142e640e26bcb812790c2517d49d660c44e1b3ae6c88ac")
    anchor_txid = "4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029"
    # Parent spends the mined anchor's change output but carries a -50
    # sat output; the child spends the -50 output plus the 200 output
    # and outputs 150, so conservation holds only via the negative output.
    parent = Tx(
        1, [TxIn(anchor_txid, 1, b"", 0xFFFFFFFF)],
        [TxOut(-50, script), TxOut(200, script)], 0,
    )
    child = Tx(
        1, [TxIn(parent.txid(), 0, b"", 0xFFFFFFFF),
            TxIn(parent.txid(), 1, b"", 0xFFFFFFFF)],
        [TxOut(150, script)], 0,
    )
    beef0, _a, _c = _ttn_beef()
    from sealrun.spv import build_bump
    from test_spv import BLOCK_36722

    bump = build_bump(BLOCK_36722["tx"], [2], block_height=36722)
    beef = Beef(
        bumps=(bump,),
        txs=(beef0.txs[0],
             BeefTx(raw=parent.serialize(), txid=parent.txid(), bump_index=None),
             BeefTx(raw=child.serialize(), txid=child.txid(), bump_index=None)),
    )
    verdict = BeefVerifier(_HeaderFetcher()).verify_beef(beef)
    assert verdict.verified is False


class _HeaderFetcher:
    def fetch_header(self, height):
        from test_beef import _header_36722

        return _header_36722()


# ---------------------------------------------------------------------------
# F4 — negative prev_index
# ---------------------------------------------------------------------------


def test_f4_anchor_sig_rejects_negative_prev_index():
    anchor = copy.deepcopy(ANCHOR1_TX)
    anchor["vin"][0]["vout"] = -1
    # vout[-1] is the real funding output; vout[0] is garbage. A verifier
    # that reads vout[-1] proceeds; a correct one rejects the index.
    prev = copy.deepcopy(FAUCET_TX_JSON)
    prev["vout"] = [
        {"value": 999.0, "scriptPubKey": {"hex": "6a00"}},
        {"value": 0.001, "scriptPubKey": {
            "hex": "76a9142e640e26bcb812790c2517d49d660c44e1b3ae6c88ac"}},
    ]
    result = verify_anchor_tx_signature(anchor, prev, ANCHOR_PUBKEY)
    assert result["verified"] is False


def test_f4_beef_rejects_negative_prev_index():
    # A negative prev_index cannot appear on the wire (parse reads
    # uint32), so this exercises _verify_ancestry directly with a
    # hand-built Tx — defense-in-depth, same as the adversarial probe.
    from test_beef import _ttn_beef

    from sealrun.bsv import parse_tx_prefix

    script = bytes.fromhex("76a9142e640e26bcb812790c2517d49d660c44e1b3ae6c88ac")
    anchor_txid = "4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029"
    child = Tx(
        1, [TxIn(anchor_txid, -1, b"", 0xFFFFFFFF)],
        [TxOut(99000, script)], 0,
    )
    beef0, _a, _c = _ttn_beef()
    anchor_parsed, _consumed = parse_tx_prefix(beef0.txs[0].raw)
    verifier = BeefVerifier(_HeaderFetcher())
    by_txid = {
        anchor_txid.lower(): beef0.txs[0],
        "child": BeefTx(raw=b"", txid="child", bump_index=None),
    }
    parsed = {anchor_txid.lower(): anchor_parsed, "child": child}
    memo = {anchor_txid.lower(): True}  # anchor passed its BUMP proof
    result = verifier._verify_ancestry(
        "child", by_txid, parsed, {}, {}, memo, set()
    )
    assert result is False
