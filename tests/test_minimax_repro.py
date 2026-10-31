"""Repro tests for MiniMax findings 1-3 (Oct 26, 2026), written by BB.

These tests encode the FIXED behaviour, so they must FAIL on held main
a3fd789b and PASS after the fix. They are repros, not yet the final
regression tests (which will live in test_payload_binding.py /
test_beef.py after review of the fix shape).
"""
import copy
import json

from sealrun.anchor import (
    _tx_from_woc_json,
    apply_payload_binding,
    encode_anchor_payload,
    verify_anchor_chain,
)
from sealrun.beef import Beef, BeefTx, BeefVerifier, apply_beef_inclusion, beef_to_bytes
from sealrun.bsv import Tx, TxIn, TxOut, build_op_return_script
from test_anchor_signature import ANCHOR1_TX, TX1
from test_beef import _header_36722, _ttn_beef

ZERO_TXID = "0" * 64


class FakeFetcher:
    def __init__(self, by_txid):
        self.by_txid = by_txid

    def fetch_tx_full(self, txid):
        return self.by_txid[txid.lower()]


def test_f1_payload_binding_txid_mismatch_must_fail():
    # Forged payload, requested txid = real anchor1 txid, provider serves
    # a DIFFERENT tx body (real anchor1 tx with its OP_RETURN swapped
    # to the forged payload) under TX1's URL.
    forged = encode_anchor_payload(
        head_hash="22" * 32, start_seq=1, end_seq=3, release_seq=0, prev_txid=ZERO_TXID
    )
    modified = copy.deepcopy(ANCHOR1_TX)
    modified["vout"][0]["scriptPubKey"]["hex"] = build_op_return_script(forged).hex()
    # Prove the served body does NOT hash to the requested txid.
    assert _tx_from_woc_json(modified).txid() != TX1.lower()
    result = verify_anchor_chain([(forged, TX1)], ZERO_TXID)
    bound = apply_payload_binding(result, FakeFetcher({TX1.lower(): modified}))
    assert bound["payload_binding_verified"] is False


def test_f2_beef_ancestry_only_must_not_count_as_inclusion():
    beef, anchor_txid, child_txid = _ttn_beef()
    # Anchor = the child tx, which verifies by ancestry only.
    chain_result = {"chain": {"anchors": [{"txid": child_txid}]}}
    out = apply_beef_inclusion(
        chain_result, BeefVerifier(_HeaderFetcher(header=_header_36722())), beef
    )
    per = out["chain"]["anchors"][0]["beef_inclusion"]
    assert per["status"] == "ancestry"
    assert per["blockheight"] is None
    assert out["beef_inclusion_verified"] is False


class _HeaderFetcher:
    def __init__(self, header=None):
        self.header = header

    def fetch_header(self, height):
        return self.header


def test_f3_beef_envelope_overall_failure_must_block_inclusion():
    beef, anchor_txid, child_txid = _ttn_beef()
    # Unrelated tx with a BUMP claim that cannot verify: raw tx not in
    # the BUMP's leaf set, so its per-tx verdict is failed.
    bad_tx = Tx(
        1,
        [TxIn(anchor_txid, 0, b"", 0xFFFFFFFF)],
        [TxOut(1000, bytes.fromhex("76a9142e640e26bcb812790c2517d49d660c44e1b3ae6c88ac"))],
        0,
    )
    bad_raw = bad_tx.serialize()
    bad_txid = bad_tx.txid()
    bad_beef = Beef(
        bumps=beef.bumps,
        txs=beef.txs + (BeefTx(raw=bad_raw, txid=bad_txid, bump_index=0),),
    )
    verifier = BeefVerifier(_HeaderFetcher(header=_header_36722()))
    verdict = verifier.verify_beef(bad_beef)
    assert verdict.verified is False
    assert verdict.per_tx[bad_txid]["verified"] is False
    assert verdict.per_tx[anchor_txid]["verified"] is True
    chain_result = {"chain": {"anchors": [{"txid": anchor_txid}]}}
    out = apply_beef_inclusion(chain_result, verifier, bad_beef)
    assert out["beef_inclusion_verified"] is False
