"""Tests for header-chain sync (protocol §6: chain back to a checkpoint).

Fixtures: the real Teratestnet headers 36721–36723, recorded live
from WoC-TTN 2026-10-16. Block 36722 holds live anchor #1, block
36723 holds live anchor #2; 36721 is the checkpoint used below.
"""
import copy
import json

import pytest

from sealrun.anchor import apply_header_chain, encode_anchor_payload, verify_anchor_chain
from sealrun.spv import (
    BlockHeader,
    HeaderChainResult,
    HeaderChainVerifier,
    SPVUnavailable,
    verify_chain_to_checkpoint,
)

TX1 = "4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029"
TX2 = "d8407bb7a60f23aadcf021e9cb0098c6ae362a519aa04cbd8536265519c09230"

BLOCK_36721 = {
    "hash": "0000000048cb33f8f96e4927e4e8066742076b180d7091c013e7e36d4b246eae",
    "prev": "000000002f9d0b6a01c151cd796a9ce6fd6f9a967da4ed7a12ff4a83ef38d67a",
    "root": "63b2cda9b315b4532bf532ae2d9a0500a326a56597ae4ee7dbed1bad77ffe0d6",
    "version": 536870912,
    "time": 1792196982,
    "bits": 0x1C55AD80,
    "nonce": 87798228,
}

BLOCK_36722 = {
    "hash": "000000001d8a81abcf3b84b3d610cb1cc9161dce73c8a1c2bb512ae27ef46daf",
    "prev": "0000000048cb33f8f96e4927e4e8066742076b180d7091c013e7e36d4b246eae",
    "root": "8e55225402e64109e0974b4e0dc810c4d4ca3c2e61800d7559e05d04d175f4bb",
    "version": 536870912,
    "time": 1792198024,
    "bits": 0x1C55DEB0,
    "nonce": 21614930,
}

BLOCK_36723 = {
    "hash": "0000000023615eaeee840cb73143947abb46069a58f1dcd77d544447297149d2",
    "prev": "000000001d8a81abcf3b84b3d610cb1cc9161dce73c8a1c2bb512ae27ef46daf",
    "root": "ba817c0213543c2e7ffbb9bc0c317017a3d165058d2e980f655a63ec7c650544",
    "version": 536870912,
    "time": 1792199107,
    "bits": 0x1C561092,
    "nonce": 1396520704,
}

BLOCKS = {36721: BLOCK_36721, 36722: BLOCK_36722, 36723: BLOCK_36723}
CHECKPOINT_HASH = BLOCK_36721["hash"]
CHECKPOINT_HEIGHT = 36721


def _header(block: dict, height: int) -> BlockHeader:
    return BlockHeader(
        version=block["version"],
        prev_hash=block["prev"],
        merkle_root=block["root"],
        time=block["time"],
        bits=block["bits"],
        nonce=block["nonce"],
        height=height,
        hash=block["hash"],
    )


class FakeHeaderFetcher:
    """Serves the recorded headers; knobs for adversarial cases."""

    def __init__(self, *, broken_link=False, pow_fail_tip=False,
                 fail_on=(), unconfirmed=()):
        self.broken_link = broken_link
        self.pow_fail_tip = pow_fail_tip
        self.fail_on = set(fail_on)
        self.unconfirmed = set(unconfirmed)

    def fetch_tx(self, txid):
        if txid in self.unconfirmed:
            return {"blockheight": None, "blockhash": None}
        if txid == TX1:
            return {"blockheight": 36722, "blockhash": BLOCK_36722["hash"]}
        if txid == TX2:
            if self.pow_fail_tip:
                # The tip header served below has tiny bits and a
                # recomputed hash; the tx lookup must agree with it
                # so the walk reaches the PoW check.
                return {"blockheight": 36723, "blockhash": self._pow_fail_hash()}
            return {"blockheight": 36723, "blockhash": BLOCK_36723["hash"]}
        return {"blockheight": None, "blockhash": None}

    def _pow_fail_hash(self):
        from sealrun.spv import header_hash

        header = self._pow_fail_header()
        return header_hash(header.to_bytes())

    def _pow_fail_header(self):
        block = BLOCK_36723
        return BlockHeader(
            version=block["version"], prev_hash=block["prev"],
            merkle_root=block["root"], time=block["time"],
            bits=0x03000001, nonce=block["nonce"],
            height=36723, hash=None,
        )

    def fetch_header(self, height):
        if height in self.fail_on:
            raise SPVUnavailable("boom")
        block = copy.deepcopy(BLOCKS[height])
        if self.broken_link and height == 36722:
            block["prev"] = "00" * 32
        if self.pow_fail_tip and height == 36723:
            header = self._pow_fail_header()
            return BlockHeader(
                version=header.version, prev_hash=header.prev_hash,
                merkle_root=header.merkle_root, time=header.time,
                bits=header.bits, nonce=header.nonce,
                height=height, hash=self._pow_fail_hash(),
            )
        return _header(block, height)


def _verifier(**kwargs):
    return HeaderChainVerifier(
        FakeHeaderFetcher(**kwargs),
        checkpoint_hash=CHECKPOINT_HASH,
        checkpoint_height=CHECKPOINT_HEIGHT,
    )


# --- walk ------------------------------------------------------------------


def test_walk_verifies_both_live_anchors():
    assert _verifier().verify_chain_for_tx(TX2).verified is True
    result = _verifier().verify_chain_for_tx(TX2)
    assert result.headers_checked == 3
    assert result.tip_height == 36723
    assert _verifier().verify_chain_for_tx(TX1).headers_checked == 2


def test_walk_single_header_checkpoint_equals_tip():
    verifier = HeaderChainVerifier(
        FakeHeaderFetcher(),
        checkpoint_hash=BLOCK_36722["hash"],
        checkpoint_height=36722,
    )
    result = verifier.verify_chain_for_tx(TX1)
    assert result.verified is True
    assert result.headers_checked == 1


def test_walk_fails_closed_wrong_checkpoint_hash():
    verifier = HeaderChainVerifier(
        FakeHeaderFetcher(),
        checkpoint_hash="ff" * 32,
        checkpoint_height=CHECKPOINT_HEIGHT,
    )
    result = verifier.verify_chain_for_tx(TX2)
    assert result.verified is False
    assert "checkpoint" in result.reason


def test_walk_fails_closed_checkpoint_above_tip():
    verifier = HeaderChainVerifier(
        FakeHeaderFetcher(),
        checkpoint_hash=CHECKPOINT_HASH,
        checkpoint_height=36730,
    )
    result = verifier.verify_chain_for_tx(TX2)
    assert result.verified is False
    assert "above the tip" in result.reason


def test_walk_fails_closed_broken_link():
    result = _verifier(broken_link=True).verify_chain_for_tx(TX2)
    assert result.verified is False
    assert "hash mismatch" in result.reason


def test_walk_fails_closed_pow():
    result = _verifier(pow_fail_tip=True).verify_chain_for_tx(TX2)
    assert result.verified is False
    assert "proof-of-work" in result.reason


def test_walk_fails_closed_fetch_error():
    result = _verifier(fail_on={36722}).verify_chain_for_tx(TX2)
    assert result.verified is False
    assert "fetch failed" in result.reason


def test_walk_fails_closed_unconfirmed():
    result = _verifier(unconfirmed={TX2}).verify_chain_for_tx(TX2)
    assert result.verified is False
    assert "unconfirmed" in result.reason


def test_walk_fails_closed_over_cap():
    verified, checked, reason = verify_chain_to_checkpoint(
        FakeHeaderFetcher(),
        tip_height=36723,
        tip_hash=BLOCK_36723["hash"],
        checkpoint_hash=CHECKPOINT_HASH,
        checkpoint_height=CHECKPOINT_HEIGHT,
        max_headers=2,
    )
    assert verified is False
    assert "exceeds cap" in reason
    assert checked == 0


def test_walk_rejects_negative_heights():
    verified, _, reason = verify_chain_to_checkpoint(
        FakeHeaderFetcher(),
        tip_height=36723,
        tip_hash=BLOCK_36723["hash"],
        checkpoint_hash=CHECKPOINT_HASH,
        checkpoint_height=-1,
    )
    assert verified is False
    assert "non-negative" in reason


# --- apply -----------------------------------------------------------------


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


def test_apply_header_chain_plain_shape():
    result = apply_header_chain(_two_anchor_chain(), _verifier())
    assert result["header_chain_verified"] is True
    for summary in result["anchors"]:
        assert summary["header_chain_verified"] is True
        assert summary["header_chain"]["headers_checked"] >= 2


def test_apply_header_chain_mixed_is_false():
    result = apply_header_chain(
        _two_anchor_chain(), _verifier(broken_link=True)
    )
    assert result["header_chain_verified"] is False


def test_apply_header_chain_journal_shape():
    chain = _two_anchor_chain()
    journal_shaped = {
        "verified": True,
        "chain": chain,
        "anchors": [{"verified": True}],
        "chain_inclusion_verified": False,
    }
    result = apply_header_chain(journal_shaped, _verifier())
    assert result["header_chain_verified"] is True
    assert result["chain"]["anchors"][0]["header_chain_verified"] is True


# --- CLI -------------------------------------------------------------------


def test_cli_header_chain_verifies_and_prints_line(tmp_path, capsys, monkeypatch):
    from sealrun import cli as cli_module
    from sealrun.bsv import build_op_return_script

    genesis = "0" * 64
    claimed = encode_anchor_payload(
        head_hash="11" * 32, start_seq=1, end_seq=3,
        release_seq=0, prev_txid=genesis,
    )

    class FakeWoC:
        def __init__(self, base_url=None):
            self.inner = FakeHeaderFetcher()

        def fetch_tx(self, txid):
            return self.inner.fetch_tx(txid)

        def fetch_header(self, height):
            return self.inner.fetch_header(height)

        def fetch_tx_full(self, txid):
            script = build_op_return_script(claimed)
            return {"vout": [{"scriptPubKey": {"hex": script.hex()}}]}

    monkeypatch.setattr(cli_module, "WoCBlockFetcher", FakeWoC)
    anchor1 = tmp_path / "a1.json"
    anchor1.write_text(json.dumps({
        "payload_hex": claimed.hex(),
        "txid": TX1,
    }))
    cli_module.main([
        "anchor-chain-verify", "--genesis-txid", genesis,
        "--anchor", str(anchor1),
        "--header-chain",
        "--checkpoint-hash", CHECKPOINT_HASH,
        "--checkpoint-height", str(CHECKPOINT_HEIGHT),
    ])
    out = capsys.readouterr().out
    assert "HEADER CHAIN VERIFIED: 1 anchor(s)" in out
    assert '"header_chain_verified": true' in out


def test_cli_header_chain_missing_checkpoint_args_is_rejected(tmp_path, capsys):
    from sealrun import cli as cli_module

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
        "--anchor", str(anchor1), "--header-chain",
    ]) == 1
    assert "ERROR" in capsys.readouterr().err
