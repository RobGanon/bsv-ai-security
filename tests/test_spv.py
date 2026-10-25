"""Tests for sealrun.spv: Merkle proofs, headers, PoW, inclusion.

Real fixtures: Teratestnet blocks 36721–36723, recorded live from
WoC-TTN 2026-10-16. Block 36722 holds live anchor #1 (tx index 2),
block 36723 holds live anchor #2 (tx index 1), block 36721 holds the
BRC-166 settlement tx (index 1). Recomputing these blocks' Merkle
roots from their tx lists is the ground-truth check for byte order.
"""
import json

import pytest

from sealrun.anchor import encode_anchor_payload, verify_anchor_chain
from sealrun.spv import (
    SPVUnavailable,
    SPVVerifier,
    BlockHeader,
    InclusionResult,
    WoCBlockFetcher,
    apply_chain_inclusion,
    header_hash,
    merkle_path,
    merkle_root,
    target_from_bits,
    validate_woc_base_url,
    verify_header,
    verify_header_chain,
    verify_merkle_proof,
    verify_pow,
)

TX1 = "4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029"
TX2 = "d8407bb7a60f23aadcf021e9cb0098c6ae362a519aa04cbd8536265519c09230"
BRC_SETTLE = "8f3975a0218a1841f2b3c0e42ef348003781ec65221f31a951466a9a800f184d"

BLOCK_36721 = {
    "hash": "0000000048cb33f8f96e4927e4e8066742076b180d7091c013e7e36d4b246eae",
    "prev": "000000002f9d0b6a01c151cd796a9ce6fd6f9a967da4ed7a12ff4a83ef38d67a",
    "root": "63b2cda9b315b4532bf532ae2d9a0500a326a56597ae4ee7dbed1bad77ffe0d6",
    "version": 536870912,
    "time": 1792196982,
    "bits": 0x1C55AD80,
    "nonce": 87798228,
    "tx": [
        "6c0608102a3373ef25e75224e1943fe0bfa9d0ddd399b3a5665b6b98639004e6",
        BRC_SETTLE,
    ],
}

BLOCK_36722 = {
    "hash": "000000001d8a81abcf3b84b3d610cb1cc9161dce73c8a1c2bb512ae27ef46daf",
    "prev": "0000000048cb33f8f96e4927e4e8066742076b180d7091c013e7e36d4b246eae",
    "root": "8e55225402e64109e0974b4e0dc810c4d4ca3c2e61800d7559e05d04d175f4bb",
    "version": 536870912,
    "time": 1792198024,
    "bits": 0x1C55DEB0,
    "nonce": 21614930,
    "tx": [
        "93181bbcfa8c3240fd5d8613a7dad0d4940c7a6d80233182d43d2792035f101a",
        "2aa2442b25ecd79bcaf6b2ce025fd179f1e72aef90213a6e3c2516e6188aae7a",
        TX1,
    ],
}

BLOCK_36723 = {
    "hash": "0000000023615eaeee840cb73143947abb46069a58f1dcd77d544447297149d2",
    "prev": "000000001d8a81abcf3b84b3d610cb1cc9161dce73c8a1c2bb512ae27ef46daf",
    "root": "ba817c0213543c2e7ffbb9bc0c317017a3d165058d2e980f655a63ec7c650544",
    "version": 536870912,
    "time": 1792199107,
    "bits": 0x1C561092,
    "nonce": 1396520704,
    "tx": [
        "785027487d963e7a4a716a942a94b59fb770b6010b07b9bf2977984142402c73",
        TX2,
    ],
}

BLOCKS = [BLOCK_36721, BLOCK_36722, BLOCK_36723]


def _header(block: dict) -> BlockHeader:
    return BlockHeader(
        version=block["version"],
        prev_hash=block["prev"],
        merkle_root=block["root"],
        time=block["time"],
        bits=block["bits"],
        nonce=block["nonce"],
        height=None,
        hash=block["hash"],
    )


# --- Merkle tree -----------------------------------------------------------


def test_merkle_root_matches_real_block_headers():
    for block in BLOCKS:
        assert merkle_root(block["tx"]) == block["root"]


def test_merkle_root_single_tx_is_itself():
    assert merkle_root([TX1]) == TX1


def test_merkle_root_empty_rejected():
    with pytest.raises(ValueError):
        merkle_root([])


def test_merkle_path_round_trip_every_real_tx():
    for block in BLOCKS:
        for i, txid in enumerate(block["tx"]):
            path = merkle_path(block["tx"], i)
            assert verify_merkle_proof(txid, path, block["root"])


def test_merkle_path_round_trip_synthetic_sizes():
    base = [f"{i:064x}" for i in range(1, 8)]
    for n in range(1, 8):
        txids = base[:n]
        root = merkle_root(txids)
        for i, txid in enumerate(txids):
            assert verify_merkle_proof(txid, merkle_path(txids, i), root)


def test_merkle_proof_rejects_tampering():
    txids = BLOCK_36722["tx"]
    path = merkle_path(txids, 2)
    root = BLOCK_36722["root"]
    assert verify_merkle_proof(TX1, path, root)
    # Tampered sibling hash.
    bad = [dict(node) for node in path]
    bad[0] = {**bad[0], "hash": "00" * 32}
    assert not verify_merkle_proof(TX1, bad, root)
    # Wrong root, wrong txid, bad position, bad hex, non-list path.
    assert not verify_merkle_proof(TX1, path, "00" * 32)
    assert not verify_merkle_proof(TX2, path, root)
    assert not verify_merkle_proof(TX1, [{**path[0], "position": "up"}], root)
    assert not verify_merkle_proof(TX1, [{"hash": "zz", "position": "left"}], root)
    assert not verify_merkle_proof(TX1, "not-a-list", root)  # type: ignore[arg-type]
    assert not verify_merkle_proof("not-hex", path, root)


def test_merkle_path_index_validation():
    with pytest.raises(ValueError):
        merkle_path(BLOCK_36722["tx"], 3)
    with pytest.raises(ValueError):
        merkle_path(BLOCK_36722["tx"], -1)
    with pytest.raises(ValueError):
        merkle_path([], 0)


# --- Headers / PoW ---------------------------------------------------------


def test_header_hash_matches_real_block_hashes():
    for block in BLOCKS:
        assert header_hash(_header(block).to_bytes()) == block["hash"]


def test_pow_passes_for_real_headers():
    for block in BLOCKS:
        header = _header(block)
        assert verify_pow(header.to_bytes(), header.bits)
        assert verify_header(header.to_bytes(), block["hash"], header.bits)


def test_pow_fails_for_tampered_nonce():
    block = dict(BLOCK_36722)
    header = _header({**block, "nonce": block["nonce"] + 1})
    assert not verify_pow(header.to_bytes(), header.bits)
    assert not verify_header(header.to_bytes(), block["hash"], header.bits)


def test_target_from_bits_genesis_vector():
    # Bitcoin genesis bits 0x1d00ffff -> target 0x00000000ffff0000...
    assert target_from_bits(0x1D00FFFF) == 0x00000000FFFF0000000000000000000000000000000000000000000000000000


def test_target_from_bits_invalid():
    for bad in (0x00000000, 0x02000000, 0x1C000000):
        with pytest.raises(ValueError):
            target_from_bits(bad)


def test_header_chain_links_real_blocks():
    headers = [_header(b) for b in BLOCKS]
    assert verify_header_chain(headers)
    assert not verify_header_chain(list(reversed(headers)))
    assert not verify_header_chain([])
    tampered = [_header(BLOCK_36721), _header({**BLOCK_36722, "prev": "00" * 32}), _header(BLOCK_36723)]
    assert not verify_header_chain(tampered)
    wrong_hash = [_header(BLOCK_36721), _header({**BLOCK_36722, "hash": "00" * 32}), _header(BLOCK_36723)]
    assert not verify_header_chain(wrong_hash)


# --- SPVVerifier with a fake fetcher ---------------------------------------


class FakeFetcher:
    """Serves the recorded TTN blocks; knobs for adversarial cases."""

    def __init__(self, *, unconfirmed=(), missing=(), wrong_root=False,
                 wrong_blockhash=False, pow_bits=None, fail=False):
        self.unconfirmed = set(unconfirmed)
        self.missing = set(missing)
        self.wrong_root = wrong_root
        self.wrong_blockhash = wrong_blockhash
        self.pow_bits = pow_bits
        self.fail = fail

    def _block_for(self, txid):
        for block in BLOCKS:
            if txid in block["tx"]:
                return block
        return None

    def fetch_tx(self, txid):
        if self.fail:
            raise SPVUnavailable("boom")
        block = self._block_for(txid)
        if txid in self.unconfirmed or block is None:
            return {"blockheight": None, "blockhash": None}
        return {
            "blockheight": BLOCKS.index(block) + 36721,
            "blockhash": "ff" * 32 if self.wrong_blockhash else block["hash"],
        }

    def fetch_block(self, height):
        if self.fail:
            raise SPVUnavailable("boom")
        block = BLOCKS[height - 36721]
        txids = [t for t in block["tx"] if t not in self.missing]
        header = _header(block)
        if self.wrong_root:
            header = BlockHeader(
                version=header.version, prev_hash=header.prev_hash,
                merkle_root="00" * 32, time=header.time, bits=header.bits,
                nonce=header.nonce, height=height, hash=header.hash,
            )
        if self.pow_bits is not None:
            header = BlockHeader(
                version=header.version, prev_hash=header.prev_hash,
                merkle_root=header.merkle_root, time=header.time,
                bits=self.pow_bits, nonce=header.nonce,
                height=height, hash=header.hash,
            )
        return header, txids


def test_verifier_confirms_both_live_anchors():
    verifier = SPVVerifier(FakeFetcher())
    for txid, height in ((TX1, 36722), (TX2, 36723)):
        result = verifier.verify_inclusion(txid)
        assert result.verified
        assert result.blockheight == height


def test_verifier_fails_closed_unconfirmed():
    result = SPVVerifier(FakeFetcher(unconfirmed={TX1})).verify_inclusion(TX1)
    assert not result.verified and "unconfirmed" in result.reason


def test_verifier_fails_closed_missing_from_block():
    result = SPVVerifier(FakeFetcher(missing={TX1})).verify_inclusion(TX1)
    assert not result.verified and "not present" in result.reason


def test_verifier_fails_closed_blockhash_mismatch():
    result = SPVVerifier(FakeFetcher(wrong_blockhash=True)).verify_inclusion(TX1)
    assert not result.verified and "blockhash mismatch" in result.reason


def test_verifier_fails_closed_root_mismatch():
    result = SPVVerifier(FakeFetcher(wrong_root=True)).verify_inclusion(TX1)
    assert not result.verified and "Merkle" in result.reason


def test_verifier_fails_closed_pow():
    # bits 0x03000001 -> target 1: no real header hash can pass.
    result = SPVVerifier(FakeFetcher(pow_bits=0x03000001)).verify_inclusion(TX1)
    assert not result.verified and "proof-of-work" in result.reason


def test_verifier_fails_closed_fetch_error():
    result = SPVVerifier(FakeFetcher(fail=True)).verify_inclusion(TX1)
    assert not result.verified and "fetch failed" in result.reason


def test_verifier_unknown_txid_is_unconfirmed():
    result = SPVVerifier(FakeFetcher()).verify_inclusion("ab" * 32)
    assert not result.verified and "unconfirmed" in result.reason


# --- apply_chain_inclusion -------------------------------------------------


def _two_anchor_chain():
    genesis = "0" * 64
    head1 = "11" * 32
    head2 = "22" * 32
    anchors = [
        {
            "payload_hex": encode_anchor_payload(head_hash=head1, start_seq=1, end_seq=3, release_seq=0, prev_txid=genesis).hex(),
            "txid": TX1,
        },
        {
            "payload_hex": encode_anchor_payload(head_hash=head2, start_seq=4, end_seq=4, release_seq=0, prev_txid=TX1).hex(),
            "txid": TX2,
        },
    ]
    return verify_anchor_chain(anchors, genesis)


def test_apply_chain_inclusion_plain_shape():
    result = apply_chain_inclusion(_two_anchor_chain(), SPVVerifier(FakeFetcher()))
    assert result["chain_inclusion_verified"] is True
    for summary in result["anchors"]:
        assert summary["chain_inclusion_verified"] is True
        assert summary["chain_inclusion"]["blockheight"] in (36722, 36723)


def test_apply_chain_inclusion_mixed_is_false():
    result = apply_chain_inclusion(
        _two_anchor_chain(),
        SPVVerifier(FakeFetcher(unconfirmed={TX2})),
    )
    assert result["chain_inclusion_verified"] is False
    assert result["anchors"][0]["chain_inclusion_verified"] is True
    assert result["anchors"][1]["chain_inclusion_verified"] is False


def test_apply_chain_inclusion_journal_shape():
    chain = _two_anchor_chain()
    journal_shaped = {
        "verified": True,
        "chain": chain,
        "anchors": [{"verified": True, "head_hash": "11" * 32}],
        "chain_inclusion_verified": False,
    }
    result = apply_chain_inclusion(journal_shaped, SPVVerifier(FakeFetcher()))
    assert result["chain_inclusion_verified"] is True
    assert result["chain"]["anchors"][0]["chain_inclusion_verified"] is True


# --- WoC fetcher parsing ---------------------------------------------------


def test_woc_fetcher_parses_block_bits_hex_string():
    """WoC returns bits as a hex string ("1c55deb0"); the fetcher must decode it."""
    calls = []

    def request_fn(method, url):
        calls.append(url)
        if "/tx/hash/" in url:
            body = {"blockheight": 36722, "blockhash": BLOCK_36722["hash"]}
        else:
            body = {
                "version": BLOCK_36722["version"],
                "previousblockhash": BLOCK_36722["prev"],
                "merkleroot": BLOCK_36722["root"],
                "time": BLOCK_36722["time"],
                "bits": "1c55deb0",
                "nonce": BLOCK_36722["nonce"],
                "height": 36722,
                "hash": BLOCK_36722["hash"],
                "tx": BLOCK_36722["tx"],
            }
        return 200, json.dumps(body).encode()

    fetcher = WoCBlockFetcher(request_fn=request_fn)
    assert fetcher.fetch_tx(TX1)["blockheight"] == 36722
    header, txids = fetcher.fetch_block(36722)
    assert header.bits == 0x1C55DEB0
    assert txids == BLOCK_36722["tx"]


def test_woc_fetcher_maps_http_error_to_unavailable():
    def request_fn(method, url):
        return 500, b"error"

    with pytest.raises(SPVUnavailable):
        WoCBlockFetcher(request_fn=request_fn).fetch_tx(TX1)


def test_woc_base_url_scheme_enforced():
    """Regression (A31): --woc-base accepted plaintext HTTP, so SPV
    inputs could travel unencrypted. Only https, or http for loopback."""
    assert validate_woc_base_url("https://api.example.com/v1") == (
        "https://api.example.com/v1"
    )
    assert validate_woc_base_url("http://127.0.0.1:9") == "http://127.0.0.1:9"
    assert validate_woc_base_url("http://localhost:3000/x") == (
        "http://localhost:3000/x"
    )
    for bad in (
        "http://api.example.com/v1",
        "http://example.com",
        "ftp://example.com",
        "example.com",
        "",
        "https://",
    ):
        with pytest.raises(ValueError, match="https"):
            validate_woc_base_url(bad)


def test_woc_fetcher_rejects_plaintext_base():
    with pytest.raises(ValueError, match="https"):
        WoCBlockFetcher(base_url="http://api.example.com/v1")
    fetcher = WoCBlockFetcher(base_url="http://127.0.0.1:9")
    assert fetcher.base_url == "http://127.0.0.1:9"


# --- CLI --spv -------------------------------------------------------------


def test_cli_spv_verifies_chain_and_prints_inclusion_line(tmp_path, capsys, monkeypatch):
    from sealrun import cli as cli_module
    from sealrun.bsv import build_op_return_script

    class FakeWoC:
        def __init__(self, base_url=None):
            self.inner = FakeFetcher()

        def fetch_tx(self, txid):
            return self.inner.fetch_tx(txid)

        def fetch_block(self, height):
            return self.inner.fetch_block(height)

        def fetch_tx_full(self, txid):
            # The claimed payloads are what these txs commit to: the
            # binding check compares the fetched OP_RETURN to the claim.
            claimed = {TX1: payload1, TX2: payload2}
            script = build_op_return_script(claimed[txid])
            return {"vout": [{"scriptPubKey": {"hex": script.hex()}}]}

    monkeypatch.setattr(cli_module, "WoCBlockFetcher", FakeWoC)
    anchor1 = tmp_path / "a1.json"
    anchor2 = tmp_path / "a2.json"
    genesis = "0" * 64
    payload1 = encode_anchor_payload(head_hash="11" * 32, start_seq=1, end_seq=3, release_seq=0, prev_txid=genesis)
    payload2 = encode_anchor_payload(head_hash="22" * 32, start_seq=4, end_seq=4, release_seq=0, prev_txid=TX1)
    anchor1.write_text(json.dumps({
        "payload_hex": payload1.hex(),
        "txid": TX1,
    }))
    anchor2.write_text(json.dumps({
        "payload_hex": payload2.hex(),
        "txid": TX2,
    }))
    assert cli_module.main([
        "anchor-chain-verify", "--genesis-txid", genesis,
        "--anchor", str(anchor1), "--anchor", str(anchor2), "--spv",
    ]) in (None, 0)
    out = capsys.readouterr().out
    assert "CHAIN INCLUSION VERIFIED: 2 anchor(s)" in out
    assert "LOCAL CHECK ONLY" not in out
    assert '"chain_inclusion_verified": true' in out


def test_cli_without_spv_keeps_local_check_only_warning(tmp_path, capsys):
    from sealrun import cli as cli_module

    anchor1 = tmp_path / "a1.json"
    genesis = "0" * 64
    anchor1.write_text(json.dumps({
        "payload_hex": encode_anchor_payload(head_hash="11" * 32, start_seq=1, end_seq=3, release_seq=0, prev_txid=genesis).hex(),
        "txid": TX1,
    }))
    cli_module.main([
        "anchor-chain-verify", "--genesis-txid", genesis,
        "--anchor", str(anchor1),
    ])
    out = capsys.readouterr().out
    assert "LOCAL CHECK ONLY" in out
