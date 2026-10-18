"""Tests for BUMP (BRC-74) compact Merkle proofs in aiguard/spv.py.

The spec fixtures are the BRC-74 reference BUMP for block 813706: all
three client txids must fold to the spec's stated root. The hex string
is the binary encoding of the same BUMP as the JSON object.
"""

import copy
import json

import pytest

from aiguard.anchor import encode_anchor_payload
from aiguard.spv import (
    BUMPVerifier,
    BlockHeader,
    SPVUnavailable,
    apply_bump_inclusion,
    build_bump,
    bump_to_hex,
    merkle_root,
    parse_bump_hex,
    parse_bump_json,
    verify_bump_proof,
)

# --- BRC-74 reference fixtures (block 813706) -------------------------------

SPEC_ROOT = '57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4'
SPEC_TXIDS = ['304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711', 'd888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00', '98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e']
SPEC_JSON = {'blockHeight': 813706, 'path': [[{'offset': 3048, 'hash': '304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711'}, {'offset': 3049, 'txid': True, 'hash': 'd888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00'}, {'offset': 3050, 'txid': True, 'hash': '98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e'}, {'offset': 3051, 'duplicate': True}], [{'offset': 1524, 'hash': '811ae75c80fecd27efff5ef272c2adf7edb6e535447f27a4087d23724f397106'}, {'offset': 1525, 'hash': '82520a4501a06061dd2386fb92fa5e9ceaed14747acc00edf34a6cecabcc2b26'}], [{'offset': 763, 'duplicate': True}], [{'offset': 380, 'hash': '858e41febe934b4cbc1cb80a1dc8e254cb1e69acff8e4f91ecdd779bcaefb393'}], [{'offset': 191, 'duplicate': True}], [{'offset': 94, 'hash': 'f80263e813c644cd71bcc88126d0463df070e28f11023a00543c97b66e828158'}], [{'offset': 46, 'hash': 'f36f792fa2b42acfadfa043a946d4d7b6e5e1e2e0266f2cface575bbb82b7ae0'}], [{'offset': 22, 'hash': '7d5051f0d4ceb7d2e27a49e448aedca2b3865283ceffe0b00b9c3017faca2081'}], [{'offset': 10, 'hash': '43aeeb9b6a9e94a5a787fbf04380645e6fd955f8bf0630c24365f492ac592e50'}], [{'offset': 4, 'hash': '45be5d16ac41430e3589a579ad780e5e42cf515381cc309b48d0f4648f9fcd1c'}], [{'offset': 3, 'duplicate': True}], [{'offset': 0, 'hash': 'd40cb31af3ef53dd910f5ce15e9a1c20875c009a22d25eab32c11c7ece6487af'}]]}
SPEC_HEX = 'fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b0102fdf405000671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81fdf50500262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a528201fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4'


# --- Spec vectors ------------------------------------------------------------


def test_spec_json_verifies_all_three_txids():
    bump = parse_bump_json(SPEC_JSON)
    assert bump["blockHeight"] == 813706
    assert len(bump["path"]) == 12
    for txid in SPEC_TXIDS:
        assert verify_bump_proof(txid, bump, SPEC_ROOT) is True


def test_spec_hex_parses_to_spec_json():
    assert parse_bump_hex(SPEC_HEX) == parse_bump_json(SPEC_JSON)


def test_spec_json_encodes_to_spec_hex():
    assert bump_to_hex(SPEC_JSON) == SPEC_HEX


def test_spec_proof_rejects_wrong_root_and_unknown_txid():
    bump = parse_bump_json(SPEC_JSON)
    assert verify_bump_proof(SPEC_TXIDS[0], bump, "0" * 64) is False
    assert verify_bump_proof("f" * 64, bump, SPEC_ROOT) is False


def test_spec_proof_rejects_tampered_leaf():
    bump = parse_bump_json(SPEC_JSON)
    tampered = copy.deepcopy(bump)
    # Level 3, offset 380 sits on all three txids' paths.
    leaf = tampered["path"][3][0]
    assert leaf["offset"] == 380
    leaf["hash"] = ("0" if leaf["hash"][0] != "0" else "1") + leaf["hash"][1:]
    for txid in SPEC_TXIDS:
        assert verify_bump_proof(txid, tampered, SPEC_ROOT) is False


def test_spec_proof_rejects_missing_sibling():
    bump = parse_bump_json(SPEC_JSON)
    pruned = copy.deepcopy(bump)
    pruned["path"][1] = [pruned["path"][1][0]]  # drop sibling at offset 1525
    # Sibling offsets at level 1: txid 3049 needs 1525 (gone), txid
    # 3048 needs 1525 (gone), txid 3050 needs 1524 (still there).
    assert verify_bump_proof(SPEC_TXIDS[1], pruned, SPEC_ROOT) is False
    assert verify_bump_proof(SPEC_TXIDS[0], pruned, SPEC_ROOT) is False
    assert verify_bump_proof(SPEC_TXIDS[2], pruned, SPEC_ROOT) is True


# --- Malformed BUMP inputs ---------------------------------------------------


def test_parse_bump_hex_rejects_truncated():
    with pytest.raises(ValueError):
        parse_bump_hex(SPEC_HEX[:-4])
    with pytest.raises(ValueError):
        parse_bump_hex("")


def test_parse_bump_hex_rejects_bad_flags_and_trailing_bytes():
    # flags byte 0x03 is not a defined BUMP flag; craft a minimal BUMP
    # with treeHeight 1, one leaf, flags 0x03.
    with pytest.raises(ValueError):
        parse_bump_hex("01010300ff")
    with pytest.raises(ValueError):
        parse_bump_hex(SPEC_HEX + "00")


def test_parse_bump_hex_rejects_non_hex():
    with pytest.raises(ValueError):
        parse_bump_hex("zz")
    with pytest.raises(ValueError):
        parse_bump_hex(123)  # type: ignore[arg-type]


def test_parse_bump_json_rejects_malformed():
    with pytest.raises(ValueError):
        parse_bump_json({"blockHeight": -1, "path": []})
    with pytest.raises(ValueError):
        parse_bump_json({"blockHeight": 1})  # missing path
    with pytest.raises(ValueError):
        parse_bump_json({"blockHeight": 1, "path": "nope"})
    with pytest.raises(ValueError):
        # duplicate offset inside one level
        parse_bump_json({
            "blockHeight": 1,
            "path": [[
                {"offset": 0, "hash": "a" * 64},
                {"offset": 0, "hash": "b" * 64},
            ]],
        })
    with pytest.raises(ValueError):
        # duplicate leaf must carry no hash
        parse_bump_json({
            "blockHeight": 1,
            "path": [[{"offset": 0, "duplicate": True, "hash": "a" * 64}]],
        })
    with pytest.raises(ValueError):
        # short hash
        parse_bump_json({
            "blockHeight": 1,
            "path": [[{"offset": 0, "hash": "ab"}]],
        })
    with pytest.raises(ValueError):
        parse_bump_json(None)


def test_parse_bump_json_normalizes():
    bump = parse_bump_json({
        "blockHeight": 7,
        "path": [[
            {"offset": 1, "hash": "B" * 64},
            {"offset": 0, "hash": "A" * 64, "txid": True},
        ]],
    })
    assert bump["path"][0][0] == {"offset": 0, "hash": "a" * 64, "txid": True}
    assert bump["path"][0][1] == {"offset": 1, "hash": "b" * 64}


def test_verify_bump_proof_fails_closed_on_bad_types():
    bump = parse_bump_json(SPEC_JSON)
    assert verify_bump_proof(None, bump, SPEC_ROOT) is False  # type: ignore[arg-type]
    assert verify_bump_proof(SPEC_TXIDS[0], None, SPEC_ROOT) is False  # type: ignore[arg-type]
    assert verify_bump_proof(SPEC_TXIDS[0], bump, None) is False  # type: ignore[arg-type]
    assert verify_bump_proof("not hex", bump, SPEC_ROOT) is False
    assert verify_bump_proof(SPEC_TXIDS[0], {"blockHeight": 1, "path": []}, "x") is False


# --- build_bump --------------------------------------------------------------


def _fake_txids(n):
    return [f"{i + 1:064x}" for i in range(n)]


def test_build_bump_verifies_every_position_for_sizes_1_to_17():
    for n in range(1, 18):
        txids = _fake_txids(n)
        root = merkle_root(txids)
        for index in (0, n - 1, n // 2):
            bump = build_bump(txids, [index], block_height=1000 + n)
            assert bump["blockHeight"] == 1000 + n
            assert verify_bump_proof(txids[index], bump, root) is True
            # Round-trip through the binary encoding.
            assert parse_bump_hex(bump_to_hex(bump)) == bump


def test_build_bump_multi_index_single_proof():
    txids = _fake_txids(9)
    root = merkle_root(txids)
    bump = build_bump(txids, [0, 4, 8], block_height=42)
    for index in (0, 4, 8):
        assert verify_bump_proof(txids[index], bump, root) is True


def test_build_bump_emits_duplicate_leaf_for_odd_last_node():
    txids = _fake_txids(5)
    bump = build_bump(txids, [4], block_height=1)
    level0 = {leaf["offset"]: leaf for leaf in bump["path"][0]}
    # Index 4 is the last node of an odd-count level: its sibling
    # offset 5 is past the end, so it is a duplicate leaf.
    assert level0[5] == {"offset": 5, "duplicate": True}
    assert level0[4] == {
        "offset": 4, "hash": txids[4], "txid": True,
    }


def test_build_bump_single_tx_has_empty_path():
    txid = _fake_txids(1)[0]
    bump = build_bump([txid], [0], block_height=3)
    assert bump == {"blockHeight": 3, "path": []}
    assert verify_bump_proof(txid, bump, txid) is True
    assert bump_to_hex(bump) == "0300"


def test_build_bump_verifies_real_ttn_anchor():
    from test_spv import BLOCK_36722, TX1

    txids = BLOCK_36722["tx"]
    bump = build_bump(txids, [2], block_height=36722)
    assert verify_bump_proof(TX1, bump, BLOCK_36722["root"]) is True
    assert parse_bump_hex(bump_to_hex(bump)) == bump


def test_bump_verifier_accepts_real_ttn_anchor():
    from test_spv import BLOCK_36722, TX1

    header = BlockHeader(
        version=BLOCK_36722["version"],
        prev_hash=BLOCK_36722["prev"],
        merkle_root=BLOCK_36722["root"],
        time=BLOCK_36722["time"],
        bits=BLOCK_36722["bits"],
        nonce=BLOCK_36722["nonce"],
        height=36722,
        hash=BLOCK_36722["hash"],
    )
    bump = build_bump(BLOCK_36722["tx"], [2], block_height=36722)
    verdict = BUMPVerifier(_StubFetcher(header=header)).verify_bump_for_tx(
        TX1, bump
    )
    assert verdict.verified is True
    assert verdict.blockheight == 36722
    assert verdict.blockhash == BLOCK_36722["hash"]


def test_build_bump_rejects_bad_input():
    with pytest.raises(ValueError):
        build_bump([], [0], 1)
    with pytest.raises(ValueError):
        build_bump(_fake_txids(3), [3], 1)
    with pytest.raises(ValueError):
        build_bump(_fake_txids(3), [-1], 1)
    with pytest.raises(ValueError):
        build_bump(_fake_txids(3), [], 1)
    with pytest.raises(ValueError):
        build_bump(_fake_txids(3), [0], -1)


# --- BUMPVerifier + apply_bump_inclusion -------------------------------------


def _spec_header(bits=0x207FFFFF, grind=True):
    """Stub header carrying the spec root. With grind=True the nonce is
    advanced until the header meets its (easiest) target, so the stub
    passes proof-of-work the way a real header does."""
    from aiguard.spv import verify_pow

    nonce = 0
    while True:
        header = BlockHeader(
            version=1,
            prev_hash="00" * 32,
            merkle_root=SPEC_ROOT,
            time=0,
            bits=bits,
            nonce=nonce,
            height=813706,
            hash="00" * 32,
        )
        if not grind or verify_pow(header.to_bytes(), bits):
            return header
        nonce += 1
        if nonce > 100000:
            raise AssertionError("could not grind a passing stub header")


class _StubFetcher:
    def __init__(self, header=None, error=None):
        self.header = header if header is not None else _spec_header()
        self.error = error

    def fetch_header(self, height):
        if self.error is not None:
            raise self.error
        return self.header


def test_bump_verifier_accepts_spec_proof():
    verdict = BUMPVerifier(_StubFetcher()).verify_bump_for_tx(
        SPEC_TXIDS[0], parse_bump_json(SPEC_JSON)
    )
    assert verdict.verified is True
    assert verdict.blockheight == 813706
    assert verdict.blockhash == "00" * 32


def test_bump_verifier_rejects_wrong_height_header():
    bump = parse_bump_json(SPEC_JSON)
    bump = dict(bump, blockHeight=1)
    verdict = BUMPVerifier(_StubFetcher()).verify_bump_for_tx(SPEC_TXIDS[0], bump)
    assert verdict.verified is False
    assert "height" in verdict.reason


def test_bump_verifier_rejects_tampered_proof_and_fetch_error():
    bump = copy.deepcopy(parse_bump_json(SPEC_JSON))
    bump["path"][0][0]["hash"] = "0" * 64
    assert BUMPVerifier(_StubFetcher()).verify_bump_for_tx(
        SPEC_TXIDS[0], bump
    ).verified is False
    assert BUMPVerifier(
        _StubFetcher(error=SPVUnavailable("down"))
    ).verify_bump_for_tx(SPEC_TXIDS[0], SPEC_JSON).verified is False


def test_bump_verifier_rejects_pow_failure():
    # Same header, but a mainnet-difficulty target its hash cannot meet.
    header = _spec_header(bits=0x1D00FFFF, grind=False)
    verdict = BUMPVerifier(_StubFetcher(header=header)).verify_bump_for_tx(
        SPEC_TXIDS[0], parse_bump_json(SPEC_JSON)
    )
    assert verdict.verified is False
    assert "proof-of-work" in verdict.reason


def test_apply_bump_inclusion_simple_shape():
    result = {"anchors": [{"txid": SPEC_TXIDS[0], "payload_hex": "00"}]}
    out = apply_bump_inclusion(
        result,
        BUMPVerifier(_StubFetcher()),
        {SPEC_TXIDS[0]: parse_bump_json(SPEC_JSON)},
    )
    assert out["bump_inclusion_verified"] is True
    assert out["anchors"][0]["bump_inclusion_verified"] is True
    assert result["anchors"][0].get("bump_inclusion") is None  # not mutated


def test_apply_bump_inclusion_chain_shape_and_missing_bump():
    result = {
        "chain": {"anchors": [
            {"txid": SPEC_TXIDS[0]},
            {"txid": "ee" * 32},
        ]}
    }
    out = apply_bump_inclusion(
        result,
        BUMPVerifier(_StubFetcher()),
        {SPEC_TXIDS[0]: parse_bump_json(SPEC_JSON)},
    )
    assert out["bump_inclusion_verified"] is False
    assert out["chain"]["anchors"][0]["bump_inclusion_verified"] is True
    assert out["chain"]["anchors"][1]["bump_inclusion_verified"] is False
    assert "no BUMP supplied" in out["chain"]["anchors"][1]["bump_inclusion"]["reason"]


def test_apply_bump_inclusion_rejects_non_dict():
    with pytest.raises(ValueError):
        apply_bump_inclusion({}, BUMPVerifier(_StubFetcher()), [])


# --- CLI ---------------------------------------------------------------------


def test_cli_bump_file_verifies_and_prints_line(tmp_path, capsys, monkeypatch):
    from aiguard import cli as cli_module
    from aiguard.bsv import build_op_return_script

    genesis = "0" * 64
    claimed = encode_anchor_payload(
        head_hash="11" * 32, start_seq=1, end_seq=3,
        release_seq=0, prev_txid=genesis,
    )

    class FakeWoC:
        def __init__(self, base_url=None):
            pass

        def fetch_header(self, height):
            return _spec_header()

        def fetch_tx_full(self, txid):
            script = build_op_return_script(claimed)
            return {"vout": [{"scriptPubKey": {"hex": script.hex()}}]}

    monkeypatch.setattr(cli_module, "WoCBlockFetcher", FakeWoC)
    anchor = tmp_path / "a1.json"
    anchor.write_text(json.dumps({
        "payload_hex": claimed.hex(),
        "txid": SPEC_TXIDS[0],
    }))
    bumps = tmp_path / "bumps.json"
    bumps.write_text(json.dumps({SPEC_TXIDS[0]: SPEC_JSON}))
    cli_module.main([
        "anchor-chain-verify", "--genesis-txid", genesis,
        "--anchor", str(anchor),
        "--bump-file", str(bumps),
    ])
    out = capsys.readouterr().out
    assert "BUMP INCLUSION VERIFIED: 1 anchor(s)" in out
    assert '"bump_inclusion_verified": true' in out
    assert "LOCAL CHECK ONLY" not in out


def test_cli_bump_file_failure_prints_failed_line(tmp_path, capsys, monkeypatch):
    from aiguard import cli as cli_module

    class FakeWoC:
        def __init__(self, base_url=None):
            pass

        def fetch_header(self, height):
            return _spec_header()

    monkeypatch.setattr(cli_module, "WoCBlockFetcher", FakeWoC)
    genesis = "0" * 64
    anchor = tmp_path / "a1.json"
    anchor.write_text(json.dumps({
        "payload_hex": encode_anchor_payload(
            head_hash="11" * 32, start_seq=1, end_seq=3,
            release_seq=0, prev_txid=genesis,
        ).hex(),
        "txid": SPEC_TXIDS[0],
    }))
    tampered = copy.deepcopy(SPEC_JSON)
    tampered["path"][0][0]["hash"] = "0" * 64
    bumps = tmp_path / "bumps.json"
    bumps.write_text(json.dumps({SPEC_TXIDS[0]: tampered}))
    cli_module.main([
        "anchor-chain-verify", "--genesis-txid", genesis,
        "--anchor", str(anchor),
        "--bump-file", str(bumps),
    ])
    out = capsys.readouterr().out
    assert "BUMP INCLUSION CHECK FAILED" in out
    assert '"bump_inclusion_verified": false' in out
