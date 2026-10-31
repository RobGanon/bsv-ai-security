"""Tests for BEEF (BRC-62) envelope parsing and verification in
sealrun/beef.py.

The spec fixture is the BRC-62 reference BEEF example: version
0100BEEF, one BUMP, two transactions — the parent carries the BUMP
(index 0), the payment spends the parent's output and carries no
BUMP. The live fixture is a BEEF built from the real Teratestnet
block 36722 BUMP + the real anchor #1 tx + a child spending anchor
#1's change output.
"""

import copy
import json
import struct

import pytest

from sealrun.beef import (
    BEEF_MAGIC,
    BEEF_VERSION,
    Beef,
    BeefTx,
    BeefVerification,
    BeefVerifier,
    apply_beef_inclusion,
    beef_to_bytes,
    beef_to_hex,
    parse_beef,
    parse_beef_hex,
)
from sealrun.spv import BlockHeader, SPVUnavailable

# --- BRC-62 reference BEEF example -----------------------------------------
# Transcribed from the BRC-62 spec (Open BSV license). Cross-checked by
# the tests below: the payment tx's input must reference the parent
# txid, and the parent txid must be the txid-flagged leaf of the
# BUMP's level 0 — a mistranscription anywhere in the parent tx or
# that leaf breaks those checks.

SPEC_BEEF_HEX = (
    "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331"
    "02"
    "0100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac00000000"
    "01" "00"
    "0100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac00000000"
    "00"
)


def test_spec_beef_constants():
    assert BEEF_VERSION == 4022206465
    assert BEEF_MAGIC == bytes.fromhex("0100beef")
    assert SPEC_BEEF_HEX.startswith("0100beef")


def test_spec_beef_parses_structure():
    beef = parse_beef_hex(SPEC_BEEF_HEX)
    assert len(beef.bumps) == 1
    assert len(beef.txs) == 2
    parent, payment = beef.txs
    assert parent.bump_index == 0
    assert payment.bump_index is None
    # The BUMP's block height decodes from its first VarInt.
    assert beef.bumps[0]["blockHeight"] == 814435
    # The payment spends the parent: its single input references the
    # parent txid (stored little-endian in the raw input).
    assert payment.raw is not None
    from sealrun.bsv import parse_tx

    payment_tx = parse_tx(payment.raw)
    assert len(payment_tx.inputs) == 1
    assert payment_tx.inputs[0].prev_txid == parent.txid
    assert payment_tx.inputs[0].prev_index == 0


def test_spec_beef_bump_contains_parent_txid():
    beef = parse_beef_hex(SPEC_BEEF_HEX)
    parent = beef.txs[0]
    level0 = beef.bumps[0]["path"][0]
    flagged = [leaf for leaf in level0 if leaf.get("txid")]
    assert len(flagged) == 1
    assert flagged[0]["hash"] == parent.txid


def test_spec_beef_round_trips():
    beef = parse_beef_hex(SPEC_BEEF_HEX)
    assert beef_to_hex(beef) == SPEC_BEEF_HEX.lower()
    assert beef_to_bytes(beef) == bytes.fromhex(SPEC_BEEF_HEX)
    assert parse_beef(bytes.fromhex(SPEC_BEEF_HEX)) == beef


def test_parse_beef_rejects_bad_version():
    bad = bytearray(bytes.fromhex(SPEC_BEEF_HEX))
    bad[0] = 0x02
    with pytest.raises(ValueError):
        parse_beef(bytes(bad))
    with pytest.raises(ValueError):
        parse_beef(b"")
    with pytest.raises(ValueError):
        parse_beef(b"\x01\x00\xbe\xef")


def test_parse_beef_rejects_truncated_and_trailing():
    raw = bytes.fromhex(SPEC_BEEF_HEX)
    with pytest.raises(ValueError):
        parse_beef(raw[:-1])
    with pytest.raises(ValueError):
        parse_beef(raw[:-100])
    with pytest.raises(ValueError):
        parse_beef(raw + b"\x00")
    with pytest.raises(ValueError):
        parse_beef_hex(SPEC_BEEF_HEX + "00")
    with pytest.raises(ValueError):
        parse_beef_hex("zz")
    with pytest.raises(ValueError):
        parse_beef_hex(123)  # type: ignore[arg-type]


def test_parse_beef_rejects_bad_has_bump_flag():
    # Flip the payment tx's Has-BUMP flag (last byte) from 00 to 02.
    raw = bytearray(bytes.fromhex(SPEC_BEEF_HEX))
    assert raw[-1] == 0x00
    raw[-1] = 0x02
    with pytest.raises(ValueError):
        parse_beef(bytes(raw))


def test_parse_beef_rejects_bump_index_out_of_range():
    # The parent tx's Has-BUMP flag is 01 followed by index 00; bump
    # the index to 01 (only 1 BUMP exists).
    beef = parse_beef_hex(SPEC_BEEF_HEX)
    rebuilt = bytearray()
    rebuilt += BEEF_MAGIC
    rebuilt += bytes([1])
    from sealrun.spv import bump_to_hex

    rebuilt += bytes.fromhex(bump_to_hex(beef.bumps[0]))
    rebuilt += bytes([2])
    parent_raw, payment_raw = beef.txs[0].raw, beef.txs[1].raw
    rebuilt += parent_raw + bytes([1, 1])  # has BUMP, index 1 (invalid)
    rebuilt += payment_raw + bytes([0])
    with pytest.raises(ValueError):
        parse_beef(bytes(rebuilt))


def test_parse_beef_rejects_duplicate_txid():
    beef = parse_beef_hex(SPEC_BEEF_HEX)
    parent_raw, payment_raw = beef.txs[0].raw, beef.txs[1].raw
    from sealrun.spv import bump_to_hex

    raw = (
        BEEF_MAGIC
        + bytes([1])
        + bytes.fromhex(bump_to_hex(beef.bumps[0]))
        + bytes([3])
        + parent_raw + bytes([1, 0])
        + parent_raw + bytes([1, 0])  # same tx twice
        + payment_raw + bytes([0])
    )
    with pytest.raises(ValueError):
        parse_beef(raw)


def _noncanonical_tx_fixture(*, field: str) -> tuple[bytes, bytes]:
    """Return ``(raw, canonical)`` for a tx with a non-canonical varint.

    A trivially-valid tx (version 1, one null-prevout input, one
    empty-script output) is built twice: once with the CompactSize
    varint for the chosen ``field`` non-canonically encoded (a
    ``0xfd``-prefixed encoding of a value below ``0xFD``), and once
    with the canonical single-byte encoding. The two byte strings
    describe the *same logical transaction*, so a parser that ignores
    canonicality re-serializes ``raw`` to ``canonical`` and reports a
    txid that ``raw`` does not hash to.
    """
    from sealrun.bsv import _varint

    def build(noncanonical: bool) -> bytes:
        out = bytearray()
        out += struct.pack("<i", 1)  # version
        # input count
        if field == "input_count" and noncanonical:
            out += b"\xfd" + struct.pack("<H", 1)
        else:
            out += _varint(1)
        # single input: null prevout, index 0, empty scriptSig, sequence
        out += b"\x00" * 32
        out += struct.pack("<I", 0)
        out += b"\x00"  # empty scriptSig
        out += struct.pack("<I", 0xFFFFFFFF)
        # output count
        out += _varint(1)
        out += struct.pack("<q", 0)  # value 0
        # output script length
        if field == "output_script_len" and noncanonical:
            out += b"\xfd" + struct.pack("<H", 0)
        else:
            out += b"\x00"
        out += struct.pack("<I", 0)  # locktime
        return bytes(out)

    raw = build(True)
    canonical = build(False)
    assert raw != canonical
    return raw, canonical


def test_parse_beef_rejects_noncanonical_varint():
    """A10 regression: a BEEF carrying a non-canonical CompactSize
    varint must be rejected outright, not quietly re-serialized.

    On the unfixed code this envelope parses "successfully" and the
    reported txid is the hash of the *canonical* re-serialization,
    not of the bytes in the envelope.
    """
    from sealrun.bsv import sha256d

    for field in ("input_count", "output_script_len"):
        tx_raw, canonical = _noncanonical_tx_fixture(field=field)
        # Sanity: the two encodings really do hash differently, so a
        # parse that accepts the envelope is reporting a txid the raw
        # bytes do not commit to.
        assert sha256d(canonical) != sha256d(tx_raw)

        envelope = BEEF_MAGIC + bytes([0, 1]) + tx_raw + bytes([0])
        with pytest.raises(ValueError):
            parse_beef(envelope)


def test_parse_beef_rejects_txid_that_does_not_match_raw_bytes():
    """A10 regression: the txid a BEEF reports must be the hash of the
    exact raw bytes it carries.

    The envelope below has well-formed structure but its raw tx bytes
    are non-canonical, so ``sha256d(raw)`` differs from
    ``sha256d(canonical)``. The unfixed parser reports the latter
    while keeping the non-canonical bytes as ``raw`` — so the reported
    txid is *not* the txid of the bytes the consumer re-hashes. The
    parser, the encoder, and the verifier must all refuse it.
    """
    from sealrun.bsv import sha256d

    tx_raw, canonical = _noncanonical_tx_fixture(field="input_count")
    claimed = sha256d(canonical)[::-1].hex()
    assert claimed != sha256d(tx_raw)[::-1].hex()

    # parse_beef must reject it (raw-bytes binding).
    envelope = BEEF_MAGIC + bytes([0, 1]) + tx_raw + bytes([0])
    with pytest.raises(ValueError):
        parse_beef(envelope)

    # A hand-built Beef carrying the mismatched pair must also be
    # refused at encode time (beef_to_bytes) and flagged by the
    # verifier as "txid does not match raw bytes".
    bad = Beef(bumps=(), txs=(BeefTx(raw=tx_raw, txid=claimed, bump_index=None),))
    with pytest.raises(ValueError):
        beef_to_bytes(bad)

    verdict = BeefVerifier(_RejectingFetcher()).verify_beef(bad)
    assert verdict.verified is False
    reason = verdict.per_tx[claimed]["reason"]
    # The entry must be rejected for a raw-bytes reason: either the
    # varint canonicality check fires first, or (on a canonical-but-
    # mismatched pair) the raw-bytes binding check does.
    assert (
        "does not match raw bytes" in reason
        or "non-canonical CompactSize" in reason
    )


class _RejectingFetcher:
    """A BlockFetcher that fails every fetch: these cases must never
    reach a network call — the structural rejection happens first."""

    def fetch_tx(self, _txid: str):
        raise AssertionError("verifier must not fetch for a malformed BEEF")

    def fetch_tx_full(self, _txid: str):
        raise AssertionError("verifier must not fetch for a malformed BEEF")

    def fetch_block(self, _height: int):
        raise AssertionError("verifier must not fetch for a malformed BEEF")

    def fetch_header(self, _height: int):
        raise AssertionError("verifier must not fetch for a malformed BEEF")


def test_beef_to_bytes_rejects_bad_bump_index():
    beef = parse_beef_hex(SPEC_BEEF_HEX)
    bad = Beef(
        bumps=beef.bumps,
        txs=(BeefTx(raw=beef.txs[0].raw, txid=beef.txs[0].txid, bump_index=5),),
    )
    with pytest.raises(ValueError):
        beef_to_bytes(bad)
    bad2 = Beef(
        bumps=beef.bumps,
        txs=(BeefTx(raw=beef.txs[0].raw, txid="00" * 32, bump_index=0),),
    )
    with pytest.raises(ValueError):
        beef_to_bytes(bad2)  # txid must match the raw bytes


# --- Live Teratestnet BEEF: anchor #1 + child -------------------------------
# BUMP built from the real block 36722 tx list; anchor #1's raw tx
# reconstructed from the WoC-TTN JSON fixture in test_anchor_signature
# (its txid must come out as TX1); child spends anchor #1's change
# output (vout 1, 99,500 sats) with a 500-sat fee.


def _anchor1_raw() -> bytes:
    from test_anchor_signature import ANCHOR1_TX, FAUCET_TX

    from sealrun.bsv import Tx, TxIn, TxOut

    script_sig = bytes.fromhex(ANCHOR1_TX["vin"][0]["scriptSig"]["hex"])
    op_return = bytes.fromhex(ANCHOR1_TX["vout"][0]["scriptPubKey"]["hex"])
    change_script = bytes.fromhex(ANCHOR1_TX["vout"][1]["scriptPubKey"]["hex"])
    tx = Tx(
        1,
        [TxIn(FAUCET_TX, 0, script_sig, 4294967295)],
        [TxOut(0, op_return), TxOut(99500, change_script)],
        0,
    )
    assert tx.txid() == "4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029"
    return tx.serialize()


def _child_raw() -> bytes:
    from sealrun.bsv import Tx, TxIn, TxOut

    change_script = bytes.fromhex(
        "76a9142e640e26bcb812790c2517d49d660c44e1b3ae6c88ac"
    )
    tx = Tx(
        1,
        [TxIn(
            "4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029",
            1, b"", 0xFFFFFFFF,
        )],
        [TxOut(99000, change_script)],
        0,
    )
    return tx.serialize()


def _ttn_beef():
    from test_spv import BLOCK_36722

    from sealrun.spv import build_bump

    bump = build_bump(BLOCK_36722["tx"], [2], block_height=36722)
    anchor_raw = _anchor1_raw()
    child_raw = _child_raw()
    from sealrun.bsv import parse_tx

    anchor_txid = parse_tx(anchor_raw).txid()
    child_txid = parse_tx(child_raw).txid()
    beef = Beef(
        bumps=(bump,),
        txs=(
            BeefTx(raw=anchor_raw, txid=anchor_txid, bump_index=0),
            BeefTx(raw=child_raw, txid=child_txid, bump_index=None),
        ),
    )
    return beef, anchor_txid, child_txid


class _HeaderFetcher:
    def __init__(self, header=None, error=None):
        self.header = header
        self.error = error

    def fetch_header(self, height):
        if self.error is not None:
            raise self.error
        return self.header


def _header_36722():
    from test_spv import BLOCK_36722

    return BlockHeader(
        version=BLOCK_36722["version"],
        prev_hash=BLOCK_36722["prev"],
        merkle_root=BLOCK_36722["root"],
        time=BLOCK_36722["time"],
        bits=BLOCK_36722["bits"],
        nonce=BLOCK_36722["nonce"],
        height=36722,
        hash=BLOCK_36722["hash"],
    )


def test_ttn_beef_round_trips_and_verifies():
    beef, anchor_txid, child_txid = _ttn_beef()
    assert parse_beef(beef_to_bytes(beef)) == beef
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(beef)
    assert verdict.verified is True
    assert verdict.per_tx[anchor_txid]["status"] == "bump"
    assert verdict.per_tx[anchor_txid]["verified"] is True
    assert verdict.per_tx[anchor_txid]["blockheight"] == 36722
    assert verdict.per_tx[child_txid]["status"] == "ancestry"
    assert verdict.per_tx[child_txid]["verified"] is True


def test_bump_never_overrides_structural_txid_mismatch():
    beef, anchor_txid, _child_txid = _ttn_beef()
    entry = beef.txs[0]
    raw = bytearray(entry.raw)
    raw[-1] ^= 1  # valid serialization whose bytes no longer hash to txid
    bad = Beef(
        bumps=beef.bumps,
        txs=(BeefTx(bytes(raw), entry.txid, entry.bump_index),),
    )
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(bad)
    assert verdict.verified is False
    assert verdict.per_tx[anchor_txid]["verified"] is False
    assert "does not match raw bytes" in verdict.per_tx[anchor_txid]["reason"]


def test_ttn_beef_child_before_parent_still_verifies():
    beef, anchor_txid, child_txid = _ttn_beef()
    reordered = Beef(bumps=beef.bumps, txs=(beef.txs[1], beef.txs[0]))
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(
        reordered
    )
    assert verdict.verified is True
    assert verdict.per_tx[child_txid]["status"] == "ancestry"


def test_verify_rejects_tampered_bump_and_header_problems():
    beef, anchor_txid, child_txid = _ttn_beef()
    tampered_bump = copy.deepcopy(beef.bumps[0])
    tampered_bump["path"][0][0]["hash"] = "0" * 64
    bad = Beef(bumps=(tampered_bump,), txs=beef.txs)
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(bad)
    assert verdict.verified is False
    assert verdict.per_tx[anchor_txid]["verified"] is False
    # The child depends on the anchor, so it fails too.
    assert verdict.per_tx[child_txid]["verified"] is False

    verdict = BeefVerifier(
        _HeaderFetcher(error=SPVUnavailable("down"))
    ).verify_beef(beef)
    assert verdict.verified is False

    wrong_height = _header_36722()
    wrong_height = BlockHeader(
        version=wrong_height.version,
        prev_hash=wrong_height.prev_hash,
        merkle_root=wrong_height.merkle_root,
        time=wrong_height.time,
        bits=wrong_height.bits,
        nonce=wrong_height.nonce,
        height=36721,
        hash=wrong_height.hash,
    )
    verdict = BeefVerifier(_HeaderFetcher(header=wrong_height)).verify_beef(beef)
    assert verdict.verified is False
    assert "height" in verdict.per_tx[anchor_txid]["reason"]


def test_verify_rejects_missing_parent_overspend_and_bad_vout():
    beef, anchor_txid, child_txid = _ttn_beef()
    from sealrun.bsv import Tx, TxIn, TxOut, parse_tx

    # Child spends a parent that is not in the BEEF.
    orphan = Tx(
        1, [TxIn("ff" * 32, 0, b"", 0xFFFFFFFF)], [TxOut(100, b"")], 0
    )
    orphan_raw = orphan.serialize()
    orphan_beef = Beef(
        bumps=beef.bumps,
        txs=beef.txs + (
            BeefTx(
                raw=orphan_raw, txid=parse_tx(orphan_raw).txid(),
                bump_index=None,
            ),
        ),
    )
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(
        orphan_beef
    )
    assert verdict.verified is False
    assert verdict.per_tx[parse_tx(orphan_raw).txid()]["verified"] is False

    # Child overspends anchor #1's change output (99,500 in, 100,000 out).
    change_script = bytes.fromhex(
        "76a9142e640e26bcb812790c2517d49d660c44e1b3ae6c88ac"
    )
    overspend = Tx(
        1,
        [TxIn(anchor_txid, 1, b"", 0xFFFFFFFF)],
        [TxOut(100000, change_script)],
        0,
    )
    overspend_raw = overspend.serialize()
    overspend_beef = Beef(
        bumps=beef.bumps,
        txs=(
            beef.txs[0],
            BeefTx(
                raw=overspend_raw, txid=parse_tx(overspend_raw).txid(),
                bump_index=None,
            ),
        ),
    )
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(
        overspend_beef
    )
    assert verdict.verified is False
    assert "exceed" in verdict.per_tx[parse_tx(overspend_raw).txid()]["reason"]

    # Child references a vout that does not exist in the parent.
    bad_vout = Tx(
        1,
        [TxIn(anchor_txid, 7, b"", 0xFFFFFFFF)],
        [TxOut(100, change_script)],
        0,
    )
    bad_vout_raw = bad_vout.serialize()
    bad_vout_beef = Beef(
        bumps=beef.bumps,
        txs=(
            beef.txs[0],
            BeefTx(
                raw=bad_vout_raw, txid=parse_tx(bad_vout_raw).txid(),
                bump_index=None,
            ),
        ),
    )
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(
        bad_vout_beef
    )
    assert verdict.verified is False


def test_verify_rejects_ancestry_cycle():
    # A genuine in-BEEF cycle (A spends B, B spends A) would need a
    # SHA-256 fixed point, so it cannot be constructed — but the DFS
    # must still terminate on adversarial graphs. The closest
    # constructible case is a tx whose input references a txid that no
    # tx in the BEEF has (here, its own would-be txid): it must fail
    # as a missing parent, not loop.
    from sealrun.bsv import Tx, TxIn, TxOut, parse_tx

    self_tx = Tx(
        1, [TxIn("00" * 32, 0, b"", 0xFFFFFFFF)], [TxOut(100, b"")], 0
    )
    self_raw = self_tx.serialize()
    self_txid = parse_tx(self_raw).txid()
    self_spend = Tx(
        1,
        [TxIn(self_txid, 0, b"", 0xFFFFFFFF)],
        [TxOut(100, b"")],
        0,
    )
    self_spend_raw = self_spend.serialize()
    cycle_beef = Beef(
        bumps=(),
        txs=(
            BeefTx(
                raw=self_spend_raw, txid=parse_tx(self_spend_raw).txid(),
                bump_index=None,
            ),
        ),
    )
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(
        cycle_beef
    )
    assert verdict.verified is False



def test_verify_rejects_empty_beef_and_mined_tx_not_in_bump():
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(
        Beef(bumps=(), txs=())
    )
    assert verdict.verified is False
    assert "no transactions" in verdict.reason

    beef, anchor_txid, child_txid = _ttn_beef()
    # Anchor tx claims BUMP 0, but the BUMP proves a different tx: swap
    # the BUMP for one built over a different tx set.
    from test_spv import BLOCK_36722

    from sealrun.spv import build_bump

    other_bump = build_bump(BLOCK_36722["tx"], [0], block_height=36722)
    swapped = Beef(bumps=(other_bump,), txs=beef.txs)
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(
        swapped
    )
    assert verdict.verified is False
    assert verdict.per_tx[anchor_txid]["verified"] is False


# --- apply_beef_inclusion ----------------------------------------------------


def test_apply_beef_inclusion_simple_and_chain_shapes():
    from sealrun.anchor import encode_anchor_payload

    beef, anchor_txid, _child = _ttn_beef()
    result = {"anchors": [{"txid": anchor_txid, "payload_hex": "00"}]}
    out = apply_beef_inclusion(
        result, BeefVerifier(_HeaderFetcher(header=_header_36722())), beef
    )
    assert out["beef_inclusion_verified"] is True
    assert out["anchors"][0]["beef_inclusion_verified"] is True
    assert out["anchors"][0]["beef_inclusion"]["status"] == "bump"
    assert result["anchors"][0].get("beef_inclusion") is None  # not mutated

    chain_result = {"chain": {"anchors": [
        {"txid": anchor_txid},
        {"txid": "ee" * 32},
    ]}}
    out = apply_beef_inclusion(
        chain_result, BeefVerifier(_HeaderFetcher(header=_header_36722())), beef
    )
    assert out["beef_inclusion_verified"] is False
    assert out["chain"]["anchors"][0]["beef_inclusion_verified"] is True
    assert out["chain"]["anchors"][1]["beef_inclusion_verified"] is False
    assert "not in BEEF" in out["chain"]["anchors"][1]["beef_inclusion"]["reason"]


def test_apply_beef_inclusion_rejects_non_beef():
    with pytest.raises(ValueError):
        apply_beef_inclusion(
            {}, BeefVerifier(_HeaderFetcher(header=_header_36722())), {}
        )


# --- CLI ---------------------------------------------------------------------


def _real_anchor1_payload():
    # The real anchor #1 OP_RETURN payload. Payload binding now
    # recomputes the fetched tx's txid, so the fake provider must
    # return a full tx body that hashes to the claimed txid and
    # carries the claimed payload — a vout-only stub cannot pass.
    from test_anchor_signature import ANCHOR1_TX

    script = bytes.fromhex(ANCHOR1_TX["vout"][0]["scriptPubKey"]["hex"])
    assert script[:3] == bytes.fromhex("6a4c54")
    return script[3:]


def _run_cli_beef(tmp_path, capsys, monkeypatch, beef, anchor_txid):
    from sealrun import cli as cli_module
    from test_anchor_signature import ANCHOR1_TX

    claimed = _real_anchor1_payload()

    class FakeWoC:
        def __init__(self, base_url=None):
            pass

        def fetch_header(self, height):
            return _header_36722()

        def fetch_tx_full(self, txid):
            if txid.lower() == anchor_txid.lower():
                return copy.deepcopy(ANCHOR1_TX)
            raise KeyError(txid)

    monkeypatch.setattr(cli_module, "WoCBlockFetcher", FakeWoC)
    genesis = "0" * 64
    anchor = tmp_path / "a1.json"
    anchor.write_text(json.dumps({
        "payload_hex": claimed.hex(),
        "txid": anchor_txid,
    }))
    beef_file = tmp_path / "envelope.beef"
    beef_file.write_bytes(beef_to_bytes(beef))
    cli_module.main([
        "anchor-chain-verify", "--genesis-txid", genesis,
        "--anchor", str(anchor),
        "--beef-file", str(beef_file),
    ])
    return capsys.readouterr().out


def test_cli_beef_file_verifies_and_prints_line(tmp_path, capsys, monkeypatch):
    beef, anchor_txid, _child = _ttn_beef()
    out = _run_cli_beef(tmp_path, capsys, monkeypatch, beef, anchor_txid)
    assert "BEEF INCLUSION VERIFIED: 1 anchor(s)" in out
    assert '"beef_inclusion_verified": true' in out
    assert "LOCAL CHECK ONLY" not in out


def test_cli_beef_file_accepts_hex(tmp_path, capsys, monkeypatch):
    from sealrun import cli as cli_module
    from test_anchor_signature import ANCHOR1_TX

    beef, anchor_txid, _child = _ttn_beef()

    genesis = "0" * 64
    claimed = _real_anchor1_payload()

    class FakeWoC:
        def __init__(self, base_url=None):
            pass

        def fetch_header(self, height):
            return _header_36722()

        def fetch_tx_full(self, txid):
            if txid.lower() == anchor_txid.lower():
                return copy.deepcopy(ANCHOR1_TX)
            raise KeyError(txid)

    monkeypatch.setattr(cli_module, "WoCBlockFetcher", FakeWoC)
    anchor = tmp_path / "a1.json"
    anchor.write_text(json.dumps({
        "payload_hex": claimed.hex(),
        "txid": anchor_txid,
    }))
    beef_file = tmp_path / "envelope.hex"
    beef_file.write_text(beef_to_hex(beef) + "\n")
    cli_module.main([
        "anchor-chain-verify", "--genesis-txid", genesis,
        "--anchor", str(anchor),
        "--beef-file", str(beef_file),
    ])
    out = capsys.readouterr().out
    assert "BEEF INCLUSION VERIFIED: 1 anchor(s)" in out


def test_cli_beef_file_failure_prints_failed_line(tmp_path, capsys, monkeypatch):
    beef, anchor_txid, _child = _ttn_beef()
    # BEEF without the anchor tx: the anchor cannot be proven.
    empty = Beef(bumps=(), txs=())
    out = _run_cli_beef(tmp_path, capsys, monkeypatch, empty, anchor_txid)
    assert "BEEF INCLUSION CHECK FAILED" in out
    assert '"beef_inclusion_verified": false' in out
    assert "LOCAL CHECK ONLY" in out


# --- Extra adversarial coverage --------------------------------------------
# Shared-BUMP success (two mined txs under one BUMP), deep ancestry,
# offset-aware sub-parsers, unreferenced BUMPs, huge counts.


def test_two_mined_txs_share_one_bump():
    from sealrun.bsv import Tx, TxOut, parse_tx
    from sealrun.spv import build_bump, merkle_root, verify_pow

    raw_a = Tx(1, [], [TxOut(1, b"\x01")], 0).serialize()
    raw_b = Tx(1, [], [TxOut(2, b"\x02")], 0).serialize()
    txid_a, txid_b = parse_tx(raw_a).txid(), parse_tx(raw_b).txid()
    bump = build_bump([txid_a, txid_b], [0, 1], block_height=999)
    root = merkle_root([txid_a, txid_b])
    nonce = 0
    while True:
        header = BlockHeader(
            version=1, prev_hash="00" * 32, merkle_root=root, time=0,
            bits=0x207FFFFF, nonce=nonce, height=999, hash="00" * 32,
        )
        if verify_pow(header.to_bytes(), 0x207FFFFF):
            break
        nonce += 1
    beef = Beef(
        bumps=(bump,),
        txs=(
            BeefTx(raw=raw_a, txid=txid_a, bump_index=0),
            BeefTx(raw=raw_b, txid=txid_b, bump_index=0),
        ),
    )
    verdict = BeefVerifier(_HeaderFetcher(header=header)).verify_beef(beef)
    assert verdict.verified is True
    assert verdict.per_tx[txid_a]["status"] == "bump"
    assert verdict.per_tx[txid_b]["status"] == "bump"


def test_deep_ancestry_chain_verifies():
    from sealrun.bsv import Tx, TxIn, TxOut, parse_tx
    from sealrun.spv import build_bump, verify_pow

    # Root is a mined coinbase-like tx (single-tx block, empty BUMP
    # path, root == txid); 59 unmined descendants each spend the
    # previous tx's only output at full value (fee 0).
    root_tx = Tx(1, [], [TxOut(1000, b"")], 0)
    root_raw = root_tx.serialize()
    root_txid = parse_tx(root_raw).txid()
    bump = build_bump([root_txid], [0], block_height=999)
    assert bump["path"] == []
    nonce = 0
    while True:
        header = BlockHeader(
            version=1, prev_hash="00" * 32, merkle_root=root_txid,
            time=0, bits=0x207FFFFF, nonce=nonce, height=999,
            hash="00" * 32,
        )
        if verify_pow(header.to_bytes(), 0x207FFFFF):
            break
        nonce += 1
    raws = [root_raw]
    prev_txid = root_txid
    for _ in range(59):
        tx = Tx(
            1,
            [TxIn(prev_txid, 0, b"", 0xFFFFFFFF)],
            [TxOut(1000, b"")],
            0,
        )
        raw = tx.serialize()
        prev_txid = parse_tx(raw).txid()
        raws.append(raw)
    beef = Beef(
        bumps=(bump,),
        txs=tuple(
            BeefTx(
                raw=raw,
                txid=parse_tx(raw).txid(),
                bump_index=0 if i == 0 else None,
            )
            for i, raw in enumerate(raws)
        ),
    )
    verdict = BeefVerifier(_HeaderFetcher(header=header)).verify_beef(beef)
    assert verdict.verified is True


def test_unreferenced_bump_is_ignored():
    beef, _anchor, _child = _ttn_beef()
    from test_spv import BLOCK_36722

    from sealrun.spv import build_bump

    extra = build_bump(BLOCK_36722["tx"], [0], block_height=36722)
    beef2 = Beef(bumps=beef.bumps + (extra,), txs=beef.txs)
    verdict = BeefVerifier(_HeaderFetcher(header=_header_36722())).verify_beef(
        beef2
    )
    assert verdict.verified is True


def test_parse_beef_rejects_huge_counts_without_hanging():
    with pytest.raises(ValueError):
        # nBUMPs = 0xFFFFFFFF, then nothing: must fail on truncation.
        parse_beef(BEEF_MAGIC + b"\xfe\xff\xff\xff\xff")


def test_parse_bump_bytes_offset():
    from test_bump import SPEC_JSON

    from sealrun.spv import bump_to_bytes, parse_bump_bytes

    blob = b"PREFIX" + bump_to_bytes(SPEC_JSON) + b"SUFFIX"
    bump, consumed = parse_bump_bytes(blob, 6)
    assert bump == SPEC_JSON
    assert consumed == len(bump_to_bytes(SPEC_JSON))
    with pytest.raises(ValueError):
        parse_bump_bytes(blob, len(blob) + 1)


def test_parse_tx_prefix_offset():
    from sealrun.bsv import parse_tx, parse_tx_prefix

    raw = _anchor1_raw()
    blob = b"\x00\x01\x02" + raw + b"\x99"
    tx, consumed = parse_tx_prefix(blob, 3)
    assert consumed == len(raw)
    assert tx.txid() == parse_tx(raw).txid()
    with pytest.raises(ValueError):
        parse_tx_prefix(blob, len(blob) + 1)
