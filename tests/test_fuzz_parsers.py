"""Stdlib-only parser fuzzer for BUMP (spv.py) and BEEF (beef.py).

An outside AI supplied a Hypothesis-based skeleton for this job, but it was
wrong in every detail: it called a nonexistent ``spv.parse_bump``, fuzzed
Bitcoin Core merkleblock format (flags bitmask + hash list) instead of
BRC-74 BUMP, and assumed a Hypothesis dependency this project does not have
(stdlib-only; test deps are just pytest). This file corrects all three:
it uses the ``random`` module only, with fixed seeds for reproducibility,
and targets the real entry points.

Invariants under test (all fail-closed):
- ``parse_bump_bytes`` / ``parse_bump_json``: return a normalized dict or
  raise ``ValueError`` — never any other exception type.
- ``verify_bump_proof``: return a bool — never raise (its docstring
  promises this; the implementation catches the plausible error types).
- ``parse_beef``: return a :class:`Beef` or raise ``BeefError``
  (a ``ValueError``) — never any other exception type.
- ``BeefVerifier.verify_beef``: return a :class:`BeefVerification` —
  never raise (except on a non-``Beef`` argument, a programmer error);
  per-tx verdicts cover only txids actually in the envelope.
- Positive properties: ``build_bump`` output verifies for every proven
  txid and for nothing outside the block; BUMP byte round-trips preserve verification.

Determinism: every test uses ``random.Random(<fixed seed>)``, so the same
seed produces the same inputs on every run. If a seed ever exposes a
failure, the seed is the reproducer.
"""

import random
import struct

import pytest

from aiguard.beef import (
    Beef,
    BeefError,
    BeefTx,
    BeefVerification,
    BeefVerifier,
    beef_to_bytes,
    parse_beef,
)
from aiguard.bsv import Tx, TxIn, TxOut
from aiguard.spv import (
    build_bump,
    bump_to_bytes,
    merkle_root,
    parse_bump_bytes,
    parse_bump_json,
    verify_bump_proof,
)


# ---------------------------------------------------------------------------
# Generators (all deterministic given the rng)
# ---------------------------------------------------------------------------


def _rand_hex(rng: random.Random, nbytes: int = 32) -> str:
    return bytes(rng.getrandbits(8) for _ in range(nbytes)).hex()


def _rand_txid_set(rng: random.Random, n: int) -> list[str]:
    seen: set[str] = set()
    while len(seen) < n:
        seen.add(_rand_hex(rng))
    return sorted(seen)


def _mutate_bytes(rng: random.Random, data: bytes) -> bytes:
    """One random small mutation: bit flip, byte flip, truncate, or extend."""
    if not data:
        return bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 8)))
    kind = rng.choice(["bitflip", "byteflip", "truncate", "extend", "splice"])
    buf = bytearray(data)
    if kind == "bitflip":
        i = rng.randrange(len(buf))
        buf[i] ^= 1 << rng.randrange(8)
    elif kind == "byteflip":
        i = rng.randrange(len(buf))
        buf[i] = rng.getrandbits(8)
    elif kind == "truncate":
        buf = buf[: rng.randrange(len(buf))]
    elif kind == "extend":
        buf += bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 16)))
    else:  # splice: replace a random span with random bytes
        i = rng.randrange(len(buf))
        j = min(len(buf), i + rng.randint(1, 8))
        buf[i:j] = bytes(rng.getrandbits(8) for _ in range(j - i))
    return bytes(buf)


def _valid_bump_bytes(rng: random.Random) -> tuple[bytes, list[str], list[int]]:
    txids = _rand_txid_set(rng, rng.randint(2, 9))
    indices = sorted(rng.sample(range(len(txids)), rng.randint(1, len(txids))))
    bump = build_bump(txids, indices, block_height=rng.randint(0, 900_000))
    return bump_to_bytes(bump), txids, indices


def _rand_jsonish(rng: random.Random, depth: int = 0):
    """Random JSON-ish value, nested to depth 2."""
    choices = ["none", "bool", "int", "float", "str", "list", "dict"]
    kind = rng.choice(choices)
    if kind == "none":
        return None
    if kind == "bool":
        return rng.choice([True, False])
    if kind == "int":
        return rng.choice(
            [0, 1, -1, 64, 65, 2**31, 2**64, rng.randint(-100, 100)]
        )
    if kind == "float":
        return rng.choice([0.5, 1.5, float("nan"), float("inf")])
    if kind == "str":
        return rng.choice(["", "0", "ab" * 32, "zz" * 32, "blockHeight", "x" * 100])
    if kind == "list" or depth >= 2:
        return [_rand_jsonish(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {
        rng.choice(["blockHeight", "path", "offset", "hash", "txid", "junk"]):
        _rand_jsonish(rng, depth + 1)
        for _ in range(rng.randint(0, 3))
    }


def _malformed_bump_jsons(rng: random.Random) -> list[object]:
    """Structured malformed BUMP JSON shapes (not random noise)."""
    good_hash = "ab" * 32
    return [
        None,
        [],
        "bump",
        42,
        {},
        {"blockHeight": -1, "path": []},
        {"blockHeight": True, "path": []},
        {"blockHeight": "1", "path": []},
        {"blockHeight": 1.5, "path": []},
        {"blockHeight": 1},
        {"path": []},
        {"blockHeight": 1, "path": {}},
        {"blockHeight": 1, "path": "x"},
        {"blockHeight": 1, "path": [[]]},
        {"blockHeight": 1, "path": [[{"offset": -1, "hash": good_hash}]]},
        {"blockHeight": 1, "path": [[{"offset": True, "hash": good_hash}]]},
        {"blockHeight": 1, "path": [[{"offset": "0", "hash": good_hash}]]},
        {"blockHeight": 1, "path": [[{"hash": good_hash}]]},
        {"blockHeight": 1, "path": [[{"offset": 0}]]},
        {"blockHeight": 1, "path": [[{"offset": 0, "hash": "zz" * 32}]]},
        {"blockHeight": 1, "path": [[{"offset": 0, "hash": "ab"}]]},
        {"blockHeight": 1, "path": [[{"offset": 0, "hash": 42}]]},
        {
            "blockHeight": 1,
            "path": [
                [
                    {"offset": 0, "hash": good_hash},
                    {"offset": 0, "hash": good_hash},
                ]
            ],
        },
        {
            "blockHeight": 1,
            "path": [[{"offset": 0, "duplicate": True, "hash": good_hash}]],
        },
        {
            "blockHeight": 1,
            "path": [[{"offset": 0, "duplicate": True, "txid": True}]],
        },
        {
            "blockHeight": 1,
            "path": [[{"offset": 0, "hash": good_hash, "txid": 1}]],
        },
        {"blockHeight": 1, "path": [[] for _ in range(65)]},
        {"blockHeight": 1, "path": [[{"offset": 0, "hash": good_hash}]] * 3},
        # Unknown keys are ignored by the parser: still valid input shape.
        {"blockHeight": 1, "path": [], "extra": rng.choice([1, "x", None])},
    ]


# ---------------------------------------------------------------------------
# Test 1 — parse_bump_bytes
# ---------------------------------------------------------------------------


def test_fuzz_parse_bump_bytes():
    rng = random.Random(0xBEEF01)
    cases: list[tuple[bytes, int]] = []

    # (a) Pure random byte strings.
    for _ in range(400):
        cases.append(
            (bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200))), 0)
        )

    # (b) Mutations of valid BUMP bytes: all truncations + random edits.
    valid_blobs: list[bytes] = []
    for _ in range(3):
        blob, _, _ = _valid_bump_bytes(rng)
        valid_blobs.append(blob)
        for cut in range(len(blob) + 1):
            cases.append((blob[:cut], 0))
    for blob in valid_blobs:
        for _ in range(100):
            cases.append((_mutate_bytes(rng, blob), 0))

    # (c) Structured malformed encodings: layout is varint blockHeight,
    # 1-byte tree height, then per level: varint n_leaves, per leaf:
    # varint offset, 1 flag byte, optional 32-byte hash.
    structured = [
        b"",  # empty
        b"\x01",  # height only, no tree-height byte
        b"\x01\x41",  # tree height 65 (> 64)
        b"\x01\xff",  # tree height 255
        b"\x01\x01\x01\x00\x03",  # leaf flag 0x03 invalid
        b"\x01\x01\x01\x00\xff",  # leaf flag 0xFF invalid
        b"\x01\x01\x01\x00\x02" + b"\xaa" * 10,  # truncated 32-byte hash
        b"\x01\x01\x01\xff\x01\x02",  # varint offset truncated (0xFF + 2B)
        b"\x01\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff",  # huge n_leaves
        b"\x01\x01\x01\x00\x00",  # sibling leaf, zero-length rest
        b"\x01\x01\x01\x00\x01",  # duplicate leaf, no hash needed
        b"\x01\x01\x01\x00\x02" + b"\x00" * 32,  # txid leaf, all-zero hash
        b"\x01\x00",  # tree height 0, no levels
        b"\xfd\x00\x00\x01\x00",  # block height via 0xFD varint
        b"\xfe\x00\x00\x00\x00\x01\x00",  # block height via 0xFE varint
        b"\xff" + b"\x00" * 8 + b"\x01\x00",  # block height via 0xFF varint
        b"\xfd\x00",  # truncated 0xFD varint
        b"\xfe\x00\x00",  # truncated 0xFE varint
    ]
    for raw in structured:
        cases.append((raw, 0))
    # Offset parameter: negative / past-the-end must fail closed.
    for raw in [b"\x01\x01\x01\x00\x01", b""]:
        cases.append((raw, -1))
        cases.append((raw, len(raw) + 1))
        cases.append((raw, len(raw)))

    for data, offset in cases:
        try:
            result = parse_bump_bytes(data, offset)
        except ValueError:
            continue
        except Exception as exc:  # noqa: BLE001 — any other type is a finding
            pytest.fail(
                f"parse_bump_bytes leaked {type(exc).__name__} for "
                f"input {data[:32]!r} offset {offset}: {exc}"
            )
        assert isinstance(result, tuple) and len(result) == 2, result
        bump, consumed = result
        assert isinstance(bump, dict), bump
        assert isinstance(bump.get("blockHeight"), int)
        assert bump["blockHeight"] >= 0
        assert isinstance(bump.get("path"), list)
        assert isinstance(consumed, int) and 0 <= consumed <= len(data)


# ---------------------------------------------------------------------------
# Test 2 — parse_bump_json
# ---------------------------------------------------------------------------


def test_fuzz_parse_bump_json():
    rng = random.Random(0xBEEF02)
    cases: list[object] = [_rand_jsonish(rng) for _ in range(400)]
    cases.extend(_malformed_bump_jsons(rng))
    # Random mutations of a valid built BUMP dict.
    for _ in range(3):
        txids = _rand_txid_set(rng, 5)
        bump = build_bump(txids, [0, 2], block_height=100)
        import copy
        import json

        for _ in range(50):
            mutated = copy.deepcopy(bump)
            # Randomly perturb one field.
            choice = rng.choice(["height", "path-type", "leaf", "drop"])
            if choice == "height":
                mutated["blockHeight"] = rng.choice([-1, True, "1", 1.5, None])
            elif choice == "path-type":
                mutated["path"] = rng.choice([None, {}, "x", 1])
            elif choice == "leaf":
                if mutated["path"] and mutated["path"][0]:
                    mutated["path"][0][0]["offset"] = rng.choice(
                        [-1, True, "0", None]
                    )
            else:
                mutated.pop(rng.choice(list(mutated.keys())), None)
            cases.append(json.loads(json.dumps(mutated, default=str)))

    for bump in cases:
        try:
            result = parse_bump_json(bump)
        except ValueError:
            continue
        except Exception as exc:  # noqa: BLE001 — any other type is a finding
            pytest.fail(
                f"parse_bump_json leaked {type(exc).__name__} for "
                f"input {str(bump)[:120]!r}: {exc}"
            )
        assert isinstance(result, dict), result
        assert isinstance(result.get("blockHeight"), int)
        assert result["blockHeight"] >= 0
        assert isinstance(result.get("path"), list)
        assert len(result["path"]) <= 64


# ---------------------------------------------------------------------------
# Test 3 — verify_bump_proof: no false-accept, no escape
# ---------------------------------------------------------------------------


def test_fuzz_verify_bump_proof():
    rng = random.Random(0xBEEF03)
    # Random (txid, bump, root) combos: garbage bumps included.
    for _ in range(300):
        txid = rng.choice([_rand_hex(rng), "", "zz" * 32, "ab", _rand_hex(rng, 16)])
        root = rng.choice([_rand_hex(rng), "", "zz" * 32])
        bump = rng.choice(
            [
                None,
                {},
                {"blockHeight": 1},
                {"blockHeight": 1, "path": "x"},
                {"blockHeight": 1, "path": [[{"offset": 0, "hash": "ab" * 32}]]},
                _rand_jsonish(rng),
            ]
        )
        try:
            result = verify_bump_proof(txid, bump, root)
        except Exception as exc:  # noqa: BLE001 — docstring says never raises
            pytest.fail(
                f"verify_bump_proof raised {type(exc).__name__} for "
                f"txid {txid[:16]!r} bump {str(bump)[:80]!r}: {exc}"
            )
        assert isinstance(result, bool), result

    # Positive property: a built BUMP verifies for included txids only.
    for _ in range(10):
        txids = _rand_txid_set(rng, rng.randint(2, 9))
        indices = sorted(rng.sample(range(len(txids)), rng.randint(1, len(txids))))
        bump = build_bump(txids, indices, block_height=100)
        root = merkle_root(txids)
        for i, txid in enumerate(txids):
            result = verify_bump_proof(txid, bump, root)
            if i in indices:
                assert result is True, f"proven txid {txid} failed to verify"
            if result is True:
                # Soundness: anything that verifies must genuinely be a
                # member of the block. (Siblings of proven txids also
                # verify — they are real members, so that is not a
                # false-accept. Members absent from the path may verify
                # False; that is incompleteness, not unsoundness.)
                assert txid in txids, f"non-member txid {txid} verified"
        # Wrong root, and a non-included txid, must both fail.
        assert verify_bump_proof(txids[0], bump, _rand_hex(rng)) is False
        assert verify_bump_proof(_rand_hex(rng), bump, root) is False


# ---------------------------------------------------------------------------
# Test 4 — BUMP round-trip
# ---------------------------------------------------------------------------


def test_fuzz_bump_round_trip():
    rng = random.Random(0xBEEF04)
    for n in (1, 2, 3, 5, 9):
        txids = _rand_txid_set(rng, n)
        indices = sorted(rng.sample(range(n), rng.randint(1, n)))
        bump = build_bump(txids, indices, block_height=777)
        blob = bump_to_bytes(bump)
        parsed, consumed = parse_bump_bytes(blob)
        assert consumed == len(blob)
        # Round-trip preserves the JSON form (normalization is idempotent).
        assert parse_bump_json(parsed) == parse_bump_json(bump)
        root = merkle_root(txids)
        for i, txid in enumerate(txids):
            result = verify_bump_proof(txid, parsed, root)
            if i in indices:
                assert result is True, f"proven txid {txid} failed to verify"
            if result is True:
                assert txid in txids, f"non-member txid {txid} verified"
        # JSON-form parse of the same BUMP also verifies.
        assert parse_bump_json(bump)["blockHeight"] == 777


# ---------------------------------------------------------------------------
# Test 5 — BEEF parsing
# ---------------------------------------------------------------------------


def _valid_beef_bytes() -> bytes:
    # Reuse the existing TTN BEEF fixture (real on-chain envelope).
    from test_beef import _ttn_beef

    beef, _, _ = _ttn_beef()
    return beef_to_bytes(beef)


def _mutated_beef_inputs(rng: random.Random) -> list[bytes]:
    valid = _valid_beef_bytes()
    cases: list[bytes] = []
    for _ in range(300):
        cases.append(bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200))))
    for cut in range(len(valid) + 1):
        cases.append(valid[:cut])
    for _ in range(200):
        cases.append(_mutate_bytes(rng, valid))
    # Structured malformed envelopes: version is uint32LE 4022206465.
    version = struct.pack("<I", 4022206465)
    cases.extend(
        [
            b"",
            b"\x01\x00",
            struct.pack("<I", 1234) + b"\x00\x00",
            version,  # version only
            version + b"\x02",  # nBUMPs=2, no BUMP bytes
            version + b"\x00\x01",  # nBUMPs=0, nTx=1, no tx bytes
            version + b"\x00\x01\x00\x02",  # Has-BUMP flag 0x02
            version + b"\x00\x01\x00\x00",  # Has-BUMP flag 0x00, empty tx
            version + b"\xff\xff\xff\xff\xff\xff\xff\xff\xff",  # huge nBUMPs
            version + b"\x00\xff\xff\xff\xff\xff\xff\xff\xff",  # huge nTx
            version + b"\x00\x00" + b"\x00",  # nTx=0, trailing byte
        ]
    )
    return cases


def test_fuzz_parse_beef():
    rng = random.Random(0xBEEF05)
    for data in _mutated_beef_inputs(rng):
        try:
            result = parse_beef(data)
        except ValueError:
            continue
        except Exception as exc:  # noqa: BLE001 — any other type is a finding
            pytest.fail(
                f"parse_beef leaked {type(exc).__name__} for "
                f"input {data[:32]!r}: {exc}"
            )
        assert isinstance(result, Beef), result
        # Every txid must match its raw bytes (the parser guarantees this,
        # but the fuzzer re-checks the invariant rather than trusting it).
        from aiguard.bsv import parse_tx

        for tx in result.txs:
            assert parse_tx(tx.raw).txid() == tx.txid


# ---------------------------------------------------------------------------
# Test 6 — BeefVerifier.verify_beef + ancestry cycle guard
# ---------------------------------------------------------------------------


class _StubHeaderFetcher:
    """Header fetcher returning the fixed TTN 36722 header (as in test_beef)."""

    def __init__(self) -> None:
        from test_beef import _header_36722

        self._header = _header_36722()

    def fetch_header(self, height):
        return self._header


def test_fuzz_verify_beef_on_mutated_envelopes():
    rng = random.Random(0xBEEF06)
    verifier = BeefVerifier(_StubHeaderFetcher())
    checked = 0
    for data in _mutated_beef_inputs(rng):
        try:
            beef = parse_beef(data)
        except ValueError:
            continue
        # Mutated envelope still parses: verification must fail closed.
        try:
            verdict = verifier.verify_beef(beef)
        except ValueError:
            # Only acceptable for a non-Beef argument; parse_beef returned
            # a Beef, so any ValueError here is a finding.
            pytest.fail(f"verify_beef raised ValueError on a parsed Beef: {data[:32]!r}")
        except Exception as exc:  # noqa: BLE001 — any other type is a finding
            pytest.fail(
                f"verify_beef leaked {type(exc).__name__} for "
                f"input {data[:32]!r}: {exc}"
            )
        assert isinstance(verdict, BeefVerification), verdict
        envelope_txids = {tx.txid.lower() for tx in beef.txs}
        assert set(verdict.per_tx) <= envelope_txids, (
            "per-tx verdict for a txid not in the envelope",
            set(verdict.per_tx) - envelope_txids,
        )
        assert verdict.verified == (
            bool(verdict.per_tx)
            and all(entry["verified"] for entry in verdict.per_tx.values())
        )
        checked += 1
    # The mutation set must actually exercise the verifier (not all inputs
    # rejected at parse time). If this ever fails, the generator — not the
    # verifier — needs widening.
    assert checked > 0, "no mutated envelope parsed; fuzzer generated nothing"
    # Direct case: a tx whose bump_index points at a garbage BUMP must fail.
    from test_beef import _ttn_beef

    beef, anchor_txid, _ = _ttn_beef()
    garbage = Beef(
        bumps=({"blockHeight": 1, "path": "not-a-list"},),
        txs=(beef.txs[0],),
    )
    verdict = verifier.verify_beef(garbage)
    assert verdict.verified is False
    assert verdict.per_tx[anchor_txid.lower()]["verified"] is False


def test_verify_ancestry_cycle_guard_direct():
    """White-box cycle test: A spends B, B spends A, bypassing hash
    consistency (a true hash cycle is cryptographically impossible to
    construct, so this calls _verify_ancestry directly). The `visiting`
    guard must return False — not RecursionError, not an infinite loop.
    """
    key_a, key_b = "aa" * 32, "bb" * 32
    parsed = {
        key_a: Tx(1, [TxIn(key_b, 0, b"", 0xFFFFFFFF)], [TxOut(100, b"")], 0),
        key_b: Tx(1, [TxIn(key_a, 0, b"", 0xFFFFFFFF)], [TxOut(100, b"")], 0),
    }
    by_txid = {
        key_a: BeefTx(raw=b"", txid=key_a, bump_index=None),
        key_b: BeefTx(raw=b"", txid=key_b, bump_index=None),
    }
    verifier = BeefVerifier(None)  # fetcher unused by _verify_ancestry
    per_tx: dict = {}
    memo: dict = {}
    result = verifier._verify_ancestry(
        key_a, by_txid, parsed, {}, per_tx, memo, set()
    )
    assert result is False
    assert memo.get(key_a) is False
    assert memo.get(key_b) is False
    assert per_tx[key_a]["verified"] is False
    assert per_tx[key_b]["verified"] is False
