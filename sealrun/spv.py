"""Block inclusion verification (SPV) for anchor transactions.

What this proves: an anchor txid is really inside a mined block. Two
paths, same evidence bar:

* Full block (``--spv``): the verifier fetches the block the tx claims
  to be in, recomputes the Merkle root from the block's tx list, and
  checks it against the block header's merkleroot — plus the header
  hash and proof-of-work.
* Compact proof (``--bump-file``): the verifier checks an
  operator-supplied BUMP (BRC-74) against the block header's
  merkleroot plus proof-of-work, fetching only the header.

One honest naming note: no public source serves BUMPs today (WoC's
``/tx/{txid}/proof`` 404s on Teratestnet and mainnet, verified
2026-10-16/17), so compact proofs are operator-supplied or built
locally with :func:`build_bump`. That is still *stronger* evidence
than trusting a proof server (the header's PoW and merkleroot are
checked), and it downloads only the header — the mainnet path.
Header-chain sync (verifying headers link back to a trusted
checkpoint) is implemented in :func:`verify_chain_to_checkpoint`.
"""
from __future__ import annotations

import json
import struct
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from typing import Callable, Protocol

from .bsv import sha256d

# Default Teratestnet WhatsOnChain (WoC v1 compatible).
WOC_TTN_BASE = "https://api.woc-ttn.bsvblockchain.tech/v1/bsv/test"


def validate_woc_base_url(base_url: str) -> str:
    """Return ``base_url`` if it is safe for chain-data fetches.

    Only https is accepted, plus http for a loopback host (127.0.0.1 /
    localhost) so local tests and dev servers keep working. Anything
    else is rejected: SPV inputs and broadcast fetches must not travel
    over plaintext, where a network attacker could feed fabricated
    chain data.
    """
    if not isinstance(base_url, str) or not base_url:
        raise ValueError(f"WoC base URL must be an https URL, got {base_url!r}")
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or ""
    if parsed.scheme == "https" and host:
        return base_url
    if parsed.scheme == "http" and host in ("127.0.0.1", "localhost"):
        return base_url
    raise ValueError(
        f"WoC base URL must use https (http only for loopback), got {base_url!r}"
    )

HEX_64 = set("0123456789abcdefABCDEF")


class SPVError(Exception):
    """Base class for inclusion-verification failures."""


class SPVUnavailable(SPVError):
    """The chain data source could not be reached; retrying may help."""


# ---------------------------------------------------------------------------
# Merkle tree (Bitcoin/BSV: duplicate the last hash on odd levels)
# ---------------------------------------------------------------------------


def _internal(txid_display: str) -> bytes:
    """Display (big-endian) txid hex -> internal (little-endian) bytes."""
    if (
        not isinstance(txid_display, str)
        or len(txid_display) != 64
        or any(c not in HEX_64 for c in txid_display)
    ):
        raise ValueError("txid must be 64 hexadecimal characters")
    return bytes.fromhex(txid_display)[::-1]


def _display(internal: bytes) -> str:
    return internal[::-1].hex()


def merkle_root(txids: list[str]) -> str:
    """Compute the Merkle root (display hex) for a block's txid list."""
    if not txids:
        raise ValueError("cannot compute a Merkle root for an empty tx list")
    level = [_internal(t) for t in txids]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(sha256d(left + right))
        level = nxt
    return _display(level[0])


def merkle_path(txids: list[str], index: int) -> list[dict[str, str]]:
    """Build the Merkle proof path for ``txids[index]``.

    Each node is ``{"hash": <display hex>, "position": "left"|"right"}``,
    where ``position`` says where the sibling sits relative to the
    running hash. A single-tx block has an empty path (the txid *is*
    the root).
    """
    if not txids:
        raise ValueError("cannot build a Merkle path for an empty tx list")
    if not isinstance(index, int) or index < 0 or index >= len(txids):
        raise ValueError("Merkle path index out of range")
    level = [_internal(t) for t in txids]
    path: list[dict[str, str]] = []
    pos = index
    while len(level) > 1:
        if pos % 2 == 0:
            sib = level[pos + 1] if pos + 1 < len(level) else level[pos]
            path.append({"hash": _display(sib), "position": "right"})
        else:
            path.append({"hash": _display(level[pos - 1]), "position": "left"})
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(sha256d(left + right))
        level = nxt
        pos //= 2
    return path


def verify_merkle_proof(txid: str, path: list[dict], root: str) -> bool:
    """Fold a Merkle proof path and compare against ``root``.

    Fail-closed: any malformed input (bad hex, bad position, wrong
    types) returns False, never raises.
    """
    try:
        current = _internal(txid)
        if not isinstance(path, list):
            return False
        for node in path:
            if not isinstance(node, dict):
                return False
            sibling = _internal(node["hash"])
            if node["position"] == "left":
                current = sha256d(sibling + current)
            elif node["position"] == "right":
                current = sha256d(current + sibling)
            else:
                return False
        if not isinstance(root, str) or len(root) != 64:
            return False
        return _display(current) == root.lower()
    except (ValueError, KeyError, TypeError):
        return False


# ---------------------------------------------------------------------------
# BUMP (BRC-74): compact Merkle proofs in binary or JSON encoding
# ---------------------------------------------------------------------------
#
# A BUMP carries the txids of interest plus exactly the sibling hashes
# needed to recompute the block's Merkle root, without the full tx list.
# Binary layout (BRC-74): VarInt blockHeight, 1-byte treeHeight, then
# per level VarInt nLeaves and per leaf VarInt offset, 1-byte flags
# (0x00 = sibling hash follows, 0x01 = duplicate working hash, no data,
# 0x02 = client txid, hash follows), 0/32-byte hash (stored reversed).
# JSON layout: {"blockHeight": int, "path": [[{"offset", "hash"?,
# "txid"? true, "duplicate"? true}]]}; hash is display (reversed-byte)
# hex, and a level's leaves sort by offset.
#
# Verification walks the path from the txid's level-0 offset: at each
# level the sibling sits at (index >> height) ^ 1. A duplicate leaf means
# the working hash pairs with itself (the level's last node when the
# level has an odd count). Sibling-offset parity decides the order:
# even = sibling is left. Hashing is done in internal (unreversed)
# bytes, exactly like verify_merkle_proof.
#
# No public source serves BUMPs today (WoC returns 404 for /proof on
# Teratestnet and mainnet, checked 2026-10-17), so proofs are
# operator-supplied (--bump-file) or built locally with build_bump.
# The verifier still checks the header's proof-of-work and that the
# BUMP root equals the header's merkleroot, so a served proof is never
# trusted on its own.

_BUMP_FLAG_SIBLING = 0x00
_BUMP_FLAG_DUPLICATE = 0x01
_BUMP_FLAG_TXID = 0x02
_BUMP_MAX_TREE_HEIGHT = 64


def _bump_varint(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint must be non-negative")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


class _BumpReader:
    """Bounds-checked reader for BUMP binary encoding."""

    def __init__(self, data: bytes, pos: int = 0) -> None:
        if pos < 0 or pos > len(data):
            raise ValueError("BUMP offset out of range")
        self.data = data
        self.pos = pos

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("BUMP truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def varint(self) -> int:
        first = self.read(1)[0]
        if first < 0xFD:
            return first
        if first == 0xFD:
            val = struct.unpack("<H", self.read(2))[0]
            if val < 0xFD:
                raise ValueError("non-canonical CompactSize encoding")
            return val
        if first == 0xFE:
            val = struct.unpack("<I", self.read(4))[0]
            if val <= 0xFFFF:
                raise ValueError("non-canonical CompactSize encoding")
            return val
        val = struct.unpack("<Q", self.read(8))[0]
        if val <= 0xFFFFFFFF:
            raise ValueError("non-canonical CompactSize encoding")
        return val

    def done(self) -> bool:
        return self.pos == len(self.data)


def parse_bump_json(bump: object) -> dict:
    """Validate a BUMP in JSON form and return a normalized copy.

    Normalization: leaves sorted by offset within each level, hashes
    lowercased, ``txid``/``duplicate`` present only when True.
    Raises ValueError on any malformed input.
    """
    if not isinstance(bump, dict):
        raise ValueError("BUMP must be an object")
    block_height = bump.get("blockHeight")
    if (
        not isinstance(block_height, int)
        or isinstance(block_height, bool)
        or block_height < 0
    ):
        raise ValueError("BUMP blockHeight must be a non-negative integer")
    path = bump.get("path")
    if not isinstance(path, list):
        raise ValueError("BUMP path must be an array of levels")
    if len(path) > _BUMP_MAX_TREE_HEIGHT:
        raise ValueError("BUMP tree height exceeds max 64")
    normalized: list[list[dict]] = []
    for level in path:
        if not isinstance(level, list):
            raise ValueError("BUMP path level must be an array")
        seen: set[int] = set()
        leaves: list[dict] = []
        for leaf in level:
            if not isinstance(leaf, dict):
                raise ValueError("BUMP leaf must be an object")
            offset = leaf.get("offset")
            if (
                not isinstance(offset, int)
                or isinstance(offset, bool)
                or offset < 0
            ):
                raise ValueError(
                    "BUMP leaf offset must be a non-negative integer"
                )
            if offset in seen:
                raise ValueError(
                    f"BUMP has duplicate offset {offset} in one level"
                )
            seen.add(offset)
            duplicate = leaf.get("duplicate", False)
            txid = leaf.get("txid", False)
            if not isinstance(duplicate, bool) or not isinstance(txid, bool):
                raise ValueError("BUMP leaf duplicate/txid flags must be booleans")
            if duplicate:
                if txid or "hash" in leaf:
                    raise ValueError(
                        "BUMP duplicate leaf must carry no hash or txid flag"
                    )
                leaves.append({"offset": offset, "duplicate": True})
            else:
                leaf_hash = leaf.get("hash")
                if not isinstance(leaf_hash, str) or len(leaf_hash) != 64:
                    raise ValueError("BUMP leaf hash must be 64 hex chars")
                try:
                    bytes.fromhex(leaf_hash)
                except ValueError as exc:
                    raise ValueError("BUMP leaf hash must be hex") from exc
                entry: dict = {"offset": offset, "hash": leaf_hash.lower()}
                if txid:
                    entry["txid"] = True
                leaves.append(entry)
        leaves.sort(key=lambda entry: entry["offset"])
        normalized.append(leaves)
    return {"blockHeight": block_height, "path": normalized}


def parse_bump_bytes(data: bytes, offset: int = 0) -> tuple[dict, int]:
    """Parse one BUMP binary encoding starting at ``offset``.

    Returns ``(bump, consumed)`` where ``consumed`` is the number of
    bytes the BUMP occupies, so a caller parsing a stream (e.g. a
    BEEF envelope) knows where the next field starts. Raises
    ValueError on truncated input, unknown flag bytes, or a tree
    height over 64. Trailing bytes after the BUMP are the caller's
    problem — use :func:`parse_bump_hex` for the standalone form,
    which rejects them.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("BUMP data must be bytes")
    start = offset
    reader = _BumpReader(bytes(data), offset)
    block_height = reader.varint()
    tree_height = reader.read(1)[0]
    if tree_height > _BUMP_MAX_TREE_HEIGHT:
        raise ValueError(f"BUMP tree height {tree_height} exceeds max 64")
    path: list[list[dict]] = []
    for _level in range(tree_height):
        n_leaves = reader.varint()
        leaves: list[dict] = []
        for _i in range(n_leaves):
            offset = reader.varint()
            flags = reader.read(1)[0]
            if flags == _BUMP_FLAG_DUPLICATE:
                leaves.append({"offset": offset, "duplicate": True})
            elif flags in (_BUMP_FLAG_SIBLING, _BUMP_FLAG_TXID):
                leaf = {
                    "offset": offset,
                    "hash": reader.read(32)[::-1].hex(),
                }
                if flags == _BUMP_FLAG_TXID:
                    leaf["txid"] = True
                leaves.append(leaf)
            else:
                raise ValueError(
                    f"BUMP leaf has invalid flags byte 0x{flags:02x}"
                )
        leaves.sort(key=lambda leaf: leaf["offset"])
        path.append(leaves)
    bump = {"blockHeight": block_height, "path": path}
    # Reuse the JSON validator so binary parsing is exactly as strict
    # (e.g. duplicate offsets inside one level are rejected here too).
    return parse_bump_json(bump), reader.pos - start


def parse_bump_hex(hex_str: str) -> dict:
    """Parse a BUMP binary encoding (hex) into the normalized JSON form.

    Raises ValueError on truncated input, unknown flag bytes, trailing
    bytes, or a tree height over 64.
    """
    if not isinstance(hex_str, str):
        raise ValueError("BUMP hex must be a string")
    try:
        data = bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError("BUMP hex is not valid hex") from exc
    bump, consumed = parse_bump_bytes(data)
    if consumed != len(data):
        raise ValueError("BUMP has trailing bytes after the last level")
    return bump


def bump_to_bytes(bump: dict) -> bytes:
    """Encode a BUMP (JSON form) to its binary encoding."""
    bump = parse_bump_json(bump)
    out = bytearray(_bump_varint(bump["blockHeight"]))
    out.append(len(bump["path"]))
    for leaves in bump["path"]:
        out += _bump_varint(len(leaves))
        for leaf in leaves:
            out += _bump_varint(leaf["offset"])
            if leaf.get("duplicate"):
                out.append(_BUMP_FLAG_DUPLICATE)
            else:
                out.append(
                    _BUMP_FLAG_TXID if leaf.get("txid") else _BUMP_FLAG_SIBLING
                )
                out += bytes.fromhex(leaf["hash"])[::-1]
    return bytes(out)


def bump_to_hex(bump: dict) -> str:
    """Encode a BUMP (JSON form) to its binary hex encoding."""
    return bump_to_bytes(bump).hex()


def verify_bump_proof(txid: str, bump: dict, root: str) -> bool:
    """True iff the BUMP proves ``txid`` is under Merkle ``root``.

    Fail-closed: any malformed input (bad hex, missing sibling, wrong
    types) returns False, never raises.
    """
    try:
        bump = parse_bump_json(bump)
        path = bump["path"]
        if not path:
            # Single-transaction block: the root is the txid itself.
            return txid.lower() == root.lower()
        index = None
        for leaf in path[0]:
            if leaf.get("hash", "").lower() == txid.lower():
                index = leaf["offset"]
                break
        if index is None:
            return False
        current = _internal(txid)
        for height, leaves in enumerate(path):
            sibling_offset = (index >> height) ^ 1
            leaf = next(
                (entry for entry in leaves if entry["offset"] == sibling_offset),
                None,
            )
            if leaf is None:
                return False
            if leaf.get("duplicate"):
                current = sha256d(current + current)
            else:
                sibling = _internal(leaf["hash"])
                if sibling_offset % 2 == 0:
                    current = sha256d(sibling + current)
                else:
                    current = sha256d(current + sibling)
        if not isinstance(root, str) or len(root) != 64:
            return False
        return _display(current) == root.lower()
    except (ValueError, KeyError, TypeError, AttributeError, IndexError):
        return False


def build_bump(txids: list[str], indices: list[int], block_height: int) -> dict:
    """Build a BUMP (JSON form) proving the txids at ``indices`` are in
    the block whose full txid list is ``txids``.

    Emits, per level, the working nodes plus their siblings; a sibling
    past the end of an odd-count level is a duplicate leaf, not a hash.
    Raises ValueError on empty/ out-of-range input.
    """
    if not isinstance(txids, list) or not txids:
        raise ValueError("build_bump needs a non-empty txid list")
    if (
        not isinstance(block_height, int)
        or isinstance(block_height, bool)
        or block_height < 0
    ):
        raise ValueError("block height must be a non-negative integer")
    index_set = set(indices)
    if (
        not index_set
        or any(
            not isinstance(i, int) or isinstance(i, bool) or i < 0 or i >= len(txids)
            for i in index_set
        )
    ):
        raise ValueError("indices must be in-range positions")
    for txid in txids:
        if not isinstance(txid, str) or len(txid) != 64:
            raise ValueError("txids must be 64-char hex strings")
    levels = [[_internal(t) for t in txids]]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        nxt = []
        for i in range(0, len(prev) - 1, 2):
            nxt.append(sha256d(prev[i] + prev[i + 1]))
        if len(prev) % 2 == 1:
            nxt.append(sha256d(prev[-1] + prev[-1]))
        levels.append(nxt)
    path: list[list[dict]] = []
    working = set(index_set)
    for height in range(len(levels) - 1):
        count = len(levels[height])
        emit = set(working)
        for offset in working:
            emit.add(offset ^ 1)
        leaves = []
        for offset in sorted(emit):
            if offset >= count:
                leaves.append({"offset": offset, "duplicate": True})
            else:
                leaf: dict = {
                    "offset": offset,
                    "hash": _display(levels[height][offset]),
                }
                if height == 0 and offset in index_set:
                    leaf["txid"] = True
                leaves.append(leaf)
        path.append(leaves)
        working = {offset // 2 for offset in working}
    return {"blockHeight": block_height, "path": path}


# ---------------------------------------------------------------------------
# Block headers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BlockHeader:
    version: int
    prev_hash: str  # display hex
    merkle_root: str  # display hex
    time: int
    bits: int
    nonce: int
    height: int | None = None
    hash: str | None = None  # display hex, if already known

    def to_bytes(self) -> bytes:
        """Serialize the 80-byte header (internal byte order for hashes)."""
        return (
            struct.pack("<I", self.version)
            + bytes.fromhex(self.prev_hash)[::-1]
            + bytes.fromhex(self.merkle_root)[::-1]
            + struct.pack("<I", self.time)
            + struct.pack("<I", self.bits)
            + struct.pack("<I", self.nonce)
        )


def header_hash(header: bytes) -> str:
    """Double-SHA256 of 80 header bytes, as display hex."""
    if len(header) != 80:
        raise ValueError("block header must be exactly 80 bytes")
    return _display(sha256d(header))


def target_from_bits(bits: int) -> int:
    """Decode compact ``bits`` into the proof-of-work target integer."""
    if not isinstance(bits, int) or bits < 0 or bits > 0xFFFFFFFF:
        raise ValueError("bits must be a 32-bit unsigned integer")
    exponent = bits >> 24
    mantissa = bits & 0xFFFFFF
    if mantissa == 0 or exponent < 3 or exponent > 32:
        raise ValueError(f"invalid compact target bits: {bits:#x}")
    return mantissa * (1 << (8 * (exponent - 3)))


def verify_pow(header: bytes, bits: int) -> bool:
    """True iff the header hash meets the target implied by ``bits``."""
    try:
        return int(header_hash(header), 16) <= target_from_bits(bits)
    except ValueError:
        return False


def verify_header(header: bytes, expected_hash: str, bits: int) -> bool:
    """True iff the header hashes to ``expected_hash`` and passes PoW."""
    if not isinstance(expected_hash, str):
        return False
    try:
        if header_hash(header) != expected_hash.lower():
            return False
    except (ValueError, TypeError, AttributeError, struct.error):
        return False
    return verify_pow(header, bits)


def verify_header_chain(
    headers: list[BlockHeader],
    *,
    daa: "DAAParams | None" = None,
    window_inputs: "list[BlockHeader] | None" = None,
) -> bool:
    """True iff consecutive headers link (child.prev == parent.hash),
    every header hashes to its declared hash, and every header passes
    its own proof-of-work. Fail-closed on any malformed header.

    With ``daa`` given, additionally require every header's ``bits``
    to match the difficulty schedule recomputed from its preceding
    window (see :func:`validate_daa_schedule`); ``window_inputs``
    supplies the authenticated headers preceding ``headers`` that
    the earliest windows reach back into. Heights are then required
    and must be consecutive across inputs and headers. Without
    ``daa`` the schedule is not checked (the pre-Finding-B
    behavior, kept for chains without a confirmed parameter set).
    """
    try:
        if not headers:
            return False
        segment = list(headers)
        combined = list(window_inputs or []) + segment
        for header in combined:
            declared = header.hash
            if not isinstance(declared, str) or len(declared) != 64:
                return False
            if header_hash(header.to_bytes()) != declared.lower():
                return False
            if not verify_pow(header.to_bytes(), header.bits):
                return False
        for parent, child in zip(combined, combined[1:]):
            if child.prev_hash.lower() != (parent.hash or "").lower():
                return False
        if daa is not None:
            ok, _reason = validate_daa_schedule(
                combined, daa, first_vouched_height=segment[0].height or 0
            )
            if not ok:
                return False
        return True
    except (ValueError, TypeError, AttributeError, struct.error):
        return False


# ---------------------------------------------------------------------------
# Difficulty-schedule validation (Finding B): the BSV "cash" DAA.
#
# Ported from the BSV node source (bitcoin-sv/bitcoin-sv, read
# 2026-10-23):
#   src/pow.cpp           GetNextWorkRequired (dispatches on the
#                         PREVIOUS block's height >= consensus
#                         daaHeight), GetNextCashWorkRequired,
#                         ComputeTarget, GetSuitableBlock
#   src/arith_uint256.cpp arith_uint256::SetCompact / GetCompact
#   src/chainparams.cpp   consensus.daaHeight = 504031 (mainnet)
# Per-block work is the node's GetBlockProof:
#   (~target / (target + 1)) + 1, and 0 for negative, overflow, or
#   zero targets. Chainwork is only ever accumulated here from the
#   decoded targets of headers inside the authenticated walk —
#   never accepted as a supplied value.
# ---------------------------------------------------------------------------

_DAA_WINDOW = 144

# Ancestor reach below the lowest vouched block. Validating block
# h runs the DAA over the window ending at h-1: the first anchor
# sits at (h-1) - 144 and GetSuitableBlock can select a block 2
# further down at that end, i.e. down to h-147. For the lowest
# vouched block (checkpoint + 1) the walk must therefore extend
# _DAA_INPUT_DEPTH headers below the checkpoint.
_DAA_INPUT_DEPTH = _DAA_WINDOW + 2


def _set_compact(bits: int) -> tuple[int, bool, bool]:
    """``arith_uint256::SetCompact``: decode compact ``bits`` into
    (target, negative, overflow), exactly as the node does."""
    if not isinstance(bits, int) or isinstance(bits, bool):
        raise ValueError("bits must be an integer")
    if bits < 0 or bits > 0xFFFFFFFF:
        raise ValueError("bits must be a 32-bit unsigned integer")
    size = bits >> 24
    word = bits & 0x007FFFFF
    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))
    negative = word != 0 and (bits & 0x00800000) != 0
    overflow = word != 0 and (
        size > 34
        or (word > 0xFF and size > 33)
        or (word > 0xFFFF and size > 32)
    )
    return target, negative, overflow


def _get_compact(target: int) -> int:
    """``arith_uint256::GetCompact`` for a non-negative target."""
    if target < 0:
        raise ValueError("target must be non-negative")
    n_size = (target.bit_length() + 7) // 8
    if n_size <= 3:
        compact = target << (8 * (3 - n_size))
    else:
        compact = target >> (8 * (n_size - 3))
    # The 0x00800000 bit denotes the sign; if set, shift the
    # mantissa down a byte and grow the exponent.
    if compact & 0x00800000:
        compact >>= 8
        n_size += 1
    return (n_size << 24) | compact


def _block_work(bits: int) -> int:
    """Per-block work (the node's GetBlockProof): expected number
    of hashes to mine at this target; 0 for invalid targets."""
    try:
        target, negative, overflow = _set_compact(bits)
    except ValueError:
        return 0
    if negative or overflow or target == 0:
        return 0
    return ((1 << 256) - 1 - target) // (target + 1) + 1


@dataclass(frozen=True)
class DAAParams:
    """Consensus parameters for difficulty-schedule validation.

    Only parameter sets verified against a network's own published
    consensus source may exist here. Teratestnet deliberately has
    none yet: its parameters are unconfirmed, so schedule
    validation stays off for TTN chains (Finding B design note,
    decision 4) rather than borrowing mainnet's.
    """

    pow_limit_bits: int
    target_spacing: int = 600
    daa_height: int = 504031

    @property
    def pow_limit_target(self) -> int:
        target, negative, overflow = _set_compact(self.pow_limit_bits)
        if negative or overflow or target == 0:
            raise ValueError("invalid pow-limit bits")
        return target

    @classmethod
    def mainnet(cls) -> "DAAParams":
        """BSV mainnet: pow limit 0x1d00ffff, 600s spacing, cash
        DAA from daaHeight 504031 (first DAA-computed block
        504032, because the node dispatches on the previous
        block's height)."""
        return cls(pow_limit_bits=0x1D00FFFF)


def _suitable_position(headers: list[BlockHeader], pos: int) -> int:
    """Position of the median-of-3 suitable block for the block at
    ``pos`` (the node's GetSuitableBlock over pos, pos-1, pos-2).

    The node's exact swap sequence (strict ``>`` comparisons) is
    reproduced so equal timestamps resolve to the same block the
    node would pick."""
    order = [pos - 2, pos - 1, pos]

    def _time(i: int) -> int:
        return headers[i].time

    if _time(order[0]) > _time(order[2]):
        order[0], order[2] = order[2], order[0]
    if _time(order[0]) > _time(order[1]):
        order[0], order[1] = order[1], order[0]
    if _time(order[1]) > _time(order[2]):
        order[1], order[2] = order[2], order[1]
    return order[1]


def _expected_bits(
    headers: list[BlockHeader],
    chainwork: list[int],
    idx: int,
    params: DAAParams,
) -> int:
    """Bits the cash DAA requires for ``headers[idx]``, computed
    from the preceding headers in the list
    (GetNextCashWorkRequired + ComputeTarget). ``chainwork`` is
    the cumulative work up to and including each position."""
    prev_pos = idx - 1
    last_pos = _suitable_position(headers, prev_pos)
    first_pos = _suitable_position(headers, prev_pos - _DAA_WINDOW)
    work = chainwork[last_pos] - chainwork[first_pos]
    work *= params.target_spacing
    timespan = headers[last_pos].time - headers[first_pos].time
    hi = 288 * params.target_spacing
    lo = 72 * params.target_spacing
    if timespan > hi:
        timespan = hi
    elif timespan < lo:
        timespan = lo
    work //= timespan
    if work <= 0:
        # A window with no measurable work rate targets the pow
        # limit (the node's arithmetic would divide by zero; a
        # real chain window cannot reach this).
        return params.pow_limit_bits
    # (-work) / work in uint256 arithmetic.
    target = ((1 << 256) - work) // work
    if target > params.pow_limit_target:
        target = params.pow_limit_target
    return _get_compact(target)


def validate_daa_schedule(
    headers: list[BlockHeader],
    params: DAAParams,
    *,
    first_vouched_height: int,
) -> tuple[bool, str]:
    """(ok, reason): every header at height >=
    max(``first_vouched_height``, ``params.daa_height`` + 1) must
    declare exactly the bits the cash DAA computes from its
    preceding window inside ``headers``.

    ``headers`` must be ascending with present, consecutive
    heights, and deep enough that every vouched block's full
    window is in the list. Headers below the vouching floor are
    inputs only (their bits feed chainwork; nothing is claimed
    about their own schedule). Every header, vouched or input,
    must also decode within the pow limit (the node's
    CheckProofOfWork range check). Fail-closed."""
    try:
        if not headers:
            return False, "no headers for schedule validation"
        heights = [h.height for h in headers]
        if any(
            not isinstance(x, int) or isinstance(x, bool) for x in heights
        ):
            return False, "header heights are required for schedule validation"
        for a, b in zip(heights, heights[1:]):
            if b != a + 1:
                return False, "header heights are not consecutive"
        for h in headers:
            target, negative, overflow = _set_compact(h.bits)
            if (
                negative
                or overflow
                or target == 0
                or target > params.pow_limit_target
            ):
                return False, f"bits out of range at height {h.height}"
        chainwork: list[int] = []
        acc = 0
        for h in headers:
            acc += _block_work(h.bits)
            chainwork.append(acc)
        floor = max(first_vouched_height, params.daa_height + 1)
        for idx, h in enumerate(headers):
            if h.height is None or h.height < floor:
                continue
            if idx - 1 - _DAA_WINDOW - 2 < 0:
                return (
                    False,
                    f"insufficient window depth at height {h.height}",
                )
            if h.bits != _expected_bits(headers, chainwork, idx, params):
                return (
                    False,
                    f"difficulty schedule mismatch at height {h.height}",
                )
        return True, "difficulty schedule verified"
    except (ValueError, TypeError, AttributeError, struct.error):
        return False, "malformed header data in schedule validation"


# ---------------------------------------------------------------------------
# Inclusion verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InclusionResult:
    verified: bool
    txid: str
    blockheight: int | None = None
    blockhash: str | None = None
    reason: str = ""


class BlockFetcher(Protocol):
    """Supplies the chain data inclusion checks run against."""

    def fetch_tx(self, txid: str) -> dict:
        """Return {"blockheight": int|None, "blockhash": str|None}."""
        ...

    def fetch_tx_full(self, txid: str) -> dict:
        """Return the full WoC ``/tx/hash`` JSON body for ``txid``."""
        ...

    def fetch_block(self, height: int) -> tuple[BlockHeader, list[str]]:
        """Return (header, txid list) for a block height."""
        ...

    def fetch_header(self, height: int) -> BlockHeader:
        """Return the header for a block height (no tx list)."""
        ...


# request_fn(method, url) -> (status, body_bytes). Injectable for tests.
RequestFn = Callable[[str, str], tuple[int, bytes]]


def _urllib_get(method: str, url: str) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method=method)
    # WoC-TTN rejects the default "Python-urllib/..." User-Agent with 403
    # (verified live 2026-10-16). Identify the client honestly.
    req.add_header("User-Agent", "sealrun/1.0")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise ConnectionError(f"request to {url} failed: {exc}") from exc


def _header_from_block_json(data: dict, height: int) -> BlockHeader:
    """Parse a WoC ``/block/height`` body into a :class:`BlockHeader`."""
    try:
        return BlockHeader(
            version=int(data["version"]),
            prev_hash=str(data["previousblockhash"]),
            merkle_root=str(data["merkleroot"]),
            time=int(data["time"]),
            bits=int(data["bits"], 16) if isinstance(data["bits"], str) else int(data["bits"]),
            nonce=int(data["nonce"]),
            height=int(data["height"]),
            hash=str(data["hash"]),
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise SPVUnavailable(
            f"WoC block {height} body is missing required fields"
        ) from exc


def _txids_from_block_json(data: dict, height: int) -> list[str]:
    try:
        return [str(t) for t in data["tx"]]
    except (KeyError, TypeError) as exc:
        raise SPVUnavailable(
            f"WoC block {height} body is missing required fields"
        ) from exc


class WoCBlockFetcher:
    """Fetch tx + block data from a WhatsOnChain (WoC v1) endpoint."""

    def __init__(
        self,
        base_url: str = WOC_TTN_BASE,
        request_fn: RequestFn | None = None,
    ) -> None:
        self.base_url = validate_woc_base_url(base_url).rstrip("/")
        self._request = request_fn or _urllib_get

    def _get_json(self, path: str) -> dict:
        try:
            status, body = self._request("GET", f"{self.base_url}{path}")
        except ConnectionError as exc:
            raise SPVUnavailable(str(exc)) from exc
        if status != 200:
            raise SPVUnavailable(f"WoC {path} returned HTTP {status}")
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise SPVUnavailable(f"WoC {path} returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise SPVUnavailable(f"WoC {path} returned a non-object body")
        return data

    def fetch_tx(self, txid: str) -> dict:
        data = self._get_json(f"/tx/hash/{txid}")
        return {
            "blockheight": data.get("blockheight"),
            "blockhash": data.get("blockhash"),
        }

    def fetch_tx_full(self, txid: str) -> dict:
        """Return the full WoC ``/tx/hash`` JSON body for ``txid``."""
        return self._get_json(f"/tx/hash/{txid}")

    def fetch_block(self, height: int) -> tuple[BlockHeader, list[str]]:
        data = self._get_json(f"/block/height/{height}")
        return (
            _header_from_block_json(data, height),
            _txids_from_block_json(data, height),
        )

    def fetch_header(self, height: int) -> BlockHeader:
        """Return the header for a block height (no tx list)."""
        return _header_from_block_json(
            self._get_json(f"/block/height/{height}"), height
        )


class SPVVerifier:
    """Verify anchor txids are really inside mined blocks.

    Fail-closed throughout: an unconfirmed tx, a tx missing from its
    claimed block, a Merkle root mismatch, a header-hash mismatch, or
    a proof-of-work failure all return ``verified=False`` with a
    reason — never an exception for a single anchor.
    """

    def __init__(self, fetcher: BlockFetcher) -> None:
        self.fetcher = fetcher

    def verify_inclusion(self, txid: str) -> InclusionResult:
        txid = txid.lower()
        try:
            tx = self.fetcher.fetch_tx(txid)
        except SPVError as exc:
            return InclusionResult(False, txid, reason=f"fetch failed: {exc}")
        height = tx.get("blockheight")
        blockhash = tx.get("blockhash")
        if height is None or blockhash is None:
            return InclusionResult(
                False, txid, reason="unconfirmed: no blockheight on record"
            )
        try:
            header, txids = self.fetcher.fetch_block(int(height))
        except (SPVError, ValueError, TypeError, AttributeError, struct.error, OverflowError) as exc:
            return InclusionResult(
                False, txid, blockheight=height, blockhash=blockhash,
                reason=f"fetch failed: {exc}",
            )
        try:
            return self._verify_against_block(txid, height, blockhash, header, txids)
        except (ValueError, TypeError, AttributeError, struct.error, OverflowError) as exc:
            return InclusionResult(
                False, txid, blockheight=height, blockhash=blockhash,
                reason=f"malformed block data: {exc}",
            )

    @staticmethod
    def _verify_against_block(txid, height, blockhash, header, txids):
        if (header.hash or "").lower() != str(blockhash).lower():
            return InclusionResult(
                False, txid, blockheight=height, blockhash=blockhash,
                reason="blockhash mismatch: tx's block differs from fetched block",
            )
        try:
            index = [t.lower() for t in txids].index(txid)
        except ValueError:
            return InclusionResult(
                False, txid, blockheight=height, blockhash=blockhash,
                reason="txid not present in its claimed block",
            )
        path = merkle_path(txids, index)
        if not verify_merkle_proof(txid, path, header.merkle_root):
            return InclusionResult(
                False, txid, blockheight=height, blockhash=blockhash,
                reason="Merkle proof failed: recomputed root != header merkleroot",
            )
        if not verify_pow(header.to_bytes(), header.bits):
            return InclusionResult(
                False, txid, blockheight=height, blockhash=blockhash,
                reason="proof-of-work failed: header hash exceeds target",
            )
        # Checked last, so existing fail-closed reasons (blockhash
        # mismatch, Merkle, PoW) are preserved: the header bytes must
        # hash to the claimed blockhash. A hostile provider serving a
        # hash string that matches its own blockhash string, with a
        # Merkle root and trivial bits, fails here. Residual: a fully
        # self-consistent fabricated block with trivial difficulty
        # still passes --spv alone; hostile-provider proof requires
        # the header-chain walk to a pinned checkpoint.
        try:
            recomputed = header_hash(header.to_bytes())
        except (ValueError, TypeError, AttributeError, struct.error, OverflowError):
            return InclusionResult(
                False, txid, blockheight=height, blockhash=blockhash,
                reason="malformed header data: cannot recompute header hash",
            )
        if recomputed != str(blockhash).lower():
            return InclusionResult(
                False, txid, blockheight=height, blockhash=blockhash,
                reason="header hash mismatch: recomputed header hash differs from claimed blockhash",
            )
        return InclusionResult(
            True, txid, blockheight=height, blockhash=blockhash,
            reason=f"inclusion verified: block {height}",
        )


def apply_chain_inclusion(result: dict, verifier: SPVVerifier) -> dict:
    """Attach per-anchor inclusion results to a chain-verify result.

    Handles both shapes: ``verify_anchor_chain`` (``result["anchors"]``)
    and ``verify_journal_against_anchor_chain`` (``result["chain"]``
    plus per-anchor journal entries). Returns a new dict; the input
    is not mutated. Top-level ``chain_inclusion_verified`` is True
    only when every anchor's inclusion verifies.
    """
    if "chain" in result:
        chain = dict(result["chain"])
        summaries = chain.get("anchors", [])
        merged = []
        all_verified = True
        for summary in summaries:
            inclusion = verifier.verify_inclusion(summary["txid"])
            all_verified = all_verified and inclusion.verified
            merged.append(
                {
                    **summary,
                    "chain_inclusion_verified": inclusion.verified,
                    "chain_inclusion": {
                        "verified": inclusion.verified,
                        "blockheight": inclusion.blockheight,
                        "blockhash": inclusion.blockhash,
                        "reason": inclusion.reason,
                    },
                }
            )
        chain["anchors"] = merged
        return {
            **result,
            "chain": chain,
            "chain_inclusion_verified": all_verified,
        }
    merged = []
    all_verified = True
    for summary in result.get("anchors", []):
        inclusion = verifier.verify_inclusion(summary["txid"])
        all_verified = all_verified and inclusion.verified
        merged.append(
            {
                **summary,
                "chain_inclusion_verified": inclusion.verified,
                "chain_inclusion": {
                    "verified": inclusion.verified,
                    "blockheight": inclusion.blockheight,
                    "blockhash": inclusion.blockhash,
                    "reason": inclusion.reason,
                },
            }
        )
    return {
        **result,
        "anchors": merged,
        "chain_inclusion_verified": all_verified,
    }


class BUMPVerifier:
    """Verify a txid against an operator-supplied BUMP and the block
    header. The BUMP carries the block height; the header (fetched at
    that height) supplies the Merkle root and the proof-of-work check,
    so a served proof is never trusted on its own.
    """

    def __init__(self, fetcher: BlockFetcher) -> None:
        self.fetcher = fetcher

    def verify_bump_for_tx(self, txid: str, bump: dict) -> InclusionResult:
        try:
            bump = parse_bump_json(bump)
        except ValueError as exc:
            return InclusionResult(False, txid, reason=f"malformed BUMP: {exc}")
        height = bump["blockHeight"]
        try:
            header = self.fetcher.fetch_header(height)
        except (SPVError, OverflowError) as exc:
            return InclusionResult(
                False, txid, blockheight=height,
                reason=f"header fetch failed: {exc}",
            )
        if header.height != height:
            return InclusionResult(
                False, txid, blockheight=height,
                reason=f"fetcher returned header for height {header.height}, "
                f"expected {height}",
            )
        if not verify_bump_proof(txid, bump, header.merkle_root):
            return InclusionResult(
                False, txid, blockheight=height, blockhash=header.hash,
                reason="BUMP proof does not reach the header Merkle root",
            )
        try:
            pow_ok = verify_pow(header.to_bytes(), header.bits)
        except (ValueError, TypeError, AttributeError, struct.error, OverflowError) as exc:
            return InclusionResult(
                False, txid, blockheight=height, blockhash=header.hash,
                reason=f"malformed header data: {exc}",
            )
        if not pow_ok:
            return InclusionResult(
                False, txid, blockheight=height, blockhash=header.hash,
                reason="header proof-of-work failed",
            )
        return InclusionResult(
            True, txid, blockheight=height, blockhash=header.hash,
            reason=f"BUMP inclusion verified: block {height}",
        )


def apply_bump_inclusion(
    result: dict, verifier: BUMPVerifier, bumps: dict
) -> dict:
    """Attach per-anchor BUMP inclusion results to a chain-verify result.

    ``bumps`` maps txid (any case) to a BUMP in JSON form. Anchors with
    no supplied BUMP verify as False. Same two result shapes and
    non-mutating contract as apply_chain_inclusion. Top-level
    ``bump_inclusion_verified`` is True only when every anchor's BUMP
    verifies.
    """
    if not isinstance(bumps, dict):
        raise ValueError("BUMPs must map txid -> BUMP")
    by_txid = {str(txid).lower(): bump for txid, bump in bumps.items()}
    if "chain" in result:
        chain = dict(result["chain"])
        summaries = chain.get("anchors", [])
        merged = []
        all_verified = True
        for summary in summaries:
            bump = by_txid.get(summary["txid"].lower())
            if bump is None:
                verdict = InclusionResult(
                    False, summary["txid"],
                    reason="no BUMP supplied for this txid",
                )
            else:
                verdict = verifier.verify_bump_for_tx(summary["txid"], bump)
            all_verified = all_verified and verdict.verified
            merged.append(
                {
                    **summary,
                    "bump_inclusion_verified": verdict.verified,
                    "bump_inclusion": {
                        "verified": verdict.verified,
                        "blockheight": verdict.blockheight,
                        "blockhash": verdict.blockhash,
                        "reason": verdict.reason,
                    },
                }
            )
        chain["anchors"] = merged
        return {
            **result,
            "chain": chain,
            "bump_inclusion_verified": all_verified,
        }
    merged = []
    all_verified = True
    for summary in result.get("anchors", []):
        bump = by_txid.get(summary["txid"].lower())
        if bump is None:
            verdict = InclusionResult(
                False, summary["txid"],
                reason="no BUMP supplied for this txid",
            )
        else:
            verdict = verifier.verify_bump_for_tx(summary["txid"], bump)
        all_verified = all_verified and verdict.verified
        merged.append(
            {
                **summary,
                "bump_inclusion_verified": verdict.verified,
                "bump_inclusion": {
                    "verified": verdict.verified,
                    "blockheight": verdict.blockheight,
                    "blockhash": verdict.blockhash,
                    "reason": verdict.reason,
                },
            }
        )
    return {
        **result,
        "anchors": merged,
        "bump_inclusion_verified": all_verified,
    }


# ---------------------------------------------------------------------------
# Header-chain sync: walk from a tip block back to a pinned checkpoint
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HeaderChainResult:
    verified: bool
    txid: str
    tip_height: int | None = None
    checkpoint_height: int | None = None
    headers_checked: int = 0
    reason: str = ""


# Default walk cap: 4032 headers. That preserves the historical
# 2016-header tip-to-checkpoint span and leaves room for the DAA
# input extension below the checkpoint (Finding B), with headroom.
# An operator pinning a checkpoint farther back than this fails
# closed with a clear reason instead of walking the whole chain on
# every verify.
DEFAULT_MAX_HEADERS = 4032


def verify_chain_to_checkpoint(
    fetcher: BlockFetcher,
    *,
    tip_height: int,
    tip_hash: str,
    checkpoint_hash: str,
    checkpoint_height: int,
    max_headers: int = DEFAULT_MAX_HEADERS,
    daa: DAAParams | None = None,
) -> tuple[bool, int, str]:
    """Walk headers from ``tip_height`` back to ``checkpoint_height``.

    Every fetched header must hash to the hash the walk expects
    (the tip hash for the first header, then each header's
    ``prev_hash``), and must pass its own proof-of-work. At the
    checkpoint height the header's hash must equal ``checkpoint_hash``
    — the operator-pinned trust anchor, distributed out-of-band like
    the genesis txid.

    With ``daa`` given, the walk additionally extends
    ``_DAA_INPUT_DEPTH`` headers *below* the checkpoint — each one
    authenticated the same way, by the hash its already-verified
    child commits to — and every block above the checkpoint must
    declare exactly the bits the cash DAA computes from its
    preceding window inside the walk (Finding B). The extension
    headers are inputs only; nothing is vouched for at or below
    the checkpoint.

    Returns (verified, headers_checked, reason). Fail-closed: any
    fetch error, hash mismatch, PoW failure, schedule mismatch, or
    walk overrun returns False with a reason, never raises.
    """
    if not isinstance(tip_height, int) or not isinstance(checkpoint_height, int):
        return False, 0, "tip/checkpoint heights must be integers"
    if not isinstance(tip_hash, str):
        return False, 0, "tip_hash must be a string"
    if checkpoint_height < 0 or tip_height < 0:
        return False, 0, "heights must be non-negative"
    if checkpoint_height > tip_height:
        return False, 0, "checkpoint is above the tip block"
    if daa is not None and tip_height < daa.daa_height + 1:
        return (
            False,
            0,
            f"tip block at height {tip_height} predates the DAA "
            "activation height; schedule validation unsupported",
        )
    walk_len = tip_height - checkpoint_height + 1
    fetch_len = walk_len + (_DAA_INPUT_DEPTH if daa is not None else 0)
    if fetch_len > max_headers:
        return (
            False,
            0,
            f"walk of {fetch_len} headers exceeds cap {max_headers}: "
            "pin a more recent checkpoint",
        )
    expected_hash = tip_hash.lower()
    checked = 0
    walked: list[tuple[int, BlockHeader]] = []
    checkpoint_header: BlockHeader | None = None
    try:
        for height in range(tip_height, checkpoint_height - 1, -1):
            header = fetcher.fetch_header(height)
            # The declared hash must equal the hash recomputed from the
            # header bytes AND the hash the walk expects: a source that
            # serves tampered fields with a copied hash is caught here,
            # not left to proof-of-work luck.
            if header_hash(header.to_bytes()) != expected_hash:
                return (
                    False,
                    checked,
                    f"header hash mismatch at height {height}",
                )
            if (header.hash or "").lower() != expected_hash:
                return (
                    False,
                    checked,
                    f"header hash mismatch at height {height}",
                )
            if not verify_pow(header.to_bytes(), header.bits):
                return (
                    False,
                    checked,
                    f"proof-of-work failed at height {height}",
                )
            walked.append((height, header))
            checked += 1
            if height == checkpoint_height:
                if (header.hash or "").lower() != checkpoint_hash.lower():
                    return (
                        False,
                        checked,
                        "checkpoint hash mismatch at height "
                        f"{checkpoint_height}",
                    )
                if daa is None:
                    return (
                        True,
                        checked,
                        f"chain verified: {checked} header(s) back to "
                        f"checkpoint {checkpoint_height}",
                    )
                checkpoint_header = header
                break
            expected_hash = header.prev_hash.lower()
        if daa is not None and checkpoint_header is not None:
            # Authenticated DAA inputs below the checkpoint: each
            # header must hash to the prev_hash committed by its
            # already-verified child, exactly as in the main walk.
            expected_hash = checkpoint_header.prev_hash.lower()
            extension: list[tuple[int, BlockHeader]] = []
            for height in range(
                checkpoint_height - 1,
                checkpoint_height - 1 - _DAA_INPUT_DEPTH,
                -1,
            ):
                header = fetcher.fetch_header(height)
                if header_hash(header.to_bytes()) != expected_hash:
                    return (
                        False,
                        checked,
                        f"header hash mismatch at height {height}",
                    )
                if (header.hash or "").lower() != expected_hash:
                    return (
                        False,
                        checked,
                        f"header hash mismatch at height {height}",
                    )
                if not verify_pow(header.to_bytes(), header.bits):
                    return (
                        False,
                        checked,
                        f"proof-of-work failed at height {height}",
                    )
                extension.append((height, header))
                expected_hash = header.prev_hash.lower()
            pairs = sorted(walked + extension, key=lambda p: p[0])
            ascending = [replace(h, height=ht) for ht, h in pairs]
            ok, reason = validate_daa_schedule(
                ascending, daa, first_vouched_height=checkpoint_height + 1
            )
            if not ok:
                return False, checked, reason
            return (
                True,
                checked,
                f"chain verified: {checked} header(s) back to "
                f"checkpoint {checkpoint_height}; difficulty "
                "schedule verified",
            )
    except SPVError as exc:
        return False, checked, f"fetch failed: {exc}"
    except (ValueError, TypeError, AttributeError, struct.error, OverflowError) as exc:
        return False, checked, f"malformed header data: {exc}"
    return False, checked, "walk ended without reaching the checkpoint"


class HeaderChainVerifier:
    """Verify an anchor tx's block chains back to a pinned checkpoint.

    Fail-closed throughout: an unconfirmed tx, a hash/PoW failure, a
    checkpoint mismatch, or a fetch error all return ``verified=False``
    with a reason.
    """

    def __init__(
        self,
        fetcher: BlockFetcher,
        *,
        checkpoint_hash: str,
        checkpoint_height: int,
        max_headers: int = DEFAULT_MAX_HEADERS,
        daa: DAAParams | None = None,
    ) -> None:
        self.fetcher = fetcher
        self.checkpoint_hash = checkpoint_hash
        self.checkpoint_height = checkpoint_height
        self.max_headers = max_headers
        self.daa = daa

    def verify_chain_for_tx(self, txid: str) -> HeaderChainResult:
        txid = txid.lower()
        try:
            tx = self.fetcher.fetch_tx(txid)
        except SPVError as exc:
            return HeaderChainResult(
                False, txid,
                checkpoint_height=self.checkpoint_height,
                reason=f"fetch failed: {exc}",
            )
        height = tx.get("blockheight")
        blockhash = tx.get("blockhash")
        if height is None or blockhash is None:
            return HeaderChainResult(
                False, txid,
                checkpoint_height=self.checkpoint_height,
                reason="unconfirmed: no blockheight on record",
            )
        try:
            tip_height = int(height)
        except (ValueError, TypeError, OverflowError) as exc:
            return HeaderChainResult(
                False, txid,
                checkpoint_height=self.checkpoint_height,
                reason=f"malformed blockheight: {exc}",
            )
        verified, checked, reason = verify_chain_to_checkpoint(
            self.fetcher,
            tip_height=tip_height,
            tip_hash=str(blockhash),
            checkpoint_hash=self.checkpoint_hash,
            checkpoint_height=self.checkpoint_height,
            max_headers=self.max_headers,
            daa=self.daa,
        )
        return HeaderChainResult(
            verified, txid,
            tip_height=tip_height,
            checkpoint_height=self.checkpoint_height,
            headers_checked=checked,
            reason=reason,
        )
