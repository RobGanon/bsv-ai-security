"""Block inclusion verification (SPV) for anchor transactions.

What this proves: an anchor txid is really inside a mined block. The
verifier fetches the block the tx claims to be in, recomputes the
Merkle root from the block's tx list, and checks it against the
block header's merkleroot — plus the header hash and proof-of-work.

One honest naming note: WoC-TTN serves no compact Merkle-proof
endpoint (its ``/tx/{txid}/proof`` variants 404/500, verified
2026-10-16), so the fetcher here recomputes the Merkle path from the
block's full tx list instead of trusting a proof server. That is
*stronger* evidence than a served proof (nothing to forge upstream)
but downloads the whole block's tx list — trivial for Teratestnet's
tiny blocks, heavy for mainnet. The pure :func:`verify_merkle_proof`
below is real SPV: compact proofs plug in unchanged when a source
serves them. Header-chain sync (verifying headers link back to a
trusted checkpoint) is the follow-up; :func:`verify_header_chain`
already checks consecutive-header linkage for a supplied header list.
"""
from __future__ import annotations

import json
import struct
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol

from .bsv import sha256d

# Default Teratestnet WhatsOnChain (WoC v1 compatible).
WOC_TTN_BASE = "https://api.woc-ttn.bsvblockchain.tech/v1/bsv/test"

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
    try:
        if header_hash(header) != expected_hash.lower():
            return False
    except ValueError:
        return False
    return verify_pow(header, bits)


def verify_header_chain(headers: list[BlockHeader]) -> bool:
    """True iff consecutive headers link (child.prev == parent.hash),
    every header hashes to its declared hash, and every header passes
    its own proof-of-work. Fail-closed on any malformed header."""
    try:
        if not headers:
            return False
        for header in headers:
            declared = header.hash
            if not isinstance(declared, str) or len(declared) != 64:
                return False
            if header_hash(header.to_bytes()) != declared.lower():
                return False
            if not verify_pow(header.to_bytes(), header.bits):
                return False
        for parent, child in zip(headers, headers[1:]):
            if child.prev_hash.lower() != (parent.hash or "").lower():
                return False
        return True
    except (ValueError, TypeError, AttributeError):
        return False


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

    def fetch_block(self, height: int) -> tuple[BlockHeader, list[str]]:
        """Return (header, txid list) for a block height."""
        ...


# request_fn(method, url) -> (status, body_bytes). Injectable for tests.
RequestFn = Callable[[str, str], tuple[int, bytes]]


def _urllib_get(method: str, url: str) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method=method)
    # WoC-TTN rejects the default "Python-urllib/..." User-Agent with 403
    # (verified live 2026-10-16). Identify the client honestly.
    req.add_header("User-Agent", "aiguard/1.0")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise ConnectionError(f"request to {url} failed: {exc}") from exc


class WoCBlockFetcher:
    """Fetch tx + block data from a WhatsOnChain (WoC v1) endpoint."""

    def __init__(
        self,
        base_url: str = WOC_TTN_BASE,
        request_fn: RequestFn | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
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

    def fetch_block(self, height: int) -> tuple[BlockHeader, list[str]]:
        data = self._get_json(f"/block/height/{height}")
        try:
            header = BlockHeader(
                version=int(data["version"]),
                prev_hash=str(data["previousblockhash"]),
                merkle_root=str(data["merkleroot"]),
                time=int(data["time"]),
                bits=int(data["bits"], 16) if isinstance(data["bits"], str) else int(data["bits"]),
                nonce=int(data["nonce"]),
                height=int(data["height"]),
                hash=str(data["hash"]),
            )
            txids = [str(t) for t in data["tx"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise SPVUnavailable(
                f"WoC block {height} body is missing required fields"
            ) from exc
        return header, txids


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
        except SPVError as exc:
            return InclusionResult(
                False, txid, blockheight=height, blockhash=blockhash,
                reason=f"fetch failed: {exc}",
            )
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
