"""BEEF (BRC-62) envelope parsing and verification.

A BEEF envelope bundles the transactions of a payment together with
the BUMPs (BRC-74) proving the mined ones, so a receiver can verify
the whole ancestry without a separate proof lookup per transaction.
Layout (BRC-62)::

    version       Uint32LE, always 4022206465 (``0100BEEF``)
    nBUMPs        VarInt
    BUMP data     nBUMPs x BUMP binary (BRC-74)
    nTransactions VarInt
    per tx:       raw tx bytes, then Has-BUMP (``01`` + VarInt BUMP
                  index, or ``00`` with nothing after it)

Verification (:meth:`BeefVerifier.verify_beef`):

* every tx carrying a BUMP must prove against the block header at the
  BUMP's height (Merkle root + proof-of-work, via
  :class:`sealrun.spv.BUMPVerifier`);
* every tx without a BUMP must have all of its inputs' parent txs
  present in the envelope and verified (BUMP or ancestry), each
  referenced output must exist, and input value must cover output
  value (fee >= 0).

What this does NOT do: script evaluation. BRC-62's local-validation
step also requires that the scripts of unmined transactions evaluate
to TRUE; sealrun has no script interpreter, so an unmined tx's
signatures are not checked here. A BEEF that verifies proves
inclusion and ancestry, not script validity. Envelopes are
operator-supplied: no public WhatsOnChain endpoint serves BEEF
(``/tx/{txid}/proof`` 404s on Teratestnet and mainnet, checked
2026-10-17).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from sealrun.bsv import parse_tx_prefix
from sealrun.spv import (
    BUMPVerifier,
    BlockFetcher,
    bump_to_bytes,
    parse_bump_bytes,
    parse_bump_json,
)

BEEF_VERSION = 4022206465
BEEF_MAGIC = b"\x01\x00\xbe\xef"


class BeefError(ValueError):
    """Raised for malformed BEEF input at parse/encode time."""


@dataclass(frozen=True)
class BeefTx:
    """One transaction inside a BEEF envelope."""

    raw: bytes
    txid: str  # display hex; must equal double-SHA-256 of raw, reversed
    bump_index: int | None  # index into Beef.bumps, or None if unmined


@dataclass(frozen=True)
class Beef:
    """A parsed BEEF envelope: BUMPs plus transactions."""

    bumps: tuple = ()
    txs: tuple = ()


@dataclass(frozen=True)
class BeefVerification:
    """Result of :meth:`BeefVerifier.verify_beef`."""

    verified: bool
    reason: str
    per_tx: dict  # txid (lowercase) -> status/verified/blockheight/blockhash/reason


def _varint(n: int) -> bytes:
    if n < 0:
        raise BeefError("varint must be non-negative")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


class _Reader:
    """Bounds-checked reader for the BEEF stream."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise BeefError("BEEF truncated")
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
                raise BeefError("non-canonical CompactSize encoding")
            return val
        if first == 0xFE:
            val = struct.unpack("<I", self.read(4))[0]
            if val <= 0xFFFF:
                raise BeefError("non-canonical CompactSize encoding")
            return val
        val = struct.unpack("<Q", self.read(8))[0]
        if val <= 0xFFFFFFFF:
            raise BeefError("non-canonical CompactSize encoding")
        return val

    def done(self) -> bool:
        return self.pos == len(self.data)


def parse_beef(data: bytes) -> Beef:
    """Parse BEEF bytes into a :class:`Beef`.

    Raises :class:`BeefError` (a ValueError) on any malformed input:
    wrong version, truncated stream, trailing bytes, a Has-BUMP flag
    other than ``00``/``01``, a BUMP index out of range, a duplicate
    txid, or a txid that does not match its raw bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise BeefError("BEEF data must be bytes")
    data = bytes(data)
    reader = _Reader(data)
    version = struct.unpack("<I", reader.read(4))[0]
    if version != BEEF_VERSION:
        raise BeefError(
            f"BEEF version {version} is not {BEEF_VERSION} "
            f"({BEEF_MAGIC.hex()})"
        )
    n_bumps = reader.varint()
    bumps = []
    for _ in range(n_bumps):
        bump, consumed = parse_bump_bytes(data, reader.pos)
        reader.pos += consumed
        bumps.append(bump)
    n_txs = reader.varint()
    txs = []
    seen: set[str] = set()
    for _ in range(n_txs):
        tx_start = reader.pos
        try:
            tx, consumed = parse_tx_prefix(data, reader.pos)
        except ValueError as exc:
            raise BeefError(f"transaction {len(txs)}: {exc}") from exc
        reader.pos += consumed
        flag = reader.read(1)[0]
        if flag == 0x01:
            bump_index = reader.varint()
            if bump_index >= n_bumps:
                raise BeefError(
                    f"transaction {len(txs)} references BUMP {bump_index} "
                    f"but the envelope has {n_bumps}"
                )
        elif flag == 0x00:
            bump_index = None
        else:
            raise BeefError(
                f"transaction {len(txs)} has invalid Has-BUMP flag "
                f"0x{flag:02x}"
            )
        # Compute txid from raw bytes to bind txid to raw bytes (A10)
        from .bsv import sha256d
        raw_tx = data[tx_start : tx_start + consumed]
        txid = sha256d(raw_tx)[::-1].hex()
        if txid != tx.txid():
            raise BeefError(f"transaction {len(txs)} txid does not match its raw bytes")
        if txid in seen:
            raise BeefError(f"duplicate txid {txid} in BEEF")
        seen.add(txid)
        txs.append(
            BeefTx(
                raw=raw_tx,
                txid=txid,
                bump_index=bump_index,
            )
        )
    if not reader.done():
        raise BeefError("BEEF has trailing bytes after the last transaction")
    return Beef(bumps=tuple(bumps), txs=tuple(txs))


def parse_beef_hex(hex_str: str) -> Beef:
    """Parse a BEEF hex string. Raises BeefError on malformed input."""
    if not isinstance(hex_str, str):
        raise BeefError("BEEF hex must be a string")
    try:
        data = bytes.fromhex(hex_str)
    except ValueError as exc:
        raise BeefError("BEEF hex is not valid hex") from exc
    return parse_beef(data)


def beef_to_bytes(beef: Beef) -> bytes:
    """Encode a :class:`Beef` to its BEEF bytes.

    Raises BeefError on a malformed Beef (bad BUMP, a txid that does
    not match its raw bytes, a trailing-bytes raw tx, or a BUMP index
    out of range).
    """
    if not isinstance(beef, Beef):
        raise BeefError("beef_to_bytes needs a Beef")
    bumps = []
    for i, bump in enumerate(beef.bumps):
        try:
            parse_bump_json(bump)
        except ValueError as exc:
            raise BeefError(f"BUMP {i}: {exc}") from exc
        bumps.append(bump)
    out = bytearray(BEEF_MAGIC)
    out += _varint(len(bumps))
    for bump in bumps:
        out += bump_to_bytes(bump)
    out += _varint(len(beef.txs))
    for i, entry in enumerate(beef.txs):
        if not isinstance(entry, BeefTx):
            raise BeefError(f"transaction {i} is not a BeefTx")
        try:
            tx, consumed = parse_tx_prefix(entry.raw)
        except ValueError as exc:
            raise BeefError(f"transaction {i}: {exc}") from exc
        if consumed != len(entry.raw):
            raise BeefError(f"transaction {i} raw has trailing bytes")
        from .bsv import sha256d
        raw_txid = sha256d(entry.raw)[::-1].hex().lower()
        if raw_txid != entry.txid.lower() or tx.txid() != entry.txid.lower():
            raise BeefError(
                f"transaction {i} txid does not match its raw bytes"
            )
        if entry.bump_index is not None and not (
            0 <= entry.bump_index < len(bumps)
        ):
            raise BeefError(
                f"transaction {i} references BUMP {entry.bump_index} "
                f"but the envelope has {len(bumps)}"
            )
        out += entry.raw
        if entry.bump_index is None:
            out.append(0x00)
        else:
            out.append(0x01)
            out += _varint(entry.bump_index)
    return bytes(out)


def beef_to_hex(beef: Beef) -> str:
    """Encode a :class:`Beef` to its BEEF hex string."""
    return beef_to_bytes(beef).hex()


class BeefVerifier:
    """Verify a BEEF envelope: BUMP inclusion for mined txs, ancestry
    + amount conservation for unmined ones. Fail-closed: malformed
    content yields verified=False, never raises (a non-Beef argument
    is a programmer error and raises ValueError).
    """

    def __init__(self, fetcher: BlockFetcher) -> None:
        self._bump = BUMPVerifier(fetcher)

    def verify_beef(self, beef: Beef) -> BeefVerification:
        if not isinstance(beef, Beef):
            raise ValueError("verify_beef needs a Beef")
        if not beef.txs:
            return BeefVerification(
                False, "BEEF contains no transactions", {}
            )
        keys = [tx.txid.lower() for tx in beef.txs]
        if len(set(keys)) != len(keys):
            return BeefVerification(
                False, "BEEF contains a duplicate txid", {}
            )
        by_txid = {tx.txid.lower(): tx for tx in beef.txs}
        parsed: dict[str, object] = {}
        structural: dict[str, str] = {}
        for tx in beef.txs:
            key = tx.txid.lower()
            try:
                parsed_tx, consumed = parse_tx_prefix(tx.raw)
            except ValueError as exc:
                structural[key] = f"unparsable raw tx: {exc}"
                continue
            if consumed != len(tx.raw):
                structural[key] = "raw tx has trailing bytes"
                continue
            from .bsv import sha256d
            raw_txid = sha256d(tx.raw)[::-1].hex().lower()
            if parsed_tx.txid() != key or raw_txid != key:
                structural[key] = "txid does not match raw bytes"
                continue
            parsed[key] = parsed_tx

        per_tx: dict[str, dict] = {}
        memo: dict[str, bool] = {}
        try:
            self._verify_bump_txs(beef, by_txid, per_tx, memo)
            for tx in beef.txs:
                key = tx.txid.lower()
                if tx.bump_index is None and key not in per_tx:
                    self._verify_ancestry(
                        key, by_txid, parsed, structural, per_tx, memo, set()
                    )
        except RecursionError:
            return BeefVerification(
                False, "BEEF ancestry chain too deep", per_tx
            )
        for key, reason in structural.items():
            if key not in per_tx:
                per_tx[key] = {
                    "status": "failed",
                    "verified": False,
                    "blockheight": None,
                    "blockhash": None,
                    "reason": reason,
                }
                memo[key] = False
        verified = bool(per_tx) and all(
            entry["verified"] for entry in per_tx.values()
        )
        return BeefVerification(
            verified,
            "BEEF verified"
            if verified
            else "BEEF verification failed: see per-tx reasons",
            per_tx,
        )

    def _verify_bump_txs(self, beef, by_txid, per_tx, memo) -> None:
        for tx in beef.txs:
            if tx.bump_index is None:
                continue
            key = tx.txid.lower()
            if not (0 <= tx.bump_index < len(beef.bumps)):
                per_tx[key] = {
                    "status": "failed",
                    "verified": False,
                    "blockheight": None,
                    "blockhash": None,
                    "reason": (
                        f"references BUMP {tx.bump_index} but the "
                        f"envelope has {len(beef.bumps)}"
                    ),
                }
                memo[key] = False
                continue
            verdict = self._bump.verify_bump_for_tx(
                tx.txid, beef.bumps[tx.bump_index]
            )
            memo[key] = verdict.verified
            per_tx[key] = {
                "status": "bump" if verdict.verified else "failed",
                "verified": verdict.verified,
                "blockheight": verdict.blockheight,
                "blockhash": verdict.blockhash,
                "reason": verdict.reason,
            }

    def _verify_ancestry(self, key, by_txid, parsed, structural, per_tx, memo, visiting) -> bool:
        if key in memo:
            return memo[key]
        if key in visiting:
            # A genuine cycle needs a SHA-256 fixed point, so this is
            # unreachable for real txs; fail closed if it ever happens.
            return False
        if key in structural:
            memo[key] = False
            return False
        visiting.add(key)
        tx = by_txid[key]
        parsed_tx = parsed.get(key)
        ok = parsed_tx is not None
        reason = "ancestry verified"
        total_in = 0
        if ok:
            # Consensus validity for unmined txs: a tx with no inputs or
            # no outputs, a negative output, or a duplicated input pair
            # can never be mined, so it must not verify as "ancestry
            # verified" even when the arithmetic happens to balance.
            # (Mined txs take the BUMP path and are not checked here.)
            if not parsed_tx.inputs or not parsed_tx.outputs:  # type: ignore[union-attr]
                ok = False
                reason = "unmined tx must have at least one input and one output"
            elif any(out.value < 0 for out in parsed_tx.outputs):  # type: ignore[union-attr]
                ok = False
                reason = "unmined tx has a negative output value"
        if ok:
            seen_inputs: set[tuple[str, int]] = set()
            for txin in parsed_tx.inputs:  # type: ignore[union-attr]
                pair = (txin.prev_txid.lower(), txin.prev_index)
                if pair in seen_inputs:
                    ok = False
                    reason = (
                        f"duplicate input spends {txin.prev_txid}:"
                        f"{txin.prev_index} twice"
                    )
                    break
                seen_inputs.add(pair)
                parent_key = txin.prev_txid.lower()
                parent = by_txid.get(parent_key)
                if parent is None:
                    ok = False
                    reason = (
                        f"input spends {txin.prev_txid}:{txin.prev_index} "
                        "which is not in the BEEF"
                    )
                    break
                if parent.bump_index is not None:
                    if not memo.get(parent_key, False):
                        ok = False
                        reason = (
                            f"parent {parent_key} failed its BUMP proof"
                        )
                        break
                elif not self._verify_ancestry(
                    parent_key, by_txid, parsed, structural, per_tx, memo,
                    visiting,
                ):
                    ok = False
                    reason = (
                        f"parent {parent_key} failed ancestry verification"
                    )
                    break
                parent_tx = parsed.get(parent_key)
                if (
                    parent_tx is None
                    or txin.prev_index < 0
                    or txin.prev_index >= len(parent_tx.outputs)
                ):  # type: ignore[union-attr]
                    ok = False
                    reason = (
                        f"input references vout {txin.prev_index} of "
                        f"{parent_key}, which does not exist"
                    )
                    break
                total_in += parent_tx.outputs[txin.prev_index].value  # type: ignore[union-attr]
            if ok:
                total_out = sum(
                    out.value for out in parsed_tx.outputs  # type: ignore[union-attr]
                )
                if total_in < total_out:
                    ok = False
                    reason = (
                        f"outputs ({total_out} sats) exceed inputs "
                        f"({total_in} sats)"
                    )
        visiting.discard(key)
        memo[key] = ok
        per_tx[key] = {
            "status": "ancestry" if ok else "failed",
            "verified": ok,
            "blockheight": None,
            "blockhash": None,
            "reason": reason,
        }
        return ok


def apply_beef_inclusion(result: dict, verifier: BeefVerifier, beef: Beef) -> dict:
    """Attach per-anchor BEEF inclusion results to a chain-verify result.

    The envelope is verified once as a whole; each anchor is then
    reported by its own tx's status inside it. Anchors whose txid is
    not in the envelope verify as False. Same two result shapes and
    non-mutating contract as apply_bump_inclusion. Top-level
    ``beef_inclusion_verified`` is True only when every anchor's tx
    is in the envelope and verifies. Per-anchor verdicts carry
    ``verified: True`` with ``status: "ancestry"`` for unmined txs — that
    means ancestry + amount conservation only, not signature verification;
    consumers must read ``status``, not the bare ``verified`` flag.
    """
    if not isinstance(beef, Beef):
        raise ValueError("beef must be a Beef")
    if not isinstance(verifier, BeefVerifier):
        raise ValueError("verifier must be a BeefVerifier")
    verification = verifier.verify_beef(beef)
    by_txid = {tx.txid.lower(): tx for tx in beef.txs}

    def _verdict(txid: str) -> dict:
        key = txid.lower()
        if key not in by_txid:
            return {
                "verified": False,
                "blockheight": None,
                "blockhash": None,
                "status": "failed",
                "reason": "anchor txid not in BEEF",
            }
        entry = verification.per_tx.get(key)
        if entry is None:
            return {
                "verified": False,
                "blockheight": None,
                "blockhash": None,
                "status": "failed",
                "reason": "BEEF verification produced no verdict for this tx",
            }
        return {
            "verified": entry["verified"],
            "blockheight": entry["blockheight"],
            "blockhash": entry["blockhash"],
            "status": entry["status"],
            "reason": entry["reason"],
        }

    if "chain" in result:
        chain = dict(result["chain"])
        summaries = chain.get("anchors", [])
        merged = []
        all_verified = True
        for summary in summaries:
            verdict = _verdict(summary["txid"])
            all_verified = all_verified and verdict["verified"]
            merged.append(
                {
                    **summary,
                    "beef_inclusion_verified": verdict["verified"],
                    "beef_inclusion": verdict,
                }
            )
        chain["anchors"] = merged
        return {
            **result,
            "chain": chain,
            "beef_inclusion_verified": all_verified,
        }
    merged = []
    all_verified = True
    for summary in result.get("anchors", []):
        verdict = _verdict(summary["txid"])
        all_verified = all_verified and verdict["verified"]
        merged.append(
            {
                **summary,
                "beef_inclusion_verified": verdict["verified"],
                "beef_inclusion": verdict,
            }
        )
    return {
        **result,
        "anchors": merged,
        "beef_inclusion_verified": all_verified,
    }
