"""Minimal BSV primitives for the live anchor: secp256k1, P2PKH, tx build/sign.

Stdlib only, no external dependency — the same posture as the rest of
aiguard and the same approach the BRC-166 harness proved in Go. This
module is deliberately narrow: one input (P2PKH), one OP_RETURN output
(the 84-byte anchor payload), one change output. It does not implement
script verification, fee estimation, or SPV — the publisher verifies
locally before broadcasting, and inclusion verification is a separate
verifier's job (ADR 0001).

Signing is RFC 6979 deterministic with low-S normalization: no RNG is
involved in signature generation, so a bad RNG cannot leak the key.
The implementation is pure-Python bignum arithmetic and is not
constant-time; timing side-channels would require local access to
the signing host.

Sighash is SIGHASH_ALL | SIGHASH_FORKID (0x41), BIP 143.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

# secp256k1 domain parameters.
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

SIGHASH_ALL_FORKID = 0x41
DUST_SATS = 546
# Consensus maximum: 21,000,000 BTC, in satoshis. Values above this are
# not real amounts; rejecting them here keeps hostile fetcher data from
# reaching struct.pack (which would raise struct.error, not ValueError).
MAX_SATS = 21_000_000 * 100_000_000


def sats_from_btc_decimal(value: object) -> int:
    """Convert a WoC decimal BTC value to exact integer satoshis.

    Fail-closed: reject non-numeric, non-finite, negative,
    sub-satoshi, and above-consensus-maximum values. Uses Decimal over
    the shortest repr of the input so no binary floating-point rounding
    is involved — a ``float`` 0.000995 becomes exactly 99500, never
    99499.99999.... Raises ValueError on any deviation; callers map it
    to their own fail-closed error.
    """
    try:
        sats = Decimal(str(value)) * 10**8
    except (InvalidOperation, ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"invalid BTC decimal value {value!r}") from exc
    if (
        not sats.is_finite()
        or sats < 0
        or sats > MAX_SATS
        or sats != sats.to_integral_value()
    ):
        raise ValueError(
            f"BTC decimal value {value!r} is not a whole non-negative "
            "satoshi amount within the consensus maximum"
        )
    return int(sats)


def hash160(data: bytes) -> bytes:
    """RIPEMD-160(SHA-256(data)). Raises loudly if RIPEMD-160 is unavailable."""
    try:
        return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()
    except ValueError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError(
            "RIPEMD-160 is not available in this Python's hashlib; "
            "aiguard/bsv.py cannot derive addresses without it"
        ) from exc


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# --- base58 ---------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    if not out:
        # All-zero (or empty) input: exactly the leading-zero padding,
        # with "1" for the empty case.
        return "1" * pad if pad else "1"
    return "1" * pad + out


def base58_decode(text: str) -> bytes:
    n = 0
    for char in text:
        try:
            digit = _B58_ALPHABET.index(char)
        except ValueError as exc:
            raise ValueError(f"invalid base58 character {char!r}") from exc
        n = n * 58 + digit
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + raw


def base58check_encode(version: int, payload: bytes) -> str:
    data = bytes([version]) + payload
    return base58_encode(data + sha256d(data)[:4])


def base58check_decode(text: str) -> tuple[int, bytes]:
    raw = base58_decode(text)
    if len(raw) < 5:
        raise ValueError("base58check string too short")
    data, checksum = raw[:-4], raw[-4:]
    if sha256d(data)[:4] != checksum:
        raise ValueError("base58check checksum mismatch")
    return data[0], data[1:]


# --- elliptic curve ---------------------------------------------------------

def _point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _scalar_mult(k: int, point: tuple[int, int] = (_GX, _GY)) -> tuple[int, int] | None:
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def pubkey_from_privkey(secret: int) -> bytes:
    point = _scalar_mult(secret)
    assert point is not None
    x, y = point
    return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")


def _pubkey_point(pubkey: bytes) -> tuple[int, int]:
    if len(pubkey) != 33 or pubkey[0] not in (0x02, 0x03):
        raise ValueError("pubkey must be a 33-byte compressed secp256k1 key")
    x = int.from_bytes(pubkey[1:], "big")
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if (y & 1) != (pubkey[0] & 1):
        y = _P - y
    if (y * y - y_sq) % _P != 0:
        raise ValueError("pubkey is not on the secp256k1 curve")
    return (x, y)


# --- ECDSA (RFC 6979) -------------------------------------------------------

def _rfc6979_nonce(secret: int, digest: bytes) -> int:
    bx = secret.to_bytes(32, "big") + digest
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < _N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def _der_encode_integer(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + bytes([len(raw)]) + raw


def _der_encode_signature(r: int, s: int) -> bytes:
    body = _der_encode_integer(r) + _der_encode_integer(s)
    return b"\x30" + bytes([len(body)]) + body


def _der_decode_signature(sig: bytes) -> tuple[int, int]:
    if len(sig) < 8 or sig[0] != 0x30:
        raise ValueError("signature is not DER")
    total = sig[1]
    if total + 2 != len(sig):
        raise ValueError("DER signature length mismatch")
    if sig[2] != 0x02:
        raise ValueError("DER signature missing R")
    r_len = sig[3]
    s_pos = 4 + r_len
    # Bounds-check before indexing: a hostile r_len must yield
    # ValueError here, not an IndexError at sig[s_pos].
    if s_pos >= len(sig):
        raise ValueError("DER signature truncated at R")
    r = int.from_bytes(sig[4 : 4 + r_len], "big")
    if sig[s_pos] != 0x02:
        raise ValueError("DER signature missing S")
    if s_pos + 1 >= len(sig):
        raise ValueError("DER signature truncated at S")
    s_len = sig[s_pos + 1]
    s = int.from_bytes(sig[s_pos + 2 : s_pos + 2 + s_len], "big")
    if s_pos + 2 + s_len != len(sig):
        raise ValueError("DER signature trailing bytes")
    return r, s


def sign_digest(privkey: "PrivKey", digest: bytes) -> bytes:
    """RFC 6979 deterministic ECDSA, low-S normalized. Returns DER."""
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    z = int.from_bytes(digest, "big")
    k = _rfc6979_nonce(privkey.secret, digest)
    point = _scalar_mult(k)
    assert point is not None
    r = point[0] % _N
    if r == 0:
        raise ValueError("degenerate signature (r == 0)")
    s = (pow(k, -1, _N) * (z + r * privkey.secret)) % _N
    if s == 0:
        raise ValueError("degenerate signature (s == 0)")
    if s > _N // 2:  # low-S normalization (BIP 62)
        s = _N - s
    return _der_encode_signature(r, s)


def verify_sig(pubkey: bytes, digest: bytes, der_sig: bytes) -> bool:
    """Verify a DER ECDSA signature against a compressed pubkey and digest."""
    if len(digest) != 32:
        return False
    try:
        r, s = _der_decode_signature(der_sig)
        point = _pubkey_point(pubkey)
    except ValueError:
        return False
    if not 1 <= r < _N or not 1 <= s < _N:
        return False
    z = int.from_bytes(digest, "big")
    w = pow(s, -1, _N)
    u1 = (z * w) % _N
    u2 = (r * w) % _N
    result = _point_add(_scalar_mult(u1), _scalar_mult(u2, point))
    if result is None:
        return False
    return result[0] % _N == r


# --- keys ---------------------------------------------------------------------

#: Networks the signing code supports. "testnet" is always the default;
#: mainnet must be selected explicitly, and a key's version byte must
#: match the selected network (a mainnet WIF is refused for testnet use
#: and vice versa) so a key can never silently cross networks.
NETWORKS = ("testnet", "mainnet")
_WIF_VERSION = {"testnet": 0xEF, "mainnet": 0x80}
_ADDRESS_VERSION = {"testnet": 0x6F, "mainnet": 0x00}


def validate_network(network: str) -> str:
    """Return a normalized network name, or raise for an unknown one."""
    if not isinstance(network, str):
        raise ValueError(f"network must be 'testnet' or 'mainnet', got {network!r}")
    normalized = network.strip().lower()
    if normalized not in _WIF_VERSION:
        raise ValueError(f"network must be 'testnet' or 'mainnet', got {network!r}")
    return normalized


class PrivKey:
    """A secp256k1 private key. Never logged; never serialized except via WIF."""

    def __init__(self, secret: int) -> None:
        if not 1 <= secret < _N:
            raise ValueError("private key must satisfy 1 <= secret < curve order")
        self.secret = secret

    @classmethod
    def from_bytes(cls, data: bytes) -> "PrivKey":
        if len(data) != 32:
            raise ValueError("private key must be 32 bytes")
        return cls(int.from_bytes(data, "big"))

    @classmethod
    def from_wif(cls, wif: str, network: str = "testnet") -> "PrivKey":
        network = validate_network(network)
        version, payload = base58check_decode(wif)
        expected = _WIF_VERSION[network]
        if version != expected:
            raise ValueError(
                f"WIF version 0x{version:02x} does not match network "
                f"{network!r} (expected 0x{expected:02x}); refusing "
                "cross-network key use"
            )
        if len(payload) != 33 or payload[-1] != 0x01:
            raise ValueError("WIF must encode a compressed private key")
        return cls(int.from_bytes(payload[:32], "big"))

    def to_bytes(self) -> bytes:
        return self.secret.to_bytes(32, "big")

    def pubkey_compressed(self) -> bytes:
        return pubkey_from_privkey(self.secret)

    def address(self, network: str = "testnet") -> str:
        network = validate_network(network)
        return base58check_encode(
            _ADDRESS_VERSION[network], hash160(self.pubkey_compressed())
        )

    def wif(self, network: str = "testnet") -> str:
        network = validate_network(network)
        return base58check_encode(_WIF_VERSION[network], self.to_bytes() + b"\x01")


# --- transactions ---------------------------------------------------------------

def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


class _Reader:
    def __init__(self, data: bytes, pos: int = 0) -> None:
        if pos < 0 or pos > len(data):
            raise ValueError("transaction offset out of range")
        self.data = data
        self.pos = pos

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("transaction truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def varint(self) -> int:
        first = self.read(1)[0]
        if first < 0xFD:
            return first
        if first == 0xFD:
            return struct.unpack("<H", self.read(2))[0]
        if first == 0xFE:
            return struct.unpack("<I", self.read(4))[0]
        return struct.unpack("<Q", self.read(8))[0]


@dataclass
class TxIn:
    prev_txid: str  # displayed (big-endian) hex
    prev_index: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF

    def serialize(self) -> bytes:
        return (
            bytes.fromhex(self.prev_txid)[::-1]
            + struct.pack("<I", self.prev_index)
            + _varint(len(self.script_sig))
            + self.script_sig
            + struct.pack("<I", self.sequence)
        )


@dataclass
class TxOut:
    value: int  # satoshis
    script: bytes

    def serialize(self) -> bytes:
        return struct.pack("<q", self.value) + _varint(len(self.script)) + self.script


@dataclass
class Tx:
    version: int = 1
    inputs: list[TxIn] = field(default_factory=list)
    outputs: list[TxOut] = field(default_factory=list)
    locktime: int = 0

    def serialize(self) -> bytes:
        out = struct.pack("<i", self.version)
        out += _varint(len(self.inputs))
        for txin in self.inputs:
            out += txin.serialize()
        out += _varint(len(self.outputs))
        for txout in self.outputs:
            out += txout.serialize()
        out += struct.pack("<I", self.locktime)
        return out

    def txid(self) -> str:
        """Displayed txid: double-SHA-256 of the serialization, byte-reversed."""
        return sha256d(self.serialize())[::-1].hex()

    @staticmethod
    def build_anchor(
        *, funding: "FundingUTXO", payload: bytes, change_address: str,
        fee_sats: int, signer: "Signer", network: str = "testnet",
    ) -> "Tx":
        """Build + sign a 1-input anchor tx (OP_RETURN payload + change).

        ``funding`` is the outpoint being spent (value + locking script
        taken from it). ``signer`` signs the FORKID sighash; its pubkey
        must match the funding output's P2PKH script (checked by the
        caller-side sighash, not re-derived here — the network rejects
        a mismatched signature, and the broadcaster surfaces that).
        ``network`` selects the change-address version; it must match
        the address given.
        """
        from .broadcast import BroadcastError  # local import: avoid a cycle

        if len(payload) != 84:
            raise BroadcastError("anchor payload must be exactly 84 bytes")
        if fee_sats < 0:
            raise BroadcastError("fee_sats must be non-negative")
        if (
            not isinstance(funding.vout, int)
            or isinstance(funding.vout, bool)
            or not 0 <= funding.vout <= 0xFFFFFFFF
        ):
            raise BroadcastError(
                f"funding vout {funding.vout!r} is not a uint32 output index"
            )
        if (
            not isinstance(funding.value, int)
            or isinstance(funding.value, bool)
            or not 0 <= funding.value <= MAX_SATS
        ):
            raise BroadcastError(
                "funding value must be within the consensus range"
            )
        change = funding.value - fee_sats
        if change < 0:
            raise BroadcastError(
                f"insufficient funds: funding {funding.value} sats < fee {fee_sats}"
            )
        outputs = [TxOut(0, build_op_return_script(payload))]
        if change >= DUST_SATS:
            outputs.append(
                TxOut(
                    change,
                    build_p2pkh_script_for_address(change_address, network=network),
                )
            )
        # Dust change is absorbed into the fee (no change output).
        tx = Tx(
            inputs=[TxIn(funding.txid, funding.vout)],
            outputs=outputs,
        )
        digest = sighash_forkid(
            tx, 0, bytes.fromhex(funding.script_hex), funding.value
        )
        der = signer.sign(digest)
        pubkey = signer.pubkey_compressed()
        tx.inputs[0].script_sig = (
            _push(der + bytes([SIGHASH_ALL_FORKID])) + _push(pubkey)
        )
        return tx


def _push(data: bytes) -> bytes:
    if len(data) > 75:
        raise ValueError("push of >75 bytes is not supported by this builder")
    return bytes([len(data)]) + data


def parse_tx_prefix(raw: bytes, offset: int = 0) -> tuple[Tx, int]:
    """Parse one raw transaction starting at ``offset``.

    Returns ``(tx, consumed)`` where ``consumed`` is the number of
    bytes the transaction occupies, so a caller parsing a stream
    (e.g. a BEEF envelope) knows where the next field starts.
    Raises ValueError on truncated input or an out-of-range offset.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("transaction must be bytes")
    r = _Reader(bytes(raw), offset)
    version = struct.unpack("<i", r.read(4))[0]
    n_in = r.varint()
    inputs = []
    for _ in range(n_in):
        prev_txid = r.read(32)[::-1].hex()
        prev_index = struct.unpack("<I", r.read(4))[0]
        script_len = r.varint()
        script_sig = r.read(script_len)
        sequence = struct.unpack("<I", r.read(4))[0]
        inputs.append(TxIn(prev_txid, prev_index, script_sig, sequence))
    n_out = r.varint()
    outputs = []
    for _ in range(n_out):
        value = struct.unpack("<q", r.read(8))[0]
        script_len = r.varint()
        outputs.append(TxOut(value, r.read(script_len)))
    locktime = struct.unpack("<I", r.read(4))[0]
    return Tx(version, inputs, outputs, locktime), r.pos - offset


def parse_tx(raw: bytes) -> Tx:
    tx, consumed = parse_tx_prefix(raw)
    if consumed != len(raw):
        raise ValueError("transaction has trailing bytes")
    return tx


def sighash_forkid(tx: Tx, input_index: int, prev_script: bytes, prev_value: int) -> bytes:
    """BIP 143 sighash with SIGHASH_ALL | SIGHASH_FORKID.

    Raises ValueError on an out-of-range input index or a prev_value
    outside the consensus range — a negative or above-maximum value
    must fail here, not as a struct.error from the packing below.
    """
    if not 0 <= input_index < len(tx.inputs):
        raise ValueError("input_index out of range")
    if (
        not isinstance(prev_value, int)
        or isinstance(prev_value, bool)
        or not 0 <= prev_value <= MAX_SATS
    ):
        raise ValueError("prev_value must be within the consensus range")
    hash_prevouts = sha256d(
        b"".join(
            bytes.fromhex(txin.prev_txid)[::-1] + struct.pack("<I", txin.prev_index)
            for txin in tx.inputs
        )
    )
    hash_sequence = sha256d(
        b"".join(struct.pack("<I", txin.sequence) for txin in tx.inputs)
    )
    hash_outputs = sha256d(b"".join(txout.serialize() for txout in tx.outputs))
    txin = tx.inputs[input_index]
    preimage = (
        struct.pack("<i", tx.version)
        + hash_prevouts
        + hash_sequence
        + bytes.fromhex(txin.prev_txid)[::-1]
        + struct.pack("<I", txin.prev_index)
        + _varint(len(prev_script))
        + prev_script
        + struct.pack("<q", prev_value)
        + struct.pack("<I", txin.sequence)
        + hash_outputs
        + struct.pack("<I", tx.locktime)
        + struct.pack("<I", SIGHASH_ALL_FORKID)
    )
    return sha256d(preimage)


# --- scripts ----------------------------------------------------------------------

def build_p2pkh_script(pubkey: bytes) -> bytes:
    """P2PKH locking script for a compressed pubkey."""
    return b"\x76\xa9\x14" + hash160(pubkey) + b"\x88\xac"


def build_p2pkh_script_for_address(address: str, network: str = "testnet") -> bytes:
    """P2PKH locking script for a base58check address on the given network.

    The address version byte must match the network, so a testnet
    address can never be baked into a mainnet transaction or vice versa.
    """
    network = validate_network(network)
    version, payload = base58check_decode(address)
    if version != _ADDRESS_VERSION[network] or len(payload) != 20:
        raise ValueError(
            f"address version 0x{version:02x} does not match network "
            f"{network!r}; refusing cross-network address use"
        )
    return b"\x76\xa9\x14" + payload + b"\x88\xac"


def build_op_return_script(payload: bytes) -> bytes:
    """OP_RETURN script carrying the exact anchor payload bytes."""
    if len(payload) > 0xFFFF:
        raise ValueError("OP_RETURN payload too large")
    if len(payload) <= 75:
        return b"\x6a" + bytes([len(payload)]) + payload
    if len(payload) <= 0xFF:
        return b"\x6a\x4c" + bytes([len(payload)]) + payload
    return b"\x6a\x4d" + struct.pack("<H", len(payload)) + payload
