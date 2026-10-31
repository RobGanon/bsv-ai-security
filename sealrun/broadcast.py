"""Real broadcast for the Phase 2 publisher: build + sign + send anchor txs.

The publisher's broadcaster interface is ``broadcast(payload_hex) -> txid``,
with an optional ``broadcast_with_tx(payload_hex) -> (txid, tx_hex)``
shape: when a broadcaster provides it, the publisher stores the tx bytes
so later runs can bind the recorded txid to the transaction itself.
This module provides the first real implementation: :class:`WoCBroadcaster`,
which builds the 1-input anchor transaction (OP_RETURN payload + change),
signs it through a :class:`Signer`, and posts it to a WhatsOnChain
endpoint (Teratestnet for the first live anchor). The broadcaster takes
an explicit ``network`` ("testnet" or "mainnet"); testnet is the
default, and mainnet must be selected deliberately — the CLI requires
a separate --confirm-mainnet flag for a mainnet broadcast, and a
key's version byte must match the selected network.

Key management (ADR 0001): signing lives behind the :class:`Signer`
interface. Long-lived private keys are never passed through publishing
configuration — the CLI builds a :class:`WIFSigner` from the ``ANCHOR_WIF``
environment variable, and a future offline signer can implement the same
interface. For the Teratestnet proof the key necessarily sits on the same
machine as the publisher, which weakens protocol §7's offline-signing bar;
that is acceptable for a testnet proof and is stated in the docs, not
hidden.

Funding: the broadcaster spends one explicit funding UTXO (txid + vout).
The previous output's locking script and value are fetched from the
chain (WoC ``/tx/hash``) — on-chain truth, not the caller's claim — so a
mismatched funding claim fails instead of building an invalid tx.
WoC-TTN's unspent index is broken (its address and script ``/unspent``
endpoints both 500, verified 2026-10-16), so UTXO discovery by address
is not available on TTN; the funding outpoint comes from the faucet claim
(or the operator), the same way the BRC-166 harness payer does it.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol

from .anchor import decode_anchor_payload
from .bsv import PrivKey, Tx, sats_from_btc_decimal, validate_network
from .spv import validate_woc_base_url

# Default Teratestnet WhatsOnChain (WoC v1 compatible).
WOC_TTN_BASE = "https://api.woc-ttn.bsvblockchain.tech/v1/bsv/test"
# Default mainnet WhatsOnChain (WoC v1).
WOC_MAINNET_BASE = "https://api.whatsonchain.com/v1/bsv/main"


def validate_woc_network_base(base_url: str, network: str) -> str:
    """Validate transport and reject the known opposite-network WoC base.

    Custom endpoints remain supported, but the built-in mainnet and
    Teratestnet URLs must not be crossed with the selected network.
    """
    selected = validate_network(network)
    normalized = validate_woc_base_url(base_url).rstrip("/")
    opposite = WOC_MAINNET_BASE if selected == "testnet" else WOC_TTN_BASE
    if normalized == opposite:
        raise ValueError(
            f"WoC base URL does not match selected network {selected!r}"
        )
    return normalized


class BroadcastError(Exception):
    """Base class for broadcast failures."""


class BroadcastRejected(BroadcastError):
    """The network rejected the transaction (invalid, missing inputs, ...)."""


class BroadcastUnavailable(BroadcastError):
    """The broadcaster could not be reached; retrying may help."""


@dataclass(frozen=True)
class FundingUTXO:
    txid: str  # displayed (big-endian) hex
    vout: int
    value: int  # satoshis (cross-checked against the fetched prev tx)
    script_hex: str  # previous output's locking script


class Signer(Protocol):
    """Signs 32-byte digests. Implementations hold the key, not the config."""

    def sign(self, digest: bytes) -> bytes:
        """Return a DER ECDSA signature for ``digest``."""
        ...

    def pubkey_compressed(self) -> bytes:
        """Return the 33-byte compressed pubkey matching the signing key."""
        ...

    def address(self, network: str = "testnet") -> str:
        """Return the P2PKH address receiving change on the given network."""
        ...


class WIFSigner:
    """A :class:`Signer` backed by a WIF (from env, never logged).

    The WIF's version byte must match ``network``: a mainnet WIF is
    refused for testnet use and vice versa.
    """

    def __init__(self, key: PrivKey) -> None:
        self._key = key

    @classmethod
    def from_wif(cls, wif: str, network: str = "testnet") -> "WIFSigner":
        return cls(PrivKey.from_wif(wif, network=network))

    def sign(self, digest: bytes) -> bytes:
        from .bsv import sign_digest

        return sign_digest(self._key, digest)

    def pubkey_compressed(self) -> bytes:
        return self._key.pubkey_compressed()

    def address(self, network: str = "testnet") -> str:
        return self._key.address(network=network)


# request_fn(method, url, body) -> (status, body_bytes). Injectable for tests.
RequestFn = Callable[[str, str, bytes | None], tuple[int, bytes]]


def _urllib_request(method: str, url: str, body: bytes | None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    # WoC-TTN rejects the default "Python-urllib/..." User-Agent with 403
    # (verified live 2026-10-16). Identify the client honestly.
    req.add_header("User-Agent", "sealrun/1.0")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise ConnectionError(f"request to {url} failed: {exc}") from exc


class WoCBroadcaster:
    """Broadcast anchor payloads through a WhatsOnChain ``/tx/raw`` endpoint.

    ``network`` selects the change-address version and is threaded into
    the transaction builder; it defaults to testnet and must be set
    explicitly to mainnet by the caller (the CLI requires a separate
    --confirm-mainnet flag for a mainnet broadcast).
    """

    def __init__(
        self,
        *,
        base_url: str = WOC_TTN_BASE,
        network: str = "testnet",
        signer: Signer,
        fee_sats: int = 500,
        funding: FundingUTXO,
        request_fn: RequestFn | None = None,
    ) -> None:
        self.network = validate_network(network)
        self.base_url = validate_woc_network_base(base_url, self.network)
        self.signer = signer
        self.fee_sats = fee_sats
        self.funding = funding
        self._request = request_fn or _urllib_request

    def _fetch_prev_output(self) -> tuple[str, int]:
        """Return (locking script hex, value sats) for the funding outpoint."""
        return fetch_prev_output(
            self.base_url, self.funding.txid, self.funding.vout, self._request
        )

    def broadcast(self, payload_hex: str) -> str:
        """Build, sign, and broadcast the anchor tx for ``payload_hex``."""
        txid, _tx_hex = self.broadcast_with_tx(payload_hex)
        return txid

    def broadcast_with_tx(self, payload_hex: str) -> tuple[str, str]:
        """Build, sign, and broadcast the anchor tx, returning its bytes.

        Returns ``(txid, tx_hex)``: the publisher stores ``tx_hex`` with
        the broadcast record so a later run can bind the recorded txid
        to the actual transaction (recomputed txid + OP_RETURN payload)
        instead of trusting a txid string from an attacker-writable
        store. ``broadcast`` above keeps the txid-only shape for
        callers that do not need the bytes.
        """
        try:
            payload = bytes.fromhex(payload_hex)
            decode_anchor_payload(payload)  # validates magic + 84-byte layout
        except ValueError as exc:
            raise BroadcastError(f"invalid anchor payload: {exc}") from exc
        script_hex, value = self._fetch_prev_output()
        funding = FundingUTXO(
            txid=self.funding.txid,
            vout=self.funding.vout,
            value=value,
            script_hex=script_hex,
        )
        tx = Tx.build_anchor(
            funding=funding,
            payload=payload,
            change_address=self.signer.address(network=self.network),
            fee_sats=self.fee_sats,
            signer=self.signer,
            network=self.network,
        )
        tx_hex = tx.serialize().hex()
        txid = post_raw_tx(self.base_url, tx_hex, self._request,
                           local_txid=tx.txid())
        return txid, tx_hex


def fetch_prev_output(
    base_url: str, txid: str, vout: int,
    request_fn: RequestFn | None = None,
) -> tuple[str, int]:
    """Return (locking script hex, value sats) for one outpoint.

    The previous output comes from the chain (WoC ``/tx/hash``) — on-chain
    truth, not the caller's claim. Shared by :class:`WoCBroadcaster` and
    the offline-signing publisher paths, which need the funding output
    without a signer.
    """
    base_url = validate_woc_base_url(base_url).rstrip("/")
    request = request_fn or _urllib_request
    if (
        not isinstance(vout, int)
        or isinstance(vout, bool)
        or not 0 <= vout <= 0xFFFFFFFF
    ):
        raise BroadcastRejected(
            f"funding vout {vout!r} is not a uint32 output index"
        )
    url = f"{base_url.rstrip('/')}/tx/hash/{txid}"
    try:
        status, body = request("GET", url, None)
    except ConnectionError as exc:
        raise BroadcastUnavailable(str(exc)) from exc
    if status != 200:
        raise BroadcastRejected(
            f"cannot fetch funding tx {txid}: HTTP {status}"
        )
    try:
        tx = json.loads(body)
        vout_data = tx["vout"][vout]
        script = vout_data["scriptPubKey"]["hex"]
        value = sats_from_btc_decimal(vout_data["value"])
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise BroadcastRejected(
            f"funding tx {txid} has no output {vout}"
        ) from exc
    return script, value


def post_raw_tx(
    base_url: str, raw_hex: str, request_fn: RequestFn | None = None,
    *, local_txid: str,
) -> str:
    """POST one raw transaction hex and return its txid.

    Shared by :class:`WoCBroadcaster` and the offline-signing
    ``broadcast-signed`` path. Fail closed: do not trust endpoint echoes
    blindly and do not treat rejection strings as success.
    """
    base_url = validate_woc_base_url(base_url).rstrip("/")
    request = request_fn or _urllib_request
    try:
        status, body = request(
            "POST",
            f"{base_url.rstrip('/')}/tx/raw",
            json.dumps({"txhex": raw_hex}).encode(),
        )
    except ConnectionError as exc:
        raise BroadcastUnavailable(str(exc)) from exc
    text = body.decode("utf-8", "replace").strip()

    # Only explicit idempotent-success messages are accepted. Incidental
    # substrings such as "output already spent" or "not already known"
    # are rejections, even when an endpoint incorrectly uses a 2xx status.
    if status // 100 == 2:
        try:
            already_message = json.loads(text)
        except ValueError:
            already_message = text
        if isinstance(already_message, str) and already_message.strip().lower() in {
            "258: txn-already-known",
            "txn-already-known",
            "transaction already known",
            "already in mempool",
        }:
            return local_txid

    if status == 200:
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            raise BroadcastRejected(
                f"broadcast success body is not JSON: {text[:200]}"
            ) from exc
        txid = (
            parsed
            if isinstance(parsed, str)
            else parsed.get("txid")
            if isinstance(parsed, dict)
            else None
        )
        if not isinstance(txid, str) or len(txid) != 64:
            raise BroadcastRejected(
                f"broadcast returned an unusable txid: {text[:200]}"
            )
        txid = txid.lower()
        # Bind echoed txid to the locally computed txid (A2). Never trust
        # an arbitrary txid returned by the endpoint.
        if txid != local_txid.lower():
            raise BroadcastRejected(
                "broadcast returned txid does not match the locally computed txid"
            )
        return txid
    if status // 100 == 2:
        # Any other 2xx must still return a txid that matches local_txid.
        # Try to parse if possible, otherwise fail closed.
        try:
            parsed = json.loads(text)
            txid = (
                parsed
                if isinstance(parsed, str)
                else parsed.get("txid")
                if isinstance(parsed, dict)
                else None
            )
            if isinstance(txid, str) and len(txid) == 64:
                txid = txid.lower()
                if txid != local_txid.lower():
                    raise BroadcastRejected(
                        "broadcast returned txid does not match the locally computed txid"
                    )
                return txid
        except (ValueError, AttributeError):
            pass
        raise BroadcastRejected(
            f"broadcast success body did not provide a matching txid: {text[:200]}"
        )
    raise BroadcastRejected(f"broadcast rejected: HTTP {status}: {text[:500]}")
