"""Safe interfaces and configuration for Phase 2 BSV publishing.

This module intentionally contains no live network, wallet, signing, or
broadcast implementation. Network publishing must be implemented behind
these contracts and independently reviewed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Protocol
from urllib.parse import urlparse


class PublishingConfigurationError(ValueError):
    """Raised when publishing configuration is missing or unsafe."""


@dataclass(frozen=True)
class PublishingConfig:
    """Validated non-secret configuration for a publishing backend."""

    network: str
    backend: str
    endpoint: str
    fee_rate_sat_per_byte: int
    max_fee_sat: int
    provider_token: str | None = None
    rpc_username: str | None = None
    rpc_password: str | None = None

    def __repr__(self) -> str:
        # URLs may contain tokens in query strings; never print endpoints.
        return (
            "PublishingConfig("
            f"network={self.network!r}, backend={self.backend!r}, "
            "endpoint='<configured>', "
            f"fee_rate_sat_per_byte={self.fee_rate_sat_per_byte!r}, "
            f"max_fee_sat={self.max_fee_sat!r}, "
            f"provider_token={'<redacted>' if self.provider_token else None!r}, "
            f"rpc_username={'<redacted>' if self.rpc_username else None!r}, "
            f"rpc_password={'<redacted>' if self.rpc_password else None!r})"
        )


def _reject_url_credentials(parsed, label: str) -> None:
    if parsed.username is not None or parsed.password is not None:
        raise PublishingConfigurationError(
            f"{label} URL must not embed credentials; use environment secrets"
        )


def load_publishing_config(
    environ: Mapping[str, str] | None = None,
) -> PublishingConfig:
    """Load and validate testnet-only configuration from environment variables.

    Mainnet is deliberately rejected in this foundation. A future mainnet
    implementation requires a separate reviewed change and explicit approval.
    """
    env = os.environ if environ is None else environ
    network = env.get("AIGUARD_BSV_NETWORK", "testnet").strip().lower()
    if network != "testnet":
        raise PublishingConfigurationError(
            "only the testnet network is enabled; mainnet publishing is disabled"
        )

    backend = env.get("AIGUARD_BSV_BACKEND", "provider").strip().lower()
    if backend not in {"provider", "node"}:
        raise PublishingConfigurationError(
            "AIGUARD_BSV_BACKEND must be 'provider' or 'node'"
        )

    if backend == "provider":
        endpoint = env.get("AIGUARD_BSV_PROVIDER_URL", "").strip()
        token = env.get("AIGUARD_BSV_PROVIDER_TOKEN") or None
        username = password = None
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise PublishingConfigurationError(
                "provider endpoint must be an HTTPS URL"
            )
        _reject_url_credentials(parsed, "provider")
    else:
        endpoint = env.get("AIGUARD_BSV_NODE_RPC_URL", "").strip()
        token = None
        username = env.get("AIGUARD_BSV_NODE_RPC_USERNAME") or None
        password = env.get("AIGUARD_BSV_NODE_RPC_PASSWORD") or None
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PublishingConfigurationError(
                "node RPC endpoint must be an HTTP(S) URL"
            )
        _reject_url_credentials(parsed, "node RPC")
        if parsed.scheme == "http" and parsed.hostname not in {
            "localhost", "127.0.0.1", "::1"
        }:
            raise PublishingConfigurationError(
                "unencrypted node RPC is permitted only on loopback"
            )
        if bool(username) != bool(password):
            raise PublishingConfigurationError(
                "node RPC username and password must be configured together"
            )

    try:
        fee_rate = int(env.get("AIGUARD_BSV_FEE_RATE", "1"))
        max_fee = int(env.get("AIGUARD_BSV_MAX_FEE_SAT", "10000"))
    except (TypeError, ValueError) as exc:
        raise PublishingConfigurationError(
            "fee rate and maximum fee must be integers"
        ) from exc
    if fee_rate < 1:
        raise PublishingConfigurationError("fee rate must be at least 1 sat/byte")
    if max_fee < 1:
        raise PublishingConfigurationError("maximum fee must be positive")

    return PublishingConfig(
        network=network,
        backend=backend,
        endpoint=endpoint,
        fee_rate_sat_per_byte=fee_rate,
        max_fee_sat=max_fee,
        provider_token=token,
        rpc_username=username,
        rpc_password=password,
    )


@dataclass(frozen=True)
class SpendableOutput:
    """A candidate previous output; raw script and amount must be validated."""

    txid: str
    output_index: int
    value_sat: int
    locking_script_hex: str
    confirmed: bool


@dataclass(frozen=True)
class FeeQuote:
    """Fee estimate with enough provenance for policy/logging."""

    sat_per_byte: int
    source: str
    observed_at: str


@dataclass(frozen=True)
class BroadcastResult:
    """Untrusted broadcaster response; txid must be recomputed locally."""

    returned_txid: str
    response_summary: str


@dataclass(frozen=True)
class MerkleProof:
    """Untrusted proof material; validation is the verifier's responsibility."""

    txid: str
    block_hash: str
    block_height: int
    transaction_index: int
    branch_hashes: tuple[str, ...]


class PublisherAdapter(Protocol):
    """Shared contract for provider and self-hosted-node adapters."""

    def get_spendable_outputs(self, address: str) -> list[SpendableOutput]:
        """Return candidate UTXOs; callers must validate their provenance."""

    def get_fee_quote(self, estimated_size_bytes: int) -> FeeQuote:
        """Return a fee estimate for the expected serialized transaction size."""

    def broadcast(self, raw_transaction_hex: str) -> BroadcastResult:
        """Broadcast signed raw transaction bytes without claiming inclusion."""

    def get_raw_transaction(self, txid: str) -> bytes:
        """Fetch serialized transaction bytes for the requested txid."""


class VerifierSource(Protocol):
    """Read-only source used independently of the publishing adapter."""

    def get_raw_transaction(self, txid: str) -> bytes:
        """Fetch raw transaction bytes."""

    def get_merkle_proof(self, txid: str) -> MerkleProof:
        """Fetch untrusted Merkle proof material."""

    def get_header(self, block_hash: str) -> bytes:
        """Fetch serialized block header bytes."""


class Signer(Protocol):
    """Signing boundary; implementations may be external or offline."""

    def sign_transaction(
        self,
        unsigned_transaction_hex: str,
        prevouts: list[SpendableOutput],
        network: str,
    ) -> str:
        """Return signed transaction hex; caller must verify it before broadcast."""
