import pytest

from sealrun.publishing import (
    PublishingConfigurationError,
    load_publishing_config,
)


def test_defaults_to_testnet_but_requires_provider_endpoint():
    with pytest.raises(PublishingConfigurationError, match="HTTPS"):
        load_publishing_config({})


def test_provider_configuration_uses_testnet_and_redacts_token():
    config = load_publishing_config({
        "SEALRUN_BSV_NETWORK": "testnet",
        "SEALRUN_BSV_BACKEND": "provider",
        "SEALRUN_BSV_PROVIDER_URL": "https://provider.example/api",
        "SEALRUN_BSV_PROVIDER_TOKEN": "do-not-print-this-token",
    })
    assert config.network == "testnet"
    assert config.backend == "provider"
    assert "do-not-print-this-token" not in repr(config)
    assert "provider.example" not in repr(config)
    assert "<redacted>" in repr(config)


def test_provider_rejects_credentials_embedded_in_url():
    with pytest.raises(PublishingConfigurationError, match="must not embed credentials"):
        load_publishing_config({
            "SEALRUN_BSV_PROVIDER_URL": "https://user:secret@provider.example/api",
        })


def test_mainnet_requires_explicit_confirmation():
    # Mainnet without the confirmation value is refused: it must never
    # be enabled by a single variable or by accident.
    with pytest.raises(PublishingConfigurationError, match="confirm"):
        load_publishing_config({
            "SEALRUN_BSV_NETWORK": "mainnet",
            "SEALRUN_BSV_PROVIDER_URL": "https://provider.example/api",
        })
    with pytest.raises(PublishingConfigurationError, match="confirm"):
        load_publishing_config({
            "SEALRUN_BSV_NETWORK": "mainnet",
            "SEALRUN_BSV_MAINNET_CONFIRM": "yes",
            "SEALRUN_BSV_PROVIDER_URL": "https://provider.example/api",
        })


def test_mainnet_with_confirmation_loads():
    config = load_publishing_config({
        "SEALRUN_BSV_NETWORK": "mainnet",
        "SEALRUN_BSV_MAINNET_CONFIRM": "I_UNDERSTAND_MAINNET_RISK",
        "SEALRUN_BSV_PROVIDER_URL": "https://provider.example/api",
    })
    assert config.network == "mainnet"


def test_unknown_backend_is_rejected():
    with pytest.raises(PublishingConfigurationError, match="must be 'provider' or 'node'"):
        load_publishing_config({
            "SEALRUN_BSV_BACKEND": "magic",
            "SEALRUN_BSV_PROVIDER_URL": "https://provider.example/api",
        })


def test_provider_requires_https():
    with pytest.raises(PublishingConfigurationError, match="HTTPS"):
        load_publishing_config({
            "SEALRUN_BSV_PROVIDER_URL": "http://provider.example/api",
        })


def test_node_allows_loopback_http():
    config = load_publishing_config({
        "SEALRUN_BSV_BACKEND": "node",
        "SEALRUN_BSV_NODE_RPC_URL": "http://127.0.0.1:8332",
    })
    assert config.backend == "node"
    assert config.endpoint == "http://127.0.0.1:8332"


def test_node_rejects_remote_unencrypted_rpc():
    with pytest.raises(PublishingConfigurationError, match="loopback"):
        load_publishing_config({
            "SEALRUN_BSV_BACKEND": "node",
            "SEALRUN_BSV_NODE_RPC_URL": "http://node.example:8332",
        })


def test_node_requires_username_and_password_together():
    with pytest.raises(PublishingConfigurationError, match="configured together"):
        load_publishing_config({
            "SEALRUN_BSV_BACKEND": "node",
            "SEALRUN_BSV_NODE_RPC_URL": "https://node.example:8332",
            "SEALRUN_BSV_NODE_RPC_USERNAME": "operator",
        })


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("SEALRUN_BSV_FEE_RATE", "0"),
        ("SEALRUN_BSV_MAX_FEE_SAT", "0"),
        ("SEALRUN_BSV_FEE_RATE", "not-an-int"),
        ("SEALRUN_BSV_MAX_FEE_SAT", "not-an-int"),
    ],
)
def test_invalid_fee_policy_is_rejected(variable, value):
    with pytest.raises(PublishingConfigurationError):
        load_publishing_config({
            "SEALRUN_BSV_PROVIDER_URL": "https://provider.example/api",
            variable: value,
        })
