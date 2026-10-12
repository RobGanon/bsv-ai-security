# Phase 2 publishing foundation: current implementation

This branch adds the first code foundation for the Phase 2 publishing design. It deliberately does **not** implement a BSV client, transaction serializer, wallet, signer, broadcast call, or SPV/header consensus verifier.

## Implemented

- `aiguard.publishing.PublishingConfig` and `load_publishing_config()` validate a testnet-only configuration.
- The backend selection is explicit: `provider` or `node`.
- Provider endpoints must use HTTPS. Node RPC may use HTTP only on loopback; remote node RPC requires HTTPS.
- Credentials embedded in endpoint URLs are rejected. Configuration representations redact tokens, credentials, and endpoint URLs.
- Fee rate and maximum fee must be positive integers.
- Typed protocol interfaces define the future provider/node adapter, independent verifier source, and signer boundary.
- Unit tests cover mainnet rejection, backend validation, transport safeguards, redaction, and fee policy.

## Configuration examples

Provider backend:

```sh
export AIGUARD_BSV_NETWORK=testnet
export AIGUARD_BSV_BACKEND=provider
export AIGUARD_BSV_PROVIDER_URL=https://your-provider.example/api
export AIGUARD_BSV_PROVIDER_TOKEN='set-outside-the-repository'
export AIGUARD_BSV_FEE_RATE=1
export AIGUARD_BSV_MAX_FEE_SAT=10000
```

Self-hosted node backend:

```sh
export AIGUARD_BSV_NETWORK=testnet
export AIGUARD_BSV_BACKEND=node
export AIGUARD_BSV_NODE_RPC_URL=http://127.0.0.1:8332
# If required, set username/password using a local secret manager or shell.
export AIGUARD_BSV_NODE_RPC_USERNAME='operator'
export AIGUARD_BSV_NODE_RPC_PASSWORD='set-outside-the-repository'
```

These examples are illustrative only. No adapter consumes these settings yet. Do not paste real credentials into source files, issues, pull requests, or chat. Do not use mainnet values; the configuration loader rejects any network except `testnet`.

## Important limits

- Interfaces are contracts, not working network implementations.
- `load_publishing_config` does not prove that an endpoint is really a BSV testnet endpoint. Before any network call, a future adapter must verify the configured network identity against trusted chain parameters and fail closed.
- No private-key field exists in the configuration. Signing belongs behind the `Signer` protocol and should preferably be performed by an offline or external signer.
- No transaction is created or broadcast by this code. No on-chain inclusion or confirmation claim can be made.
- Mainnet must remain blocked pending a separate security review and explicit approval.

## Next implementation stage

1. Select and review a maintained BSV transaction library and consensus-compatible SPV/header validation implementation.
2. Implement mock adapters and a shared conformance suite.
3. Implement transaction serialization and local txid computation using tested library functionality.
4. Add independent Merkle proof and header-chain verification before any “accepted” result is possible.
5. Only after deterministic tests pass, add a manually enabled testnet integration test using a dedicated test key or external signer.
