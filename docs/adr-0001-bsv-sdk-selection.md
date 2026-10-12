# ADR 0001: BSV transaction and SPV library selection

- Status: provisional selection for a proof-of-concept
- Date: 2026-10-11
- Scope: transaction serialization, script verification, Merkle inclusion, and chain-tracker integration

## Decision

Evaluate the official BSV Blockchain Python SDK, distributed as `bsv-sdk`, as the first candidate for this Python repository. The repository targets Python 3.10+, and the SDK metadata currently declares Python 3.10+ support. Its published feature list describes transaction construction/serialization/signing, OP_RETURN, BEEF/SPV/Merkle paths, and script execution.

References:
- Project: https://github.com/bitcoin-sv/py-sdk
- Package metadata: https://pypi.org/project/bsv-sdk/
- SDK documentation: https://docs.bsvblockchain.org/guides/sdks/py

This is a candidate selection, not a claim that every required consensus-validation feature has been proven suitable for this threat model.

## Why this candidate

- Same language/runtime as the existing project; avoids a second runtime or custom bridge for the first implementation.
- Purpose-built for BSV rather than relying on a generic Bitcoin library that may differ on BSV-specific transaction/script behavior.
- Publicly documented transaction and SPV-related components.
- The SDK repository exposes a test suite and CI, allowing an API and behavior review before we depend on it.

## Required validation before adding it as a runtime dependency

1. Pin a reviewed compatible release and verify its license/dependency footprint.
2. Write offline tests using fixed transaction, script, txid, and Merkle proof fixtures.
3. Confirm the SDK can parse serialized transaction bytes and compute the txid using correct byte order.
4. Confirm OP_RETURN payload construction and round-trip parsing preserve the exact 84-byte AIGUARD payload.
5. Confirm script validation checks each anchor input against its referenced previous output; locating a public key in a script is not enough.
6. Confirm its SPV API validates the Merkle path against a header supplied by a trustworthy, independently validated chain tracker.
7. Review how chain-tracker implementations establish network identity, proof of work, difficulty transitions, chain selection, and reorganization behavior. A Merkle proof by itself does not validate the header chain.
8. Verify the exact APIs against a pinned release in CI; do not code against guessed method names from README examples.

## Provider and node backends

The SDK may provide transaction primitives and some broadcaster/chain-tracker implementations, but it does not eliminate the need for our explicit adapter boundary. The provider adapter and self-hosted-node adapter must remain separate implementations of the same local protocol. The verifier should use a separately configured read-only source and must not accept a publisher's “confirmed” response as proof.

## Key management

Do not pass long-lived private keys through publishing configuration. Keep signing behind the `Signer` interface; prefer an external or offline signer. Any SDK method that couples signing and broadcasting must not be used as a single opaque operation for this project.

## Stop conditions

Do not proceed to live publishing if the library's header-chain trust assumptions cannot be made explicit and tested, if required BSV network behavior is unclear, or if a security-critical method cannot be covered with deterministic test vectors. In that case, isolate the SDK to transaction/script primitives and use a separately reviewed verifier, or pause for design review.
