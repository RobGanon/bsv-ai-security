# Phase 2 BSV Publishing and Independent Verification Design

Status: design proposal for review. This document does not enable broadcasting and does not authorize mainnet use.

## Decisions

- **Initial network:** BSV test environment only. Network selection must be explicit; mainnet publishing is disabled unless a later, separately reviewed change enables it.
- **Connection paths:** support both a provider adapter and a self-hosted node adapter behind one publisher interface.
- **Independent verification:** the verifier must not trust the publishing provider's “confirmed” response as proof. It must independently validate the transaction bytes, expected payload, anchor-chain linkage, and transaction inclusion against a locally validated BSV header chain or a separately operated SPV verifier.
- **Keys:** private keys are never committed to GitHub, checked into fixtures, printed in logs, or stored in repository configuration. Signing is a separate interface and should support an external signer; the publisher process need not possess the private key.
- **Repository safety:** implementation remains on a feature branch and draft PR. Do not merge to `main` without explicit user approval.

## 1. Components and trust boundaries

```text
verified local journal
       |
       v
anchor payload builder ----> unsigned transaction builder
                                    |
                                    v
                             signer interface
                         (external signer preferred)
                                    |
                                    v
                              broadcaster
                           /               \\
                 provider adapter       node adapter
                           \\               /
                            txid + raw tx
                                  |
                                  v
                    independent verifier (separate path)
                    - fetch raw transaction from source A
                    - fetch block/header and Merkle proof from source B
                    - validate proof against trusted header chain
                    - parse OP_RETURN and compare exact payload
                    - verify anchor input/key policy and prevout
                    - validate anchor sequence and prev_txid chain
                    - recompute journal commitments
```

The broadcaster and verifier should use different endpoints or operators where practical. A provider API response, explorer page, transaction ID, or unconfirmed mempool observation alone is not inclusion proof.

## 2. Common adapter contracts

Keep network-specific code out of journal/payload validation. The initial interfaces should be narrow and mockable:

- `PublisherAdapter.get_utxos(address)`: return candidate spendable outputs with outpoint, value, locking script, and confirmation status.
- `PublisherAdapter.get_fee_quote(tx_size_bytes)`: return a bounded fee estimate with source and timestamp.
- `PublisherAdapter.broadcast(raw_tx_hex)`: return the calculated/observed txid and provider response. Recompute the txid locally from the serialized transaction; do not blindly trust the response.
- `PublisherAdapter.get_raw_transaction(txid)`: retrieve transaction bytes, not merely parsed JSON.
- `VerifierSource.get_transaction(txid)`: obtain raw transaction bytes from an independent source.
- `VerifierSource.get_merkle_proof(txid)` and `get_header(height/hash)`: provide proof material and header data. Proofs are only as trustworthy as the verifier's validation of the header chain.
- `Signer.sign(unsigned_tx, prevouts, policy)`: separate interface. The implementation must verify the returned signed transaction locally before broadcast. A future offline/air-gapped signer can implement this contract.

Use typed result objects and explicit errors (network unavailable, rejected, fee exceeds cap, malformed response, not found, unconfirmed, invalid proof). Never silently downgrade a failed proof check to success.

## 3. Provider and self-hosted node options

### Option A — provider adapter

Use a configured BSV transaction API for UTXO discovery, fee estimates, broadcast, and transaction retrieval. Keep the provider-specific HTTP/API code in one module. Require endpoint and credential configuration through environment variables or an external secret manager; never put credentials in source files or example configs.

Advantages: lower setup burden and easier testnet experimentation. Risks: provider availability, API changes, rate limits, privacy leakage, and potentially misleading confirmation status. Mitigations: cap fees, set request timeouts, record provider identity, retry safely, and use an independent source for verification.

### Option B — self-hosted node adapter

Connect to a locally operated BSV node over its authenticated/local RPC interface. The node adapter must not expose RPC publicly without strong network controls. Document node version, network mode, synchronization status, pruning/indexing requirements, and the exact RPC capabilities used. Do not assume an RPC method exists until it is tested against the chosen node version.

Advantages: stronger control over data access and fewer third-party dependencies. Risks: storage/bandwidth/operations burden, stale or unsynced node, RPC credential exposure, and operational maintenance. The verifier should still check inclusion independently; a node being self-hosted does not itself prove its data is current or canonical.

Both options implement the same adapter contract and run the same conformance tests. Provider credentials and node RPC credentials are not signing keys.

## 4. Network and configuration policy

- Default test configuration must name the intended BSV test network explicitly and fail closed if network identity cannot be established.
- Separate configuration namespaces for test and mainnet; never infer network from an endpoint string alone.
- Testnet address/version prefixes, genesis/header parameters, fee policy, and transaction APIs must be verified against the selected BSV implementation before coding network constants.
- Mainnet mode must remain unavailable by default. Enabling it requires a dedicated reviewed change, explicit operator action, a fee cap, and a key-management review.
- No automatic real-value funding, faucet access, or broadcast should occur during unit tests.
- CI uses mocks and deterministic fixtures only. Live testnet tests are opt-in, separately marked, and require explicit configuration.

Suggested environment variables (names illustrative until implementation):
- `SEALRUN_BSV_NETWORK=testnet`
- `SEALRUN_BSV_BACKEND=provider|node`
- `SEALRUN_BSV_PROVIDER_URL` / `SEALRUN_BSV_PROVIDER_TOKEN`
- `SEALRUN_BSV_NODE_RPC_URL` / external secret for RPC credentials
- `SEALRUN_BSV_FEE_RATE` and `SEALRUN_BSV_MAX_FEE_SAT`
- signer configuration identifying a local development signer or external signer, never a private-key value in a committed file.

## 5. Transaction construction and publication lifecycle

1. Verify the entire local journal and calculate the anchor payload. Validate that the proposed interval starts at the previous confirmed anchor's `end_seq + 1`; genesis starts at sequence 1 and uses a zero `prev_txid`.
2. Build a transaction with a canonical data-carrier output containing the exact 84-byte payload, plus a change output only when needed. Do not include event text, prompts, model bytes, user identifiers, or secrets.
3. Select eligible UTXOs for the configured anchor address, estimate size/fee, enforce a hard maximum fee, and prepare the unsigned transaction with exact prevout data.
4. Ask the configured signer to sign. Do not log secret material. Verify transaction structure, inputs, outputs, fee, network, and signatures locally before broadcast.
5. Broadcast once. Calculate txid from the final serialized transaction and compare it with the returned txid. Persist a local pending record with payload hash, txid, network, timestamp, and state; never treat this record as proof of inclusion.
6. Retry without creating duplicate anchors when possible: first query the exact txid and check whether the same transaction is already known. If fee replacement or rebuilding is necessary, preserve the payload and chain predecessor, and record each attempt. A retry must not silently advance the anchor chain or create competing successors.
7. Mark confirmed only after the independent verifier validates inclusion under the configured confirmation policy. The publisher must distinguish prepared, signed, broadcast, observed, included, and accepted states.

If broadcast outcome is ambiguous (timeout after submission), query by the locally calculated txid before creating another transaction. Never fabricate a txid or advance `prev_txid` based only on a successful HTTP response.

## 6. Independent inclusion verification

A full verification result must be more than “payload matches local journal.” It should report separate booleans/fields for each proof obligation:

1. **Transaction identity:** parse raw serialized transaction; compute txid according to BSV transaction rules; ensure it equals the requested txid.
2. **Payload:** parse the output script, identify exactly one valid SEALRUN payload output, and compare all 84 bytes to the expected payload. Reject malformed, duplicate, or ambiguous SEALRUN outputs.
3. **Block inclusion:** validate the transaction's Merkle branch against the Merkle root in the claimed block header. Check proof serialization, byte order, index, and duplicate-last-node rules against test vectors.
4. **Header-chain validity:** validate proof-of-work, target/difficulty transitions, parent linkage, and network genesis/consensus parameters using a maintained BSV implementation or audited library. A Merkle proof without a trusted/validated header chain is not independently sufficient.
5. **Confirmation policy:** require a configurable minimum depth and report block height/hash and observed depth. Testnet reorgs are expected; re-check the anchor chain after a reorg.
6. **Input authorization:** resolve each anchor input's previous output and validate the unlocking script/signature against the previous locking script using a consensus-compatible transaction/script verifier. Separately enforce the configured anchor-key/address policy. Merely finding a public key in an input script is not sufficient proof that the input was valid.
7. **Anchor chain:** decode the payload, verify genesis trust anchor, ensure each successor's `prev_txid` points to the accepted predecessor, and enforce contiguous non-overlapping sequence ranges. Detect multiple successors from the same predecessor and return a fork error unless an explicit, documented fork-resolution policy exists.
8. **Journal commitment:** recompute every event hash and compare each anchor's `head_hash` at its `end_seq`; reject missing/shortened journals, mismatches, sequence gaps, and rollback of the trusted highest `release_seq`.
9. **Independent sources:** allow the verifier's raw-transaction source and header/proof source to be configured separately from the publisher. A disagreement is an error requiring investigation, not a reason to trust whichever endpoint answered last.

The verifier output must distinguish: `journal_valid`, `payload_matches`, `txid_valid`, `merkle_inclusion_valid`, `header_chain_valid`, `input_authorization_valid`, `anchor_chain_valid`, `release_checkpoint_valid`, `confirmations`, and final `accepted`. Missing evidence is “unknown/false,” never success.

## 7. Key and secret handling

- No private keys, seed phrases, wallet files, raw signing secrets, provider tokens, or RPC passwords in Git, issue comments, logs, test snapshots, crash reports, or generated documentation.
- Add secret-pattern scanning and repository ignore rules before a live signer is introduced. Tests use clearly fake keys and deterministic fixtures only.
- Prefer an external or offline signer. The online publisher should construct and validate the transaction but should not need to export a long-lived private key.
- Separate the anchor key from manifest-signing keys. Document backup, recovery, rotation, authorization, and compromise response before any mainnet use.
- Do not promise that anchoring proves the content of an AI event is true. It proves a commitment existed by a block and makes later rewriting detectable under the verifier's trust assumptions.

## 8. Test and release plan

### Stage A — deterministic unit tests (no network)
- Provider/node adapters conform to the same contract.
- Raw transaction txid calculation, payload script parsing, byte order, Merkle proof validation, and header validation have known-good and adversarial fixtures.
- Reject wrong network, wrong magic/version, wrong payload, malformed transaction, wrong txid, altered Merkle branch, invalid header linkage/PoW, invalid input signature, unknown prevout, anchor fork, sequence gap/overlap, journal truncation, journal deletion, and release rollback.
- Fee caps, timeout handling, ambiguous broadcast retry, duplicate txid, and reorg state transitions are tested.
- Ensure logs and exceptions never include credentials or private key material.

### Stage B — testnet integration (explicit opt-in)
- Use a dedicated low-value test key or external test signer, never a production key.
- Publish a test anchor, independently retrieve raw transaction and inclusion proof through a separate source, and verify it end-to-end.
- Exercise confirmation delays, provider disagreement, unavailable endpoints, duplicate broadcast, and a simulated/observed reorg.
- Keep live tests out of default CI; document required environment variables and teardown/key disposal.

### Stage C — security review before mainnet
- Review dependencies, transaction serialization/script verification, fee calculation, secret handling, and header consensus validation.
- Verify test vectors independently and review the trust-anchor distribution procedure.
- Mainnet support requires a separate pull request and explicit approval. Passing testnet tests is not approval to spend mainnet funds.

## 9. Implementation sequence

1. Add typed interfaces and configuration validation, with network defaulting to testnet and mainnet explicitly blocked.
2. Choose and pin an actively maintained BSV transaction/consensus library after reviewing supported network and SPV APIs; do not hand-roll consensus or signature validation.
3. Implement mock provider/node adapters and conformance tests.
4. Implement transaction construction/signing boundary and provider/node broadcasting, still with live broadcast disabled by default.
5. Implement independent transaction, Merkle proof, header-chain, input authorization, and anchor-chain verification.
6. Add opt-in testnet integration and operational documentation.
7. Keep this PR draft until code review and testnet evidence are complete.

## 10. Acceptance criteria

Phase 2 publishing is not complete until:
- both adapter paths pass the same contract suite;
- default CI is offline and deterministic;
- no secret material is present in the repository or logs;
- a testnet anchor is independently verified from raw transaction bytes and a valid inclusion proof against a validated header chain;
- the complete anchor chain and journal commitment verify, including tamper/truncation/fork cases;
- all verification dimensions are reported separately; and
- mainnet remains disabled unless separately reviewed and explicitly approved.
