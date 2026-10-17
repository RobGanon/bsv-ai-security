# BSV Anchoring Protocol — Design v0.1 (Phase 2)

Anchors the Phase 1 local audit journal and rollback checkpoint to the
Bitcoin SV blockchain, giving them **independent verifiability**: a third
party holding the journal file, the anchor transactions, and BSV block
headers can confirm the log was not rewritten — even against the local
administrator.

Status: publisher + WoC broadcaster implemented. First live anchor on
Teratestnet 2026-10-16 (txid ``4111b7cf9d42624be75aa78f5031caaebe4e836665b95fbcdbadbb086b2bf029``,
OP_RETURN payload committing journal head seq 1–3). SPV / Merkle inclusion
verification is still out of scope (see §10).

## 1. What this fixes (and why Phase 1 needs it)

Phase 1 review found three weaknesses that local software cannot fix on its
own, because the attacker and the defender are the same machine:

| # | Weakness | Local result | With anchoring |
|---|----------|--------------|----------------|
| 1 | Journal tail truncation (delete last N events) | Remaining chain still verifies — undetectable | Anchor commits to a head hash; truncation breaks the recomputation check |
| 2 | Whole-journal deletion | `verify_audit_journal` returns 0 ("valid") | Last anchor names an `end_seq`; a missing journal contradicts it |
| 3 | Rollback-checkpoint rewind (highest accepted `release_seq`) | Checkpoint lives in local storage the admin can rewrite | Checkpoint is committed on-chain; rewind requires forking visible history |

The anchor does not make the log *truthful* — it makes the log's *history*
unrewritable without detection. That distinction is the entire security
argument; everything below follows from it.

## 2. Security properties (explicit)

**Provided:**

- *Existence bound.* Journal state S existed no later than the block that
  confirms its anchor (block time is the authoritative timestamp; the
  local `anchored_at` field is informational only).
- *History integrity.* Any modification, deletion, or truncation of journal
  events after anchoring is detectable by recomputation (§6).
- *Checkpoint durability.* The highest accepted manifest `release_seq`, once
  anchored, cannot be rolled back without producing a visibly forked anchor
  chain (§4).
- *Fork visibility.* Anchor transactions chain on-chain via `prev_txid`;
  a competing history requires a competing visible chain, not a silent edit.

**Explicitly NOT provided:**

- *Truthfulness.* A compromised administrator can append false events *before*
  they are anchored. Anchoring proves *when* a statement was committed, not
  that the statement is true. Garbage in, anchored garbage out.
- *Liveness.* If the anchor publisher stops publishing, verifiers lose
  freshness (recent events unanchored), never history.
- *Key-compromise resistance.* Whoever holds the anchor private key can anchor
  arbitrary roots. Key management (§7) is a separate requirement, not solved
  by this protocol.
- *Privacy.* Anchored data is public. Only hashes and sequence numbers go
  on-chain — never event contents, prompts, model data, or keys.

## 3. What is anchored

Per anchor interval, the publisher commits to:

- `head_hash` (32 bytes): the `event_hash` of the last journal event in the
  interval. Because every event commits to its predecessor, the head commits
  to the *entire* journal history — no separate Merkle tree is needed. (The
  existing `event_hash` values are already suitable leaf hashes.)
- `start_seq` / `end_seq` (4 bytes each, big-endian uint32): the journal
  sequence range covered. `start_seq` MUST equal previous anchor's
  `end_seq + 1`; the genesis anchor starts at 1.
- `release_seq` (4 bytes, big-endian uint32): the highest manifest
  `release_seq` accepted during the interval (0 if none). This is the
  durable rollback checkpoint.
- `prev_txid` (32 bytes): txid of the previous anchor transaction
  (all zeros for the genesis anchor). Chains anchors on-chain.

No Merkle tree over events is required for the base protocol: chain-head
commitment plus full-journal recomputation is simpler and matches the
existing hash-chain structure. (A Merkle-tree variant enabling selective
disclosure of sub-ranges is a possible future extension; it is not needed
to close findings 1–3.)

## 4. Anchor transaction format

- **Inputs:** one input spending to the anchor key (funds the fee; the
  input's pubkey also authenticates authorship — see §5).
- **Outputs:**
  1. `OP_RETURN` data push with the payload below.
  2. Optional change output back to the anchor key's address.
- **Payload** (84 bytes + script overhead — trivially within standard
  OP_RETURN limits):

```
offset  size  field
0       8     magic: ASCII "AIGUARD1" (protocol id + version)
8       32    head_hash: journal chain head event_hash
40      4     start_seq (big-endian uint32)
44      4     end_seq (big-endian uint32)
48      4     release_seq (big-endian uint32, highest accepted manifest seq)
52      32    prev_txid (previous anchor txid; zeros for genesis)
```

- The transaction is signed with the anchor private key, which is a BSV
  key by construction (ECDSA/secp256k1). This is independent of the
  manifest signing key (see §7 — separate keys, with a recommendation on
  scheme alignment).

**Why chain anchors via `prev_txid`:** without it, a compromised anchor key
could publish a "replacement" history starting from any point and a verifier
could not tell which chain is canonical. With chaining, the canonical chain
is the one reachable from the genesis anchor; any competing chain is a
visible fork, and the fork point identifies exactly where history diverged.

## 5. Trust anchors (distributed out-of-band, once)

A verifier needs exactly three things that cannot be derived from the chain
itself:

1. **Manifest signing public key** (already required in Phase 1).
2. **Genesis anchor txid.** Everything else is discovered by following
   `prev_txid` links. Distribute it through the same authenticated channel
   as the manifest public key.
3. **Anchor public key / address.** The verifier checks each anchor
   transaction's input against this key, so an attacker cannot anchor fake
   roots under a different key and claim them as ours.

Rotation of any of these is a key-ceremony event, out of scope for v0.1.

## 6. Verification procedure (independent verifier)

Inputs: journal file, genesis anchor txid, anchor pubkey, BSV block headers
(or an SPV source serving Merkle inclusion proofs, e.g. BEEF).

**Status (2026-10-16):** step 1's inclusion check is implemented in
`aiguard/spv.py` (`anchor-chain-verify --spv`). WoC-TTN serves no
compact Merkle-proof endpoint, so the verifier recomputes the Merkle
root from the claimed block's tx list and checks the header hash +
proof-of-work — stronger evidence than a served proof, heavier on
bandwidth (fine for Teratestnet's tiny blocks; compact proofs are the
mainnet path). Header-chain sync back to a trusted checkpoint is
implemented in `aiguard/spv.py` (`anchor-chain-verify --header-chain
--checkpoint-hash --checkpoint-height`): the verifier walks headers
from each anchor's block back to the operator-pinned checkpoint,
checking every header's hash + proof-of-work; walks are capped at
2016 headers and fail closed past the cap.
anchor-input-signature check (step 1, second bullet) is implemented in
`aiguard/anchor.py` (`anchor-chain-verify --anchor-sig --anchor-pubkey`):
the anchor tx's single input must parse as P2PKH with sighash
`SIGHASH_ALL|FORKID`, carry the trusted anchor pubkey, spend a P2PKH
output to that pubkey, and its ECDSA signature must verify against
the BIP 143 FORKID sighash.

1. **Collect the anchor chain.** From the genesis txid, fetch each anchor
   transaction and follow `prev_txid` until the latest. For each anchor:
   - Verify a Merkle inclusion proof against block headers (confirms the
     anchor is really on-chain, at a specific height/time).
   - Verify the transaction input is signed by the anchor pubkey.
   - Verify `start_seq == previous end_seq + 1` (no gaps, no overlaps).
2. **Recompute the journal.** Walk the journal from event 1, recomputing
   each `event_hash` and checking `previous_hash`/`seq` linkage (the Phase 1
   `verify_audit_journal` logic).
3. **Compare.** For each anchor interval, the recomputed head hash at
   `end_seq` MUST equal the anchored `head_hash`. The highest anchored
   `release_seq` MUST be >= the `release_seq` of the manifest currently in
   use (rollback check against the durable checkpoint).
4. **Verdict.** Any mismatch identifies the exact interval where history
   was altered. A journal shorter than the last anchored `end_seq` is
   truncation, detected. A missing journal with anchors present is deletion,
   detected.

Complexity is O(journal length + anchor count); anchors are small and
infrequent (§8).

## 7. Key management

- **Anchor key** MUST be generated and held separately from the AI host —
  ideally offline, with signing done on an isolated machine (the
  air-gapped-QR pattern, e.g. the ElectrumSVP-Signer model, fits here: the
  online publisher prepares the unsigned anchor tx, the offline signer
  signs it). If the AI host holds the anchor key, findings 1–3 regress to
  "attacker can anchor a false history" — the protocol then proves nothing
  against the local admin.
- **Manifest signing key** stays separate from the anchor key (different
  authorities: *release approval* vs. *history attestation*). Recommendation:
  migrate manifest signing from Ed25519 to secp256k1 so the whole system
  uses one signature scheme and one cryptographic audit surface. The keys
  remain distinct; only the scheme is unified.
- **Production:** consider a multisig anchor key (2-of-3 across separate
  custodians) so no single compromised machine can anchor false history.

## 8. Anchoring policy (parameters)

- Trigger: `anchor_every_n_events` (e.g. 100) OR `anchor_every_t_seconds`
  (e.g. 3600), whichever fires first.
- Anchoring is **best-effort and asynchronous**: local verification and
  operation NEVER block on chain availability. If broadcast fails, retry
  with an extended interval — the payload commits to
  `[last_anchored_seq + 1, current_head]`, so retries are naturally
  idempotent (same head → same payload).
- Cost: BSV sub-cent fees make frequent anchoring cheap. At ~$0.0001 per
  anchor, hourly anchoring costs on the order of $1/year. (Estimate only;
  measure at implementation time.)

## 9. What this still does not fix (carried forward)

- Real-time false-event injection by a compromised admin (detectable only
  after the fact, by out-of-band audit of event *contents*).
- The verify→launch TOCTOU gap (needs the privileged launcher consuming
  `verified_artifacts()` handles — see Phase 1 v0.2.0 README).
- Private-key protection on the AI host itself.
- Liveness of the anchor publisher (monitor it; alert on missed intervals).

## 10. Implementation work items (Phase 2)

1. `anchor` module: interval tracking, payload construction ( §4 byte
   layout), BSV transaction build/fund/broadcast (needs a BSV library and
   node or mAPI access).
2. `anchor-verify` CLI implementing §6 (SPV proof check + chain
   recomputation + checkpoint comparison).
3. Configuration: anchor address, node/mAPI endpoint, policy parameters
   (§8), genesis txid registry.
4. Tests: tampered journal detected against anchor; truncated tail
   detected; deleted journal detected; checkpoint rollback detected;
   forked anchor chain detected; broadcast-failure retry idempotency.
5. secp256k1 migration for manifest signing (recommended before §10.1
   references signature schemes).
