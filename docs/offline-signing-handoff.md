# Offline signing handoff: publisher export → human signer → broadcast

The publisher half of the anchor signing ceremony. The full ceremony
design (roles, custody, hard rules, threat model) lives in the signing
ceremony doc; this file documents what the publisher does and how the
three steps fit together.

## The loop

```
1. publish --export-unsigned unsigned.hex
      (publisher: builds the unsigned anchor tx, writes its hex, stops)
            |
            v
2. Human-side signer signs unsigned.hex
      (human reviews the decoded tx, approves with password + 2FA,
       signer returns the signed tx — a separate tool, not this repo's
       publisher; the builder never sees the key)
            |
            v
3. publish --broadcast-signed signed.hex
      (publisher: verifies the signed tx against a freshly rebuilt
       unsigned tx, then broadcasts it)
```

## Step 1 — export

```
sealrun publish --journal audit.jsonl --anchor-record anchors.json \
  --export-unsigned unsigned.hex \
  --funding-txid <prev anchor change txid> --funding-vout <vout> \
  --change-address <anchor address> [--fee-sats 500]
```

- Builds the anchor payload from the journal head (same checkpoint
  logic as the normal publish flow, including acceptance binding) and
  the unsigned transaction from the funding UTXO + payload + change
  address, and writes the unsigned hex to the file.
- **Never signs, never broadcasts.** Export mode takes no signer, makes
  no POST, and refuses when `ANCHOR_WIF` is set: the builder side of
  the ceremony must never hold signing material.
- Prints the human cross-checks: `unsigned_txid` (the hash of the
  *unsigned* tx — NOT the final txid, which changes once the signature
  is added), the decoded payload (head hash, sequence range, release
  sequence, previous txid), fee, change address, and funding outpoint.
  The human compares `unsigned_txid` + payload against the signer's
  display before approving.
- The funding UTXO must pay to the change (anchor) address — the
  previous anchor's change output is the funding source, so a funding
  claim pointing elsewhere is operator error and fails here.
- Refuses mainnet unconditionally. Testnet only.

## Step 2 — sign (human side, outside this repo's publisher)

The human carries `unsigned.hex` to the signer, reviews the decoded
transaction, and approves with password + 2FA. The signer returns the
signed transaction hex. Nothing in this step touches the publisher,
and the publisher never learns the key.

## Step 3 — broadcast-signed

```
sealrun publish --journal audit.jsonl --anchor-record anchors.json \
  --broadcast-signed signed.hex \
  --funding-txid <same> --funding-vout <same> \
  --change-address <same> [--fee-sats <same>]
```

The `--funding-*`, `--change-address`, and `--fee-sats` arguments must
match the export: broadcast-signed rebuilds the expected unsigned tx
from the same inputs, so any difference refuses.

Verification, in order, all before any broadcast:

1. The signed tx decodes and has exactly 1 input with a non-empty
   script_sig.
2. The checkpoint is rebuilt fresh from the journal + record store
   (same payload as the export — a stale signed tx for an older head
   fails here, because the rebuilt payload differs).
3. The signed tx, with its script_sig stripped, serializes
   byte-identically to the rebuilt unsigned tx. This pins version,
   input outpoint, sequence, every output, and locktime.
4. The script_sig is exactly `push(DER || SIGHASH_ALL|FORKID) +
   push(pubkey)`; the pubkey matches the funding output's P2PKH
   script; the signature verifies against the FORKID sighash.
5. If the head is already broadcast, the signed tx must be the same
   txid (an idempotent retry). A different signed tx for the same head
   — including a malleated-signature variant — is refused.
6. The canonical re-serialization of the verified tx is posted, and
   the network-echoed txid must equal the verified txid; a mismatch
   refuses and leaves the record pending.

On success the record is marked `broadcast` with the txid. A broadcast
failure (network) leaves the record `pending`; retrying the same
signed tx is safe.

## What it does not do

- It does not check that the *signer* enforced the ceremony's hard
  rules — that is the signer's job, on the human side, outside the
  builder's reach. The publisher verifies the signed tx matches what
  *it* built; it cannot verify what the human saw.
- It does not authorize mainnet spend. Export and broadcast-signed
  refuse mainnet unconditionally in this build.
- It does not replace the normal `publish --broadcast` path, which
  still exists for the (discouraged, testnet-proof) flow where the
  key sits alongside the publisher. The ceremony flow is the one to
  use for any anchor that matters.

## Failure modes

| Situation | Behavior |
|---|---|
| Signed tx tampered (outputs, outpoint, locktime changed) | Refused: stripped form no longer matches |
| Bad / wrong signature | Refused: signature verification fails |
| Wrong sighash byte | Refused: must be SIGHASH_ALL\|FORKID |
| Fee / change address / funding differs from export | Refused: rebuilt unsigned tx differs |
| Journal head advanced after export | Refused: rebuilt payload differs (stale signed tx) |
| Network echoes a different txid | Refused: record stays pending |
| Same signed tx broadcast twice | Idempotent: second broadcast returns the same txid |
| `ANCHOR_WIF` set in export / broadcast-signed mode | Refused: builder must never hold signing material |
