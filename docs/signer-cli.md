# Offline anchor signer CLI

`aiguard signer` is the human side of the anchor signing ceremony
(see the ceremony design doc):
the AI/publisher prepares an unsigned anchor transaction, and this
signer — running on the human's machine, outside the builder's reach —
independently decodes it, enforces the ceremony's hard rules, shows
the decoded transaction for human review, requires username + password
+ TOTP authentication for this one transaction only, and signs.

Stdlib only. No network access anywhere in the signer: it never
fetches anything and never broadcasts. The builder broadcasts the
signed transaction separately.

## Setup

```sh
aiguard signer init --config ~/signer/signer.json --key-file ~/signer/anchor-key.txt
```

`init` generates a fresh **testnet** anchor key, sets your username and
password (typed twice), and prints a TOTP secret **once** — add it to
your authenticator app immediately. It refuses to overwrite existing
files. The key file and config are written with `0600` permissions.

Before each anchor, record what the next anchor must spend and anchor:

```sh
aiguard signer expect --config ~/signer/signer.json \
  --prev-txid <previous anchor txid> \
  --utxo-txid <funding UTXO txid> --utxo-vout <vout> --utxo-value <sats> \
  --expected-payload <84-byte anchor payload hex>
```

The expected payload is the full anchor payload hex you verified
out-of-band (e.g. against the journal head). The signer compares the
transaction's OP_RETURN bytes to it exactly.

## Signing

```sh
aiguard signer sign --config ~/signer/signer.json --tx <unsigned tx hex>
# or: --tx-file <file holding the unsigned tx hex>
# or: --expected-payload <hex>  (overrides the config value for this signing)
```

The flow:

1. **Decode + hard rules, before any prompt.** The signer parses the
   unsigned tx with the project's existing transaction parser and
   checks every hard rule below. A violation is refused here — you are
   never asked for credentials for a bad transaction.
2. **Human review.** The decoded transaction is displayed: network,
   unsigned tx hash, inputs, every output, fee, and the decoded
   payload (head hash, sequence range, release sequence, previous
   anchor txid). Compare the previous anchor txid and sequence range
   against the last anchor you know of.
3. **Authenticate + approve.** Username, password (no echo), then the
   current TOTP code from your authenticator app. Authentication
   unlocks signing for this one transaction only. The approval is
   bound to the exact hash of the unsigned transaction — any byte
   change voids it, and the signer re-hashes and re-checks the rules
   immediately before signing.
4. **Sign.** The signer prints `SIGNED_TX_HEX=<hex>` and the signed
   txid. Hand the signed hex to the builder for broadcast.

## Hard rules (enforced by the signer, no override)

- Exactly 1 input, with an empty script_sig (unsigned).
- Exactly one OP_RETURN output, carrying the `AIGUARD1` payload, with
  zero value.
- OP_RETURN payload matches the expected payload byte-for-byte, and
  its `prev_txid` matches the expected previous anchor.
- The input spends the expected UTXO (txid + vout).
- Every non-data output pays to the configured anchor address
  (change returns home; any other destination is refused).
- Fee = input value − output values is ≥ 0 and ≤ the configured fee
  cap (default 2000 sats; set deliberately per network before first use).
- Network matches the config and the key (WIF version byte checked).

## What the human checks

The signer enforces the rules above in code, but the human is the
last check: read the review display. Refuse if you do not recognize
the input, the chain position, or the journal range; if the fee is
near the cap; or if the request arrives with time pressure. Refusal
is a normal outcome — there is no emergency override.

## Failure modes

- **Authentication failure** (wrong username, password, or TOTP):
  refused, recorded as `auth_failure`. The message does not say which
  factor failed.
- **Key file / config group- or world-readable**: refused. Fix with
  `chmod 0600` (but if the key was ever readable by others, treat it
  as compromised: rotate).
- **Key does not match the configured anchor address**: refused.
- **Mainnet**: refused unconditionally in this build. There is no
  mainnet key config; creating one is a separate witnessed step that
  happens only after the TTN proof passes and the mainnet gate is
  addressed on its own terms.
- **Human unavailable**: requests wait. Nothing signs without a human.

## Audit log

Every request, refusal, authentication failure, and signature is
appended as JSONL to the configured log file (`signer-audit.jsonl`
next to the config by default): timestamp, txid, decision, rule /
reason. No passwords, TOTP codes, or key material are ever logged.
A failed audit write fails the operation: a signed transaction must
not go unrecorded.

## Key storage honesty

The key file and config (which holds the TOTP secret) are protected
by `0600` file permissions, and the password gates *use* of the key.
The standard library has no vetted symmetric cipher, so this signer
deliberately does **not** hand-roll encryption for the key at rest —
at-rest protection relies on OS permissions plus full-disk encryption
on the signer's device. A vetted-library encryption layer is a future
upgrade. Until then, do not place the key file or config on a shared,
cloud-synced, or multi-user machine, and keep the signer on a device
the builder/AI cannot reach.
