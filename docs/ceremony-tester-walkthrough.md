# Try the signing ceremony yourself (Teratestnet)

This walkthrough takes you through the full anchor signing ceremony on your
own machine, end to end, with play money: build a journal, fund a testnet
address from the faucet, export an unsigned anchor transaction, run the
negative test (a tampered tx the signer must refuse), sign the real one with
your own password + authenticator app, broadcast it, and verify it on-chain.

You need: Python 3.10+, `git`, an authenticator app on your phone, and about
30 minutes. Everything runs on Teratestnet (TTN) — play money only. The
signer refuses mainnet unconditionally.

```sh
git clone https://github.com/RobGanon/bsv-ai-security.git
cd bsv-ai-security
python3 -m sealrun.cli --help   # sanity check: stdlib only, no install
```

## 1. Make a demo journal

The anchor commits to the head of a hash-chained audit journal. Make one:

```sh
python3 -m sealrun.cli audit-append --journal demo.jsonl --event-type note --detail "tester run 1"
python3 -m sealrun.cli audit-append --journal demo.jsonl --event-type note --detail "tester run 2"
python3 -m sealrun.cli audit-verify --journal demo.jsonl
# expect: AUDIT OK: 2 event(s)
```

Note the head hash it prints — you'll cross-check it later.

## 2. Create your signer identity

```sh
python3 -m sealrun.cli signer init --config signer-config.json --key-file signer-key.txt
```

It asks for a `Username:`, then a `Password:` (twice, hidden). Then it prints:

- `Anchor address (testnet): m...` — **save this.** It's your fresh testnet
  address. The key was generated on your machine and never leaves it.
- `TOTP secret (shown once): ...` — open your authenticator app, add a manual
  entry with this secret, name it "sealrun signer". It now shows 6-digit codes
  rotating every 30 seconds. You'll use one per signing.

Check the key file's permissions: `ls -l signer-key.txt` should show
`-rw-------` (only you can read it).

If you ever forget the username/password: the credentials only gate the
signer's use of the key — they don't encrypt it. Read the WIF out of
`signer-key.txt`, re-run `signer init` with new credentials, and point it at
the same key. If you lose `signer-key.txt` itself, whatever it controlled is
gone — same as losing any private key. Back it up somewhere safe.

## 3. Fund your address (play money)

The TTN faucet pays 100,000 sats per claim:

```sh
curl -s -X POST https://faucet-ttn.bsvblockchain.tech/api/claim \
  -H 'Content-Type: application/json' \
  -d '{"address":"YOUR_ADDRESS_FROM_STEP_2","network":"ttn"}'
```

It returns the payout txid. Note the txid and the vout that paid your address
(usually vout 0 or 1 — check the tx on the explorer, see step 8).

## 4. Export the unsigned anchor tx

The builder side never touches your key — export refuses to run if
`ANCHOR_WIF` is set:

```sh
python3 -m sealrun.cli publish \
  --journal demo.jsonl --anchor-record demo-anchors.json \
  --export-unsigned unsigned.hex \
  --funding-txid <faucet payout txid> --funding-vout <vout> \
  --change-address <your address> --fee-sats 500 \
  --mode once --network testnet
```

It prints the cross-checks: `unsigned_txid`, the payload (head hash, sequence
range, previous txid), fee, change address, funding outpoint. Confirm the head
hash matches the journal head from step 1.

## 5. Tell the signer what to expect

This binds your approval to exactly one transaction. Anything else gets
refused before any credential prompt:

```sh
python3 -m sealrun.cli signer expect --config signer-config.json \
  --prev-txid 0000000000000000000000000000000000000000000000000000000000000000 \
  --utxo-txid <faucet payout txid> --utxo-vout <vout> --utxo-value 100000 \
  --expected-payload <payload hex printed by the export>
```

(The prev-txid is all zeros here because this is your first anchor — a
genesis anchor. Later anchors chain to the previous anchor's txid.)

## 6. Negative test: tamper with the tx

Make a tampered copy — change any byte of the change output, or just flip one
hex character in the middle of `unsigned.hex`:

```sh
cp unsigned.hex tampered.hex
# edit tampered.hex: change one hex digit somewhere in the change-output region
python3 -m sealrun.cli signer sign --config signer-config.json \
  --tx-file tampered.hex --network testnet
```

Expected: `signer: refused: ...` **before** any username prompt, exit code 1.
The refusal is also written to the signer's JSONL audit log. Try other
tamperings: redirect the change address, raise the fee above your cap, swap the
payload. Each must refuse pre-authentication.

## 7. Sign the real one

```sh
python3 -m sealrun.cli signer sign --config signer-config.json \
  --tx-file unsigned.hex --network testnet
```

It prints the decoded transaction first. **Check it before approving:**
unsigned_txid matches the export, input is your faucet UTXO, outputs are the
OP_RETURN payload + change back to your address, fee is what you set.

Then: `Username:`, `Password:` (hidden), and the current 6-digit code from
your authenticator app. It prints `SIGNED_TX_HEX=...` — save that value to
`signed.hex`.

## 8. Broadcast and verify on-chain

```sh
python3 -m sealrun.cli publish \
  --journal demo.jsonl --anchor-record demo-anchors.json \
  --funding-txid <faucet payout txid> --funding-vout <vout> \
  --change-address <your address> --fee-sats 500 \
  --broadcast-signed signed.hex \
  --mode once --network testnet
```

The publisher rebuilds the expected unsigned tx itself and requires the
stripped signed tx to match it byte-for-byte, the script_sig in exact form,
and the signature to verify — all before broadcasting. Then verify
independently: go to `https://woc-ttn.bsvblockchain.tech`, tap the search
icon, paste your txid. (The site search only finds confirmed transactions;
TTN mining is intermittent, so it may take a while to appear. The broadcast
being accepted is the proof the network took it.)

## What to poke at

If you're here to test rather than just tour:

- The hard rules in `sealrun/signer_cli.py` (`check_hard_rules`) — every one
  is enforced before any credential prompt. Try to construct a tx that slips
  past one.
- `sealrun/publishing.py` `broadcast_signed` — the byte-equality gate between
  what the human approved and what gets broadcast.
- The files no outside reviewer has read yet: `spv.py`, `beef.py`, `cli.py`,
  `publishing.py`, `broadcast.py`.
- Open an issue with anything you find — including "I found nothing," with
  what you tried. That's useful data too.

## Don't

- Don't use a mainnet key anywhere near this flow. The signer refuses mainnet;
  keep it that way.
- Don't commit `signer-key.txt`, `signer-config.json`, or any journal with
  real data to a public repo. Keep them local — this walkthrough's PR adds
  the two signer files to `.gitignore`, but check `git status` before
  committing anything.
