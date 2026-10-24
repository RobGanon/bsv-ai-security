# STATUS — sealrun security fixes

Branch: `security-fixes-round2` (from `main` @ `61fb063`).
Base for "pre-fix" comparisons: `d78eda0` (the parent of PR #56).

**Legend.** *proven* = a regression test exists that **fails on the
pre-fix code** and passes here. *fixed, unproven* = the behaviour is
fixed but no test proves it. *open* = not fixed.

## Fixed and proven (fail-on-old-code regression test exists)

| Item | Fix | Test |
|---|---|---|
| **A1** | Injected record store: the publisher now re-derives the payload from the journal for **both** the `pending` and the `broadcast` branch of the dedupe path, and refuses to anchor on a store that disagrees with the journal | `tests/test_round2_regressions.py::test_a1_injected_pending_record_is_not_broadcast`, `::test_a1_injected_broadcast_record_is_not_reported_as_anchored` |
| **A2** | The broadcast txid is compared against the locally computed txid; a mismatch is refused | `::test_a2_broadcast_txid_must_match_the_locally_computed_one` |
| **A3** | The "already known" body heuristic now requires a 2xx status; a rejected broadcast is never recorded as a success (covered on 400 and 500, with and without the "already"/"258:" text) | `::test_a3_rejected_broadcast_is_never_treated_as_success[400]`, `[500]`, and `::test_a3_already_known_on_success_is_still_a_success` |
| **A4** | TOTP codes are single-use: the matched time-step is persisted and re-used codes are refused; the consume is guarded by an exclusive lock | `tests/test_signer_cli.py` — 11 tests (`test_totp_code_cannot_be_replayed`, `::test_concurrent_ceremonies_consume_a_code_only_once`, …) |
| **A5** | An acceptance is only recorded against a manifest whose signature verifies against a trusted key; the hash-only binding (which could never be verified) is refused | `::test_a5_acceptance_for_an_invalid_signature_manifest_is_refused`, `::test_a5_acceptance_bound_to_an_unverifiable_hash_is_refused` |
| **A6** | The launcher does not forward the caller's environment to the child (only `PATH` is carried over) | `::test_a6_launcher_does_not_forward_the_parent_environment`, `::test_a6_launcher_child_does_not_see_parent_secrets` |
| **A7** | `sealrun publish --broadcast` exits non-zero when the broadcast fails | `::test_a7_publish_broadcast_exits_non_zero_when_the_broadcast_fails` |
| **A10** | BEEF transactions: the txid is the hash of the raw bytes, and non-canonical CompactSize encodings are rejected | `tests/test_beef.py::test_parse_beef_rejects_noncanonical_varint`, `::test_parse_beef_rejects_txid_that_does_not_match_raw_bytes` |
| **N2** | The launcher carries `PATH` into the child, so a command found only on `PATH` still launches by name; the `launch()` docstring now describes this | `::test_n2_launch_finds_a_command_by_name_via_path`, `::test_n2_child_environment_carries_path_only` |
| **N3** | A non-ASCII-digit TOTP code fails closed instead of raising `TypeError` out of the CLI | `::test_n3_non_ascii_totp_code_fails_closed_without_raising`, `::test_n3_non_ascii_totp_code_does_not_escape_as_an_exception` |
| **N4** | The BUMP varint reader rejects non-canonical CompactSize, consistent with the transaction and envelope readers | `::test_n4_bump_rejects_noncanonical_varint` (3 cases), `::test_n4_beef_envelope_with_a_noncanonical_bump_is_rejected` |

## Fixed without a test (documentation only — no behaviour to regress)

| Item | Change |
|---|---|
| **N1** | `docs/signer-cli.md` now discloses that the TOTP state file is **unauthenticated**: deleting *or forging* `last_used_step` resets single-use, and states the threat-model bound (write access to the signer directory suffices; read access to the key is still worse). No HMAC is implemented in this round. |
| **N5** | The inline deliberation left in `sealrun/cli.py` (the "should we require the public key?" commentary) is gone; the code states the rule. |
| **N6** | `docs/using-sealrun.md` and `docs/phase2-implementation.md` now show `audit-manifest-accepted` with `--public-key`, matching the CLI. The end-user guide previously failed at the first anchor. |

## Round 3 — A1 residual + A9 (branch `a1-predecessor-verification`)

| Item | Fix | Test |
|---|---|---|
| **A1 residual** | `create_anchor_payload` takes an explicit `end_seq` (historical re-derivation), and the publisher re-derives **every** broadcast record from the journal, in chain order, before acting on the store (`_verify_broadcast_chain`). The store loader's continuity checks (issue #8) never bound records to the journal; now a store that is internally consistent yet journal-false is refused | `tests/test_round2_regressions.py::test_a1r_*` (6 tests; the tip-payload and transplanted-store cases fail on the pre-fix code, the rest are layered coverage) |
| **A9** | `signer sign --expected-payload` requires `--override-expected` as an explicit acknowledgment; unacknowledged overrides refuse before any prompt | `tests/test_signer_cli.py::test_expected_payload_override_requires_the_flag`, `::test_main_return_codes` |
| **A8** | Accepted, no code: the rationale is written into REVIEW.md's known limitations (signer config integrity is part of the signer-host trust domain) | — |

## Known residual (identified in round 2, not yet fixed)
- **`audit-append --event-type manifest_accepted` still writes an
  acceptance with no verification at all** (issue #11, the operator's
  journal write access is trusted by design). The CLI's
  `audit-manifest-accepted` now verifies, but the generic append path
  does not. A chain-preserving repair path for already-poisoned
  journals is still not implemented.

## Still open (from the 2026-10-21 independent review)

A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22,
A23, A24, A25, A26 (see N3 — the TOTP half is fixed; the timing/lockout
half is not), A27, A28, A29, A30, A31, A32, A33, A34, A35, A36, A37.
(A8 accepted with a written rationale and A9 fixed in round 3 — see
the round-3 table above.)
