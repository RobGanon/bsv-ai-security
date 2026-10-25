"""Tests for the offline anchor signer CLI (sealrun/signer_cli.py).

Test-first: these tests were written before the implementation. All
key material here is freshly generated throwaway keys; no real key
material, no network, no mainnet.
"""

import base64
import hashlib
import hmac
import json
import os
import stat

import pytest

from sealrun.anchor import decode_anchor_payload, encode_anchor_payload
from sealrun.bsv import (
    SIGHASH_ALL_FORKID,
    PrivKey,
    Tx,
    TxIn,
    TxOut,
    build_op_return_script,
    build_p2pkh_script_for_address,
    parse_tx,
    sighash_forkid,
    verify_sig,
)
from sealrun.signer_cli import (
    AUTH_FAILURES_FILENAME,
    Refusal,
    SignerError,
    _authenticate,
    _read_failure_count,
    backoff_delay_for_failures,
    check_hard_rules,
    format_review,
    hash_password,
    init_signer,
    load_config,
    main,
    run_sign,
    set_expectation,
    sign_approved_tx,
    sign_flow,
    totp_code,
    totp_verify,
    verify_password,
)

# RFC 6238 Appendix B: secret is the ASCII string "12345678901234567890".
RFC_SECRET_ASCII = b"12345678901234567890"
RFC_SECRET_B32 = base64.b32encode(RFC_SECRET_ASCII).decode("ascii")
# (timestamp, 8-digit TOTP) from the published RFC 6238 SHA-1 vectors.
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]

PASSWORD = "correct horse battery staple"
FIXED_TIME = 59
PREV_TXID = "11" * 32
UTXO_VALUE = 99_500
FEE = 500


def _exploding(*args, **kwargs):
    raise AssertionError("prompted for credentials during a pre-approval refusal")


@pytest.fixture
def env(tmp_path):
    """A valid signer setup: throwaway key, config, expected UTXO/payload."""
    key = PrivKey.generate()
    addr = key.address("testnet")
    payload = encode_anchor_payload(
        head_hash="ab" * 32,
        start_seq=5,
        end_seq=5,
        release_seq=0,
        prev_txid=PREV_TXID,
    )
    key_path = tmp_path / "anchor-key.txt"
    key_path.write_text(key.wif("testnet"), encoding="ascii")
    os.chmod(key_path, 0o600)
    config = {
        "version": 1,
        "network": "testnet",
        "username": "operator",
        "anchor_address": addr,
        "key_file": "anchor-key.txt",
        "log_file": "audit.jsonl",
        "fee_cap_sats": 2000,
        "expected_prev_txid": PREV_TXID,
        "expected_utxo": {"txid": PREV_TXID, "vout": 1, "value": UTXO_VALUE},
        "expected_payload_hex": payload.hex(),
        "password": hash_password(PASSWORD),
        "totp": {"secret": RFC_SECRET_B32, "digits": 6},
    }
    config_path = tmp_path / "signer.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(config_path, 0o600)
    return {
        "dir": tmp_path,
        "key": key,
        "addr": addr,
        "payload": payload,
        "config_path": config_path,
        "key_path": key_path,
        "config": config,
    }


def _unsigned_tx(env, *, payload=None, change_value=UTXO_VALUE - FEE,
                 change_addr=None, prev_txid=PREV_TXID, vout=1,
                 n_inputs=1, script_sig=b"", extra_outputs=()):
    payload = env["payload"] if payload is None else payload
    change_addr = env["addr"] if change_addr is None else change_addr
    outputs = [TxOut(0, build_op_return_script(payload))]
    if change_value is not None:
        outputs.append(
            TxOut(change_value, build_p2pkh_script_for_address(change_addr, "testnet"))
        )
    outputs.extend(extra_outputs)
    inputs = [TxIn(prev_txid, vout, script_sig=script_sig)]
    for _ in range(n_inputs - 1):
        inputs.append(TxIn("22" * 32, 0))
    return Tx(inputs=inputs, outputs=outputs)


def _auth_fns(env, *, password=PASSWORD, totp_time=FIXED_TIME, username="operator"):
    code = totp_code(env["config"]["totp"]["secret"], totp_time, digits=6)

    def input_fn(prompt):
        if "Username" in prompt:
            return username
        if "TOTP" in prompt or "code" in prompt:
            return code
        raise AssertionError(f"unexpected prompt: {prompt!r}")

    def getpass_fn(prompt):
        return password

    return input_fn, getpass_fn


def _log_entries(env):
    log_path = env["dir"] / "audit.jsonl"
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]


# --- TOTP: RFC 6238 vectors ------------------------------------------------


@pytest.mark.parametrize("timestamp,expected", RFC_VECTORS)
def test_totp_rfc6238_vectors_8_digit(timestamp, expected):
    assert totp_code(RFC_SECRET_B32, timestamp, digits=8) == expected


@pytest.mark.parametrize("timestamp,expected8", RFC_VECTORS)
def test_totp_rfc6238_vectors_6_digit(timestamp, expected8):
    # 6-digit codes are the same dynamic truncation modulo 10**6.
    assert totp_code(RFC_SECRET_B32, timestamp, digits=6) == expected8[-6:]


def test_totp_verify_window():
    code_now = totp_code(RFC_SECRET_B32, FIXED_TIME, digits=6)
    assert totp_verify(RFC_SECRET_B32, code_now, FIXED_TIME, digits=6)
    # One step either side is accepted.
    assert totp_verify(RFC_SECRET_B32, totp_code(RFC_SECRET_B32, FIXED_TIME - 30, digits=6),
                       FIXED_TIME, digits=6)
    assert totp_verify(RFC_SECRET_B32, totp_code(RFC_SECRET_B32, FIXED_TIME + 30, digits=6),
                       FIXED_TIME, digits=6)
    # Two steps out is rejected.
    assert not totp_verify(RFC_SECRET_B32, totp_code(RFC_SECRET_B32, FIXED_TIME + 60, digits=6),
                           FIXED_TIME, digits=6)
    assert not totp_verify(RFC_SECRET_B32, "000000", FIXED_TIME, digits=6)


def test_totp_wrong_secret_rejected():
    other = base64.b32encode(b"AAAAAAAAAAAAAAAAAAAA").decode("ascii")
    code = totp_code(RFC_SECRET_B32, FIXED_TIME, digits=6)
    assert not totp_verify(other, code, FIXED_TIME, digits=6)


# --- password hashing ------------------------------------------------------


def test_password_roundtrip_and_wrong_password():
    record = hash_password(PASSWORD)
    assert verify_password(PASSWORD, record)
    assert not verify_password("wrong password", record)
    assert record["iterations"] >= 100_000
    assert record["salt"] != record["hash"]


def test_password_record_is_not_plaintext():
    record = hash_password(PASSWORD)
    assert PASSWORD.encode() not in json.dumps(record).encode()


# --- private file loading: one descriptor, no stat-then-read window --------


def test_load_config_refuses_symlink(env):
    """Regression (outside review, 2026-10-20): the config path is opened
    once with O_NOFOLLOW and fstat()d on that descriptor, so a symlink
    in place of the config is refused rather than checked-then-read."""
    link = env["dir"] / "linked-config.json"
    link.symlink_to(env["config_path"])
    with pytest.raises(SignerError):
        load_config(link)


def test_config_totp_digits_bool_refused(env):
    """Regression (A33): JSON true passed the int check as 1, silently
    weakening TOTP to 1 digit. Both booleans are refused; 6 is accepted."""
    for bad in (True, False):
        config = dict(env["config"])
        config["totp"] = {"secret": RFC_SECRET_B32, "digits": bad}
        path = env["dir"] / "signer-bad-digits.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        os.chmod(path, 0o600)
        with pytest.raises(SignerError, match="digits"):
            load_config(path)
    config = dict(env["config"])
    config["totp"] = {"secret": RFC_SECRET_B32, "digits": 6}
    path = env["dir"] / "signer-good-digits.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    os.chmod(path, 0o600)
    assert load_config(path)["totp"]["digits"] == 6


def test_totp_code_digits_bool_refused():
    """Regression (A33, defense in depth): totp_code rejects bool digits."""
    for bad in (True, False):
        with pytest.raises(SignerError, match="digits"):
            totp_code(RFC_SECRET_B32, FIXED_TIME, digits=bad)
    assert len(totp_code(RFC_SECRET_B32, FIXED_TIME, digits=6)) == 6


def test_load_signer_key_refuses_symlink(env):
    from sealrun.signer_cli import load_signer_key

    config = load_config(env["config_path"])
    link = env["dir"] / "linked-key.txt"
    link.symlink_to(env["key_path"])
    config["key_file"] = "linked-key.txt"
    with pytest.raises(SignerError):
        load_signer_key(config, env["dir"])


# --- hard rules: refused pre-approval, before any credential prompt --------


def test_change_to_wrong_address_refused_before_prompt(env):
    other = PrivKey.generate().address("testnet")
    tx = _unsigned_tx(env, change_addr=other)
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule == "change_address"


def test_bad_op_return_magic_refused(env):
    bad_payload = b"BADMAGIC" + env["payload"][8:]
    tx = _unsigned_tx(env, payload=bad_payload)
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=bad_payload.hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule == "payload_format"


def test_payload_mismatch_refused(env):
    other_payload = encode_anchor_payload(
        head_hash="cd" * 32, start_seq=5, end_seq=5, release_seq=0, prev_txid=PREV_TXID)
    tx = _unsigned_tx(env, payload=other_payload)
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule == "payload_match"


def test_payload_prev_txid_mismatch_refused(env):
    payload = encode_anchor_payload(
        head_hash="ab" * 32, start_seq=5, end_seq=5, release_seq=0, prev_txid="22" * 32)
    tx = _unsigned_tx(env, payload=payload)
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=payload.hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule == "prev_txid"


def test_fee_over_cap_refused(env):
    tx = _unsigned_tx(env, change_value=UTXO_VALUE - 5000)
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule == "fee_cap"


def test_negative_fee_refused(env):
    tx = _unsigned_tx(env, change_value=UTXO_VALUE + 1)
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule == "fee"


def test_wrong_utxo_refused(env):
    tx = _unsigned_tx(env, prev_txid="33" * 32)
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule == "utxo"


def test_multi_input_refused(env):
    tx = _unsigned_tx(env, n_inputs=2)
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule == "inputs"


def test_presigned_input_refused(env):
    tx = _unsigned_tx(env, script_sig=b"\x01\x02")
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule == "unsigned"


def test_extra_output_refused(env):
    other = PrivKey.generate().address("testnet")
    extra = TxOut(100, build_p2pkh_script_for_address(other, "testnet"))
    tx = _unsigned_tx(env, extra_outputs=(extra,))
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule in ("change_address", "outputs")


def test_missing_expected_payload_refused(env):
    env["config"]["expected_payload_hex"] = None
    env["config_path"].write_text(json.dumps(env["config"]), encoding="utf-8")
    tx = _unsigned_tx(env)
    with pytest.raises(Refusal) as exc:
        sign_flow(env["config_path"], tx.serialize().hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert exc.value.rule == "expected_payload"


def test_garbage_tx_refused(env):
    with pytest.raises((Refusal, SignerError)):
        sign_flow(env["config_path"], "00ff",
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)


# --- authentication --------------------------------------------------------


def test_wrong_password_rejected(env):
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env, password="wrong password")
    with pytest.raises(SignerError, match="authentication failed"):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=input_fn, getpass_fn=getpass_fn,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert _log_entries(env)[-1]["decision"] == "auth_failure"


def test_wrong_username_rejected(env):
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env, username="mallory")
    with pytest.raises(SignerError, match="authentication failed"):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=input_fn, getpass_fn=getpass_fn,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)


def test_wrong_totp_rejected(env):
    tx = _unsigned_tx(env)

    def input_fn(prompt):
        if "Username" in prompt:
            return "operator"
        return "000000"

    with pytest.raises(SignerError, match="authentication failed"):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=input_fn, getpass_fn=lambda p: PASSWORD,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)


# --- TOTP single use (A4) ---------------------------------------------------
#
# A TOTP code is valid for a whole 30-second step, so a stateless
# check lets one observed code authorize an unbounded number of
# signatures. The signer must consume the step: one code, one
# signature.


def test_totp_code_cannot_be_replayed(env):
    """A4 regression: the same TOTP code must not authorize a second
    signature.

    On the unfixed code both ceremonies succeed — the code is valid
    for the whole step, and nothing records that it was already used.
    """
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)

    first = sign_flow(env["config_path"], tx.serialize().hex(),
                      expected_payload_hex=env["payload"].hex(),
                      input_fn=input_fn, getpass_fn=getpass_fn,
                      output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert first

    # The very same code, presented again in the same time step.
    replay_fn, replay_getpass = _auth_fns(env)
    with pytest.raises(SignerError, match="authentication failed"):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=replay_fn, getpass_fn=replay_getpass,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)


def test_totp_code_cannot_be_replayed_for_a_different_transaction(env):
    """A4 regression: a replayed code must not sign a *different*
    transaction either — the code is consumed, not the transaction."""
    first_tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)
    sign_flow(env["config_path"], first_tx.serialize().hex(),
              expected_payload_hex=env["payload"].hex(),
              input_fn=input_fn, getpass_fn=getpass_fn,
              output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)

    # A different (but equally valid) transaction, same code.
    other_tx = _unsigned_tx(env, change_value=UTXO_VALUE - FEE - 1)
    replay_fn, replay_getpass = _auth_fns(env)
    with pytest.raises(SignerError, match="authentication failed"):
        sign_flow(env["config_path"], other_tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=replay_fn, getpass_fn=replay_getpass,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)


def test_totp_step_is_consumed_across_skew_window(env):
    """A4 regression: the skew window must not reopen a consumed step.

    ``_auth_fns`` builds a code for the current step. A code from the
    *previous* step is also inside the accepted +-1 step window, so it
    is a valid code — but it must be refused once the current step has
    been consumed, because accepting it would let a shoulder-surfed
    code authorize a second signature.
    """
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)
    sign_flow(env["config_path"], tx.serialize().hex(),
              expected_payload_hex=env["payload"].hex(),
              input_fn=input_fn, getpass_fn=getpass_fn,
              output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)

    # The previous step's code, presented at the same timestamp. It is
    # within the skew window, so a stateless check accepts it.
    stale = totp_code(env["config"]["totp"]["secret"], FIXED_TIME - 30, digits=6)
    assert totp_verify(env["config"]["totp"]["secret"], stale, FIXED_TIME, digits=6)

    def stale_input_fn(prompt):
        if "Username" in prompt:
            return "operator"
        return stale

    with pytest.raises(SignerError, match="authentication failed"):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=stale_input_fn, getpass_fn=lambda p: PASSWORD,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)


def test_totp_state_file_records_the_consumed_step(env):
    """The consumed time-step is persisted, so a second signer process
    (or a later invocation) sees that the code was already used."""
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)
    sign_flow(env["config_path"], tx.serialize().hex(),
              expected_payload_hex=env["payload"].hex(),
              input_fn=input_fn, getpass_fn=getpass_fn,
              output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)

    state_path = env["dir"] / "totp-state.json"
    assert state_path.exists()
    state = json.loads(state_path.read_text())
    assert state["last_used_step"] == FIXED_TIME // 30
    # The state file holds no secret material.
    assert "secret" not in state_path.read_text()


def test_totp_state_file_is_private(env):
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)
    sign_flow(env["config_path"], tx.serialize().hex(),
              expected_payload_hex=env["payload"].hex(),
              input_fn=input_fn, getpass_fn=getpass_fn,
              output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    mode = stat.S_IMODE(os.stat(env["dir"] / "totp-state.json").st_mode)
    assert mode == 0o600


def test_totp_replay_is_recorded_in_the_audit_log(env):
    """A replay attempt is worth seeing in the audit log, unlike the
    other factor failures whose cause is deliberately not disclosed."""
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)
    sign_flow(env["config_path"], tx.serialize().hex(),
              expected_payload_hex=env["payload"].hex(),
              input_fn=input_fn, getpass_fn=getpass_fn,
              output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)

    replay_fn, replay_getpass = _auth_fns(env)
    with pytest.raises(SignerError, match="authentication failed"):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=replay_fn, getpass_fn=replay_getpass,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)

    reasons = [e.get("reason", "") for e in _log_entries(env)]
    assert any("replay" in r for r in reasons)


def test_broken_symlink_totp_state_fails_closed(env):
    """A broken symlink at the state path must not read as "no state
    yet": that would silently reset single-use protection. The signer
    refuses instead."""
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)
    sign_flow(env["config_path"], tx.serialize().hex(),
              expected_payload_hex=env["payload"].hex(),
              input_fn=input_fn, getpass_fn=getpass_fn,
              output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)

    state_path = env["dir"] / "totp-state.json"
    state_path.unlink()
    state_path.symlink_to(env["dir"] / "does-not-exist")

    replay_fn, replay_getpass = _auth_fns(env)
    with pytest.raises(SignerError):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=replay_fn, getpass_fn=replay_getpass,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)


def test_corrupt_totp_state_fails_closed(env):
    """A corrupt state file must not silently re-enable a used code:
    the signer refuses rather than guessing."""
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)
    sign_flow(env["config_path"], tx.serialize().hex(),
              expected_payload_hex=env["payload"].hex(),
              input_fn=input_fn, getpass_fn=getpass_fn,
              output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)

    (env["dir"] / "totp-state.json").write_text("{not json", encoding="utf-8")
    os.chmod(env["dir"] / "totp-state.json", 0o600)

    replay_fn, replay_getpass = _auth_fns(env)
    with pytest.raises(SignerError):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=replay_fn, getpass_fn=replay_getpass,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)


def test_fresh_signer_with_no_state_file_can_still_sign(env):
    """A signer that has never signed has no state file: the first
    ceremony must work (the state is created, not required)."""
    tx = _unsigned_tx(env)
    assert not (env["dir"] / "totp-state.json").exists()
    input_fn, getpass_fn = _auth_fns(env)
    signed = sign_flow(env["config_path"], tx.serialize().hex(),
                       expected_payload_hex=env["payload"].hex(),
                       input_fn=input_fn, getpass_fn=getpass_fn,
                       output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    assert signed
    assert (env["dir"] / "totp-state.json").exists()


def test_new_code_in_a_later_step_is_accepted(env):
    """Single use must not break the normal flow: the next step's
    code authorizes the next signature."""
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)
    sign_flow(env["config_path"], tx.serialize().hex(),
              expected_payload_hex=env["payload"].hex(),
              input_fn=input_fn, getpass_fn=getpass_fn,
              output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)

    next_input, next_getpass = _auth_fns(env, totp_time=FIXED_TIME + 30)
    signed = sign_flow(env["config_path"], tx.serialize().hex(),
                       expected_payload_hex=env["payload"].hex(),
                       input_fn=next_input, getpass_fn=next_getpass,
                       output_fn=lambda s: None, time_fn=lambda: FIXED_TIME + 30)
    assert signed


def test_concurrent_ceremonies_consume_a_code_only_once(env):
    """A4 regression: the check-and-consume sequence is atomic, so two
    ceremonies racing on the same code produce exactly one signature.

    Without the lock, both would read the same (unused) state and both
    would sign.
    """
    import threading

    tx = _unsigned_tx(env)
    code = totp_code(env["config"]["totp"]["secret"], FIXED_TIME, digits=6)
    results = []
    barrier = threading.Barrier(8)

    def input_fn(prompt):
        if "Username" in prompt:
            return "operator"
        return code

    def worker():
        barrier.wait()
        try:
            sign_flow(env["config_path"], tx.serialize().hex(),
                      expected_payload_hex=env["payload"].hex(),
                      input_fn=input_fn, getpass_fn=lambda p: PASSWORD,
                      output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
            results.append("signed")
        except SignerError:
            results.append("refused")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("signed") == 1


# --- approval binding ------------------------------------------------------


def test_modified_tx_after_approval_refuses(env):
    tx = _unsigned_tx(env)
    approved = tx.txid()
    tx.outputs[1].value += 1  # mutate after approval
    with pytest.raises(Refusal) as exc:
        sign_approved_tx(tx, approved, env["config"], env["key"])
    assert exc.value.rule == "approval_binding"


def test_wrong_approved_hash_refuses(env):
    tx = _unsigned_tx(env)
    with pytest.raises(Refusal) as exc:
        sign_approved_tx(tx, "00" * 32, env["config"], env["key"])
    assert exc.value.rule == "approval_binding"


# --- happy path ------------------------------------------------------------


def test_happy_path_signs_and_signature_verifies(env):
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)
    shown = []
    signed_hex = sign_flow(env["config_path"], tx.serialize().hex(),
                           expected_payload_hex=env["payload"].hex(),
                           input_fn=input_fn, getpass_fn=getpass_fn,
                           output_fn=shown.append, time_fn=lambda: FIXED_TIME)
    signed = parse_tx(bytes.fromhex(signed_hex))
    assert signed.inputs[0].script_sig
    # ScriptSig is push(DER + sighash byte) + push(pubkey).
    sig_push_len = signed.inputs[0].script_sig[0]
    der_plus_flag = signed.inputs[0].script_sig[1:1 + sig_push_len]
    assert der_plus_flag[-1] == SIGHASH_ALL_FORKID
    pubkey_len = signed.inputs[0].script_sig[1 + sig_push_len]
    pubkey = signed.inputs[0].script_sig[2 + sig_push_len:2 + sig_push_len + pubkey_len]
    assert pubkey == env["key"].pubkey_compressed()
    prev_script = build_p2pkh_script_for_address(env["addr"], "testnet")
    digest = sighash_forkid(signed, 0, prev_script, UTXO_VALUE)
    assert verify_sig(pubkey, digest, der_plus_flag[:-1])
    # The signed tx differs from the unsigned one (script_sig added).
    assert signed.txid() != tx.txid()
    # Review display was shown and names the network + fee.
    display = "\n".join(shown)
    assert "testnet" in display
    assert "500" in display
    # Log records request + signed result.
    decisions = [e["decision"] for e in _log_entries(env)]
    assert "request" in decisions
    assert "signed" in decisions


def test_refusal_is_logged(env):
    other = PrivKey.generate().address("testnet")
    tx = _unsigned_tx(env, change_addr=other)
    with pytest.raises(Refusal):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)
    entries = _log_entries(env)
    assert entries[-1]["decision"] == "refusal"
    assert entries[-1]["rule"] == "change_address"
    assert "password" not in json.dumps(entries).lower()
    assert "totp" not in json.dumps(entries).lower()


def test_review_display_shows_decoded_payload(env):
    tx = _unsigned_tx(env)
    info = check_hard_rules(tx, env["config"], env["payload"].hex())
    display = format_review(tx, info, env["config"])
    decoded = decode_anchor_payload(env["payload"])
    assert decoded["head_hash"] in display
    assert str(decoded["start_seq"]) in display
    assert decoded["prev_txid"] in display
    assert env["addr"] in display


# --- file permissions ------------------------------------------------------


def test_group_readable_key_file_refused(env):
    os.chmod(env["key_path"], 0o640)
    tx = _unsigned_tx(env)
    input_fn, getpass_fn = _auth_fns(env)
    with pytest.raises(SignerError, match="must not be group- or world-readable"):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=input_fn, getpass_fn=getpass_fn,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)


def test_group_readable_config_refused(env):
    os.chmod(env["config_path"], 0o644)
    with pytest.raises(SignerError, match="must not be group- or world-readable"):
        load_config(env["config_path"])


def test_group_readable_totp_config_refused(env):
    # The TOTP secret lives in the config file, so the config file gets
    # the same permission treatment as the key file.
    os.chmod(env["config_path"], 0o604)
    with pytest.raises(SignerError, match="must not be group- or world-readable"):
        load_config(env["config_path"])


# --- mainnet -----------------------------------------------------------------


def test_mainnet_config_refused_at_sign(env):
    env["config"]["network"] = "mainnet"
    env["config_path"].write_text(json.dumps(env["config"]), encoding="utf-8")
    tx = _unsigned_tx(env)
    with pytest.raises(SignerError, match="mainnet"):
        sign_flow(env["config_path"], tx.serialize().hex(),
                  expected_payload_hex=env["payload"].hex(),
                  input_fn=_exploding, getpass_fn=_exploding,
                  output_fn=lambda s: None, time_fn=lambda: FIXED_TIME)


def test_main_return_codes(env, monkeypatch, capsys):
    import time as _time

    tx = _unsigned_tx(env)
    # main() uses real wall-clock time, so the TOTP code must be for now.
    input_fn, getpass_fn = _auth_fns(env, totp_time=_time.time())
    monkeypatch.setattr("builtins.input", input_fn)
    monkeypatch.setattr("getpass.getpass", getpass_fn)
    rc = main(["sign", "--config", str(env["config_path"]),
               "--tx", tx.serialize().hex(),
               "--expected-payload", env["payload"].hex(),
               "--override-expected"])
    assert rc == 0
    rc = main(["sign", "--config", str(env["config_path"]),
               "--tx", tx.serialize().hex(),
               "--expected-payload", env["payload"].hex(),
               "--override-expected",
               "--network", "mainnet"])
    assert rc == 1


# --- init / expect -----------------------------------------------------------


def test_init_creates_config_and_key_0600(tmp_path, monkeypatch):
    config_path = tmp_path / "signer.json"
    key_path = tmp_path / "key.txt"
    inputs = iter(["operator", "newtotp"])

    def input_fn(prompt):
        return next(inputs)

    passwords = iter([PASSWORD, PASSWORD])

    def getpass_fn(prompt):
        return next(passwords)

    init_signer(config_path, key_path, input_fn=input_fn, getpass_fn=getpass_fn,
                output_fn=lambda s: None)
    assert oct(stat.S_IMODE(os.stat(config_path).st_mode)) == "0o600"
    assert oct(stat.S_IMODE(os.stat(key_path).st_mode)) == "0o600"
    cfg = load_config(config_path)
    assert cfg["network"] == "testnet"
    assert cfg["anchor_address"]
    assert cfg["totp"]["secret"]
    assert verify_password(PASSWORD, cfg["password"])
    # The generated key matches the config address.
    assert PrivKey.from_wif(key_path.read_text().strip(), "testnet").address("testnet") == cfg["anchor_address"]


def test_init_refuses_existing_config(env):
    with pytest.raises(SignerError, match="already exists"):
        init_signer(env["config_path"], env["key_path"],
                    input_fn=lambda p: "x", getpass_fn=lambda p: "y",
                    output_fn=lambda s: None)


def test_init_password_mismatch_refused(tmp_path):
    config_path = tmp_path / "signer.json"
    key_path = tmp_path / "key.txt"
    passwords = iter([PASSWORD, "different"])

    with pytest.raises(SignerError, match="do not match"):
        init_signer(config_path, key_path,
                    input_fn=lambda p: "operator",
                    getpass_fn=lambda p: next(passwords),
                    output_fn=lambda s: None)
    assert not config_path.exists()
    assert not key_path.exists()


def test_set_expectation_updates_config(env):
    new_payload = encode_anchor_payload(
        head_hash="cd" * 32, start_seq=6, end_seq=6, release_seq=0, prev_txid="44" * 32)
    set_expectation(env["config_path"], prev_txid="44" * 32,
                    utxo_txid="44" * 32, utxo_vout=1, utxo_value=98_000,
                    expected_payload_hex=new_payload.hex())
    cfg = load_config(env["config_path"])
    assert cfg["expected_prev_txid"] == "44" * 32
    assert cfg["expected_utxo"] == {"txid": "44" * 32, "vout": 1, "value": 98_000}
    assert cfg["expected_payload_hex"] == new_payload.hex()


def test_set_expectation_rejects_bad_hex(env):
    with pytest.raises(SignerError):
        set_expectation(env["config_path"], prev_txid="not-hex",
                        utxo_txid="44" * 32, utxo_vout=1, utxo_value=98_000)


# --- no network in this module ------------------------------------------------


def test_signer_module_has_no_network_access():
    import pathlib
    import re

    source = pathlib.Path(__file__).parent.parent.joinpath("sealrun", "signer_cli.py").read_text()
    # Match import statements, not prose (the word "requests" is legitimate
    # in "signing requests").
    for match in re.finditer(r"^\s*(?:import|from)\s+([a-zA-Z0-9_.]+)", source, re.M):
        module = match.group(1)
        assert module.split(".")[0] not in (
            "urllib", "socket", "requests", "http", "httpx", "aiohttp",
        ), f"signer_cli must not import {module}"


def test_expected_payload_override_requires_the_flag(env, capsys):
    """A9: --expected-payload silently overrode the recorded
    expectation. It now requires --override-expected as an explicit
    acknowledgment; without it the sign command refuses before any
    prompt or signing attempt."""
    tx = _unsigned_tx(env)
    rc = main(["sign", "--config", str(env["config_path"]),
               "--tx", tx.serialize().hex(),
               "--expected-payload", env["payload"].hex()])
    assert rc == 1
    assert "--override-expected" in capsys.readouterr().err


# --- A26: failed-attempt backoff ----------------------------------------------
#
# All backoff tests inject a recording sleep_fn, so no test ever waits
# a real delay: the delay is asserted, never slept. A fresh env has no
# counter file (count 0); failures are wrong-password unless stated.


def _counter_path(env):
    return env["dir"] / AUTH_FAILURES_FILENAME


def _counter_value(env):
    return json.loads(_counter_path(env).read_text())["consecutive_failures"]


def _try_auth(env, *, password=PASSWORD, username="operator",
              code=None, sleeps=None):
    """One _authenticate call; returns (ok, sleeps recorded)."""
    if sleeps is None:
        sleeps = []
    if code is None:
        input_fn, getpass_fn = _auth_fns(env, password=password, username=username)
    else:
        def input_fn(prompt):
            if "Username" in prompt:
                return username
            if "TOTP" in prompt or "code" in prompt:
                return code
            raise AssertionError(f"unexpected prompt: {prompt!r}")

        def getpass_fn(prompt):
            return password

    ok = _authenticate(env["config"], input_fn=input_fn, getpass_fn=getpass_fn,
                       time_fn=lambda: FIXED_TIME, sleep_fn=sleeps.append,
                       config_dir=env["dir"])
    return ok, sleeps


def test_a26_backoff_schedule():
    assert backoff_delay_for_failures(0) == 0
    assert backoff_delay_for_failures(4) == 0
    assert backoff_delay_for_failures(5) == 30
    assert backoff_delay_for_failures(6) == 60
    assert backoff_delay_for_failures(7) == 120
    assert backoff_delay_for_failures(8) == 240
    assert backoff_delay_for_failures(9) == 300
    assert backoff_delay_for_failures(10) == 300
    assert backoff_delay_for_failures(100) == 300
    assert backoff_delay_for_failures(1000) == 300


def test_a26_five_failures_then_backoff_enforced(env):
    sleeps = []
    for _ in range(4):
        ok, sleeps = _try_auth(env, password="wrong password", sleeps=sleeps)
        assert not ok
    assert sleeps == []  # first four failures are free
    assert _counter_value(env) == 4
    ok, sleeps = _try_auth(env, password="wrong password", sleeps=sleeps)
    assert not ok
    assert sleeps == [30]  # 5th failure sleeps 30s (mocked, not waited)
    assert _counter_value(env) == 5
    ok, sleeps = _try_auth(env, password="wrong password", sleeps=sleeps)
    assert not ok
    assert sleeps == [30, 60]  # 6th failure doubles to 60s
    # Continuing through the real increment path reaches the cap.
    for _ in range(3):
        ok, sleeps = _try_auth(env, password="wrong password", sleeps=sleeps)
        assert not ok
    assert sleeps == [30, 60, 120, 240, 300]
    assert _counter_value(env) == 9


def test_a26_wrong_totp_failures_also_count(env):
    # Failure means ANY factor: correct password, wrong TOTP code.
    # "000000" is not the valid code at FIXED_TIME (valid is 287082).
    sleeps = []
    for _ in range(5):
        ok, sleeps = _try_auth(env, code="000000", sleeps=sleeps)
        assert not ok
    assert sleeps == [30]
    assert _counter_value(env) == 5


def test_a26_counter_resets_on_success(env):
    sleeps = []
    for _ in range(3):
        ok, sleeps = _try_auth(env, password="wrong password", sleeps=sleeps)
        assert not ok
    assert _counter_value(env) == 3
    ok, sleeps = _try_auth(env, sleeps=sleeps)  # correct credentials
    assert ok
    assert sleeps == []  # success never sleeps
    assert _counter_value(env) == 0
    # The next failure restarts from 1, with no backoff.
    ok, sleeps = _try_auth(env, password="wrong password", sleeps=sleeps)
    assert not ok
    assert sleeps == []
    assert _counter_value(env) == 1


def test_a26_never_permanent_after_many_failures(env):
    # The counter is seeded directly to 100 instead of performing 100
    # real failed authentications (each would pay a PBKDF2 password
    # verification; the increment path itself is covered by the tests
    # above). The seeded state is exactly what 100 failures produce.
    _counter_path(env).write_text(
        json.dumps({"consecutive_failures": 100}), encoding="utf-8")
    os.chmod(_counter_path(env), 0o600)
    assert _read_failure_count(env["dir"]) == 100
    assert backoff_delay_for_failures(100) == 300  # capped, never grows
    # A correct attempt still succeeds immediately (no sleep on success)
    # and resets the counter — no lockout window exists to expire.
    sleeps = []
    ok, sleeps = _try_auth(env, sleeps=sleeps)
    assert ok
    assert sleeps == []
    assert _counter_value(env) == 0


def test_a26_counter_file_is_private_and_persists_across_calls(env):
    sleeps = []
    ok, sleeps = _try_auth(env, password="wrong password", sleeps=sleeps)
    assert not ok
    path = _counter_path(env)
    assert path.exists()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert _counter_value(env) == 1
    # A second, separate call reads the persisted count (not memory).
    ok, sleeps = _try_auth(env, password="wrong password", sleeps=sleeps)
    assert not ok
    assert _counter_value(env) == 2


def test_a26_success_with_counter_zero_has_no_delay_and_no_file(env):
    sleeps = []
    ok, sleeps = _try_auth(env, sleeps=sleeps)
    assert ok
    assert sleeps == []
    assert not _counter_path(env).exists()  # reset is a no-op at 0
    assert _read_failure_count(env["dir"]) == 0


def test_a26_corrupt_counter_file_does_not_brick_ceremony(env):
    _counter_path(env).write_text("this is not json", encoding="utf-8")
    os.chmod(_counter_path(env), 0o600)
    assert _read_failure_count(env["dir"]) == 0  # corrupt reads as 0
    sleeps = []
    ok, sleeps = _try_auth(env, password="wrong password", sleeps=sleeps)
    assert not ok
    assert sleeps == []
    assert _counter_value(env) == 1  # self-healed on next failure
    ok, sleeps = _try_auth(env, sleeps=sleeps)  # correct creds still work
    assert ok
    assert _counter_value(env) == 0


def test_a26_backoff_engages_through_sign_flow(env):
    # Threading check: the real ceremony path passes sleep_fn through.
    tx = _unsigned_tx(env)
    sleeps = []
    for _ in range(5):
        input_fn, getpass_fn = _auth_fns(env, password="wrong password")
        with pytest.raises(SignerError, match="authentication failed"):
            sign_flow(env["config_path"], tx.serialize().hex(),
                      input_fn=input_fn, getpass_fn=getpass_fn,
                      output_fn=lambda s: None, time_fn=lambda: FIXED_TIME,
                      sleep_fn=sleeps.append)
    assert sleeps == [30]
    assert _counter_value(env) == 5
