"""Offline anchor-transaction signer (human-side signing ceremony).

Implements the anchor signing ceremony: the builder (AI / publisher)
prepares an unsigned anchor transaction; this signer — running on the
human's side, outside the builder's reach — independently decodes the
transaction from raw bytes, enforces the ceremony's hard rules, shows
the decoded transaction for human review, requires username + password
+ TOTP authentication for this one transaction only, binds the
approval to the exact hash of the unsigned transaction, and signs.

Authentication is single-use: the TOTP time-step of an accepted code
is persisted (in ``totp-state.json`` next to the config) and the same
code is refused afterwards, so an observed code authorizes exactly one
signature. The check-and-consume sequence is guarded by an exclusive
lock, so concurrent ceremonies cannot both consume the same code.

Stdlib only. No network access anywhere in this module: the signer
never fetches anything and never broadcasts; the builder broadcasts
the signed transaction separately.

Key storage honesty: the anchor key file and the config file (which
holds the TOTP secret) are protected by 0600 file permissions, and
the password gates *use* of the key (verified against a PBKDF2 hash).
The standard library has no vetted symmetric cipher, so this module
deliberately does NOT hand-roll encryption for the key at rest —
at-rest protection relies on OS permissions plus full-disk encryption
on the signer's device. A vetted-library encryption layer (e.g. an
OS keyring or an age/sops-style envelope) is a future upgrade; until
then, do not place the key file or config on a shared, cloud-synced,
or multi-user machine.

Mainnet: signing is refused unconditionally in this build. There is
no mainnet key config, and creating one is a separate witnessed step
that happens only after the TTN proof passes and the mainnet gate is
addressed on its own terms.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import json
import os
import secrets
import stat
import struct
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix platforms
    fcntl = None  # type: ignore[assignment]

from .anchor import decode_anchor_payload
from .bsv import (
    SIGHASH_ALL_FORKID,
    PrivKey,
    Tx,
    build_p2pkh_script_for_address,
    parse_tx,
    sign_digest,
    sighash_forkid,
    validate_network,
)
from .core import VerificationError

PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_BYTES = 16
PBKDF2_KEY_BYTES = 32
TOTP_STEP_SECONDS = 30
TOTP_WINDOW_STEPS = 1
TOTP_DEFAULT_DIGITS = 6
DEFAULT_FEE_CAP_SATS = 2000
CONFIG_VERSION = 1
# Name of the single-use TOTP state file, resolved next to the config.
TOTP_STATE_FILENAME = "totp-state.json"
# Sentinel meaning "no code has been consumed yet".
NO_TOTP_STEP_USED = -1


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class SignerError(Exception):
    """Any signer failure: config, authentication, or usage error."""


class Refusal(SignerError):
    """A hard-rule refusal. The transaction must not be signed.

    ``rule`` names the failed check so refusals are auditable; it is
    also recorded in the JSONL audit log.
    """

    def __init__(self, rule: str, detail: str) -> None:
        self.rule = rule
        self.detail = detail
        super().__init__(f"{rule}: {detail}")


# --- TOTP (RFC 6238, HMAC-SHA1) --------------------------------------------


def _hotp(secret: bytes, counter: int, digits: int) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return str(binary % (10**digits)).zfill(digits)


def totp_code(secret_b32: str, timestamp: float, *, digits: int = TOTP_DEFAULT_DIGITS,
              step: int = TOTP_STEP_SECONDS) -> str:
    """Compute the TOTP code for ``timestamp`` (seconds since epoch)."""
    if isinstance(digits, bool) or not 1 <= digits <= 10:
        raise SignerError("TOTP digits must be between 1 and 10")
    try:
        secret = base64.b32decode(secret_b32, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise SignerError("TOTP secret is not valid base32") from exc
    return _hotp(secret, int(timestamp) // step, digits)


def totp_matching_step(secret_b32: str, code: str, timestamp: float, *,
                       digits: int = TOTP_DEFAULT_DIGITS,
                       window: int = TOTP_WINDOW_STEPS,
                       step: int = TOTP_STEP_SECONDS) -> int | None:
    """Return the HOTP time-step a code matches, or None.

    Accepts +-``window`` steps of clock skew (the same tolerance as
    :func:`totp_verify`) and returns the integer counter
    ``int(timestamp) // step`` of the matching step — the value a
    single-use check persists so the same code can never be replayed.
    Fails closed (None) on malformed input or a bad secret.
    """
    code = code.strip()
    # isascii() first: str.isdigit() accepts Unicode digits (e.g. the
    # Arabic-Indic '١٢٣٤٥٦'), and hmac.compare_digest cannot compare
    # non-ASCII str -- it raises TypeError. A TOTP code is ASCII
    # digits; anything else is malformed input and must fail closed.
    if not code.isascii() or not code.isdigit() or len(code) != digits:
        return None
    now_step = int(timestamp) // step
    try:
        for delta in range(-window, window + 1):
            candidate = now_step + delta
            expected = totp_code(
                secret_b32, candidate * step, digits=digits, step=step
            )
            if hmac.compare_digest(expected, code):
                return candidate
    except (SignerError, TypeError, ValueError):
        # A malformed code, a bad secret, or a comparison the platform
        # refuses (compare_digest raises TypeError on non-ASCII str) is
        # a failed authentication, never an exception: the caller's
        # "fail closed" contract is that this function returns None.
        return None
    return None


def totp_verify(secret_b32: str, code: str, timestamp: float, *,
                digits: int = TOTP_DEFAULT_DIGITS,
                window: int = TOTP_WINDOW_STEPS,
                step: int = TOTP_STEP_SECONDS) -> bool:
    """Verify a TOTP code, accepting +-``window`` steps of clock skew.

    Fails closed (False) on malformed input or a bad secret.

    Note: this is a *stateless* check and does NOT enforce single use.
    Callers that gate a privileged action must use
    :func:`totp_matching_step` together with the persisted last-used
    step (see :func:`_authenticate`) so one code authorizes exactly
    one action.
    """
    return totp_matching_step(
        secret_b32, code, timestamp, digits=digits, window=window, step=step
    ) is not None


# --- password hashing (PBKDF2-HMAC-SHA256) ----------------------------------


def hash_password(password: str, *, salt: bytes | None = None,
                  iterations: int = PBKDF2_ITERATIONS) -> dict[str, Any]:
    """Hash a password for storage. The record holds no password bytes."""
    if salt is None:
        salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=PBKDF2_KEY_BYTES
    )
    return {"salt": salt.hex(), "hash": digest.hex(), "iterations": iterations}


def verify_password(password: str, record: dict[str, Any]) -> bool:
    """Constant-time password check against a :func:`hash_password` record."""
    try:
        salt = bytes.fromhex(record["salt"])
        expected = bytes.fromhex(record["hash"])
        iterations = int(record["iterations"])
    except (KeyError, TypeError, ValueError):
        return False
    if iterations < 1:
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=PBKDF2_KEY_BYTES
    )
    return hmac.compare_digest(digest, expected)


# --- private files ----------------------------------------------------------


def _read_private_text(path: Path, what: str, *, encoding: str = "utf-8") -> str:
    """Read a private file through a single descriptor.

    Opens once with O_NOFOLLOW, checks permissions with fstat() on that
    descriptor, and reads from the same descriptor — the bytes read are
    the bytes whose permissions were checked, with no stat-then-read
    window for a path swap or symlink substitution between check and
    use. Refuses non-regular files and group/world-readable files.
    """
    flags = os.O_RDONLY | _O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SignerError(f"cannot read {what}: {path}") from exc
    try:
        mode = os.fstat(fd).st_mode
    except OSError as exc:
        os.close(fd)
        raise SignerError(f"cannot stat {what}: {path}") from exc
    if not stat.S_ISREG(mode):
        os.close(fd)
        raise SignerError(f"{what} is not a regular file: {path}")
    if mode & 0o077:
        os.close(fd)
        raise SignerError(f"{what} must not be group- or world-readable: {path}")
    try:
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise SignerError(f"cannot read {what}: {path}") from exc
    try:
        return raw.decode(encoding)
    except UnicodeDecodeError as exc:
        raise SignerError(f"cannot read {what}: {path}") from exc


def _write_private_text(path: Path, text: str) -> None:
    """Write a file with 0600 permissions (no group/world access)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise SignerError(f"cannot write {path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_private_json(path: Path, obj: dict[str, Any]) -> None:
    _write_private_text(path, json.dumps(obj, indent=2, sort_keys=True) + "\n")


def _resolve(maybe_relative: str, config_dir: Path) -> Path:
    p = Path(maybe_relative)
    return p if p.is_absolute() else config_dir / p


# --- config -----------------------------------------------------------------


def _require_hex64(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise SignerError(f"{field} must be a 64-character hex string")
    value = value.lower()
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise SignerError(f"{field} must be a 64-character hex string") from exc
    if len(raw) != 32:
        raise SignerError(f"{field} must be a 64-character hex string")
    return value


def load_config(path: str | Path) -> dict[str, Any]:
    """Load and validate a signer config. Refuses a group/world-readable file."""
    path = Path(path)
    text = _read_private_text(path, "signer config")
    try:
        config = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SignerError(f"cannot read signer config: {path}") from exc
    if not isinstance(config, dict):
        raise SignerError("signer config must be a JSON object")
    for key in ("version", "network", "username", "anchor_address", "key_file",
                "log_file", "fee_cap_sats", "password", "totp"):
        if key not in config:
            raise SignerError(f"signer config is missing {key!r}")
    if config["version"] != CONFIG_VERSION:
        raise SignerError(f"unsupported signer config version: {config['version']!r}")
    try:
        config["network"] = validate_network(config["network"])
    except ValueError as exc:
        raise SignerError(f"invalid network in signer config: {exc}") from exc
    if not isinstance(config["username"], str) or not config["username"]:
        raise SignerError("signer config username must be a non-empty string")
    if not isinstance(config["anchor_address"], str) or not config["anchor_address"]:
        raise SignerError("signer config anchor_address must be a non-empty string")
    if not isinstance(config["fee_cap_sats"], int) or isinstance(config["fee_cap_sats"], bool) \
            or config["fee_cap_sats"] < 0:
        raise SignerError("signer config fee_cap_sats must be a non-negative integer")
    if not isinstance(config["password"], dict):
        raise SignerError("signer config password record must be an object")
    totp = config["totp"]
    if not isinstance(totp, dict) or "secret" not in totp:
        raise SignerError("signer config totp must be an object with a secret")
    digits = totp.get("digits", TOTP_DEFAULT_DIGITS)
    if not isinstance(digits, int) or isinstance(digits, bool) or not 1 <= digits <= 10:
        raise SignerError("signer config totp digits must be between 1 and 10")
    if config.get("expected_prev_txid") is not None:
        config["expected_prev_txid"] = _require_hex64(
            config["expected_prev_txid"], "expected_prev_txid")
    utxo = config.get("expected_utxo")
    if utxo is not None:
        if not isinstance(utxo, dict):
            raise SignerError("signer config expected_utxo must be an object")
        utxo["txid"] = _require_hex64(utxo.get("txid"), "expected_utxo.txid")
        if not isinstance(utxo.get("vout"), int) or isinstance(utxo.get("vout"), bool) \
                or not 0 <= utxo["vout"] <= 0xFFFFFFFF:
            raise SignerError("signer config expected_utxo.vout must be a uint32")
        if not isinstance(utxo.get("value"), int) or isinstance(utxo.get("value"), bool) \
                or utxo["value"] < 0:
            raise SignerError("signer config expected_utxo.value must be a non-negative integer")
    payload_hex = config.get("expected_payload_hex")
    if payload_hex is not None:
        try:
            bytes.fromhex(payload_hex)
        except ValueError as exc:
            raise SignerError("signer config expected_payload_hex must be hex") from exc
    return config


def load_signer_key(config: dict[str, Any], config_dir: Path) -> PrivKey:
    """Load the anchor key: perms-checked, WIF version matches network,
    and the derived address must equal the configured anchor address."""
    key_path = _resolve(config["key_file"], config_dir)
    wif = _read_private_text(key_path, "signer key file", encoding="ascii").strip()
    try:
        key = PrivKey.from_wif(wif, config["network"])
    except ValueError as exc:
        raise SignerError(
            f"signer key is not valid WIF for network {config['network']!r}"
        ) from exc
    if key.address(config["network"]) != config["anchor_address"]:
        raise SignerError("signer key does not match the configured anchor address")
    return key


# --- audit log --------------------------------------------------------------


def _append_log(config: dict[str, Any], config_dir: Path, entry: dict[str, Any]) -> None:
    """Append one JSONL audit entry. A failed audit write fails the operation:
    a signed transaction must not go unrecorded."""
    log_path = _resolve(config.get("log_file", "signer-audit.jsonl"), config_dir)
    record = {"ts": datetime.now(timezone.utc).isoformat(), **entry}
    line = json.dumps(record, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | _O_NOFOLLOW
    try:
        fd = os.open(log_path, flags, 0o600)
    except OSError as exc:
        raise SignerError(f"cannot open signer audit log: {log_path}") from exc
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError as exc:
        raise SignerError(f"cannot write signer audit log: {log_path}") from exc


# --- TOTP single-use state ---------------------------------------------------
#
# A TOTP code is valid for a whole 30-second step (and the +-1 step
# skew window), so a stateless check lets one observed code authorize
# an unbounded number of signatures. The signer therefore persists the
# HOTP time-step of the last consumed code and refuses any code whose
# matched step is not strictly newer. The state lives in a small file
# next to the config, written atomically and guarded by an exclusive
# lock so two concurrent ceremonies cannot both consume the same step.


def _totp_state_path(config_dir: Path) -> Path:
    return config_dir / TOTP_STATE_FILENAME


@contextmanager
def _totp_state_lock(config_dir: Path) -> Iterator[None]:
    """Hold an exclusive lock over the TOTP state file.

    The lock is advisory and process-local, but it is what makes the
    check-and-consume sequence atomic between two signer invocations
    sharing one state file: the second one blocks here, then reads
    the state the first one already advanced.
    """
    lock_path = config_dir / (TOTP_STATE_FILENAME + ".lock")
    if fcntl is None:  # pragma: no cover - non-Unix platforms
        raise SignerError(
            "cannot lock the TOTP single-use state: this platform has no "
            "file locking, so single use cannot be guaranteed; refusing to sign"
        )
    flags = os.O_RDWR | os.O_CREAT | _O_NOFOLLOW
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise SignerError(
            f"cannot open TOTP state lock: {lock_path}"
        ) from exc
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as exc:
            raise SignerError(
                f"cannot lock TOTP state: {lock_path}"
            ) from exc
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _read_last_used_step(config_dir: Path) -> int:
    """Return the last consumed TOTP time-step, or ``NO_TOTP_STEP_USED``.

    A missing state file means no code has been consumed yet. A
    malformed or unreadable state file is a fail-closed condition:
    it could mean a consumed code would be accepted again, so the
    signer refuses rather than guessing.
    """
    state_path = _totp_state_path(config_dir)
    # lexists, not exists: a *broken symlink* must not read as
    # "no state yet" (that would silently reset single-use
    # protection). It is read below, where O_NOFOLLOW refuses it
    # and the signer fails closed.
    if not os.path.lexists(state_path):
        return NO_TOTP_STEP_USED
    try:
        text = _read_private_text(state_path, "TOTP state file")
    except SignerError as exc:
        raise SignerError(
            "cannot read the TOTP single-use state; refusing to sign because "
            "a previously used code might be accepted again "
            f"({exc})"
        ) from exc
    try:
        state = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SignerError(
            "TOTP single-use state is corrupt; refusing to sign because a "
            "previously used code might be accepted again"
        ) from exc
    if not isinstance(state, dict):
        raise SignerError(
            "TOTP single-use state is malformed; refusing to sign because a "
            "previously used code might be accepted again"
        )
    last = state.get("last_used_step")
    if not isinstance(last, int) or isinstance(last, bool) or last < NO_TOTP_STEP_USED:
        raise SignerError(
            "TOTP single-use state is malformed; refusing to sign because a "
            "previously used code might be accepted again"
        )
    return last


def _write_last_used_step(config_dir: Path, step: int) -> None:
    """Persist the consumed TOTP time-step atomically.

    Written to a temporary file in the same directory, fsynced, then
    renamed into place: a crash can leave the old state or the new
    state, never a half-written one. The rename is atomic, so a
    reader never sees a truncated file.
    """
    state_path = _totp_state_path(config_dir)
    payload = json.dumps({"last_used_step": step}, indent=2, sort_keys=True) + "\n"
    tmp_path = state_path.with_name(f".{TOTP_STATE_FILENAME}.tmp")
    # O_EXCL: never write through a pre-created file (it could be
    # someone else's inode). A stale temp file left behind by a
    # crashed run is removed and recreated.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW
    try:
        fd = os.open(tmp_path, flags, 0o600)
    except FileExistsError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        try:
            fd = os.open(tmp_path, flags, 0o600)
        except OSError as exc:
            raise SignerError(
                f"cannot write TOTP single-use state: {tmp_path}"
            ) from exc
    except OSError as exc:
        raise SignerError(
            f"cannot write TOTP single-use state: {tmp_path}"
        ) from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            # fchmod on the descriptor: the mode is set on the inode
            # being written, so a path swap cannot redirect it.
            try:
                os.fchmod(handle.fileno(), 0o600)
            except OSError:
                pass
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise SignerError(
            f"cannot write TOTP single-use state: {tmp_path}"
        ) from exc
    try:
        os.replace(tmp_path, state_path)
    except OSError as exc:
        raise SignerError(
            f"cannot install TOTP single-use state: {state_path}"
        ) from exc
    # fsync the directory so the rename itself is durable.
    try:
        dir_fd = os.open(config_dir, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


# --- transaction decoding (uses the existing Tx parser) --------------------


def _extract_op_return_push(script: bytes) -> bytes:
    """Extract the payload from one OP_RETURN script. Fails closed."""
    if len(script) < 2 or script[0] != 0x6A:
        raise Refusal("payload_format", "OP_RETURN output is malformed")
    op = script[1]
    if op <= 75:
        length, header = op, 2
    elif op == 0x4C:
        if len(script) < 3:
            raise Refusal("payload_format", "OP_RETURN PUSHDATA1 is truncated")
        length, header = script[2], 3
    elif op == 0x4D:
        if len(script) < 4:
            raise Refusal("payload_format", "OP_RETURN PUSHDATA2 is truncated")
        length = struct.unpack("<H", script[2:4])[0]
        header = 4
    else:
        raise Refusal("payload_format", f"OP_RETURN uses unsupported push opcode {op:#x}")
    if len(script) != header + length:
        raise Refusal("payload_format", "OP_RETURN push length does not match the output script")
    return bytes(script[header:])


def decode_op_return(tx: Tx) -> bytes:
    """Return the tx's single OP_RETURN payload. Zero or multiple fail closed."""
    payloads = [
        _extract_op_return_push(out.script)
        for out in tx.outputs
        if out.script and out.script[0] == 0x6A
    ]
    if not payloads:
        raise Refusal("payload_format", "tx has no OP_RETURN output")
    if len(payloads) > 1:
        raise Refusal(
            "payload_format",
            f"tx has {len(payloads)} OP_RETURN outputs, expected exactly one",
        )
    return payloads[0]


def _refuse_mainnet(config: dict[str, Any]) -> None:
    if config["network"] == "mainnet":
        raise SignerError(
            "mainnet signing is not enabled in this build: mainnet key "
            "creation is a separate witnessed step, and no mainnet key "
            "config exists"
        )


def check_hard_rules(tx: Tx, config: dict[str, Any],
                     expected_payload_hex: str | None) -> dict[str, Any]:
    """Enforce every ceremony hard rule on the decoded transaction.

    Runs BEFORE any human approval is possible: a violation is refused
    here, without prompting for credentials. Returns the decoded info
    the review display needs. Raises Refusal on any violation.
    """
    _refuse_mainnet(config)
    if len(tx.inputs) != 1:
        raise Refusal(
            "inputs",
            f"anchor tx must have exactly 1 input, got {len(tx.inputs)}",
        )
    txin = tx.inputs[0]
    if txin.script_sig:
        raise Refusal(
            "unsigned",
            "input already carries a script_sig; refusing to sign a pre-signed tx",
        )
    if not 1 <= len(tx.outputs) <= 2:
        raise Refusal(
            "outputs",
            f"anchor tx must have 1-2 outputs (OP_RETURN + optional change), "
            f"got {len(tx.outputs)}",
        )
    payload_bytes = decode_op_return(tx)
    try:
        payload = decode_anchor_payload(payload_bytes)
    except VerificationError as exc:
        raise Refusal("payload_format", str(exc)) from exc
    if expected_payload_hex is None:
        expected_payload_hex = config.get("expected_payload_hex")
    if not expected_payload_hex:
        raise Refusal(
            "expected_payload",
            "no expected payload supplied: pass --expected-payload or set it "
            "with `sealrun signer expect`",
        )
    try:
        expected_bytes = bytes.fromhex(expected_payload_hex)
    except ValueError as exc:
        raise Refusal("expected_payload", "expected payload is not hex") from exc
    if not hmac.compare_digest(payload_bytes, expected_bytes):
        raise Refusal(
            "payload_match",
            "OP_RETURN payload does not match the expected payload",
        )
    expected_prev = config.get("expected_prev_txid")
    if not expected_prev or payload["prev_txid"] != expected_prev.lower():
        raise Refusal(
            "prev_txid",
            "payload prev_txid does not match the expected previous anchor",
        )
    utxo = config.get("expected_utxo")
    if not isinstance(utxo, dict):
        raise Refusal(
            "utxo",
            "config has no expected UTXO: set it with `sealrun signer expect`",
        )
    if txin.prev_txid.lower() != utxo["txid"].lower() or txin.prev_index != utxo["vout"]:
        raise Refusal(
            "utxo",
            "input does not spend the expected UTXO "
            f"({utxo['txid']}:{utxo['vout']})",
        )
    anchor_script = build_p2pkh_script_for_address(
        config["anchor_address"], config["network"]
    )
    total_out = 0
    for out in tx.outputs:
        total_out += out.value
        if out.script and out.script[0] == 0x6A:
            if out.value != 0:
                raise Refusal(
                    "change_address",
                    "OP_RETURN output must carry no spendable value",
                )
            continue
        if out.script != anchor_script:
            raise Refusal(
                "change_address",
                "a non-data output does not pay to the anchor address",
            )
    fee = utxo["value"] - total_out
    if fee < 0:
        raise Refusal("fee", f"outputs exceed the input value by {-fee} sats")
    if fee > config["fee_cap_sats"]:
        raise Refusal(
            "fee_cap",
            f"fee {fee} sats exceeds the cap of {config['fee_cap_sats']} sats",
        )
    return {
        "payload": payload,
        "payload_bytes": payload_bytes,
        "fee": fee,
        "input_value": utxo["value"],
        "unsigned_txid": tx.txid(),
    }


def format_review(tx: Tx, info: dict[str, Any], config: dict[str, Any]) -> str:
    """Human review display, built from the signer's own decode."""
    payload = info["payload"]
    anchor_script = build_p2pkh_script_for_address(
        config["anchor_address"], config["network"]
    )
    lines = [
        "=== Anchor transaction for review ===",
        f"Network: {config['network']}",
        f"Unsigned tx hash: {info['unsigned_txid']}",
        "Inputs:",
        f"  {tx.inputs[0].prev_txid}:{tx.inputs[0].prev_index}  "
        f"({info['input_value']} sats)",
        "Outputs:",
    ]
    for out in tx.outputs:
        if out.script and out.script[0] == 0x6A:
            lines.append(f"  OP_RETURN (data): {out.value} sats")
        elif out.script == anchor_script:
            lines.append(f"  {out.value} sats -> {config['anchor_address']} (change)")
        else:
            lines.append(f"  {out.value} sats -> {out.script.hex()} (UNEXPECTED)")
    lines.append(f"Fee: {info['fee']} sats (cap {config['fee_cap_sats']} sats)")
    lines.append("Decoded payload:")
    lines.append(f"  head hash: {payload['head_hash']}")
    lines.append(f"  sequence range: {payload['start_seq']}..{payload['end_seq']}")
    lines.append(f"  release sequence: {payload['release_seq']}")
    lines.append(f"  previous anchor txid: {payload['prev_txid']}")
    return "\n".join(lines)


# --- signing ----------------------------------------------------------------


def _push_data(data: bytes) -> bytes:
    """Encode one script push (direct push only; signature pushes fit)."""
    if len(data) > 75:
        raise SignerError(f"push of {len(data)} bytes is not supported")
    return bytes([len(data)]) + data


def sign_approved_tx(tx: Tx, approved_txid: str, config: dict[str, Any],
                     privkey: PrivKey,
                     expected_payload_hex: str | None = None) -> Tx:
    """Sign a tx whose approval is bound to ``approved_txid``.

    Re-hashes and re-verifies the hard rules immediately before signing;
    any byte change since display voids the approval.
    """
    _refuse_mainnet(config)
    if tx.txid() != approved_txid:
        raise Refusal(
            "approval_binding",
            "transaction changed after approval; the approval is void",
        )
    if expected_payload_hex is None:
        expected_payload_hex = config.get("expected_payload_hex")
    check_hard_rules(tx, config, expected_payload_hex)
    utxo = config["expected_utxo"]
    prev_script = build_p2pkh_script_for_address(
        config["anchor_address"], config["network"]
    )
    digest = sighash_forkid(tx, 0, prev_script, utxo["value"])
    der = sign_digest(privkey, digest)
    pubkey = privkey.pubkey_compressed()
    tx.inputs[0].script_sig = (
        _push_data(der + bytes([SIGHASH_ALL_FORKID])) + _push_data(pubkey)
    )
    return tx


def _authenticate(config: dict[str, Any], *, input_fn: Callable[[str], str],
                  getpass_fn: Callable[[str], str],
                  time_fn: Callable[[], float],
                  config_dir: Path | None = None) -> bool:
    """Username + password + TOTP for this one transaction only.

    Returns False without saying which factor failed.

    The TOTP factor is **single-use**: the time-step of an accepted
    code is persisted and any code from that step (or an older one)
    is refused afterwards, so an observed code authorizes exactly one
    signature. The step is consumed *before* the key is loaded and
    the transaction is signed — a code that was accepted is never
    accepted again, even if the ceremony fails afterwards.

    ``config_dir`` is where the single-use state lives; it defaults
    to the current directory.
    """
    username = input_fn("Username: ")
    password = getpass_fn("Password: ")
    code = input_fn("TOTP code: ")
    if username != config["username"]:
        return False
    if not verify_password(password, config["password"]):
        return False
    totp = config["totp"]
    if config_dir is None:
        config_dir = Path.cwd()
    # Hold the lock across read-check-consume so two concurrent
    # ceremonies cannot both consume the same time-step.
    with _totp_state_lock(config_dir):
        matched_step = totp_matching_step(
            totp["secret"], code, time_fn(),
            digits=totp.get("digits", TOTP_DEFAULT_DIGITS),
        )
        if matched_step is None:
            return False
        last_used = _read_last_used_step(config_dir)
        if matched_step <= last_used:
            # A code from this step (or an earlier one) was already
            # used. Refuse: one code authorizes exactly one signature.
            # Recorded distinctly: a replay attempt is worth seeing in
            # the audit log, unlike the other factor failures whose
            # cause is deliberately not disclosed.
            try:
                _append_log(config, config_dir, {
                    "decision": "auth_failure",
                    "reason": "TOTP code replay refused (code already used)",
                })
            except SignerError:
                pass  # the refusal stands even if the audit write fails
            return False
        # Burn the step before anything is signed.
        _write_last_used_step(config_dir, matched_step)
    return True


def sign_flow(config_path: str | Path, tx_hex: str, *,
              expected_payload_hex: str | None = None,
              input_fn: Callable[[str], str] | None = None,
              getpass_fn: Callable[[str], str] | None = None,
              output_fn: Callable[[str], None] | None = None,
              time_fn: Callable[[], float] | None = None,
              network: str | None = None) -> str:
    """Run one signing ceremony. Returns the signed tx hex.

    Raises Refusal (hard-rule violation, incl. approval binding) or
    SignerError (config / authentication / usage failure). Every
    request, refusal, authentication failure, and signature is
    recorded in the JSONL audit log.
    """
    input_fn = input_fn or input
    getpass_fn = getpass_fn or getpass.getpass
    output_fn = output_fn or print
    time_fn = time_fn or time.time
    config_path = Path(config_path)
    config = load_config(config_path)
    config_dir = config_path.parent
    if network is not None and network != config["network"]:
        raise SignerError(
            f"--network {network!r} does not match the signer config network "
            f"{config['network']!r}"
        )
    txid: str | None = None
    try:
        try:
            tx = parse_tx(bytes.fromhex(tx_hex))
            txid = tx.txid()
        except ValueError as exc:
            raise Refusal("parse", f"cannot parse unsigned tx: {exc}") from exc
        expected = expected_payload_hex or config.get("expected_payload_hex")
        info = check_hard_rules(tx, config, expected)
    except Refusal as refusal:
        try:
            _append_log(config, config_dir, {
                "decision": "refusal", "rule": refusal.rule,
                "reason": refusal.detail, "txid": txid,
            })
        except SignerError:
            pass  # the refusal stands even if the audit log write fails
        raise
    _append_log(config, config_dir, {
        "decision": "request", "txid": info["unsigned_txid"],
        "reason": "signing requested",
    })
    output_fn(format_review(tx, info, config))
    if not _authenticate(config, input_fn=input_fn, getpass_fn=getpass_fn,
                         time_fn=time_fn, config_dir=config_dir):
        _append_log(config, config_dir, {
            "decision": "auth_failure", "txid": info["unsigned_txid"],
            "reason": "authentication failed",
        })
        raise SignerError("authentication failed")
    privkey = load_signer_key(config, config_dir)
    signed = sign_approved_tx(tx, info["unsigned_txid"], config, privkey,
                              expected_payload_hex=expected)
    signed_hex = signed.serialize().hex()
    _append_log(config, config_dir, {
        "decision": "signed", "txid": signed.txid(),
        "unsigned_txid": info["unsigned_txid"], "reason": "signed after approval",
    })
    output_fn(f"SIGNED_TX_HEX={signed_hex}")
    output_fn(f"Signed txid: {signed.txid()}")
    return signed_hex


def run_sign(config_path: str | Path, tx_hex: str, *,
             expected_payload_hex: str | None = None,
             input_fn: Callable[[str], str] | None = None,
             getpass_fn: Callable[[str], str] | None = None,
             output_fn: Callable[[str], None] | None = None,
             time_fn: Callable[[], float] | None = None,
             network: str | None = None) -> int:
    """CLI wrapper around :func:`sign_flow`: exit code, never a traceback."""
    output_fn = output_fn or print

    def error_fn(msg: str) -> None:
        print(msg, file=sys.stderr)

    try:
        sign_flow(config_path, tx_hex, expected_payload_hex=expected_payload_hex,
                  input_fn=input_fn, getpass_fn=getpass_fn, output_fn=output_fn,
                  time_fn=time_fn, network=network)
        return 0
    except (Refusal, SignerError) as exc:
        error_fn(f"signer: refused: {exc}")
        return 1


# --- setup commands ---------------------------------------------------------


def init_signer(config_path: str | Path, key_path: str | Path, *,
                input_fn: Callable[[str], str] | None = None,
                getpass_fn: Callable[[str], str] | None = None,
                output_fn: Callable[[str], None] | None = None) -> None:
    """Create a fresh testnet signer: generate the key, set the password,
    print the TOTP secret once for the authenticator app. Refuses to
    overwrite existing files and refuses mainnet (no mainnet config
    exists in this build)."""
    input_fn = input_fn or input
    getpass_fn = getpass_fn or getpass.getpass
    output_fn = output_fn or print
    config_path = Path(config_path)
    key_path = Path(key_path)
    if config_path.exists():
        raise SignerError(f"signer config already exists: {config_path}")
    if key_path.exists():
        raise SignerError(f"key file already exists: {key_path}")
    username = input_fn("Username: ")
    if not username:
        raise SignerError("username must not be empty")
    password = getpass_fn("New password: ")
    if not password:
        raise SignerError("password must not be empty")
    if getpass_fn("Confirm password: ") != password:
        raise SignerError("passwords do not match")
    key = PrivKey.generate()
    _write_private_text(key_path, key.wif("testnet") + "\n")
    totp_secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    config = {
        "version": CONFIG_VERSION,
        "network": "testnet",
        "username": username,
        "anchor_address": key.address("testnet"),
        "key_file": str(key_path),
        "log_file": str(config_path.parent / "signer-audit.jsonl"),
        "fee_cap_sats": DEFAULT_FEE_CAP_SATS,
        "expected_prev_txid": None,
        "expected_utxo": None,
        "expected_payload_hex": None,
        "password": hash_password(password),
        "totp": {"secret": totp_secret, "digits": TOTP_DEFAULT_DIGITS},
    }
    _write_private_json(config_path, config)
    output_fn(f"Anchor address (testnet): {config['anchor_address']}")
    output_fn(
        "TOTP secret (shown once — add it to your authenticator app now): "
        f"{totp_secret}"
    )
    output_fn("Next: `sealrun signer expect` to set the expected UTXO and payload.")


def set_expectation(config_path: str | Path, *, prev_txid: str, utxo_txid: str,
                    utxo_vout: int, utxo_value: int,
                    expected_payload_hex: str | None = None) -> None:
    """Record what the NEXT anchor must spend and anchor.

    The expected payload is the full 84-byte anchor payload hex the
    human verified out-of-band (e.g. against the journal head); the
    signer compares the tx's OP_RETURN bytes to it exactly.
    """
    config_path = Path(config_path)
    config = load_config(config_path)
    config["expected_prev_txid"] = _require_hex64(prev_txid, "prev_txid")
    config["expected_utxo"] = {
        "txid": _require_hex64(utxo_txid, "utxo_txid"),
        "vout": utxo_vout,
        "value": utxo_value,
    }
    if not isinstance(utxo_vout, int) or isinstance(utxo_vout, bool) \
            or not 0 <= utxo_vout <= 0xFFFFFFFF:
        raise SignerError("utxo_vout must be a uint32")
    if not isinstance(utxo_value, int) or isinstance(utxo_value, bool) \
            or utxo_value < 0:
        raise SignerError("utxo_value must be a non-negative integer")
    if expected_payload_hex is not None:
        try:
            raw = bytes.fromhex(expected_payload_hex)
        except ValueError as exc:
            raise SignerError("expected payload is not hex") from exc
        try:
            decode_anchor_payload(raw)
        except VerificationError as exc:
            raise SignerError(f"expected payload is not a valid anchor payload: {exc}") from exc
        config["expected_payload_hex"] = expected_payload_hex.lower()
    _write_private_json(config_path, config)


# --- CLI --------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Entry point: ``sealrun signer <init|expect|sign> ...``."""
    parser = argparse.ArgumentParser(
        prog="sealrun signer",
        description="Offline anchor-transaction signer (human-side signing ceremony).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a fresh testnet signer config + key")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--key-file", required=True, type=Path)

    p = sub.add_parser("expect", help="record the expected UTXO / payload for the next anchor")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--prev-txid", required=True)
    p.add_argument("--utxo-txid", required=True)
    p.add_argument("--utxo-vout", required=True, type=int)
    p.add_argument("--utxo-value", required=True, type=int)
    p.add_argument("--expected-payload", default=None)

    p = sub.add_parser("sign", help="review, authenticate, and sign one unsigned anchor tx")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--tx", default=None, help="unsigned tx hex")
    p.add_argument("--tx-file", default=None, type=Path,
                   help="file holding the unsigned tx hex (alternative to --tx)")
    p.add_argument("--expected-payload", default=None,
                   help="expected 84-byte anchor payload hex (overrides "
                   "the recorded expectation; requires --override-expected)")
    p.add_argument("--override-expected", action="store_true",
                   help="acknowledge that --expected-payload overrides "
                   "the expectation recorded with `signer expect` for "
                   "this one signing")
    p.add_argument("--network", default=None, choices=["testnet", "mainnet"],
                   help="must match the config network; mainnet is refused")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            init_signer(args.config, args.key_file)
            return 0
        if args.command == "expect":
            set_expectation(
                args.config, prev_txid=args.prev_txid, utxo_txid=args.utxo_txid,
                utxo_vout=args.utxo_vout, utxo_value=args.utxo_value,
                expected_payload_hex=args.expected_payload,
            )
            return 0
        if args.command == "sign":
            if args.expected_payload is not None and not args.override_expected:
                print("signer: --expected-payload overrides the recorded "
                      "expectation; pass --override-expected to "
                      "acknowledge the override", file=sys.stderr)
                return 1
            if bool(args.tx) == bool(args.tx_file):
                print("signer: exactly one of --tx or --tx-file is required",
                      file=sys.stderr)
                return 1
            if args.tx_file is not None:
                try:
                    tx_hex = args.tx_file.read_text(encoding="ascii").strip()
                except (OSError, UnicodeDecodeError) as exc:
                    print(f"signer: cannot read tx file: {exc}", file=sys.stderr)
                    return 1
            else:
                tx_hex = args.tx
            return run_sign(args.config, tx_hex,
                            expected_payload_hex=args.expected_payload,
                            network=args.network)
    except (Refusal, SignerError) as exc:
        print(f"signer: refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
