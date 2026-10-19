"""Phase 2 publisher: anchor checkpoints on release acceptance + on schedule.

The publisher turns the anchoring design (``docs/anchoring-protocol.md``)
into running code, with one hard boundary: **broadcast is disabled by
default**. By default the publisher *prepares* anchor payloads and
records them locally. Nothing is signed, spent, or sent to any network
unless the operator explicitly enables broadcast *and* supplies a
broadcaster (see :class:`NullBroadcaster` and :func:`Publisher.__init__`).
The real broadcaster implementation is
:class:`sealrun.broadcast.WoCBroadcaster` (build + sign + send via
WhatsOnChain); the CLI wires it up under ``publish --broadcast``.

What the publisher does
-----------------------
- **Anchor-on-release**: when a new ``manifest_accepted`` event lands in
  the journal, :meth:`Publisher.on_release_accepted` builds the anchor
  for that checkpoint immediately.
- **Scheduled checkpoints**: :meth:`Publisher.run_once` builds an anchor
  for the current journal head when the configured interval has elapsed
  since the last anchor, even when no release landed — closing the
  unanchored-tail window between releases.
- **Anchor record**: emitted anchors are persisted (payload + txid slot +
  status) in a JSON record store, so a later run resumes from the last
  anchor instead of re-anchoring the same range. Two anchors never
  silently cover the same range: a checkpoint for a head that is already
  anchored returns the existing record. All store mutations run under
  an inter-process lock (``<store>.lock``, flock, reentrant) across the
  whole load-modify-save flow, so concurrent publishers cannot lose
  updates or emit duplicate anchors for one head.

Chaining model (honest about what is / is not on-chain)
------------------------------------------------------
``prev_txid`` in a payload must be the previous anchor *transaction* id,
so a new anchor chains to the last **broadcast** anchor (the last record
with a txid). A merely *prepared* (never broadcast) anchor has no txid
and therefore anchors nothing on-chain: when the head advances past it,
the new anchor still chains to the last broadcast anchor (or the genesis
txid) and covers the full range from there, and the stale prepared
record is marked ``superseded``. Prepared payloads are drafts until a
broadcast gives them a txid; they are never presented as on-chain proof.

Fail-closed rules
-----------------
The publisher refuses to anchor when the journal fails verification,
when acceptance binding fails (acceptances present but no verified
manifests / trusted public key), when the journal is missing or
malformed, or when the configured genesis txid disagrees with the
genesis the record store was created with. It never anchors a
checkpoint it cannot verify locally.

Explicitly out of scope (documented, not faked)
----------------------------------------------
- Blockchain proof verification (Merkle-proof / header-chain /
  confirmation): a broadcast anchor's inclusion is ``confirmed-unknown``
  until an SPV verifier lands. The record store never claims
  ``confirmed``.
- Anchor-chain continuity enforcement (issue #8) for the *record
  store*: on every load, the broadcast records must form one
  continuous, fork-free chain from the store's genesis
  (``anchor.verify_anchor_chain``). A tampered store — edited
  ``prev_txid``, a forked record, a gap — refuses every publisher
  operation, so the publisher can never build a new anchor on top of
  a broken chain. On-chain confirmation of those anchors is still
  unverified (see above).
- Transaction construction / signing / real broadcast: implemented in
  :mod:`sealrun.bsv` (stdlib-only secp256k1 + tx build/sign) and
  :mod:`sealrun.broadcast` (:class:`WoCBroadcaster` via WhatsOnChain).
  First live anchor on Teratestnet 2026-10-16 (txid
  ``4111b7cf…2bf029``). The ``publish --broadcast`` CLI path wires it up;
  broadcast stays opt-in and fail-closed without ``ANCHOR_WIF`` +
  funding.
"""
from __future__ import annotations

import contextlib
import functools
import json
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .anchor import (
    ZERO_TXID,
    create_anchor_payload,
    decode_anchor_payload,
    verify_anchor_chain,
)
from .broadcast import (
    BroadcastError,
    FundingUTXO,
    fetch_prev_output,
    post_raw_tx,
)
from .bsv import (
    SIGHASH_ALL_FORKID,
    Tx,
    TxIn,
    build_p2pkh_script,
    build_p2pkh_script_for_address,
    parse_tx,
    sighash_forkid,
    validate_network,
    verify_sig,
)
from .core import HEX_64, VerificationError, _no_duplicate_object, _read_jsonl, _verify_audit_events

MANIFEST_ACCEPTED_EVENT_TYPE = "manifest_accepted"

RECORD_STATUSES = ("pending", "broadcast", "superseded")

# O_NOFOLLOW makes open(2) fail on a trailing symlink instead of following
# it. It is Unix-only; where unavailable the value is 0 (a no-op flag),
# matching sealrun.core.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

try:
    import fcntl
except ImportError:  # non-POSIX platforms have no flock
    fcntl = None  # type: ignore[assignment]

# Sensible default: anchor at least hourly even with no new release.
DEFAULT_CHECKPOINT_INTERVAL_SECONDS = 3600

# Flow-level lock for the record store: one lock file next to the store,
# ``<store>.lock``. Holders are keyed by (store path, thread) so the lock
# is reentrant for run_once -> build_checkpoint nesting and for two
# Publisher instances in one thread, while threads in one process and
# separate processes serialize on flock.
_STORE_LOCK_GUARD = threading.Lock()
_STORE_LOCK_HOLDERS: dict[tuple[str, int], list] = {}


class PublisherError(VerificationError):
    """Raised when the publisher refuses to anchor or its state is unsafe."""


@dataclass(frozen=True)
class PublisherConfig:
    """Configuration for one publisher run.

    ``broadcast_enabled`` defaults to False: with it off, the publisher
    prepares payloads and records them but never calls a broadcaster.
    ``genesis_txid`` is the out-of-band genesis anchor txid; the zero
    txid means "no genesis anchor yet" (the first broadcast anchor uses
    it as its ``prev_txid``). ``manifests`` / ``public_key`` are the
    signed manifest envelopes and trusted manifest-signing key used to
    check acceptance binding; they are required whenever the journal
    contains an acceptance (enforced by anchor creation, fail-closed).
    ``manifests_dir`` is re-read at every checkpoint: a long-running
    publisher must be able to check acceptances that land after startup,
    so the operator drops newly signed manifest envelopes into this
    directory and the publisher picks them up. ``manifests`` is a fixed
    snapshot taken at construction; ``manifests_dir`` is the live source.
    ``lock_timeout_seconds`` bounds how long a publisher waits for the
    record-store lock before failing closed.
    """

    journal: Path
    anchor_record: Path
    genesis_txid: str = ZERO_TXID
    checkpoint_interval_seconds: int = DEFAULT_CHECKPOINT_INTERVAL_SECONDS
    broadcast_enabled: bool = False
    manifests: tuple[dict, ...] = ()
    public_key: Any = None
    manifests_dir: Path | None = None
    lock_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not isinstance(self.genesis_txid, str) or not HEX_64.fullmatch(
            self.genesis_txid
        ):
            raise PublisherError("genesis_txid must be 64 hexadecimal characters")
        if (
            not isinstance(self.checkpoint_interval_seconds, int)
            or isinstance(self.checkpoint_interval_seconds, bool)
            or self.checkpoint_interval_seconds <= 0
        ):
            raise PublisherError("checkpoint_interval_seconds must be a positive integer")
        if (
            not isinstance(self.lock_timeout_seconds, (int, float))
            or isinstance(self.lock_timeout_seconds, bool)
            or self.lock_timeout_seconds <= 0
        ):
            raise PublisherError("lock_timeout_seconds must be a positive number")


class NullBroadcaster:
    """A broadcaster that always refuses.

    Used when broadcast is enabled but no real broadcaster was supplied:
    construction fails closed instead of silently dropping the anchor.
    """

    def broadcast(self, payload_hex: str) -> str:
        raise PublisherError(
            "no broadcaster configured: broadcast is disabled. Supply a "
            "broadcaster explicitly to enable broadcast."
        )


def _parse_anchor_script_sig(script_sig: bytes) -> tuple[bytes, bytes]:
    """Split an anchor input script_sig into (DER signature, pubkey).

    The script_sig must be exactly ``push(DER || sighash-byte) +
    push(pubkey)`` with single-byte push opcodes — anchor signatures
    (~71-72 bytes + 1 hashtype byte) and compressed pubkeys (33 bytes)
    both fit. The sighash byte must be SIGHASH_ALL | SIGHASH_FORKID
    and the pubkey 33-byte compressed. Anything else is refused: the
    publisher only ever broadcasts anchor transactions in exactly
    this shape.
    """
    if len(script_sig) < 2:
        raise PublisherError("anchor script_sig is too short")
    first_len = script_sig[0]
    if first_len <= 1 or 1 + first_len > len(script_sig):
        raise PublisherError("anchor script_sig has a malformed first push")
    sig_plus = script_sig[1:1 + first_len]
    rest = script_sig[1 + first_len:]
    if len(rest) < 2 or rest[0] != len(rest) - 1:
        raise PublisherError("anchor script_sig has a malformed pubkey push")
    pubkey = rest[1:]
    if len(pubkey) != 33 or pubkey[0] not in (0x02, 0x03):
        raise PublisherError(
            "anchor script_sig pubkey must be 33-byte compressed"
        )
    der, sighash_byte = sig_plus[:-1], sig_plus[-1]
    if sighash_byte != SIGHASH_ALL_FORKID:
        raise PublisherError(
            f"anchor sighash byte 0x{sighash_byte:02x} is not "
            f"SIGHASH_ALL|FORKID (0x{SIGHASH_ALL_FORKID:02x})"
        )
    if not der:
        raise PublisherError("anchor script_sig carries an empty signature")
    return der, pubkey


def _check_txid(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise PublisherError(f"{field} must be 64 hexadecimal characters")
    return value.lower()


def _validate_record(record: Any) -> dict:
    """Validate one anchor record from the store; fail closed on corruption."""
    if not isinstance(record, dict):
        raise PublisherError("anchor record store is corrupt: record is not an object")
    required = {
        "payload_hex": str,
        "head_hash": str,
        "start_seq": int,
        "end_seq": int,
        "release_seq": int,
        "prev_txid": str,
        "status": str,
        "txid": (str, type(None)),
        "reason": str,
        "created_at": (int, float),
    }
    for key, types in required.items():
        if key not in record or not isinstance(record[key], types):
            raise PublisherError(
                f"anchor record store is corrupt: record missing/invalid {key!r}"
            )
    if record["status"] not in RECORD_STATUSES:
        raise PublisherError(
            f"anchor record store is corrupt: unknown status {record['status']!r}"
        )
    try:
        fields = decode_anchor_payload(bytes.fromhex(record["payload_hex"]))
    except (ValueError, VerificationError) as exc:
        raise PublisherError(
            "anchor record store is corrupt: payload_hex is not a valid anchor payload"
        ) from exc
    for key in ("head_hash", "start_seq", "end_seq", "release_seq", "prev_txid"):
        if record[key] != fields[key]:
            raise PublisherError(
                "anchor record store is corrupt: record disagrees with its payload"
            )
    _check_txid(record["prev_txid"], "prev_txid")
    if record["txid"] is not None:
        _check_txid(record["txid"], "txid")
    return dict(record)


def _locked(method):
    """Serialize a Publisher operation across the record-store flow.

    Holds the inter-process store lock for the whole operation —
    load, decide, save, and (when enabled) broadcast — so two
    publishers can never interleave load-modify-save and lose updates
    or emit duplicate anchors for one head. Reentrant for nested calls
    (``run_once`` -> ``build_checkpoint``) via the holders table. The
    lock is held across broadcast deliberately: anchoring is a
    serialized operation, and a second publisher must not build on a
    store snapshot taken before the first one's broadcast lands.
    """

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._locked_store():
            return method(self, *args, **kwargs)

    return wrapper


class Publisher:
    """Build and record anchor checkpoints for a journal.

    ``broadcaster`` must expose ``broadcast(payload_hex) -> txid``. It is
    only consulted when ``broadcast_enabled`` is set; with broadcast off
    it is never called. When broadcast is on and no broadcaster was
    supplied, construction raises :class:`PublisherError`.
    """

    def __init__(
        self,
        config: PublisherConfig,
        broadcaster: Any = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.config = config
        if config.broadcast_enabled and broadcaster is None:
            raise PublisherError(
                "broadcast_enabled requires an explicit broadcaster; "
                "no broadcaster was supplied, refusing to run"
            )
        self.broadcaster = broadcaster
        self._clock = clock or time.time

    # -- record-store lock ----------------------------------------------

    @contextlib.contextmanager
    def _locked_store(self):
        """Hold the inter-process record-store lock for one operation.

        The lock file is ``<store>.lock`` next to the store. Same-thread
        re-entry (``run_once`` -> ``build_checkpoint``, or two Publisher
        instances in one thread) just deepens a counter; threads and
        processes serialize on flock. The fd is closed on release, so a
        dead holder's lock vanishes with it — a stale lock file on disk
        is inert. Fail-closed throughout: no fcntl, a symlink at the
        lock path, a non-regular lock file, or a timeout all raise
        :class:`PublisherError` instead of proceeding unsynchronized.
        """
        if fcntl is None:
            raise PublisherError(
                "anchor record store locking requires fcntl (POSIX); "
                "refusing to run without mutual exclusion"
            )
        key = (
            os.path.abspath(os.fspath(self.config.anchor_record)),
            threading.get_ident(),
        )
        with _STORE_LOCK_GUARD:
            holder = _STORE_LOCK_HOLDERS.get(key)
            if holder is not None:
                holder[0] += 1
                try:
                    yield
                finally:
                    holder[0] -= 1
                return
        fd = self._acquire_store_lock()
        with _STORE_LOCK_GUARD:
            _STORE_LOCK_HOLDERS[key] = [1, fd]
        try:
            yield
        finally:
            with _STORE_LOCK_GUARD:
                _STORE_LOCK_HOLDERS.pop(key, None)
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    def _acquire_store_lock(self) -> int:
        """Open + flock the lock file; return the fd on success.

        Polls ``LOCK_EX | LOCK_NB`` until ``lock_timeout_seconds`` so a
        stuck holder fails closed instead of hanging the caller
        forever. O_NOFOLLOW refuses a trailing symlink at open time;
        the fd is re-checked as regular after the lock lands.
        """
        assert fcntl is not None
        lock_path = self.config.anchor_record.parent / (
            self.config.anchor_record.name + ".lock"
        )
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(
                lock_path, os.O_RDWR | os.O_CREAT | _O_NOFOLLOW, 0o644
            )
        except OSError as exc:
            raise PublisherError(
                "anchor record store lock file must be a regular "
                "non-symlink file"
            ) from exc
        try:
            deadline = time.monotonic() + self.config.lock_timeout_seconds
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise PublisherError(
                            "timed out waiting for the anchor record "
                            "store lock; another publisher may be holding it"
                        )
                    time.sleep(0.05)
                except OSError as exc:
                    raise PublisherError(
                        f"could not lock the anchor record store: {exc}"
                    ) from exc
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise PublisherError(
                    "anchor record store lock file must be a regular "
                    "non-symlink file"
                )
            return fd
        except BaseException:
            os.close(fd)
            raise

    # -- record store -------------------------------------------------

    def _load_store(self) -> dict:
        path = self.config.anchor_record
        if not path.exists():
            return {"genesis_txid": self.config.genesis_txid.lower(), "anchors": []}
        try:
            store = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise PublisherError(
                f"anchor record store is unreadable: {path}"
            ) from exc
        if not isinstance(store, dict):
            raise PublisherError("anchor record store is corrupt: not a JSON object")
        genesis = store.get("genesis_txid")
        if not isinstance(genesis, str) or not HEX_64.fullmatch(genesis):
            raise PublisherError(
                "anchor record store is corrupt: genesis_txid missing or invalid"
            )
        if genesis.lower() != self.config.genesis_txid.lower():
            raise PublisherError(
                "genesis mismatch: record store was created with a different "
                "genesis txid than the configured one; refusing to anchor"
            )
        anchors = store.get("anchors")
        if not isinstance(anchors, list):
            raise PublisherError("anchor record store is corrupt: anchors is not a list")
        validated = [_validate_record(record) for record in anchors]
        # Continuity (issue #8): broadcast records must form one
        # continuous, fork-free chain from the store's genesis. A
        # tampered store refuses every operation, so the publisher can
        # never build a new anchor on top of a broken chain. Pending /
        # superseded records are drafts, not chain members, and are not
        # checked here.
        broadcast = [r for r in validated if r["status"] == "broadcast"]
        if broadcast:
            try:
                verify_anchor_chain(broadcast, genesis.lower())
            except VerificationError as exc:
                raise PublisherError(
                    f"anchor record store chain is broken: {exc}"
                ) from exc
        return {
            "genesis_txid": genesis.lower(),
            "anchors": validated,
        }

    def _save_store(self, store: dict) -> None:
        path = self.config.anchor_record
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(store, indent=2, sort_keys=True) + "\n"
        # Unique tmp per save, in the same directory so os.replace stays
        # atomic on one filesystem. A shared, predictable tmp path is
        # unsafe two ways: concurrent writers race on it (one thread's
        # replace removes the tmp out from under another's, crashing
        # the save and losing updates), and a planted symlink at the
        # predictable path redirects store bytes into its target.
        # A random suffix makes the tmp unpredictable and unshared; a
        # symlink planted at any legacy predictable tmp path is simply
        # never followed. O_NOFOLLOW refuses a trailing symlink at open
        # time as defense in depth.
        tmp = path.parent / (
            f"{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW
        try:
            fd = os.open(tmp, flags, 0o666)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(text)
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            os.replace(tmp, path)
        except BaseException:
            # Best-effort cleanup of our own tmp; never mask the
            # original error (e.g. an interrupted save).
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # -- journal ------------------------------------------------------

    def _load_manifests(self) -> list[dict] | None:
        """Current manifest envelopes: snapshot + live directory, if any.

        Returns None when no envelopes are available (anchor creation
        then fails closed if the journal contains any acceptance).
        A missing directory contributes zero envelopes — the operator
        may create it when the first release ships; the binding check
        still fails closed the moment an acceptance needs checking. A
        path that exists but is not a directory is a misconfiguration
        and raises.
        """
        envelopes = list(self.config.manifests)
        if self.config.manifests_dir is not None:
            directory = self.config.manifests_dir
            if directory.exists() and not directory.is_dir():
                raise PublisherError(
                    f"manifests_dir is not a directory: {directory}"
                )
            if directory.is_dir():
                for path in sorted(directory.glob("*.json")):
                    try:
                        envelope = json.loads(
                            path.read_text(encoding="utf-8"),
                            object_pairs_hook=_no_duplicate_object,
                        )
                    except (OSError, ValueError) as exc:
                        raise PublisherError(
                            f"cannot read manifest envelope: {path}"
                        ) from exc
                    if not isinstance(envelope, dict):
                        raise PublisherError(
                            f"manifest envelope is not a JSON object: {path}"
                        )
                    envelopes.append(envelope)
        return envelopes or None

    def _read_verified_events(self) -> list[dict]:
        """Read and verify the journal; any failure raises (fail-closed)."""
        try:
            events = _read_jsonl(self.config.journal)
        except (OSError, VerificationError) as exc:
            raise PublisherError(f"cannot read journal: {exc}") from exc
        try:
            _verify_audit_events(events)
        except VerificationError as exc:
            raise PublisherError(f"journal verification failed: {exc}") from exc
        return events

    @staticmethod
    def _last_broadcast(anchors: list[dict]) -> dict | None:
        for record in reversed(anchors):
            if record["status"] == "broadcast":
                return record
        return None

    @staticmethod
    def _latest_prepared(anchors: list[dict]) -> dict | None:
        for record in reversed(anchors):
            if record["status"] == "pending":
                return record
        return None

    # -- checkpoint construction ---------------------------------------

    def _broadcast_record(self, store: dict, record: dict) -> dict:
        """Attempt broadcast for a pending record; on failure it stays pending."""
        assert self.broadcaster is not None
        txid = self.broadcaster.broadcast(record["payload_hex"])
        txid = _check_txid(txid, "broadcast txid")
        record["txid"] = txid
        record["status"] = "broadcast"
        self._save_store(store)
        return dict(record)

    @_locked
    def build_checkpoint(self, reason: str, *, raise_on_broadcast_failure: bool = True) -> dict:
        """Build (and, if enabled, broadcast) the anchor for the current head.

        Returns the anchor record. If the current head is already anchored
        (a pending or broadcast record with the same head hash), returns
        the existing record without emitting a duplicate; when broadcast
        is enabled and the existing record is still pending, the broadcast
        is retried for that same record.

        Broadcast failure: the record is already saved as ``pending``,
        so with ``raise_on_broadcast_failure=False`` (used by the
        scheduler) the pending record is returned with a transient
        ``broadcast_error`` field instead of raising — anchoring is
        best-effort per the protocol doc §8, and the next tick retries
        the same record. With ``True`` (explicit operator calls) the
        broadcast error propagates.
        """
        if reason not in ("release", "scheduled"):
            raise PublisherError(f"unknown checkpoint reason: {reason!r}")
        store = self._load_store()
        anchors: list[dict] = store["anchors"]
        events = self._read_verified_events()
        if not events:
            raise PublisherError("cannot anchor an empty journal")
        head_hash = events[-1]["event_hash"].lower()

        # Dedupe: same head already anchored -> return it, never duplicate.
        for record in reversed(anchors):
            if record["head_hash"] == head_hash and record["status"] in (
                "pending",
                "broadcast",
            ):
                if self.config.broadcast_enabled and record["status"] == "pending":
                    return self._broadcast_or_report(
                        store, record, raise_on_broadcast_failure
                    )
                return dict(record)

        last_broadcast = self._last_broadcast(anchors)
        if last_broadcast is not None:
            start_seq = last_broadcast["end_seq"] + 1
            prev_txid = last_broadcast["txid"]
            assert prev_txid is not None  # broadcast records always carry a txid
        else:
            start_seq = 1
            prev_txid = self.config.genesis_txid.lower()

        # create_anchor_payload re-verifies the journal and enforces
        # acceptance binding (fail-closed). start_seq > end_seq (journal
        # truncated below the last broadcast anchor) raises there.
        try:
            fields = create_anchor_payload(
                self.config.journal,
                start_seq=start_seq,
                prev_txid=prev_txid,
                manifests=self._load_manifests(),
                public_key=self.config.public_key,
            )
        except VerificationError as exc:
            raise PublisherError(f"anchor creation refused: {exc}") from exc
        if fields["head_hash"] != head_hash:  # pragma: no cover - defensive
            raise PublisherError("internal error: payload head does not match journal")

        # A stale prepared record for an older head is superseded: nothing
        # was ever broadcast for it, so the new anchor covers the full
        # range from the last broadcast anchor and chains to it.
        for record in anchors:
            if record["status"] == "pending":
                record["status"] = "superseded"

        record = {
            "payload_hex": fields["payload_hex"],
            "head_hash": fields["head_hash"],
            "start_seq": fields["start_seq"],
            "end_seq": fields["end_seq"],
            "release_seq": fields["release_seq"],
            "prev_txid": fields["prev_txid"],
            "status": "pending",
            "txid": None,
            "reason": reason,
            "created_at": self._clock(),
        }
        anchors.append(record)
        self._save_store(store)
        if self.config.broadcast_enabled:
            return self._broadcast_or_report(
                store, record, raise_on_broadcast_failure
            )
        return dict(record)

    def _broadcast_or_report(
        self, store: dict, record: dict, raise_on_broadcast_failure: bool
    ) -> dict:
        """Broadcast, or report the failure on the returned pending record."""
        try:
            return self._broadcast_record(store, record)
        except Exception as exc:  # noqa: BLE001 - broadcaster errors are reported, not hidden
            if raise_on_broadcast_failure:
                raise
            failed = dict(record)
            failed["broadcast_error"] = str(exc)
            return failed

    # -- offline signing ceremony (export / broadcast-signed) -----------

    @_locked
    def export_unsigned(
        self,
        *,
        funding_txid: str,
        funding_vout: int,
        change_address: str,
        fee_sats: int = 500,
        woc_base: str,
        network: str = "testnet",
        request_fn: Any = None,
    ) -> dict:
        """Build the unsigned anchor tx for the current head and stop.

        The offline-signing ceremony's handoff: the publisher prepares
        everything up to the signature and exports the unsigned tx hex.
        This method never signs and never broadcasts — it takes no
        signer and makes no POST. The caller writes ``unsigned_hex`` to
        the file the human carries to the signer, and cross-checks
        ``unsigned_txid`` + the payload summary against the signer's
        display.

        The funding UTXO must pay to ``change_address`` (the anchor
        address): the previous anchor's change output is the funding
        source, so a funding claim pointing elsewhere is operator error
        and fails here instead of producing an unusable unsigned tx.
        Mainnet is refused unconditionally.
        """
        if validate_network(network) != "testnet":
            raise PublisherError(
                "export-unsigned refuses mainnet: the offline-signing "
                "flow is testnet-only until a witnessed mainnet-key "
                "step exists"
            )
        record = self.build_checkpoint("scheduled")
        payload = bytes.fromhex(record["payload_hex"])
        try:
            script_hex, value = fetch_prev_output(
                woc_base, funding_txid, funding_vout, request_fn
            )
        except BroadcastError as exc:
            raise PublisherError(
                f"cannot fetch funding output: {exc}"
            ) from exc
        funding_script = bytes.fromhex(script_hex)
        if funding_script != build_p2pkh_script_for_address(
            change_address, network=network
        ):
            raise PublisherError(
                "funding UTXO does not pay to the change/anchor address: "
                "the funding outpoint must be the previous anchor's change"
            )
        try:
            unsigned = Tx.build_anchor_unsigned(
                funding=FundingUTXO(
                    txid=funding_txid,
                    vout=funding_vout,
                    value=value,
                    script_hex=script_hex,
                ),
                payload=payload,
                change_address=change_address,
                fee_sats=fee_sats,
                network=network,
            )
        except BroadcastError as exc:
            raise PublisherError(
                f"cannot build unsigned anchor tx: {exc}"
            ) from exc
        return {
            "unsigned_hex": unsigned.serialize().hex(),
            # Hash of the UNSIGNED tx. NOT the final txid: adding the
            # signature changes the bytes, so the broadcast txid will
            # differ. The human cross-checks this hash against the
            # signer's display, which binds approval to it.
            "unsigned_txid": unsigned.txid(),
            "payload": decode_anchor_payload(payload),
            "record": dict(record),
            "fee_sats": fee_sats,
            "change_address": change_address,
            "funding_txid": funding_txid,
            "funding_vout": funding_vout,
            "funding_value": value,
            "network": network,
        }

    @_locked
    def broadcast_signed(
        self,
        *,
        signed_hex: str,
        funding_txid: str,
        funding_vout: int,
        change_address: str,
        fee_sats: int = 500,
        woc_base: str,
        network: str = "testnet",
        request_fn: Any = None,
    ) -> dict:
        """Verify a human-signed anchor tx, then broadcast it.

        Verification rebuilds the expected unsigned tx fresh from the
        journal + record store (same inputs as :meth:`export_unsigned`)
        and requires: the signed tx, with its script_sig stripped,
        serializes byte-identically to the expected unsigned tx; the
        script_sig is exactly ``push(DER || SIGHASH_ALL|FORKID) +
        push(pubkey)``; the pubkey matches the funding output's P2PKH
        script; and the signature verifies against the FORKID sighash.
        Any mismatch refuses, with no broadcast. On success the
        canonical re-serialization of the verified tx is posted, so
        the recorded txid is exactly the broadcast tx's txid.

        A retry of the same signed tx is idempotent (the network
        answers already-known). A different signed tx for an
        already-broadcast head is refused.
        Mainnet is refused unconditionally.
        """
        if validate_network(network) != "testnet":
            raise PublisherError(
                "broadcast-signed refuses mainnet: the offline-signing "
                "flow is testnet-only until a witnessed mainnet-key "
                "step exists"
            )
        try:
            signed = parse_tx(bytes.fromhex(signed_hex))
        except ValueError as exc:
            raise PublisherError(f"signed tx does not decode: {exc}") from exc
        if len(signed.inputs) != 1:
            raise PublisherError(
                f"signed tx must have exactly 1 input, has {len(signed.inputs)}"
            )
        script_sig = signed.inputs[0].script_sig
        if not script_sig:
            raise PublisherError(
                "signed tx input has an empty script_sig: nothing was signed"
            )
        record = self.build_checkpoint("scheduled")
        payload = bytes.fromhex(record["payload_hex"])
        try:
            script_hex, value = fetch_prev_output(
                woc_base, funding_txid, funding_vout, request_fn
            )
        except BroadcastError as exc:
            raise PublisherError(
                f"cannot fetch funding output: {exc}"
            ) from exc
        funding_script = bytes.fromhex(script_hex)
        if funding_script != build_p2pkh_script_for_address(
            change_address, network=network
        ):
            raise PublisherError(
                "funding UTXO does not pay to the change/anchor address: "
                "the funding outpoint must be the previous anchor's change"
            )
        try:
            expected = Tx.build_anchor_unsigned(
                funding=FundingUTXO(
                    txid=funding_txid,
                    vout=funding_vout,
                    value=value,
                    script_hex=script_hex,
                ),
                payload=payload,
                change_address=change_address,
                fee_sats=fee_sats,
                network=network,
            )
        except BroadcastError as exc:
            raise PublisherError(
                f"cannot rebuild expected unsigned tx: {exc}"
            ) from exc
        stripped = Tx(
            version=signed.version,
            inputs=[
                TxIn(
                    signed.inputs[0].prev_txid,
                    signed.inputs[0].prev_index,
                    b"",
                    signed.inputs[0].sequence,
                )
            ],
            outputs=signed.outputs,
            locktime=signed.locktime,
        )
        if stripped.serialize() != expected.serialize():
            raise PublisherError(
                "signed tx does not match the expected unsigned tx: "
                "version, input outpoint, outputs, or locktime differ"
            )
        der, pubkey = _parse_anchor_script_sig(script_sig)
        if funding_script != build_p2pkh_script(pubkey):
            raise PublisherError(
                "signing pubkey does not match the funding output's "
                "locking script"
            )
        digest = sighash_forkid(expected, 0, funding_script, value)
        if not verify_sig(pubkey, digest, der):
            raise PublisherError(
                "anchor input signature does not verify against the "
                "funding output"
            )
        signed_txid = signed.txid()
        if record["status"] == "broadcast" and record["txid"] != signed_txid:
            raise PublisherError(
                f"head already broadcast as {record['txid']}, refusing "
                "a different tx for the same head"
            )
        canonical_hex = signed.serialize().hex()
        try:
            txid = post_raw_tx(
                woc_base, canonical_hex, request_fn, local_txid=signed_txid
            )
        except BroadcastError as exc:
            raise PublisherError(f"broadcast failed: {exc}") from exc
        if txid != signed_txid:
            raise PublisherError(
                f"broadcast returned txid {txid}, expected {signed_txid}: "
                "refusing to record a txid that is not the verified tx"
            )
        store = self._load_store()
        for stored in store["anchors"]:
            if stored["head_hash"] == record["head_hash"] and stored[
                "status"
            ] in ("pending", "broadcast"):
                stored["txid"] = txid
                stored["status"] = "broadcast"
                self._save_store(store)
                return dict(stored)
        raise PublisherError(  # pragma: no cover - store changed under lock
            "internal error: anchor record vanished after broadcast"
        )

    def on_release_accepted(self) -> dict:
        """Anchor immediately when a new release acceptance lands."""
        return self.build_checkpoint(reason="release")

    # -- scheduling ----------------------------------------------------

    @_locked
    def run_once(self, now: float | None = None) -> dict:
        """One scheduler tick.

        Returns ``{"action": "anchored"|"none", "reason": ..., "record": ...}``.
        Anchors when a new acceptance landed since the last anchor, or
        when the checkpoint interval elapsed since the last anchor, or
        (bootstrap) when no anchor exists yet. Otherwise a no-op. A
        malformed or unverifiable journal raises :class:`PublisherError`
        — the scheduler never silently skips a broken journal. A
        broadcast failure does NOT raise here: the anchor is already
        recorded as pending and the decision carries ``broadcast_error``;
        the next tick retries the same record (best-effort, protocol
        doc §8).
        """
        at = self._clock() if now is None else now
        store = self._load_store()
        anchors: list[dict] = store["anchors"]
        events = self._read_verified_events()
        if not events:
            return {"action": "none", "reason": "empty-journal", "record": None}

        head_hash = events[-1]["event_hash"].lower()
        last = anchors[-1] if anchors else None
        if last is not None and last["head_hash"] == head_hash:
            # A pending record whose broadcast failed is retried here:
            # without this, the scheduler would report "already-anchored"
            # forever and the anchor would never reach the chain.
            if self.config.broadcast_enabled and last["status"] == "pending":
                record = self.build_checkpoint(
                    reason=last["reason"], raise_on_broadcast_failure=False
                )
                return {
                    "action": "anchored",
                    "reason": last["reason"],
                    "record": record,
                    "broadcast_error": record.pop("broadcast_error", None),
                }
            return {"action": "none", "reason": "already-anchored", "record": dict(last)}

        if last is None:
            record = self.build_checkpoint(
                reason="scheduled", raise_on_broadcast_failure=False
            )
            return {
                "action": "anchored",
                "reason": "scheduled",
                "record": record,
                "broadcast_error": record.pop("broadcast_error", None),
            }

        # A new acceptance since the last anchor triggers immediately.
        covered = last["end_seq"]
        new_acceptance = any(
            event.get("event_type") == MANIFEST_ACCEPTED_EVENT_TYPE
            and isinstance(event.get("seq"), int)
            and event["seq"] > covered
            for event in events
        )
        if new_acceptance:
            record = self.build_checkpoint(
                reason="release", raise_on_broadcast_failure=False
            )
            return {
                "action": "anchored",
                "reason": "release",
                "record": record,
                "broadcast_error": record.pop("broadcast_error", None),
            }
        if at - last["created_at"] >= self.config.checkpoint_interval_seconds:
            record = self.build_checkpoint(
                reason="scheduled", raise_on_broadcast_failure=False
            )
            return {
                "action": "anchored",
                "reason": "scheduled",
                "record": record,
                "broadcast_error": record.pop("broadcast_error", None),
            }
        return {"action": "none", "reason": "interval-not-elapsed", "record": None}

    def run_loop(
        self,
        interval_seconds: int | None = None,
        max_iterations: int | None = None,
    ) -> list[dict]:
        """Run scheduler ticks until interrupted (or ``max_iterations``).

        ``max_iterations`` is a test / operator safety cap; ``None`` runs
        forever. Returns the list of tick decisions.
        """
        interval = (
            self.config.checkpoint_interval_seconds
            if interval_seconds is None
            else interval_seconds
        )
        if interval <= 0:
            raise PublisherError("loop interval must be positive")
        decisions: list[dict] = []
        count = 0
        while max_iterations is None or count < max_iterations:
            decisions.append(self.run_once())
            count += 1
            if max_iterations is not None and count >= max_iterations:
                break
            time.sleep(interval)
        return decisions
