"""Phase 2 publisher: anchor checkpoints on release acceptance + on schedule.

The publisher turns the anchoring design (``docs/anchoring-protocol.md``)
into running code, with one hard boundary: **broadcast is disabled by
default and no real broadcaster exists in this build**. By default the
publisher *prepares* anchor payloads and records them locally. Nothing
is signed, spent, or sent to any network unless the operator explicitly
enables broadcast *and* supplies a broadcaster (see :class:`NullBroadcaster`
and :func:`Publisher.__init__`).

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
  anchored returns the existing record.

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
- Anchor-chain continuity enforcement (issue #8): the publisher chains
  to the last broadcast txid it recorded, but does not independently
  validate a full on-chain chain from genesis — that verifier is
  future work.
- Transaction construction / signing / real broadcast: no BSV
  transaction is built here. Broadcast, when enabled, goes through a
  caller-supplied broadcaster object.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .anchor import ZERO_TXID, create_anchor_payload, decode_anchor_payload
from .core import HEX_64, VerificationError, _read_jsonl, _verify_audit_events

MANIFEST_ACCEPTED_EVENT_TYPE = "manifest_accepted"

RECORD_STATUSES = ("pending", "broadcast", "superseded")

# Sensible default: anchor at least hourly even with no new release.
DEFAULT_CHECKPOINT_INTERVAL_SECONDS = 3600


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
    """

    journal: Path
    anchor_record: Path
    genesis_txid: str = ZERO_TXID
    checkpoint_interval_seconds: int = DEFAULT_CHECKPOINT_INTERVAL_SECONDS
    broadcast_enabled: bool = False
    manifests: tuple[dict, ...] = ()
    public_key: Any = None
    manifests_dir: Path | None = None

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
        return {
            "genesis_txid": genesis.lower(),
            "anchors": [_validate_record(record) for record in anchors],
        }

    def _save_store(self, store: dict) -> None:
        path = self.config.anchor_record
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(store, indent=2, sort_keys=True) + "\n"
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)

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
                        envelope = json.loads(path.read_text(encoding="utf-8"))
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

    def on_release_accepted(self) -> dict:
        """Anchor immediately when a new release acceptance lands."""
        return self.build_checkpoint(reason="release")

    # -- scheduling ----------------------------------------------------

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
