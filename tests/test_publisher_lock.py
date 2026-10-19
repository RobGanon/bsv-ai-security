"""Flow-level lock for the publisher record store.

Without a lock across load-modify-save, two publishers racing on the
same store interleave: both load the same snapshot, both append their
own record, and the second save silently overwrites the first's —
lost updates, or duplicate anchors for one journal head. These tests
probe the lock that closes that gap:

* threads racing build_checkpoint: exactly one anchor, no lost update;
* separate processes racing build_checkpoint: same, across flock;
* a stuck holder fails the waiter closed on timeout, not a hang;
* a symlink planted at the lock path is never followed;
* the lock is released when the holder raises, and re-entry
  (run_once -> build_checkpoint) does not deadlock.
"""

import json
import multiprocessing
import threading

import pytest
from sealrun.bsv import PrivKey

from sealrun.core import (
    manifest_hash,
    record_manifest_acceptance,
    sign_manifest,
)
from sealrun.publisher import (
    Publisher,
    PublisherConfig,
    PublisherError,
)


def _envelope(key, release_seq, release_id):
    payload = {
        "schema": "sealrun-manifest-v1",
        "release_id": release_id,
        "release_seq": release_seq,
        "artifacts": [{"path": "a.txt", "sha256": "a" * 64, "size": 1}],
    }
    return sign_manifest(payload, key)


def _config(tmp_path, *, key, manifests, lock_timeout=30.0):
    return PublisherConfig(
        journal=tmp_path / "audit.jsonl",
        anchor_record=tmp_path / "anchors.json",
        genesis_txid="0" * 64,
        checkpoint_interval_seconds=3600,
        broadcast_enabled=False,
        manifests=tuple(manifests),
        public_key=key.pubkey_compressed(),
        manifests_dir=None,
        lock_timeout_seconds=lock_timeout,
    )


def _seed_journal(tmp_path):
    """One acceptance in the journal; return (key, manifests)."""
    key = PrivKey.generate()
    manifests = []
    envelope = _envelope(key, 1, "r1")
    manifests.append(envelope)
    record_manifest_acceptance(
        tmp_path / "audit.jsonl", 1, "r1", manifest_hash(envelope)
    )
    return key, manifests


def _read_store(tmp_path):
    return json.loads((tmp_path / "anchors.json").read_text(encoding="utf-8"))


def test_threads_racing_build_checkpoint_emit_one_anchor(tmp_path):
    """8 threads, one publisher: exactly one anchor, no lost update."""
    key, manifests = _seed_journal(tmp_path)
    publisher = Publisher(_config(tmp_path, key=key, manifests=manifests))
    results, errors = [], []

    def work():
        try:
            results.append(publisher.build_checkpoint(reason="release"))
        except Exception as exc:  # noqa: BLE001 - collected, asserted below
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(results) == 8
    assert len({r["payload_hex"] for r in results}) == 1
    assert len(_read_store(tmp_path)["anchors"]) == 1
    lock_path = tmp_path / "anchors.json.lock"
    assert lock_path.is_file() and not lock_path.is_symlink()


def _child_build(tmp_path, key, manifests, queue, barrier):
    try:
        barrier.wait(timeout=30)
        publisher = Publisher(
            PublisherConfig(
                journal=tmp_path / "audit.jsonl",
                anchor_record=tmp_path / "anchors.json",
                genesis_txid="0" * 64,
                checkpoint_interval_seconds=3600,
                broadcast_enabled=False,
                manifests=tuple(manifests),
                public_key=key.pubkey_compressed(),
                manifests_dir=None,
            )
        )
        queue.put(("ok", publisher.build_checkpoint(reason="release")))
    except Exception as exc:  # noqa: BLE001 - reported to the parent
        queue.put(("error", repr(exc)))


def test_processes_building_concurrently_complete_without_deadlock(tmp_path):
    """4 separate processes: no deadlock, one anchor total.

    NOTE: this test alone cannot prove the lock works — all four
    children build the identical record for one journal head, so a
    last-writer-wins race would still leave one (identical) anchor.
    It guards the other direction: the lock must not hang or break
    concurrent publishers. The race itself is proven by
    ``test_lock_serializes_processes`` below.
    """
    key, manifests = _seed_journal(tmp_path)
    ctx = multiprocessing.get_context("fork")
    queue = ctx.Queue()
    # Barrier: all children hit build_checkpoint at the same instant, so
    # the race is real rather than staggered by spawn timing.
    barrier = ctx.Barrier(4)
    procs = [
        ctx.Process(
            target=_child_build, args=(tmp_path, key, manifests, queue, barrier)
        )
        for _ in range(4)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        assert not p.is_alive(), "child publisher hung"
    outcomes = [queue.get() for _ in range(4)]
    assert [o[0] for o in outcomes] == ["ok"] * 4
    assert len({o[1]["payload_hex"] for o in outcomes}) == 1
    assert len(_read_store(tmp_path)["anchors"]) == 1


def _child_increment(tmp_path, queue, barrier):
    """One locked read-modify-write of a shared counter."""
    import time as _time

    try:
        barrier.wait(timeout=30)
        publisher = Publisher(
            PublisherConfig(
                journal=tmp_path / "audit.jsonl",
                anchor_record=tmp_path / "anchors.json",
            )
        )
        counter = tmp_path / "counter.txt"
        with publisher._locked_store():
            # Sleep inside the critical section: without the lock, all
            # children read 0 before any writes, and updates are lost.
            n = int(counter.read_text(encoding="utf-8"))
            _time.sleep(0.05)
            counter.write_text(str(n + 1), encoding="utf-8")
        queue.put("ok")
    except Exception as exc:  # noqa: BLE001 - reported to the parent
        queue.put(f"error: {exc!r}")


def test_lock_serializes_processes(tmp_path):
    """4 processes, locked read-modify-write: counter reaches exactly 4.

    The sleep inside the critical section makes the race
    deterministic: without the lock every child reads 0 and the final
    count is 1 (lost updates). With the lock it is 4.
    """
    (tmp_path / "counter.txt").write_text("0", encoding="utf-8")
    ctx = multiprocessing.get_context("fork")
    queue = ctx.Queue()
    barrier = ctx.Barrier(4)
    procs = [
        ctx.Process(target=_child_increment, args=(tmp_path, queue, barrier))
        for _ in range(4)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        assert not p.is_alive(), "child publisher hung"
    assert [queue.get() for _ in range(4)] == ["ok"] * 4
    assert (tmp_path / "counter.txt").read_text(encoding="utf-8") == "4"


def test_waiter_times_out_instead_of_hanging(tmp_path):
    """A stuck holder fails the waiter closed on timeout."""
    key, manifests = _seed_journal(tmp_path)
    publisher = Publisher(
        _config(tmp_path, key=key, manifests=manifests, lock_timeout=0.2)
    )
    errors = []

    def waiter():
        try:
            publisher.build_checkpoint(reason="release")
        except PublisherError as exc:
            errors.append(str(exc))

    with publisher._locked_store():
        t = threading.Thread(target=waiter)
        t.start()
        t.join(timeout=30)
        assert not t.is_alive(), "waiter hung past its timeout"
    assert len(errors) == 1 and "timed out" in errors[0]
    # The holder released: a later build succeeds.
    assert publisher.build_checkpoint(reason="release")["status"] == "pending"


def test_symlink_at_lock_path_refused(tmp_path):
    """A symlink planted at <store>.lock is never followed."""
    key, manifests = _seed_journal(tmp_path)
    victim = tmp_path / "victim.txt"
    victim.write_text("SENTINEL", encoding="utf-8")
    (tmp_path / "anchors.json.lock").symlink_to(victim)
    publisher = Publisher(_config(tmp_path, key=key, manifests=manifests))
    with pytest.raises(PublisherError, match="non-symlink"):
        publisher.build_checkpoint(reason="release")
    assert victim.read_text(encoding="utf-8") == "SENTINEL"


def test_lock_released_when_holder_raises(tmp_path):
    """An exception inside the critical section must not stick the lock."""
    key, manifests = _seed_journal(tmp_path)
    publisher = Publisher(_config(tmp_path, key=key, manifests=manifests))
    with pytest.raises(PublisherError, match="boom"):
        with publisher._locked_store():
            raise PublisherError("boom")
    with publisher._locked_store():
        pass  # re-entry succeeds: the lock was released


def test_run_once_reentry_does_not_deadlock(tmp_path):
    """run_once -> build_checkpoint nests the lock without deadlocking."""
    key, manifests = _seed_journal(tmp_path)
    publisher = Publisher(_config(tmp_path, key=key, manifests=manifests))
    first = publisher.run_once()
    assert first["action"] == "anchored"
    second = publisher.run_once()
    assert second["action"] == "none"
    assert second["reason"] == "already-anchored"
    assert len(_read_store(tmp_path)["anchors"]) == 1
