"""Adversarial tests for the publisher record-store save path.

``Publisher._save_store`` writes through a unique ``.tmp`` path in the
same directory and then ``os.replace``s it over the store. These tests
probe the hazards the save path must resist:

* a symlink planted at the legacy predictable ``.tmp`` path;
* concurrent writers racing on the save path;
* interruption mid-save leaving a corrupt or unusable store.

Tests assert the secure behavior (never follow planted symlinks /
preserve old content on interruption / stay valid under concurrency), so
they fail against code that does not provide it -- the same
tests-first pattern as the keypair-output-paths review.
"""

import json
import threading

import pytest

from sealrun.publisher import Publisher, PublisherConfig


def _config(tmp_path, *, genesis="0" * 64):
    return PublisherConfig(
        journal=tmp_path / "audit.jsonl",
        anchor_record=tmp_path / "anchors.json",
        genesis_txid=genesis,
        checkpoint_interval_seconds=3600,
        broadcast_enabled=False,
        manifests=(),
        public_key=None,
        manifests_dir=None,
    )


def _store(*, marker=0, n_anchors=0):
    return {
        "genesis_txid": "0" * 64,
        "anchors": [{"marker": marker, "seq": i} for i in range(n_anchors)],
    }


def _tmp_path(tmp_path):
    store = tmp_path / "anchors.json"
    return store.with_suffix(store.suffix + ".tmp")


def test_save_ignores_symlink_at_legacy_tmp_path(tmp_path):
    """A symlink planted at the legacy predictable .tmp path is inert.

    Saves use a unique tmp name, so the planted symlink is never
    followed: the victim must be untouched and the save must succeed
    with the correct store.
    """
    victim = tmp_path / "victim.txt"
    victim.write_text("SENTINEL", encoding="utf-8")
    tmp = _tmp_path(tmp_path)
    tmp.symlink_to(victim)
    publisher = Publisher(_config(tmp_path))
    new = _store(marker=1)
    publisher._save_store(new)
    assert victim.read_text(encoding="utf-8") == "SENTINEL"
    assert publisher._load_store()["anchors"] == new["anchors"]


def test_save_ignores_tmp_symlink_to_store_path(tmp_path):
    """A .tmp symlink pointing at the store itself is never followed."""
    store_path = tmp_path / "anchors.json"
    old = _store(marker=7)
    store_path.write_text(json.dumps(old), encoding="utf-8")
    tmp = _tmp_path(tmp_path)
    tmp.symlink_to(store_path)
    publisher = Publisher(_config(tmp_path))
    new = _store(marker=8)
    publisher._save_store(new)
    assert not store_path.is_symlink()
    assert publisher._load_store()["anchors"] == new["anchors"]


def test_save_replaces_symlink_store_path(tmp_path):
    """A symlink *at* the store path is replaced, never followed.

    os.replace() renames over the destination symlink itself, so the
    symlink's target must be untouched and the store must become a
    regular file holding the new store.
    """
    victim = tmp_path / "victim.txt"
    victim.write_text("SENTINEL", encoding="utf-8")
    store_path = tmp_path / "anchors.json"
    store_path.symlink_to(victim)
    publisher = Publisher(_config(tmp_path))
    new = _store(marker=2)
    publisher._save_store(new)
    assert not store_path.is_symlink()
    assert json.loads(store_path.read_text(encoding="utf-8")) == new
    assert victim.read_text(encoding="utf-8") == "SENTINEL"


def test_concurrent_saves_never_tear_store(tmp_path):
    """Concurrent saves must leave one complete store, never torn JSON.

    Writers share one .tmp path, so interleaved writes could mix two
    stores. The final file must parse and equal exactly one writer's
    store -- a torn mix is a failure.
    """
    publisher = Publisher(_config(tmp_path))
    stores = [_store(marker=i, n_anchors=50) for i in range(8)]
    errors = []

    def _worker(store):
        try:
            for _ in range(10):
                publisher._save_store(store)
        except Exception as exc:  # noqa: BLE001 - collected, then asserted
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(s,)) for s in stores]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    final = json.loads((tmp_path / "anchors.json").read_text(encoding="utf-8"))
    assert final in stores


def test_interrupted_save_keeps_old_store(tmp_path, monkeypatch):
    """A crash between tmp write and replace must preserve the old store."""
    store_path = tmp_path / "anchors.json"
    old = _store(marker=3)
    store_path.write_text(json.dumps(old), encoding="utf-8")
    old_bytes = store_path.read_bytes()
    publisher = Publisher(_config(tmp_path))

    def _crash(_src, _dst):
        raise RuntimeError("simulated crash during replace")

    import os

    monkeypatch.setattr(os, "replace", _crash)
    with pytest.raises(RuntimeError, match="simulated crash"):
        publisher._save_store(_store(marker=4))
    assert store_path.read_bytes() == old_bytes
    assert publisher._load_store()["anchors"] == old["anchors"]

    # A later save must still succeed; the stale tmp must not poison it.
    monkeypatch.undo()
    publisher._save_store(_store(marker=5))
    assert publisher._load_store()["anchors"] == _store(marker=5)["anchors"]


def test_stale_tmp_from_crashed_save_does_not_break_next_save(tmp_path):
    """Garbage left in .tmp by a crashed run must not break the next save."""
    tmp = _tmp_path(tmp_path)
    tmp.write_text("{torn garbage", encoding="utf-8")
    publisher = Publisher(_config(tmp_path))
    new = _store(marker=6)
    publisher._save_store(new)
    assert publisher._load_store()["anchors"] == new["anchors"]
