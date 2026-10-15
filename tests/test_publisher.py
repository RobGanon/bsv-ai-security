"""Phase 2 publisher: anchor-on-release + scheduled checkpoints, dry-run by default.

Broadcast is disabled by default and no real broadcaster exists in this
build; tests use a recording stub and verify it is never called unless
broadcast is explicitly enabled with that stub supplied.
"""

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aiguard.cli import main
from aiguard.core import (
    VerificationError,
    append_audit_event,
    manifest_hash,
    record_manifest_acceptance,
    sign_manifest,
)
from aiguard.publisher import (
    Publisher,
    PublisherConfig,
    PublisherError,
)


def _envelope(key, release_seq, release_id):
    payload = {
        "schema": "aiguard-manifest-v1",
        "release_id": release_id,
        "release_seq": release_seq,
        "artifacts": [{"path": "a.txt", "sha256": "a" * 64, "size": 1}],
    }
    return sign_manifest(payload, key)


def _accept(journal, key, manifests, release_seq, release_id):
    envelope = _envelope(key, release_seq, release_id)
    manifests.append(envelope)
    return record_manifest_acceptance(
        journal, release_seq, release_id, manifest_hash(envelope)
    )


def _accept_to_dir(journal, key, directory, release_seq, release_id):
    """Record an acceptance whose envelope lives in the manifests dir.

    Mirrors the daemon flow: the operator drops the signed envelope into
    the directory, and the publisher picks it up at checkpoint time.
    """
    envelope = _envelope(key, release_seq, release_id)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{release_id}.json").write_text(
        json.dumps(envelope), encoding="utf-8"
    )
    return record_manifest_acceptance(
        journal, release_seq, release_id, manifest_hash(envelope)
    )


def _config(tmp_path, *, interval=3600, genesis="0" * 64, broadcast=False,
            manifests=(), public_key=None, manifests_dir=None):
    return PublisherConfig(
        journal=tmp_path / "audit.jsonl",
        anchor_record=tmp_path / "anchors.json",
        genesis_txid=genesis,
        checkpoint_interval_seconds=interval,
        broadcast_enabled=broadcast,
        manifests=tuple(manifests),
        public_key=public_key,
        manifests_dir=manifests_dir,
    )


class _FakeClock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        return self.now


class _StubBroadcaster:
    """Recording fake broadcaster: returns deterministic fake txids."""

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def broadcast(self, payload_hex):
        self.calls.append(payload_hex)
        if self.fail:
            raise PublisherError("simulated broadcast failure")
        # Fake txid: NOT a real transaction id, only a test placeholder.
        import hashlib

        return hashlib.sha256(("fake-broadcast:" + payload_hex).encode()).hexdigest()


def _read_store(tmp_path):
    return json.loads((tmp_path / "anchors.json").read_text(encoding="utf-8"))


# --- configuration / fail-closed construction ---


def test_broadcast_enabled_without_broadcaster_refuses(tmp_path):
    config = _config(tmp_path, broadcast=True)
    with pytest.raises(PublisherError, match="explicit broadcaster"):
        Publisher(config)


def test_bad_genesis_and_interval_rejected(tmp_path):
    with pytest.raises(PublisherError, match="genesis_txid"):
        _config(tmp_path, genesis="not-hex")
    with pytest.raises(PublisherError, match="positive integer"):
        _config(tmp_path, interval=0)


def test_genesis_mismatch_fails_closed(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    genesis_a, genesis_b = "a" * 64, "b" * 64
    Publisher(_config(tmp_path, genesis=genesis_a)).build_checkpoint("scheduled")
    with pytest.raises(PublisherError, match="genesis mismatch"):
        Publisher(_config(tmp_path, genesis=genesis_b)).build_checkpoint("scheduled")


def test_corrupt_record_store_fails_closed(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    (tmp_path / "anchors.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(PublisherError, match="unreadable|corrupt"):
        Publisher(_config(tmp_path)).build_checkpoint("scheduled")


# --- checkpoint basics + dedupe ---


def test_checkpoint_prepares_pending_anchor_chained_to_genesis(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    append_audit_event(journal, "test", "second")
    record = Publisher(_config(tmp_path)).build_checkpoint("scheduled")
    assert record["status"] == "pending"
    assert record["txid"] is None
    assert record["start_seq"] == 1
    assert record["end_seq"] == 2
    assert record["release_seq"] == 0
    assert record["prev_txid"] == "0" * 64
    assert len(bytes.fromhex(record["payload_hex"])) == 84
    store = _read_store(tmp_path)
    assert len(store["anchors"]) == 1


def test_no_duplicate_anchor_for_same_head(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    publisher = Publisher(_config(tmp_path))
    first = publisher.build_checkpoint("scheduled")
    second = publisher.build_checkpoint("scheduled")
    assert first == second
    assert len(_read_store(tmp_path)["anchors"]) == 1


def test_empty_journal_refuses(tmp_path):
    journal = tmp_path / "audit.jsonl"
    journal.write_text("", encoding="utf-8")
    with pytest.raises(PublisherError, match="empty journal"):
        Publisher(_config(tmp_path)).build_checkpoint("scheduled")


def test_missing_journal_refuses(tmp_path):
    with pytest.raises(PublisherError, match="cannot read journal"):
        Publisher(_config(tmp_path)).build_checkpoint("scheduled")


def test_pending_anchor_superseded_when_head_advances(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    publisher = Publisher(_config(tmp_path))
    first = publisher.build_checkpoint("scheduled")
    append_audit_event(journal, "test", "second")
    append_audit_event(journal, "test", "third")
    second = publisher.build_checkpoint("scheduled")
    assert second["start_seq"] == 1  # nothing broadcast: full range re-covered
    assert second["end_seq"] == 3
    assert second["prev_txid"] == "0" * 64
    store = _read_store(tmp_path)
    assert [a["status"] for a in store["anchors"]] == ["superseded", "pending"]
    assert store["anchors"][0]["payload_hex"] == first["payload_hex"]


# --- anchor-on-release ---


def test_on_release_fires_exactly_once_per_acceptance(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests_dir = tmp_path / "manifests"
    publisher = Publisher(
        _config(tmp_path, manifests_dir=manifests_dir,
                public_key=key.public_key())
    )
    _accept_to_dir(journal, key, manifests_dir, 5, "r-5")
    first = publisher.on_release_accepted()
    second = publisher.on_release_accepted()
    assert first == second
    assert first["release_seq"] == 5
    assert len(_read_store(tmp_path)["anchors"]) == 1
    # A second acceptance fires exactly one more anchor.
    _accept_to_dir(journal, key, manifests_dir, 7, "r-7")
    third = publisher.on_release_accepted()
    assert third["release_seq"] == 7
    assert third["payload_hex"] != first["payload_hex"]
    assert len(_read_store(tmp_path)["anchors"]) == 2


def test_missing_manifests_dir_contributes_no_envelopes(tmp_path):
    # A missing dir is not an error by itself: it contributes zero
    # envelopes. Binding still fails closed once an acceptance exists.
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    append_audit_event(journal, "test", "first")
    publisher = Publisher(
        _config(tmp_path, manifests_dir=tmp_path / "no-such-dir",
                public_key=key.public_key())
    )
    assert publisher.build_checkpoint("scheduled")["status"] == "pending"
    manifests = []
    _accept(journal, key, manifests, 5, "r-5")
    with pytest.raises(PublisherError, match="cannot verify acceptance binding"):
        publisher.build_checkpoint("scheduled")


def test_manifests_dir_path_that_is_a_file_fails_closed(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    not_a_dir = tmp_path / "not-a-dir.json"
    not_a_dir.write_text("{}", encoding="utf-8")
    publisher = Publisher(
        _config(tmp_path, manifests_dir=not_a_dir, public_key=None)
    )
    with pytest.raises(PublisherError, match="not a directory"):
        publisher.build_checkpoint("scheduled")


def test_acceptance_without_binding_inputs_fails_closed(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key, manifests, 5, "r-5")
    # Publisher was not given the manifests / public key to check against.
    with pytest.raises(VerificationError):
        Publisher(_config(tmp_path)).on_release_accepted()


# --- scheduled checkpoints ---


def test_scheduled_checkpoint_covers_tail_without_release(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    clock = _FakeClock()
    publisher = Publisher(_config(tmp_path, interval=3600), clock=clock)
    first = publisher.run_once()
    assert first["action"] == "anchored"
    # No new events, interval not elapsed: no-op.
    assert publisher.run_once()["action"] == "none"
    # Tail grows without any release; interval elapses -> scheduled anchor.
    append_audit_event(journal, "test", "second")
    append_audit_event(journal, "test", "third")
    clock.now += 1800
    assert publisher.run_once()["action"] == "none"
    clock.now += 1800
    decision = publisher.run_once()
    assert decision["action"] == "anchored"
    assert decision["reason"] == "scheduled"
    assert decision["record"]["end_seq"] == 3
    assert decision["record"]["release_seq"] == 0


def test_run_once_bootstrap_anchors_current_head(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    decision = Publisher(_config(tmp_path)).run_once()
    assert decision["action"] == "anchored"
    assert decision["record"]["end_seq"] == 1


def test_run_once_new_acceptance_triggers_before_interval(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    key = Ed25519PrivateKey.generate()
    manifests_dir = tmp_path / "manifests"
    clock = _FakeClock()
    publisher = Publisher(
        _config(tmp_path, interval=3600, manifests_dir=manifests_dir,
                public_key=key.public_key()),
        clock=clock,
    )
    assert publisher.run_once()["action"] == "anchored"
    _accept_to_dir(journal, key, manifests_dir, 9, "r-9")
    clock.now += 60  # far short of the interval
    decision = publisher.run_once()
    assert decision["action"] == "anchored"
    assert decision["reason"] == "release"
    assert decision["record"]["release_seq"] == 9


# --- broadcast path (stub only) ---


def test_broadcast_stub_never_called_when_disabled(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    stub = _StubBroadcaster()
    publisher = Publisher(_config(tmp_path, broadcast=False), broadcaster=stub)
    publisher.build_checkpoint("scheduled")
    publisher.run_once()
    assert stub.calls == []


def test_prev_txid_chains_to_previous_broadcast(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    stub = _StubBroadcaster()
    publisher = Publisher(
        _config(tmp_path, broadcast=True), broadcaster=stub
    )
    first = publisher.build_checkpoint("scheduled")
    assert first["status"] == "broadcast"
    assert first["txid"] == hashlib.sha256(
        ("fake-broadcast:" + first["payload_hex"]).encode()
    ).hexdigest()
    assert stub.calls == [first["payload_hex"]]
    append_audit_event(journal, "test", "second")
    second = publisher.build_checkpoint("scheduled")
    assert second["prev_txid"] == first["txid"]
    assert second["start_seq"] == first["end_seq"] + 1 == 2
    assert second["end_seq"] == 2


def test_broadcast_failure_leaves_pending_and_retries_without_duplicate(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    stub = _StubBroadcaster(fail=True)
    publisher = Publisher(_config(tmp_path, broadcast=True), broadcaster=stub)
    with pytest.raises(PublisherError, match="simulated broadcast failure"):
        publisher.build_checkpoint("scheduled")
    store = _read_store(tmp_path)
    assert len(store["anchors"]) == 1
    assert store["anchors"][0]["status"] == "pending"
    assert store["anchors"][0]["txid"] is None
    # Retry succeeds for the SAME record: no duplicate anchor.
    stub.fail = False
    record = publisher.build_checkpoint("scheduled")
    assert record["status"] == "broadcast"
    assert record["txid"] is not None
    assert len(_read_store(tmp_path)["anchors"]) == 1


def test_run_once_survives_broadcast_failure_and_retries(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    stub = _StubBroadcaster(fail=True)
    publisher = Publisher(_config(tmp_path, broadcast=True), broadcaster=stub)
    decision = publisher.run_once()
    assert decision["action"] == "anchored"
    assert decision["record"]["status"] == "pending"
    assert "simulated broadcast failure" in (decision["broadcast_error"] or "")
    # Next tick retries the SAME record instead of dying or duplicating.
    stub.fail = False
    decision = publisher.run_once()
    assert decision["record"]["status"] == "broadcast"
    assert len(_read_store(tmp_path)["anchors"]) == 1


def test_bad_broadcaster_txid_fails_closed(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")

    class _BadTxid:
        def broadcast(self, payload_hex):
            return "not-a-txid"

    with pytest.raises(PublisherError, match="broadcast txid"):
        Publisher(_config(tmp_path, broadcast=True),
                  broadcaster=_BadTxid()).build_checkpoint("scheduled")


# --- resume ---


def test_resume_after_restart_does_not_reanchor(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    Publisher(_config(tmp_path)).build_checkpoint("scheduled")
    # "Restart": a fresh Publisher on the same store + journal.
    publisher2 = Publisher(_config(tmp_path))
    assert publisher2.run_once()["action"] == "none"
    assert len(_read_store(tmp_path)["anchors"]) == 1


def test_resume_after_restart_with_new_events_anchors_once(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    clock = _FakeClock()
    Publisher(_config(tmp_path, interval=3600), clock=clock).run_once()
    append_audit_event(journal, "test", "second")
    clock.now += 3600
    publisher2 = Publisher(_config(tmp_path, interval=3600), clock=clock)
    decision = publisher2.run_once()
    assert decision["action"] == "anchored"
    assert len(_read_store(tmp_path)["anchors"]) == 2


# --- adversarial spot-checks (a)-(h) ---


def test_spotcheck_a_tampered_journal_refuses(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    publisher = Publisher(_config(tmp_path))
    publisher.build_checkpoint("scheduled")
    # Tamper: rewrite the event detail without updating the hash chain.
    text = journal.read_text(encoding="utf-8")
    journal.write_text(text.replace("first", "forgd"), encoding="utf-8")
    with pytest.raises(PublisherError, match="journal verification failed"):
        publisher.build_checkpoint("scheduled")


def test_spotcheck_b_no_duplicate_anchor_for_same_head(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    publisher = Publisher(_config(tmp_path))
    assert publisher.build_checkpoint("scheduled") == publisher.build_checkpoint("release")
    assert len(_read_store(tmp_path)["anchors"]) == 1


def test_spotcheck_c_on_release_fires_exactly_once(tmp_path):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests_dir = tmp_path / "manifests"
    publisher = Publisher(
        _config(tmp_path, manifests_dir=manifests_dir,
                public_key=key.public_key())
    )
    _accept_to_dir(journal, key, manifests_dir, 3, "r-3")
    records = [publisher.on_release_accepted() for _ in range(3)]
    assert records[0] == records[1] == records[2]
    assert len(_read_store(tmp_path)["anchors"]) == 1


def test_spotcheck_d_scheduled_covers_tail_without_release(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    clock = _FakeClock()
    publisher = Publisher(_config(tmp_path, interval=600), clock=clock)
    publisher.run_once()
    for i in range(3):
        append_audit_event(journal, "test", f"tail-{i}")
    clock.now += 600
    decision = publisher.run_once()
    assert decision["action"] == "anchored"
    assert decision["record"]["end_seq"] == 4
    assert decision["record"]["release_seq"] == 0


def test_spotcheck_e_prev_txid_chains_to_previous_anchor(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    stub = _StubBroadcaster()
    publisher = Publisher(_config(tmp_path, broadcast=True), broadcaster=stub)
    first = publisher.build_checkpoint("scheduled")
    append_audit_event(journal, "test", "second")
    append_audit_event(journal, "test", "third")
    second = publisher.build_checkpoint("scheduled")
    assert second["prev_txid"] == first["txid"]
    # Not an arbitrary value: it must equal the recorded broadcast txid.
    assert second["prev_txid"] != "0" * 64
    assert second["start_seq"] == 2


def test_spotcheck_f_broadcast_stub_never_called_when_disabled(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    stub = _StubBroadcaster()
    publisher = Publisher(_config(tmp_path), broadcaster=stub)
    publisher.build_checkpoint("scheduled")
    publisher.on_release_accepted()
    publisher.run_once()
    assert stub.calls == []


def test_spotcheck_g_resume_does_not_reanchor_same_range(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    append_audit_event(journal, "test", "second")
    Publisher(_config(tmp_path)).build_checkpoint("scheduled")
    restarted = Publisher(_config(tmp_path))
    assert restarted.run_once()["action"] == "none"
    assert restarted.build_checkpoint("scheduled")["end_seq"] == 2
    assert len(_read_store(tmp_path)["anchors"]) == 1


def test_spotcheck_h_malformed_journal_and_genesis_mismatch_fail_closed(tmp_path):
    journal = tmp_path / "audit.jsonl"
    journal.write_text("this is not jsonl\n", encoding="utf-8")
    with pytest.raises(PublisherError):
        Publisher(_config(tmp_path)).build_checkpoint("scheduled")
    # Genesis mismatch: store created under one genesis, run under another.
    journal.write_text("", encoding="utf-8")
    append_audit_event(journal, "test", "first")
    Publisher(_config(tmp_path, genesis="c" * 64)).build_checkpoint("scheduled")
    with pytest.raises(PublisherError, match="genesis mismatch"):
        Publisher(_config(tmp_path, genesis="d" * 64)).build_checkpoint("scheduled")


def test_truncated_journal_below_broadcast_anchor_fails_closed(tmp_path):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    append_audit_event(journal, "test", "second")
    stub = _StubBroadcaster()
    Publisher(_config(tmp_path, broadcast=True),
              broadcaster=stub).build_checkpoint("scheduled")
    # Truncate to a still-valid 1-event journal: below the broadcast anchor.
    first_line = journal.read_text(encoding="utf-8").splitlines()[0]
    journal.write_text(first_line + "\n", encoding="utf-8")
    with pytest.raises(PublisherError):
        Publisher(_config(tmp_path)).build_checkpoint("scheduled")


# --- CLI ---


def test_cli_publish_once_dry_run(tmp_path, capsys):
    journal = tmp_path / "audit.jsonl"
    record_file = tmp_path / "anchors.json"
    append_audit_event(journal, "test", "first")
    assert main([
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(record_file),
    ]) == 0
    output = capsys.readouterr().out
    assert "DRY RUN: broadcast disabled" in output
    assert '"action": "anchored"' in output
    assert json.loads(record_file.read_text(encoding="utf-8"))["anchors"][0]["status"] == "pending"


def test_cli_publish_broadcast_flag_fails_closed(tmp_path, capsys):
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    assert main([
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(tmp_path / "anchors.json"),
        "--broadcast",
    ]) == 1
    assert "no broadcaster" in capsys.readouterr().err


def test_cli_publish_on_release_with_binding(tmp_path, capsys):
    journal = tmp_path / "audit.jsonl"
    key = Ed25519PrivateKey.generate()
    manifests = []
    _accept(journal, key, manifests, 2, "r-2")
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(manifests[0]), encoding="utf-8")
    public_key_file = tmp_path / "public.pem"
    from cryptography.hazmat.primitives import serialization

    public_key_file.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    assert main([
        "publish",
        "--journal", str(journal),
        "--anchor-record", str(tmp_path / "anchors.json"),
        "--mode", "on-release",
        "--manifest", str(manifest_file),
        "--public-key", str(public_key_file),
    ]) == 0
    output = capsys.readouterr().out
    assert '"reason": "release"' in output
    assert "DRY RUN" in output
