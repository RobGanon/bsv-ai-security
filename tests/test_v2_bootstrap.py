"""Launch-flow v2 plan item 10: deployment-time bootstrap (§8).

At deployment time, while the network is available, the anchor chain is
authenticated with the item 8 anchor-only predicate and its bound
``manifest_accepted`` release sequence is written to the item 9 cache.
At launch time the launcher reads only that isolated cache: no network
call, and no value derived from launch/finish events.

The cache is append-only with a monotonic ``checkpoint_seq``; an appended
older checkpoint is refused. Truncating the file back to an older,
internally valid prefix remains undetectable without an external trusted
high-water mark. That residual is exercised and documented here rather
than hidden.
"""

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import sealrun.core as core
import sealrun.launcher as launcher
import sealrun.spv as spv
import sealrun.v2_anchor as v2_anchor
from sealrun.anchor import create_anchor_payload, encode_anchor_payload
from sealrun.bsv import PrivKey, Tx, TxIn, TxOut, build_op_return_script
from sealrun.checkpoint_cache import (
    anchored_release_seq,
    append_checkpoint_cache,
    assert_checkpoint_cache_isolation,
    bootstrap_checkpoint,
    read_checkpoint_cache,
    verify_checkpoint_against_journal,
)
from sealrun.cli import main
from sealrun.core import (
    V2_FINISH_EVENT_TYPE,
    V2_LAUNCH_EVENT_TYPE,
    VerificationError,
    append_v2_event,
    create_manifest,
    manifest_hash,
    read_journal_prefix,
    record_manifest_acceptance,
    sign_manifest,
)
from sealrun.launcher import launch
from sealrun.spv import HeaderChainResult, InclusionResult

GENESIS = "ab" * 32
PUBKEY = "02" + "11" * 32


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def launch_detail(run_id=None, nonce="a" * 32):
    return {
        "launch_mode": "v2",
        "run_id": run_id or "00000000-0000-4000-8000-000000000000",
        "journal_nonce": nonce,
        "manifest_hash": "b" * 64,
        "artifact_count": 1,
        "argv_fingerprint": "c" * 64,
        "env_fingerprint": "d" * 64,
        "executable": "true",
        "cwd": "/tmp",
        "seal": False,
        "uid": 12345,
        "gid": 12345,
    }


def finish_detail(run_id=None):
    return {
        "launch_mode": "v2",
        "run_id": run_id or "00000000-0000-4000-8000-000000000000",
        "exit_code": 0,
        "launcher_signal": 0,
        "escalated": False,
        "duration_ms": 1,
    }


def make_release(tmp_path: Path, manifest_seq: int = 10):
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    (root / "model.bin").write_bytes(b"model-v1")
    private = PrivKey.generate()
    payload = create_manifest(
        root, ["model.bin"], f"release-{manifest_seq}", manifest_seq
    )
    return root, sign_manifest(payload, private), private


def make_journal(
    tmp_path: Path,
    *,
    envelope: dict | None = None,
    accept_seq: int | None = None,
    finish: bool = False,
) -> Path:
    """A v2 journal with identity, optionally an acceptance/run events."""
    journal = tmp_path / "audit.jsonl"
    append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, launch_detail())
    if finish:
        append_v2_event(journal, V2_FINISH_EVENT_TYPE, finish_detail())
    if accept_seq is not None:
        assert envelope is not None
        record_manifest_acceptance(
            journal, accept_seq, f"release-{accept_seq}", manifest_hash(envelope)
        )
    return journal


def anchor_from_fields(fields: dict) -> tuple[dict, dict]:
    """Build an anchor entry plus the tx body committing to ``fields``."""
    payload = encode_anchor_payload(
        head_hash=fields["head_hash"],
        start_seq=fields["start_seq"],
        end_seq=fields["end_seq"],
        release_seq=fields["release_seq"],
        prev_txid=fields["prev_txid"],
    )
    script = build_op_return_script(payload)
    prev_txid = "cd" * 32
    tx = Tx(
        version=1,
        inputs=[TxIn(prev_txid, 0, b"", 0xFFFFFFFF)],
        outputs=[TxOut(0, script)],
        locktime=0,
    )
    txid = tx.txid()
    tx_json = {
        "version": 1,
        "locktime": 0,
        "vin": [
            {
                "txid": prev_txid,
                "vout": 0,
                "scriptSig": {"hex": ""},
                "sequence": 0xFFFFFFFF,
            }
        ],
        "vout": [
            {
                "value": "0.00000000",
                "scriptPubKey": {"hex": script.hex()},
            }
        ],
    }
    return {"payload_hex": payload.hex(), "txid": txid}, {txid: tx_json}


def make_anchors(
    journal: Path,
    *,
    manifests=None,
    public_key=None,
    release_override: int | None = None,
):
    fields = create_anchor_payload(
        journal,
        start_seq=1,
        prev_txid=GENESIS,
        manifests=manifests,
        public_key=public_key,
    )
    if release_override is not None:
        fields = dict(fields, release_seq=release_override)
    anchor, txs = anchor_from_fields(fields)
    return [anchor], txs


class FakePayloadFetcher:
    def __init__(self, by_txid):
        self.by_txid = by_txid

    def fetch_tx_full(self, txid):
        return self.by_txid[txid]


class FakeSignatureVerifier:
    def __init__(self, verified=True):
        self.verified = verified

    def verify_signature(self, txid):
        return SimpleNamespace(
            verified=self.verified,
            reason="fake signature",
            pubkey=PUBKEY,
        )


class FakeInclusionVerifier:
    def __init__(self, verified=True):
        self.verified = verified

    def verify_inclusion(self, txid):
        return InclusionResult(
            self.verified,
            txid,
            blockheight=10,
            blockhash="66" * 32,
            reason="fake inclusion",
        )


class FakeHeaderVerifier:
    def __init__(self, verified=True):
        self.verified = verified

    def verify_chain_for_tx(self, txid):
        return HeaderChainResult(
            self.verified,
            txid,
            tip_height=10,
            checkpoint_height=1,
            headers_checked=1,
            reason="fake header chain",
        )


def do_bootstrap(
    journal: Path,
    cache: Path,
    anchors,
    txs,
    *,
    manifests=None,
    public_key=None,
    header_verified=True,
):
    return bootstrap_checkpoint(
        journal,
        cache,
        anchors,
        GENESIS,
        payload_fetcher=FakePayloadFetcher(txs),
        signature_verifier=FakeSignatureVerifier(),
        inclusion="spv",
        inclusion_verifier=FakeInclusionVerifier(),
        header_verifier=FakeHeaderVerifier(header_verified),
        manifests=manifests,
        public_key=public_key,
        child_uid=65534,
        launcher_euid=0,
    )


@pytest.fixture
def isolated_cache(tmp_path, monkeypatch):
    """A cache path whose own directory passes the injected §5.7 checks."""
    monkeypatch.setattr(core, "_ancestor_directories", lambda path: [])
    monkeypatch.setattr(core, "_filesystem_type", lambda path: "btrfs")
    parent = tmp_path / "isolated"
    parent.mkdir(mode=0o700)
    return parent / "checkpoint.jsonl"


class Spy:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, *, pass_fds=(), env=None, user=None, group=None,
                 extra_groups=None, check=False):
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0)


def install_spy(monkeypatch, spy):
    def run_v2_child(argv, *, pass_fds, child_env, uid, gid, drop_groups, signals):
        completed = spy(
            argv, pass_fds=pass_fds, env=child_env, user=uid, group=gid,
            extra_groups=drop_groups, check=False,
        )
        return launcher._V2RunResult(completed.returncode, 0, False)

    monkeypatch.setattr(launcher, "_run_v2_child", run_v2_child)
    monkeypatch.setattr(
        launcher, "assert_journal_writer_isolation", lambda *args, **kwargs: None
    )


# --------------------------------------------------------------------------
# bootstrap: online verification records the bound checkpoint
# --------------------------------------------------------------------------

def test_bootstrap_authenticates_anchor_chain_and_records_bound_checkpoint(
    tmp_path, isolated_cache
):
    _root, envelope, private = make_release(tmp_path, 10)
    public = private.pubkey_compressed()
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(
        journal, manifests=[envelope], public_key=public
    )

    result = do_bootstrap(
        journal,
        isolated_cache,
        anchors,
        txs,
        manifests=[envelope],
        public_key=public,
    )

    record = result["checkpoint"]
    assert result["acceptance"]["accepted"] is True
    assert record["release_seq"] == 10
    assert record["checkpoint_seq"] == 1
    assert record["anchor_end_seq"] == len(read_journal_prefix(journal)[0])
    assert read_checkpoint_cache(isolated_cache) == record

    events, _fragment = read_journal_prefix(journal)
    assert anchored_release_seq(events, record["anchor_end_seq"]) == 10
    # The record is still bound to the journal prefix it was derived from.
    assert verify_checkpoint_against_journal(record, journal) == 10


def test_bootstrap_writes_checkpoint_for_a_clean_run_state_journal(
    tmp_path, isolated_cache
):
    private = PrivKey.generate()
    root = tmp_path / "root2"
    root.mkdir()
    (root / "model.bin").write_bytes(b"model-v2")
    payload = create_manifest(root, ["model.bin"], "release-0", 0)
    envelope = sign_manifest(payload, private)
    journal = make_journal(tmp_path, envelope=envelope, finish=True)
    fields = create_anchor_payload(
        journal,
        start_seq=1,
        prev_txid=GENESIS,
        manifests=None,
        public_key=None,
    )
    anchor, txs = anchor_from_fields(fields)

    result = do_bootstrap(journal, isolated_cache, [anchor], txs)

    assert result["checkpoint"]["release_seq"] == 0
    assert result["checkpoint"]["anchor_end_seq"] == 2


def test_launch_reads_only_the_bootstrapped_cache_and_makes_no_network_call(
    tmp_path, isolated_cache, monkeypatch
):
    root, envelope, private = make_release(tmp_path, 10)
    public = private.pubkey_compressed()
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(journal, manifests=[envelope], public_key=public)
    do_bootstrap(
        journal,
        isolated_cache,
        anchors,
        txs,
        manifests=[envelope],
        public_key=public,
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("launch must not use the network")

    monkeypatch.setattr(v2_anchor, "verify_v2_anchor_chain", forbidden)
    monkeypatch.setattr(spv, "WoCBlockFetcher", forbidden)
    spy = Spy()
    install_spy(monkeypatch, spy)

    assert launch(
        root,
        envelope,
        public,
        ["true"],
        mode="v2",
        journal=journal,
        uid=12345,
        gid=12345,
        min_release_seq=10,
        checkpoint_cache=isolated_cache,
    ) == 0
    assert len(spy.calls) == 1


def test_seq_at_or_above_the_bootstrapped_checkpoint_launches_below_refuses(
    tmp_path, isolated_cache, monkeypatch
):
    root, envelope, private = make_release(tmp_path, 10)
    public = private.pubkey_compressed()
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(journal, manifests=[envelope], public_key=public)
    do_bootstrap(
        journal,
        isolated_cache,
        anchors,
        txs,
        manifests=[envelope],
        public_key=public,
    )
    spy = Spy()
    install_spy(monkeypatch, spy)

    assert launch(
        root, envelope, public, ["true"], mode="v2", journal=journal,
        uid=12345, gid=12345, min_release_seq=10,
        checkpoint_cache=isolated_cache,
    ) == 0

    below_root, below_envelope, below_private = make_release(tmp_path, 9)
    with pytest.raises(VerificationError, match="below the anchored release checkpoint 10"):
        launch(
            below_root,
            below_envelope,
            below_private.pubkey_compressed(),
            ["true"],
            mode="v2",
            journal=journal,
            uid=12345,
            gid=12345,
            min_release_seq=9,
            checkpoint_cache=isolated_cache,
        )
    assert len(spy.calls) == 1


def test_missing_min_release_seq_refuses_in_v2_mode(
    tmp_path, isolated_cache, monkeypatch
):
    root, envelope, private = make_release(tmp_path, 10)
    public = private.pubkey_compressed()
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(journal, manifests=[envelope], public_key=public)
    do_bootstrap(
        journal, isolated_cache, anchors, txs,
        manifests=[envelope], public_key=public,
    )
    spy = Spy()
    install_spy(monkeypatch, spy)

    with pytest.raises(VerificationError, match="requires --min-release-seq"):
        launch(
            root, envelope, public, ["true"], mode="v2", journal=journal,
            uid=12345, gid=12345, min_release_seq=None,
            checkpoint_cache=isolated_cache,
        )
    assert spy.calls == []


# --------------------------------------------------------------------------
# refusals: withheld authentication, unbound or non-acceptance advances
# --------------------------------------------------------------------------

def test_bootstrap_refuses_a_withheld_anchor_predicate(tmp_path, isolated_cache):
    private = PrivKey.generate()
    root = tmp_path / "root3"
    root.mkdir()
    (root / "model.bin").write_bytes(b"model")
    payload = create_manifest(root, ["model.bin"], "release-10", 10)
    envelope = sign_manifest(payload, private)
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(
        journal, manifests=[envelope], public_key=private.pubkey_compressed()
    )

    with pytest.raises(VerificationError, match="authentication withheld"):
        do_bootstrap(
            journal, isolated_cache, anchors, txs,
            manifests=[envelope], public_key=private.pubkey_compressed(),
            header_verified=False,
        )
    assert not isolated_cache.exists()


def test_bootstrap_refuses_an_anchored_acceptance_without_manifest_binding(
    tmp_path, isolated_cache
):
    envelope = make_release(tmp_path, 10)[1]
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    events, _fragment = read_journal_prefix(journal)
    fields = {
        "head_hash": events[-1]["event_hash"],
        "start_seq": 1,
        "end_seq": len(events),
        "release_seq": 10,
        "prev_txid": GENESIS,
    }
    anchor, txs = anchor_from_fields(fields)

    with pytest.raises(VerificationError, match="not supplied to prove the acceptance binding"):
        do_bootstrap(journal, isolated_cache, [anchor], txs)
    assert not isolated_cache.exists()


def test_launch_and_finish_events_do_not_advance_the_anchored_checkpoint(
    tmp_path, isolated_cache
):
    journal = make_journal(tmp_path, finish=True)
    events, _fragment = read_journal_prefix(journal)
    # A forged anchor claims release 5 even though the prefix contains only
    # launch/finish events, so the bound derivation must still be 0.
    fields = {
        "head_hash": events[-1]["event_hash"],
        "start_seq": 1,
        "end_seq": len(events),
        "release_seq": 5,
        "prev_txid": GENESIS,
    }
    anchor, txs = anchor_from_fields(fields)

    with pytest.raises(VerificationError, match="max bound manifest_accepted sequence \\(0\\)"):
        do_bootstrap(journal, isolated_cache, [anchor], txs)
    assert not isolated_cache.exists()


def test_bootstrap_refuses_an_anchor_whose_release_seq_lies_about_binding(
    tmp_path, isolated_cache
):
    private = PrivKey.generate()
    root = tmp_path / "root4"
    root.mkdir()
    (root / "model.bin").write_bytes(b"model")
    payload = create_manifest(root, ["model.bin"], "release-10", 10)
    envelope = sign_manifest(payload, private)
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(
        journal,
        manifests=[envelope],
        public_key=private.pubkey_compressed(),
        release_override=11,
    )

    with pytest.raises(VerificationError, match="does not match the journal-derived"):
        do_bootstrap(
            journal, isolated_cache, anchors, txs,
            manifests=[envelope], public_key=private.pubkey_compressed(),
        )
    assert not isolated_cache.exists()


# --------------------------------------------------------------------------
# §5.7 isolation for the cache store
# --------------------------------------------------------------------------

def make_safe_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "_ancestor_directories", lambda path: [])
    monkeypatch.setattr(core, "_filesystem_type", lambda path: "btrfs")
    parent = tmp_path / "store"
    parent.mkdir(mode=0o700)
    return parent / "checkpoint.jsonl"


def test_cache_isolation_accepts_a_safe_placement(tmp_path, monkeypatch):
    cache = make_safe_cache(tmp_path, monkeypatch)
    assert_checkpoint_cache_isolation(cache, 65534, launcher_euid=0)


def test_cache_isolation_refuses_unprivileged_deployment(tmp_path, monkeypatch):
    cache = make_safe_cache(tmp_path, monkeypatch)
    with pytest.raises(VerificationError, match="privileged launcher"):
        assert_checkpoint_cache_isolation(cache, 65534, launcher_euid=1000)


def test_cache_isolation_refuses_missing_or_root_child_uid(tmp_path, monkeypatch):
    cache = make_safe_cache(tmp_path, monkeypatch)
    with pytest.raises(VerificationError, match="requires --uid"):
        assert_checkpoint_cache_isolation(cache, None, launcher_euid=0)
    with pytest.raises(VerificationError, match="uid of 0"):
        assert_checkpoint_cache_isolation(cache, 0, launcher_euid=0)


def test_cache_isolation_refuses_a_child_owned_path(tmp_path, monkeypatch):
    cache = make_safe_cache(tmp_path, monkeypatch)
    cache.write_text("", encoding="utf-8")
    with pytest.raises(VerificationError, match="owned by the child uid"):
        assert_checkpoint_cache_isolation(
            cache, os.getuid(), launcher_euid=0
        )


def test_cache_isolation_refuses_group_or_world_writable_paths(
    tmp_path, monkeypatch
):
    cache = make_safe_cache(tmp_path, monkeypatch)
    cache.write_text("", encoding="utf-8")
    cache.chmod(0o666)
    with pytest.raises(VerificationError, match="group- or world-writable"):
        assert_checkpoint_cache_isolation(cache, 65534, launcher_euid=0)

    cache.chmod(0o600)
    cache.parent.chmod(0o777)
    with pytest.raises(VerificationError, match="group- or world-writable"):
        assert_checkpoint_cache_isolation(cache, 65534, launcher_euid=0)


def test_cache_isolation_refuses_missing_parent_symlink_and_acl(
    tmp_path, monkeypatch
):
    missing = tmp_path / "absent" / "checkpoint.jsonl"
    with pytest.raises(VerificationError, match="must already exist"):
        assert_checkpoint_cache_isolation(missing, 65534, launcher_euid=0)

    cache = make_safe_cache(tmp_path, monkeypatch)
    cache.symlink_to(tmp_path / "real.jsonl")
    with pytest.raises(VerificationError, match="symlink"):
        assert_checkpoint_cache_isolation(cache, 65534, launcher_euid=0)

    cache.unlink()
    cache.write_text("", encoding="utf-8")

    def fake_getxattr(path, name):
        if name in core._ACL_XATTRS:
            return b"acl"
        raise OSError(61, "No data")

    monkeypatch.setattr(core.os, "getxattr", fake_getxattr)
    with pytest.raises(VerificationError, match="ACL"):
        assert_checkpoint_cache_isolation(cache, 65534, launcher_euid=0)


def test_cache_isolation_refuses_a_writable_ancestor(tmp_path, monkeypatch):
    cache = make_safe_cache(tmp_path, monkeypatch)
    bad = tmp_path / "ancestor"
    bad.mkdir()
    bad.chmod(0o777)
    monkeypatch.setattr(core, "_ancestor_directories", lambda path: [bad])
    with pytest.raises(VerificationError, match="checkpoint cache ancestor"):
        assert_checkpoint_cache_isolation(cache, 65534, launcher_euid=0)


@pytest.mark.parametrize("filesystem", ["nfs", "nfs4", "fuse", "cifs", None])
def test_cache_isolation_refuses_non_ownership_enforcing_filesystems(
    tmp_path, monkeypatch, filesystem
):
    cache = make_safe_cache(tmp_path, monkeypatch)
    monkeypatch.setattr(core, "_filesystem_type", lambda path: filesystem)
    with pytest.raises(VerificationError, match="filesystem type"):
        assert_checkpoint_cache_isolation(cache, 65534, launcher_euid=0)


# --------------------------------------------------------------------------
# append-only rollback and the stated truncation residual
# --------------------------------------------------------------------------

def test_bootstrap_refuses_to_append_an_older_checkpoint(
    tmp_path, isolated_cache
):
    private = PrivKey.generate()
    root = tmp_path / "root5"
    root.mkdir()
    (root / "model.bin").write_bytes(b"model")
    payload = create_manifest(root, ["model.bin"], "release-10", 10)
    envelope = sign_manifest(payload, private)
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(
        journal, manifests=[envelope], public_key=private.pubkey_compressed()
    )
    do_bootstrap(
        journal, isolated_cache, anchors, txs,
        manifests=[envelope], public_key=private.pubkey_compressed(),
    )

    events, _fragment = read_journal_prefix(journal)
    # An earlier anchored prefix (before the acceptance) genuinely derives
    # release_seq 0, so it passes the anchor predicate but must still be
    # refused when appended after the cache already holds 10.
    older_fields = {
        "head_hash": events[0]["event_hash"],
        "start_seq": 1,
        "end_seq": 1,
        "release_seq": 0,
        "prev_txid": GENESIS,
    }
    older_anchor, older_txs = anchor_from_fields(older_fields)
    with pytest.raises(VerificationError, match="older than the cache's current release_seq"):
        do_bootstrap(
            journal, isolated_cache, [older_anchor], older_txs,
            manifests=[envelope], public_key=private.pubkey_compressed(),
        )


def test_truncation_to_an_older_internally_valid_prefix_is_a_stated_residual(
    tmp_path, isolated_cache
):
    """The cache detects appended rollback, not truncation.

    This test pins the limitation stated in checkpoint_cache.py and
    docs/launcher.md: an attacker who can rewrite the cache file can
    present an older valid prefix. Only an external trusted high-water
    mark closes it.
    """
    journal = make_journal(tmp_path)
    envelope = make_release(tmp_path, 10)[1]
    record_manifest_acceptance(
        journal, 10, "release-10", manifest_hash(envelope)
    )
    events, _fragment = read_journal_prefix(journal)
    prefix_end = len(events) - 1

    append_checkpoint_cache(
        isolated_cache,
        release_seq=0,
        anchor_end_seq=prefix_end,
        head_hash=events[prefix_end - 1]["event_hash"],
    )
    append_checkpoint_cache(
        isolated_cache,
        release_seq=10,
        anchor_end_seq=len(events),
        head_hash=events[-1]["event_hash"],
    )
    newest = read_checkpoint_cache(isolated_cache)
    assert newest["release_seq"] == 10

    lines = isolated_cache.read_text(encoding="utf-8").splitlines(keepends=True)
    isolated_cache.write_text(lines[0], encoding="utf-8")

    truncated = read_checkpoint_cache(isolated_cache)
    assert truncated["release_seq"] == 0
    assert verify_checkpoint_against_journal(truncated, journal) == 0


# --------------------------------------------------------------------------
# CLI surface
# --------------------------------------------------------------------------

def test_cli_bootstrap_validates_the_required_predicate_inputs(tmp_path, capsys):
    journal = make_journal(tmp_path)
    cache = tmp_path / "checkpoint.jsonl"
    rc = main([
        "checkpoint-bootstrap",
        "--journal", str(journal),
        "--checkpoint-cache", str(cache),
        "--genesis-txid", GENESIS,
        "--uid", "12345",
    ])
    assert rc == 1
    error = capsys.readouterr().err
    assert "at least one --anchor" in error
