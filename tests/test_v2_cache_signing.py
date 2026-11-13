"""Finding #1 fix: checkpoint-cache record signing (design A+, §5).

The checkpoint cache was an unkeyed local file: any structurally valid,
journal-consistent record was trusted, so a hand-written zero record
(``anchor_end_seq 0``, zero ``head_hash``, ``release_seq 0``) "verified"
against any journal and reset the checkpoint. The fix signs every record
with HMAC-SHA256 under a deployment key stored beside the cache, and
carries the journal's v2 identity inside the signed payload.

These tests pin the approved behaviour (§5.6):

- the #1 repro is refused: a hand-written zero record, a record with a
  valid identity but no/bogus MAC, and a record signed for journal A
  presented against journal B;
- the legitimate flows still work: bootstrap writes signed records, a
  cached launch accepts them, re-bootstrap appends a second signed
  record, and a legitimate checkpoint-0 bootstrap writes a *signed* 0
  record;
- the negative cases refuse: tampering with any signed field, a missing
  key file, a wrong key, a pre-fix unsigned cache (re-bootstrap named as
  the remedy), and bootstrap on an unseeded journal.

The launch-level tests stand in for the v2 child runner exactly as
``tests/test_v2_rollback.py`` does, and the §5.7 isolation predicate is
bypassed only where a real privileged launcher would be required.
"""

import json
import secrets
import stat
import subprocess
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

import sealrun.core as core
import sealrun.launcher as launcher
from sealrun.anchor import create_anchor_payload, encode_anchor_payload
from sealrun.bsv import PrivKey, Tx, TxIn, TxOut, build_op_return_script
from sealrun.checkpoint_cache import (
    _read_records,
    append_checkpoint_cache,
    bootstrap_checkpoint,
    cache_key_path,
    compute_record_mac,
    load_cache_key,
    read_checkpoint_cache,
    verify_checkpoint_against_journal,
    write_cache_key,
)
from sealrun.core import (
    V2_LAUNCH_EVENT_TYPE,
    V2_LAUNCH_FAILED_EVENT_TYPE,
    VerificationError,
    append_audit_event,
    append_v2_event,
    canonical_json_bytes,
    create_manifest,
    journal_genesis_identity,
    manifest_hash,
    read_journal_prefix,
    record_manifest_acceptance,
    sign_manifest,
    verify_audit_journal,
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


def seed_launch_event(journal: Path, *, nonce: str = "a" * 32) -> dict:
    """Append a minimal valid v2_launch event, as a completed launch would."""
    return append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, launch_detail(nonce=nonce))


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
    nonce: str = "a" * 32,
    envelope: dict | None = None,
    accept_seq: int | None = None,
) -> Path:
    """A seeded v2 journal, optionally with one bound acceptance."""
    journal = tmp_path / "audit.jsonl"
    seed_launch_event(journal, nonce=nonce)
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


def make_anchors(journal: Path, *, manifests=None, public_key=None):
    fields = create_anchor_payload(
        journal,
        start_seq=1,
        prev_txid=GENESIS,
        manifests=manifests,
        public_key=public_key,
    )
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


@pytest.fixture
def isolated_dir(tmp_path, monkeypatch) -> Path:
    """A directory that passes the injected §5.7 checks."""
    monkeypatch.setattr(core, "_ancestor_directories", lambda path: [])
    monkeypatch.setattr(core, "_filesystem_type", lambda path: "btrfs")
    parent = tmp_path / "isolated"
    parent.mkdir(mode=0o700)
    return parent


def do_bootstrap(
    journal: Path,
    cache: Path,
    anchors,
    txs,
    *,
    manifests=None,
    public_key=None,
    cache_key=None,
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
        header_verifier=FakeHeaderVerifier(True),
        manifests=manifests,
        public_key=public_key,
        child_uid=65534,
        launcher_euid=0,
        cache_key=cache_key,
    )


class Spy:
    """Stand in for the v2 child runner and count invocations."""

    def __init__(self, returncode: int = 0):
        self.returncode = returncode
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, pass_fds=(), env=None, user=None, group=None,
                 extra_groups=None, check=False):
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(argv, self.returncode)


def bypass_isolation(monkeypatch) -> None:
    monkeypatch.setattr(
        launcher, "assert_journal_writer_isolation", lambda *args, **kwargs: None
    )
    # The cache — and its deployment key — are second trust stores checked
    # under the same §5.7 rules; those also need a privileged launcher, so
    # bypass them together.
    monkeypatch.setattr(
        launcher, "assert_checkpoint_cache_isolation", lambda *args, **kwargs: None
    )


def install_spy(monkeypatch, spy: Spy) -> None:
    monkeypatch.setattr(launcher, "subprocess", types.SimpleNamespace(run=spy))

    def run_v2_child(argv, *, pass_fds, child_env, uid, gid, drop_groups, signals):
        completed = spy(
            argv, pass_fds=pass_fds, env=child_env, user=uid, group=gid,
            extra_groups=drop_groups, check=False,
        )
        return launcher._V2RunResult(completed.returncode, 0, False)

    monkeypatch.setattr(launcher, "_run_v2_child", run_v2_child)


def do_launch(bundle, journal: Path, *, min_release_seq, checkpoint_cache,
              cache_key=None):
    root, envelope, private = bundle
    return launch(
        root,
        envelope,
        private.pubkey_compressed(),
        ["true"],
        mode="v2",
        journal=journal,
        uid=12345,
        gid=12345,
        min_release_seq=min_release_seq,
        checkpoint_cache=checkpoint_cache,
        cache_key=cache_key,
    )


def read_events(journal: Path) -> list[dict]:
    return [
        json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()
    ]


def assert_launch_failed(journal: Path, match: str) -> None:
    events = read_events(journal)
    assert events[-1]["event_type"] == V2_LAUNCH_FAILED_EVENT_TYPE
    failed = json.loads(events[-1]["detail"])
    assert failed["launch_mode"] == "v2"
    assert failed["stage"] == "launch"
    assert match in failed["reason"]
    assert verify_audit_journal(journal) == len(events)


def deployment_key(cache: Path) -> bytes:
    """The deployment key for a cache, beside it like bootstrap writes."""
    key_path = cache_key_path(cache)
    if key_path.exists():
        return load_cache_key(key_path)
    key = secrets.token_bytes(32)
    write_cache_key(key_path, key)
    return key


def hand_signed_record(
    key: bytes, journal_identity: str, *, checkpoint_seq: int, release_seq: int,
    anchor_end_seq: int, head_hash: str,
) -> dict:
    """A record with a valid MAC, as only the key holder can produce."""
    record = {
        "checkpoint_seq": checkpoint_seq,
        "release_seq": release_seq,
        "anchor_end_seq": anchor_end_seq,
        "head_hash": head_hash,
        "journal_identity": journal_identity,
    }
    record["record_mac"] = compute_record_mac(key, record)
    return record


def write_records(path: Path, *records: dict) -> Path:
    path.write_text(
        "".join(
            canonical_json_bytes(record).decode("utf-8") + "\n"
            for record in records
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def v2_launch(tmp_path, monkeypatch):
    bypass_isolation(monkeypatch)
    spy = Spy()
    install_spy(monkeypatch, spy)
    return tmp_path, spy


# --------------------------------------------------------------------------
# the #1 repro: forged records are refused
# --------------------------------------------------------------------------

def test_forged_zero_record_is_refused(v2_launch):
    """The #1 repro, after the fix. Before it, a hand-written zero record
    ("anchor_end_seq 0", zero head_hash, release_seq 0) verified against
    any journal and reset the checkpoint; now nothing without a valid MAC
    is trusted, and the refusal is recorded as ``v2_launch_failed``."""
    tmp_path, spy = v2_launch
    bundle = make_release(tmp_path, manifest_seq=10)
    journal = make_journal(tmp_path, envelope=bundle[1], accept_seq=10)
    cache = tmp_path / "checkpoint.jsonl"
    # The deployment key exists (a real deployment bootstrapped before the
    # forgery was written); only the record is hand-made.
    write_cache_key(cache_key_path(cache), secrets.token_bytes(32))
    write_records(
        cache,
        {
            "checkpoint_seq": 1,
            "release_seq": 0,
            "anchor_end_seq": 0,
            "head_hash": "0" * 64,
        },
    )

    with pytest.raises(VerificationError, match="predates record signing"):
        do_launch(bundle, journal, min_release_seq=0, checkpoint_cache=cache)

    assert spy.calls == []
    assert_launch_failed(journal, "predates record signing")


def test_zero_record_with_a_valid_identity_but_no_mac_is_refused(v2_launch):
    """A forgery that copies the journal's real identity still refuses:
    without the key there is no valid MAC, and a bogus MAC is not one."""
    tmp_path, spy = v2_launch
    bundle = make_release(tmp_path, manifest_seq=10)
    journal = make_journal(tmp_path, envelope=bundle[1], accept_seq=10)
    events, _fragment = read_journal_prefix(journal)
    identity = journal_genesis_identity(events)["identity"]
    cache = tmp_path / "checkpoint.jsonl"
    write_cache_key(cache_key_path(cache), secrets.token_bytes(32))

    # The identity alone, with no MAC field at all.
    write_records(
        cache,
        {
            "checkpoint_seq": 1,
            "release_seq": 0,
            "anchor_end_seq": 0,
            "head_hash": "0" * 64,
            "journal_identity": identity,
        },
    )
    with pytest.raises(VerificationError, match="missing field\\(s\\): record_mac"):
        do_launch(bundle, journal, min_release_seq=0, checkpoint_cache=cache)
    assert spy.calls == []

    # The identity with a bogus MAC.
    write_records(
        cache,
        {
            "checkpoint_seq": 1,
            "release_seq": 0,
            "anchor_end_seq": 0,
            "head_hash": "0" * 64,
            "journal_identity": identity,
            "record_mac": "f" * 64,
        },
    )
    with pytest.raises(VerificationError, match="failed record_mac verification"):
        do_launch(bundle, journal, min_release_seq=0, checkpoint_cache=cache)
    assert spy.calls == []
    assert_launch_failed(journal, "failed record_mac verification")


def test_record_signed_for_journal_a_is_refused_against_journal_b(v2_launch):
    """The identity inside the signed payload binds the record to one
    journal: a record whose MAC is valid but whose identity names journal
    A is refused against journal B even when every prefix check would
    pass."""
    tmp_path, spy = v2_launch
    bundle = make_release(tmp_path, manifest_seq=10)
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    journal_a = make_journal(tmp_path / "a", envelope=bundle[1], accept_seq=10)
    journal_b = make_journal(
        tmp_path / "b", nonce="b" * 32, envelope=bundle[1], accept_seq=10
    )
    events_b, _fragment = read_journal_prefix(journal_b)
    identity_a = journal_genesis_identity(read_journal_prefix(journal_a)[0])[
        "identity"
    ]
    cache = tmp_path / "checkpoint.jsonl"

    # Every journal-consistent field is derived from journal B; only the
    # signed identity belongs to journal A.
    write_records(
        cache,
        hand_signed_record(
            deployment_key(cache),
            identity_a,
            checkpoint_seq=1,
            release_seq=10,
            anchor_end_seq=len(events_b),
            head_hash=events_b[-1]["event_hash"],
        ),
    )

    with pytest.raises(
        VerificationError, match="journal_identity belongs to a different journal"
    ):
        do_launch(bundle, journal_b, min_release_seq=10, checkpoint_cache=cache)
    assert spy.calls == []
    assert_launch_failed(journal_b, "journal_identity belongs to a different journal")


# --------------------------------------------------------------------------
# positive: the legitimate flows still work, now signed
# --------------------------------------------------------------------------

def test_bootstrap_writes_a_signed_record_and_a_cached_launch_accepts_it(
    tmp_path, isolated_dir
):
    cache = isolated_dir / "checkpoint.jsonl"
    _root, envelope, private = make_release(tmp_path, 10)
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(journal, manifests=[envelope], public_key=private.pubkey_compressed())

    result = do_bootstrap(journal, cache, anchors, txs,
                          manifests=[envelope], public_key=private.pubkey_compressed())
    record = result["checkpoint"]

    # The record carries both new fields, and the MAC verifies under the
    # deployment key bootstrap generated beside the cache.
    events, _fragment = read_journal_prefix(journal)
    identity = journal_genesis_identity(events)["identity"]
    assert record["journal_identity"] == identity
    key_path = cache_key_path(cache)
    assert key_path.name == "cache.key"
    assert key_path.parent == cache.parent
    assert stat.S_IMODE(key_path.stat().st_mode) & 0o777 == 0o600
    key = load_cache_key(key_path)
    assert len(key) == 32
    assert record["record_mac"] == compute_record_mac(key, record)
    assert read_checkpoint_cache(cache, key=key) == record
    assert verify_checkpoint_against_journal(record, journal) == 10
    # The same reader the launcher uses accepts the signed record.
    assert read_checkpoint_cache(cache, key=key)["release_seq"] == 10


def test_cached_launch_accepts_a_signed_record(v2_launch):
    tmp_path, spy = v2_launch
    bundle = make_release(tmp_path, manifest_seq=10)
    journal = make_journal(tmp_path, envelope=bundle[1], accept_seq=10)
    cache = tmp_path / "checkpoint.jsonl"
    events, _fragment = read_journal_prefix(journal)
    append_checkpoint_cache(
        cache,
        release_seq=10,
        anchor_end_seq=len(events),
        head_hash=events[-1]["event_hash"],
        key=deployment_key(cache),
        journal_identity=journal_genesis_identity(events)["identity"],
    )

    assert do_launch(
        bundle, journal, min_release_seq=10, checkpoint_cache=cache
    ) == 0
    assert len(spy.calls) == 1


def test_re_bootstrap_appends_a_second_signed_record(tmp_path, isolated_dir):
    cache = isolated_dir / "checkpoint.jsonl"
    _root, envelope, private = make_release(tmp_path, 10)
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(journal, manifests=[envelope], public_key=private.pubkey_compressed())
    do_bootstrap(journal, cache, anchors, txs,
                 manifests=[envelope], public_key=private.pubkey_compressed())

    # New release accepted and anchored: re-bootstrap appends, it does
    # not rewrite, so the cache keeps a contiguous signed history.
    (tmp_path / "second").mkdir()
    second_root = tmp_path / "second" / "root"
    second_root.mkdir()
    (second_root / "model.bin").write_bytes(b"model-v2")
    payload2 = create_manifest(second_root, ["model.bin"], "release-11", 11)
    envelope2 = sign_manifest(payload2, private)
    record_manifest_acceptance(
        journal, 11, "release-11", manifest_hash(envelope2)
    )
    anchors2, txs2 = make_anchors(
        journal, manifests=[envelope, envelope2],
        public_key=private.pubkey_compressed(),
    )
    result = do_bootstrap(journal, cache, anchors2, txs2,
                          manifests=[envelope, envelope2], public_key=private.pubkey_compressed())

    assert result["checkpoint"]["checkpoint_seq"] == 2
    assert result["checkpoint"]["release_seq"] == 11
    key = load_cache_key(cache_key_path(cache))
    records = _read_records_as_list(cache, key)
    assert [r["checkpoint_seq"] for r in records] == [1, 2]
    for stored in records:
        assert stored["record_mac"] == compute_record_mac(key, stored)


def _read_records_as_list(cache: Path, key: bytes):
    return _read_records(cache, key=key)


def test_legitimate_checkpoint_zero_bootstrap_writes_a_signed_zero_record(
    tmp_path, isolated_dir, monkeypatch
):
    """Criterion 2: a deployment whose anchored prefix contains no bound
    acceptances has checkpoint 0 legitimately — the *signature*, not the
    sequence, distinguishes it from the forged zero record."""
    bypass_isolation(monkeypatch)
    spy = Spy()
    install_spy(monkeypatch, spy)
    cache = isolated_dir / "checkpoint.jsonl"
    _root, envelope, _private = make_release(tmp_path, 0)
    journal = make_journal(tmp_path)
    anchors, txs = make_anchors(journal)

    result = do_bootstrap(journal, cache, anchors, txs)
    record = result["checkpoint"]
    assert record["release_seq"] == 0
    assert record["checkpoint_seq"] == 1
    events, _fragment = read_journal_prefix(journal)
    assert record["anchor_end_seq"] == len(events)
    key = load_cache_key(cache_key_path(cache))
    assert record["record_mac"] == compute_record_mac(key, record)

    bundle = (_root, envelope, _private)
    assert do_launch(
        bundle, journal, min_release_seq=0, checkpoint_cache=cache
    ) == 0
    assert len(spy.calls) == 1


# --------------------------------------------------------------------------
# negative: tampering, keys, migration, unseeded bootstrap
# --------------------------------------------------------------------------

def test_tampering_any_signed_field_invalidates_the_mac(tmp_path, isolated_dir):
    cache = isolated_dir / "checkpoint.jsonl"
    _root, envelope, private = make_release(tmp_path, 10)
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(journal, manifests=[envelope], public_key=private.pubkey_compressed())
    do_bootstrap(journal, cache, anchors, txs,
                 manifests=[envelope], public_key=private.pubkey_compressed())
    key = load_cache_key(cache_key_path(cache))
    original = json.loads(cache.read_text(encoding="utf-8").splitlines()[0])

    mutations = {
        "checkpoint_seq": original["checkpoint_seq"] + 1,
        "release_seq": original["release_seq"] + 1,
        "anchor_end_seq": original["anchor_end_seq"] + 1,
        "head_hash": "f" * 64,
        "journal_identity": "f" * 64,
    }
    for field, value in mutations.items():
        tampered = dict(original)
        assert tampered[field] != value
        tampered[field] = value
        # The tampered line is written without re-signing: exactly what an
        # attacker without the key can do.
        cache.write_text(
            canonical_json_bytes(tampered).decode("utf-8") + "\n",
            encoding="utf-8",
        )
        with pytest.raises(
            VerificationError, match="failed record_mac verification"
        ):
            read_checkpoint_cache(cache, key=key)


def test_missing_key_file_refuses_the_launch(v2_launch):
    tmp_path, spy = v2_launch
    bundle = make_release(tmp_path, manifest_seq=10)
    journal = make_journal(tmp_path, envelope=bundle[1], accept_seq=10)
    cache = tmp_path / "checkpoint.jsonl"
    events, _fragment = read_journal_prefix(journal)
    append_checkpoint_cache(
        cache,
        release_seq=10,
        anchor_end_seq=len(events),
        head_hash=events[-1]["event_hash"],
        key=deployment_key(cache),
        journal_identity=journal_genesis_identity(events)["identity"],
    )
    cache_key_path(cache).unlink()

    with pytest.raises(VerificationError, match="cache key .*re-bootstrap"):
        do_launch(bundle, journal, min_release_seq=10, checkpoint_cache=cache)
    assert spy.calls == []
    assert_launch_failed(journal, "re-bootstrap")


def test_wrong_key_refuses(tmp_path, isolated_dir):
    cache = isolated_dir / "checkpoint.jsonl"
    _root, envelope, private = make_release(tmp_path, 10)
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(journal, manifests=[envelope], public_key=private.pubkey_compressed())
    do_bootstrap(journal, cache, anchors, txs,
                 manifests=[envelope], public_key=private.pubkey_compressed())

    # A different 32-byte key: the records no longer authenticate.
    cache_key_path(cache).unlink()
    write_cache_key(cache_key_path(cache), secrets.token_bytes(32))

    with pytest.raises(VerificationError, match="failed record_mac verification"):
        read_checkpoint_cache(cache, key=load_cache_key(cache_key_path(cache)))


def test_pre_fix_unsigned_cache_refuses_with_the_re_bootstrap_message(
    v2_launch,
):
    """§5.5 migration: a cache written before the fix has neither new
    field. It is refused with the remedy named, and the diagnosis says
    the cache *predates signing* rather than calling it forged (a forged
    record has the fields but fails the MAC — that distinct message is
    asserted in the tampering tests)."""
    tmp_path, spy = v2_launch
    bundle = make_release(tmp_path, manifest_seq=10)
    journal = make_journal(tmp_path, envelope=bundle[1], accept_seq=10)
    events, _fragment = read_journal_prefix(journal)
    cache = tmp_path / "checkpoint.jsonl"
    write_cache_key(cache_key_path(cache), secrets.token_bytes(32))
    # Structurally exactly what the pre-fix bootstrap wrote, and even
    # consistent with this journal — still refused.
    write_records(
        cache,
        {
            "checkpoint_seq": 1,
            "release_seq": 10,
            "anchor_end_seq": len(events),
            "head_hash": events[-1]["event_hash"],
        },
    )

    with pytest.raises(
        VerificationError, match="predates record signing.*re-bootstrap"
    ):
        do_launch(bundle, journal, min_release_seq=10, checkpoint_cache=cache)
    assert spy.calls == []
    assert_launch_failed(journal, "re-bootstrap")


def test_bootstrap_refuses_an_unseeded_journal(tmp_path, isolated_dir):
    """Decision (d): bootstrap before first launch is not supported. A
    journal with no nonce-bearing v2 event has no identity to bind the
    record to; bootstrap refuses with the remedy instead of recording a
    null identity."""
    cache = isolated_dir / "checkpoint.jsonl"
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")

    with pytest.raises(
        VerificationError,
        match="run a first v2 launch to seed the journal identity",
    ):
        do_bootstrap(journal, cache, [], {})


# --------------------------------------------------------------------------
# key handling: derived path and --cache-key override
# --------------------------------------------------------------------------

def test_cache_key_override_is_used_by_bootstrap_and_launch(
    tmp_path, isolated_dir, monkeypatch
):
    bypass_isolation(monkeypatch)
    spy = Spy()
    install_spy(monkeypatch, spy)
    cache = isolated_dir / "checkpoint.jsonl"
    override = isolated_dir / "keys" / "custom.key"
    override.parent.mkdir(mode=0o700)
    _root, envelope, private = make_release(tmp_path, 10)
    journal = make_journal(tmp_path, envelope=envelope, accept_seq=10)
    anchors, txs = make_anchors(journal, manifests=[envelope], public_key=private.pubkey_compressed())

    do_bootstrap(journal, cache, anchors, txs,
                 manifests=[envelope],
                 public_key=private.pubkey_compressed(), cache_key=override)

    # The override replaces the derived path: no key beside the cache.
    assert override.exists()
    assert not cache_key_path(cache).exists()
    key = load_cache_key(override)

    bundle = (_root, envelope, private)
    # Without the flag the derived default is missing, and that refuses —
    # the safe failure mode (§5.4).
    with pytest.raises(VerificationError, match="cache key"):
        do_launch(bundle, journal, min_release_seq=10, checkpoint_cache=cache)
    assert spy.calls == []

    # With the flag the launch loads the same key and accepts.
    assert do_launch(
        bundle, journal, min_release_seq=10, checkpoint_cache=cache,
        cache_key=override,
    ) == 0
    assert len(spy.calls) == 1
    assert load_cache_key(override) == key
