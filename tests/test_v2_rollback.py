"""Launch-flow v2 plan item 9: anchored-checkpoint rollback (§8).

A v2 launch requires an explicit ``--min-release-seq`` *and* an anchored
release checkpoint cache. The launcher binds the cache to the journal,
requires the manifest sequence to be at least the anchored checkpoint,
and refuses (recording ``v2_launch_failed``) before any child runs when
either is missing, when the operator minimum is below the checkpoint, or
when the cache is tampered, older, or no longer bound to the journal.

The one exception is the *first* v2 launch for a journal: bootstrap
derives the journal identity from the journal's nonce-bearing v2 events,
so a journal without one cannot have a cache yet, and requiring the
cache first would close the loop with no entry point. When the cache is
missing and the journal has no nonce-bearing v2 event, the launch
proceeds with effective checkpoint 0, prints the first-launch notice,
and its ``v2_launch`` event seeds the identity. Once any nonce-bearing
v2 event exists, a missing cache refuses exactly as before. Only the
cache requirement is excepted: ``--min-release-seq`` stays mandatory.

The cache itself is append-only with a monotonic ``checkpoint_seq`` and a
non-decreasing ``release_seq`` / ``anchor_end_seq``. That detects an
*appended* older checkpoint. Truncating the file back to an older,
internally valid prefix is not detectable without an external trusted
high-water mark; it is documented in ``docs/launcher.md`` rather than
hidden here.
"""

import json
import subprocess
import types
import uuid
from pathlib import Path

import pytest
from sealrun.bsv import PrivKey

import sealrun.checkpoint_cache as checkpoint_cache
import sealrun.core as core
import sealrun.launcher as launcher
from sealrun.checkpoint_cache import (
    anchored_release_seq,
    append_checkpoint_cache,
    read_checkpoint_cache,
    verify_checkpoint_against_journal,
)
from sealrun.cli import main
from sealrun.core import (
    MANIFEST_ACCEPTED_EVENT_TYPE,
    V2_FINISH_EVENT_TYPE,
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
from sealrun.launcher import V2_FIRST_LAUNCH_NOTICE, launch


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def make_bundle(tmp_path: Path, manifest_seq: int):
    """A signed release bundle plus a journal/cache pair it can anchor to."""
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    (root / "model.bin").write_bytes(b"model-v1")
    (root / "config.json").write_text('{"safe":true}\n', encoding="utf-8")
    private = PrivKey.generate()
    payload = create_manifest(
        root, ["model.bin", "config.json"], f"release-{manifest_seq}", manifest_seq
    )
    envelope = sign_manifest(payload, private)
    return root, envelope, private


class Spy:
    """Stand in for the v2 child runner and count invocations."""

    def __init__(self, returncode: int = 0):
        self.returncode = returncode
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, pass_fds=(), env=None, user=None, group=None,
                 extra_groups=None, check=False):
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(argv, self.returncode)


def install_spy(monkeypatch, spy: Spy) -> None:
    monkeypatch.setattr(launcher, "subprocess", types.SimpleNamespace(run=spy))

    def run_v2_child(argv, *, pass_fds, child_env, uid, gid, drop_groups, signals):
        completed = spy(
            argv, pass_fds=pass_fds, env=child_env, user=uid, group=gid,
            extra_groups=drop_groups, check=False,
        )
        return launcher._V2RunResult(completed.returncode, 0, False)

    monkeypatch.setattr(launcher, "_run_v2_child", run_v2_child)


def bypass_isolation(monkeypatch) -> None:
    monkeypatch.setattr(
        launcher, "assert_journal_writer_isolation", lambda *args, **kwargs: None
    )
    # The cache is a second trust store checked under the same §5.7 rules;
    # those also need a privileged launcher, so bypass them together.
    monkeypatch.setattr(
        launcher, "assert_checkpoint_cache_isolation", lambda *args, **kwargs: None
    )


def write_cache(
    path: Path,
    journal: Path,
    release_seq: int,
    *,
    anchor_end_seq: int | None = None,
    head_hash: str | None = None,
) -> Path:
    events, _fragment = read_journal_prefix(journal)
    if anchor_end_seq is None:
        anchor_end_seq = len(events)
    if head_hash is None:
        head_hash = events[-1]["event_hash"] if events else "0" * 64
    append_checkpoint_cache(
        path,
        release_seq=release_seq,
        anchor_end_seq=anchor_end_seq,
        head_hash=head_hash,
    )
    return path


def accept(journal: Path, envelope: dict, seq: int) -> None:
    record_manifest_acceptance(
        journal, seq, f"release-{seq}", manifest_hash(envelope)
    )


def seed_launch_event(journal: Path, *, nonce: str = "a" * 32) -> dict:
    """Append a minimal valid v2_launch event, as a completed launch would."""
    return append_v2_event(
        journal,
        V2_LAUNCH_EVENT_TYPE,
        {
            "launch_mode": "v2",
            "run_id": "00000000-0000-4000-8000-000000000000",
            "journal_nonce": nonce,
            "manifest_hash": "b" * 64,
            "artifact_count": 0,
            "argv_fingerprint": "c" * 64,
            "env_fingerprint": "d" * 64,
            "executable": "true",
            "cwd": "/tmp",
            "seal": False,
            "uid": 12345,
            "gid": 12345,
        },
    )


def seed_launch_failed_event(journal: Path) -> None:
    """Append a v2_launch_failed event: it carries no journal_nonce."""
    append_v2_event(
        journal,
        V2_LAUNCH_FAILED_EVENT_TYPE,
        {
            "launch_mode": "v2",
            "run_id": str(uuid.uuid4()),
            "stage": "launch",
            "reason": "an earlier launch attempt failed",
        },
    )


def do_launch(bundle, journal: Path, *, min_release_seq, checkpoint_cache):
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
    )


def read_events(journal: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in journal.read_text(encoding="utf-8").splitlines()
    ]


def assert_launch_failed(journal: Path, match: str) -> None:
    events = read_events(journal)
    assert events[-1]["event_type"] == V2_LAUNCH_FAILED_EVENT_TYPE
    failed = json.loads(events[-1]["detail"])
    assert failed["launch_mode"] == "v2"
    assert failed["stage"] == "launch"
    assert match in failed["reason"]
    assert verify_audit_journal(journal) == len(events)


@pytest.fixture
def v2_launch(tmp_path, monkeypatch):
    bypass_isolation(monkeypatch)
    spy = Spy()
    install_spy(monkeypatch, spy)
    return tmp_path, spy


# --------------------------------------------------------------------------
# the required core cases
# --------------------------------------------------------------------------

def test_checkpoint_ahead_of_manifest_and_minimum_refuses(v2_launch):
    """checkpoint 10 / manifest 5 / min 1: both the minimum and the
    manifest are below the anchored checkpoint, so the launch refuses."""
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=5)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 10)
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 10)

    with pytest.raises(VerificationError, match="below the anchored release checkpoint 10"):
        do_launch(bundle, journal, min_release_seq=1, checkpoint_cache=cache)

    assert spy.calls == []
    assert_launch_failed(journal, "below the anchored release checkpoint 10")


def test_manifest_below_checkpoint_refuses_even_when_minimum_matches(v2_launch):
    """The manifest sequence is independently required to meet the
    checkpoint, not only the operator-supplied minimum."""
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=5)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 10)
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 10)

    with pytest.raises(VerificationError, match="manifest release_seq 5"):
        do_launch(bundle, journal, min_release_seq=10, checkpoint_cache=cache)

    assert spy.calls == []
    assert_launch_failed(journal, "manifest release_seq 5")


def test_omitting_min_release_seq_refuses_before_running_the_child(v2_launch):
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=10)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 10)
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 10)

    with pytest.raises(VerificationError, match="requires --min-release-seq"):
        do_launch(bundle, journal, min_release_seq=None, checkpoint_cache=cache)

    assert spy.calls == []
    assert_launch_failed(journal, "requires --min-release-seq")


def test_seeded_journal_refuses_a_missing_cache(v2_launch):
    """Case A5 preserved: once the journal has a nonce-bearing v2 event, a
    missing cache refuses exactly as before — whether the cache path is
    omitted entirely or names a file that does not exist."""
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=10)
    seeded = tmp_path / "seeded.jsonl"
    seed_launch_event(seeded)

    with pytest.raises(VerificationError, match="requires --checkpoint-cache"):
        do_launch(bundle, seeded, min_release_seq=10, checkpoint_cache=None)
    assert spy.calls == []
    assert_launch_failed(seeded, "requires --checkpoint-cache")

    missing = tmp_path / "checkpoint.jsonl"
    with pytest.raises(VerificationError, match="cache is missing"):
        do_launch(bundle, seeded, min_release_seq=10, checkpoint_cache=missing)
    assert spy.calls == []
    assert_launch_failed(seeded, "cache is missing")


def test_sequence_at_the_checkpoint_launches(v2_launch):
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=10)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 10)
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 10)

    assert do_launch(
        bundle, journal, min_release_seq=10, checkpoint_cache=cache
    ) == 0
    assert len(spy.calls) == 1
    events = read_events(journal)
    assert events[-2]["event_type"] == V2_LAUNCH_EVENT_TYPE
    assert events[-1]["event_type"] == V2_FINISH_EVENT_TYPE
    for event in events[-2:]:
        assert json.loads(event["detail"])["launch_mode"] == "v2"


def test_higher_manifest_and_minimum_launch(v2_launch):
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=12)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 10)
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 10)

    assert do_launch(
        bundle, journal, min_release_seq=12, checkpoint_cache=cache
    ) == 0
    assert len(spy.calls) == 1


def test_zero_checkpoint_is_valid_when_no_acceptance_is_anchored(v2_launch):
    """0 is a real checkpoint only when the anchored prefix contains no
    ``manifest_accepted`` events; it is not the missing-cache default."""
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=0)
    journal = tmp_path / "audit.jsonl"
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 0)

    assert do_launch(
        bundle, journal, min_release_seq=0, checkpoint_cache=cache
    ) == 0
    assert len(spy.calls) == 1


def test_first_launch_without_a_cache_seeds_the_identity(v2_launch, capsys):
    """The first-launch exception. Bootstrap derives the journal identity
    from the journal's nonce-bearing v2 events, so a journal without one
    cannot have a checkpoint cache yet, and requiring the cache first
    would close the loop with no entry point. A journal with no
    nonce-bearing v2 event — a fresh journal, or one whose only v2 events
    are ``v2_launch_failed`` (they carry no ``journal_nonce``) — launches
    with effective checkpoint 0, and its ``v2_launch`` event seeds the
    identity. ``--min-release-seq`` is still required and still enforced.
    """
    tmp_path, spy = v2_launch
    missing = tmp_path / "checkpoint.jsonl"

    # A fresh journal: the very first v2 launch for this deployment.
    bundle = make_bundle(tmp_path, manifest_seq=0)
    journal = tmp_path / "audit.jsonl"
    assert do_launch(
        bundle, journal, min_release_seq=0, checkpoint_cache=missing
    ) == 0
    assert len(spy.calls) == 1
    assert V2_FIRST_LAUNCH_NOTICE in capsys.readouterr().out
    events = read_events(journal)
    assert [event["event_type"] for event in events] == [
        V2_LAUNCH_EVENT_TYPE, V2_FINISH_EVENT_TYPE
    ]
    nonce = json.loads(events[0]["detail"])["journal_nonce"]
    identity = journal_genesis_identity(read_journal_prefix(journal)[0])
    assert identity["genesis_nonce"] == nonce

    # v2_launch_failed events carry no journal_nonce, so they do not seed
    # an identity: a journal holding only those still takes the exception.
    failed_journal = tmp_path / "failed-first.jsonl"
    seed_launch_failed_event(failed_journal)
    seed_launch_failed_event(failed_journal)
    assert do_launch(
        bundle, failed_journal, min_release_seq=0, checkpoint_cache=missing
    ) == 0
    assert len(spy.calls) == 2
    assert V2_FIRST_LAUNCH_NOTICE in capsys.readouterr().out
    assert [
        event["event_type"] for event in read_events(failed_journal)
    ] == [
        V2_LAUNCH_FAILED_EVENT_TYPE,
        V2_LAUNCH_FAILED_EVENT_TYPE,
        V2_LAUNCH_EVENT_TYPE,
        V2_FINISH_EVENT_TYPE,
    ]


# --------------------------------------------------------------------------
# tampering / stale / truncated cache
# --------------------------------------------------------------------------

def test_launch_refuses_a_cache_that_fails_isolation(v2_launch, monkeypatch):
    """§5.7 at launch time: the cache is a second trust store, so a cache
    file present at launch must satisfy the same placement rules
    bootstrap enforced, checked before its contents are trusted. A
    group-writable cache file is refused (and recorded as
    ``v2_launch_failed``) even though its contents would verify.
    """
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=5)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 5)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    cache = write_cache(store / "checkpoint.jsonl", journal, 5)
    cache.chmod(0o666)

    # The §5.7 predicate needs a privileged launcher; tests run
    # unprivileged, so inject the euid the production call site already
    # has (the same injection the bootstrap isolation tests use). The
    # /tmp ancestor chain is group-writable, so scope the predicate to
    # the store directory like make_safe_cache does in the bootstrap
    # isolation tests.
    real_isolation = checkpoint_cache.assert_checkpoint_cache_isolation
    monkeypatch.setattr(
        launcher,
        "assert_checkpoint_cache_isolation",
        lambda path, child_uid: real_isolation(path, child_uid, launcher_euid=0),
    )
    monkeypatch.setattr(core, "_ancestor_directories", lambda path: [])
    monkeypatch.setattr(core, "_filesystem_type", lambda path: "btrfs")

    with pytest.raises(VerificationError, match="group- or world-writable"):
        do_launch(bundle, journal, min_release_seq=5, checkpoint_cache=cache)
    assert len(spy.calls) == 0
    assert_launch_failed(journal, "checkpoint cache isolation")


def test_launch_does_not_isolation_check_a_missing_cache(v2_launch, monkeypatch):
    """Only a present cache file is isolation-checked: a missing cache
    follows the first-launch path and must not newly fail on the cache
    path's placement — here a parent directory that would refuse §5.7 if
    the predicate ran on the missing cache.
    """
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=0)
    journal = tmp_path / "audit.jsonl"

    real_isolation = checkpoint_cache.assert_checkpoint_cache_isolation
    monkeypatch.setattr(
        launcher,
        "assert_checkpoint_cache_isolation",
        lambda path, child_uid: real_isolation(path, child_uid, launcher_euid=0),
    )
    monkeypatch.setattr(core, "_ancestor_directories", lambda path: [])
    monkeypatch.setattr(core, "_filesystem_type", lambda path: "btrfs")
    loose = tmp_path / "loose"
    loose.mkdir()
    loose.chmod(0o777)

    assert do_launch(
        bundle, journal, min_release_seq=0, checkpoint_cache=loose / "checkpoint.jsonl"
    ) == 0
    assert len(spy.calls) == 1


def test_tampered_head_hash_refuses(v2_launch):
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=10)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 10)
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 10)

    record = read_checkpoint_cache(cache)
    forged = "1" * 64 if record["head_hash"] != "1" * 64 else "2" * 64
    forged_record = dict(record, head_hash=forged)
    cache.write_text(
        canonical_json_bytes(forged_record).decode("utf-8") + "\n",
        encoding="utf-8",
    )

    with pytest.raises(VerificationError, match="does not match the journal"):
        do_launch(bundle, journal, min_release_seq=10, checkpoint_cache=cache)

    assert spy.calls == []
    assert_launch_failed(journal, "does not match the journal")


def test_older_release_seq_in_the_cache_refuses(v2_launch):
    """A cache that claims an older checkpoint than the anchored prefix
    actually contains is refused."""
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=10)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 10)
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 5)

    with pytest.raises(VerificationError, match="not the max accepted sequence"):
        do_launch(bundle, journal, min_release_seq=10, checkpoint_cache=cache)

    assert spy.calls == []
    assert_launch_failed(journal, "not the max accepted sequence")


def test_truncated_journal_below_the_anchor_refuses(v2_launch):
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=10)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 10)
    accept(journal, bundle[1], 11)
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 11)

    lines = journal.read_text(encoding="utf-8").splitlines()
    journal.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    with pytest.raises(VerificationError, match="truncated below the anchored checkpoint"):
        do_launch(bundle, journal, min_release_seq=11, checkpoint_cache=cache)

    assert spy.calls == []
    assert_launch_failed(journal, "truncated below the anchored checkpoint")


def test_cache_with_a_decreasing_release_seq_refuses(v2_launch):
    """The cache's own append-only sequence detects an appended older
    checkpoint."""
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=10)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 10)
    cache = tmp_path / "checkpoint.jsonl"
    cache.write_text(
        canonical_json_bytes(
            {
                "checkpoint_seq": 1,
                "release_seq": 10,
                "anchor_end_seq": len(read_journal_prefix(journal)[0]),
                "head_hash": "a" * 64,
            }
        ).decode("utf-8")
        + "\n"
        + canonical_json_bytes(
            {
                "checkpoint_seq": 2,
                "release_seq": 5,
                "anchor_end_seq": len(read_journal_prefix(journal)[0]),
                "head_hash": "b" * 64,
            }
        ).decode("utf-8")
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(VerificationError, match="rollback detected: release_seq decreased"):
        do_launch(bundle, journal, min_release_seq=10, checkpoint_cache=cache)

    assert spy.calls == []
    assert_launch_failed(journal, "rollback detected: release_seq decreased")


def test_append_writer_refuses_an_older_checkpoint(tmp_path):
    cache = tmp_path / "checkpoint.jsonl"
    append_checkpoint_cache(
        cache, release_seq=10, anchor_end_seq=5, head_hash="a" * 64
    )
    with pytest.raises(VerificationError, match="older than the cache's current release_seq"):
        append_checkpoint_cache(
            cache, release_seq=5, anchor_end_seq=6, head_hash="b" * 64
        )


# --------------------------------------------------------------------------
# only anchored manifest_accepted events advance the checkpoint
# --------------------------------------------------------------------------

def test_launch_and_finish_events_do_not_advance_the_checkpoint(
    v2_launch, capsys
):
    tmp_path, spy = v2_launch
    bundle = make_bundle(tmp_path, manifest_seq=0)
    journal = tmp_path / "audit.jsonl"
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 0)

    assert do_launch(
        bundle, journal, min_release_seq=0, checkpoint_cache=cache
    ) == 0
    assert [event["event_type"] for event in read_events(journal)] == [
        V2_LAUNCH_EVENT_TYPE, V2_FINISH_EVENT_TYPE
    ]

    # Anchor a second checkpoint at the post-run prefix. If launch/finish
    # events advanced the checkpoint, the derived release_seq would no
    # longer be 0 and this second launch would refuse.
    events, _fragment = read_journal_prefix(journal)
    assert anchored_release_seq(events, len(events)) == 0
    write_cache(tmp_path / "checkpoint.jsonl", journal, 0)

    assert do_launch(
        bundle, journal, min_release_seq=0, checkpoint_cache=cache
    ) == 0
    assert len(spy.calls) == 2

    # The second launch ran on a journal that already has v2 events and a
    # cache present: behaviour is exactly as before the first-launch
    # exception, and no seeding notice is printed.
    assert V2_FIRST_LAUNCH_NOTICE not in capsys.readouterr().out


def test_anchored_release_seq_ignores_events_after_the_prefix(tmp_path):
    bundle = make_bundle(tmp_path, manifest_seq=0)
    journal = tmp_path / "audit.jsonl"
    accept(journal, bundle[1], 10)
    events, _fragment = read_journal_prefix(journal)

    assert anchored_release_seq(events, 0) == 0
    assert anchored_release_seq(events, len(events)) == 10


def test_run_events_alone_derive_checkpoint_zero(tmp_path):
    journal = tmp_path / "audit.jsonl"
    run_id = "00000000-0000-4000-8000-000000000000"
    append_v2_event(
        journal,
        V2_LAUNCH_EVENT_TYPE,
        {
            "launch_mode": "v2",
            "run_id": run_id,
            "journal_nonce": "a" * 32,
            "manifest_hash": "b" * 64,
            "artifact_count": 0,
            "argv_fingerprint": "c" * 64,
            "env_fingerprint": "d" * 64,
            "executable": "true",
            "cwd": "/tmp",
            "seal": False,
            "uid": 12345,
            "gid": 12345,
        },
    )
    append_v2_event(
        journal,
        V2_FINISH_EVENT_TYPE,
        {
            "launch_mode": "v2",
            "run_id": run_id,
            "exit_code": 0,
            "launcher_signal": 0,
            "escalated": False,
            "duration_ms": 1,
        },
    )
    events, _fragment = read_journal_prefix(journal)
    assert anchored_release_seq(events, len(events)) == 0


# --------------------------------------------------------------------------
# fail-closed acceptance parsing (agrees with the anchor derivation)
# --------------------------------------------------------------------------

def test_unbound_acceptance_fails_closed_instead_of_counting(tmp_path):
    """An acceptance whose detail lacks the manifest binding must not
    advance the checkpoint. The launch-time derivation agrees with the
    anchor derivation's fail-closed parsing: it raises, it neither
    counts the acceptance nor silently skips it (a silent skip would let
    a hand-written cache claim a checkpoint a bound journal refutes, and
    would hide the malformed acceptance from the operator).
    """
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    append_audit_event(
        journal,
        MANIFEST_ACCEPTED_EVENT_TYPE,
        json.dumps({"release_seq": 5}),
    )
    events, _fragment = read_journal_prefix(journal)

    with pytest.raises(
        VerificationError, match="legacy unbound manifest_accepted"
    ):
        anchored_release_seq(events, len(events))


def test_malformed_acceptance_details_fail_closed(tmp_path):
    """Every structural defect the anchor derivation refuses also refuses
    the launch-time derivation, with the same wording family."""
    cases = [
        ("detail must be a JSON string", None),
        ("not valid JSON or has duplicate keys", "{bad"),
        (
            "detail must be a JSON object",
            json.dumps(["not", "an", "object"]),
        ),
        ("detail has no manifest_hash", json.dumps({"release_seq": 5})),
        (
            "release_seq is invalid",
            json.dumps(
                {
                    "release_seq": -1,
                    "release_id": "release-5",
                    "manifest_hash": "a" * 64,
                }
            ),
        ),
        (
            "release_seq is invalid",
            json.dumps(
                {
                    "release_seq": "5",
                    "release_id": "release-5",
                    "manifest_hash": "a" * 64,
                }
            ),
        ),
        (
            "release_id must be a non-empty string",
            json.dumps(
                {
                    "release_seq": 5,
                    "release_id": "",
                    "manifest_hash": "a" * 64,
                }
            ),
        ),
        (
            "must be 64 hexadecimal characters",
            json.dumps(
                {
                    "release_seq": 5,
                    "release_id": "release-5",
                    "manifest_hash": "not-a-hash",
                }
            ),
        ),
    ]
    for case_index, (expected, detail) in enumerate(cases):
        journal = tmp_path / f"audit-{case_index}.jsonl"
        append_audit_event(journal, "test", "first")
        if detail is None:
            # The append API refuses a non-string detail, so this case
            # writes the tampered journal line directly — exactly the
            # hand-written-journal situation the check defends against.
            with journal.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "seq": 2,
                            "event_type": MANIFEST_ACCEPTED_EVENT_TYPE,
                            "detail": None,
                        }
                    )
                    + "\n"
                )
        else:
            append_audit_event(journal, MANIFEST_ACCEPTED_EVENT_TYPE, detail)
        events, _fragment = read_journal_prefix(journal)
        with pytest.raises(VerificationError, match=expected):
            anchored_release_seq(events, len(events))


def test_duplicate_detail_keys_fail_closed(tmp_path):
    """Duplicate JSON keys parse ambiguously; the anchor derivation
    rejects them, so the launch-time derivation refuses them too rather
    than counting whichever value a lenient parser would keep."""
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    append_audit_event(
        journal,
        MANIFEST_ACCEPTED_EVENT_TYPE,
        '{"release_seq": 5, "release_seq": 6, "release_id": "release-5", '
        '"manifest_hash": "' + "a" * 64 + '"}',
    )
    events, _fragment = read_journal_prefix(journal)

    with pytest.raises(
        VerificationError, match="not valid JSON or has duplicate keys"
    ):
        anchored_release_seq(events, len(events))


def test_bound_acceptance_still_counts_after_fail_closed_parsing(tmp_path):
    """The fail-closed rules must not reject a genuinely bound
    acceptance: the same event that raises when unbound counts when it
    carries release_id and manifest_hash (the structural fields this
    derivation can check without the manifests themselves)."""
    bundle = make_bundle(tmp_path, manifest_seq=5)
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    accept(journal, bundle[1], 5)
    events, _fragment = read_journal_prefix(journal)

    assert anchored_release_seq(events, len(events)) == 5


def test_cache_over_an_unbound_acceptance_refuses(tmp_path):
    """A cache record claiming release_seq 5 over a journal whose only
    acceptance is unbound must be refused at launch: the checkpoint the
    cache pins cannot be derived from bound acceptances, so the
    prefix-consistency check fails closed instead of trusting the cache's
    own claim."""
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    append_audit_event(
        journal,
        MANIFEST_ACCEPTED_EVENT_TYPE,
        json.dumps({"release_seq": 5}),
    )
    events, _fragment = read_journal_prefix(journal)
    record = {
        "checkpoint_seq": 1,
        "release_seq": 5,
        "anchor_end_seq": len(events),
        "head_hash": events[-1]["event_hash"],
    }

    with pytest.raises(
        VerificationError, match="legacy unbound manifest_accepted"
    ):
        verify_checkpoint_against_journal(record, journal)


# --------------------------------------------------------------------------
# CLI plumbing and v1 preservation
# --------------------------------------------------------------------------

def test_cli_v2_refuses_a_launch_without_min_release_seq(
    tmp_path, monkeypatch, capsys
):
    bypass_isolation(monkeypatch)
    spy = Spy()
    install_spy(monkeypatch, spy)
    bundle = make_bundle(tmp_path, manifest_seq=0)
    root, envelope, private = bundle
    journal = tmp_path / "audit.jsonl"
    cache = write_cache(tmp_path / "checkpoint.jsonl", journal, 0)
    manifest = tmp_path / "manifest.signed.json"
    manifest.write_text(json.dumps(envelope), encoding="utf-8")
    public = tmp_path / "public.pub"
    public.write_text(private.pubkey_compressed().hex(), encoding="ascii")

    rc = main([
        "launch",
        "--root", str(root),
        "--manifest", str(manifest),
        "--public-key", str(public),
        "--mode", "v2",
        "--journal", str(journal),
        "--checkpoint-cache", str(cache),
        "--uid", "12345",
        "--gid", "12345",
        "--", "true",
    ])
    assert rc == 1
    assert "requires --min-release-seq" in capsys.readouterr().err
    assert spy.calls == []
    assert_launch_failed(journal, "requires --min-release-seq")


def test_v1_launch_is_unchanged(tmp_path, monkeypatch):
    bundle = make_bundle(tmp_path, manifest_seq=1)
    root, envelope, private = bundle
    spy = Spy()
    install_spy(monkeypatch, spy)

    assert launch(
        root, envelope, private.pubkey_compressed(), ["true"],
    ) == 0
    assert len(spy.calls) == 1


def test_v1_refuses_a_checkpoint_cache(tmp_path):
    bundle = make_bundle(tmp_path, manifest_seq=1)
    root, envelope, private = bundle
    with pytest.raises(VerificationError, match="only valid with --mode v2"):
        launch(
            root, envelope, private.pubkey_compressed(), ["true"],
            checkpoint_cache=tmp_path / "checkpoint.jsonl",
        )
