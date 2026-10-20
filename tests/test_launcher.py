"""Tests for the privileged launcher (verify -> exec on pinned handles).

The launcher closes the verify-to-launch TOCTOU gap: it consumes the open
descriptors produced by ``verified_artifacts()`` and hands them to the
launched process instead of letting it reopen artifact paths. These tests
pin down the guarantee (a path swap after verification cannot change what
the child reads), the ``--seal`` freeze, the environment contract, the
privilege-drop failure mode, and descriptor hygiene.

A ``_RunSpy`` replaces ``subprocess.run`` so the "child" can act at the
exact moment after verification but before exec — the window a real
attacker would need — and read the descriptors the launcher would have
passed.
"""

import json
import os
import pwd
import subprocess
import sys
import types
from pathlib import Path

import pytest
from sealrun.bsv import PrivKey

import sealrun.launcher as launcher
from sealrun.cli import main
from sealrun.core import (
    VerificationError,
    create_manifest,
    generate_keypair,
    load_private_key,
    manifest_hash,
    sign_manifest,
)
from sealrun.launcher import (
    _seal_fd,
    artifact_env_name,
    build_child_environment,
    launch,
    resolve_gid,
    resolve_uid,
)


def setup_artifacts(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    root.mkdir()
    (root / "model.bin").write_bytes(b"model-v1")
    (root / "config.json").write_text('{"safe":true}\n', encoding="utf-8")
    return root


def make_signed(root: Path, release_id="test-release", release_seq: int = 1,
                paths=("model.bin", "config.json")):
    private = PrivKey.generate()
    payload = create_manifest(root, list(paths), release_id, release_seq)
    return private, sign_manifest(payload, private)


def _read_fd(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while True:
        block = os.read(fd, 4096)
        if not block:
            break
        chunks.append(block)
    return b"".join(chunks)


class _RunSpy:
    """Stand-in for ``subprocess.run`` that records the launch contract.

    ``action`` runs with the spy while the verified handles are still
    open — the same instant a real child would exec — so tests can mutate
    the artifact tree and observe what the child *would* read.
    """

    def __init__(self, action=None, returncode: int = 0):
        self.action = action
        self.returncode = returncode
        self.argv = None
        self.env = None
        self.pass_fds = ()
        self.user = None
        self.group = None
        self.extra_groups = None
        self.reads = None

    def __call__(self, argv, *, pass_fds=(), env=None, user=None, group=None,
                 extra_groups=None, check=False):
        self.argv = list(argv)
        self.pass_fds = tuple(pass_fds)
        self.env = env
        self.user = user
        self.group = group
        self.extra_groups = extra_groups
        if self.action is not None:
            self.action(self)
        return subprocess.CompletedProcess(argv, self.returncode)


def install_spy(monkeypatch, spy: _RunSpy) -> None:
    monkeypatch.setattr(launcher, "subprocess", types.SimpleNamespace(run=spy))


# --------------------------------------------------------------------------
# artifact_env_name / environment contract
# --------------------------------------------------------------------------

def test_artifact_env_name_collapses_paths():
    assert artifact_env_name("model.bin") == "SEALRUN_ARTIFACT_MODEL_BIN"
    assert artifact_env_name("weights-01.ckpt") == "SEALRUN_ARTIFACT_WEIGHTS_01_CKPT"
    assert artifact_env_name("a/b.bin") == "SEALRUN_ARTIFACT_A_B_BIN"
    # Deliberately the same variable name: callers must refuse this pair.
    assert artifact_env_name("a_b.bin") == "SEALRUN_ARTIFACT_A_B_BIN"


def test_child_environment_reports_verified_provenance():
    envelope = {"payload": {"release_id": "rel-9", "release_seq": 9, "artifacts": []},
                "signature": "eA=="}
    env = build_child_environment(envelope, [("model.bin", 7)], base={"PATH": "/bin"})
    assert env["PATH"] == "/bin"
    assert env["SEALRUN_MANIFEST_HASH"] == manifest_hash(envelope)
    assert env["SEALRUN_RELEASE_ID"] == "rel-9"
    assert env["SEALRUN_RELEASE_SEQ"] == "9"
    assert env["SEALRUN_ARTIFACT_MODEL_BIN"] == "/proc/self/fd/7"


def test_child_environment_ignores_non_string_release_id():
    envelope = {"payload": {"release_id": 42, "release_seq": True, "artifacts": []},
                "signature": "eA=="}
    env = build_child_environment(envelope, [], base={})
    assert "SEALRUN_RELEASE_ID" not in env
    assert "SEALRUN_RELEASE_SEQ" not in env


def test_child_environment_refuses_ambiguous_names():
    envelope = {"payload": {"artifacts": []}, "signature": "eA=="}
    with pytest.raises(VerificationError, match="ambiguous"):
        build_child_environment(envelope, [("a/b.bin", 3), ("a_b.bin", 4)], base={})


# --------------------------------------------------------------------------
# verification gates: failure means the command never runs
# --------------------------------------------------------------------------

def test_launch_runs_command_reading_verified_fd(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    out = tmp_path / "copied.bin"
    script = (
        "import os, sys\n"
        "with open(os.environ['SEALRUN_ARTIFACT_MODEL_BIN'], 'rb') as src:\n"
        "    data = src.read()\n"
        "with open(sys.argv[1], 'wb') as dst:\n"
        "    dst.write(data)\n"
    )
    rc = launch(root, envelope, private.pubkey_compressed(),
                [sys.executable, "-c", script, str(out)])
    assert rc == 0
    assert out.read_bytes() == b"model-v1"


def test_launch_inherits_environment_and_sets_provenance(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, release_id="rel-77", release_seq=77)
    out = tmp_path / "env.json"
    script = (
        "import json, os, sys\n"
        "keys = ('SEALRUN_MANIFEST_HASH', 'SEALRUN_RELEASE_ID',\n"
        "        'SEALRUN_RELEASE_SEQ', 'PATH')\n"
        "json.dump({k: os.environ.get(k) for k in keys}, open(sys.argv[1], 'w'))\n"
    )
    rc = launch(root, envelope, private.pubkey_compressed(),
                [sys.executable, "-c", script, str(out)])
    assert rc == 0
    child = json.loads(out.read_text(encoding="utf-8"))
    assert child["SEALRUN_MANIFEST_HASH"] == manifest_hash(envelope)
    assert child["SEALRUN_RELEASE_ID"] == "rel-77"
    assert child["SEALRUN_RELEASE_SEQ"] == "77"
    assert child["PATH"]  # inherited from the launcher's own environment


def test_launch_refuses_tampered_artifact_without_running(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    (root / "model.bin").write_bytes(b"tampered!")
    marker = tmp_path / "ran"
    with pytest.raises(VerificationError, match="integrity mismatch"):
        launch(root, envelope, private.pubkey_compressed(),
               [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"])
    assert not marker.exists()


def test_launch_refuses_bad_signature_without_running(tmp_path):
    root = setup_artifacts(tmp_path)
    _, envelope = make_signed(root)
    wrong = PrivKey.generate()
    marker = tmp_path / "ran"
    with pytest.raises(VerificationError, match="signature invalid"):
        launch(root, envelope, wrong.pubkey_compressed(),
               [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"])
    assert not marker.exists()


def test_launch_refuses_rollback_without_running(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, release_seq=1)
    marker = tmp_path / "ran"
    with pytest.raises(VerificationError, match="rollback rejected"):
        launch(root, envelope, private.pubkey_compressed(),
               [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"],
               min_release_seq=5)
    assert not marker.exists()


def test_launch_requires_a_command(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    for argv in ([], ["--"]):
        with pytest.raises(VerificationError, match="requires a command"):
            launch(root, envelope, private.pubkey_compressed(), argv)


def test_launch_rejects_ambiguous_artifact_names(tmp_path):
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    (root / "a" / "b.bin").write_bytes(b"one")
    (root / "a_b.bin").write_bytes(b"two")
    private = PrivKey.generate()
    payload = create_manifest(root, ["a/b.bin", "a_b.bin"], "collide", 1)
    envelope = sign_manifest(payload, private)
    with pytest.raises(VerificationError, match="ambiguous"):
        launch(root, envelope, private.pubkey_compressed(), ["true"])


def test_launch_propagates_child_exit_status(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    rc = launch(root, envelope, private.pubkey_compressed(),
                [sys.executable, "-c", "import sys; sys.exit(7)"])
    assert rc == 7


# --------------------------------------------------------------------------
# the core guarantee: pinned descriptors vs. path swaps
# --------------------------------------------------------------------------

def test_launch_passes_open_fds_not_paths(tmp_path, monkeypatch):
    """Replacing the path after verification must not change child bytes.

    The spy stands in for the child: it atomically replaces ``model.bin``
    (a new inode at the same path) *after* verification, then reads the
    descriptors the launcher would have handed it. The pinned descriptors
    still reference the verified inode, so the child sees the original
    bytes, not the swapped file.
    """
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)

    def swap_then_read(spy):
        replacement = root / "replacement.tmp"
        replacement.write_bytes(b"swapped-bytes")
        os.replace(replacement, root / "model.bin")
        spy.reads = [_read_fd(fd) for fd in spy.pass_fds]

    spy = _RunSpy(swap_then_read)
    install_spy(monkeypatch, spy)
    rc = launch(root, envelope, private.pubkey_compressed(), ["true"])
    assert rc == 0
    assert b"model-v1" in spy.reads
    assert b"swapped-bytes" not in spy.reads


def test_launch_without_seal_reflects_in_place_mutation(tmp_path, monkeypatch):
    """Document the residual caveat: an fd pins the inode, not its bytes.

    Without ``--seal`` a writer with access to the verified inode can
    still change what the child reads. This test asserts the caveat so it
    cannot regress silently into a false sense of immutability.
    """
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, paths=("model.bin",))

    def mutate_then_read(spy):
        with open(root / "model.bin", "r+b") as handle:
            handle.write(b"HACKED!!")
        spy.reads = [_read_fd(fd) for fd in spy.pass_fds]

    spy = _RunSpy(mutate_then_read)
    install_spy(monkeypatch, spy)
    launch(root, envelope, private.pubkey_compressed(), ["true"])
    assert spy.reads == [b"HACKED!!"]


def test_launch_with_seal_freezes_bytes(tmp_path, monkeypatch):
    """With ``--seal`` the same in-place mutation cannot reach the child."""
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, paths=("model.bin",))

    def mutate_then_read(spy):
        with open(root / "model.bin", "r+b") as handle:
            handle.write(b"HACKED!!")
        spy.reads = [_read_fd(fd) for fd in spy.pass_fds]

    spy = _RunSpy(mutate_then_read)
    install_spy(monkeypatch, spy)
    rc = launch(root, envelope, private.pubkey_compressed(), ["true"], seal=True)
    assert rc == 0
    assert spy.reads == [b"model-v1"]


def test_launch_with_seal_aborts_when_mutation_lands_before_copy(tmp_path, monkeypatch):
    """Regression (outside review, 2026-10-20): the verify→copy window.

    Verification hashes the artifact, then the seal copy is made from
    the same descriptor. A writer who mutates the source inode in
    between must not get the mutated bytes frozen into the sealed
    copy: the copy is re-hashed against the manifest, the launch
    aborts, and the child never runs.
    """
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root, paths=("model.bin",))
    real_seal = launcher._seal_fd

    def mutating_seal(src_fd, **kwargs):
        with open(root / "model.bin", "r+b") as handle:
            handle.write(b"HACKED!!")  # same length: a size-only check would miss it
        return real_seal(src_fd, **kwargs)

    monkeypatch.setattr(launcher, "_seal_fd", mutating_seal)
    spy = _RunSpy()
    install_spy(monkeypatch, spy)
    with pytest.raises(VerificationError):
        launch(root, envelope, private.pubkey_compressed(), ["true"], seal=True)
    assert spy.argv is None  # the child never launched


def test_seal_fd_rejects_copy_that_differs_from_expected(tmp_path):
    """Unit level: expected hash/size are enforced on the copied bytes."""
    import hashlib

    src = tmp_path / "src.bin"
    src.write_bytes(b"evil-bytes")  # 10 bytes, same length as the expected content
    expected = hashlib.sha256(b"model-v1!!").hexdigest()
    src_fd = os.open(src, os.O_RDONLY)
    try:
        with pytest.raises(VerificationError):
            _seal_fd(src_fd, expected_sha256=expected, expected_size=10)
    finally:
        os.close(src_fd)


def test_seal_fd_copies_and_freezes(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"frozen-bytes")
    src_fd = os.open(src, os.O_RDONLY)
    try:
        sealed = _seal_fd(src_fd)
    finally:
        os.close(src_fd)
    try:
        assert _read_fd(sealed) == b"frozen-bytes"
        with pytest.raises(OSError):
            os.write(sealed, b"x")
        with pytest.raises(OSError):
            os.ftruncate(sealed, 0)
        # A writer to the *source inode* cannot reach the frozen snapshot.
        src.write_bytes(b"changed-bytes")
        assert _read_fd(sealed) == b"frozen-bytes"
    finally:
        os.close(sealed)


def test_seal_fd_closes_memfd_on_read_failure(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"x")
    write_only = os.open(src, os.O_WRONLY)
    before = len(os.listdir("/proc/self/fd"))
    try:
        with pytest.raises(OSError):
            _seal_fd(write_only)
        assert len(os.listdir("/proc/self/fd")) == before
    finally:
        os.close(write_only)


# --------------------------------------------------------------------------
# descriptor hygiene
# --------------------------------------------------------------------------

def test_launch_passes_only_artifact_fds(tmp_path, monkeypatch):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)  # two artifacts
    unrelated = os.open(tmp_path / "unrelated", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        spy = _RunSpy()
        install_spy(monkeypatch, spy)
        launch(root, envelope, private.pubkey_compressed(), ["true"])
    finally:
        os.close(unrelated)
    assert len(spy.pass_fds) == 2
    assert len(set(spy.pass_fds)) == 2
    assert unrelated not in spy.pass_fds
    assert set(spy.env) >= {
        "SEALRUN_ARTIFACT_MODEL_BIN",
        "SEALRUN_ARTIFACT_CONFIG_JSON",
    }


@pytest.mark.parametrize("seal", [False, True])
def test_launch_does_not_leak_fds(tmp_path, seal):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    before = len(os.listdir("/proc/self/fd"))
    rc = launch(root, envelope, private.pubkey_compressed(),
                [sys.executable, "-c", "pass"], seal=seal)
    assert rc == 0
    assert len(os.listdir("/proc/self/fd")) == before


# --------------------------------------------------------------------------
# privilege drop
# --------------------------------------------------------------------------

def test_resolve_ids_accept_names_and_numbers():
    assert resolve_uid(None) is None
    assert resolve_gid(None) is None
    assert resolve_uid(os.getuid()) == os.getuid()
    assert resolve_uid(str(os.getuid())) == os.getuid()
    assert resolve_gid(os.getgid()) == os.getgid()
    assert resolve_gid(str(os.getgid())) == os.getgid()
    assert resolve_uid(pwd.getpwuid(os.getuid()).pw_name) == os.getuid()


def test_resolve_ids_reject_unknown_and_malformed():
    with pytest.raises(VerificationError, match="unknown user"):
        resolve_uid("no-such-user-sealrun-xyz")
    with pytest.raises(VerificationError, match="unknown group"):
        resolve_gid("no-such-group-sealrun-xyz")
    with pytest.raises(VerificationError, match="must be a name or numeric id"):
        resolve_uid("")
    with pytest.raises(VerificationError, match="must be a name or numeric id"):
        resolve_uid(True)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can setuid, so the drop succeeds")
def test_launch_refuses_unprivileged_privilege_drop(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    marker = tmp_path / "ran"
    with pytest.raises(VerificationError, match="cannot drop privileges"):
        launch(root, envelope, private.pubkey_compressed(),
               [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"],
               uid=0, gid=0)
    assert not marker.exists()


def test_launch_defaults_gid_to_target_users_group(tmp_path, monkeypatch):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    spy = _RunSpy()
    install_spy(monkeypatch, spy)
    rc = launch(root, envelope, private.pubkey_compressed(), ["true"],
                uid=os.getuid())
    assert rc == 0
    assert spy.user == os.getuid()
    assert spy.group == pwd.getpwuid(os.getuid()).pw_gid
    # Not privileged in the test, so supplementary groups are left alone.
    assert spy.extra_groups is None


def test_launch_uid_without_passwd_entry_requires_gid(tmp_path):
    root = setup_artifacts(tmp_path)
    private, envelope = make_signed(root)
    with pytest.raises(VerificationError, match="no passwd entry"):
        launch(root, envelope, private.pubkey_compressed(), ["true"],
               uid=2 ** 31 - 1)


# --------------------------------------------------------------------------
# CLI integration
# --------------------------------------------------------------------------

def _write_signed_bundle(tmp_path: Path):
    root = setup_artifacts(tmp_path)
    priv = tmp_path / "private.wif"
    pub = tmp_path / "public.pub"
    generate_keypair(priv, pub)
    payload = create_manifest(root, ["model.bin", "config.json"], "cli-release", 1)
    envelope = sign_manifest(payload, load_private_key(priv))
    manifest = tmp_path / "manifest.signed.json"
    manifest.write_text(json.dumps(envelope), encoding="utf-8")
    return root, manifest, pub


def test_cli_launch_round_trip(tmp_path):
    root, manifest, pub = _write_signed_bundle(tmp_path)
    out = tmp_path / "copied.bin"
    script = (
        "import os, sys\n"
        "with open(os.environ['SEALRUN_ARTIFACT_MODEL_BIN'], 'rb') as src:\n"
        "    data = src.read()\n"
        "open(sys.argv[1], 'wb').write(data)\n"
    )
    rc = main([
        "launch",
        "--root", str(root),
        "--manifest", str(manifest),
        "--public-key", str(pub),
        "--", sys.executable, "-c", script, str(out),
    ])
    assert rc == 0
    assert out.read_bytes() == b"model-v1"


def test_cli_launch_seal_flag(tmp_path):
    root, manifest, pub = _write_signed_bundle(tmp_path)
    out = tmp_path / "copied.bin"
    script = (
        "import os, sys\n"
        "with open(os.environ['SEALRUN_ARTIFACT_MODEL_BIN'], 'rb') as src:\n"
        "    data = src.read()\n"
        "open(sys.argv[1], 'wb').write(data)\n"
    )
    rc = main([
        "launch", "--seal",
        "--root", str(root),
        "--manifest", str(manifest),
        "--public-key", str(pub),
        "--", sys.executable, "-c", script, str(out),
    ])
    assert rc == 0
    assert out.read_bytes() == b"model-v1"


def test_cli_launch_refuses_tampered_artifact(tmp_path, capsys):
    root, manifest, pub = _write_signed_bundle(tmp_path)
    (root / "model.bin").write_bytes(b"tampered")
    rc = main([
        "launch",
        "--root", str(root),
        "--manifest", str(manifest),
        "--public-key", str(pub),
        "--", sys.executable, "-c", "pass",
    ])
    assert rc == 1
    assert "ERROR:" in capsys.readouterr().err


def test_cli_launch_requires_command(tmp_path, capsys):
    root, manifest, pub = _write_signed_bundle(tmp_path)
    rc = main([
        "launch",
        "--root", str(root),
        "--manifest", str(manifest),
        "--public-key", str(pub),
        "--",
    ])
    assert rc == 1
    assert "requires a command" in capsys.readouterr().err


def test_cli_launch_unknown_uid_is_reported(tmp_path, capsys):
    root, manifest, pub = _write_signed_bundle(tmp_path)
    rc = main([
        "launch",
        "--root", str(root),
        "--manifest", str(manifest),
        "--public-key", str(pub),
        "--uid", "no-such-user-sealrun-xyz",
        "--", sys.executable, "-c", "pass",
    ])
    assert rc == 1
    assert "unknown user" in capsys.readouterr().err
