import hashlib
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import sealrun.cli as cli
from sealrun.core import load_private_key, load_public_key


def _set_environment(
    monkeypatch, *, installed=True, importable=True, pip=True, version=(3, 11, 0)
):
    monkeypatch.setattr(cli.sys, "version_info", version)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0 if pip else 1,
            stdout="pip 25.0" if pip else "",
            stderr="" if pip else "No module named pip",
        ),
    )

    def distribution(name):
        if installed:
            return object()
        raise cli.PackageNotFoundError(name)

    def import_module(name):
        if importable:
            return object()
        raise ImportError("module unavailable")

    monkeypatch.setattr(cli, "distribution", distribution)
    monkeypatch.setattr(cli, "import_module", import_module)


def _setup_args(private_path, public_path):
    return [
        "setup",
        "--private-key", str(private_path),
        "--public-key", str(public_path),
    ]


def test_setup_checks_environment_and_generates_demo_keypair(tmp_path, monkeypatch, capsys):
    _set_environment(monkeypatch)
    private_path = tmp_path / "keys" / "private.wif"
    public_path = tmp_path / "keys" / "public.pub"

    assert cli.main(_setup_args(private_path, public_path)) == 0

    output = capsys.readouterr().out
    assert "PASS: Python >= 3.10" in output
    assert "PASS: pip available" in output
    assert "PASS: SealRun installed and importable" in output
    assert "DEMONSTRATION keys" in output
    public_key = load_public_key(public_path)
    private_key = load_private_key(private_path)
    assert public_key == private_key.pubkey_compressed()
    assert private_path.read_text(encoding="ascii").strip() not in output
    assert f"Public key: {public_key.hex()}" in output
    assert f"Public key SHA-256: {hashlib.sha256(public_key).hexdigest()}" in output
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert f"mode {stat.S_IMODE(private_path.stat().st_mode):04o}" in output


def test_setup_stops_when_python_is_too_old(tmp_path, monkeypatch, capsys):
    _set_environment(monkeypatch, installed=False, version=(3, 9, 9))
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("unexpected prompt"))
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"

    assert cli.main(_setup_args(private_path, public_path)) == 1

    output = capsys.readouterr()
    assert "FAIL: Python >= 3.10" in output.out
    assert "PASS: pip available" in output.out
    assert "FAIL: SealRun installed and importable" in output.out
    assert "Recommended install command" in output.out
    assert "requires Python 3.10 or newer" in output.err
    assert not private_path.exists()
    assert not public_path.exists()


def test_setup_stops_when_pip_is_unavailable(tmp_path, monkeypatch, capsys):
    _set_environment(monkeypatch, installed=False, pip=False)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("unexpected prompt"))
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"

    assert cli.main(_setup_args(private_path, public_path)) == 1

    output = capsys.readouterr()
    assert "FAIL: pip available" in output.out
    assert "Recommended install command" in output.out
    assert "Setup stopped: pip is unavailable" in output.err
    assert not private_path.exists()
    assert not public_path.exists()


def test_setup_requires_approval_to_install_sealrun(tmp_path, monkeypatch, capsys):
    _set_environment(monkeypatch, installed=False)
    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"

    assert cli.main(_setup_args(private_path, public_path)) == 1

    output = capsys.readouterr()
    assert "FAIL: SealRun installed and importable" in output.out
    assert "Recommended install command" in output.out
    assert "installation was not approved" in output.err
    assert not private_path.exists()
    assert not public_path.exists()


def test_setup_installs_only_after_approval_and_rechecks(tmp_path, monkeypatch, capsys):
    _set_environment(monkeypatch, installed=False)
    installation = {"complete": False}
    original_distribution = cli.distribution

    def distribution(name):
        if installation["complete"]:
            return object()
        return original_distribution(name)

    monkeypatch.setattr(cli, "distribution", distribution)
    commands = []

    def run(command, *, cwd, check):
        commands.append((command, cwd, check))
        installation["complete"] = True
        return SimpleNamespace(returncode=0)

    def run_with_pip_check(command, **kwargs):
        if command[-1] == "--version":
            return SimpleNamespace(returncode=0, stdout="pip 25.0", stderr="")
        return run(command, **kwargs)

    monkeypatch.setattr(cli.subprocess, "run", run_with_pip_check)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"

    assert cli.main(_setup_args(private_path, public_path)) == 0

    assert commands == [
        (
            [cli.sys.executable, "-m", "pip", "install", "-e", "."],
            Path(cli.__file__).resolve().parent.parent,
            False,
        )
    ]
    assert capsys.readouterr().out.count("PASS: SealRun installed and importable") == 1
    assert (
        load_public_key(public_path)
        == load_private_key(private_path).pubkey_compressed()
    )


def test_setup_does_not_overwrite_existing_keys_without_approval(tmp_path, monkeypatch, capsys):
    _set_environment(monkeypatch)
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"
    private_path.write_bytes(b"existing private bytes")
    public_path.write_bytes(b"existing public bytes")
    monkeypatch.setattr("builtins.input", lambda prompt: "no")

    assert cli.main(_setup_args(private_path, public_path)) == 1

    output = capsys.readouterr()
    assert "existing key files were not changed" in output.err
    assert private_path.read_bytes() == b"existing private bytes"
    assert public_path.read_bytes() == b"existing public bytes"


def test_setup_overwrites_existing_keys_only_after_approval(tmp_path, monkeypatch):
    _set_environment(monkeypatch)
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"
    private_path.write_bytes(b"old private")
    public_path.write_bytes(b"old public")
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")

    assert cli.main(_setup_args(private_path, public_path)) == 0
    assert (
        load_public_key(public_path)
        == load_private_key(private_path).pubkey_compressed()
    )


def test_setup_does_not_install_when_installed_package_is_not_importable(
    tmp_path, monkeypatch, capsys
):
    _set_environment(monkeypatch, importable=False)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("unexpected prompt"))
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"

    assert cli.main(_setup_args(private_path, public_path)) == 1

    output = capsys.readouterr()
    assert "FAIL: SealRun installed and importable" in output.out
    assert "installed but could not be imported" in output.err
    assert not private_path.exists()
    assert not public_path.exists()
