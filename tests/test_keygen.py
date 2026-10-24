import os
import stat

import pytest

from sealrun.cli import main
from sealrun.core import generate_keypair, load_private_key, load_public_key


def _keygen_args(private_path, public_path):
    return [
        "keygen",
        "--private-key", str(private_path),
        "--public-key", str(public_path),
    ]


def _assert_matching_pair(private_path, public_path):
    private = load_private_key(private_path)
    public = load_public_key(public_path)
    assert public == private.pubkey_compressed()


def test_fresh_paths_create_loadable_matching_keypair(tmp_path, capsys):
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"

    assert main(_keygen_args(private_path, public_path)) == 0

    assert capsys.readouterr().out == (
        "Development keypair generated. Protect the private key.\n"
    )
    assert private_path.is_file()
    assert public_path.is_file()
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(public_path.stat().st_mode) == 0o644
    _assert_matching_pair(private_path, public_path)


def test_existing_private_key_refused_without_partial_write(tmp_path, capsys):
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"
    original = b"existing private key bytes\n"
    private_path.write_bytes(original)

    assert main(_keygen_args(private_path, public_path)) == 1

    assert str(private_path) in capsys.readouterr().err
    assert private_path.read_bytes() == original
    assert not os.path.lexists(public_path)


def test_existing_public_key_refused_without_partial_write(tmp_path, capsys):
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"
    original = b"existing public key bytes\n"
    public_path.write_bytes(original)

    assert main(_keygen_args(private_path, public_path)) == 1

    assert str(public_path) in capsys.readouterr().err
    assert public_path.read_bytes() == original
    assert not os.path.lexists(private_path)


def test_existing_keypair_refused_without_changes(tmp_path, capsys):
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"
    original_private = b"existing private key bytes\n"
    original_public = b"existing public key bytes\n"
    private_path.write_bytes(original_private)
    public_path.write_bytes(original_public)

    assert main(_keygen_args(private_path, public_path)) == 1

    assert str(private_path) in capsys.readouterr().err
    assert private_path.read_bytes() == original_private
    assert public_path.read_bytes() == original_public


def test_force_overwrites_existing_keypair(tmp_path):
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"
    private_path.write_bytes(b"old private key bytes\n")
    public_path.write_bytes(b"old public key bytes\n")

    assert main(_keygen_args(private_path, public_path) + ["--force"]) == 0

    assert private_path.read_bytes() != b"old private key bytes\n"
    assert public_path.read_bytes() != b"old public key bytes\n"
    _assert_matching_pair(private_path, public_path)


def test_aliased_paths_remain_refused(tmp_path):
    private_path = tmp_path / "same.key"
    public_path = tmp_path / "nested" / ".." / "same.key"

    with pytest.raises(ValueError, match="private and public key paths must be different"):
        generate_keypair(private_path, public_path)

    assert not os.path.lexists(private_path)


@pytest.mark.parametrize("which_path", ["private", "public"])
def test_dangling_symlink_refused_without_partial_write(tmp_path, which_path):
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"
    selected = private_path if which_path == "private" else public_path
    other = public_path if which_path == "private" else private_path
    selected.symlink_to(tmp_path / "missing-target")

    with pytest.raises(ValueError, match="already exists") as exc_info:
        generate_keypair(private_path, public_path)

    assert str(selected) in str(exc_info.value)
    assert selected.is_symlink()
    assert not os.path.lexists(other)
