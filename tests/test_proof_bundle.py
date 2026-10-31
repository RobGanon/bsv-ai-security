"""Tests for proof bundles (sealrun proof-bundle-create / proof-bundle-verify).

A bundle must never be created from an unverified run, must never
contain private-key material, and must never verify (exit 0) after
tampering with an artifact, the journal, the public key, or the
manifest. These tests exercise the CLI, so a failure means the
shipped command fails, not just a library helper.
"""
import json
import re
import zipfile
from pathlib import Path

import pytest

from sealrun import __version__ as sealrun_version
from sealrun.bsv import PrivKey
from sealrun.cli import main
from sealrun.core import (
    append_audit_event,
    create_manifest,
    sign_manifest,
)
from sealrun.proof_bundle import BUNDLE_SCHEMA


def make_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    root.mkdir()
    (root / "model.bin").write_bytes(b"model-v1")
    (root / "config.json").write_text('{"safe":true}\n', encoding="utf-8")
    return root


def make_signed(tmp_path: Path, root: Path, extra_files: dict | None = None):
    """Write a signed envelope + public key for root's artifacts."""
    private = PrivKey.generate()
    names = ["model.bin", "config.json"]
    if extra_files:
        for name, data in extra_files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(data, str):
                path.write_text(data, encoding="utf-8")
            else:
                path.write_bytes(data)
            names.append(name)
    payload = create_manifest(root, names, "test-release", 1)
    envelope = sign_manifest(payload, private)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    pubkey_path = tmp_path / "public.pub"
    pubkey_path.write_text(private.pubkey_compressed().hex() + "\n", encoding="utf-8")
    return private, manifest_path, pubkey_path


def create_bundle_cli(tmp_path, manifest_path, pubkey_path, root, journal=None, anchor=None):
    bundle = tmp_path / "bundle.zip"
    argv = ["proof-bundle-create", "--manifest", str(manifest_path),
            "--public-key", str(pubkey_path), "--root", str(root),
            "--output", str(bundle)]
    if journal is not None:
        argv += ["--journal", str(journal)]
    if anchor is not None:
        argv += ["--anchor", str(anchor)]
    assert main(argv) == 0
    assert bundle.is_file()
    return bundle


def rebuild_zip(bundle: Path, out: Path, mutate: dict | None = None, remove: set | None = None):
    """Rewrite a bundle, optionally replacing/removing entries."""
    mutate = mutate or {}
    remove = remove or set()
    with zipfile.ZipFile(bundle) as zin:
        entries = {name: zin.read(name) for name in zin.namelist()}
    for name in remove:
        entries.pop(name, None)
    entries.update(mutate)
    with zipfile.ZipFile(out, "w") as zout:
        for name, data in entries.items():
            zout.writestr(name, data)
    return out


def test_version_flag_prints_version_and_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert f"sealrun {sealrun_version}" in capsys.readouterr().out


def test_version_matches_pyproject():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    match = re.search(r'^version = "([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M)
    assert match is not None
    assert sealrun_version == match.group(1)


def test_bundle_round_trip_no_journal_no_anchor(tmp_path, capsys):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(tmp_path, root)
    bundle = create_bundle_cli(tmp_path, manifest, pubkey, root)
    with zipfile.ZipFile(bundle) as zf:
        names = zf.namelist()
        assert names[-1] == "bundle.json"
        assert names[:-1] == sorted(names[:-1])
        doc = json.loads(zf.read("bundle.json"))
    assert doc["schema"] == BUNDLE_SCHEMA
    assert doc["artifacts"] == ["model.bin", "config.json"]
    assert doc["journal"] is None
    assert doc["anchor"] is None
    assert doc["claims"]["does_not_prove"]

    assert main(["proof-bundle-verify", "--bundle", str(bundle)]) == 0
    out = capsys.readouterr().out
    assert "BUNDLE VERIFIED: 2 artifact(s)" in out
    assert "journal: absent" in out
    assert "anchor: absent" in out
    assert "does NOT prove" in out


def test_bundle_round_trip_with_journal_and_anchor(tmp_path, capsys):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(tmp_path, root)
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    append_audit_event(journal, "test", "second")
    anchor = tmp_path / "anchor.json"
    assert main(["anchor-payload", "--journal", str(journal),
                 "--start-seq", "1", "--output", str(anchor)]) == 0
    bundle = create_bundle_cli(tmp_path, manifest, pubkey, root,
                               journal=journal, anchor=anchor)
    with zipfile.ZipFile(bundle) as zf:
        doc = json.loads(zf.read("bundle.json"))
    assert doc["journal"] == "journal.json"
    assert doc["journal_events"] == 2
    assert doc["anchor_verified"] is True

    assert main(["proof-bundle-verify", "--bundle", str(bundle)]) == 0
    out = capsys.readouterr().out
    assert "BUNDLE VERIFIED: 2 artifact(s)" in out
    assert "journal events: 2" in out
    assert "anchor: journal head matches anchor payload" in out


def test_bundle_with_journal_but_no_anchor_verifies(tmp_path):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(tmp_path, root)
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "only")
    bundle = create_bundle_cli(tmp_path, manifest, pubkey, root, journal=journal)
    assert main(["proof-bundle-verify", "--bundle", str(bundle)]) == 0


def test_create_refuses_unverified_run(tmp_path):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(tmp_path, root)
    (root / "model.bin").write_bytes(b"tampered before packing")
    bundle = tmp_path / "bundle.zip"
    assert main(["proof-bundle-create", "--manifest", str(manifest),
                 "--public-key", str(pubkey), "--root", str(root),
                 "--output", str(bundle)]) == 1
    assert not bundle.exists()


def test_create_refuses_private_key_artifact(tmp_path):
    root = make_root(tmp_path)
    secret = PrivKey.generate()
    _, manifest, pubkey = make_signed(
        tmp_path, root, extra_files={"secret.wif": secret.wif(network="testnet") + "\n"}
    )
    bundle = tmp_path / "bundle.zip"
    assert main(["proof-bundle-create", "--manifest", str(manifest),
                 "--public-key", str(pubkey), "--root", str(root),
                 "--output", str(bundle)]) == 1
    assert not bundle.exists()


def test_create_refuses_private_key_filename(tmp_path):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(
        tmp_path, root, extra_files={"private_key.txt": "harmless text\n"}
    )
    bundle = tmp_path / "bundle.zip"
    assert main(["proof-bundle-create", "--manifest", str(manifest),
                 "--public-key", str(pubkey), "--root", str(root),
                 "--output", str(bundle)]) == 1
    assert not bundle.exists()


def test_verify_fails_on_tampered_artifact(tmp_path):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(tmp_path, root)
    bundle = create_bundle_cli(tmp_path, manifest, pubkey, root)
    bad = rebuild_zip(bundle, tmp_path / "bad.zip",
                      mutate={"artifacts/model.bin": b"tampered"})
    assert main(["proof-bundle-verify", "--bundle", str(bad)]) == 1


def test_verify_fails_on_tampered_journal(tmp_path):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(tmp_path, root)
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    bundle = create_bundle_cli(tmp_path, manifest, pubkey, root, journal=journal)
    tampered = journal.read_text(encoding="utf-8").replace("first", "forged")
    bad = rebuild_zip(bundle, tmp_path / "bad.zip",
                      mutate={"journal.json": tampered.encode("utf-8")})
    assert main(["proof-bundle-verify", "--bundle", str(bad)]) == 1


def test_verify_fails_on_wrong_public_key(tmp_path):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(tmp_path, root)
    bundle = create_bundle_cli(tmp_path, manifest, pubkey, root)
    other = PrivKey.generate()
    bad = rebuild_zip(bundle, tmp_path / "bad.zip",
                      mutate={"public_key": (other.pubkey_compressed().hex() + "\n").encode("ascii")})
    assert main(["proof-bundle-verify", "--bundle", str(bad)]) == 1


def test_verify_fails_on_missing_manifest(tmp_path):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(tmp_path, root)
    bundle = create_bundle_cli(tmp_path, manifest, pubkey, root)
    bad = rebuild_zip(bundle, tmp_path / "bad.zip", remove={"manifest.json"})
    assert main(["proof-bundle-verify", "--bundle", str(bad)]) == 1


def test_verify_fails_on_missing_bundle_json(tmp_path):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(tmp_path, root)
    bundle = create_bundle_cli(tmp_path, manifest, pubkey, root)
    bad = rebuild_zip(bundle, tmp_path / "bad.zip", remove={"bundle.json"})
    assert main(["proof-bundle-verify", "--bundle", str(bad)]) == 1


def test_bundle_layout_is_deterministic(tmp_path):
    root = make_root(tmp_path)
    _, manifest, pubkey = make_signed(tmp_path, root)
    b1 = create_bundle_cli(tmp_path, manifest, pubkey, root)
    bundle2 = tmp_path / "bundle2.zip"
    assert main(["proof-bundle-create", "--manifest", str(manifest),
                 "--public-key", str(pubkey), "--root", str(root),
                 "--output", str(bundle2)]) == 0
    with zipfile.ZipFile(b1) as z1, zipfile.ZipFile(bundle2) as z2:
        assert z1.namelist() == z2.namelist()
