import hashlib
import json
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


def _set_responses(
    monkeypatch,
    responses,
    *,
    signed_manifest_bytes=b'{"payload": {}, "signature": "manual"}\n',
):
    answers = iter(responses)

    def answer(prompt):
        try:
            response = next(answers)
        except StopIteration:
            pytest.fail(f"unexpected setup prompt: {prompt}")
        if (
            prompt.startswith("After running it successfully")
            and response.strip().lower() in {"y", "yes"}
        ):
            signed_path = Path("state/manifest.signed.json")
            signed_path.parent.mkdir(parents=True, exist_ok=True)
            content = (
                signed_manifest_bytes()
                if callable(signed_manifest_bytes)
                else signed_manifest_bytes
            )
            if content is not None:
                signed_path.write_bytes(content)
        return response

    monkeypatch.setattr("builtins.input", answer)


def test_setup_checks_environment_and_generates_demo_keypair(tmp_path, monkeypatch, capsys):
    _set_environment(monkeypatch)
    monkeypatch.chdir(tmp_path)
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("demo", encoding="utf-8")
    _set_responses(
        monkeypatch,
        ["1", str(artifact), "yes", "demo-release", "1", "yes"],
    )
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
    monkeypatch.chdir(tmp_path)
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("demo", encoding="utf-8")
    _set_responses(
        monkeypatch,
        ["yes", "1", str(artifact), "yes", "demo-release", "1", "yes"],
    )

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
    monkeypatch.chdir(tmp_path)
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"
    private_path.write_bytes(b"old private")
    public_path.write_bytes(b"old public")
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("demo", encoding="utf-8")
    _set_responses(
        monkeypatch,
        ["yes", "1", str(artifact), "yes", "demo-release", "1", "yes"],
    )

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


def _run_setup_with_responses(
    tmp_path,
    monkeypatch,
    responses,
    *,
    manual_sign_response="yes",
    signed_manifest_bytes=b'{"payload": {}, "signature": "manual"}\n',
):
    _set_environment(monkeypatch)
    monkeypatch.chdir(tmp_path)
    _set_responses(
        monkeypatch,
        [*responses, manual_sign_response],
        signed_manifest_bytes=signed_manifest_bytes,
    )
    private_path = tmp_path / "private.wif"
    public_path = tmp_path / "public.pub"
    return cli.main(_setup_args(private_path, public_path)), private_path, public_path


def test_setup_collects_recursive_directory_artifacts_and_confirms_list(
    tmp_path, monkeypatch, capsys
):
    root = tmp_path / "artifacts"
    nested = root / "nested"
    nested.mkdir(parents=True)
    first = root / "first.txt"
    second = nested / "second.txt"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    result, _, _ = _run_setup_with_responses(
        tmp_path,
        monkeypatch,
        ["1", str(root), "yes", "demo-release", "1"],
    )

    assert result == 0
    output = capsys.readouterr().out
    assert f"- {first}" in output
    assert f"- {second}" in output
    assert "Stage 3 complete: 2 artifact(s) confirmed." in output
    manifest = json.loads((tmp_path / "state" / "manifest.json").read_text())
    assert [item["path"] for item in manifest["artifacts"]] == [
        "first.txt",
        "nested/second.txt",
    ]


def test_setup_accepts_quoted_file_paths(tmp_path, monkeypatch, capsys):
    first = tmp_path / "one file.txt"
    second = tmp_path / "two file.txt"
    first.write_text("one", encoding="utf-8")
    second.write_text("two", encoding="utf-8")
    raw_paths = f'"{first}" "{second}"'

    result, _, _ = _run_setup_with_responses(
        tmp_path, monkeypatch, ["1", raw_paths, "yes", "demo-release", "1"]
    )

    assert result == 0
    output = capsys.readouterr().out
    assert f"- {first}" in output
    assert f"- {second}" in output


def test_setup_reports_missing_path_and_allows_retry(tmp_path, monkeypatch, capsys):
    missing = tmp_path / "missing.txt"
    existing = tmp_path / "existing.txt"
    existing.write_text("content", encoding="utf-8")

    result, _, _ = _run_setup_with_responses(
        tmp_path,
        monkeypatch,
        ["1", str(missing), "r", str(existing), "yes", "demo-release", "1"],
    )

    assert result == 0
    output = capsys.readouterr()
    assert f"path does not exist: {missing}" in output.err
    assert f"- {existing}" in output.out
    assert f"- {missing}" not in output.out


def test_setup_reports_unreadable_file_and_stops_cleanly(
    tmp_path, monkeypatch, capsys
):
    unreadable = tmp_path / "unreadable.txt"
    unreadable.write_text("content", encoding="utf-8")
    check_path = cli._artifact_path_error

    def reject_file(path):
        if path == unreadable:
            return f"file is not readable: {path} (permission denied)"
        return check_path(path)

    monkeypatch.setattr(cli, "_artifact_path_error", reject_file)

    result, _, _ = _run_setup_with_responses(
        tmp_path, monkeypatch, ["1", str(unreadable), "q"]
    )

    assert result == 1
    output = capsys.readouterr()
    assert f"file is not readable: {unreadable}" in output.err
    assert "no valid artifacts were provided" in output.err


def test_setup_rejects_empty_directory_and_allows_stop(tmp_path, monkeypatch, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()

    result, _, _ = _run_setup_with_responses(
        tmp_path, monkeypatch, ["1", str(empty), "q"]
    )

    assert result == 1
    output = capsys.readouterr()
    assert f"directory contains no files: {empty}" in output.err
    assert "no valid artifacts were provided" in output.err


def test_setup_creates_and_confirms_marked_demo_artifacts(
    tmp_path, monkeypatch, capsys
):
    demo_root = tmp_path / "demo-artifacts"

    def make_demo_directory(prefix):
        demo_root.mkdir()
        return str(demo_root)

    monkeypatch.setattr(cli.tempfile, "mkdtemp", make_demo_directory)
    result, _, _ = _run_setup_with_responses(
        tmp_path, monkeypatch, ["2", "yes", "demo-release", "1"]
    )

    assert result == 0
    demo_files = sorted(demo_root.iterdir())
    assert len(demo_files) == 3
    assert all(
        "DEMO CONTENT ONLY" in path.read_text(encoding="utf-8")
        for path in demo_files
    )
    output = capsys.readouterr().out
    assert "Created three DEMO CONTENT ONLY text artifacts." in output
    assert all(str(path) in output for path in demo_files)
    assert (tmp_path / "state" / "manifest.json").is_file()


def test_setup_removes_unconfirmed_demo_artifacts(tmp_path, monkeypatch, capsys):
    demo_root = tmp_path / "demo-artifacts"

    def make_demo_directory(prefix):
        demo_root.mkdir()
        return str(demo_root)

    monkeypatch.setattr(cli.tempfile, "mkdtemp", make_demo_directory)

    result, _, _ = _run_setup_with_responses(
        tmp_path, monkeypatch, ["2", "no"]
    )

    assert result == 1
    assert not demo_root.exists()
    assert "artifact list was not confirmed" in capsys.readouterr().err


def test_setup_stops_when_user_declines_artifact_list(tmp_path, monkeypatch, capsys):
    artifact = tmp_path / "sample.txt"
    artifact.write_text("content", encoding="utf-8")
    result, _, _ = _run_setup_with_responses(
        tmp_path, monkeypatch, ["1", str(artifact), "no"]
    )

    assert result == 1
    assert "artifact list was not confirmed" in capsys.readouterr().err
    assert artifact.is_file()


def test_setup_stage4_shows_exact_unsigned_manifest_and_public_key(
    tmp_path, monkeypatch, capsys
):
    artifact = tmp_path / "model-notes.txt"
    artifact.write_text("demo artifact", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "sign_manifest",
        lambda *args, **kwargs: pytest.fail("Stage 4 must not sign the manifest"),
    )

    result, private_path, public_path = _run_setup_with_responses(
        tmp_path,
        monkeypatch,
        ["1", str(artifact), "yes", "", "1"],
    )

    assert result == 0
    output = capsys.readouterr().out
    manifest_path = tmp_path / "state" / "manifest.json"
    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    public_key = load_public_key(public_path)
    assert f"Unsigned manifest written: {Path('state/manifest.json')}" in output
    assert (
        "Public key for later verification (out of band; not embedded in "
        f"the signed manifest): {public_key.hex()}"
    ) in output
    assert "Unsigned manifest contents (the exact payload Stage 5 will sign):" in output
    assert manifest_text in output
    assert manifest["release_id"] == "local-dev-release"
    assert manifest["release_seq"] == 1
    assert manifest["artifacts"] == [
        {
            "path": artifact.name,
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "size": len(artifact.read_bytes()),
        }
    ]
    assert "public_key" not in manifest
    assert "signature" not in manifest
    assert private_path.is_file()


def test_setup_stage4_refuses_existing_manifest_without_overwriting(
    tmp_path, monkeypatch, capsys
):
    artifact = tmp_path / "input.txt"
    artifact.write_text("input", encoding="utf-8")
    manifest_path = tmp_path / "state" / "manifest.json"
    manifest_path.parent.mkdir()
    existing = b"existing manifest bytes\n"
    manifest_path.write_bytes(existing)

    result, _, _ = _run_setup_with_responses(
        tmp_path, monkeypatch, ["1", str(artifact), "yes"]
    )

    assert result == 1
    assert manifest_path.read_bytes() == existing
    assert f"manifest file already exists: {Path('state/manifest.json')}" in (
        capsys.readouterr().err
    )


def test_setup_stage4_reports_manifest_creation_errors(tmp_path, monkeypatch, capsys):
    artifact = tmp_path / "input.txt"
    artifact.write_text("input", encoding="utf-8")

    def fail_manifest(*args, **kwargs):
        raise cli.VerificationError("synthetic manifest failure")

    monkeypatch.setattr(cli, "create_manifest", fail_manifest)
    result, _, _ = _run_setup_with_responses(
        tmp_path,
        monkeypatch,
        ["1", str(artifact), "yes", "demo-release", "1"],
    )

    assert result == 1
    assert "manifest creation failed: synthetic manifest failure" in (
        capsys.readouterr().err
    )
    assert not (tmp_path / "state" / "manifest.json").exists()


def test_setup_stage5_displays_manual_command_and_hands_off_unverified_manifest(
    tmp_path, monkeypatch, capsys
):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("contents", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "sign_manifest",
        lambda *args, **kwargs: pytest.fail("Stage 5 must not sign the manifest"),
    )

    result, private_path, _ = _run_setup_with_responses(
        tmp_path,
        monkeypatch,
        ["1", str(artifact), "yes", "demo-release", "1"],
    )

    assert result == 0
    output = capsys.readouterr().out
    assert "Stage 5 — Manual manifest signing" in output
    assert "Review the unsigned manifest. This exact payload will be signed:" in output
    assert '"sha256":' in output
    assert (
        "sealrun manifest-sign --manifest state/manifest.json --private-key "
        f"{private_path} --output state/manifest.signed.json"
    ) in output
    assert "The wizard will not run the signing command or access the private key." in output
    assert f"Signed manifest received: {Path('state/manifest.signed.json')}" in output
    assert "NOT VERIFIED. Stage 6 must verify the signature and artifact hashes" in output
    assert "VERIFIED:" not in output
    assert "sealrun launch" not in output
    assert "sealrun anchor" not in output


def test_setup_stage5_stops_when_manual_signing_is_refused(
    tmp_path, monkeypatch, capsys
):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("contents", encoding="utf-8")

    result, _, _ = _run_setup_with_responses(
        tmp_path,
        monkeypatch,
        ["1", str(artifact), "yes", "demo-release", "1"],
        manual_sign_response="no",
    )

    assert result == 1
    assert not (tmp_path / "state" / "manifest.signed.json").exists()
    assert "manual signing was refused or not confirmed" in capsys.readouterr().err


def test_setup_stage5_stops_when_manual_signing_does_not_produce_a_file(
    tmp_path, monkeypatch, capsys
):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("contents", encoding="utf-8")

    result, _, _ = _run_setup_with_responses(
        tmp_path,
        monkeypatch,
        ["1", str(artifact), "yes", "demo-release", "1"],
        signed_manifest_bytes=None,
    )

    assert result == 1
    assert not (tmp_path / "state" / "manifest.signed.json").exists()
    assert "signed manifest was not produced" in capsys.readouterr().err


def test_setup_stage5_hands_invalid_signature_to_mandatory_verify_gate(
    tmp_path, monkeypatch, capsys
):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("contents", encoding="utf-8")
    signed_manifest_bytes = (
        b'{"payload": {"release_seq": 1}, "signature": "invalid-signature"}\n'
    )

    result, _, _ = _run_setup_with_responses(
        tmp_path,
        monkeypatch,
        ["1", str(artifact), "yes", "demo-release", "1"],
        signed_manifest_bytes=signed_manifest_bytes,
    )

    output = capsys.readouterr().out
    assert result == 0
    assert (tmp_path / "state" / "manifest.signed.json").read_bytes() == (
        signed_manifest_bytes
    )
    assert "Signed manifest received:" in output
    assert "NOT VERIFIED. Stage 6 must verify the signature and artifact hashes" in output
    assert "VERIFIED:" not in output


def test_setup_stage5_hands_tampered_signed_manifest_to_mandatory_verify_gate(
    tmp_path, monkeypatch, capsys
):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("contents", encoding="utf-8")

    def sign_then_tamper():
        payload = cli._read_json(Path("state/manifest.json"))
        signed = cli.sign_manifest(payload, load_private_key(Path("private.wif")))
        signed["payload"]["release_id"] = "tampered-after-signing"
        return json.dumps(signed).encode("utf-8")

    result, _, _ = _run_setup_with_responses(
        tmp_path,
        monkeypatch,
        ["1", str(artifact), "yes", "demo-release", "1"],
        signed_manifest_bytes=sign_then_tamper,
    )

    output = capsys.readouterr().out
    signed = json.loads(
        (tmp_path / "state" / "manifest.signed.json").read_text(encoding="utf-8")
    )
    assert result == 0
    assert signed["payload"]["release_id"] == "tampered-after-signing"
    assert "signature" in signed
    assert "Signed manifest received:" in output
    assert "NOT VERIFIED. Stage 6 must verify the signature and artifact hashes" in output
    assert "VERIFIED:" not in output


def test_setup_stage5_does_not_overwrite_existing_signed_manifest_without_approval(
    tmp_path, monkeypatch, capsys
):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("contents", encoding="utf-8")
    signed_path = tmp_path / "state" / "manifest.signed.json"
    signed_path.parent.mkdir()
    existing = b'{"existing": "signed manifest"}\n'
    signed_path.write_bytes(existing)

    result, _, _ = _run_setup_with_responses(
        tmp_path,
        monkeypatch,
        ["1", str(artifact), "yes", "demo-release", "1"],
        manual_sign_response="no",
    )

    output = capsys.readouterr()
    assert result == 1
    assert signed_path.read_bytes() == existing
    assert "Existing signed manifest found:" in output.out
    assert "existing signed manifest was not approved for overwrite" in output.err
