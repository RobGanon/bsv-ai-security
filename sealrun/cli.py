from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import struct
import sys
import tempfile
from importlib import import_module
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from .anchor import (
    AnchorSignatureVerifier,
    apply_anchor_signatures,
    apply_header_chain,
    apply_payload_binding,
    create_anchor_payload,
    verify_anchor_chain,
    verify_journal_against_anchor,
    verify_journal_against_anchor_chain,
)
from .broadcast import (
    FundingUTXO,
    WIFSigner,
    WoCBroadcaster,
    WOC_MAINNET_BASE,
    WOC_TTN_BASE,
)
from .beef import (
    BEEF_MAGIC,
    BeefVerifier,
    apply_beef_inclusion,
    parse_beef,
    parse_beef_hex,
)
from .spv import (
    BUMPVerifier,
    DAAParams,
    HeaderChainVerifier,
    SPVVerifier,
    WoCBlockFetcher,
    apply_bump_inclusion,
    apply_chain_inclusion,
)
from .publisher import (
    Publisher,
    PublisherConfig,
    PublisherError,
)
from .core import (
    VerificationError,
    _no_duplicate_object,
    append_audit_event,
    create_manifest,
    generate_keypair,
    load_private_key,
    load_public_key,
    manifest_hash,
    MANIFEST_ACCEPTED_EVENT_TYPE,
    record_manifest_acceptance,
    sign_manifest,
    verify_audit_journal,
    verify_audit_journal_report,
    verify_manifest,
)
from .launcher import (
    launch,
    resolve_gid,
    resolve_uid,
)
from .checkpoint_cache import bootstrap_checkpoint
from .v2_anchor import (
    VERDICT_PREFIX,
    VERDICT_TIP,
    verify_v2_anchor_chain,
)
from .proof_bundle import create_bundle, verify_bundle
from . import __version__ as _SEALRUN_VERSION


def _read_json(path: Path):
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_object,
        )
    except ValueError as exc:
        raise VerificationError(f"invalid JSON in {path}: {exc}") from exc


def _read_beef(path: Path):
    """Read a BEEF envelope file: raw BEEF binary (magic ``0100BEEF``)
    or hex text. Raises VerificationError on unreadable/malformed
    input."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"cannot read --beef-file: {exc}") from exc
    try:
        if data[:4] == BEEF_MAGIC:
            return parse_beef(data)
        return parse_beef_hex(data.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise VerificationError(f"malformed --beef-file: {exc}") from exc


def _write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_json_new(path: Path, obj) -> str:
    content = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with path.open("x", encoding="utf-8") as handle:
            created = True
            handle.write(content)
    except FileExistsError as exc:
        raise VerificationError(f"manifest file already exists: {path}") from exc
    except OSError as exc:
        if created:
            try:
                path.unlink()
            except OSError as cleanup_error:
                raise VerificationError(
                    f"could not write manifest {path}: {exc}; "
                    f"could not remove incomplete file: {cleanup_error}"
                ) from exc
        raise VerificationError(f"could not write manifest {path}: {exc}") from exc
    return content


def _check_setup_environment() -> tuple[bool, bool, bool, bool]:
    python_ok = sys.version_info >= (3, 10)
    python_version = ".".join(str(part) for part in sys.version_info[:3])
    print(
        f"{'PASS' if python_ok else 'FAIL'}: Python >= 3.10 "
        f"(found {python_version})"
    )

    try:
        pip_result = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        pip_available = pip_result.returncode == 0
        pip_detail = (
            pip_result.stdout.strip()
            if pip_available
            else (pip_result.stderr.strip() or pip_result.stdout.strip())
        )
    except OSError as exc:
        pip_available = False
        pip_detail = str(exc)
    print(
        f"{'PASS' if pip_available else 'FAIL'}: pip available"
        + (f" ({pip_detail})" if pip_detail else "")
    )

    try:
        distribution("sealrun")
        installed = True
        install_detail = "installed"
    except PackageNotFoundError:
        installed = False
        install_detail = "not installed"

    try:
        import_module("sealrun")
        importable = True
        import_detail = "importable"
    except ImportError as exc:
        importable = False
        import_detail = f"not importable ({exc})"

    sealrun_ok = installed and importable
    detail = f"{install_detail}, {import_detail}"
    print(
        f"{'PASS' if sealrun_ok else 'FAIL'}: "
        f"SealRun installed and importable ({detail})"
    )
    return python_ok, pip_available, installed, sealrun_ok


def _confirm_setup(prompt: str) -> bool:
    try:
        response = input(prompt).strip().lower()
    except EOFError:
        return False
    return response in {"y", "yes"}


def _setup_manual_signing(
    manifest_path: Path, signed_manifest_path: Path, private_key_path: Path
) -> int:
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
        _read_json(manifest_path)
    except (OSError, VerificationError) as exc:
        print(f"ERROR: cannot review unsigned manifest: {exc}", file=sys.stderr)
        return 1

    print("\nStage 5 — Manual manifest signing")
    print("Review the unsigned manifest. This exact payload will be signed:")
    print(manifest_text, end="" if manifest_text.endswith("\n") else "\n")
    print(
        "The wizard will not run the signing command or access the private key."
    )

    if os.path.lexists(signed_manifest_path):
        print(f"Existing signed manifest found: {signed_manifest_path}")
        if not _confirm_setup(
            "Allow the manual manifest-sign command to overwrite it? [y/N]: "
        ):
            print(
                "Setup stopped: existing signed manifest was not approved "
                "for overwrite.",
                file=sys.stderr,
            )
            return 1

    command = [
        "sealrun",
        "manifest-sign",
        "--manifest",
        os.fspath(manifest_path),
        "--private-key",
        os.fspath(private_key_path),
        "--output",
        os.fspath(signed_manifest_path),
    ]
    print("Run this existing SealRun command manually:")
    print(" ".join(shlex.quote(part) for part in command))
    if not _confirm_setup(
        "After running it successfully, continue with the signed manifest? [y/N]: "
    ):
        print(
            "Setup stopped: manual signing was refused or not confirmed. "
            "No verification, launch, or anchoring was run.",
            file=sys.stderr,
        )
        return 1

    try:
        if not signed_manifest_path.is_file():
            print(
                f"ERROR: signed manifest was not produced: {signed_manifest_path}",
                file=sys.stderr,
            )
            return 1
        signed_manifest = signed_manifest_path.read_bytes()
    except OSError as exc:
        print(f"ERROR: cannot read signed manifest: {exc}", file=sys.stderr)
        return 1
    if not signed_manifest.strip():
        print(
            f"ERROR: signed manifest is empty: {signed_manifest_path}",
            file=sys.stderr,
        )
        return 1

    print(f"Signed manifest received: {signed_manifest_path}")
    print(
        "NOT VERIFIED. Stage 6 must verify the signature and artifact hashes "
        "before any launch or anchoring. This stage does not verify, launch, "
        "or anchor."
    )
    return 0


def _artifact_path_error(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return f"path does not exist: {path}"
    except OSError as exc:
        return f"cannot inspect path {path}: {exc}"

    if stat.S_ISLNK(info.st_mode):
        return f"symbolic links are not allowed: {path}"
    if not stat.S_ISREG(info.st_mode):
        return f"path is not a regular file: {path}"
    try:
        with path.open("rb") as artifact:
            artifact.read(1)
    except OSError as exc:
        return f"file is not readable: {path} ({exc})"
    return None


def _directory_artifacts(root: Path) -> tuple[list[Path], list[str]]:
    artifacts: list[Path] = []
    errors: list[str] = []

    def visit(directory: Path) -> None:
        try:
            with os.scandir(directory) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
        except OSError as exc:
            errors.append(f"cannot read directory {directory}: {exc}")
            return

        for entry in children:
            path = Path(entry.path)
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                errors.append(f"cannot inspect path {path}: {exc}")
                continue
            if stat.S_ISLNK(mode):
                errors.append(f"symbolic links are not allowed: {path}")
            elif stat.S_ISDIR(mode):
                visit(path)
            elif stat.S_ISREG(mode):
                error = _artifact_path_error(path)
                if error:
                    errors.append(error)
                else:
                    artifacts.append(path)
            else:
                errors.append(f"path is not a regular file: {path}")

    visit(root)
    if not artifacts and not errors:
        errors.append(f"directory contains no files: {root}")
    elif not artifacts:
        errors.append(f"directory contains no readable files: {root}")
    return artifacts, errors


def _user_artifact_paths(raw_paths: str) -> tuple[list[Path], list[str]]:
    try:
        words = shlex.split(raw_paths)
    except ValueError as exc:
        return [], [f"invalid path list: {exc}"]
    if not words:
        return [], ["no artifact paths were provided"]

    paths = [Path(os.path.abspath(Path(word).expanduser())) for word in words]
    path_info: list[tuple[Path, os.stat_result | None]] = []
    errors = []
    for path in paths:
        try:
            info = path.lstat()
        except FileNotFoundError:
            errors.append(f"path does not exist: {path}")
            path_info.append((path, None))
        except OSError as exc:
            errors.append(f"cannot inspect path {path}: {exc}")
            path_info.append((path, None))
        else:
            path_info.append((path, info))

    directories = [path for path, info in path_info
                   if info is not None and stat.S_ISDIR(info.st_mode)]
    if directories:
        if len(paths) == 1 and len(directories) == 1:
            root = directories[0]
            artifacts, directory_errors = _directory_artifacts(root)
            return artifacts, errors + directory_errors
        errors.extend(
            f"choose one directory by itself, not with other paths: {path}"
            for path in directories
        )
        return [], errors

    artifacts = []
    seen = set()
    for path, info in path_info:
        if info is None:
            continue
        if path in seen:
            errors.append(f"duplicate artifact path: {path}")
            continue
        seen.add(path)
        error = _artifact_path_error(path)
        if error:
            errors.append(error)
        else:
            artifacts.append(path)
    return artifacts, errors


def _retry_artifacts() -> bool:
    while True:
        try:
            response = input("Retry artifact selection or stop? [r/q]: ").strip().lower()
        except EOFError:
            return False
        if response in {"r", "retry"}:
            return True
        if response in {"q", "quit"}:
            return False
        print("Enter 'r' to retry or 'q' to stop.")


def _choose_artifact_source() -> str | None:
    print("\nStage 3 — Artifacts")
    print("1) Use your own directory or files")
    print("2) Use the built-in demo set")
    print("q) Stop setup")
    while True:
        try:
            choice = input("Choose an artifact source [1/2/q]: ").strip().lower()
        except EOFError:
            return None
        if choice in {"1", "2"}:
            return choice
        if choice in {"q", "quit"}:
            return None
        print("Choose 1, 2, or q.")


def _collect_user_artifacts() -> list[Path] | None:
    while True:
        try:
            raw_paths = input(
                "Enter one directory (searched recursively) or file paths "
                "(quote paths with spaces): "
            )
        except EOFError:
            return None
        artifacts, errors = _user_artifact_paths(raw_paths)
        if not errors and artifacts:
            return artifacts
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        if not _retry_artifacts():
            return None


def _create_demo_artifacts() -> tuple[Path, list[Path]] | None:
    contents = {
        "demo-model-description.txt": (
            "DEMO CONTENT ONLY\n"
            "Placeholder description; this is not a model.\n"
        ),
        "demo-run-config.txt": (
            "DEMO CONTENT ONLY\n"
            "mode=example\n"
            "temperature=0.2\n"
        ),
        "demo-sample-input.txt": (
            "DEMO CONTENT ONLY\n"
            "Sample input for the SealRun setup wizard.\n"
        ),
    }
    try:
        root = Path(tempfile.mkdtemp(prefix="sealrun-demo-artifacts-"))
    except OSError as exc:
        print(f"ERROR: cannot create demo artifact directory: {exc}", file=sys.stderr)
        return None

    print(f"Creating clearly marked demo content in: {root}")
    artifacts = []
    try:
        for name, content in contents.items():
            path = root / name
            path.write_text(content, encoding="utf-8")
            artifacts.append(path)
    except OSError as exc:
        try:
            shutil.rmtree(root)
        except OSError as cleanup_error:
            print(
                f"ERROR: could not remove incomplete demo directory {root}: "
                f"{cleanup_error}",
                file=sys.stderr,
            )
        print(f"ERROR: could not create demo artifact {path}: {exc}", file=sys.stderr)
        return None
    print("Created three DEMO CONTENT ONLY text artifacts.")
    return root, artifacts


def _setup(args) -> int:
    python_ok, pip_available, installed, sealrun_ok = _check_setup_environment()
    if not installed:
        print(
            "Recommended install command (run from the repository root): "
            "pip install -e ."
        )
    if not python_ok:
        print(
            "Setup stopped: SealRun requires Python 3.10 or newer.",
            file=sys.stderr,
        )
        return 1
    if not pip_available:
        print(
            "Setup stopped: pip is unavailable for this Python interpreter.",
            file=sys.stderr,
        )
        return 1

    if not sealrun_ok:
        if installed:
            print(
                "Setup stopped: SealRun is installed but could not be imported. "
                "Fix the installation before continuing.",
                file=sys.stderr,
            )
            return 1
        if not _confirm_setup("Install SealRun now with pip? [y/N]: "):
            print("Setup stopped: SealRun installation was not approved.", file=sys.stderr)
            return 1

        print("Installing SealRun with the current Python interpreter...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-e", "."],
                cwd=Path(__file__).resolve().parent.parent,
                check=False,
            )
        except OSError as exc:
            print(f"FAIL: SealRun installation ({exc})", file=sys.stderr)
            return 1
        if result.returncode != 0:
            print(
                f"FAIL: SealRun installation (pip exited with status {result.returncode})",
                file=sys.stderr,
            )
            return 1

        python_ok, pip_available, _, sealrun_ok = _check_setup_environment()
        if not python_ok or not pip_available or not sealrun_ok:
            print(
                "Setup stopped: the required environment checks did not pass "
                "after installation.",
                file=sys.stderr,
            )
            return 1

    print()
    print(
        "WARNING: These are DEMONSTRATION keys. Production keys stay offline "
        "or in an HSM and outside this workflow."
    )
    existing_paths = [
        path for path in (args.private_key, args.public_key) if os.path.lexists(path)
    ]
    force = False
    if existing_paths:
        print("Existing key file(s) found: " + ", ".join(str(path) for path in existing_paths))
        if not _confirm_setup("Overwrite existing key file(s) and generate a new demo keypair? [y/N]: "):
            print("Setup stopped: existing key files were not changed.", file=sys.stderr)
            return 1
        force = True

    try:
        generate_keypair(args.private_key, args.public_key, force=force)
        public_key = load_public_key(args.public_key)
        private_key = load_private_key(args.private_key)
        if private_key.pubkey_compressed() != public_key:
            raise VerificationError("generated public and private keys do not match")
        private_mode = stat.S_IMODE(args.private_key.stat().st_mode)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        f"Demo keypair generated. Private key: {args.private_key} "
        f"(mode {private_mode:04o})"
    )
    print(f"Public key: {public_key.hex()}")
    print("Key info: secp256k1; compressed 33-byte public key; testnet WIF encoding.")
    print(f"Public key SHA-256: {hashlib.sha256(public_key).hexdigest()}")

    artifact_source = _choose_artifact_source()
    if artifact_source is None:
        print("Setup stopped: no artifact source was selected.", file=sys.stderr)
        return 1

    demo_root = None
    if artifact_source == "1":
        artifacts = _collect_user_artifacts()
        if artifacts is None:
            print("Setup stopped: no valid artifacts were provided.", file=sys.stderr)
            return 1
    else:
        demo_artifacts = _create_demo_artifacts()
        if demo_artifacts is None:
            return 1
        demo_root, artifacts = demo_artifacts

    print("\nArtifacts to seal:")
    for artifact in artifacts:
        print(f"- {artifact}")
    if not _confirm_setup("Continue with this artifact list? [y/N]: "):
        print("Setup stopped: the artifact list was not confirmed.", file=sys.stderr)
        if demo_root is not None:
            try:
                shutil.rmtree(demo_root)
            except OSError as exc:
                print(
                    f"ERROR: could not remove unconfirmed demo directory "
                    f"{demo_root}: {exc}",
                    file=sys.stderr,
                )
        return 1

    print(f"Stage 3 complete: {len(artifacts)} artifact(s) confirmed.")
    if demo_root is not None:
        print(f"Demo artifacts remain in: {demo_root}")

    manifest_path = Path("state/manifest.json")
    if os.path.lexists(manifest_path):
        print(
            f"Setup stopped: manifest file already exists: {manifest_path}",
            file=sys.stderr,
        )
        return 1

    try:
        release_id = input("Release ID [local-dev-release]: ").strip()
        release_id = release_id or "local-dev-release"
        release_seq_text = input("Release sequence (required integer): ").strip()
    except EOFError:
        print("Setup stopped: release details were not provided.", file=sys.stderr)
        return 1
    try:
        release_seq = int(release_seq_text)
    except ValueError:
        print("ERROR: release sequence must be an integer.", file=sys.stderr)
        return 1

    try:
        root = Path(os.path.commonpath([os.fspath(path.parent) for path in artifacts]))
        relative_paths = [path.relative_to(root).as_posix() for path in artifacts]
        manifest = create_manifest(root, relative_paths, release_id, release_seq)
        manifest_json = _write_json_new(manifest_path, manifest)
    except (OSError, ValueError) as exc:
        print(f"ERROR: manifest creation failed: {exc}", file=sys.stderr)
        return 1

    print(f"Unsigned manifest written: {manifest_path}")
    print(
        "Public key for later verification (out of band; not embedded in "
        f"the signed manifest): {public_key.hex()}"
    )
    print("Unsigned manifest contents (the exact payload Stage 5 will sign):")
    print(manifest_json, end="")
    print("Stage 4 complete. The manifest is unsigned; signing was not run.")
    return _setup_manual_signing(
        manifest_path,
        Path("state/manifest.signed.json"),
        args.private_key,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sealrun", description="Local AI artifact trust core")
    parser.add_argument("--version", action="version", version=f"sealrun {_SEALRUN_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser(
        "setup", help="check the environment and create a demo keypair"
    )
    p.add_argument("--private-key", type=Path, default=Path("keys/private.wif"))
    p.add_argument("--public-key", type=Path, default=Path("keys/public.pub"))

    p = sub.add_parser("keygen", help="generate a development secp256k1 keypair")
    p.add_argument("--private-key", required=True, type=Path)
    p.add_argument("--public-key", required=True, type=Path)
    p.add_argument("--force", action="store_true", help="overwrite existing key files")

    p = sub.add_parser("manifest-create", help="create an unsigned manifest payload")
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--artifact", action="append", required=True)
    p.add_argument("--release-id", default="local-dev-release")
    p.add_argument("--release-seq", required=True, type=int,
                   help="monotonic release sequence number; verifiers can reject older releases")
    p.add_argument("--output", required=True, type=Path)

    p = sub.add_parser("manifest-sign", help="sign a manifest payload")
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--private-key", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)

    p = sub.add_parser("verify", help="verify signature and artifact hashes")
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--public-key", required=True, type=Path)
    p.add_argument("--min-release-seq", type=int, default=None,
                   help="reject manifests older than this release sequence (rollback protection)")

    p = sub.add_parser(
        "launch",
        help="verify a manifest, then run a command against the verified "
             "artifact handles (closes the verify-to-launch window)",
    )
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--public-key", required=True, type=Path)
    p.add_argument("--min-release-seq", type=int, default=None,
                   help="reject manifests older than this release sequence (rollback protection); "
                        "required in v2 mode")
    p.add_argument("--checkpoint-cache", type=Path, default=None,
                   help="v2 only: append-only anchored release checkpoint cache; "
                        "required in v2 mode (a missing cache is not checkpoint 0)")
    p.add_argument("--cache-key", type=Path, default=None,
                   help="v2 only: deployment key file that authenticates the "
                        "checkpoint cache records (default: <cache-dir>/cache.key)")
    p.add_argument("--mode", choices=("v1", "v2"), default="v1",
                   help="launch mode (default: v1, unchanged); v2 is the "
                        "explicit per-launch opt-in that writes strict journal events")
    p.add_argument("--journal", type=Path, default=None,
                   help="v2 journal path (required with --mode v2; invalid in v1, "
                        "which writes no journal record)")
    p.add_argument("--require-v2", action="store_true",
                   help="refuse to launch unless --mode v2 is used (a v2-only "
                        "deployment refuses a v1 invocation at invocation time)")
    p.add_argument("--seal", action="store_true",
                   help="copy each artifact into a sealed memfd before exec, so the "
                        "child reads a frozen snapshot (costs a copy of every artifact in RAM)")
    p.add_argument("--executable-binding", choices=("record-only", "verified"),
                   default="record-only",
                   help="executable binding (default: record-only). 'verified' "
                        "runs a Linux ELF manifest artifact via execveat(AT_EMPTY_PATH) "
                        "and records that artifact; it requires --mode v2")
    p.add_argument("--executable-artifact", default=None,
                   help="manifest artifact path to execute in verified mode when "
                        "argv[0] does not match an artifact path exactly")
    p.add_argument("--uid", default=None,
                   help="drop to this user (name or numeric id) before exec (needs privilege)")
    p.add_argument("--gid", default=None,
                   help="drop to this group (name or numeric id) before exec (needs privilege)")
    p.add_argument("command_argv", nargs=argparse.REMAINDER, metavar="CMD [ARGS...]",
                   help="command to run; separate it from options with '--'")

    p = sub.add_parser("audit-append", help="append a local audit event")
    p.add_argument("--journal", required=True, type=Path)
    p.add_argument("--event-type", required=True)
    p.add_argument("--detail", required=True)

    p = sub.add_parser("audit-verify", help="verify the local audit hash chain")
    p.add_argument("--journal", required=True, type=Path)

    p = sub.add_parser(
        "audit-manifest-accepted",
        help="record an operator's adoption of a release (journal-derived anchor checkpoint)",
    )
    p.add_argument("--journal", required=True, type=Path)
    p.add_argument("--release-seq", required=True, type=int,
                   help="release sequence being adopted; anchored release_seq is derived from these events")
    p.add_argument("--release-id", required=True,
                   help="release identifier being adopted")
    p.add_argument("--manifest", type=Path, default=None,
                   help="path to the signed manifest envelope JSON being adopted; "
                   "the acceptance is bound to this manifest's hash")
    p.add_argument("--manifest-hash", default=None,
                   help="manifest hash (64 hex) to cross-check --manifest against; "
                   "it cannot be used on its own, because an unverifiable binding "
                   "would poison the journal permanently")
    p.add_argument("--public-key", type=Path, default=None,
                   help="trusted manifest-signing public key (compressed hex); "
                   "required with --manifest, so the manifest signature is verified "
                   "before the acceptance is recorded")

    p = sub.add_parser("anchor-payload", help="prepare unsigned BSV anchor payload bytes (no broadcast)")
    p.add_argument("--journal", required=True, type=Path)
    p.add_argument("--start-seq", required=True, type=int)
    p.add_argument("--prev-txid", default="0" * 64)
    p.add_argument("--manifest", action="append", type=Path, default=None,
                   help="signed manifest envelope JSON to check acceptances against; "
                   "repeatable; required when the journal contains acceptances")
    p.add_argument("--public-key", type=Path, default=None,
                   help="trusted manifest-signing public key (compressed hex); "
                   "required with --manifest when the journal contains acceptances")
    p.add_argument("--output", required=True, type=Path)

    p = sub.add_parser("anchor-verify", help="verify a journal against saved anchor payload bytes")
    p.add_argument("--journal", required=True, type=Path)
    p.add_argument("--payload", required=True, type=Path,
                   help="JSON file produced by anchor-payload")
    p.add_argument("--manifest", action="append", type=Path, default=None,
                   help="signed manifest envelope JSON to re-check acceptance binding with; "
                   "repeatable; requires --public-key")
    p.add_argument("--public-key", type=Path, default=None,
                   help="trusted manifest-signing public key (compressed hex) for binding re-verification")

    p = sub.add_parser(
        "anchor-chain-verify",
        help="verify anchor-chain continuity from a trusted genesis txid (issue #8)",
    )
    p.add_argument("--genesis-txid", required=True,
                   help="trusted genesis anchor txid from operator-pinned config; "
                   "never inferred from the anchors being checked")
    p.add_argument("--anchor", action="append", type=Path, default=None,
                   help="JSON file with payload_hex + txid for one anchor; "
                   "repeatable, in chain order")
    p.add_argument("--anchor-record", type=Path, default=None,
                   help="publisher anchor-record JSON; its broadcast records "
                   "are chain-checked (pending/superseded drafts are not chain members)")
    p.add_argument("--v2", action="store_true",
                   help="require the full anchor-only acceptance predicate "
                   "(payload binding + anchor signature + exactly one of "
                   "--spv/--bump-file/--beef-file + header chain to a pinned "
                   "checkpoint) and print the two named verdicts. No signed "
                   "pins are used.")
    p.add_argument("--journal", type=Path, default=None,
                   help="if given, also verify the journal against every anchor "
                   "in the chain (head hash + binding re-derivation)")
    p.add_argument("--manifest", action="append", type=Path, default=None,
                   help="signed manifest envelope JSON for binding re-verification; "
                   "repeatable; requires --public-key")
    p.add_argument("--public-key", type=Path, default=None,
                   help="trusted manifest-signing public key (compressed hex) for binding re-verification")
    p.add_argument("--spv", action="store_true",
                   help="also verify each anchor tx is really inside its "
                   "claimed block (Merkle root recomputation + header hash "
                   "+ proof-of-work) via the --woc-base endpoint")
    p.add_argument("--bump-file", type=Path, default=None,
                   help="JSON file mapping txid -> BUMP (BRC-74 JSON form); "
                   "if given, verify each anchor tx's inclusion from its "
                   "compact proof, fetching only the block header via "
                   "--woc-base. Proofs are operator-supplied: no public "
                   "WhatsOnChain endpoint serves BUMPs (404 on TTN and "
                   "mainnet, checked 2026-10-17).")
    p.add_argument("--beef-file", type=Path, default=None,
                   help="BEEF envelope file (BRC-62 binary, or hex text); "
                   "if given, verify each anchor tx's inclusion from the "
                   "envelope's BUMPs + ancestry, fetching only block "
                   "headers via --woc-base. Envelopes are "
                   "operator-supplied: no public WhatsOnChain endpoint "
                   "serves BEEF (404 on TTN and mainnet, checked "
                   "2026-10-17).")
    p.add_argument("--anchor-sig", action="store_true",
                   help="also verify each anchor tx's single input is "
                   "signed by the trusted anchor pubkey (requires "
                   "--anchor-pubkey)")
    p.add_argument("--anchor-pubkey", default=None,
                   help="trusted anchor compressed pubkey hex (66 chars, "
                   "02/03 prefix); required with --anchor-sig")
    p.add_argument("--header-chain", action="store_true",
                   help="also verify each anchor tx's block chains back "
                   "to a pinned checkpoint header (requires "
                   "--checkpoint-hash + --checkpoint-height)")
    p.add_argument("--checkpoint-hash", default=None,
                   help="trusted checkpoint block hash (64 hex chars), "
                   "pinned out-of-band like the genesis txid; required "
                   "with --header-chain")
    p.add_argument("--checkpoint-height", type=int, default=None,
                   help="height of the trusted checkpoint header; "
                   "required with --header-chain")
    p.add_argument("--daa", choices=["mainnet"], default=None,
                   help="with --header-chain: also validate the "
                   "difficulty schedule of every block above the "
                   "checkpoint against the named network's cash-DAA "
                   "parameters (Finding B). Only 'mainnet' has a "
                   "confirmed parameter set; other chains keep "
                   "linkage + proof-of-work only.")
    p.add_argument("--woc-base", default=WOC_TTN_BASE,
                   help="WhatsOnChain base URL for --spv / --anchor-sig "
                   "chain data (default: Teratestnet)")

    p = sub.add_parser(
        "bootstrap",
        aliases=("checkpoint-bootstrap",),
        help="deployment-time: verify the anchor chain online and record "
             "its release_seq in the isolated checkpoint cache",
    )
    p.add_argument("--journal", required=True, type=Path)
    p.add_argument("--checkpoint-cache", required=True, type=Path,
                   help="append-only checkpoint cache to write (its directory "
                        "must already satisfy the §5.7 isolation rules)")
    p.add_argument("--cache-key", type=Path, default=None,
                   help="deployment key file that authenticates the cache "
                        "records (default: <cache-dir>/cache.key; generated "
                        "on first bootstrap)")
    p.add_argument("--genesis-txid", required=True,
                   help="trusted genesis anchor txid from operator-pinned "
                        "config; never inferred from the anchors being checked")
    p.add_argument("--anchor", action="append", type=Path, default=None,
                   help="JSON file with payload_hex + txid for one anchor; "
                        "repeatable, in chain order")
    p.add_argument("--anchor-record", type=Path, default=None,
                   help="publisher anchor-record JSON; its broadcast records "
                        "are chain-checked")
    p.add_argument("--manifest", action="append", type=Path, default=None,
                   help="signed manifest envelope JSON for binding "
                        "re-verification; repeatable; required when the "
                        "anchored prefix contains acceptances")
    p.add_argument("--public-key", type=Path, default=None,
                   help="trusted manifest-signing public key; required with "
                        "--manifest when the anchored prefix contains "
                        "acceptances")
    p.add_argument("--spv", action="store_true",
                   help="verify each anchor tx is inside its claimed block "
                        "via the --woc-base endpoint (exactly one inclusion "
                        "source is required)")
    p.add_argument("--bump-file", type=Path, default=None,
                   help="JSON file mapping txid -> BUMP (exactly one "
                        "inclusion source is required)")
    p.add_argument("--beef-file", type=Path, default=None,
                   help="BEEF envelope file (exactly one inclusion source is "
                        "required; ancestry-only BEEF does not count)")
    p.add_argument("--anchor-sig", action="store_true",
                   help="accepted for parity with anchor-chain-verify; "
                        "bootstrap always verifies the anchor signature")
    p.add_argument("--anchor-pubkey", default=None,
                   help="trusted anchor compressed pubkey hex (66 chars, "
                        "02/03 prefix); required")
    p.add_argument("--header-chain", action="store_true",
                   help="accepted for parity with anchor-chain-verify; "
                        "bootstrap always verifies the header chain")
    p.add_argument("--checkpoint-hash", default=None,
                   help="trusted checkpoint block hash (64 hex chars); "
                        "required")
    p.add_argument("--checkpoint-height", type=int, default=None,
                   help="height of the trusted checkpoint header; required")
    p.add_argument("--daa", choices=["mainnet"], default=None,
                   help="also validate the difficulty schedule above the "
                        "checkpoint against mainnet cash-DAA parameters")
    p.add_argument("--woc-base", default=WOC_TTN_BASE,
                   help="WhatsOnChain base URL (default: Teratestnet)")
    p.add_argument("--uid", "--child-uid", dest="uid", default=None,
                   help="uid the launcher will drop the child to; required so "
                        "the cache can be checked against the §5.7 isolation "
                        "rules (a name or numeric id)")

    p = sub.add_parser(
        "publish",
        help="publisher: anchor checkpoints on release acceptance + on schedule "
        "(dry-run by default: prepares payloads, never broadcasts)",
    )
    p.add_argument("--journal", required=True, type=Path)
    p.add_argument("--anchor-record", required=True, type=Path,
                   help="JSON file persisting emitted anchors (payload + txid slot + status)")
    p.add_argument("--genesis-txid", default="0" * 64,
                   help="out-of-band genesis anchor txid; zeros mean no genesis anchor yet")
    p.add_argument("--interval-seconds", type=int, default=3600,
                   help="scheduled checkpoint interval (default 3600)")
    p.add_argument("--mode", choices=["once", "on-release", "loop"], default="once",
                   help="once: one scheduler tick; on-release: anchor immediately; "
                   "loop: repeat ticks until interrupted or --max-iterations")
    p.add_argument("--max-iterations", type=int, default=None,
                   help="cap loop iterations (test / operator safety)")
    p.add_argument("--broadcast", action="store_true",
                   help="opt-in broadcast: build, sign, and send the anchor "
                   "transaction via WoC. Requires ANCHOR_WIF (WIF for the "
                   "selected --network) in the environment plus "
                   "--funding-txid/--funding-vout. Mainnet also requires "
                   "--confirm-mainnet.")
    p.add_argument("--network", choices=["testnet", "mainnet"], default="testnet",
                   help="network to anchor on (default: testnet). The "
                   "ANCHOR_WIF version byte must match this network.")
    p.add_argument("--confirm-mainnet", action="store_true",
                   help="required with --network mainnet --broadcast: "
                   "mainnet spends real funds and must never happen "
                   "by default or accident")
    p.add_argument("--woc-base", default=None,
                   help="WhatsOnChain base URL for broadcast + prev-tx fetch "
                   "(default: Teratestnet for testnet, WoC mainnet for "
                   "mainnet; an explicit --woc-base overrides)")
    p.add_argument("--funding-txid", default=None,
                   help="txid of the funding UTXO to spend (required with --broadcast)")
    p.add_argument("--funding-vout", type=int, default=0,
                   help="vout of the funding UTXO (default 0)")
    p.add_argument("--fee-sats", type=int, default=500,
                   help="miner fee in satoshis (default 500)")
    p.add_argument("--manifest", action="append", type=Path, default=None,
                   help="signed manifest envelope JSON to check acceptances against; "
                   "repeatable; required when the journal contains acceptances")
    p.add_argument("--manifest-dir", type=Path, default=None,
                   help="directory of signed manifest envelope JSON files, "
                   "re-read at every checkpoint (for long-running publishers)")
    p.add_argument("--public-key", type=Path, default=None,
                   help="trusted manifest-signing public key (compressed hex); "
                   "required with --manifest when the journal contains acceptances")
    p.add_argument("--export-unsigned", type=Path, default=None,
                   help="offline-signing ceremony: build the unsigned anchor "
                   "tx for the current head, write its hex to this file, and "
                   "stop. Never signs, never broadcasts. Requires "
                   "--funding-txid/--funding-vout + --change-address. "
                   "Refuses mainnet and refuses when ANCHOR_WIF is set.")
    p.add_argument("--broadcast-signed", type=Path, default=None,
                   help="offline-signing ceremony: read a human-signed tx "
                   "hex from this file, verify it against a freshly "
                   "rebuilt unsigned tx, then broadcast it. Requires "
                   "--funding-txid/--funding-vout + --change-address. "
                   "Refuses mainnet and refuses when ANCHOR_WIF is set.")
    p.add_argument("--change-address", default=None,
                   help="anchor address receiving change (required with "
                   "--export-unsigned / --broadcast-signed)")

    p = sub.add_parser("proof-bundle-create", help="pack a verified run into a portable proof bundle")
    p.add_argument("--manifest", required=True, type=Path)
    p.add_argument("--public-key", required=True, type=Path)
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--journal", type=Path, default=None)
    p.add_argument("--anchor", type=Path, default=None,
                   help="JSON file produced by anchor-payload")
    p.add_argument("--output", required=True, type=Path)

    p = sub.add_parser("proof-bundle-verify", help="re-verify a portable proof bundle offline")
    p.add_argument("--bundle", required=True, type=Path)

    p = sub.add_parser(
        "signer",
        help="offline anchor-transaction signer: human-side signing ceremony "
             "(init / expect / sign; testnet only)",
    )
    p.add_argument("signer_argv", nargs=argparse.REMAINDER,
                   metavar="SIGNER-CMD [ARGS...]",
                   help="signer subcommand; separate it from options with '--'")

    args = parser.parse_args(argv)
    try:
        if args.command == "setup":
            return _setup(args)
        elif args.command == "keygen":
            generate_keypair(args.private_key, args.public_key, force=args.force)
            print("Development keypair generated. Protect the private key.")
        elif args.command == "manifest-create":
            payload = create_manifest(args.root, args.artifact, args.release_id,
                                      args.release_seq)
            _write_json(args.output, payload)
            print(f"Unsigned manifest written: {args.output}")
        elif args.command == "manifest-sign":
            payload = _read_json(args.manifest)
            envelope = sign_manifest(payload, load_private_key(args.private_key))
            _write_json(args.output, envelope)
            print(f"Signed manifest written: {args.output}")
        elif args.command == "verify":
            envelope = _read_json(args.manifest)
            artifacts = verify_manifest(args.root, envelope, load_public_key(args.public_key),
                                        min_release_seq=args.min_release_seq)
            print(f"VERIFIED: {len(artifacts)} artifact(s): " + ", ".join(artifacts))
        elif args.command == "launch":
            envelope = _read_json(args.manifest)
            return launch(
                args.root,
                envelope,
                load_public_key(args.public_key),
                args.command_argv,
                min_release_seq=args.min_release_seq,
                checkpoint_cache=args.checkpoint_cache,
                cache_key=args.cache_key,
                seal=args.seal,
                uid=resolve_uid(args.uid),
                gid=resolve_gid(args.gid),
                mode=args.mode,
                journal=args.journal,
                require_v2=args.require_v2,
                executable_binding=args.executable_binding,
                executable_artifact=args.executable_artifact,
            )
        elif args.command == "audit-append":
            if args.event_type == MANIFEST_ACCEPTED_EVENT_TYPE:
                raise VerificationError(
                    "audit-append cannot record manifest_accepted events; "
                    "use audit-manifest-accepted with --manifest and "
                    "--public-key so the acceptance is verified before "
                    "it is recorded"
                )
            event = append_audit_event(args.journal, args.event_type, args.detail)
            print(f"Audit event appended: seq={event['seq']} hash={event['event_hash']}")
        elif args.command == "audit-verify":
            report = verify_audit_journal_report(args.journal)
            print(f"AUDIT OK: {report['events']} event(s)")
            if report["fragment_bytes"]:
                print(
                    "TORN TAIL: "
                    f"{report['fragment_bytes']} byte(s) after the last complete "
                    "event (reported, not repaired)"
                )
            for entry in report["channel_lists"]:
                if entry["present"]:
                    kind = "inline" if entry["inline"] else "detached"
                    print(
                        f"CHANNEL LIST OK: run {entry['run_id']} "
                        f"({len(entry['records'])} channel(s), {kind})"
                    )
                else:
                    print(
                        f"CHANNEL LIST MISSING: run {entry['run_id']} "
                        f"({entry['reason']}; the map is not reconstructable "
                        "from the committed hash)"
                    )
        elif args.command == "audit-manifest-accepted":
            # An acceptance is bound to exactly one signed manifest, and
            # that binding is checked HERE, at record time. An acceptance
            # that cannot be checked against a trusted key is refused:
            # the journal is append-only and hash-chained, so an
            # acceptance bound to a manifest that can never verify
            # (a wrong hash, or a manifest with a bad signature) would
            # poison the journal permanently, while `audit-verify` kept
            # reporting it as healthy.
            if args.manifest is None:
                raise VerificationError(
                    "audit-manifest-accepted requires --manifest (the signed "
                    "manifest envelope) and --public-key (the trusted "
                    "manifest-signing key) so the acceptance can be verified "
                    "before it is recorded; --manifest-hash alone cannot be "
                    "verified and is refused"
                )
            if args.public_key is None:
                raise VerificationError(
                    "audit-manifest-accepted requires --public-key to verify "
                    "the manifest signature before recording"
                )
            manifest_obj = _read_json(args.manifest)
            bound_hash = manifest_hash(manifest_obj)
            if args.manifest_hash is not None:
                if bound_hash != args.manifest_hash.lower():
                    raise VerificationError(
                        "--manifest and --manifest-hash disagree on the manifest hash"
                    )
            from .core import _load_verified_payload
            pubkey = load_public_key(args.public_key)
            payload = _load_verified_payload(manifest_obj, pubkey)
            # Enforce release identity consistency at record time too
            if payload.get("release_id") != args.release_id:
                raise VerificationError(
                    "release_id does not match the manifest"
                )
            if payload.get("release_seq") != args.release_seq:
                raise VerificationError(
                    "release_seq does not match the manifest"
                )
            event = record_manifest_acceptance(
                args.journal, args.release_seq, args.release_id, bound_hash
            )
            print(f"Manifest acceptance recorded: seq={event['seq']} hash={event['event_hash']}")
        elif args.command == "anchor-payload":
            manifests = None
            public_key = None
            if args.manifest is not None or args.public_key is not None:
                if args.manifest is None or args.public_key is None:
                    raise VerificationError(
                        "anchor-payload requires --manifest and --public-key together "
                        "to check acceptance binding"
                    )
                manifests = [_read_json(path) for path in args.manifest]
                public_key = load_public_key(args.public_key)
            fields = create_anchor_payload(
                args.journal,
                start_seq=args.start_seq,
                prev_txid=args.prev_txid,
                manifests=manifests,
                public_key=public_key,
            )
            _write_json(args.output, fields)
            print(f"Unsigned anchor payload prepared: {args.output}")
            print("NOT BROADCAST: this file is not proof of an on-chain transaction.")
        elif args.command == "anchor-verify":
            fields = _read_json(args.payload)
            payload_hex = fields.get("payload_hex") if isinstance(fields, dict) else None
            if not isinstance(payload_hex, str):
                raise VerificationError("payload JSON must contain a payload_hex string")
            try:
                payload_bytes = bytes.fromhex(payload_hex)
            except ValueError as exc:
                raise VerificationError("payload_hex is not valid hexadecimal") from exc
            manifests = None
            public_key = None
            if args.manifest is not None or args.public_key is not None:
                if args.manifest is None or args.public_key is None:
                    raise VerificationError(
                        "anchor-verify requires --manifest and --public-key together "
                        "to re-check acceptance binding"
                    )
                manifests = [_read_json(path) for path in args.manifest]
                public_key = load_public_key(args.public_key)
            result = verify_journal_against_anchor(
                args.journal, payload_bytes, manifests, public_key
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            print("LOCAL CHECK ONLY: BSV transaction inclusion has not been verified.")
            if args.manifest is None and args.public_key is None:
                print(
                    "WARNING: acceptance binding was NOT re-checked: "
                    "re-run with --manifest and --public-key to re-derive "
                    "binding from the signed manifests."
                )
        elif args.command == "anchor-chain-verify":
            anchors: list[dict] = []
            for path in args.anchor or []:
                entry = _read_json(path)
                if (
                    not isinstance(entry, dict)
                    or not isinstance(entry.get("payload_hex"), str)
                    or not isinstance(entry.get("txid"), str)
                ):
                    raise VerificationError(
                        "anchor JSON must contain payload_hex and txid"
                    )
                anchors.append(
                    {"payload_hex": entry["payload_hex"], "txid": entry["txid"]}
                )
            if args.anchor_record is not None:
                store = _read_json(args.anchor_record)
                records = store.get("anchors") if isinstance(store, dict) else None
                if not isinstance(records, list):
                    raise VerificationError(
                        "anchor-record JSON must contain an anchors list"
                    )
                for record in records:
                    if isinstance(record, dict) and record.get("status") == "broadcast":
                        anchors.append(
                            {
                                "payload_hex": record["payload_hex"],
                                "txid": record["txid"],
                            }
                        )
            if args.v2:
                # Anchor-only acceptance: no signed pin, no pin_seq, no
                # pin store. Every authenticator is required; omission is
                # a refusal, not a weaker acceptance.
                if args.journal is None:
                    raise VerificationError(
                        "--v2 requires --journal to verify the anchored "
                        "journal prefix and identity"
                    )
                if not args.anchor_sig:
                    raise VerificationError(
                        "--v2 requires --anchor-sig and --anchor-pubkey: "
                        "the anchor transaction signature is part of the "
                        "acceptance predicate"
                    )
                pubkey = args.anchor_pubkey or ""
                if (
                    len(pubkey) != 66
                    or pubkey[:2] not in ("02", "03")
                    or not all(c in "0123456789abcdefABCDEF" for c in pubkey)
                ):
                    raise VerificationError(
                        "--anchor-sig requires --anchor-pubkey as 66-char "
                        "compressed pubkey hex (02/03 prefix)"
                    )
                inclusion_sources = (
                    bool(args.spv)
                    + (args.bump_file is not None)
                    + (args.beef_file is not None)
                )
                if inclusion_sources != 1:
                    raise VerificationError(
                        "--v2 requires exactly one inclusion source: --spv, "
                        "--bump-file, or --beef-file (ancestry-only BEEF "
                        "does not count as inclusion)"
                    )
                if not args.header_chain:
                    raise VerificationError(
                        "--v2 requires --header-chain with a pinned "
                        "--checkpoint-hash and --checkpoint-height"
                    )
                checkpoint_hash = args.checkpoint_hash or ""
                if (
                    len(checkpoint_hash) != 64
                    or not all(
                        c in "0123456789abcdefABCDEF" for c in checkpoint_hash
                    )
                    or args.checkpoint_height is None
                    or args.checkpoint_height < 0
                ):
                    raise VerificationError(
                        "--header-chain requires --checkpoint-hash as "
                        "64-char block hash hex and --checkpoint-height "
                        "as a non-negative integer"
                    )
                manifests = None
                public_key = None
                if args.manifest is not None or args.public_key is not None:
                    if args.manifest is None or args.public_key is None:
                        raise VerificationError(
                            "anchor-chain-verify requires --manifest and "
                            "--public-key together to re-check acceptance binding"
                        )
                    manifests = [_read_json(path) for path in args.manifest]
                    public_key = load_public_key(args.public_key)
                fetcher = WoCBlockFetcher(base_url=args.woc_base)
                bumps = None
                beef = None
                if args.spv:
                    inclusion = "spv"
                    inclusion_verifier = SPVVerifier(fetcher)
                elif args.bump_file is not None:
                    inclusion = "bump"
                    bumps = _read_json(args.bump_file)
                    if not isinstance(bumps, dict):
                        raise VerificationError(
                            "--bump-file JSON must map txid -> BUMP"
                        )
                    inclusion_verifier = BUMPVerifier(fetcher)
                else:
                    inclusion = "beef"
                    beef = _read_beef(args.beef_file)
                    inclusion_verifier = BeefVerifier(fetcher)
                result = verify_v2_anchor_chain(
                    args.journal,
                    anchors,
                    args.genesis_txid,
                    payload_fetcher=fetcher,
                    signature_verifier=AnchorSignatureVerifier(fetcher, pubkey),
                    inclusion=inclusion,
                    inclusion_verifier=inclusion_verifier,
                    header_verifier=HeaderChainVerifier(
                        fetcher,
                        checkpoint_hash=checkpoint_hash,
                        checkpoint_height=args.checkpoint_height,
                        daa=DAAParams.mainnet() if args.daa else None,
                    ),
                    bumps=bumps,
                    beef=beef,
                    manifests=manifests,
                    public_key=public_key,
                )
                print(json.dumps(result, indent=2, sort_keys=True))
                acceptance = result["acceptance"]
                print(
                    f"{VERDICT_PREFIX}: "
                    f"{'yes' if acceptance['prefix_matches_anchor'] else 'no'}"
                )
                print(
                    f"{VERDICT_TIP}: "
                    f"{'yes' if acceptance['tip_inside_anchor'] else 'no'}"
                )
                print(
                    "freshness: unavailable (no tip service; a shorter "
                    "anchor set is not detected)"
                )
                if acceptance["authenticated_prefix_end"] is not None:
                    print(
                        "authenticated prefix end (seq): "
                        f"{acceptance['authenticated_prefix_end']}"
                    )
                for reason in acceptance["reasons"]:
                    print(f"  WITHHELD: {reason}")
                if not acceptance["accepted"]:
                    print(
                        "ANCHOR AUTHENTICATION WITHHELD: the full anchor-only "
                        "acceptance predicate did not hold."
                    )
                    return 1
                return 0
            if args.journal is not None:
                manifests = None
                public_key = None
                if args.manifest is not None or args.public_key is not None:
                    if args.manifest is None or args.public_key is None:
                        raise VerificationError(
                            "anchor-chain-verify requires --manifest and "
                            "--public-key together to re-check acceptance binding"
                        )
                    manifests = [_read_json(path) for path in args.manifest]
                    public_key = load_public_key(args.public_key)
                result = verify_journal_against_anchor_chain(
                    args.journal, anchors, args.genesis_txid, manifests, public_key
                )
            else:
                result = verify_anchor_chain(anchors, args.genesis_txid)
            anchor_count = result.get("anchor_count")
            if anchor_count is None:
                anchor_count = result.get("chain", {}).get("anchor_count")
            if anchor_count == 0:
                # Vacuous verification: nothing was checked. This is an
                # error at the CLI layer, not in the library functions,
                # whose vacuous-True semantics are unchanged.
                print("ERROR: no anchors to verify", file=sys.stderr)
                return 1
            # Payload binding: whenever any on-chain check is requested,
            # the claimed payload must equal the OP_RETURN output of the
            # fetched on-chain tx. Without this, a forged payload paired
            # with a real txid would pass every other check (they all
            # look only at the txid). Skipped for local-only runs, where
            # no on-chain claim is made.
            on_chain = (
                args.spv
                or args.bump_file is not None
                or args.beef_file is not None
                or args.anchor_sig
                or args.header_chain
            )
            if on_chain:
                result = apply_payload_binding(
                    result,
                    WoCBlockFetcher(base_url=args.woc_base),
                )
            if args.spv:
                result = apply_chain_inclusion(
                    result,
                    SPVVerifier(WoCBlockFetcher(base_url=args.woc_base)),
                )
            if args.bump_file is not None:
                bumps = _read_json(args.bump_file)
                if not isinstance(bumps, dict):
                    raise VerificationError(
                        "--bump-file JSON must map txid -> BUMP"
                    )
                result = apply_bump_inclusion(
                    result,
                    BUMPVerifier(WoCBlockFetcher(base_url=args.woc_base)),
                    bumps,
                )
            if args.beef_file is not None:
                result = apply_beef_inclusion(
                    result,
                    BeefVerifier(WoCBlockFetcher(base_url=args.woc_base)),
                    _read_beef(args.beef_file),
                )
            if args.anchor_sig:
                pubkey = args.anchor_pubkey or ""
                if (
                    len(pubkey) != 66
                    or pubkey[:2] not in ("02", "03")
                    or not all(c in "0123456789abcdefABCDEF" for c in pubkey)
                ):
                    raise VerificationError(
                        "--anchor-sig requires --anchor-pubkey as 66-char "
                        "compressed pubkey hex (02/03 prefix)"
                    )
                result = apply_anchor_signatures(
                    result,
                    AnchorSignatureVerifier(
                        WoCBlockFetcher(base_url=args.woc_base), pubkey
                    ),
                )
            if args.daa and not args.header_chain:
                raise VerificationError("--daa requires --header-chain")
            if args.header_chain:
                checkpoint_hash = args.checkpoint_hash or ""
                if (
                    len(checkpoint_hash) != 64
                    or not all(c in "0123456789abcdefABCDEF" for c in checkpoint_hash)
                    or args.checkpoint_height is None
                    or args.checkpoint_height < 0
                ):
                    raise VerificationError(
                        "--header-chain requires --checkpoint-hash as "
                        "64-char block hash hex and --checkpoint-height "
                        "as a non-negative integer"
                    )
                result = apply_header_chain(
                    result,
                    HeaderChainVerifier(
                        WoCBlockFetcher(base_url=args.woc_base),
                        checkpoint_hash=checkpoint_hash,
                        checkpoint_height=args.checkpoint_height,
                        daa=DAAParams.mainnet() if args.daa else None,
                    ),
                )
            print(json.dumps(result, indent=2, sort_keys=True))
            # Binding did not run for local-only verification; when it
            # ran, its VERIFIED banners below must not print on failure.
            binding_ok = result.get("payload_binding_verified", True)
            if "payload_binding_verified" in result and not binding_ok:
                print(
                    "PAYLOAD BINDING CHECK FAILED: see per-anchor reasons."
                )
            tail = result.get("unanchored_events")
            if tail is not None and tail > 0:
                print(
                    f"{tail} journal event(s) after the last anchor "
                    "are not yet anchored"
                )
            if args.spv and binding_ok and result.get("chain_inclusion_verified"):
                count = result.get("anchor_count") or (
                    result.get("chain", {}).get("anchor_count")
                )
                print(
                    f"CHAIN INCLUSION VERIFIED: {count} anchor(s) proven "
                    "inside their claimed blocks."
                )
            if args.bump_file is not None:
                count = result.get("anchor_count") or (
                    result.get("chain", {}).get("anchor_count")
                )
                if binding_ok and result.get("bump_inclusion_verified"):
                    print(
                        f"BUMP INCLUSION VERIFIED: {count} anchor(s) proven "
                        "inside their claimed blocks from compact proofs."
                    )
                elif not result.get("bump_inclusion_verified"):
                    print(
                        "BUMP INCLUSION CHECK FAILED: see per-anchor reasons."
                    )
            if args.beef_file is not None:
                count = result.get("anchor_count") or (
                    result.get("chain", {}).get("anchor_count")
                )
                if binding_ok and result.get("beef_inclusion_verified"):
                    print(
                        f"BEEF INCLUSION VERIFIED: {count} anchor(s) proven "
                        "inside their claimed blocks from the envelope."
                    )
                elif not result.get("beef_inclusion_verified"):
                    print(
                        "BEEF INCLUSION CHECK FAILED: see per-anchor reasons."
                    )
                    # Report ancestry separately, never as inclusion:
                    # an unmined anchor verified by ancestry only is
                    # not proven inside a claimed block.
                    _anchors = result.get("chain", {}).get("anchors", []) or result.get(
                        "anchors", []
                    )
                    for _summary in _anchors:
                        _inc = _summary.get("beef_inclusion", {})
                        if _inc.get("status") == "ancestry":
                            print(
                                "BEEF ANCESTRY (not block inclusion): "
                                f"{_summary.get('txid')} verified by ancestry only."
                            )
            if not (
                (args.spv and result.get("chain_inclusion_verified"))
                or result.get("bump_inclusion_verified")
                or result.get("beef_inclusion_verified")
            ):
                print("LOCAL CHECK ONLY: BSV transaction inclusion has not been verified.")
            if args.anchor_sig:
                count = result.get("anchor_count") or (
                    result.get("chain", {}).get("anchor_count")
                )
                if binding_ok and result.get("anchor_signatures_verified"):
                    print(
                        f"ANCHOR SIGNATURES VERIFIED: {count} anchor(s) "
                        "signed by the trusted anchor key."
                    )
                elif not result.get("anchor_signatures_verified"):
                    print(
                        "ANCHOR SIGNATURE CHECK FAILED: see per-anchor reasons."
                    )
            if args.header_chain:
                count = result.get("anchor_count") or (
                    result.get("chain", {}).get("anchor_count")
                )
                if binding_ok and result.get("header_chain_verified"):
                    print(
                        f"HEADER CHAIN VERIFIED: {count} anchor(s) chained "
                        "back to the pinned checkpoint."
                    )
                elif not result.get("header_chain_verified"):
                    print(
                        "HEADER CHAIN CHECK FAILED: see per-anchor reasons."
                    )
            if args.journal is not None and args.manifest is None and args.public_key is None:
                print(
                    "WARNING: acceptance binding was NOT re-checked: "
                    "re-run with --manifest and --public-key to re-derive "
                    "binding from the signed manifests."
                )
            # A failed check must fail the process: automation keyed on
            # the exit code must not read a FAILED line as success.
            chain_result = result.get("chain", result)
            failed = not chain_result.get("verified")
            if "payload_binding_verified" in result:
                failed = failed or not result.get("payload_binding_verified")
            if args.spv:
                failed = failed or not result.get("chain_inclusion_verified")
            if args.bump_file is not None:
                failed = failed or not result.get("bump_inclusion_verified")
            if args.beef_file is not None:
                failed = failed or not result.get("beef_inclusion_verified")
            if args.anchor_sig:
                failed = failed or not result.get("anchor_signatures_verified")
            if args.header_chain:
                failed = failed or not result.get("header_chain_verified")
            if failed:
                return 1
        elif args.command in ("bootstrap", "checkpoint-bootstrap"):
            anchors: list[dict] = []
            for path in args.anchor or []:
                entry = _read_json(path)
                if (
                    not isinstance(entry, dict)
                    or not isinstance(entry.get("payload_hex"), str)
                    or not isinstance(entry.get("txid"), str)
                ):
                    raise VerificationError(
                        "anchor JSON must contain payload_hex and txid"
                    )
                anchors.append(
                    {"payload_hex": entry["payload_hex"], "txid": entry["txid"]}
                )
            if args.anchor_record is not None:
                store = _read_json(args.anchor_record)
                records = store.get("anchors") if isinstance(store, dict) else None
                if not isinstance(records, list):
                    raise VerificationError(
                        "anchor-record JSON must contain an anchors list"
                    )
                for record in records:
                    if isinstance(record, dict) and record.get("status") == "broadcast":
                        anchors.append(
                            {
                                "payload_hex": record["payload_hex"],
                                "txid": record["txid"],
                            }
                        )
            if not anchors:
                raise VerificationError(
                    "bootstrap requires at least one --anchor or a broadcast "
                    "record in --anchor-record"
                )
            inclusion_sources = (
                bool(args.spv)
                + (args.bump_file is not None)
                + (args.beef_file is not None)
            )
            if inclusion_sources != 1:
                raise VerificationError(
                    "bootstrap requires exactly one inclusion source: --spv, "
                    "--bump-file, or --beef-file (ancestry-only BEEF does not "
                    "count as inclusion)"
                )
            pubkey = args.anchor_pubkey or ""
            if (
                len(pubkey) != 66
                or pubkey[:2] not in ("02", "03")
                or not all(c in "0123456789abcdefABCDEF" for c in pubkey)
            ):
                raise VerificationError(
                    "bootstrap requires --anchor-pubkey as 66-char "
                    "compressed pubkey hex (02/03 prefix)"
                )
            checkpoint_hash = args.checkpoint_hash or ""
            if (
                len(checkpoint_hash) != 64
                or not all(
                    c in "0123456789abcdefABCDEF" for c in checkpoint_hash
                )
                or args.checkpoint_height is None
                or args.checkpoint_height < 0
            ):
                raise VerificationError(
                    "bootstrap requires --checkpoint-hash as 64-char block "
                    "hash hex and --checkpoint-height as a non-negative integer"
                )
            if (args.manifest is None) != (args.public_key is None):
                raise VerificationError(
                    "bootstrap requires --manifest and --public-key together "
                    "to re-check acceptance binding"
                )
            manifests = None
            public_key = None
            if args.manifest is not None:
                manifests = [_read_json(path) for path in args.manifest]
                public_key = load_public_key(args.public_key)
            child_uid = resolve_uid(args.uid)
            if child_uid is None:
                raise VerificationError(
                    "bootstrap requires --uid (or --child-uid): the cache must "
                    "be isolated from the uid the launcher will drop to"
                )
            fetcher = WoCBlockFetcher(base_url=args.woc_base)
            bumps = None
            beef = None
            if args.spv:
                inclusion = "spv"
                inclusion_verifier = SPVVerifier(fetcher)
            elif args.bump_file is not None:
                inclusion = "bump"
                bumps = _read_json(args.bump_file)
                if not isinstance(bumps, dict):
                    raise VerificationError(
                        "--bump-file JSON must map txid -> BUMP"
                    )
                inclusion_verifier = BUMPVerifier(fetcher)
            else:
                inclusion = "beef"
                beef = _read_beef(args.beef_file)
                inclusion_verifier = BeefVerifier(fetcher)
            result = bootstrap_checkpoint(
                args.journal,
                args.checkpoint_cache,
                anchors,
                args.genesis_txid,
                payload_fetcher=fetcher,
                signature_verifier=AnchorSignatureVerifier(fetcher, pubkey),
                inclusion=inclusion,
                inclusion_verifier=inclusion_verifier,
                header_verifier=HeaderChainVerifier(
                    fetcher,
                    checkpoint_hash=checkpoint_hash,
                    checkpoint_height=args.checkpoint_height,
                    daa=DAAParams.mainnet() if args.daa else None,
                ),
                bumps=bumps,
                beef=beef,
                manifests=manifests,
                public_key=public_key,
                child_uid=child_uid,
                cache_key=args.cache_key,
            )
            record = result["checkpoint"]
            print(json.dumps(result, indent=2, sort_keys=True))
            print(
                "CHECKPOINT BOOTSTRAPPED: release_seq="
                f"{record['release_seq']} anchor_end_seq="
                f"{record['anchor_end_seq']} checkpoint_seq="
                f"{record['checkpoint_seq']}"
            )
            print(
                "Offline launches now read only this cache; no network call "
                "is made at launch time."
            )
        elif args.command == "proof-bundle-create":
            try:
                summary = create_bundle(
                    args.manifest, args.public_key, args.root, args.output,
                    journal_path=args.journal, anchor_path=args.anchor,
                )
            except VerificationError as exc:
                print(f"ERROR: proof bundle not created: {exc}", file=sys.stderr)
                return 1
            print(f"Proof bundle written: {args.output}")
            print(f"  artifacts: {len(summary['artifacts'])}")
            if summary["journal_events"] is not None:
                print(f"  journal events: {summary['journal_events']}")
            print(f"  anchor verified: {summary['anchor_verified']}")
        elif args.command == "proof-bundle-verify":
            try:
                summary = verify_bundle(args.bundle)
            except VerificationError as exc:
                print(f"BUNDLE VERIFICATION FAILED: {exc}", file=sys.stderr)
                return 1
            print(f"BUNDLE VERIFIED: {len(summary['artifacts'])} artifact(s): "
                  + ", ".join(summary["artifacts"]))
            if summary["journal_events"] is not None:
                print(f"  journal events: {summary['journal_events']} (hash chain intact)")
            else:
                print("  journal: absent")
            if summary["anchor_verified"]:
                print("  anchor: journal head matches anchor payload")
            else:
                print("  anchor: absent")
            print("  This proves: these artifact bytes match this signed manifest; "
                  "the journal, if present, is an intact hash chain; the journal "
                  "head, if an anchor is present, matches the anchor payload.")
            print("  This does NOT prove: the artifacts are safe, correct, or true; "
                  "the signer is trustworthy; the run did anything beyond producing "
                  "these files; or that any anchor transaction is included on-chain.")
        elif args.command == "signer":
            from .signer_cli import main as signer_main

            return signer_main(args.signer_argv)
        elif args.command == "publish":
            manifests = None
            public_key = None
            has_manifests = args.manifest is not None or args.manifest_dir is not None
            if has_manifests or args.public_key is not None:
                if not has_manifests or args.public_key is None:
                    raise VerificationError(
                        "publish requires --manifest and/or --manifest-dir "
                        "together with --public-key to check acceptance binding"
                    )
                manifests = [_read_json(path) for path in args.manifest or []]
                public_key = load_public_key(args.public_key)
            if args.export_unsigned is not None or args.broadcast_signed is not None:
                # One-shot offline-signing modes. They never combine
                # with each other, with --broadcast, or with a
                # non-once --mode; they never touch signing material.
                if (
                    args.export_unsigned is not None
                    and args.broadcast_signed is not None
                ):
                    raise PublisherError(
                        "--export-unsigned and --broadcast-signed cannot "
                        "be combined: export first, sign, then broadcast"
                    )
                if args.broadcast:
                    raise PublisherError(
                        "--export-unsigned / --broadcast-signed cannot be "
                        "combined with --broadcast: the ceremony never "
                        "signs and broadcasts in one motion"
                    )
                if args.mode != "once":
                    raise PublisherError(
                        "--export-unsigned / --broadcast-signed are "
                        "one-shot modes; --mode must be 'once'"
                    )
                if args.network != "testnet":
                    raise PublisherError(
                        "--export-unsigned / --broadcast-signed refuse "
                        "mainnet: the offline-signing flow is testnet-only "
                        "until a witnessed mainnet-key step exists"
                    )
                if os.environ.get("ANCHOR_WIF"):
                    raise PublisherError(
                        "--export-unsigned / --broadcast-signed refuse "
                        "when ANCHOR_WIF is set: the builder side of the "
                        "ceremony must never hold signing material"
                    )
                if not args.funding_txid or not args.change_address:
                    raise PublisherError(
                        "--export-unsigned / --broadcast-signed require "
                        "--funding-txid and --change-address"
                    )
                woc_base = args.woc_base or WOC_TTN_BASE
                config = PublisherConfig(
                    journal=args.journal,
                    anchor_record=args.anchor_record,
                    genesis_txid=args.genesis_txid,
                    checkpoint_interval_seconds=args.interval_seconds,
                    broadcast_enabled=False,
                    manifests=tuple(manifests) if manifests is not None else (),
                    public_key=public_key,
                    manifests_dir=args.manifest_dir,
                )
                publisher = Publisher(config)
                if args.export_unsigned is not None:
                    result = publisher.export_unsigned(
                        funding_txid=args.funding_txid,
                        funding_vout=args.funding_vout,
                        change_address=args.change_address,
                        fee_sats=args.fee_sats,
                        woc_base=woc_base,
                        network=args.network,
                    )
                    args.export_unsigned.write_text(
                        result["unsigned_hex"] + "\n", encoding="utf-8"
                    )
                    print(json.dumps({
                        "action": "exported-unsigned",
                        "unsigned_file": str(args.export_unsigned),
                        "unsigned_txid": result["unsigned_txid"],
                        "payload": result["payload"],
                        "fee_sats": result["fee_sats"],
                        "change_address": result["change_address"],
                        "funding_txid": result["funding_txid"],
                        "funding_vout": result["funding_vout"],
                        "funding_value": result["funding_value"],
                        "network": result["network"],
                        "record": result["record"],
                    }, indent=2, sort_keys=True))
                    print(
                        "Cross-check the unsigned_txid + payload above "
                        "against the signer display before approving."
                    )
                else:
                    signed_hex = args.broadcast_signed.read_text(
                        encoding="utf-8"
                    ).strip()
                    record = publisher.broadcast_signed(
                        signed_hex=signed_hex,
                        funding_txid=args.funding_txid,
                        funding_vout=args.funding_vout,
                        change_address=args.change_address,
                        fee_sats=args.fee_sats,
                        woc_base=woc_base,
                        network=args.network,
                    )
                    print(json.dumps(
                        {"action": "broadcast-signed", "record": record},
                        indent=2, sort_keys=True,
                    ))
                return 0
            if args.broadcast:
                anchor_wif = os.environ.get("ANCHOR_WIF")
                if not anchor_wif:
                    raise PublisherError(
                        "broadcast requested but ANCHOR_WIF is not set: "
                        "the anchor signing key comes from the environment, "
                        "never from config or the command line"
                    )
                if not args.funding_txid:
                    raise PublisherError(
                        "broadcast requested but --funding-txid is not set: "
                        "the funding UTXO must be named explicitly (WoC-TTN's "
                        "unspent index is broken, so discovery by address is "
                        "unavailable)"
                    )
                if args.network == "mainnet" and not args.confirm_mainnet:
                    raise PublisherError(
                        "mainnet broadcast requires --confirm-mainnet: "
                        "mainnet spends real funds and must never happen "
                        "by default or accident"
                    )
                woc_base = args.woc_base or (
                    WOC_MAINNET_BASE if args.network == "mainnet" else WOC_TTN_BASE
                )
                broadcaster = WoCBroadcaster(
                    base_url=woc_base,
                    network=args.network,
                    signer=WIFSigner.from_wif(anchor_wif, network=args.network),
                    fee_sats=args.fee_sats,
                    funding=FundingUTXO(
                        txid=args.funding_txid,
                        vout=args.funding_vout,
                        value=0,  # replaced by the fetched prev-tx value
                        script_hex="",  # replaced by the fetched prev-tx script
                    ),
                )
                broadcast_enabled = True
            else:
                broadcaster = None
                broadcast_enabled = False
            config = PublisherConfig(
                journal=args.journal,
                anchor_record=args.anchor_record,
                genesis_txid=args.genesis_txid,
                checkpoint_interval_seconds=args.interval_seconds,
                broadcast_enabled=broadcast_enabled,
                manifests=tuple(manifests) if manifests is not None else (),
                public_key=public_key,
                manifests_dir=args.manifest_dir,
            )
            publisher = Publisher(config, broadcaster=broadcaster)
            if args.mode == "on-release":
                record = publisher.on_release_accepted()
                print(json.dumps({"action": "anchored", "reason": "release",
                                  "record": record}, indent=2, sort_keys=True))
                if args.broadcast and record.get("broadcast_error"):
                    print(f"ERROR: broadcast failed: {record.get('broadcast_error')}", file=sys.stderr)
                    return 1
                if args.broadcast and record.get("status") != "broadcast":
                    print("ERROR: broadcast did not complete", file=sys.stderr)
                    return 1
            elif args.mode == "loop":
                try:
                    decisions = publisher.run_loop(max_iterations=args.max_iterations)
                except KeyboardInterrupt:
                    print("Publisher loop interrupted by operator.")
                    return 0
                print(json.dumps(decisions, indent=2, sort_keys=True))
                if args.broadcast:
                    for d in decisions:
                        rec = d.get("record") if isinstance(d, dict) else None
                        if isinstance(rec, dict) and (rec.get("broadcast_error") or (rec.get("status") not in ("broadcast",) and d.get("action") == "anchored" and rec.get("status") == "pending")):
                            print("ERROR: broadcast failed or pending after broadcast attempt", file=sys.stderr)
                            return 1
            else:
                decision = publisher.run_once()
                print(json.dumps(decision, indent=2, sort_keys=True))
                if args.broadcast:
                    rec = decision.get("record") if isinstance(decision, dict) else None
                    if isinstance(rec, dict):
                        if rec.get("broadcast_error"):
                            print(f"ERROR: broadcast failed: {rec.get('broadcast_error')}", file=sys.stderr)
                            return 1
                        if rec.get("status") == "pending" and decision.get("action") == "anchored":
                            print("ERROR: broadcast did not complete", file=sys.stderr)
                            return 1
            if not args.broadcast:
                print("DRY RUN: broadcast disabled — payloads prepared, nothing broadcast.")
    except (OSError, ValueError, KeyError, TypeError, struct.error,
            IndexError, AttributeError, OverflowError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
