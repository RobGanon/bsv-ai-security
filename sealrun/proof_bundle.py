"""Portable proof bundles: pack a verified run, re-verify it offline.

A bundle is a zip file containing a signed manifest, its public key,
the artifact bytes, and optionally the audit journal and an anchor
payload. It adds no new trust: creation re-verifies the manifest
before packing, and verification re-runs the existing ``verify``,
``audit-verify`` and ``anchor-verify`` paths on the extracted
contents. A bundle proves history integrity/existence, NOT
truthfulness: it does not prove the artifacts are safe, correct, or
true, the signer is trustworthy, or the run did anything beyond
producing these files.

Stdlib only. No change to verification, signing, journaling, or
anchoring logic lives here; this module only calls it.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__ as _SEALRUN_VERSION
from .anchor import verify_journal_against_anchor
from .bsv import PrivKey
from .core import (
    VerificationError,
    _no_duplicate_object,
    load_public_key,
    verify_audit_journal,
    verify_manifest,
)

BUNDLE_SCHEMA = "sealrun-proof-bundle-v1"

CLAIMS_PROVES = [
    "These artifact bytes match this signed manifest, verified with this public key.",
    "The journal, if present, is an intact hash chain.",
    "The journal head, if an anchor is present, matches the anchor payload.",
]

CLAIMS_DOES_NOT_PROVE = [
    "The artifacts are safe, correct, or true.",
    "The signer is trustworthy.",
    "The run did anything beyond producing these files.",
    "That any anchor transaction is included on-chain (inclusion is not checked here).",
]

_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

_PRIVATE_FILENAME_TOKENS = ("private_key", "private-key", "privkey", "id_rsa")


def _read_json(path: Path):
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_object,
        )
    except ValueError as exc:
        raise VerificationError(f"invalid JSON in {path}: {exc}") from exc
    except OSError as exc:
        raise VerificationError(f"cannot read {path}: {exc}") from exc


def looks_like_private_key(name: str, data: bytes) -> bool:
    """Guard, not a guarantee: refuse anything that looks like key material.

    Filename signals (private_key / private-key / privkey / id_rsa /
    .pem / .key) plus content signals (PEM private-key headers, or a
    body that parses as WIF). The creator remains responsible for
    what they pack; this check only stops the obvious accident.
    """
    lowered = name.lower()
    if any(token in lowered for token in _PRIVATE_FILENAME_TOKENS):
        return True
    if lowered.endswith(".pem") or lowered.endswith(".key"):
        return True
    if b"BEGIN PRIVATE KEY" in data or b"BEGIN RSA PRIVATE KEY" in data \
            or b"BEGIN EC PRIVATE KEY" in data:
        return True
    if len(data) < 512:
        try:
            text = data.decode("ascii").strip()
        except UnicodeDecodeError:
            return False
        if text:
            try:
                PrivKey.from_wif_any(text)
            except ValueError:
                return False
            return True
    return False


def _check_no_private_keys(files: dict[str, bytes]) -> None:
    for name, data in files.items():
        if looks_like_private_key(name, data):
            raise VerificationError(
                f"refusing to bundle possible private key material: {name}"
            )


def _write_zip_entry(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)


def create_bundle(
    manifest_path: Path,
    public_key_path: Path,
    root: Path,
    output_path: Path,
    journal_path: Path | None = None,
    anchor_path: Path | None = None,
) -> dict:
    """Re-verify a run, then pack it into a zip bundle.

    On any failure, no bundle is written (a partially built zip in a
    temporary file is removed; a pre-existing output file is left
    untouched).
    """
    envelope = _read_json(manifest_path)
    public_key = load_public_key(public_key_path)
    # Re-verify BEFORE packing: a bundle must never be created from
    # an unverified run.
    artifacts = verify_manifest(root, envelope, public_key)

    journal_events = None
    journal_bytes = None
    if journal_path is not None:
        if journal_path.is_symlink() or not journal_path.is_file():
            raise VerificationError(f"journal file not found: {journal_path}")
        journal_events = verify_audit_journal(journal_path)
        journal_bytes = journal_path.read_bytes()

    anchor_verified = False
    anchor_txid = None
    anchor_bytes = None
    anchor_result = None
    if anchor_path is not None:
        if journal_path is None:
            raise VerificationError(
                "an anchor can only be bundled with its journal"
            )
        anchor_obj = _read_json(anchor_path)
        if not isinstance(anchor_obj, dict) or not isinstance(
            anchor_obj.get("payload_hex"), str
        ):
            raise VerificationError(
                "anchor JSON must contain a payload_hex string"
            )
        try:
            anchor_payload = bytes.fromhex(anchor_obj["payload_hex"])
        except ValueError as exc:
            raise VerificationError(
                "anchor payload_hex is not valid hexadecimal"
            ) from exc
        anchor_result = verify_journal_against_anchor(
            journal_path, anchor_payload, [envelope], public_key
        )
        anchor_verified = bool(anchor_result.get("verified"))
        if not anchor_verified:
            raise VerificationError("journal does not match anchor payload")
        txid = anchor_obj.get("txid")
        if txid is not None and not (
            isinstance(txid, str) and len(txid) == 64
            and all(c in "0123456789abcdefABCDEF" for c in txid)
        ):
            raise VerificationError("anchor txid must be 64 hexadecimal characters")
        anchor_txid = txid.lower() if isinstance(txid, str) else None
        anchor_bytes = anchor_path.read_bytes()

    files: dict[str, bytes] = {}
    files["manifest.json"] = manifest_path.read_bytes()
    files["public_key"] = public_key_path.read_bytes()
    for rel in artifacts:
        files[f"artifacts/{rel}"] = (root / rel).read_bytes()
    if journal_bytes is not None:
        files["journal.json"] = journal_bytes
    if anchor_bytes is not None:
        files["anchor.json"] = anchor_bytes
    _check_no_private_keys(files)

    bundle_doc = {
        "schema": BUNDLE_SCHEMA,
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sealrun_version": _SEALRUN_VERSION,
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "manifest": "manifest.json",
        "public_key": "public_key",
        "artifacts": list(artifacts),
        "journal": "journal.json" if journal_bytes is not None else None,
        "journal_events": journal_events,
        "anchor": (
            {"file": "anchor.json", "txid": anchor_txid}
            if anchor_bytes is not None
            else None
        ),
        "anchor_verified": anchor_verified,
        "claims": {
            "proves": list(CLAIMS_PROVES),
            "does_not_prove": list(CLAIMS_DOES_NOT_PROVE),
        },
    }

    # Deterministic entry order: sorted content entries, bundle.json last.
    ordered = sorted(name for name in files if name != "bundle.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(output_path.parent), prefix=".proof-bundle-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            with zipfile.ZipFile(handle, "w") as zf:
                for name in ordered:
                    _write_zip_entry(zf, name, files[name])
                _write_zip_entry(
                    zf,
                    "bundle.json",
                    (json.dumps(bundle_doc, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                )
        os.replace(tmp_name, output_path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return {
        "output": str(output_path),
        "artifacts": list(artifacts),
        "journal_events": journal_events,
        "anchor_verified": anchor_verified,
        "anchor_txid": anchor_txid,
    }


def _safe_extract(zf: zipfile.ZipFile, target: Path) -> None:
    base = target.resolve()
    for info in zf.infolist():
        if info.is_dir():
            continue
        dest = (target / info.filename).resolve()
        if dest != base and base not in dest.parents:
            raise VerificationError(
                f"bundle entry escapes its directory: {info.filename}"
            )
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(dest, "wb") as dst:
            shutil.copyfileobj(src, dst)


def verify_bundle(bundle_path: Path) -> dict:
    """Re-verify a proof bundle offline. Raises on the first failed check."""
    if not zipfile.is_zipfile(bundle_path):
        raise VerificationError(f"not a zip bundle: {bundle_path}")
    with zipfile.ZipFile(bundle_path) as zf:
        names = set(zf.namelist())
        if "bundle.json" not in names:
            raise VerificationError("bundle is missing bundle.json")
        try:
            bundle_doc = json.loads(
                zf.read("bundle.json").decode("utf-8"),
                object_pairs_hook=_no_duplicate_object,
            )
        except ValueError as exc:
            raise VerificationError(f"invalid bundle.json: {exc}") from exc
        if not isinstance(bundle_doc, dict) or bundle_doc.get("schema") != BUNDLE_SCHEMA:
            raise VerificationError(
                f"unsupported bundle schema: {bundle_doc.get('schema') if isinstance(bundle_doc, dict) else type(bundle_doc).__name__}"
            )
        manifest_name = bundle_doc.get("manifest")
        public_key_name = bundle_doc.get("public_key")
        artifact_names = bundle_doc.get("artifacts")
        if manifest_name not in names or public_key_name not in names:
            raise VerificationError("bundle is missing its manifest or public key")
        if not isinstance(artifact_names, list):
            raise VerificationError("bundle.json artifacts must be a list")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _safe_extract(zf, tmp_path)
            envelope = _read_json(tmp_path / manifest_name)
            public_key = load_public_key(tmp_path / public_key_name)
            verify_root = tmp_path / "_verify_root"
            verify_root.mkdir()
            for rel in artifact_names:
                if not isinstance(rel, str) or not rel or rel.startswith("/") \
                        or ".." in Path(rel).parts:
                    raise VerificationError(f"unsafe artifact path in bundle: {rel!r}")
                src = tmp_path / "artifacts" / rel
                if not src.is_file():
                    raise VerificationError(f"bundle is missing artifact: {rel}")
                dest = verify_root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dest)
            artifacts = verify_manifest(verify_root, envelope, public_key)

            journal_events = None
            journal_name = bundle_doc.get("journal")
            journal_path = None
            if journal_name is not None:
                journal_path = tmp_path / journal_name
                if not journal_path.is_file():
                    raise VerificationError("bundle is missing its journal")
                journal_events = verify_audit_journal(journal_path)

            anchor_verified = False
            anchor_txid = None
            anchor_doc = bundle_doc.get("anchor")
            if anchor_doc is not None:
                if journal_path is None:
                    raise VerificationError(
                        "bundle claims an anchor but has no journal"
                    )
                anchor_name = anchor_doc.get("file") if isinstance(anchor_doc, dict) else None
                anchor_file = tmp_path / anchor_name if anchor_name else None
                if anchor_file is None or not anchor_file.is_file():
                    raise VerificationError("bundle is missing its anchor file")
                anchor_obj = _read_json(anchor_file)
                if not isinstance(anchor_obj, dict) or not isinstance(
                    anchor_obj.get("payload_hex"), str
                ):
                    raise VerificationError(
                        "anchor JSON must contain a payload_hex string"
                    )
                try:
                    anchor_payload = bytes.fromhex(anchor_obj["payload_hex"])
                except ValueError as exc:
                    raise VerificationError(
                        "anchor payload_hex is not valid hexadecimal"
                    ) from exc
                result = verify_journal_against_anchor(
                    journal_path, anchor_payload, [envelope], public_key
                )
                anchor_verified = bool(result.get("verified"))
                if not anchor_verified:
                    raise VerificationError(
                        "journal does not match anchor payload"
                    )
                anchor_txid = anchor_doc.get("txid") if isinstance(anchor_doc, dict) else None
    return {
        "artifacts": artifacts,
        "journal_events": journal_events,
        "anchor_verified": anchor_verified,
        "anchor_txid": anchor_txid,
        "claims": {
            "proves": list(CLAIMS_PROVES),
            "does_not_prove": list(CLAIMS_DOES_NOT_PROVE),
        },
    }
