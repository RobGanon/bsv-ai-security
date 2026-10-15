from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .anchor import create_anchor_payload, verify_journal_against_anchor
from .core import (
    VerificationError,
    append_audit_event,
    create_manifest,
    generate_keypair,
    load_private_key,
    load_public_key,
    manifest_hash,
    record_manifest_acceptance,
    sign_manifest,
    verify_audit_journal,
    verify_manifest,
)


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="aiguard", description="Local AI artifact trust core")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate a development Ed25519 keypair")
    p.add_argument("--private-key", required=True, type=Path)
    p.add_argument("--public-key", required=True, type=Path)

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
                   help="manifest hash (64 hex) to bind the acceptance to; "
                   "alternative to --manifest when only the hash is at hand")

    p = sub.add_parser("anchor-payload", help="prepare unsigned BSV anchor payload bytes (no broadcast)")
    p.add_argument("--journal", required=True, type=Path)
    p.add_argument("--start-seq", required=True, type=int)
    p.add_argument("--prev-txid", default="0" * 64)
    p.add_argument("--manifest", action="append", type=Path, default=None,
                   help="signed manifest envelope JSON to check acceptances against; "
                   "repeatable; required when the journal contains acceptances")
    p.add_argument("--public-key", type=Path, default=None,
                   help="trusted manifest-signing public key (PEM); "
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
                   help="trusted manifest-signing public key (PEM) for binding re-verification")

    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            generate_keypair(args.private_key, args.public_key)
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
        elif args.command == "audit-append":
            event = append_audit_event(args.journal, args.event_type, args.detail)
            print(f"Audit event appended: seq={event['seq']} hash={event['event_hash']}")
        elif args.command == "audit-verify":
            count = verify_audit_journal(args.journal)
            print(f"AUDIT OK: {count} event(s)")
        elif args.command == "audit-manifest-accepted":
            if args.manifest is not None and args.manifest_hash is not None:
                from_hash = manifest_hash(_read_json(args.manifest))
                if from_hash != args.manifest_hash.lower():
                    raise VerificationError(
                        "--manifest and --manifest-hash disagree on the manifest hash"
                    )
            if args.manifest is not None:
                bound_hash = manifest_hash(_read_json(args.manifest))
            elif args.manifest_hash is not None:
                bound_hash = args.manifest_hash
            else:
                raise VerificationError(
                    "audit-manifest-accepted requires --manifest or --manifest-hash "
                    "to bind the acceptance to a manifest (issue #11)"
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
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
