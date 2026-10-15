from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .anchor import (
    create_anchor_payload,
    verify_anchor_chain,
    verify_journal_against_anchor,
    verify_journal_against_anchor_chain,
)
from .publisher import (
    Publisher,
    PublisherConfig,
    PublisherError,
)
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
    p.add_argument("--journal", type=Path, default=None,
                   help="if given, also verify the journal against every anchor "
                   "in the chain (head hash + binding re-derivation)")
    p.add_argument("--manifest", action="append", type=Path, default=None,
                   help="signed manifest envelope JSON for binding re-verification; "
                   "repeatable; requires --public-key")
    p.add_argument("--public-key", type=Path, default=None,
                   help="trusted manifest-signing public key (PEM) for binding re-verification")

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
                   help="opt-in broadcast; fails closed: no broadcaster exists in "
                   "this build, so --broadcast without one is refused")
    p.add_argument("--manifest", action="append", type=Path, default=None,
                   help="signed manifest envelope JSON to check acceptances against; "
                   "repeatable; required when the journal contains acceptances")
    p.add_argument("--manifest-dir", type=Path, default=None,
                   help="directory of signed manifest envelope JSON files, "
                   "re-read at every checkpoint (for long-running publishers)")
    p.add_argument("--public-key", type=Path, default=None,
                   help="trusted manifest-signing public key (PEM); "
                   "required with --manifest when the journal contains acceptances")

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
            print(json.dumps(result, indent=2, sort_keys=True))
            print("LOCAL CHECK ONLY: BSV transaction inclusion has not been verified.")
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
            if args.broadcast:
                # No broadcaster exists in this build: the opt-in is real,
                # but enabling it without a broadcaster fails closed.
                raise PublisherError(
                    "broadcast requested but no broadcaster is configured: "
                    "no broadcast adapter exists in this build; refusing to run"
                )
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
            if args.mode == "on-release":
                record = publisher.on_release_accepted()
                print(json.dumps({"action": "anchored", "reason": "release",
                                  "record": record}, indent=2, sort_keys=True))
            elif args.mode == "loop":
                try:
                    decisions = publisher.run_loop(max_iterations=args.max_iterations)
                except KeyboardInterrupt:
                    print("Publisher loop interrupted by operator.")
                    return 0
                print(json.dumps(decisions, indent=2, sort_keys=True))
            else:
                decision = publisher.run_once()
                print(json.dumps(decision, indent=2, sort_keys=True))
            print("DRY RUN: broadcast disabled — payloads prepared, nothing broadcast.")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
