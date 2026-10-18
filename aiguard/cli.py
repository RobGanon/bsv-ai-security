from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path

from .anchor import (
    AnchorSignatureVerifier,
    apply_anchor_signatures,
    apply_header_chain,
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
    record_manifest_acceptance,
    sign_manifest,
    verify_audit_journal,
    verify_manifest,
)


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
    p.add_argument("--woc-base", default=WOC_TTN_BASE,
                   help="WhatsOnChain base URL for --spv / --anchor-sig "
                   "chain data (default: Teratestnet)")

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
                    ),
                )
            print(json.dumps(result, indent=2, sort_keys=True))
            if args.spv and result.get("chain_inclusion_verified"):
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
                if result.get("bump_inclusion_verified"):
                    print(
                        f"BUMP INCLUSION VERIFIED: {count} anchor(s) proven "
                        "inside their claimed blocks from compact proofs."
                    )
                else:
                    print(
                        "BUMP INCLUSION CHECK FAILED: see per-anchor reasons."
                    )
            if args.beef_file is not None:
                count = result.get("anchor_count") or (
                    result.get("chain", {}).get("anchor_count")
                )
                if result.get("beef_inclusion_verified"):
                    print(
                        f"BEEF INCLUSION VERIFIED: {count} anchor(s) proven "
                        "inside their claimed blocks from the envelope."
                    )
                else:
                    print(
                        "BEEF INCLUSION CHECK FAILED: see per-anchor reasons."
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
                if result.get("anchor_signatures_verified"):
                    print(
                        f"ANCHOR SIGNATURES VERIFIED: {count} anchor(s) "
                        "signed by the trusted anchor key."
                    )
                else:
                    print(
                        "ANCHOR SIGNATURE CHECK FAILED: see per-anchor reasons."
                    )
            if args.header_chain:
                count = result.get("anchor_count") or (
                    result.get("chain", {}).get("anchor_count")
                )
                if result.get("header_chain_verified"):
                    print(
                        f"HEADER CHAIN VERIFIED: {count} anchor(s) chained "
                        "back to the pinned checkpoint."
                    )
                else:
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
            if not args.broadcast:
                print("DRY RUN: broadcast disabled — payloads prepared, nothing broadcast.")
    except (OSError, ValueError, KeyError, TypeError, struct.error,
            IndexError, AttributeError, OverflowError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
