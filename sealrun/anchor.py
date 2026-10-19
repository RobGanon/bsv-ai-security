from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

from .core import (
    MANIFEST_ACCEPTED_EVENT_TYPE,
    VerificationError,
    _check_manifest_hash,
    _load_verified_payload,
    _no_duplicate_object,
    _read_jsonl,
    _verify_audit_events,
    manifest_hash as compute_manifest_hash,
)

# On-chain OP_RETURN magic. Deliberately NOT renamed: live anchors
# (Teratestnet #1/#2) carry AIGUARD1, and the anchor chain must stay
# continuous. The magic is wire-format data, not the package name.
MAGIC = b"AIGUARD1"
PAYLOAD_SIZE = 84
ZERO_TXID = "0" * 64
HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")
UINT32_MAX = (1 << 32) - 1


def _uint32(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= UINT32_MAX:
        raise VerificationError(f"{field} must be an unsigned 32-bit integer")
    return value


def encode_anchor_payload(
    *,
    head_hash: str,
    start_seq: int,
    end_seq: int,
    release_seq: int,
    prev_txid: str = ZERO_TXID,
) -> bytes:
    """Encode the protocol's exact 84-byte payload; this does not create a transaction."""
    if not isinstance(head_hash, str) or not HEX_64.fullmatch(head_hash):
        raise VerificationError("head_hash must be 64 hexadecimal characters")
    if not isinstance(prev_txid, str) or not HEX_64.fullmatch(prev_txid):
        raise VerificationError("prev_txid must be 64 hexadecimal characters")
    # Normalize to lowercase so core and anchor agree on representation.
    head_hash = head_hash.lower()
    prev_txid = prev_txid.lower()
    start_seq = _uint32(start_seq, "start_seq")
    end_seq = _uint32(end_seq, "end_seq")
    release_seq = _uint32(release_seq, "release_seq")
    if start_seq < 1:
        raise VerificationError("start_seq must be at least 1")
    if end_seq < start_seq:
        raise VerificationError("end_seq must be greater than or equal to start_seq")
    return (
        MAGIC
        + bytes.fromhex(head_hash)
        + start_seq.to_bytes(4, "big")
        + end_seq.to_bytes(4, "big")
        + release_seq.to_bytes(4, "big")
        + bytes.fromhex(prev_txid)
    )


def decode_anchor_payload(payload: bytes) -> dict[str, Any]:
    """Parse and validate an exact protocol payload."""
    if not isinstance(payload, bytes) or len(payload) != PAYLOAD_SIZE:
        raise VerificationError(f"anchor payload must be exactly {PAYLOAD_SIZE} bytes")
    if payload[:8] != MAGIC:
        raise VerificationError("unsupported anchor payload magic/version")
    start_seq = int.from_bytes(payload[40:44], "big")
    end_seq = int.from_bytes(payload[44:48], "big")
    release_seq = int.from_bytes(payload[48:52], "big")
    if start_seq < 1:
        raise VerificationError("start_seq must be at least 1")
    if end_seq < start_seq:
        raise VerificationError("end_seq must be greater than or equal to start_seq")
    return {
        "magic": MAGIC.decode("ascii"),
        "head_hash": payload[8:40].hex(),
        "start_seq": start_seq,
        "end_seq": end_seq,
        "release_seq": release_seq,
        "prev_txid": payload[52:84].hex(),
        "payload_hex": payload.hex(),
    }


def _verified_manifest_map(manifests: Any, public_key: Any) -> dict[str, dict]:
    """Verify each supplied manifest envelope and index it by its hash.

    Every envelope's secp256k1 signature is verified against ``public_key``
    via :func:`core._load_verified_payload`, so caller-supplied manifests
    are safe: a publisher cannot smuggle in a forged manifest without
    the signing key. Returns ``{manifest_hash: payload}`` where payload
    is the verified manifest payload (with ``release_id`` /
    ``release_seq`` validated). Manifests whose payload lacks valid
    release identity are rejected.
    """
    if public_key is None or manifests is None:
        raise VerificationError(
            "cannot verify acceptance binding without manifests and a "
            "trusted public key: supply the signed manifest envelopes and "
            "the manifest-signing public key to check acceptances against"
        )
    manifest_list = list(manifests)
    if not manifest_list:
        raise VerificationError(
            "cannot verify acceptance binding without manifests: "
            "supply the signed manifest envelopes to check acceptances against"
        )
    by_hash: dict[str, dict] = {}
    for envelope in manifest_list:
        if not isinstance(envelope, dict):
            raise VerificationError("manifest envelope must be a JSON object")
        payload = _load_verified_payload(envelope, public_key)
        release_id = payload.get("release_id")
        if not isinstance(release_id, str) or not release_id:
            raise VerificationError("invalid release_id in manifest")
        release_seq = payload.get("release_seq")
        if (
            not isinstance(release_seq, int)
            or isinstance(release_seq, bool)
            or not 0 <= release_seq <= UINT32_MAX
        ):
            raise VerificationError("invalid release_seq in manifest")
        by_hash[compute_manifest_hash(envelope)] = payload
    return by_hash


def _derive_release_seq(
    events: list[dict],
    end_seq: int,
    manifests: Any = None,
    public_key: Any = None,
) -> int:
    """Derive the anchored ``release_seq`` from bound journal acceptance events.

    Returns ``max(release_seq)`` over ``manifest_accepted`` events with
    ``seq <= end_seq``, or ``0`` ("no release adopted") when the covered
    range contains no acceptance. Every acceptance in the covered range
    must be *bound* to a verified manifest:

    - The detail must parse as a JSON object with ``release_seq``,
      ``release_id``, and ``manifest_hash`` (64-hex).
    - The ``manifest_hash`` must match a supplied manifest envelope
      whose secp256k1 signature verifies against ``public_key``.
    - The acceptance's ``release_id`` / ``release_seq`` must equal the
      manifest's own fields, so an acceptance cannot be rebound to a
      different release.

    Fail-closed rules: a malformed detail, a legacy acceptance without
    ``manifest_hash``, an acceptance whose hash matches no verified
    manifest, a release-identity mismatch, or any acceptance present
    without ``manifests`` + ``public_key`` to check it against all
    raise :class:`VerificationError` and anchoring fails closed.

    Legacy acceptances (pre-#11 detail without ``manifest_hash``) fail
    closed rather than being silently counted or ignored: an unbound
    acceptance is structurally identical to the forgery this binding
    closes. Operators with pre-#11 journals start a fresh journal and
    re-record bound acceptances.

    There is intentionally no caller override: any override would
    reintroduce the D2 gap the derivation closes.
    """
    acceptances: list[tuple[int, dict]] = []
    for event in events:
        seq = event.get("seq")
        if (
            not isinstance(seq, int)
            or isinstance(seq, bool)
            or seq > end_seq
            or event.get("event_type") != MANIFEST_ACCEPTED_EVENT_TYPE
        ):
            continue
        detail = event.get("detail")
        if not isinstance(detail, str):
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "detail must be a JSON string"
            )
        try:
            parsed = json.loads(detail, object_pairs_hook=_no_duplicate_object)
        except ValueError as exc:
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "detail is not valid JSON or has duplicate keys"
            ) from exc
        if not isinstance(parsed, dict):
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "detail must be a JSON object"
            )
        if "manifest_hash" not in parsed:
            raise VerificationError(
                f"legacy unbound manifest_accepted detail at sequence {seq}: "
                "detail has no manifest_hash; pre-#11 acceptances fail closed "
                "and must be re-recorded with a manifest binding"
            )
        release_seq = _uint32(parsed.get("release_seq"), "release_seq")
        release_id = parsed.get("release_id")
        if not isinstance(release_id, str) or not release_id:
            raise VerificationError(
                f"malformed manifest_accepted detail at sequence {seq}: "
                "release_id must be a non-empty string"
            )
        manifest_hash_value = _check_manifest_hash(parsed.get("manifest_hash"))
        acceptances.append((seq, {
            "release_seq": release_seq,
            "release_id": release_id,
            "manifest_hash": manifest_hash_value,
        }))
    if not acceptances:
        return 0
    verified = _verified_manifest_map(manifests, public_key)
    derived = 0
    for seq, acceptance in acceptances:
        manifest = verified.get(acceptance["manifest_hash"])
        if manifest is None:
            raise VerificationError(
                f"unbound manifest_accepted detail at sequence {seq}: "
                "manifest_hash matches no verified manifest; "
                "forged acceptance for a nonexistent manifest is rejected"
            )
        if (
            manifest.get("release_id") != acceptance["release_id"]
            or manifest.get("release_seq") != acceptance["release_seq"]
        ):
            raise VerificationError(
                f"manifest_accepted detail at sequence {seq}: "
                "release identity does not match the bound manifest; "
                "an acceptance cannot be rebound to a different release"
            )
        derived = max(derived, acceptance["release_seq"])
    return derived


def create_anchor_payload(
    journal: Path,
    *,
    start_seq: int,
    prev_txid: str = ZERO_TXID,
    manifests: Any = None,
    public_key: Any = None,
) -> dict[str, Any]:
    """Create an unsigned anchor payload from a verified local journal.

    The anchored ``release_seq`` is derived from the journal itself:
    ``max(release_seq)`` over bound ``manifest_accepted`` events with
    ``seq <= end_seq`` (``0`` when the journal contains no acceptance,
    meaning "no release adopted"). It is never taken from the caller, so a
    publisher cannot anchor an arbitrary checkpoint value.

    Binding (issue #11): when the covered range contains any acceptance,
    ``manifests`` (the signed manifest envelopes to check acceptances
    against) and ``public_key`` (the trusted manifest-signing key) are
    required. Each acceptance's ``manifest_hash`` must match a manifest
    whose signature verifies, with matching release identity; otherwise
    anchoring fails closed. Journals with no acceptance need neither.

    This only prepares commitment bytes. It does not sign, broadcast, or prove
    inclusion of a Bitcoin SV transaction.
    """
    if journal.is_symlink() or not journal.exists() or not journal.is_file():
        raise VerificationError("journal must exist as a regular non-symlink file")
    events = _read_jsonl(journal)
    _verify_audit_events(events)
    end_seq = len(events)
    start_seq = _uint32(start_seq, "start_seq")
    if end_seq < 1:
        raise VerificationError("cannot anchor an empty journal")
    if start_seq < 1 or start_seq > end_seq:
        raise VerificationError("start_seq must identify an event in the journal")
    if end_seq > UINT32_MAX:
        raise VerificationError("journal sequence exceeds the protocol's uint32 limit")
    release_seq = _derive_release_seq(events, end_seq, manifests, public_key)
    head_hash = events[end_seq - 1]["event_hash"].lower()
    payload = encode_anchor_payload(
        head_hash=head_hash,
        start_seq=start_seq,
        end_seq=end_seq,
        release_seq=release_seq,
        prev_txid=prev_txid,
    )
    return decode_anchor_payload(payload)


def verify_journal_against_anchor(
    journal: Path,
    payload: bytes,
    manifests: Any = None,
    public_key: Any = None,
) -> dict[str, Any]:
    """Check that a local journal contains the head committed by an anchor payload.

    Always verifies the hash chain and that the event hash at the
    anchored end sequence matches the payload's head hash, and detects a
    missing or shortened journal.

    When ``manifests`` and ``public_key`` are both supplied, additionally
    re-derives the anchored ``release_seq`` from bound acceptances (same
    fail-closed binding rules as creation) and requires it to equal the
    payload's ``release_seq``. When either is omitted, the payload's
    ``release_seq`` is returned as committed, without re-derivation —
    the head-hash check alone does not prove the checkpoint was honestly
    derived. Verifiers that need the full binding check must supply both.
    """
    fields = decode_anchor_payload(payload)
    if journal.is_symlink() or not journal.exists() or not journal.is_file():
        raise VerificationError("journal missing or not a regular non-symlink file")
    events = _read_jsonl(journal)
    _verify_audit_events(events)
    end_seq = fields["end_seq"]
    if len(events) < end_seq:
        raise VerificationError(
            f"journal truncation detected: anchor covers sequence {end_seq}, "
            f"journal has only {len(events)} event(s)"
        )
    actual_head = events[end_seq - 1]["event_hash"].lower()
    if actual_head != fields["head_hash"].lower():
        raise VerificationError(
            f"journal does not match anchor at sequence {end_seq}"
        )
    if (manifests is None) != (public_key is None):
        raise VerificationError(
            "manifests and public_key must be supplied together for "
            "binding re-verification"
        )
    if manifests is not None:
        rederived = _derive_release_seq(events, end_seq, manifests, public_key)
        if rederived != fields["release_seq"]:
            raise VerificationError(
                f"anchor release_seq {fields['release_seq']} does not match "
                f"the journal-derived bound release_seq {rederived}"
            )
    return {
        "verified": True,
        "anchored_start_seq": fields["start_seq"],
        "anchored_end_seq": end_seq,
        "anchored_release_seq": fields["release_seq"],
        "journal_events": len(events),
        "head_hash": actual_head,
        "prev_txid": fields["prev_txid"].lower(),
        "chain_inclusion_verified": False,
        # Whether the anchored release_seq was re-derived from bound
        # acceptances (True) or returned as committed without
        # re-derivation (False). Callers that need the full binding
        # check must look for True here, not just "verified".
        "release_seq_rederived": manifests is not None,
    }


def _normalize_chain_anchor(entry: Any, index: int) -> dict[str, Any]:
    """Validate one anchor-chain entry and return its txid + decoded fields.

    Accepted shapes (both carry the anchor's own txid, which is what the
    *next* anchor's ``prev_txid`` must equal):

    - ``{"payload": bytes, "txid": str}`` / ``{"payload_hex": str, "txid": str}``
    - ``(payload_bytes, txid)`` / ``(payload_hex, txid)`` tuples

    Publisher anchor records (``payload_hex`` + ``txid`` + ``status`` ...)
    pass through directly; callers filter to the records that belong in
    the chain (e.g. ``status == "broadcast"``) before calling.
    """
    if isinstance(entry, (tuple, list)):
        if len(entry) != 2:
            raise VerificationError(
                f"anchor {index}: tuple entry must be (payload, txid)"
            )
        payload_value, txid_value = entry
    elif isinstance(entry, dict):
        txid_value = entry.get("txid")
        if "payload" in entry:
            payload_value = entry["payload"]
        elif "payload_hex" in entry:
            payload_value = entry["payload_hex"]
        else:
            raise VerificationError(
                f"anchor {index}: entry must carry a payload or payload_hex"
            )
    else:
        raise VerificationError(
            f"anchor {index}: entry must be a dict or (payload, txid) tuple"
        )
    if not isinstance(txid_value, str) or not HEX_64.fullmatch(txid_value):
        raise VerificationError(
            f"anchor {index}: txid must be 64 hexadecimal characters"
        )
    txid = txid_value.lower()
    if isinstance(payload_value, (bytes, bytearray)):
        payload = bytes(payload_value)
    elif isinstance(payload_value, str):
        try:
            payload = bytes.fromhex(payload_value)
        except ValueError as exc:
            raise VerificationError(
                f"anchor {index}: payload_hex is not valid hexadecimal"
            ) from exc
    else:
        raise VerificationError(
            f"anchor {index}: payload must be bytes or a hex string"
        )
    fields = decode_anchor_payload(payload)
    return {"txid": txid, "payload": payload, "fields": fields}


def verify_anchor_chain(anchors: Any, genesis_txid: Any) -> dict[str, Any]:
    """Verify that anchors form one continuous, fork-free chain from genesis.

    ``anchors`` is an ordered list of entries (see
    :func:`_normalize_chain_anchor`); order matters — a reordered list is
    rejected, not silently re-sorted. ``genesis_txid`` is the trusted
    genesis anchor txid from operator-pinned config (out-of-band). It is
    never inferred from the anchor set: passing the txid of an anchor in
    the set as genesis is rejected, and a missing/invalid genesis fails
    closed.

    Enforced, fail-closed:

    - First anchor's ``prev_txid`` equals the trusted genesis (an
      arbitrary well-formed ``prev_txid`` is rejected).
    - First anchor's ``start_seq`` is 1 (protocol §3: the genesis anchor
      starts at sequence 1).
    - Each later anchor's ``prev_txid`` equals the previous anchor's
      txid (no skipped anchors, no reordering).
    - Each later anchor's ``start_seq`` equals the previous anchor's
      ``end_seq + 1`` (no gaps, no overlaps).
    - Each anchor's ``release_seq`` is >= the previous anchor's
      (release checkpoints are non-decreasing across anchors).
    - No duplicated txid, no duplicated payload.
    - No fork: no two anchors build on the same predecessor (no
      ``prev_txid`` appears twice), including two anchors both claiming
      genesis. A fork is reported as an error, never silently accepted.

    What this does NOT prove: that any anchor is really on-chain. This
    is continuity of the *claimed* chain — inclusion in a mined block
    is a separate check, available via ``sealrun.spv`` (``--spv`` on
    ``anchor-chain-verify``), which recomputes the Merkle root from the
    claimed block's tx list and checks the header hash + proof-of-work.

    An empty anchor list verifies vacuously (``anchor_count`` 0):
    nothing was checked. Callers that expect anchors must check
    ``anchor_count`` themselves.
    """
    if not isinstance(genesis_txid, str) or not HEX_64.fullmatch(genesis_txid):
        raise VerificationError(
            "genesis_txid must be supplied as 64 hexadecimal characters: "
            "it comes from operator-pinned config, never from the anchor set"
        )
    genesis = genesis_txid.lower()
    if not isinstance(anchors, (list, tuple)):
        raise VerificationError("anchors must be a list of anchor entries")
    normalized = [
        _normalize_chain_anchor(entry, index)
        for index, entry in enumerate(anchors)
    ]
    if not normalized:
        return {
            "verified": True,
            "anchor_count": 0,
            "genesis_txid": genesis,
            "first_seq": None,
            "last_seq": None,
            "last_txid": None,
            "last_release_seq": None,
            "anchors": [],
        }
    seen_txids: set[str] = set()
    seen_payloads: set[str] = set()
    seen_prev: set[str] = set()
    for index, anchor in enumerate(normalized):
        if anchor["txid"] in seen_txids:
            raise VerificationError(
                f"duplicate anchor txid at position {index}: {anchor['txid']}"
            )
        seen_txids.add(anchor["txid"])
        payload_hex = anchor["payload"].hex()
        if payload_hex in seen_payloads:
            raise VerificationError(
                f"duplicate anchor payload at position {index}: "
                "the same checkpoint anchored twice is rejected"
            )
        seen_payloads.add(payload_hex)
        if anchor["txid"] == genesis:
            raise VerificationError(
                "genesis txid must be external to the chain: it matches the "
                f"txid of the anchor at position {index}; genesis comes from "
                "operator-pinned config, never from the anchor set"
            )
        prev = anchor["fields"]["prev_txid"]
        if prev in seen_prev:
            raise VerificationError(
                f"fork detected: two anchors build on predecessor {prev} "
                f"(second at position {index}); a fork is reported, "
                "never silently accepted"
            )
        seen_prev.add(prev)
    first = normalized[0]["fields"]
    if first["prev_txid"] != genesis:
        raise VerificationError(
            f"first anchor prev_txid {first['prev_txid']} does not match "
            f"trusted genesis {genesis}: arbitrary prev_txid rejected"
        )
    if first["start_seq"] != 1:
        raise VerificationError(
            f"first anchor start_seq is {first['start_seq']}, expected 1: "
            "the genesis anchor must start at sequence 1 (protocol §3)"
        )
    for index in range(1, len(normalized)):
        previous = normalized[index - 1]
        fields = normalized[index]["fields"]
        if fields["prev_txid"] != previous["txid"]:
            raise VerificationError(
                f"anchor {index} prev_txid {fields['prev_txid']} does not "
                f"match previous anchor txid {previous['txid']}: "
                "chain linkage broken (skipped or reordered anchor)"
            )
        if fields["start_seq"] != previous["fields"]["end_seq"] + 1:
            raise VerificationError(
                f"anchor {index} start_seq {fields['start_seq']} does not "
                f"follow previous end_seq {previous['fields']['end_seq']}: "
                "sequence gap or overlap"
            )
        if fields["release_seq"] < previous["fields"]["release_seq"]:
            raise VerificationError(
                f"anchor {index} release_seq {fields['release_seq']} is "
                f"below previous anchor release_seq "
                f"{previous['fields']['release_seq']}: release checkpoints "
                "must be non-decreasing across anchors"
            )
    last = normalized[-1]
    return {
        "verified": True,
        "anchor_count": len(normalized),
        "genesis_txid": genesis,
        "first_seq": normalized[0]["fields"]["start_seq"],
        "last_seq": last["fields"]["end_seq"],
        "last_txid": last["txid"],
        "last_release_seq": last["fields"]["release_seq"],
        "anchors": [
            {
                "txid": anchor["txid"],
                "payload_hex": anchor["payload"].hex(),
                "head_hash": anchor["fields"]["head_hash"],
                "start_seq": anchor["fields"]["start_seq"],
                "end_seq": anchor["fields"]["end_seq"],
                "release_seq": anchor["fields"]["release_seq"],
                "prev_txid": anchor["fields"]["prev_txid"],
            }
            for anchor in normalized
        ],
    }


def verify_journal_against_anchor_chain(
    journal: Path,
    anchors: Any,
    genesis_txid: Any,
    manifests: Any = None,
    public_key: Any = None,
) -> dict[str, Any]:
    """Verify a journal against a full anchor chain, not one anchor alone.

    First enforces chain continuity via :func:`verify_anchor_chain`
    (genesis, linkage, contiguity, fork-free), then checks the journal
    against *each* anchor's payload (head hash at its ``end_seq``, plus
    binding re-derivation when manifests + public key are supplied).

    The chain check runs first on purpose: a set of anchors that each
    match the journal individually can still be a broken chain (wrong
    genesis, gap, fork), and that must fail verification, not warn.

    The result carries ``unanchored_events``: journal events after the
    last anchor's ``end_seq`` (0 when the chain covers the whole
    journal). A non-zero tail is legitimate between anchors; it is
    reported so callers can see it, not treated as failure.
    """
    chain = verify_anchor_chain(anchors, genesis_txid)
    per_anchor = [
        verify_journal_against_anchor(
            journal,
            bytes.fromhex(summary["payload_hex"]),
            manifests,
            public_key,
        )
        for summary in chain["anchors"]
    ]
    if per_anchor:
        # Last anchor's end_seq vs total journal events: events after the
        # last anchor exist legitimately between anchors, but the caller
        # must be able to see the unanchored tail, not infer it.
        unanchored = per_anchor[-1]["journal_events"] - chain["last_seq"]
    else:
        # No anchors: every journal event is unanchored.
        unanchored = len(_read_jsonl(journal))
    return {
        "verified": True,
        "chain": chain,
        "anchors": per_anchor,
        "chain_inclusion_verified": False,
        "unanchored_events": unanchored,
    }


# ---------------------------------------------------------------------------
# Anchor input signature verification (protocol §6, step 1)
# ---------------------------------------------------------------------------

from dataclasses import dataclass as _dataclass  # local: keep top imports stable
from typing import Protocol as _Protocol

from .bsv import (
    SIGHASH_ALL_FORKID,
    Tx,
    TxIn,
    TxOut,
    build_p2pkh_script,
    sats_from_btc_decimal,
    sighash_forkid,
    verify_sig,
)


def parse_p2pkh_script_sig(script_sig: bytes) -> tuple[bytes, int, bytes]:
    """Parse a P2PKH scriptSig into (der_signature, sighash_byte, pubkey).

    Strict: exactly two pushes, ``<sig || sighash> <compressed pubkey>``,
    no trailing bytes. Raises :class:`VerificationError` on any
    deviation (non-P2PKH, truncated, extra pushes).
    """
    if not isinstance(script_sig, (bytes, bytearray)) or len(script_sig) < 2:
        raise VerificationError("scriptSig is empty or not bytes")
    script_sig = bytes(script_sig)
    n1 = script_sig[0]
    if n1 == 0 or n1 > 75 or 1 + n1 > len(script_sig):
        raise VerificationError("scriptSig first push is malformed")
    sig_push = script_sig[1 : 1 + n1]
    rest = script_sig[1 + n1 :]
    if len(rest) < 2:
        raise VerificationError("scriptSig is missing the pubkey push")
    n2 = rest[0]
    if n2 == 0 or n2 > 75 or 1 + n2 != len(rest):
        raise VerificationError("scriptSig pubkey push is malformed")
    pubkey = rest[1:]
    if len(sig_push) < 2:
        raise VerificationError("scriptSig signature push is empty")
    if len(pubkey) != 33 or pubkey[0] not in (0x02, 0x03):
        raise VerificationError("scriptSig pubkey is not a compressed pubkey")
    return sig_push[:-1], sig_push[-1], pubkey


def _tx_from_woc_json(tx_json: Any) -> Tx:
    """Build a :class:`Tx` from a WoC ``/tx/hash`` JSON body.

    Only the fields the sighash needs are used: version, locktime,
    inputs (prev txid/vout/scriptSig/sequence), outputs (value/script).
    Integer fields are range-checked here (version fits int32,
    locktime/sequence/prev_index fit uint32) so hostile fetcher data
    fails at parse time instead of escaping as struct.error from the
    sighash packing below.
    """
    if not isinstance(tx_json, dict):
        raise VerificationError("tx JSON must be an object")
    vin = tx_json.get("vin")
    vout = tx_json.get("vout")
    if not isinstance(vin, list) or not isinstance(vout, list):
        raise VerificationError("tx JSON must carry vin and vout lists")
    inputs = []
    for entry in vin:
        try:
            script_hex = entry["scriptSig"]["hex"]
            prev_index = int(entry["vout"])
            sequence = int(entry.get("sequence", 0xFFFFFFFF))
            if not 0 <= prev_index <= UINT32_MAX:
                raise VerificationError("tx JSON has an out-of-range prev_index")
            if not 0 <= sequence <= UINT32_MAX:
                raise VerificationError("tx JSON has an out-of-range sequence")
            inputs.append(
                TxIn(
                    entry["txid"],
                    prev_index,
                    bytes.fromhex(script_hex),
                    sequence,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, VerificationError):
                raise
            raise VerificationError("tx JSON has a malformed input") from exc
    outputs = []
    for entry in vout:
        try:
            value = sats_from_btc_decimal(entry["value"])
            outputs.append(TxOut(value, bytes.fromhex(entry["scriptPubKey"]["hex"])))
        except (KeyError, TypeError, ValueError) as exc:
            raise VerificationError("tx JSON has a malformed output") from exc
    try:
        version = int(tx_json.get("version", 1))
        locktime = int(tx_json.get("locktime", 0))
    except (TypeError, ValueError) as exc:
        raise VerificationError("tx JSON has a malformed version/locktime") from exc
    if not -(2**31) <= version <= 2**31 - 1:
        raise VerificationError("tx JSON has an out-of-range version")
    if not 0 <= locktime <= UINT32_MAX:
        raise VerificationError("tx JSON has an out-of-range locktime")
    return Tx(version=version, inputs=inputs, outputs=outputs, locktime=locktime)


def verify_anchor_tx_signature(
    tx_json: Any, prev_tx_json: Any, anchor_pubkey_hex: str
) -> dict[str, Any]:
    """Check an anchor tx's single input against the trusted anchor pubkey.

    Fail-closed: every malformed input returns ``verified=False`` with a
    reason, never raises. Checked, in order:

    - The trusted pubkey is a well-formed compressed pubkey.
    - The anchor tx has exactly one input (anchor txs are 1-input).
    - The input's scriptSig parses as P2PKH with sighash
      ``SIGHASH_ALL | FORKID`` (``0x41``).
    - The scriptSig pubkey equals the trusted anchor pubkey.
    - The spent output's locking script is P2PKH to that pubkey.
    - The ECDSA signature verifies against the BIP 143 FORKID sighash
      computed from the tx, the spent script, and the spent value.
    """
    fail = lambda reason: {
        "verified": False,
        "reason": reason,
        "pubkey": None,
    }
    if not isinstance(anchor_pubkey_hex, str):
        return fail("trusted anchor pubkey must be a hex string")
    trusted = anchor_pubkey_hex.lower()
    if (
        len(trusted) != 66
        or not all(c in "0123456789abcdef" for c in trusted)
        or trusted[:2] not in ("02", "03")
    ):
        return fail("trusted anchor pubkey must be a 66-char compressed pubkey")
    try:
        tx = _tx_from_woc_json(tx_json)
    except VerificationError as exc:
        return fail(f"anchor tx malformed: {exc}")
    if len(tx.inputs) != 1:
        return fail(
            f"anchor tx must have exactly 1 input, has {len(tx.inputs)}"
        )
    txin = tx.inputs[0]
    try:
        der_sig, sighash_byte, pubkey = parse_p2pkh_script_sig(txin.script_sig)
    except VerificationError as exc:
        return fail(f"scriptSig is not a P2PKH input: {exc}")
    if sighash_byte != SIGHASH_ALL_FORKID:
        return fail(
            f"sighash byte is {sighash_byte:#x}, expected "
            f"SIGHASH_ALL|FORKID ({SIGHASH_ALL_FORKID:#x})"
        )
    if pubkey.hex() != trusted:
        return fail("scriptSig pubkey does not match the trusted anchor pubkey")
    if not isinstance(prev_tx_json, dict) or not isinstance(
        prev_tx_json.get("vout"), list
    ):
        return fail("previous tx JSON is malformed")
    if txin.prev_index < 0 or txin.prev_index >= len(prev_tx_json["vout"]):
        return fail(
            f"previous tx has no output {txin.prev_index}"
        )
    prev_out = prev_tx_json["vout"][txin.prev_index]
    try:
        prev_script = bytes.fromhex(prev_out["scriptPubKey"]["hex"])
        prev_value = sats_from_btc_decimal(prev_out["value"])
    except (KeyError, TypeError, ValueError):
        return fail("previous tx output is malformed")
    if prev_script != build_p2pkh_script(pubkey):
        return fail(
            "spent output is not P2PKH to the anchor pubkey"
        )
    try:
        digest = sighash_forkid(tx, 0, prev_script, prev_value)
        sig_ok = verify_sig(pubkey, digest, der_sig)
    except (VerificationError, struct.error, ValueError, IndexError,
            AttributeError, KeyError, TypeError, OverflowError) as exc:
        return fail(f"sighash or signature check failed: {exc}")
    if not sig_ok:
        return fail("ECDSA signature does not verify against the sighash")
    return {
        "verified": True,
        "reason": "input signed by the trusted anchor pubkey",
        "pubkey": trusted,
    }


@_dataclass(frozen=True)
class SignatureResult:
    verified: bool
    txid: str
    reason: str = ""
    pubkey: str | None = None


class AnchorTxFetcher(_Protocol):
    """Supplies full tx JSON for signature checks."""

    def fetch_tx_full(self, txid: str) -> dict:
        """Return the WoC ``/tx/hash`` JSON body for ``txid``."""
        ...


class AnchorSignatureVerifier:
    """Verify anchor tx inputs are signed by the trusted anchor pubkey.

    Fail-closed: a fetch failure or a malformed tx yields
    ``verified=False`` with a reason, never an exception.
    """

    def __init__(self, fetcher: AnchorTxFetcher, anchor_pubkey_hex: str) -> None:
        self.fetcher = fetcher
        self.anchor_pubkey_hex = anchor_pubkey_hex

    def verify_signature(self, txid: str) -> SignatureResult:
        txid = txid.lower()
        try:
            tx_json = self.fetcher.fetch_tx_full(txid)
        except Exception as exc:  # fetcher maps its own errors; stay closed
            return SignatureResult(False, txid, reason=f"fetch failed: {exc}")
        try:
            tx = _tx_from_woc_json(tx_json)
        except VerificationError as exc:
            return SignatureResult(
                False, txid, reason=f"anchor tx malformed: {exc}"
            )
        try:
            computed = tx.txid()
        except (VerificationError, struct.error, ValueError, IndexError,
                AttributeError, KeyError, TypeError, OverflowError) as exc:
            return SignatureResult(
                False, txid, reason=f"anchor tx malformed: {exc}"
            )
        if computed != txid:
            return SignatureResult(
                False, txid,
                reason="fetched anchor transaction ID does not match requested txid",
            )
        if len(tx.inputs) != 1:
            return SignatureResult(
                False, txid,
                reason=f"anchor tx must have exactly 1 input, has {len(tx.inputs)}",
            )
        try:
            prev_json = self.fetcher.fetch_tx_full(tx.inputs[0].prev_txid)
        except Exception as exc:
            return SignatureResult(False, txid, reason=f"fetch failed: {exc}")
        try:
            checked = verify_anchor_tx_signature(
                tx_json, prev_json, self.anchor_pubkey_hex
            )
        except (VerificationError, struct.error, ValueError, IndexError,
                AttributeError, KeyError, TypeError, OverflowError) as exc:
            return SignatureResult(
                False, txid, reason=f"signature check failed: {exc}"
            )
        return SignatureResult(
            checked["verified"], txid,
            reason=checked["reason"], pubkey=checked["pubkey"],
        )


def apply_anchor_signatures(result: dict, verifier: AnchorSignatureVerifier) -> dict:
    """Attach per-anchor signature results to a chain-verify result.

    Handles both shapes: ``verify_anchor_chain`` (``result["anchors"]``)
    and ``verify_journal_against_anchor_chain`` (``result["chain"]``
    plus per-anchor journal entries). Returns a new dict; the input
    is not mutated. Top-level ``anchor_signatures_verified`` is True
    only when every anchor's input signature verifies.
    """
    if "chain" in result:
        chain = dict(result["chain"])
        summaries = chain.get("anchors", [])
        merged = []
        all_verified = True
        for summary in summaries:
            sig = verifier.verify_signature(summary["txid"])
            all_verified = all_verified and sig.verified
            merged.append(
                {
                    **summary,
                    "anchor_signature_verified": sig.verified,
                    "anchor_signature": {
                        "verified": sig.verified,
                        "reason": sig.reason,
                        "pubkey": sig.pubkey,
                    },
                }
            )
        chain["anchors"] = merged
        return {
            **result,
            "chain": chain,
            "anchor_signatures_verified": all_verified,
        }
    merged = []
    all_verified = True
    for summary in result.get("anchors", []):
        sig = verifier.verify_signature(summary["txid"])
        all_verified = all_verified and sig.verified
        merged.append(
            {
                **summary,
                "anchor_signature_verified": sig.verified,
                "anchor_signature": {
                    "verified": sig.verified,
                    "reason": sig.reason,
                    "pubkey": sig.pubkey,
                },
            }
        )
    return {
        **result,
        "anchors": merged,
        "anchor_signatures_verified": all_verified,
    }


def extract_anchor_op_return(tx_json: Any) -> bytes:
    """Extract the anchor payload from a fetched tx's OP_RETURN output.

    Parses WoC ``/tx/hash`` JSON ``vout`` entries, finds OP_RETURN
    outputs (script starting with ``0x6a``), and decodes the push
    (direct length byte, ``0x4c`` PUSHDATA1, ``0x4d`` PUSHDATA2 —
    mirroring :func:`bsv.build_op_return_script`). Anchor txs carry
    exactly one OP_RETURN output, so zero, multiple, or malformed
    OP_RETURN outputs all fail closed with VerificationError.
    """
    if not isinstance(tx_json, dict) or not isinstance(
        tx_json.get("vout"), list
    ):
        raise VerificationError("tx JSON must carry a vout list")
    payloads: list[bytes] = []
    for entry in tx_json["vout"]:
        try:
            script = bytes.fromhex(entry["scriptPubKey"]["hex"])
        except (KeyError, TypeError, ValueError) as exc:
            raise VerificationError("tx JSON has a malformed output") from exc
        if not script or script[0] != 0x6A:
            continue
        if len(script) < 2:
            raise VerificationError("OP_RETURN output is malformed: no push")
        opcode = script[1]
        if opcode <= 75:
            n = opcode
            start = 2
        elif opcode == 0x4C:  # PUSHDATA1
            if len(script) < 3:
                raise VerificationError("OP_RETURN PUSHDATA1 is truncated")
            n = script[2]
            start = 3
        elif opcode == 0x4D:  # PUSHDATA2
            if len(script) < 4:
                raise VerificationError("OP_RETURN PUSHDATA2 is truncated")
            n = int.from_bytes(script[2:4], "little")
            start = 4
        else:
            raise VerificationError(
                f"OP_RETURN uses unsupported push opcode {opcode:#x}"
            )
        if start + n != len(script):
            raise VerificationError(
                "OP_RETURN push length does not match the output script"
            )
        payloads.append(script[start : start + n])
    if not payloads:
        raise VerificationError("tx has no OP_RETURN output")
    if len(payloads) > 1:
        raise VerificationError(
            f"tx has {len(payloads)} OP_RETURN outputs, expected exactly one"
        )
    return payloads[0]


def apply_payload_binding(result: dict, fetcher: "AnchorTxFetcher") -> dict:
    """Attach per-anchor payload-binding results to a chain-verify result.

    For each anchor, fetch the on-chain tx and require its OP_RETURN
    output to equal the claimed payload. This closes the hole where a
    forged payload paired with a real txid verified: chain continuity,
    journal head, SPV/BUMP/BEEF inclusion, signature, and header-chain
    checks all look only at the txid, never at what the tx committed
    to. Fetch failures are fail-closed (``verified: False`` + reason),
    never an exception.

    Same two result shapes and non-mutating contract as
    :func:`apply_anchor_signatures`. Top-level
    ``payload_binding_verified`` is True only when every anchor binds.
    """
    def _binding_for(summary: dict) -> dict:
        txid = summary.get("txid", "")
        try:
            tx_json = fetcher.fetch_tx_full(txid)
        except Exception as exc:  # fetcher maps its own errors; stay closed
            return {
                "verified": False,
                "reason": f"fetch failed: {exc}",
            }
        try:
            actual = extract_anchor_op_return(tx_json)
            claimed = bytes.fromhex(summary.get("payload_hex", ""))
        except (VerificationError, ValueError, TypeError) as exc:
            return {
                "verified": False,
                "reason": f"OP_RETURN extraction failed: {exc}",
            }
        if actual != claimed:
            return {
                "verified": False,
                "reason": (
                    "OP_RETURN payload does not match claimed anchor payload: "
                    "the on-chain tx never committed to this payload"
                ),
            }
        return {
            "verified": True,
            "reason": "OP_RETURN payload matches claimed anchor payload",
        }

    if "chain" in result:
        chain = dict(result["chain"])
        summaries = chain.get("anchors", [])
        merged = []
        all_verified = True
        for summary in summaries:
            binding = _binding_for(summary)
            all_verified = all_verified and binding["verified"]
            merged.append(
                {
                    **summary,
                    "payload_binding_verified": binding["verified"],
                    "payload_binding": binding,
                }
            )
        chain["anchors"] = merged
        return {
            **result,
            "chain": chain,
            "payload_binding_verified": all_verified,
        }
    merged = []
    all_verified = True
    for summary in result.get("anchors", []):
        binding = _binding_for(summary)
        all_verified = all_verified and binding["verified"]
        merged.append(
            {
                **summary,
                "payload_binding_verified": binding["verified"],
                "payload_binding": binding,
            }
        )
    return {
        **result,
        "anchors": merged,
        "payload_binding_verified": all_verified,
    }


# ---------------------------------------------------------------------------
# Header-chain application (protocol §6: chain back to a pinned checkpoint)
# ---------------------------------------------------------------------------


def apply_header_chain(result: dict, verifier: Any) -> dict:
    """Attach per-anchor header-chain results to a chain-verify result.

    ``verifier`` must provide ``verify_chain_for_tx(txid)`` returning
    an object with ``verified``, ``tip_height``,
    ``checkpoint_height``, ``headers_checked`` and ``reason``
    (see ``sealrun.spv.HeaderChainVerifier``).

    Handles both shapes: ``verify_anchor_chain`` (``result["anchors"]``)
    and ``verify_journal_against_anchor_chain`` (``result["chain"]``
    plus per-anchor journal entries). Returns a new dict; the input
    is not mutated. Top-level ``header_chain_verified`` is True only
    when every anchor's block chains back to the checkpoint.
    """
    if "chain" in result:
        chain = dict(result["chain"])
        summaries = chain.get("anchors", [])
        merged = []
        all_verified = True
        for summary in summaries:
            chain_result = verifier.verify_chain_for_tx(summary["txid"])
            all_verified = all_verified and chain_result.verified
            merged.append(
                {
                    **summary,
                    "header_chain_verified": chain_result.verified,
                    "header_chain": {
                        "verified": chain_result.verified,
                        "tip_height": chain_result.tip_height,
                        "checkpoint_height": chain_result.checkpoint_height,
                        "headers_checked": chain_result.headers_checked,
                        "reason": chain_result.reason,
                    },
                }
            )
        chain["anchors"] = merged
        return {
            **result,
            "chain": chain,
            "header_chain_verified": all_verified,
        }
    merged = []
    all_verified = True
    for summary in result.get("anchors", []):
        chain_result = verifier.verify_chain_for_tx(summary["txid"])
        all_verified = all_verified and chain_result.verified
        merged.append(
            {
                **summary,
                "header_chain_verified": chain_result.verified,
                "header_chain": {
                    "verified": chain_result.verified,
                    "tip_height": chain_result.tip_height,
                    "checkpoint_height": chain_result.checkpoint_height,
                    "headers_checked": chain_result.headers_checked,
                    "reason": chain_result.reason,
                },
            }
        )
    return {
        **result,
        "anchors": merged,
        "header_chain_verified": all_verified,
    }
