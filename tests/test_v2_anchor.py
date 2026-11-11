"""Launch-flow v2 plan item 8: anchor-only acceptance (§6.5).

No signed pins, no ``pin_seq``, no pin store. An anchor authenticates a
journal only when payload binding, the anchor transaction signature,
real block inclusion (ancestry-only never counts), and a header walk to
a pinned checkpoint all hold. Freshness is never provided. Empty anchors
are "freshness unavailable", never "current". The two named verdicts are
reported separately; a single boolean is not completion.
"""

import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from sealrun.anchor import encode_anchor_payload, verify_journal_against_anchor_chain
from sealrun.bsv import Tx, TxIn, TxOut, build_op_return_script
from sealrun.cli import main
from sealrun.core import (
    V2_FINISH_EVENT_TYPE,
    V2_LAUNCH_EVENT_TYPE,
    V2_LAUNCH_FAILED_EVENT_TYPE,
    VerificationError,
    _read_jsonl,
    append_audit_event,
    append_v2_event,
    journal_genesis_identity,
    journal_genesis_identity_for_path,
    read_journal_prefix,
)
import sealrun.cli as cli_module
from sealrun.spv import (
    DAAParams,
    DEFAULT_MAX_HEADERS,
    HeaderChainResult,
    HeaderChainVerifier,
    InclusionResult,
    SPVUnavailable,
    verify_chain_to_checkpoint,
)
from sealrun.v2_anchor import (
    AUTHENTICATION_ACCEPTED,
    AUTHENTICATION_WITHHELD,
    VERDICT_PREFIX,
    VERDICT_TIP,
    evaluate_anchor_acceptance,
    verify_v2_anchor_chain,
)

GENESIS = "ab" * 32
PUBKEY = "02" + "11" * 32
CHECKPOINT_HASH = "22" * 32

IDENTITY = {
    "identity": "33" * 32,
    "genesis_hash": "44" * 32,
    "genesis_event_seq": 1,
    "genesis_nonce": "55" * 16,
    "genesis_nonce_seq": 2,
    "journal_events": 3,
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def launch_detail(run_id=None, nonce="a" * 32):
    return {
        "launch_mode": "v2",
        "run_id": run_id or str(uuid.uuid4()),
        "journal_nonce": nonce,
        "manifest_hash": "b" * 64,
        "artifact_count": 1,
        "argv_fingerprint": "c" * 64,
        "env_fingerprint": "d" * 64,
        "executable": "true",
        "cwd": "/tmp",
        "seal": False,
        "uid": 12345,
        "gid": 12345,
    }


def finish_detail(run_id=None):
    return {
        "launch_mode": "v2",
        "run_id": run_id or str(uuid.uuid4()),
        "exit_code": 0,
        "launcher_signal": 0,
        "escalated": False,
        "duration_ms": 1,
    }


def make_journal(path: Path, *, events: int = 3) -> Path:
    """A v2 journal: legacy genesis, v2 launch (nonce), then events."""
    append_audit_event(path, "test", "first")
    append_v2_event(path, V2_LAUNCH_EVENT_TYPE, launch_detail())
    for index in range(events - 2):
        append_audit_event(path, "test", f"event-{index}")
    return path


def synthetic_anchor(journal: Path, *, end_seq: int = 3):
    """Build an anchor payload plus a tx body whose OP_RETURN commits to it."""
    events, _fragment = read_journal_prefix(journal)
    payload = encode_anchor_payload(
        head_hash=events[end_seq - 1]["event_hash"],
        start_seq=1,
        end_seq=end_seq,
        release_seq=0,
        prev_txid=GENESIS,
    )
    script = build_op_return_script(payload)
    prev_txid = "cd" * 32
    tx = Tx(
        version=1,
        inputs=[TxIn(prev_txid, 0, b"", 0xFFFFFFFF)],
        outputs=[TxOut(0, script)],
        locktime=0,
    )
    txid = tx.txid()
    tx_json = {
        "version": 1,
        "locktime": 0,
        "vin": [
            {
                "txid": prev_txid,
                "vout": 0,
                "scriptSig": {"hex": ""},
                "sequence": 0xFFFFFFFF,
            }
        ],
        "vout": [
            {
                "value": "0.00000000",
                "scriptPubKey": {"hex": script.hex()},
            }
        ],
    }
    return {"payload": payload, "txid": txid}, tx_json


class FakePayloadFetcher:
    def __init__(self, by_txid):
        self.by_txid = by_txid

    def fetch_tx_full(self, txid):
        return self.by_txid[txid]


class FakeSignatureVerifier:
    def __init__(self, verified=True):
        self.verified = verified

    def verify_signature(self, txid):
        return SimpleNamespace(
            verified=self.verified,
            reason="fake signature",
            pubkey=PUBKEY,
        )


class FakeInclusionVerifier:
    def __init__(self, verified=True):
        self.verified = verified

    def verify_inclusion(self, txid):
        return InclusionResult(
            self.verified,
            txid,
            blockheight=10,
            blockhash="66" * 32,
            reason="fake inclusion",
        )


class FakeHeaderVerifier:
    def __init__(self, verified=True, reason="fake header chain"):
        self.verified = verified
        self.reason = reason

    def verify_chain_for_tx(self, txid):
        return HeaderChainResult(
            self.verified,
            txid,
            tip_height=10,
            checkpoint_height=1,
            headers_checked=1,
            reason=self.reason,
        )


def composed_result(
    *,
    payload=True,
    signature=True,
    inclusion=True,
    header=True,
    chain=True,
    count=1,
    last_seq=3,
    unanchored=0,
    beef_status="bump",
):
    summary = {
        "txid": "77" * 32,
        "payload_binding_verified": payload,
        "anchor_signature_verified": signature,
        "chain_inclusion_verified": inclusion,
        "bump_inclusion_verified": inclusion,
        "beef_inclusion_verified": inclusion,
        "beef_inclusion": {
            "verified": inclusion,
            "status": beef_status,
            "blockheight": 10 if beef_status == "bump" else None,
        },
        "header_chain_verified": header,
    }
    chain_result = {
        "verified": chain,
        "anchor_count": count,
        "last_seq": last_seq,
        "anchors": [dict(summary) for _ in range(count)],
    }
    return {
        "verified": chain,
        "chain": chain_result,
        "anchors": [{"verified": True} for _ in range(count)],
        "unanchored_events": unanchored,
        "payload_binding_verified": payload,
        "anchor_signatures_verified": signature,
        "chain_inclusion_verified": inclusion,
        "bump_inclusion_verified": inclusion,
        "beef_inclusion_verified": inclusion,
        "header_chain_verified": header,
    }


# --------------------------------------------------------------------------
# journal identity: genesis hash WITH a nonce, never the bare hash
# --------------------------------------------------------------------------

def test_identity_is_not_the_bare_genesis_hash(tmp_path):
    journal = make_journal(tmp_path / "journal.jsonl")
    identity = journal_genesis_identity_for_path(journal)
    events, _fragment = read_journal_prefix(journal)

    assert identity["genesis_hash"] == events[0]["event_hash"]
    assert identity["identity"] != identity["genesis_hash"]
    assert identity["genesis_nonce"] == "a" * 32
    assert identity["genesis_nonce_seq"] == 2


def test_two_journals_with_the_same_first_event_have_distinct_identities(
    tmp_path,
):
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    for path, nonce in ((first, "a" * 32), (second, "b" * 32)):
        append_audit_event(path, "test", "same first event")
        append_v2_event(path, V2_LAUNCH_EVENT_TYPE, launch_detail(nonce=nonce))

    one = journal_genesis_identity_for_path(first)
    two = journal_genesis_identity_for_path(second)
    assert one["genesis_hash"] == two["genesis_hash"]
    assert one["identity"] != two["identity"]


def test_journal_without_a_v2_nonce_has_no_v2_identity(tmp_path):
    legacy = tmp_path / "legacy.jsonl"
    append_audit_event(legacy, "test", "legacy only")
    with pytest.raises(VerificationError, match="no v2 event"):
        journal_genesis_identity_for_path(legacy)

    no_nonce = tmp_path / "no-nonce.jsonl"
    append_v2_event(no_nonce, V2_FINISH_EVENT_TYPE, finish_detail())
    with pytest.raises(VerificationError, match="no v2 event"):
        journal_genesis_identity_for_path(no_nonce)


def test_identity_uses_the_first_nonce_bearing_v2_event(tmp_path):
    """A refused launch records ``v2_launch_failed`` first, which carries
    no ``journal_nonce``. The identity must come from the first
    nonce-bearing v2 event — the later successful ``v2_launch`` — not
    refuse because the first v2 event lacks a nonce, and it must agree
    with :func:`sealrun.core.journal_has_genesis_nonce`, which counts any
    nonce-bearing v2 event.
    """
    journal = tmp_path / "failed-first.jsonl"
    append_audit_event(journal, "test", "first")
    append_v2_event(
        journal,
        V2_LAUNCH_FAILED_EVENT_TYPE,
        {
            "launch_mode": "v2",
            "run_id": str(uuid.uuid4()),
            "stage": "launch",
            "reason": "v2 launch requires --min-release-seq",
        },
    )
    append_v2_event(journal, V2_LAUNCH_EVENT_TYPE, launch_detail(nonce="e" * 32))

    identity = journal_genesis_identity_for_path(journal)
    events, _fragment = read_journal_prefix(journal)
    assert identity["genesis_hash"] == events[0]["event_hash"]
    assert identity["identity"] != identity["genesis_hash"]
    assert identity["genesis_nonce"] == "e" * 32
    assert identity["genesis_nonce_seq"] == 3
    assert identity["journal_events"] == 3

    # The in-memory helper returns the same identity for the same journal.
    assert journal_genesis_identity(events) == identity


def test_identity_empty_and_missing_journal_fail_closed(tmp_path):
    with pytest.raises(VerificationError, match="empty journal"):
        journal_genesis_identity([])
    with pytest.raises(VerificationError, match="missing or not a regular"):
        journal_genesis_identity_for_path(tmp_path / "absent.jsonl")


def test_identity_fails_on_a_tampered_event(tmp_path):
    journal = make_journal(tmp_path / "journal.jsonl")
    events = _read_jsonl(journal)
    events[0]["detail"] = "tampered"
    journal.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )
    with pytest.raises(VerificationError, match="hash mismatch"):
        journal_genesis_identity_for_path(journal)


# --------------------------------------------------------------------------
# the four-part acceptance predicate
# --------------------------------------------------------------------------

def test_full_predicate_is_accepted_with_two_named_verdicts():
    result = evaluate_anchor_acceptance(
        composed_result(),
        inclusion="spv",
        journal_identity=IDENTITY,
    )

    assert result["authentication"] == AUTHENTICATION_ACCEPTED
    assert result["accepted"] is True
    assert result["authenticated_prefix_end"] == 3
    assert result["prefix_matches_anchor"] is True
    assert result["tip_inside_anchor"] is True
    assert result["freshness"] == "unavailable"
    assert result["freshness_available"] is False
    assert result["predicate"] == {
        "journal_chain": True,
        "payload_binding": True,
        "anchor_signature": True,
        "inclusion": True,
        "header_chain": True,
        "journal_identity": True,
    }
    assert result["verdicts"] == [
        {"name": VERDICT_PREFIX, "verified": True},
        {"name": VERDICT_TIP, "verified": True},
    ]


@pytest.mark.parametrize(
    "missing, reason_fragment",
    [
        ("payload", "payload binding"),
        ("signature", "transaction signature"),
        ("inclusion", "block inclusion"),
        ("header", "header chain"),
        ("chain", "chain continuity"),
    ],
)
def test_removing_any_single_predicate_withholds_authentication(
    missing, reason_fragment
):
    result = evaluate_anchor_acceptance(
        composed_result(**{missing: False}),
        inclusion="spv",
        journal_identity=IDENTITY,
    )

    assert result["authentication"] == AUTHENTICATION_WITHHELD
    assert result["accepted"] is False
    assert result["prefix_matches_anchor"] is False
    assert result["tip_inside_anchor"] is False
    assert result["authenticated_prefix_end"] is None
    assert any(reason_fragment in reason for reason in result["reasons"])


def test_empty_anchor_list_is_freshness_unavailable_never_current():
    result = evaluate_anchor_acceptance(
        composed_result(payload=True, signature=True, inclusion=True,
                        header=True, chain=True, count=0),
        inclusion="spv",
        journal_identity=IDENTITY,
    )

    assert result["authentication"] == AUTHENTICATION_WITHHELD
    assert result["accepted"] is False
    assert result["anchor_count"] == 0
    assert result["prefix_matches_anchor"] is False
    assert result["tip_inside_anchor"] is False
    assert result["authenticated_prefix_end"] is None
    assert result["freshness"] == "unavailable"
    assert result["freshness_available"] is False
    assert any("no anchors" in reason for reason in result["reasons"])


def test_prefix_can_match_while_the_tip_stays_outside_the_anchor():
    result = evaluate_anchor_acceptance(
        composed_result(unanchored=2),
        inclusion="spv",
        journal_identity=IDENTITY,
    )

    assert result["prefix_matches_anchor"] is True
    assert result["tip_inside_anchor"] is False
    assert result["authenticated_prefix_end"] == 3


def test_missing_per_anchor_results_withhold_authentication():
    result = composed_result(count=2)
    result["chain"]["anchors"] = result["chain"]["anchors"][:1]

    acceptance = evaluate_anchor_acceptance(
        result, inclusion="spv", journal_identity=IDENTITY
    )

    assert acceptance["accepted"] is False
    assert any(
        "do not cover" in reason for reason in acceptance["reasons"]
    )


def test_ancestry_only_beef_never_counts_as_inclusion():
    result = evaluate_anchor_acceptance(
        composed_result(beef_status="ancestry"),
        inclusion="beef",
        journal_identity=IDENTITY,
    )

    assert result["predicate"]["inclusion"] is False
    assert result["authentication"] == AUTHENTICATION_WITHHELD
    assert result["prefix_matches_anchor"] is False


def test_mined_beef_status_counts_as_inclusion():
    result = evaluate_anchor_acceptance(
        composed_result(beef_status="bump"),
        inclusion="beef",
        journal_identity=IDENTITY,
    )

    assert result["predicate"]["inclusion"] is True
    assert result["accepted"] is True


def test_unknown_inclusion_method_is_refused():
    with pytest.raises(VerificationError, match="unknown inclusion method"):
        evaluate_anchor_acceptance(composed_result(), inclusion="header")


def test_terminal_outside_the_authenticated_prefix_is_reported():
    result = evaluate_anchor_acceptance(
        composed_result(last_seq=3),
        inclusion="spv",
        terminal_seq=4,
        journal_identity=IDENTITY,
    )

    assert result["terminal_inside_anchor"] is False
    assert any("outside the authenticated" in r for r in result["reasons"])


def test_expected_identity_mismatch_withholds_authentication():
    result = evaluate_anchor_acceptance(
        composed_result(),
        inclusion="spv",
        journal_identity=IDENTITY,
        expected_journal_identity="99" * 32,
    )

    assert result["predicate"]["journal_identity"] is False
    assert result["authentication"] == AUTHENTICATION_WITHHELD
    assert any("does not match" in reason for reason in result["reasons"])


def test_bare_genesis_hash_is_not_a_valid_identity():
    result = evaluate_anchor_acceptance(
        composed_result(),
        inclusion="spv",
        journal_identity={"identity": IDENTITY["genesis_hash"]},
    )

    assert result["predicate"]["journal_identity"] is False
    assert result["authentication"] == AUTHENTICATION_WITHHELD


# --------------------------------------------------------------------------
# wrapper: empty anchors must still verify the journal, not return current
# --------------------------------------------------------------------------

def test_wrapper_empty_anchors_reports_withheld_freshness(tmp_path):
    journal = make_journal(tmp_path / "journal.jsonl")
    result = verify_journal_against_anchor_chain(journal, [], GENESIS)

    assert result["verified"] is False
    assert result["chain"]["anchor_count"] == 0
    assert result["freshness"] == "unavailable"
    assert result["freshness_available"] is False
    assert result["prefix_matches_anchor"] is False
    assert result["tip_inside_anchor"] is False
    assert result["unanchored_events"] == 3


def test_wrapper_empty_anchors_still_rejects_a_tampered_journal(tmp_path):
    journal = make_journal(tmp_path / "journal.jsonl")
    events = _read_jsonl(journal)
    events[1]["detail"] = '{"tampered":true}'
    journal.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )

    with pytest.raises(VerificationError, match="hash mismatch"):
        verify_journal_against_anchor_chain(journal, [], GENESIS)


def test_wrapper_missing_journal_raises_verification_error(tmp_path):
    missing = tmp_path / "absent.jsonl"

    with pytest.raises(VerificationError, match="missing or not a regular"):
        verify_journal_against_anchor_chain(missing, [], GENESIS)


# --------------------------------------------------------------------------
# full composition: all four checks + identity
# --------------------------------------------------------------------------

def _verify(journal, anchors, tx_json, **kwargs):
    defaults = {
        "payload_fetcher": FakePayloadFetcher(
            {anchors[0]["txid"]: tx_json}
        )
        if anchors
        else FakePayloadFetcher({}),
        "signature_verifier": FakeSignatureVerifier(),
        "inclusion": "spv",
        "inclusion_verifier": FakeInclusionVerifier(),
        "header_verifier": FakeHeaderVerifier(),
    }
    defaults.update(kwargs)
    return verify_v2_anchor_chain(
        journal, anchors, GENESIS, **defaults
    )


def test_verify_v2_accepts_a_fully_checked_anchor(tmp_path):
    journal = make_journal(tmp_path / "journal.jsonl")
    anchor, tx_json = synthetic_anchor(journal)

    result = _verify(journal, [anchor], tx_json)
    acceptance = result["acceptance"]

    assert acceptance["authentication"] == AUTHENTICATION_ACCEPTED
    assert acceptance["prefix_matches_anchor"] is True
    assert acceptance["tip_inside_anchor"] is True
    assert acceptance["authenticated_prefix_end"] == 3
    assert acceptance["freshness"] == "unavailable"
    assert acceptance["journal_identity"]["identity"] == result["journal_identity"]["identity"]
    assert result["journal_identity"]["genesis_nonce"] == "a" * 32


def test_verify_v2_withholds_when_payload_binding_fails(tmp_path):
    journal = make_journal(tmp_path / "journal.jsonl")
    anchor, tx_json = synthetic_anchor(journal)
    # Same claimed anchor txid, but serve a tx that hashes differently.
    _wrong_anchor, wrong_tx = synthetic_anchor(
        make_journal(tmp_path / "other.jsonl")
    )

    result = _verify(
        journal,
        [anchor],
        wrong_tx,
        payload_fetcher=FakePayloadFetcher({anchor["txid"]: wrong_tx}),
    )

    assert result["acceptance"]["accepted"] is False
    assert result["acceptance"]["predicate"]["payload_binding"] is False
    assert any(
        "payload binding" in reason
        for reason in result["acceptance"]["reasons"]
    )


def test_verify_v2_withholds_when_signature_fails(tmp_path):
    journal = make_journal(tmp_path / "journal.jsonl")
    anchor, tx_json = synthetic_anchor(journal)

    result = _verify(
        journal,
        [anchor],
        tx_json,
        signature_verifier=FakeSignatureVerifier(False),
    )

    assert result["acceptance"]["accepted"] is False
    assert result["acceptance"]["predicate"]["anchor_signature"] is False


def test_verify_v2_withholds_when_inclusion_fails(tmp_path):
    journal = make_journal(tmp_path / "journal.jsonl")
    anchor, tx_json = synthetic_anchor(journal)

    result = _verify(
        journal,
        [anchor],
        tx_json,
        inclusion_verifier=FakeInclusionVerifier(False),
    )

    assert result["acceptance"]["accepted"] is False
    assert result["acceptance"]["predicate"]["inclusion"] is False


def test_verify_v2_withholds_when_checkpoint_is_above_the_anchor(tmp_path):
    journal = make_journal(tmp_path / "journal.jsonl")
    anchor, tx_json = synthetic_anchor(journal)

    result = _verify(
        journal,
        [anchor],
        tx_json,
        header_verifier=FakeHeaderVerifier(
            False, reason="checkpoint is above the tip block"
        ),
    )

    assert result["acceptance"]["accepted"] is False
    assert result["acceptance"]["predicate"]["header_chain"] is False
    assert result["acceptance"]["prefix_matches_anchor"] is False
    assert any(
        "header chain" in reason
        for reason in result["acceptance"]["reasons"]
    )


def test_verify_v2_empty_anchors_is_withheld_not_current(tmp_path):
    journal = make_journal(tmp_path / "journal.jsonl")

    result = verify_v2_anchor_chain(
        journal,
        [],
        GENESIS,
        payload_fetcher=FakePayloadFetcher({}),
        signature_verifier=FakeSignatureVerifier(),
        inclusion="spv",
        inclusion_verifier=FakeInclusionVerifier(),
        header_verifier=FakeHeaderVerifier(),
    )

    assert result["acceptance"]["accepted"] is False
    assert result["acceptance"]["prefix_matches_anchor"] is False
    assert result["acceptance"]["tip_inside_anchor"] is False
    assert result["acceptance"]["freshness"] == "unavailable"
    assert result["acceptance"]["freshness_available"] is False


def test_verify_v2_requires_a_journal_identity(tmp_path):
    journal = tmp_path / "legacy.jsonl"
    append_audit_event(journal, "test", "legacy only")

    with pytest.raises(VerificationError, match="no v2 event"):
        verify_v2_anchor_chain(
            journal,
            [],
            GENESIS,
            payload_fetcher=FakePayloadFetcher({}),
            signature_verifier=FakeSignatureVerifier(),
            inclusion="spv",
            inclusion_verifier=FakeInclusionVerifier(),
            header_verifier=FakeHeaderVerifier(),
        )


# --------------------------------------------------------------------------
# header-chain cap and walk origin
# --------------------------------------------------------------------------

class _RefusingHeaderFetcher:
    """The cap check must run before any header is fetched."""

    def fetch_header(self, height):
        raise SPVUnavailable("no headers served")


def _cap_result(walk_len, *, daa=False):
    tip = 600000 if daa else 10000
    checkpoint = tip - (walk_len - 1)
    return verify_chain_to_checkpoint(
        _RefusingHeaderFetcher(),
        tip_height=tip,
        tip_hash="88" * 32,
        checkpoint_hash="99" * 32,
        checkpoint_height=checkpoint,
        daa=DAAParams.mainnet() if daa else None,
    )


def test_default_header_cap_is_4032():
    assert DEFAULT_MAX_HEADERS == 4032


def test_walk_of_4033_is_refused_before_fetching():
    verified, checked, reason = _cap_result(4033)
    assert verified is False
    assert checked == 0
    assert "exceeds cap" in reason


def test_walk_of_4032_is_not_a_cap_failure():
    verified, checked, reason = _cap_result(4032)
    assert verified is False
    assert "exceeds cap" not in reason
    assert "fetch failed" in reason


def test_walk_of_3887_with_daa_is_refused():
    verified, checked, reason = _cap_result(3887, daa=True)
    assert verified is False
    assert checked == 0
    assert "exceeds cap" in reason


def test_walk_of_3886_with_daa_is_not_a_cap_failure():
    verified, checked, reason = _cap_result(3886, daa=True)
    assert verified is False
    assert "exceeds cap" not in reason
    assert "fetch failed" in reason


class _RecordingHeaderFetcher:
    def __init__(self):
        self.heights = []

    def fetch_tx(self, txid):
        return {"blockheight": 150, "blockhash": "aa" * 32}

    def fetch_header(self, height):
        self.heights.append(height)
        raise SPVUnavailable("stop after recording the first height")


def test_walk_starts_at_the_anchor_block_not_the_tip():
    fetcher = _RecordingHeaderFetcher()
    verifier = HeaderChainVerifier(
        fetcher,
        checkpoint_hash="bb" * 32,
        checkpoint_height=100,
    )
    result = verifier.verify_chain_for_tx("cc" * 32)

    assert result.verified is False
    assert fetcher.heights[0] == 150


class _AnchorAtHeightFetcher:
    def fetch_tx(self, txid):
        return {"blockheight": 100, "blockhash": "dd" * 32}

    def fetch_header(self, height):  # pragma: no cover - must not be called
        raise AssertionError("checkpoint above the anchor must fail before walking")


def test_re_pinning_above_an_old_anchor_orphans_it():
    verifier = HeaderChainVerifier(
        _AnchorAtHeightFetcher(),
        checkpoint_hash="ee" * 32,
        checkpoint_height=101,
    )
    result = verifier.verify_chain_for_tx("ff" * 32)

    assert result.verified is False
    assert "above the tip" in result.reason


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _write_anchor(path: Path, anchor: dict) -> Path:
    path.write_text(
        json.dumps(
            {
                "payload_hex": anchor["payload"].hex(),
                "txid": anchor["txid"],
            }
        ),
        encoding="utf-8",
    )
    return path


def _v2_cli_args(journal, *, anchor=None):
    args = [
        "anchor-chain-verify",
        "--v2",
        "--genesis-txid", GENESIS,
        "--journal", str(journal),
        "--anchor-sig",
        "--anchor-pubkey", PUBKEY,
        "--spv",
        "--header-chain",
        "--checkpoint-hash", CHECKPOINT_HASH,
        "--checkpoint-height", "1",
    ]
    if anchor is not None:
        args.extend(["--anchor", str(anchor)])
    return args


def test_cli_v2_requires_a_journal(tmp_path, capsys):
    assert main([
        "anchor-chain-verify",
        "--v2",
        "--genesis-txid", GENESIS,
        "--anchor-sig",
        "--anchor-pubkey", PUBKEY,
        "--spv",
        "--header-chain",
        "--checkpoint-hash", CHECKPOINT_HASH,
        "--checkpoint-height", "1",
    ]) == 1
    assert "--v2 requires --journal" in capsys.readouterr().err


def test_cli_v2_empty_anchors_prints_both_named_verdicts(tmp_path, capsys):
    journal = make_journal(tmp_path / "journal.jsonl")

    assert main(_v2_cli_args(journal)) == 1
    output = capsys.readouterr().out

    assert f"{VERDICT_PREFIX}: no" in output
    assert f"{VERDICT_TIP}: no" in output
    assert "freshness: unavailable" in output
    assert "ANCHOR AUTHENTICATION WITHHELD" in output


def test_cli_v2_fully_accepted_chain(tmp_path, capsys, monkeypatch):
    journal = make_journal(tmp_path / "journal.jsonl")
    anchor, tx_json = synthetic_anchor(journal)
    anchor_file = _write_anchor(tmp_path / "anchor.json", anchor)

    class FakeWoC:
        def __init__(self, base_url=None):
            pass

        def fetch_tx_full(self, txid):
            return tx_json

    class FakeSig(FakeSignatureVerifier):
        def __init__(self, fetcher, pubkey):
            super().__init__(True)

    class FakeSpv(FakeInclusionVerifier):
        def __init__(self, fetcher):
            super().__init__(True)

    class FakeHeaders(FakeHeaderVerifier):
        def __init__(self, fetcher, *, checkpoint_hash, checkpoint_height, daa=None):
            super().__init__(True)

    monkeypatch.setattr(cli_module, "WoCBlockFetcher", FakeWoC)
    monkeypatch.setattr(cli_module, "AnchorSignatureVerifier", FakeSig)
    monkeypatch.setattr(cli_module, "SPVVerifier", FakeSpv)
    monkeypatch.setattr(cli_module, "HeaderChainVerifier", FakeHeaders)

    assert main(_v2_cli_args(journal, anchor=anchor_file)) == 0
    output = capsys.readouterr().out

    assert f"{VERDICT_PREFIX}: yes" in output
    assert f"{VERDICT_TIP}: yes" in output
    assert "freshness: unavailable" in output
    assert "authenticated prefix end (seq): 3" in output
