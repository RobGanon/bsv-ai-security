"""Issue #8: anchor-chain continuity from a trusted genesis txid.

``verify_anchor_chain`` checks that a sequence of anchors forms one
continuous, fork-free chain: first prev_txid == trusted genesis, each
later prev_txid == previous txid, start_seq == previous end_seq + 1,
no duplicates, no forks. Genesis is operator-supplied, never inferred
from the anchor set.
"""

import json

import pytest

from sealrun.anchor import (
    create_anchor_payload,
    decode_anchor_payload,
    encode_anchor_payload,
    verify_anchor_chain,
    verify_journal_against_anchor,
    verify_journal_against_anchor_chain,
)
from sealrun.cli import main
from sealrun.core import VerificationError, append_audit_event
from sealrun.publisher import Publisher, PublisherConfig, PublisherError

GENESIS = "aa" * 32


def _txid(byte: int) -> str:
    return f"{byte:02x}" * 32


def _entry(txid, *, start, end, prev, head="ab" * 32, release=0):
    payload = encode_anchor_payload(
        head_hash=head, start_seq=start, end_seq=end,
        release_seq=release, prev_txid=prev,
    )
    return {"payload": payload, "txid": txid}


def _valid_chain():
    return [
        _entry(_txid(0x11), start=1, end=3, prev=GENESIS),
        _entry(_txid(0x22), start=4, end=6, prev=_txid(0x11)),
        _entry(_txid(0x33), start=7, end=9, prev=_txid(0x22)),
    ]


def test_valid_chain_verifies():
    result = verify_anchor_chain(_valid_chain(), GENESIS)
    assert result["verified"] is True
    assert result["anchor_count"] == 3
    assert result["genesis_txid"] == GENESIS
    assert result["first_seq"] == 1
    assert result["last_seq"] == 9
    assert result["last_txid"] == _txid(0x33)


def test_empty_chain_verifies_vacuously_with_zero_count():
    result = verify_anchor_chain([], GENESIS)
    assert result["verified"] is True
    assert result["anchor_count"] == 0
    assert result["last_txid"] is None


def test_arbitrary_prev_txid_rejected():
    chain = _valid_chain()
    chain[0] = _entry(_txid(0x11), start=1, end=3, prev="ff" * 32)
    with pytest.raises(VerificationError, match="genesis"):
        verify_anchor_chain(chain, GENESIS)


def test_sequence_gap_rejected():
    chain = _valid_chain()
    chain[1] = _entry(_txid(0x22), start=5, end=6, prev=_txid(0x11))
    with pytest.raises(VerificationError, match="gap or overlap"):
        verify_anchor_chain(chain, GENESIS)


def test_sequence_overlap_rejected():
    chain = _valid_chain()
    chain[1] = _entry(_txid(0x22), start=3, end=6, prev=_txid(0x11))
    with pytest.raises(VerificationError, match="gap or overlap"):
        verify_anchor_chain(chain, GENESIS)


def test_reordered_anchors_rejected():
    chain = _valid_chain()
    chain[0], chain[1] = chain[1], chain[0]
    with pytest.raises(VerificationError, match="genesis|linkage"):
        verify_anchor_chain(chain, GENESIS)


def test_duplicate_txid_rejected():
    chain = _valid_chain()
    chain[1] = _entry(_txid(0x11), start=4, end=6, prev=_txid(0x11))
    with pytest.raises(VerificationError, match="duplicate anchor txid"):
        verify_anchor_chain(chain, GENESIS)


def test_duplicate_payload_rejected():
    chain = _valid_chain()
    duplicate = dict(chain[0])
    duplicate["txid"] = _txid(0x44)
    # Prepended: the duplicate precedes its original, so the
    # duplicate-payload check fires (appended, it would read as a fork).
    chain.insert(0, duplicate)
    with pytest.raises(VerificationError, match="duplicate anchor payload"):
        verify_anchor_chain(chain, GENESIS)


def test_fork_rejected():
    chain = _valid_chain()
    fork = _entry(_txid(0x44), start=4, end=5, prev=_txid(0x11), head="cc" * 32)
    chain.append(fork)
    with pytest.raises(VerificationError, match="fork"):
        verify_anchor_chain(chain, GENESIS)


def test_fork_at_genesis_rejected():
    chain = [
        _entry(_txid(0x11), start=1, end=3, prev=GENESIS),
        _entry(_txid(0x22), start=1, end=2, prev=GENESIS, head="cc" * 32),
    ]
    with pytest.raises(VerificationError, match="fork"):
        verify_anchor_chain(chain, GENESIS)


def test_wrong_genesis_rejected():
    with pytest.raises(VerificationError, match="genesis"):
        verify_anchor_chain(_valid_chain(), "bb" * 32)


def test_genesis_taken_from_anchor_set_rejected():
    with pytest.raises(VerificationError, match="external"):
        verify_anchor_chain(_valid_chain(), _txid(0x11))


def test_genesis_missing_or_invalid_rejected():
    for bad in (None, "", "xyz", "aa" * 31, 123):
        with pytest.raises(VerificationError, match="genesis_txid"):
            verify_anchor_chain(_valid_chain(), bad)


def test_first_anchor_must_start_at_one():
    chain = [_entry(_txid(0x11), start=2, end=3, prev=GENESIS)]
    with pytest.raises(VerificationError, match="start at sequence 1"):
        verify_anchor_chain(chain, GENESIS)


def test_malformed_entries_rejected():
    good = _valid_chain()[0]
    for bad in (
        {"payload": good["payload"]},
        {"payload": good["payload"], "txid": "not-hex"},
        {"payload_hex": "zz", "txid": _txid(0x11)},
        {"payload": "not-bytes-or-hex", "txid": _txid(0x11)},
        "a-string",
        ("only-one",),
    ):
        with pytest.raises(VerificationError):
            verify_anchor_chain([bad], GENESIS)
    with pytest.raises(VerificationError):
        verify_anchor_chain("not-a-list", GENESIS)


def test_tuple_and_hex_entries_accepted():
    payload, txid = _valid_chain()[0]["payload"], _txid(0x11)
    assert verify_anchor_chain([(payload, txid)], GENESIS)["anchor_count"] == 1
    assert verify_anchor_chain(
        [{"payload_hex": payload.hex(), "txid": txid}], GENESIS
    )["anchor_count"] == 1


def test_single_anchor_chain_against_genesis():
    chain = [_entry(_txid(0x11), start=1, end=3, prev=GENESIS)]
    result = verify_anchor_chain(chain, GENESIS)
    assert result["anchor_count"] == 1
    assert result["last_txid"] == _txid(0x11)


def _journal_chain(tmp_path):
    """A real journal + 3 anchors whose payloads match it (via creation)."""
    journal = tmp_path / "audit.jsonl"
    entries = []
    prev = GENESIS
    for start in (1, 4, 7):
        for _ in range(3):
            append_audit_event(journal, "test", "event")
        fields = create_anchor_payload(journal, start_seq=start, prev_txid=prev)
        txid = _txid(0x10 + start)
        entries.append({"payload_hex": fields["payload_hex"], "txid": txid})
        prev = txid
    return journal, entries


def test_journal_against_valid_chain(tmp_path):
    journal, entries = _journal_chain(tmp_path)
    result = verify_journal_against_anchor_chain(journal, entries, GENESIS)
    assert result["verified"] is True
    assert result["chain"]["anchor_count"] == 3
    assert len(result["anchors"]) == 3
    assert result["chain_inclusion_verified"] is False


def test_journal_against_chain_fails_when_chain_broken_but_anchors_match(tmp_path):
    journal, entries = _journal_chain(tmp_path)
    # Re-encode the second payload with an arbitrary prev_txid, keeping
    # head/seqs: each anchor still matches the journal individually,
    # but the chain is broken — and that must fail verification.
    fields = decode_anchor_payload(bytes.fromhex(entries[1]["payload_hex"]))
    broken = encode_anchor_payload(
        head_hash=fields["head_hash"], start_seq=fields["start_seq"],
        end_seq=fields["end_seq"], release_seq=fields["release_seq"],
        prev_txid="ff" * 32,
    )
    entries[1] = {"payload_hex": broken.hex(), "txid": entries[1]["txid"]}
    assert verify_journal_against_anchor(
        journal, broken
    )["verified"] is True
    with pytest.raises(VerificationError, match="linkage"):
        verify_journal_against_anchor_chain(journal, entries, GENESIS)


def test_journal_against_chain_fails_when_journal_tampered(tmp_path):
    journal, entries = _journal_chain(tmp_path)
    lines = journal.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("event", "EVIL!")
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(VerificationError):
        verify_journal_against_anchor_chain(journal, entries, GENESIS)


# --- publisher store wiring ------------------------------------------------

class _StubBroadcaster:
    def broadcast(self, payload_hex):
        import hashlib

        return hashlib.sha256(("stub:" + payload_hex).encode()).hexdigest()


def _publisher(tmp_path, *, genesis=GENESIS):
    config = PublisherConfig(
        journal=tmp_path / "audit.jsonl",
        anchor_record=tmp_path / "anchors.json",
        genesis_txid=genesis,
        broadcast_enabled=True,
    )
    return Publisher(config, broadcaster=_StubBroadcaster())


def _two_broadcasts(tmp_path):
    publisher = _publisher(tmp_path)
    for _ in range(3):
        append_audit_event(tmp_path / "audit.jsonl", "test", "event")
    publisher.build_checkpoint("scheduled")
    for _ in range(3):
        append_audit_event(tmp_path / "audit.jsonl", "test", "event")
    publisher.build_checkpoint("scheduled")
    return publisher


def test_publisher_store_tampered_prev_txid_refuses(tmp_path):
    _two_broadcasts(tmp_path)
    store_path = tmp_path / "anchors.json"
    store = json.loads(store_path.read_text(encoding="utf-8"))
    record = store["anchors"][1]
    assert record["status"] == "broadcast"
    fields = decode_anchor_payload(bytes.fromhex(record["payload_hex"]))
    tampered = encode_anchor_payload(
        head_hash=fields["head_hash"], start_seq=fields["start_seq"],
        end_seq=fields["end_seq"], release_seq=fields["release_seq"],
        prev_txid="ff" * 32,
    )
    record["payload_hex"] = tampered.hex()
    record["prev_txid"] = "ff" * 32
    store_path.write_text(json.dumps(store), encoding="utf-8")
    with pytest.raises(PublisherError, match="chain is broken"):
        _publisher(tmp_path).run_once()


def test_publisher_store_fork_refuses(tmp_path):
    _two_broadcasts(tmp_path)
    store_path = tmp_path / "anchors.json"
    store = json.loads(store_path.read_text(encoding="utf-8"))
    first = store["anchors"][0]
    forged_payload = encode_anchor_payload(
        head_hash="cc" * 32, start_seq=first["start_seq"],
        end_seq=first["end_seq"], release_seq=0, prev_txid=GENESIS,
    )
    store["anchors"].append(
        {
            "payload_hex": forged_payload.hex(),
            "head_hash": "cc" * 32,
            "start_seq": first["start_seq"],
            "end_seq": first["end_seq"],
            "release_seq": 0,
            "prev_txid": GENESIS,
            "status": "broadcast",
            "txid": _txid(0xDD),
            "reason": "scheduled",
            "created_at": 1.0,
        }
    )
    store_path.write_text(json.dumps(store), encoding="utf-8")
    with pytest.raises(PublisherError, match="chain is broken.*fork"):
        _publisher(tmp_path).run_once()


def test_publisher_valid_broadcast_store_loads(tmp_path):
    publisher = _two_broadcasts(tmp_path)
    decision = publisher.run_once()
    assert decision["action"] == "none"


# --- CLI -------------------------------------------------------------------

def _write_anchor_file(tmp_path, name, payload_hex, txid):
    path = tmp_path / name
    path.write_text(
        json.dumps({"payload_hex": payload_hex, "txid": txid}), encoding="utf-8"
    )
    return path


def test_cli_chain_verify_valid(tmp_path, capsys):
    chain = _valid_chain()
    paths = [
        _write_anchor_file(tmp_path, f"a{i}.json", entry["payload"].hex(), entry["txid"])
        for i, entry in enumerate(chain)
    ]
    argv = ["anchor-chain-verify", "--genesis-txid", GENESIS]
    for path in paths:
        argv += ["--anchor", str(path)]
    assert main(argv) == 0
    assert '"verified": true' in capsys.readouterr().out


def test_cli_chain_verify_broken(tmp_path, capsys):
    chain = _valid_chain()
    chain[1] = _entry(_txid(0x22), start=4, end=6, prev="ff" * 32)
    paths = [
        _write_anchor_file(tmp_path, f"a{i}.json", entry["payload"].hex(), entry["txid"])
        for i, entry in enumerate(chain)
    ]
    argv = ["anchor-chain-verify", "--genesis-txid", GENESIS]
    for path in paths:
        argv += ["--anchor", str(path)]
    assert main(argv) == 1
    assert "ERROR" in capsys.readouterr().err


def test_cli_chain_verify_with_journal(tmp_path, capsys):
    journal, entries = _journal_chain(tmp_path)
    paths = [
        _write_anchor_file(tmp_path, f"a{i}.json", e["payload_hex"], e["txid"])
        for i, e in enumerate(entries)
    ]
    argv = ["anchor-chain-verify", "--genesis-txid", GENESIS,
            "--journal", str(journal)]
    for path in paths:
        argv += ["--anchor", str(path)]
    assert main(argv) == 0
    assert '"verified": true' in capsys.readouterr().out
