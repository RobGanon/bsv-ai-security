import hashlib, json
from sealrun.bsv import PrivKey
from sealrun.core import manifest_hash, record_manifest_acceptance, sign_manifest
from sealrun.publisher import Publisher, PublisherConfig
from sealrun.spv import BlockHeader, SPVVerifier, WoCBlockFetcher, merkle_root, SPVUnavailable

def _envelope(key, seq, rid):
    payload = {"schema": "sealrun-manifest-v1", "release_id": rid, "release_seq": seq,
               "artifacts": [{"path": "a.txt", "sha256": "a"*64, "size": 1}]}
    return sign_manifest(payload, key)

def test_f2_forged_store_suppresses_scheduler(tmp_path):
    from sealrun.core import append_audit_event
    journal = tmp_path / "audit.jsonl"
    append_audit_event(journal, "test", "first")
    cfg = PublisherConfig(journal=journal, anchor_record=tmp_path/"anchors.json",
                          genesis_txid="0"*64, checkpoint_interval_seconds=3600,
                          broadcast_enabled=False, manifests=(), public_key=None)
    assert Publisher(cfg).run_once(now=1_000_000.0)["action"] == "anchored"
    # Honest record, then only created_at is moved to the far future.
    # Payload fields are untouched, so _validate_record passes; run_once
    # never re-derives the record against the journal.
    store = json.loads((tmp_path/"anchors.json").read_text())
    store["anchors"][-1]["created_at"] = 1_000_000.0 + 10**9
    (tmp_path/"anchors.json").write_text(json.dumps(store))
    append_audit_event(journal, "test", "second")
    cfg2 = PublisherConfig(journal=journal, anchor_record=tmp_path/"anchors.json",
                           genesis_txid="0"*64, checkpoint_interval_seconds=3600,
                           broadcast_enabled=False, manifests=(), public_key=None)
    import pytest
    from sealrun.publisher import PublisherError
    with pytest.raises(PublisherError, match="in the future"):
        Publisher(cfg2).run_once(now=1_000_000.0 + 7200)

def test_f3_hostile_spv_fabricated_block():
    txid = "aa"*32
    # Fabricated block: tx list contains txid, merkle root from that list, trivial bits
    root = merkle_root([txid])
    header = BlockHeader(version=1, prev_hash="00"*32, merkle_root=root, time=1700000000,
                         bits=0x207fffff, nonce=0, height=999999, hash="de"*32)
    class Fake:
        def fetch_tx(self, t): return {"blockheight": 999999, "blockhash": "de"*32}
        def fetch_block(self, h): return header, [txid]
    result = SPVVerifier(Fake()).verify_inclusion(txid)
    print("F3 result:", result)
    assert not result.verified and "header hash mismatch" in result.reason, f"expected fabricated inclusion to fail post-fix, got {result}"

def test_f5_infinity_overflow_escapes():
    body = json.dumps({"version": 1, "previousblockhash": "00"*32, "merkleroot": "00"*32,
                       "time": 1700000000, "bits": 0x1d00ffff, "nonce": 0,
                       "height": float("inf"), "hash": "00"*32, "tx": []})
    # json.loads accepts Infinity; _header_from_block_json does int(inf) -> OverflowError
    def req(method, url):
        return 200, body
    fetcher = WoCBlockFetcher(base_url="https://example.com", request_fn=req)
    try:
        fetcher.fetch_block(999999)
        raised = None
    except Exception as exc:
        raised = type(exc).__name__
    print("F5 fetch_block raised:", raised)
    assert raised == "SPVUnavailable", f"expected SPVUnavailable post-fix, got {raised}"


def test_f6_nan_store_timestamp_suppresses_scheduler(tmp_path):
    import pytest
    from sealrun.core import append_audit_event
    from sealrun.publisher import PublisherError

    journal = tmp_path / "audit.jsonl"
    store_path = tmp_path / "anchors.json"
    append_audit_event(journal, "test", "first")
    cfg = PublisherConfig(
        journal=journal, anchor_record=store_path,
        genesis_txid="0" * 64, checkpoint_interval_seconds=3600,
        broadcast_enabled=False, manifests=(), public_key=None,
    )
    Publisher(cfg, clock=lambda: 1_000_000.0).run_once(now=1_000_000.0)
    store = json.loads(store_path.read_text())
    store["anchors"][-1]["created_at"] = float("nan")
    store_path.write_text(json.dumps(store))
    append_audit_event(journal, "test", "second")

    with pytest.raises(PublisherError, match="created_at"):
        Publisher(cfg).run_once(now=1_000_000.0 + 7200)


def test_f7_superseded_tip_is_not_already_anchored(tmp_path):
    import pytest
    from sealrun.core import append_audit_event
    from sealrun.publisher import PublisherError

    journal = tmp_path / "audit.jsonl"
    store_path = tmp_path / "anchors.json"
    append_audit_event(journal, "test", "first")
    cfg = PublisherConfig(
        journal=journal, anchor_record=store_path,
        genesis_txid="0" * 64, checkpoint_interval_seconds=3600,
        broadcast_enabled=False, manifests=(), public_key=None,
    )
    Publisher(cfg, clock=lambda: 1_000_000.0).run_once(now=1_000_000.0)
    store = json.loads(store_path.read_text())
    store["anchors"][-1]["status"] = "superseded"
    store_path.write_text(json.dumps(store))

    with pytest.raises(PublisherError, match="superseded"):
        Publisher(cfg).run_once(now=1_000_000.0 + 7200)


def test_f8_negative_compact_target_is_not_valid_pow():
    from sealrun.spv import _set_compact, header_hash, verify_header_chain, verify_pow

    bits = 0x20800001
    assert _set_compact(bits)[1] is True  # consensus-negative target
    header = BlockHeader(
        version=1, prev_hash="00" * 32, merkle_root="11" * 32,
        time=1700000000, bits=bits, nonce=3, height=1,
    )
    digest = header_hash(header.to_bytes())
    header = BlockHeader(**{**header.__dict__, "hash": digest})

    assert not verify_pow(header.to_bytes(), bits)
    assert not verify_header_chain([header])


def test_f9_empty_bump_rejects_non_hex_txid_and_root():
    from sealrun.spv import verify_bump_proof

    invalid = "z" * 64
    bump = {"blockHeight": 1, "path": []}
    assert not verify_bump_proof(invalid, bump, invalid)
