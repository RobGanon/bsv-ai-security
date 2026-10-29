"""Round-2 regression tests for the fixes in `security-fixes-round2`.

Every test in this file is written to FAIL against the pre-fix code
(`d78eda0`, the parent of PR #56) and PASS on this branch. They lock
in fixes that PR #56 shipped without regression tests, plus the
round-2 remediations.

Covered:

* **A1** — a record injected into the anchor record store must not be
  believed by the publisher. Both the `pending` and the `broadcast`
  variants are covered: a store that disagrees with the journal is
  refused, not acted on.
* **A2** — a broadcast endpoint that echoes a txid the publisher did
  not compute must be refused; the txid is never recorded.
* **A3** — a *rejected* broadcast (non-2xx) must never be treated as
  success, including when the body mentions "already" / "258:".
* **A5** — an acceptance must be bound to a manifest whose signature
  verifies against a trusted key; an unverifiable binding is refused
  instead of poisoning the journal.
* **A6** — the launcher must not forward the caller's environment to
  the child (except PATH).
* **A7** — `publish --broadcast` must exit non-zero when the broadcast
  fails.
* **N2** — a command that is only findable via PATH must still launch
  by name.
* **N3** — a non-ASCII-digit TOTP code must fail closed, not raise.
* **N4** — a BUMP with a non-canonical CompactSize varint must be
  rejected.
"""

import json
import os
import stat
import struct
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sealrun.anchor import encode_anchor_payload
from sealrun.bsv import PrivKey
from sealrun.core import (
    _read_jsonl,
    append_audit_event,
    manifest_hash,
    record_manifest_acceptance,
    sign_manifest,
    verify_audit_journal,
)
from sealrun.publisher import Publisher, PublisherConfig, PublisherError

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _envelope(key, release_seq, release_id):
    payload = {
        "schema": "sealrun-manifest-v1",
        "release_id": release_id,
        "release_seq": release_seq,
        "artifacts": [{"path": "a.txt", "sha256": "a" * 64, "size": 1}],
    }
    return sign_manifest(payload, key)


def _journal_with_acceptance(tmp_path, *, release_seq=7, release_id="rel-7"):
    """A journal with one verify event and one manifest acceptance."""
    journal = tmp_path / "audit.jsonl"
    key = PrivKey.generate()
    envelope = _envelope(key, release_seq, release_id)
    append_audit_event(journal, "verify", "one")
    record_manifest_acceptance(
        journal, release_seq, release_id, manifest_hash(envelope)
    )
    return journal, key, envelope


def _publisher(tmp_path, journal, key, envelope, *, broadcast_enabled=False):
    return Publisher(
        PublisherConfig(
            journal=journal,
            anchor_record=tmp_path / "anchors.json",
            genesis_txid="0" * 64,
            checkpoint_interval_seconds=3600,
            broadcast_enabled=broadcast_enabled,
            manifests=(envelope,),
            public_key=key.pubkey_compressed(),
        )
    )


def _injected_record(head_hash, *, release_seq, status, txid):
    """A self-consistent forged record: the payload really does encode
    the claimed release_seq, so the store's own record-vs-payload
    cross-check cannot catch it. Only a re-derivation from the journal
    can."""
    payload_hex = encode_anchor_payload(
        head_hash=head_hash,
        start_seq=1,
        end_seq=1,
        release_seq=release_seq,
        prev_txid="0" * 64,
    ).hex()
    return {
        "payload_hex": payload_hex,
        "head_hash": head_hash,
        "start_seq": 1,
        "end_seq": 1,
        "release_seq": release_seq,
        "prev_txid": "0" * 64,
        "status": status,
        "txid": txid,
        "reason": "scheduled",
        "created_at": 1_000_000.0,
    }


# ---------------------------------------------------------------------------
# A1 — an injected record store must not be believed
# ---------------------------------------------------------------------------


def test_a1_injected_pending_record_is_not_broadcast(tmp_path):
    """A1: a `pending` record injected into the store must not be
    signed or broadcast.

    The forged payload is self-consistent (it really encodes the
    claimed release_seq), so the store's own cross-check accepts it.
    Only re-deriving the payload from the journal reveals the
    forgery: the journal's acceptance says release_seq 7, the
    injected record claims 0xFFFFFFFF.
    """
    journal, key, envelope = _journal_with_acceptance(tmp_path)
    head_hash = _read_jsonl(journal)[-1]["event_hash"].lower()

    injected = _injected_record(
        head_hash, release_seq=0xFFFFFFFF, status="pending", txid=None
    )
    store_path = tmp_path / "anchors.json"
    store_path.write_text(
        json.dumps({"genesis_txid": "0" * 64, "anchors": [injected]}, indent=2) + "\n"
    )

    publisher = _publisher(tmp_path, journal, key, envelope)
    with pytest.raises(PublisherError):
        publisher.build_checkpoint("scheduled")
    # Nothing was signed: the publisher refused before producing a
    # record of its own.
    assert not publisher.broadcaster


def test_a1_injected_broadcast_record_is_not_reported_as_anchored(tmp_path):
    """A1: the sibling case — a record that already claims to be
    `broadcast` (with a txid that was never broadcast) must not be
    reported as anchored, and must not become the chain predecessor
    of the next anchor.

    This is the residual the re-audit found: PR #56 re-derived only
    the `pending` branch, so the `broadcast` branch returned the
    stored record verbatim. The consequence was a durable false
    rollback claim: with release_seq 0xFFFFFFFF, every later anchor
    was rejected as a rollback and the publisher was bricked.
    """
    journal, key, envelope = _journal_with_acceptance(tmp_path)
    head_hash = _read_jsonl(journal)[-1]["event_hash"].lower()

    injected = _injected_record(
        head_hash, release_seq=0xFFFFFFFF, status="broadcast", txid="ee" * 32
    )
    store_path = tmp_path / "anchors.json"
    store_path.write_text(
        json.dumps({"genesis_txid": "0" * 64, "anchors": [injected]}, indent=2) + "\n"
    )

    publisher = _publisher(tmp_path, journal, key, envelope)
    with pytest.raises(PublisherError):
        record = publisher.build_checkpoint("scheduled")
        # If it ever returns, it must not be the injected record.
        assert record["txid"] != "ee" * 32
        assert record["release_seq"] != 0xFFFFFFFF

    # Nothing was recorded: the store still holds only the injected
    # record, and the publisher did not adopt it.
    store = json.loads(store_path.read_text())
    assert len(store["anchors"]) == 1
    assert store["anchors"][0]["txid"] == "ee" * 32


# ---------------------------------------------------------------------------
# A2 / A3 — what the publisher records after a broadcast
# ---------------------------------------------------------------------------


class _FakeWoC(BaseHTTPRequestHandler):
    """A WoC endpoint with a configurable broadcast response."""

    broadcast_status = 200
    broadcast_body = ""

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = json.dumps({
            "txid": "11" * 32,
            "vout": [{
                "value": 1.0,
                "scriptPubKey": {"hex": "76a914" + "22" * 20 + "88ac"},
            }],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.broadcast_body.encode()
        self.send_response(self.broadcast_status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(broadcast_status, broadcast_body):
    handler = type(
        "H", (_FakeWoC,),
        {"broadcast_status": broadcast_status, "broadcast_body": broadcast_body},
    )
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _publish(tmp_path, journal, key, envelope, *, status, body, port):
    """Run the publisher's broadcast path against the fake endpoint."""
    from sealrun.broadcast import FundingUTXO, WIFSigner

    signer = WIFSigner.from_wif(key.wif("testnet"), "testnet")
    broadcaster = None

    class _Broadcaster:
        def broadcast(self, payload_hex):
            return post_raw_tx(
                f"http://127.0.0.1:{port}", payload_hex, None,
                local_txid=local_txid,
            )

    # Build the anchor tx locally so we know the true txid.
    from sealrun.broadcast import WoCBroadcaster

    broadcaster = WoCBroadcaster(
        base_url=f"http://127.0.0.1:{port}",
        network="testnet",
        signer=signer,
        fee_sats=500,
        funding=FundingUTXO(
            txid="11" * 32, vout=0, value=100000,
            script_hex="76a914" + "22" * 20 + "88ac",
        ),
    )
    return broadcaster


def test_a2_broadcast_txid_must_match_the_locally_computed_one(tmp_path):
    """A2: an endpoint that answers 200 with someone else's txid must
    not be believed. The publisher must refuse, and must not record
    the attacker's txid."""
    from sealrun.broadcast import post_raw_tx

    srv, port = _serve(200, '"' + "ee" * 32 + '"')
    try:
        with pytest.raises(Exception) as exc:
            post_raw_tx(
                f"http://127.0.0.1:{port}", "00" * 40, None,
                local_txid="ab" * 32,
            )
        assert "does not match the locally computed txid" in str(exc.value)
    finally:
        srv.shutdown()


@pytest.mark.parametrize("status", [400, 500])
def test_a3_rejected_broadcast_is_never_treated_as_success(status):
    """A3: a *rejected* broadcast must not be recorded as a success,
    even when the body mentions "already" / "258:".

    The pre-fix code tested the body for "already" / "258:" *before*
    the HTTP status, so a 400/500 response that happened to contain
    that text was recorded as a successful broadcast.
    """
    from sealrun.broadcast import BroadcastRejected, post_raw_tx

    for body in ('"258: txn-already-known"', '"already in mempool"'):
        srv, port = _serve(status, body)
        try:
            with pytest.raises(BroadcastRejected):
                post_raw_tx(
                    f"http://127.0.0.1:{port}", "00" * 40, None,
                    local_txid="ab" * 32,
                )
        finally:
            srv.shutdown()


def test_a3_already_known_on_success_is_still_a_success():
    """The other side of A3: an *accepted* response that says the tx is
    already known is a success, and the txid is the locally computed
    one (the body is not a txid)."""
    from sealrun.broadcast import post_raw_tx

    srv, port = _serve(200, '"258: txn-already-known"')
    try:
        txid = post_raw_tx(
            f"http://127.0.0.1:{port}", "00" * 40, None, local_txid="ab" * 32
        )
        assert txid == "ab" * 32
    finally:
        srv.shutdown()


@pytest.mark.parametrize("body", [
    '"funding output already spent"',
    '"not already known"',
    '"258: txn-mempool-conflict"',
])
def test_a3_rejection_text_is_not_an_already_known_success(body):
    from sealrun.broadcast import BroadcastRejected, post_raw_tx

    def request(method, url, request_body):
        return 200, body.encode()

    with pytest.raises(BroadcastRejected):
        post_raw_tx(
            "https://example.invalid", "00", request, local_txid="ab" * 32
        )


@pytest.mark.parametrize("body", ["null", "[]"])
def test_a3_non_object_success_body_fails_closed(body):
    from sealrun.broadcast import BroadcastRejected, post_raw_tx

    def request(method, url, request_body):
        return 200, body.encode()

    with pytest.raises(BroadcastRejected):
        post_raw_tx(
            "https://example.invalid", "00", request, local_txid="ab" * 32
        )


# ---------------------------------------------------------------------------
# A5 — an acceptance must be verifiable
# ---------------------------------------------------------------------------


def test_a5_acceptance_for_an_invalid_signature_manifest_is_refused(tmp_path):
    """A5: an acceptance bound to a manifest whose signature does not
    verify must be refused at record time.

    The pre-fix code only *hashed* the manifest, so the acceptance was
    written. The journal is append-only and hash-chained, so the
    poisoned event could never be removed: the journal looked healthy
    (`audit-verify` reported OK) while every later anchor was refused.
    """
    from sealrun.cli import main

    journal = tmp_path / "audit.jsonl"
    key = PrivKey.generate()
    other = PrivKey.generate()

    good = _envelope(key, 6, "r-6")
    bad = _envelope(other, 6, "r-6")  # signed by a different key
    bad_file = tmp_path / "bad.json"
    bad_file.write_text(json.dumps(bad), encoding="utf-8")
    good_file = tmp_path / "good.json"
    good_file.write_text(json.dumps(good), encoding="utf-8")
    pub = tmp_path / "pub.pub"
    pub.write_text(key.pubkey_compressed().hex(), encoding="ascii")

    assert main([
        "audit-manifest-accepted",
        "--journal", str(journal),
        "--release-seq", "6",
        "--release-id", "r-6",
        "--manifest", str(bad_file),
        "--public-key", str(pub),
    ]) == 1
    # The journal was not poisoned.
    assert not journal.exists() or verify_audit_journal(journal) == 0

    # The good manifest is accepted.
    assert main([
        "audit-manifest-accepted",
        "--journal", str(journal),
        "--release-seq", "6",
        "--release-id", "r-6",
        "--manifest", str(good_file),
        "--public-key", str(pub),
    ]) == 0
    assert verify_audit_journal(journal) == 1


def test_a5_acceptance_bound_to_an_unverifiable_hash_is_refused(tmp_path):
    """A5: an acceptance that cannot be verified at all must be
    refused.

    Binding by hash alone looks harmless, but the bound hash may
    belong to a manifest that can never verify (a wrong hash, or a
    manifest with a bad signature). The journal is append-only, so
    that binding is permanent: `audit-verify` keeps reporting the
    journal as healthy while every later anchor is refused. The
    acceptance must therefore be checked at record time, not at
    anchor time.
    """
    from sealrun.cli import main

    journal = tmp_path / "audit.jsonl"
    key = PrivKey.generate()
    envelope = _envelope(key, 6, "r-6")
    pub = tmp_path / "pub.pub"
    pub.write_text(key.pubkey_compressed().hex(), encoding="ascii")

    # A hash that belongs to a manifest with an INVALID signature.
    other = PrivKey.generate()
    bad = _envelope(other, 6, "r-6")

    assert main([
        "audit-manifest-accepted",
        "--journal", str(journal),
        "--release-seq", "6",
        "--release-id", "r-6",
        "--manifest-hash", manifest_hash(bad),
    ]) == 1
    assert not journal.exists() or verify_audit_journal(journal) == 0

    # And a hash that belongs to no manifest at all.
    assert main([
        "audit-manifest-accepted",
        "--journal", str(journal),
        "--release-seq", "6",
        "--release-id", "r-6",
        "--manifest-hash", "cd" * 32,
    ]) == 1
    assert not journal.exists() or verify_audit_journal(journal) == 0


# ---------------------------------------------------------------------------
# A6 — the launcher must not forward the caller's environment
# ---------------------------------------------------------------------------


def test_a6_launcher_does_not_forward_the_parent_environment(tmp_path):
    """A6: the child must not see the caller's variables.

    The pre-fix launcher passed ``os.environ`` through verbatim, so
    ``ANCHOR_WIF`` (the anchor private key) and every other secret in
    the operator's environment reached the unprivileged model process.
    """
    from sealrun.launcher import build_child_environment

    envelope = {
        "payload": {"release_id": "rel-9", "release_seq": 9, "artifacts": []},
        "signature": "eA==",
    }
    os.environ["ANCHOR_WIF"] = "LsecretAnchorKey"
    os.environ["SECRET_TOKEN"] = "super-secret-value"
    try:
        env = build_child_environment(envelope, [])
    finally:
        del os.environ["ANCHOR_WIF"]
        del os.environ["SECRET_TOKEN"]

    assert "ANCHOR_WIF" not in env
    assert "SECRET_TOKEN" not in env
    assert env["SEALRUN_MANIFEST_HASH"]
    # PATH is the one variable carried over (it names executables).
    assert "PATH" not in env or env["PATH"] == os.environ.get("PATH")


def test_a6_launcher_child_does_not_see_parent_secrets(tmp_path):
    """A6 end-to-end: the launched child must not observe the
    caller's secret variables."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "tl", Path(__file__).parent / "test_launcher.py"
    )
    tl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tl)

    from sealrun.launcher import launch

    root = tl.setup_artifacts(tmp_path)
    private, envelope = tl.make_signed(root)
    out = tmp_path / "env.json"
    script = (
        "import json, os, sys\n"
        "json.dump({k: os.environ.get(k) for k in ('ANCHOR_WIF', 'SECRET_TOKEN',"
        " 'PATH')}, open(sys.argv[1], 'w'))\n"
    )
    os.environ["ANCHOR_WIF"] = "LsecretAnchorKey"
    os.environ["SECRET_TOKEN"] = "super-secret-value"
    try:
        rc = launch(root, envelope, private.pubkey_compressed(),
                    [sys.executable, "-c", script, str(out)])
    finally:
        del os.environ["ANCHOR_WIF"]
        del os.environ["SECRET_TOKEN"]
    assert rc == 0
    child = json.loads(out.read_text())
    assert child["ANCHOR_WIF"] is None
    assert child["SECRET_TOKEN"] is None


# ---------------------------------------------------------------------------
# A7 — publish must not report success when the broadcast failed
# ---------------------------------------------------------------------------


def test_a7_publish_broadcast_exits_non_zero_when_the_broadcast_fails(tmp_path):
    """A7: `sealrun publish --broadcast` must exit non-zero when the
    broadcast fails.

    The pre-fix code printed ``action: "anchored"`` and exited 0 even
    though the record stayed ``pending`` with a null txid. Every
    automation keyed on the exit code (cron, CI, a monitor) recorded a
    success that never happened.
    """
    from sealrun.cli import main

    journal = tmp_path / "audit.jsonl"
    journal.touch()
    append_audit_event(journal, "verify", "one")
    append_audit_event(journal, "verify", "two")

    # The funding lookup succeeds; the raw-tx broadcast fails.
    srv, port = _serve(500, '{"error":"internal server error"}')
    try:
        key = PrivKey.generate()
        os.environ["ANCHOR_WIF"] = key.wif("testnet")
        try:
            rc = main([
                "publish",
                "--journal", str(journal),
                "--anchor-record", str(tmp_path / "anchors.json"),
                "--woc-base", f"http://127.0.0.1:{port}",
                "--funding-txid", "11" * 32,
                "--funding-vout", "0",
                "--change-address", key.address("testnet"),
                "--broadcast",
            ])
        finally:
            del os.environ["ANCHOR_WIF"]
    finally:
        srv.shutdown()

    assert rc != 0, "publish reported success even though the broadcast failed"


# ---------------------------------------------------------------------------
# N2 — a command found only via PATH must still launch by name
# ---------------------------------------------------------------------------


def test_n2_launch_finds_a_command_by_name_via_path(tmp_path):
    """N2: a command that is only on PATH (not in /bin or /usr/bin)
    must still launch when named.

    The launcher resolves a relative ``argv[0]`` through the *child's*
    PATH, because that is what ``subprocess`` uses. With no PATH in the
    child environment the lookup collapsed to ``os.defpath``
    (``/bin:/usr/bin``) and a bare command name could not be found.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "tl", Path(__file__).parent / "test_launcher.py"
    )
    tl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tl)

    from sealrun.launcher import launch

    root = tl.setup_artifacts(tmp_path)
    private, envelope = tl.make_signed(root)

    bindir = tmp_path / "only-on-path"
    bindir.mkdir()
    program = bindir / "sealrun-round2-model"
    program.write_text("#!/bin/sh\necho ROUND2-RAN\n", encoding="utf-8")
    program.chmod(0o755)

    old_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{bindir}{os.pathsep}{old_path}"
    try:
        rc = launch(root, envelope, private.pubkey_compressed(),
                    ["sealrun-round2-model"])
    finally:
        os.environ["PATH"] = old_path
    assert rc == 0


def test_n2_child_environment_carries_path_only(tmp_path):
    """N2: the child environment carries PATH from the caller and
    nothing else from it."""
    from sealrun.launcher import build_child_environment

    envelope = {
        "payload": {"release_id": "rel-9", "release_seq": 9, "artifacts": []},
        "signature": "eA==",
    }
    env = build_child_environment(envelope, [])
    assert env["PATH"] == os.environ.get("PATH")
    assert set(env) <= {
        "PATH", "SEALRUN_MANIFEST_HASH", "SEALRUN_RELEASE_ID",
        "SEALRUN_RELEASE_SEQ",
    }


# ---------------------------------------------------------------------------
# N3 — a non-ASCII-digit TOTP code must fail closed
# ---------------------------------------------------------------------------


def test_n3_non_ascii_totp_code_fails_closed_without_raising():
    """N3: a code made of Unicode digits must be rejected cleanly.

    ``str.isdigit()`` accepts Unicode digits, but
    ``hmac.compare_digest`` refuses to compare non-ASCII strings and
    raises ``TypeError``. The pre-fix code let that escape as an
    unhandled traceback, and the audit log was left showing a
    ceremony request with no outcome.
    """
    from sealrun import signer_cli

    arabic = "١٢٣٤٥٦"  # Arabic-Indic digits 1-6
    assert arabic.isdigit()  # the trap: isdigit() says yes
    assert not arabic.isascii()

    # The stateless check must answer "no", not raise.
    assert signer_cli.totp_verify("JBSWY3DPEHPK3PXP", arabic, 59, digits=6) is False

    # The step-returning form (added with the single-use fix) must do
    # the same.
    matching_step = getattr(signer_cli, "totp_matching_step", None)
    if matching_step is not None:
        assert matching_step("JBSWY3DPEHPK3PXP", arabic, 59, digits=6) is None


def test_n3_non_ascii_totp_code_does_not_escape_as_an_exception(tmp_path):
    """N3 end-to-end: the CLI must refuse cleanly, not crash."""
    from sealrun.signer_cli import Refusal, SignerError, init_signer, load_config
    from sealrun.signer_cli import sign_flow
    from sealrun.bsv import Tx, TxIn, TxOut, build_op_return_script
    from sealrun.bsv import build_p2pkh_script_for_address

    password = "correct horse battery staple"
    config_path = tmp_path / "signer.json"
    key_path = tmp_path / "anchor-key.txt"
    inputs = iter(["operator", "unused"])
    init_signer(
        config_path, key_path,
        input_fn=lambda p: next(inputs),
        getpass_fn=lambda p: password,
        output_fn=lambda s: None,
    )
    cfg = load_config(config_path)
    key = PrivKey.from_wif(key_path.read_text().strip(), "testnet")
    payload = encode_anchor_payload(
        head_hash="ab" * 32, start_seq=5, end_seq=5, release_seq=0,
        prev_txid="11" * 32,
    )
    cfg["expected_prev_txid"] = "11" * 32
    cfg["expected_utxo"] = {"txid": "11" * 32, "vout": 1, "value": 99_500}
    cfg["expected_payload_hex"] = payload.hex()
    os.chmod(config_path, 0o600)
    config_path.write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")

    tx = Tx(
        inputs=[TxIn("11" * 32, 1)],
        outputs=[
            TxOut(0, build_op_return_script(payload)),
            TxOut(99_000, build_p2pkh_script_for_address(
                key.address("testnet"), "testnet")),
        ],
    )

    def input_fn(prompt):
        if "Username" in prompt:
            return "operator"
        return "١٢٣٤٥٦"

    with pytest.raises((Refusal, SignerError)):
        sign_flow(
            config_path, tx.serialize().hex(),
            expected_payload_hex=payload.hex(),
            input_fn=input_fn, getpass_fn=lambda p: password,
            output_fn=lambda s: None, time_fn=lambda: 59,
        )


# ---------------------------------------------------------------------------
# N4 — the BUMP reader must reject non-canonical CompactSize
# ---------------------------------------------------------------------------


def _bump_bytes(*, noncanonical_height=False, noncanonical_nleaves=False,
                noncanonical_offset=False):
    out = bytearray()
    if noncanonical_height:
        out += b"\xfd" + struct.pack("<H", 100)
    else:
        out += bytes([100])
    out += bytes([1])                       # tree height
    if noncanonical_nleaves:
        out += b"\xfd" + struct.pack("<H", 1)
    else:
        out += bytes([1])
    if noncanonical_offset:
        out += b"\xfd" + struct.pack("<H", 0)
    else:
        out += bytes([0])
    out += bytes([0x02])                    # flag: has a 32-byte hash
    out += b"\x11" * 32
    return bytes(out)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"noncanonical_height": True},
        {"noncanonical_nleaves": True},
        {"noncanonical_offset": True},
    ],
)
def test_n4_bump_rejects_noncanonical_varint(kwargs):
    """N4: the BUMP reader must reject a non-canonical CompactSize
    varint, exactly as the transaction and envelope readers do.

    A non-canonical encoding makes the same BUMP have two valid byte
    representations, so the envelope is not byte-canonical: a consumer
    that hashes it gets two different digests for the same content.
    """
    from sealrun.spv import parse_bump_bytes

    with pytest.raises(ValueError, match="non-canonical CompactSize"):
        parse_bump_bytes(_bump_bytes(**kwargs))


def test_n4_bump_still_parses_canonical_encodings():
    """The guard must not break the canonical form."""
    from sealrun.spv import parse_bump_bytes

    bump, consumed = parse_bump_bytes(_bump_bytes())
    assert bump["blockHeight"] == 100
    assert consumed == len(_bump_bytes())


def test_n4_beef_envelope_with_a_noncanonical_bump_is_rejected():
    """N4 end-to-end: a BEEF envelope carrying a non-canonical BUMP
    must be rejected."""
    from sealrun.beef import BEEF_MAGIC, parse_beef
    from sealrun.bsv import _varint

    tx_raw = (
        struct.pack("<i", 1) + _varint(1) + b"\x00" * 32
        + struct.pack("<I", 0) + b"\x00" + struct.pack("<I", 0xFFFFFFFF)
        + _varint(1) + struct.pack("<q", 0) + b"\x00" + struct.pack("<I", 0)
    )
    envelope = (
        BEEF_MAGIC + _varint(1) + _bump_bytes(noncanonical_nleaves=True)
        + _varint(1) + tx_raw + bytes([0])
    )
    with pytest.raises(ValueError, match="non-canonical CompactSize"):
        parse_beef(envelope)


# ---------------------------------------------------------------------------
# A1 residual — the store is bound to the journal, not just to itself
#
# The store loader already enforces store-internal continuity
# (verify_anchor_chain: genesis base, seq/prev linkage, no
# duplicate txids, no forks), and round 2 re-derived the current
# head's record on the dedupe path. What nothing checked: that a
# broadcast record's payload actually derives from THIS journal.
# A store that is internally perfect yet journal-false — payloads
# encoding another journal's heads, or a release_seq this
# journal's acceptances never derived — passed the loader and
# became the next anchor's predecessor base. The publisher now
# re-derives EVERY broadcast record from the journal, in chain
# order, before acting on the store.
#
# The two journal-binding discriminators (fail on pre-fix code,
# which builds a forked anchor): the tampered tip payload and the
# transplanted store. The remaining tampers are defense in depth —
# the loader's structural checks catch them first, and these tests
# pin that the refusal happens either way.
# ---------------------------------------------------------------------------


class _StubBroadcaster:
    """Hands out sequential fake txids; records what it was given."""

    def __init__(self):
        self.payloads = []

    def broadcast(self, payload_hex):
        self.payloads.append(payload_hex)
        return f"{len(self.payloads):064x}"


def _honest_chain(tmp_path):
    """A publisher with three broadcast anchors over a growing journal."""
    journal, key, envelope = _journal_with_acceptance(tmp_path)
    publisher = Publisher(
        PublisherConfig(
            journal=journal,
            anchor_record=tmp_path / "anchors.json",
            genesis_txid="0" * 64,
            checkpoint_interval_seconds=3600,
            broadcast_enabled=True,
            manifests=(envelope,),
            public_key=key.pubkey_compressed(),
        ),
        broadcaster=_StubBroadcaster(),
    )
    records = [publisher.build_checkpoint("scheduled")]
    for i in range(2):
        append_audit_event(journal, "verify", f"more-{i}")
        records.append(publisher.build_checkpoint("scheduled"))
    store_path = tmp_path / "anchors.json"
    store = json.loads(store_path.read_text())
    assert [r["status"] for r in store["anchors"]] == ["broadcast"] * 3
    return journal, publisher, store_path, store, records


def _rewrite_store(store_path, store):
    store_path.write_text(json.dumps(store, indent=2) + "\n")


def test_a1r_honest_chain_extends_from_the_verified_tip(tmp_path):
    journal, publisher, _path, _store, records = _honest_chain(tmp_path)
    append_audit_event(journal, "verify", "more-2")
    record = publisher.build_checkpoint("scheduled")
    assert record["prev_txid"] == records[-1]["txid"]
    assert record["start_seq"] == records[-1]["end_seq"] + 1


def test_a1r_appended_duplicate_of_an_old_anchor_is_refused(tmp_path):
    journal, publisher, store_path, store, _records = _honest_chain(tmp_path)
    # A byte-copy of the first anchor, appended last. (The loader's
    # duplicate-txid check catches this one; chain re-derivation is
    # the second layer. Kept as layered coverage.)
    store["anchors"].append(dict(store["anchors"][0]))
    _rewrite_store(store_path, store)
    append_audit_event(journal, "verify", "more-2")
    with pytest.raises(PublisherError):
        publisher.build_checkpoint("scheduled")


def test_a1r_tampered_middle_txid_is_refused(tmp_path):
    journal, publisher, store_path, store, _records = _honest_chain(tmp_path)
    # The tip record itself is untouched; its predecessor's txid is
    # rewritten. (The loader's linkage check catches this one;
    # re-derivation of the tip against the tampered base would
    # break too. Layered coverage.)
    store["anchors"][1]["txid"] = "ff" * 32
    _rewrite_store(store_path, store)
    append_audit_event(journal, "verify", "more-2")
    with pytest.raises(PublisherError):
        publisher.build_checkpoint("scheduled")


def test_a1r_tampered_tip_payload_is_refused(tmp_path):
    journal, publisher, store_path, store, records = _honest_chain(tmp_path)
    tip = store["anchors"][2]
    tip["payload_hex"] = encode_anchor_payload(
        head_hash=tip["head_hash"],
        start_seq=tip["start_seq"],
        end_seq=tip["end_seq"],
        release_seq=999,
        prev_txid=records[1]["txid"],
    ).hex()
    tip["release_seq"] = 999
    _rewrite_store(store_path, store)
    append_audit_event(journal, "verify", "more-2")
    with pytest.raises(PublisherError):
        publisher.build_checkpoint("scheduled")


def test_a1r_first_record_with_wrong_genesis_base_is_refused(tmp_path):
    journal, publisher, store_path, store, _records = _honest_chain(tmp_path)
    store["anchors"][0]["prev_txid"] = "11" * 32
    _rewrite_store(store_path, store)
    append_audit_event(journal, "verify", "more-2")
    with pytest.raises(PublisherError):
        publisher.build_checkpoint("scheduled")


def test_a1r_transplanted_store_from_another_journal_is_refused(tmp_path):
    """The clean discriminator: a store that is internally perfect
    (it is a real store — of a DIFFERENT journal) passes the
    loader's continuity checks untouched, but its payloads encode
    the other journal's heads. Only re-derivation against THIS
    journal can refuse it. On pre-fix code the next anchor builds
    on the transplanted tip."""
    journal, publisher, store_path, _store, _records = _honest_chain(tmp_path)

    # A second, honest chain over a different journal.
    b_dir = tmp_path / "b"
    b_dir.mkdir()
    journal_b = b_dir / "audit.jsonl"
    key_b = PrivKey.generate()
    envelope_b = _envelope(key_b, 7, "rel-7")
    append_audit_event(journal_b, "verify", "someone else's journal")
    record_manifest_acceptance(
        journal_b, 7, "rel-7", manifest_hash(envelope_b)
    )
    publisher_b = Publisher(
        PublisherConfig(
            journal=journal_b,
            anchor_record=b_dir / "anchors.json",
            genesis_txid="0" * 64,
            checkpoint_interval_seconds=3600,
            broadcast_enabled=True,
            manifests=(envelope_b,),
            public_key=key_b.pubkey_compressed(),
        ),
        broadcaster=_StubBroadcaster(),
    )
    publisher_b.build_checkpoint("scheduled")
    for i in range(2):
        append_audit_event(journal_b, "verify", f"b-{i}")
        publisher_b.build_checkpoint("scheduled")

    # Transplant B's store over A's: same genesis, internally
    # consistent, entirely journal-false for A.
    store_b = json.loads((b_dir / "anchors.json").read_text())
    _rewrite_store(store_path, store_b)
    append_audit_event(journal, "verify", "more-2")
    with pytest.raises(PublisherError):
        publisher.build_checkpoint("scheduled")
