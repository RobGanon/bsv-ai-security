import json

from aiguard.cli import main
from aiguard.core import append_audit_event


def test_cli_anchor_payload_and_verify_round_trip(tmp_path, capsys):
    journal = tmp_path / "audit.jsonl"
    payload_file = tmp_path / "anchor.json"
    append_audit_event(journal, "test", "first")
    append_audit_event(journal, "test", "second")

    assert main([
        "anchor-payload",
        "--journal", str(journal),
        "--start-seq", "1",
        "--release-seq", "0",
        "--output", str(payload_file),
    ]) == 0
    assert "NOT BROADCAST" in capsys.readouterr().out

    payload = json.loads(payload_file.read_text(encoding="utf-8"))
    assert len(bytes.fromhex(payload["payload_hex"])) == 84

    assert main([
        "anchor-verify",
        "--journal", str(journal),
        "--payload", str(payload_file),
    ]) == 0
    output = capsys.readouterr().out
    assert '"verified": true' in output
    assert "LOCAL CHECK ONLY" in output
