"""Tests: canonical JSON must reject NaN/Infinity (allow_nan=False).

NaN and Infinity are not valid JSON. ``canonical_json_bytes`` used to
serialize them as ``NaN``/``Infinity`` (Python's default), which meant a
journal event carrying a NaN field could hash and verify. The canonical
form must raise ValueError instead, and journal verification must
surface that as VerificationError.
"""

import pytest

from aiguard.core import (
    VerificationError,
    canonical_json_bytes,
    verify_audit_journal,
)

# event_hash of the body
# {"detail": NaN, "event_type": "test", "previous_hash": "0"*64, "seq": 1}
# computed with the pre-fix canonical serializer (NaN -> b"NaN").
# Hardcoded so the test stays deterministic after the fix, when the
# canonical serializer itself refuses to produce the hash.
NAN_EVENT_HASH = "f2e5d8b54683729fe8855c927e1ac92532ca024e67eba83cd3a66180015a436c"


@pytest.mark.parametrize(
    "bad", [float("nan"), float("inf"), float("-inf")]
)
def test_canonical_json_rejects_non_finite_floats(bad):
    with pytest.raises(ValueError):
        canonical_json_bytes(bad)


def test_journal_event_with_nan_detail_rejected(tmp_path):
    journal = tmp_path / "audit.jsonl"
    journal.write_text(
        '{"detail":NaN,"event_hash":"%s","event_type":"test",'
        '"previous_hash":"%s","seq":1}\n'
        % (NAN_EVENT_HASH, "0" * 64),
        encoding="utf-8",
    )
    with pytest.raises(VerificationError):
        verify_audit_journal(journal)
