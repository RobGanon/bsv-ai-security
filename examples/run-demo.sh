#!/usr/bin/env bash
#
# run-demo.sh — prove that SealRun catches tampering, in three cases.
#
#   A1  tampered artifact: one flipped byte in model.bin (in a copy of the
#       work dir). `verify` AND `launch` must both refuse with
#       "artifact integrity mismatch: model.bin", and the launch child
#       must never run (its marker file must not appear).
#
#   A2  tampered manifest: one changed hex digit inside the first
#       artifact sha256 of a copy of the signed manifest. `verify` must
#       refuse with "manifest signature invalid".
#
#   A6  forged finish: a copy of a healthy 3-event audit journal, with a
#       hand-appended forged finish event (seq = last+1,
#       previous_hash = last event_hash, event_hash = 64 zeroes).
#       `audit-verify` must fail with "audit event hash mismatch at
#       sequence ..." (any sequence number).
#
# The script builds its own layout under ~/sealrun-demo and invokes the
# sealrun CLI from the repo the way this project runs it:
#
#   cd <repo> && .venv/bin/python -m sealrun.cli <command>
#
# No network, no sudo, nothing outside ~/sealrun-demo is touched.
#
set -u

DEMO="${SEALRUN_DEMO:-$HOME/sealrun-demo}"
REPO="${SEALRUN_REPO:-$HOME/Work/bsv-ai-security}"
PY="$REPO/.venv/bin/python"

PRIVKEY="$DEMO/keys/private.wif"
PUBKEY="$DEMO/keys/public.pub"
WORK="$DEMO/work"
WORK_A1="$DEMO/work-a1"
STATE="$DEMO/state"
MANIFEST_UNSIGNED="$STATE/manifest.json"
SIGNED="$STATE/manifest.signed.json"
MANIFEST_A2="$STATE/manifest.a2.json"
JOURNAL="$STATE/audit.jsonl"
JOURNAL_A6="$STATE/audit.a6.jsonl"
MARKER="infer-ran.marker"

failures=0

banner() { echo; echo "=== $* ==="; }

# Start the next section at the top of a fresh screen (for video recording).
clear_screen() { printf '\033[2J\033[H'; }

# Hold the current section on screen until the viewer presses Enter.
pause() {
    echo
    printf 'Press Enter for the next case...'
    read -r _ || true
    echo
}

# sealrun <args...>: run the CLI from the repo dir, as required.
sealrun() {
    ( cd "$REPO" && "$PY" -m sealrun.cli "$@" )
}

# expect_ok <label> <required-substring> -- cmd...
# Prints the command's combined output indented; ok iff exit 0 AND the
# required substring appears.
expect_ok() {
    local label="$1" substring="$2"; shift 2
    local out rc
    out=$("$@" 2>&1); rc=$?
    printf '%s\n' "$out" | sed 's/^/  | /'
    if [ "$rc" -ne 0 ]; then
        echo "  -> FAIL: exit $rc (expected 0)"
        return 1
    fi
    if ! printf '%s' "$out" | grep -qF -- "$substring"; then
        echo "  -> FAIL: succeeded but missing expected text: $substring"
        return 1
    fi
    echo "  -> ok (exit 0; found: $substring)"
    return 0
}

# expect_refused <label> <required-substring> -- cmd...
# Prints the command's combined output indented; ok iff exit != 0 AND the
# required substring appears.
expect_refused() {
    local label="$1" substring="$2"; shift 2
    local out rc
    out=$("$@" 2>&1); rc=$?
    printf '%s\n' "$out" | sed 's/^/  | /'
    if [ "$rc" -eq 0 ]; then
        echo "  -> FAIL: command unexpectedly SUCCEEDED (expected refusal)"
        return 1
    fi
    if ! printf '%s' "$out" | grep -qF -- "$substring"; then
        echo "  -> FAIL: refused (exit $rc) but missing expected text: $substring"
        return 1
    fi
    echo "  -> ok (refused with exit $rc; found: $substring)"
    return 0
}

note_failure() {
    failures=$((failures + 1))
}

check_prereqs() {
    if [ ! -x "$PY" ]; then
        echo "FATAL: sealrun venv python not found at: $PY" >&2
        exit 1
    fi
    if ! sealrun --version >/dev/null 2>&1; then
        echo "FATAL: cannot run sealrun CLI from repo: $REPO" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------- setup
setup() {
    clear_screen
    banner "Setup: build the demo layout under $DEMO"

    # Fresh layout, but never touch this script itself.
    mkdir -p "$DEMO"
    rm -rf "$DEMO/keys" "$DEMO/work" "$DEMO/work-a1" "$DEMO/state"
    mkdir -p "$DEMO/keys" "$WORK" "$STATE"

    # Work files.
    head -c 4096 /dev/urandom > "$WORK/model.bin"
    cat > "$WORK/config.json" <<'EOF'
{
  "model": "demo-model",
  "temperature": 0.2,
  "max_tokens": 256
}
EOF
    cat > "$WORK/system-prompt.txt" <<'EOF'
You are a sealed demo assistant. Answer tersely.
EOF
    cat > "$WORK/infer.py" <<'PYEOF'
#!/usr/bin/env python3
"""Tiny inference stand-in: proves the child ran by writing a marker file."""
import sys
from pathlib import Path

marker = Path(__file__).resolve().parent / "infer-ran.marker"
marker.write_text("the sealed child ran\n")
print(f"inference complete (marker written: {marker})")
sys.exit(0)
PYEOF
    echo "  created: model.bin ($(wc -c < "$WORK/model.bin") random bytes), config.json, system-prompt.txt, infer.py"

    # Key material.
    if ! expect_ok "keygen" "Development keypair generated" \
        sealrun keygen --private-key "$PRIVKEY" --public-key "$PUBKEY"; then
        echo "FATAL: keygen failed" >&2
        exit 1
    fi

    # Manifest over the three artifacts, then sign it.
    if ! expect_ok "manifest-create" "Unsigned manifest written" \
        sealrun manifest-create --root "$WORK" \
            --artifact model.bin --artifact config.json --artifact system-prompt.txt \
            --release-id demo-v1 --release-seq 1 \
            --output "$MANIFEST_UNSIGNED"; then
        echo "FATAL: manifest-create failed" >&2
        exit 1
    fi
    if ! expect_ok "manifest-sign" "Signed manifest written" \
        sealrun manifest-sign --manifest "$MANIFEST_UNSIGNED" \
            --private-key "$PRIVKEY" --output "$SIGNED"; then
        echo "FATAL: manifest-sign failed" >&2
        exit 1
    fi

    # Baseline: the untouched layout must verify.
    if ! expect_ok "verify (baseline)" "VERIFIED: 3 artifact(s)" \
        sealrun verify --root "$WORK" --manifest "$SIGNED" --public-key "$PUBKEY"; then
        echo "FATAL: baseline verify did not say 'VERIFIED: 3 artifact(s)'" >&2
        exit 1
    fi
}

# ------------------------------------------------------------- case A1
case_a1() {
    clear_screen
    banner "Case A1: tampered artifact (flip one byte of model.bin in a copy)"

    cp -a "$WORK" "$WORK_A1"
    "$PY" - "$WORK_A1/model.bin" <<'PYEOF'
import sys

path = sys.argv[1]
data = bytearray(open(path, "rb").read())
off = len(data) // 2
data[off] ^= 0xFF
open(path, "wb").write(bytes(data))
print(f"flipped byte at offset {off} of {path} ({len(data)} bytes)")
PYEOF
    rm -f "$WORK_A1/$MARKER"

    local ok=1 out rc

    echo "-- verify: original signed manifest against the TAMPERED copy --"
    out=$(sealrun verify --root "$WORK_A1" --manifest "$SIGNED" --public-key "$PUBKEY" 2>&1); rc=$?
    printf '%s\n' "$out" | sed 's/^/  | /'
    if [ "$rc" -eq 0 ] || ! printf '%s' "$out" | grep -qF "artifact integrity mismatch: model.bin"; then
        echo "  -> FAIL: verify did not refuse with 'artifact integrity mismatch: model.bin' (exit $rc)"
        ok=0
    else
        echo "  -> ok: verify refused (exit $rc) with 'artifact integrity mismatch: model.bin'"
    fi

    echo "-- launch: would run: python3 $WORK_A1/infer.py --"
    out=$(sealrun launch --root "$WORK_A1" --manifest "$SIGNED" --public-key "$PUBKEY" \
            -- python3 "$WORK_A1/infer.py" 2>&1); rc=$?
    printf '%s\n' "$out" | sed 's/^/  | /'
    if [ "$rc" -eq 0 ] || ! printf '%s' "$out" | grep -qF "artifact integrity mismatch: model.bin"; then
        echo "  -> FAIL: launch did not refuse with 'artifact integrity mismatch: model.bin' (exit $rc)"
        ok=0
    else
        echo "  -> ok: launch refused (exit $rc) with 'artifact integrity mismatch: model.bin'"
    fi

    if [ -e "$WORK_A1/$MARKER" ]; then
        echo "  -> FAIL: marker file appeared; the tampered child RAN"
        ok=0
    else
        echo "  -> ok: no $MARKER anywhere in the copy; the child never ran"
    fi

    [ "$ok" -eq 1 ]
}

# ------------------------------------------------------------- case A2
case_a2() {
    clear_screen
    banner "Case A2: tampered manifest (one hex digit changed in the first artifact sha256)"

    cp "$SIGNED" "$MANIFEST_A2"
    "$PY" - "$MANIFEST_A2" <<'PYEOF'
import json, sys

path = sys.argv[1]
obj = json.load(open(path, encoding="utf-8"))
art = obj["payload"]["artifacts"][0]
old = art["sha256"]
new = "1" if old[0] != "1" else "2"
art["sha256"] = new + old[1:]
open(path, "w", encoding="utf-8").write(json.dumps(obj, indent=2, sort_keys=True) + "\n")
print(f"changed one hex digit in {art['path']}.sha256: {old[:1]} -> {new} (rest unchanged)")
PYEOF

    echo "-- verify: tampered manifest copy against the pristine work dir --"
    expect_refused "A2" "manifest signature invalid" \
        sealrun verify --root "$WORK" --manifest "$MANIFEST_A2" --public-key "$PUBKEY"
}

# ------------------------------------------------------------- case A6
case_a6() {
    clear_screen
    banner "Case A6: forged finish (hand-appended event with event_hash = 64 zeroes)"

    local n
    for n in 1 2 3; do
        if ! expect_ok "audit-append $n" "Audit event appended: seq=$n" \
            sealrun audit-append --journal "$JOURNAL" \
                --event-type verify --detail "demo event $n"; then
            echo "  -> FAIL: audit-append $n failed"
            return 1
        fi
    done

    echo "-- control: the pristine 3-event journal must verify --"
    if ! expect_ok "audit-verify (control)" "AUDIT OK: 3 event(s)" \
        sealrun audit-verify --journal "$JOURNAL"; then
        echo "  -> FAIL: the pristine journal did not verify"
        return 1
    fi

    cp "$JOURNAL" "$JOURNAL_A6"
    "$PY" - "$JOURNAL_A6" <<'PYEOF'
import json, sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    events = [json.loads(line) for line in f.read().splitlines() if line.strip()]
last = events[-1]
forged = {
    "seq": last["seq"] + 1,
    "event_type": "v2_finish",
    "detail": json.dumps({"forged": "hand-appended finish event"}, sort_keys=True,
                         separators=(",", ":")),
    "previous_hash": last["event_hash"],
    "event_hash": "0" * 64,
}
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")
print(f"hand-appended forged finish event: seq={forged['seq']} "
      f"previous_hash={forged['previous_hash'][:16]}... event_hash={'0' * 64}")
PYEOF

    echo "-- audit-verify: the journal copy with the forged finish appended --"
    expect_refused "A6" "audit event hash mismatch at sequence" \
        sealrun audit-verify --journal "$JOURNAL_A6"
}

# ---------------------------------------------------------------- main
check_prereqs
setup
pause

case_a1; r1=$?
pause

case_a2; r2=$?
pause

case_a6; r3=$?
pause

clear_screen
banner "Summary"
echo "CASE A1 (tampered artifact, child must never run): $([ $r1 -eq 0 ] && echo PASS || echo FAIL)"
echo "CASE A2 (tampered manifest, one hex digit):        $([ $r2 -eq 0 ] && echo PASS || echo FAIL)"
echo "CASE A6 (forged finish, 64-zero event_hash):       $([ $r3 -eq 0 ] && echo PASS || echo FAIL)"

if [ "$r1" -eq 0 ] && [ "$r2" -eq 0 ] && [ "$r3" -eq 0 ]; then
    echo
    echo "ALL 3 CASES PASS"
    exit 0
fi
echo
echo "FAILURES PRESENT: $((r1 != 0) + (r2 != 0) + (r3 != 0)) case(s) failed"
exit 1
