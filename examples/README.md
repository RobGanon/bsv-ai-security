# SealRun demo — three tamper cases

`run-demo.sh` proves SealRun catches tampering, in three cases:

- **A1 — tampered artifact:** one flipped byte in `model.bin` (in a copy of
  the work dir). `verify` AND `launch` both refuse with
  `artifact integrity mismatch: model.bin`, and the launch child never
  runs (its marker file never appears).
- **A2 — tampered manifest:** one changed hex digit inside the first
  artifact sha256 of a copy of the signed manifest. `verify` refuses
  with `manifest signature invalid`.
- **A6 — forged finish:** a copy of a healthy 3-event audit journal, with
  a hand-appended forged finish event (`event_hash` = 64 zeroes).
  `audit-verify` fails with `audit event hash mismatch at sequence 4`.

The script builds its own layout under `~/sealrun-demo` (override with
`SEALRUN_DEMO`) and invokes the sealrun CLI from the repo. No network,
no sudo, nothing outside the demo dir is touched.

## Run it

Prerequisite: a Python virtualenv in the repo (the script runs the CLI
as `.venv/bin/python -m sealrun.cli`).

```bash
git clone https://github.com/RobGanon/bsv-ai-security
cd bsv-ai-security
python3 -m venv .venv
```

Then run the demo. It pauses between cases for video recording — press
Enter to advance, or pipe newlines to run straight through:

```bash
bash examples/run-demo.sh
```

```bash
printf '\n\n\n\n' | bash examples/run-demo.sh
```

Expected output:

```
CASE A1 (tampered artifact, child must never run): PASS
CASE A2 (tampered manifest, one hex digit):        PASS
CASE A6 (forged finish, 64-zero event_hash):       PASS

ALL 3 CASES PASS
```

## Options

- `SEALRUN_REPO` — path to the repo (default `$HOME/Work/bsv-ai-security`).
- `SEALRUN_DEMO` — where the demo layout is built (default
  `$HOME/sealrun-demo`).

```bash
SEALRUN_REPO=/path/to/bsv-ai-security SEALRUN_DEMO=/tmp/sealrun-demo \
  bash examples/run-demo.sh
```
