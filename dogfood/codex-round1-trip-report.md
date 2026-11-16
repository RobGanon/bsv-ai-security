# Codex dogfood trip report — v2 guide

**Date:** 2026-11-16  
**Branch:** `dogfood/codex-v2-guide`  
**Result:** Stopped before Step 1 could create the demo tree. The session cannot elevate to root, which the guide requires for its `/srv` setup and v2 launch. No demo key, manifest, journal, or anchor payload was created.

## Step-by-step

| Guide step | Result | Time spent |
|---|---|---:|
| Install | Tried the checkout install with `.venv/bin/python -m pip install -e .`; pip could not fetch the isolated build requirement `setuptools>=68` because this environment cannot resolve PyPI. The existing checkout runtime does work: `.venv/bin/python -m sealrun.cli --version` returned `sealrun 0.5.0rc1`. | 9.7 s for pip; under 1 s for version check |
| 1 — Toy AI and demo layout | Tried the guide's `sudo mkdir -p /srv/sealrun-v2-demo/{state,work,keys}` setup. `sudo` exited in 0.4 s: `/etc/sudo.conf` is owned by uid 65534, and the session has `no new privileges`. No demo files were written. | 0.4 s to hit blocker |
| 2 — Signing key | Not attempted; blocked on the inaccessible demo layout. | 0 s (not attempted) |
| 3 — Manifest create, sign, verify | Not attempted; blocked on Steps 1–2. | 0 s (not attempted) |
| 4 — First v2 launch | Not attempted; the guide requires `sudo` and a root-owned state tree. | 0 s (not attempted) |
| 5 — Tamper refusal | Not attempted; there was no successful launch or signed workload to tamper with. | 0 s (not attempted) |
| 6 — Anchor dry run | Not attempted; there was no journal from Step 4. No broadcast was attempted. | 0 s (not attempted) |

Times above are command wall times returned by the execution tool; they do not include reading the guide or diagnosing the environment.

## Where the guide or workflow needs attention

- **Install instructions conflict with repository instructions.** The draft starts with `pip install sealrun==0.5.0rc1`; `AGENTS.md` says there is no PyPI package and directs users to install from the checkout. The draft does give a checkout fallback, but doesn't explain that this requires a working local Python environment. The existing `.venv` could run the module, while a fresh editable install attempted an isolated PyPI fetch and failed offline on `setuptools>=68`.
- **The guide is not runnable in a restricted container without root elevation.** It correctly says `sudo` is required, but this session's container policy disables elevation (`no new privileges`). Because the guide also requires root-owned state under `/srv`, the failure occurs before the toy workload can be created. A dedicated container/VM with working `sudo` is needed to dogfood the rest of the flow.
- **The checkout fallback was usable for the version check.** `.venv/bin/python -m sealrun.cli --version` returned the expected version without network access; the guide could state how to prepare that checkout environment when its packaged install path is unavailable.

## What I used and safety outcome

- Repository checkout on `dogfood/codex-v2-guide`, with its `.venv` Python and `sealrun` module.
- `sudo` for the exact demo-directory creation attempt; it was rejected by the container's privilege policy.
- No manifest key or anchor key was generated. No mainnet key was created. No transaction was broadcast, no money was spent, and no files were committed or pushed.
