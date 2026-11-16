# Antigravity Dogfood Trip Report — v2 Guide (Round 2)

**Date:** 2026-11-16  
**Tester:** Antigravity (Gemini 3.8 Flash High)  
**Branch:** `dogfood/antigravity-v2-guide`  
**Host Environment:** Linux (Arch Linux / Omarchy, kernel 6.x, x86_64), Python 3.14.8, repo `.venv` (Python 3.14.8)  
**Deliverable:** [dogfood/antigravity-round2-trip-report.md](file:///home/gantea/Work/bsv-ai-security/dogfood/antigravity-round2-trip-report.md)  
**Result:** **Blocked at Demo Layout / Step 1** when following the guide as written with `sudo`. In Standard Sandbox Mode, `sudo` is immediately refused by Linux kernel policy (`no_new_privileges`). In Bypass Sandbox Mode, `sudo` blocks on an interactive password prompt (`sudo: a password is required` / `[sudo] password for gantea:`). Without `sudo`, creating `/srv/sealrun-v2-demo` fails with `Permission denied`. All subsequent guide steps (2 through 6) were attempted as written and failed on the same elevation blocker in under 10 ms each. Standalone CLI behavior and underlying code mechanisms (`assert_journal_writer_isolation`) were analyzed using the `.venv` fallback.

---

## Executive Summary

Round 2 tested the updated `v2-user-guide-DRAFT.md`, which incorporated findings from Round 1 (Codex). The draft now includes a prominent warning note stating that `sudo` is required and that environments with `no_new_privileges` cannot run the v2 steps.

However, Round 2 reveals that the current guide structure suffers from an **"over-sudo" architecture**:
1. By mandating that all files—including the workload (`work/`), the signing keys (`keys/`), and the state (`state/`)—live together under `/srv/sealrun-v2-demo/`, the guide forces **every single step** (writing toy python scripts, generating secp256k1 keypairs, creating manifests, signing manifests, and running dry-run publisher) to require `sudo`.
2. In reality, `sealrun`'s security model only requires `euid == 0` for `sealrun launch --mode v2` (and `sealrun bootstrap`), where the launcher verifies artifacts and drops privileges to `--uid nobody`. Steps 1, 2, 3, and 6 are purely unprivileged userland operations that should not require root.
3. The draft install instruction (`pip install sealrun==0.5.0rc1`) continues to fail because the package is not on PyPI, and `sealrun` is not in the system `PATH`.

---

## Step-by-Step Execution Log & Timings

Every command in the guide's setup and Steps 1–6 was executed exactly as written. Timings reflect execution wall-clock time.

| Guide Section / Step | Exact Command Tested | Execution Time | Exit Code | Result & Exact Output |
|---|---|---:|:---:|---|
| **Install** (Primary) | `pip install sealrun==0.5.0rc1` | 0.001 s | 127 | `bash: pip: command not found`. System Python has no `pip`. |
| **Install** (Module check) | `python3 -m pip install sealrun==0.5.0rc1` | 0.033 s | 1 | `/usr/bin/python3: No module named pip`. |
| **Install** (Binary check) | `sealrun --version` | 0.001 s | 127 | `bash: sealrun: command not found`. Binary not installed in system `PATH`. |
| **Install** (`.venv` pip) | `.venv/bin/pip install sealrun==0.5.0rc1` | 8.638 s | 1 | `ERROR: Could not find a version that satisfies the requirement sealrun==0.5.0rc1 (from versions: none)`. Package is not published to PyPI. |
| **Install** (Checkout fallback) | `.venv/bin/python -m sealrun.cli --version` | 0.235 s | 0 | `sealrun 0.5.0rc1`. **Succeeded.** |
| **Demo Layout** (Sandboxed) | `sudo mkdir -p /srv/sealrun-v2-demo/state /srv/sealrun-v2-demo/work /srv/sealrun-v2-demo/keys` | 0.008 s | 1 | `sudo: /etc/sudo.conf is owned by uid 65534, should be 0`<br>`sudo: The "no new privileges" flag is set, which prevents sudo from running as root.` |
| **Demo Layout** (Bypass sandbox) | `sudo mkdir -p /srv/sealrun-v2-demo/...` | Background / Killed | N/A | Prompts interactively for `[sudo] password for gantea:`. Unattended/agent sessions cannot supply interactive passwords. |
| **Demo Layout** (Unprivileged) | `mkdir -p /srv/sealrun-v2-demo/...` | 0.005 s | 1 | `mkdir: cannot create directory ‘/srv/sealrun-v2-demo’: Permission denied`. `/srv` is `drwxr-xr-x root:root`. |
| **Step 1 — Toy AI** (`infer.py`) | `sudo tee /srv/sealrun-v2-demo/work/infer.py > /dev/null <<'EOF'...` | 0.007 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. |
| **Step 1 — Toy AI** (`config.json`) | `sudo tee /srv/sealrun-v2-demo/work/config.json > /dev/null <<'EOF'...` | 0.006 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. |
| **Step 1 — Toy AI** (`system-prompt.txt`) | `sudo tee /srv/sealrun-v2-demo/work/system-prompt.txt > /dev/null <<'EOF'...` | 0.007 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. |
| **Step 2 — Signing Key** | `sudo sealrun keygen --private-key /srv/sealrun-v2-demo/keys/demo.wif --public-key /srv/sealrun-v2-demo/keys/demo.pub` | 0.006 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. (Without sudo into `/srv`: `[Errno 30] Read-only file system: '/srv'` in 0.328 s). |
| **Step 3 — Manifest Create** | `sudo sealrun manifest-create --root /srv/sealrun-v2-demo/work ...` | 0.007 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. |
| **Step 3 — Manifest Sign** | `sudo sealrun manifest-sign --manifest /srv/sealrun-v2-demo/state/manifest.json ...` | 0.005 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. |
| **Step 3 — Verify** | `sudo sealrun verify --root /srv/sealrun-v2-demo/work ...` | 0.005 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. |
| **Step 4 — First v2 Launch (Seeding)** | `sudo sealrun launch --mode v2 --journal /srv/sealrun-v2-demo/state/journal.jsonl --min-release-seq 0 --root /srv/sealrun-v2-demo/work --manifest /srv/sealrun-v2-demo/state/manifest.signed.json --public-key /srv/sealrun-v2-demo/keys/demo.pub --uid nobody -- python3 /srv/sealrun-v2-demo/work/infer.py` | 0.006 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. |
| **Step 5 — Tamper Refusal** (Edit) | `echo "# tampered" \| sudo tee -a /srv/sealrun-v2-demo/work/infer.py > /dev/null` | 0.010 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. |
| **Step 5 — Tamper Refusal** (Launch) | `sudo sealrun launch --mode v2 ...` | 0.006 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. |
| **Step 6 — Anchor Dry Run** | `sudo sealrun publish --journal /srv/sealrun-v2-demo/state/journal.jsonl --anchor-record /srv/sealrun-v2-demo/state/anchor-record.json --mode once` | 0.006 s | 1 | `sudo: The "no new privileges" flag is set...` Blocked. |

---

## Where the Guide Was Wrong or Unclear

### 1. PyPI Install Instruction Conflicts with Project Reality
- **What the guide says:**
  ```bash
  pip install sealrun==0.5.0rc1
  sealrun --version
  ```
- **What happens:** Fails completely. There is no package on PyPI (`AGENTS.md` explicitly notes: *"No PyPI package yet. Python >= 3.10, zero dependencies (stdlib only)"*).
- **Impact:** Any user following the guide verbatim fails on line 50 before doing anything else.
- **Recommendation:** Make the checkout instructions the standard:
  ```bash
  git clone https://github.com/RobGanon/bsv-ai-security.git
  cd bsv-ai-security
  python3 -m venv .venv
  # Use .venv/bin/python -m sealrun.cli (or alias sealrun=".venv/bin/python -m sealrun.cli")
  ```

### 2. Privileges Callout Misdiagnoses Agent Sandboxing
- **What the guide says (lines 34–41):**
  > If you are an AI agent running in a sandboxed session that blocks sudo (the ChatGPT desktop app runs with `no_new_privileges`, for example), you cannot run the v2 steps...
- **Why this is misleading:**
  `no_new_privileges` (`PR_SET_NO_NEW_PRIVS`) is not an idiosyncratic quirk of the ChatGPT desktop app. It is the standard security posture of almost all containerized agent runtimes, sandbox runtimes (Bubblewrap, Docker seccomp, systemd sandboxes), and security monitors across modern Linux desktop and server agents.
- **Furthermore:** Even when the sandbox boundary is bypassed, agent sessions are non-interactive. On standard Linux installations (like Omarchy/Arch here), `sudo` requires a password (`sudo -l` shows `(ALL : ALL) ALL`), so non-interactive agent execution hangs or fails unless explicit `NOPASSWD` entries exist.

### 3. The "Over-Sudo" Architecture in the Demo Layout
- **What the guide says (lines 57–73):**
  > The v2 ownership rule refuses any state path not owned by the launcher. The launcher runs as root (via `sudo`), so the demo tree must be root-owned. That is why this guide uses `/srv`, not your home directory:
  > `sudo mkdir -p /srv/sealrun-v2-demo/state /srv/sealrun-v2-demo/work /srv/sealrun-v2-demo/keys`
- **Why this is architecturally incorrect:**
  Let's look at what the code in [sealrun/core.py](file:///home/gantea/Work/bsv-ai-security/sealrun/core.py#L2390-L2466) actually checks:
  - `assert_journal_writer_isolation` validates the **journal path** (`--journal`) and its directory ancestors. It requires `launcher_euid == 0`, ownership by root, and no group/other write permissions.
  - `assert_checkpoint_cache_isolation` in [sealrun/checkpoint_cache.py](file:///home/gantea/Work/bsv-ai-security/sealrun/checkpoint_cache.py#L549-L590) validates the **checkpoint cache** and **cache key** paths.
  - **Neither check applies to `work/` (the workload) or `keys/` (the manifest keys)!**
  - Artifacts can reside anywhere the launcher has read access. Signing keys can (and should!) be user-owned or offline.
- **Impact:**
  By packaging `work/`, `keys/`, and `state/` under `/srv/sealrun-v2-demo/`, the guide needlessly forces:
  - Creating a simple Python script (`infer.py`) to require `sudo tee`.
  - Creating a keypair (`keygen`) to require `sudo sealrun keygen`.
  - Hashing and signing a manifest (`manifest-create`, `manifest-sign`) to require `sudo sealrun`.
  - Verifying a manifest (`verify`) to require `sudo sealrun`.
  - Dry-running publisher (`publish`) to require `sudo sealrun`.
  This turns an entire 6-step walkthrough into an all-or-nothing root requirement, preventing testers and developers from completing Steps 1–3 and Step 6 unprivileged.

### 4. Poor Security Practice: Sudoing Key Generation and Manifest Signing
- In cryptographic system design, signing keys should never be owned or generated by `root` unless specifically required by hardware/system daemon architecture.
- Recommending `sudo sealrun keygen` produces root-owned private keys (`demo.wif`), which trains operators to manage private keys as root.
- The guide itself notes in line 103: *"Keep the private key private. The public key is what the launcher trusts."* Generating it as root in `/srv` directly contradicts this guidance.

### 5. What Step 4 Actually Requires (Code Reality)
We verified the exact failure mechanism in Python directly:
```python
>>> from pathlib import Path
>>> from sealrun.core import assert_journal_writer_isolation
>>> assert_journal_writer_isolation(Path('/tmp/test-journal.jsonl'), child_uid=65534)
VerificationError: v2 journal isolation requires a privileged launcher (euid 0) that can drop the child to a different uid
```
When `mode == "v2"`, [sealrun/launcher.py](file:///home/gantea/Work/bsv-ai-security/sealrun/launcher.py#L1450) calls `assert_journal_writer_isolation(journal, uid)` before anything else. This check strictly asserts `os.geteuid() == 0`. Therefore, **v2 launch cannot run unprivileged by definition**.

---

## Concrete Recommendations for `v2-user-guide-DRAFT.md`

1. **Decouple the Workload & Keys from `/srv`**:
   Keep user workspaces in standard user directories (e.g. `./demo/work` and `./demo/keys`):
   ```bash
   mkdir -p demo/work demo/keys
   ```
   Steps 1, 2, and 3 can then run completely unprivileged without `sudo`:
   - Step 1: Write `infer.py`, `config.json`, `system-prompt.txt` normally.
   - Step 2: `python3 -m sealrun.cli keygen --private-key demo/keys/demo.wif --public-key demo/keys/demo.pub`
   - Step 3: `python3 -m sealrun.cli manifest-create ...`, `manifest-sign ...`, `verify ...`

2. **Isolate only the State Directory in `/srv` (or `/var/run/sealrun`)**:
   Only the journal, checkpoint cache, and anchor records belong in the root-owned isolated state directory:
   ```bash
   sudo mkdir -p /srv/sealrun-v2-demo/state
   sudo chmod 0755 /srv/sealrun-v2-demo/state
   ```

3. **Limit `sudo` to the Commands That Genuinely Require It**:
   - `sudo sealrun launch --mode v2 ...` (Step 4 & Step 5 launch)
   - `sudo sealrun bootstrap ...` (Step 7)
   Everything else (`manifest-create`, `manifest-sign`, `verify`, `publish --mode once`, `anchor-chain-verify`, `audit-verify`) should be shown without `sudo`.

4. **Address Unprivileged / Development Testing (`--insecure-no-drop` or mock euid)**:
   For development, testing, and CI environments where agents or developers do not have root privileges, consider documenting a test flag or mock mode (such as how the test suite injects `launcher_euid` into `assert_journal_writer_isolation`) so that the v2 launch flow logic can be exercised without requiring root elevation.

---

## Environment & Safety Outcome

- **Repository Branch:** `dogfood/antigravity-v2-guide`
- **Commit History:** Pristine; no commits made to `main`.
- **Remote Operations:** No git push, no pull request opened, no branch merged.
- **Cryptographic / Network Safety:**
  - No mainnet keys were created or handled.
  - No anchor transactions were created or broadcast.
  - No network funds were spent.
