# Privileged launcher: consuming verified artifact handles

## The gap this closes

`sealrun verify` proves a signed manifest, then exits. A caller that
subsequently launches the model **by path** has to reopen the artifact
files. Between the verification and those opens there is a
check-to-use window: anyone with write access to the artifact tree can
swap the bytes, and the model runs on attacker-chosen input while the
verification record still looks clean.

`sealrun launch` removes the reopen. It runs the same verification
in-process, keeps the artifact descriptors open, and hands those
descriptors to the launched process. The descriptors pin the inodes that
were hashed, so a path swap after verification cannot change what the
child reads.

This is the "privileged launcher that consumes verified artifact
handles" from the Phase 1 roadmap.

## Usage

```bash
sealrun launch \
  --root demo/artifacts \
  --manifest demo/manifest.signed.json \
  --public-key demo/public.pub \
  -- /usr/bin/python3 train.py --config "$SEALRUN_ARTIFACT_CONFIG_JSON"
```

`--min-release-seq N` applies the same rollback rejection as `verify`.
The command and its arguments follow `--` and are passed through
unchanged. The launcher exits with the child's exit status.

## What is bound to the manifest — and what is not

The launcher guarantees the bytes behind the descriptors it passes
to the child: each one matches the signed manifest, and the child
also receives the verified manifest hash. The command after `--`
is the operator's choice, passed through unchanged — by default the
launcher does not require the executed program to be one of the manifest
artifacts, and it cannot vouch for code the child loads outside
those descriptors (an interpreter's own libraries, for example).
Operators who want a script or executable itself pinned can list
it as a manifest artifact and either check the verified copy the child
receives, or opt in to `--executable-binding verified` (below).
Deciding what to run remains the operator's responsibility.

## Executable binding (`--executable-binding`)

By default the executable is **record-only**: the v2 launch record names
the command as given, the effective `PATH`, and every `PATH` candidate
the launcher considered. It deliberately does not claim which candidate
`execvp` used, because the launcher cannot observe that, and it makes no
claim about the executed bytes.

`--executable-binding verified` (v2 only) makes the narrower claim that
the **main ELF image** is a manifest artifact, executed from its verified
descriptor with Linux `execveat(AT_EMPTY_PATH)`. The launch record names
that artifact, its SHA-256, and the descriptor on its own — not by
inferring it from `argv[0]` or from the data-channel list. `argv[0]`
must match a manifest artifact path exactly, or the artifact must be
named explicitly with `--executable-artifact`; ambiguity is refused,
never guessed.

This claim is intentionally narrow:

- It is Linux-only and ELF-only. Scripts and interpreters stay
  record-only unless proven per interpreter; a script would be handed to
  its interpreter by path, which reopens the file.
- For a dynamically linked ELF, the dynamic loader, the interpreter
  (e.g. `/lib64/ld-linux-*`), and every shared library still load by
  path. A loader-path swap or `LD_PRELOAD` is outside the claim.
- In verified mode, `execveat` unavailable or failing means the launch
  is **refused**, never downgraded to pathname execution.
- A sealed memfd is executable only when `vm.memfd_noexec` is 0. With
  `--seal`, verified binding refuses if that sysctl is 1 or 2 instead of
  silently falling back.
- The artifact's inode must carry an execute bit, as with any exec.

## Environment contract

The child receives the verified provenance alongside descriptors to the
verified bytes:

| Variable | Meaning |
| --- | --- |
| `SEALRUN_MANIFEST_HASH` | SHA-256 over the verified signed envelope |
| `SEALRUN_RELEASE_ID` | `release_id` from the verified payload |
| `SEALRUN_RELEASE_SEQ` | `release_seq` from the verified payload |
| `SEALRUN_ARTIFACT_<P>` | `/proc/self/fd/<N>`, the verified handle for the artifact whose manifest path maps to `<P>` |

`<P>` is the artifact path upper-cased with every run of non-alphanumeric
characters collapsed to a single underscore, so `weights/part-01.ckpt`
becomes `SEALRUN_ARTIFACT_WEIGHTS_PART_01_CKPT`. The mapping is
many-to-one: if two artifact paths would collapse to the same variable
name, the launcher refuses to run rather than guess which is which.

The child reads the descriptor, not the path — e.g. `open(os.environ
["SEALRUN_ARTIFACT_MODEL_BIN"], "rb")`. Because the descriptor is
already open, it also works when the artifact tree is not readable by the
child's user.

## Freezing bytes with `--seal`

An open descriptor pins the *inode*, not its contents. Without `--seal`,
a writer with access to the verified inode can still mutate the file
after it was hashed, and the child would read the new bytes.

`--seal` prevents that residual window: each verified artifact is copied
into a sealed `memfd` (`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW |
F_SEAL_SEAL`) before exec. The child reads a frozen snapshot that rejects
`write`, `ftruncate`, and further sealing, regardless of what happens to
the original file. Sealing copies every artifact into RAM, so it is
opt-in; for large models the copy cost is real.

`--seal` needs Linux (and a kernel with `memfd_create` sealing). Without
it the launcher refuses to launch when sealing is requested, rather than
falling back to passing the verified descriptor directly. Without --seal,
the launcher passes the verified descriptor directly, which is still
immune to path swaps but not to in-place mutation.

## The privilege model

The launcher is meant to be *started* privileged: as root it can read the
trusted public key and the artifact tree, then drop to an unprivileged
user before exec so the model itself never runs with privileged access.

```bash
sudo sealrun launch \
  --root /srv/artifacts --manifest /srv/manifest.signed.json \
  --public-key /etc/sealrun/public.pub \
  --uid model --gid model \
  -- /usr/bin/python3 /srv/train.py
```

`--uid`/`--gid` accept a name or a numeric id. If the caller lacks the
privilege to set them, the launcher fails closed with a clear error and
does **not** run the command. Two details matter for a real drop:

- `--uid` without `--gid` defaults the group to the target user's primary
  group, so dropping the uid does not silently keep the caller's (root's)
  group. A uid with no passwd entry has no safe default and requires an
  explicit `--gid`.
- When the launcher is privileged it also clears the supplementary group
  list before exec, rather than leaving the child in root's groups.

This repository does not ship a setuid binary; the operator starts the
launcher privileged (sudo, systemd, container entrypoint) and is
responsible for that install decision.

## Journal durability and size

V2 launches write `v2_launch` / `v2_finish` / `v2_launch_failed` events to
the hash-chained journal. Three properties matter for the run-state claim:

- **The launch event is durable before exec.** Creating a journal also
  fsyncs its directory, so the directory entry naming a newly created
  journal cannot disappear in a crash after the append returned.
- **Prior events are read from the locked descriptor.** The append does
  not re-open the path to re-verify the chain, and the journal directory
  plus inode are pinned during the §5.7 isolation check. A journal renamed
  over the path after that check is refused, not extended.
- **A complete final JSON object is an event even without a trailing
  newline.** Only an unterminated *incomplete* JSON object is a fragment.
  Anchor prefix comparison verifies the complete-event chain and reports
  the fragment separately; the strict verifier still refuses it, and
  appending to a journal without a final newline is refused.

The launch record includes the descriptor channel list: artifact path →
`SEALRUN_ARTIFACT_*` variable → SHA-256 → file descriptor. When the full
list fits in the 4 KiB event-detail limit it is recorded inline. Otherwise
the canonical bytes are written to a side file in the isolated journal
directory before the launch event, using `O_CREAT|O_EXCL|O_NOFOLLOW`, and
both the file and its directory are fsynced. The launch event then commits
the side file's bare filename and SHA-256.

The side file is a second store and is subject to the same isolation
predicate as the journal: it must not be child-writable, group/world
writable, or an ACL-bearing path. If it is later deleted, verification
reports the map **missing**; it is never reconstructed from the hash,
because the hash cannot recover the channel list.

**Operating limit.** Every append re-reads and re-verifies the whole
journal, so the mandatory pre-exec launch write costs O(n) before every
exec. On the reference host an append took 1.25 s and 113 MB RSS at
100,000 events, 3.8 s and 302 MB at 300,000, and extrapolates to roughly
13 s and 1 GB near the 1,000,000 hard cap. The practical operating limit
is therefore **100,000 events** per journal, not the hard cap. Rotate or
compact the journal (or start a new one) before then. A v2 launch also
refuses when fewer than two slots remain at the hard cap, so the launch
and its finish event cannot straddle the cliff and turn a completed run
into a permanently "incomplete" one.

## Security clarifications

A successful launch verification does NOT prove everything the AI subsequently did. Handing verified descriptors to a process does NOT prove the process consumed them. A locally valid journal is NOT by itself proof of current state. A launch+finish journal record is NOT by itself proof that a run completed — it is proof only when (a) the terminal event is inside an authenticated prefix (pin/anchor covering that sequence, §6.5), AND (b) the journal's writer is the trusted launcher alone, enforced by journal-writer isolation (§5.7) — because a pin/anchor authenticates a prefix hash, not the truth or authorship of later events, and a forged finish after the latest pin passes pin comparison while a forged finish before the next pin is faithfully committed by an honest publisher. Chain integrity and freshness are NOT event authenticity.

## Bootstrapping the anchored checkpoint (online, deployment time)

A v2 launch is offline: it reads a cached release checkpoint and makes no
network call. The cache is populated once at deployment time, while the
network is available, by `sealrun bootstrap` (alias
`sealrun checkpoint-bootstrap`). That command authenticates the anchor
chain with the full anchor-only predicate — payload binding, the anchor
transaction signature, real block inclusion (SPV, BUMP, or mined BEEF;
ancestry-only BEEF never counts), and the header walk back to an
operator-pinned block checkpoint.

The recorded value is not the anchor's claimed number on trust. It is
re-derived as the maximum `release_seq` over **bound** `manifest_accepted`
events inside the anchored prefix, using the signed manifests and their
trusted public key. Launch, finish, and launch-failed events never
advance the checkpoint. If the anchored prefix contains an acceptance
that cannot be re-derived from a verified manifest, bootstrap refuses
rather than counts it.

The cache is a second trust store and follows the same §5.7 placement
rules as the journal: the deployment must be privileged, the child uid
must be explicit and different from the cache owner, the cache directory
must already exist, no path may be child-owned, group/world-writable, or
ACL-bearing, and the filesystem must enforce local ownership (NFS/FUSE
and unknown types refuse). The cache is written append-only with a
contiguous `checkpoint_seq` and non-decreasing `release_seq` /
`anchor_end_seq`.

```bash
sudo sealrun bootstrap \
  --journal /srv/sealrun/audit.jsonl \
  --checkpoint-cache /srv/sealrun/checkpoint.jsonl \
  --genesis-txid <trusted-genesis-txid> \
  --anchor /srv/sealrun/anchor-1.json \
  --manifest /srv/sealrun/manifest.signed.json \
  --public-key /etc/sealrun/public.pub \
  --anchor-pubkey <trusted-anchor-pubkey> \
  --spv \
  --checkpoint-hash <pinned-block-hash> \
  --checkpoint-height <height> \
  --uid model
```

**Rollback limits.** The append-only cache with its monotonic sequence
detects an *appended* older checkpoint and refuses it. Truncating the
cache back to an older, internally valid prefix is **not detectable**
from the cache alone: without an external trusted high-water mark
(another append-only store, a published anchor, or an operator-pinned
value kept outside the child's reach) an attacker who can rewrite the
cache file can present an earlier valid prefix as current. This is a
stated residual, not a property the local cache can provide. Keep the
cache on storage the child and its uid cannot write, and treat an
external record of the latest anchored checkpoint as the high-water
mark when that threat is in scope.

## What this does not fix

Stated plainly, because a launcher that overclaims is worse than none:

- **It does not sandbox the child.** It pins *what bytes are launched*;
  containment (namespaces, seccomp, cgroups, resource limits) is out of
  scope.
- **An intermediate-directory swap remains a narrow race.** Artifact
  opens use `O_NOFOLLOW` on the final component and an `fstat` check, but
  a swap of a *directory* component between the manifest's per-component
  walk and the open is not closed here. Closing it fully needs opening
  each component with `O_NOFOLLOW`.
- **Without `--seal`, in-place mutation wins.** Descriptors pin the
  inode, not the bytes; `--seal` is the fix.
- **The child's own behaviour is not constrained.** A model that reads a
  different, unverified file by its own path is outside the launcher's
  reach. The launcher guarantees what *it* hands over is verified, not
  that the child uses only those descriptors.
