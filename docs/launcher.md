# Privileged launcher: consuming verified artifact handles

## The gap this closes

`aiguard verify` proves a signed manifest, then exits. A caller that
subsequently launches the model **by path** has to reopen the artifact
files. Between the verification and those opens there is a
check-to-use window: anyone with write access to the artifact tree can
swap the bytes, and the model runs on attacker-chosen input while the
verification record still looks clean.

`aiguard launch` removes the reopen. It runs the same verification
in-process, keeps the artifact descriptors open, and hands those
descriptors to the launched process. The descriptors pin the inodes that
were hashed, so a path swap after verification cannot change what the
child reads.

This is the "privileged launcher that consumes verified artifact
handles" from the Phase 1 roadmap.

## Usage

```bash
aiguard launch \
  --root demo/artifacts \
  --manifest demo/manifest.signed.json \
  --public-key demo/public.pub \
  -- /usr/bin/python3 train.py --config "$AIGUARD_ARTIFACT_CONFIG_JSON"
```

`--min-release-seq N` applies the same rollback rejection as `verify`.
The command and its arguments follow `--` and are passed through
unchanged. The launcher exits with the child's exit status.

## Environment contract

The child receives the verified provenance alongside descriptors to the
verified bytes:

| Variable | Meaning |
| --- | --- |
| `AIGUARD_MANIFEST_HASH` | SHA-256 over the verified signed envelope |
| `AIGUARD_RELEASE_ID` | `release_id` from the verified payload |
| `AIGUARD_RELEASE_SEQ` | `release_seq` from the verified payload |
| `AIGUARD_ARTIFACT_<P>` | `/proc/self/fd/<N>`, the verified handle for the artifact whose manifest path maps to `<P>` |

`<P>` is the artifact path upper-cased with every run of non-alphanumeric
characters collapsed to a single underscore, so `weights/part-01.ckpt`
becomes `AIGUARD_ARTIFACT_WEIGHTS_PART_01_CKPT`. The mapping is
many-to-one: if two artifact paths would collapse to the same variable
name, the launcher refuses to run rather than guess which is which.

The child reads the descriptor, not the path — e.g. `open(os.environ
["AIGUARD_ARTIFACT_MODEL_BIN"], "rb")`. Because the descriptor is
already open, it also works when the artifact tree is not readable by the
child's user.

## Freezing bytes with `--seal`

An open descriptor pins the *inode*, not its contents. Without `--seal`,
a writer with access to the verified inode can still mutate the file
after it was hashed, and the child would read the new bytes.

`--seal` closes that residual window: each verified artifact is copied
into a sealed `memfd` (`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW |
F_SEAL_SEAL`) before exec. The child reads a frozen snapshot that rejects
`write`, `ftruncate`, and further sealing, regardless of what happens to
the original file. Sealing copies every artifact into RAM, so it is
opt-in; for large models the copy cost is real.

`--seal` needs Linux (and a kernel with `memfd_create` sealing). Without
it the launcher falls back to passing the verified descriptor directly,
which is still immune to path swaps but not to in-place mutation.

## The privilege model

The launcher is meant to be *started* privileged: as root it can read the
trusted public key and the artifact tree, then drop to an unprivileged
user before exec so the model itself never runs with privileged access.

```bash
sudo aiguard launch \
  --root /srv/artifacts --manifest /srv/manifest.signed.json \
  --public-key /etc/aiguard/public.pub \
  --uid model --gid model \
  -- /usr/bin/python3 /srv/train.py
```

`--uid`/`--gid` accept a name or a numeric id. If the caller lacks the
privilege to set them, the launcher fails closed with a clear error and
does **not** run the command. This repository does not ship a setuid
binary; the operator starts the launcher privileged (sudo, systemd,
container entrypoint) and is responsible for that install decision.

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
