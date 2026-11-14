# High-assurance launch profile

The strongest launch configuration SealRun offers: verify the manifest,
refuse anything but v2, freeze the artifacts, and execute the verified
binary itself.

## The command

```bash
sealrun launch --root <root> --manifest <manifest> --public-key <pubkey> \
  --mode v2 --require-v2 --seal --executable-binding verified \
  --journal <journal> --min-release-seq <seq> --checkpoint-cache <cache> \
  -- <command...>
```

## What each flag establishes

- `--mode v2` — strict journal events and the v2 acceptance rules:
  rollback protection from `--min-release-seq` and the checkpoint cache.
- `--require-v2` — refuse to launch unless `--mode v2` is used. A v1
  invocation is refused at invocation time, so a deployment configured
  for v2 cannot silently run v1.
- `--seal` — each artifact is copied into a sealed `memfd` before exec,
  so the child reads a frozen snapshot. Without it, an open descriptor
  pins the *inode*, not its contents: a writer with access to the
  verified inode could still mutate the file after it was hashed.
  Sealing copies every artifact into RAM, so it is opt-in.
- `--executable-binding verified` — the executable is a manifest artifact
  run through its verified descriptor with Linux
  `execveat(AT_EMPTY_PATH)`, and the launch record names that artifact on
  its own. Requires `--mode v2`. `argv[0]` must match a manifest artifact
  path exactly, or the artifact must be named with
  `--executable-artifact`. Verified mode refuses — never downgrades to
  pathname execution — when the artifact is not an ELF, when `execveat`
  is unavailable, or when a sealed memfd could not be executed because
  `vm.memfd_noexec` is 1 or 2.

## Optional additions

- `--uid` / `--gid` — drop privilege before exec.
- `--cache-key` — the deployment key file that authenticates the
  checkpoint cache records (default: `<cache-dir>/cache.key`).

## Prerequisites

- v2 needs a seeded journal and a checkpoint cache. Bootstrap refuses
  unseeded journals, so seed first.
- `--seal` needs Linux with `memfd_create` sealing, and `vm.memfd_noexec`
  must be 0.
- Verified binding is Linux-only and ELF-only. Scripts and interpreters
  stay record-only.

## What it does not establish

Stated plainly, because a launcher that overclaims is worse than none:

- The dynamic loader, the interpreter (e.g. `/lib64/ld-linux-*`), and
  every shared library still load by path. A loader-path swap or
  `LD_PRELOAD` is outside the claim.
- It does not sandbox the child. It pins *what bytes are launched*;
  containment (namespaces, seccomp, cgroups, resource limits) is out
  of scope.
- A swap of an *intermediate directory* component between the
  manifest's per-component walk and the open remains a narrow race.
  Artifact opens use `O_NOFOLLOW` on the final component plus an
  `fstat` check; closing the directory race fully needs opening each
  component with `O_NOFOLLOW`.
- Truncating the checkpoint cache to an older internally-valid signed
  prefix is undetectable without an external trusted high-water mark.
- The child's own behaviour is not constrained. A model that reads a
  different, unverified file by its own path is outside the launcher's
  reach.
- Anchoring proves history integrity and existence, not truthfulness.

## Why this is opt-in, not the default

The defaults are v1, record-only executable binding, and no seal — by
design. v1 is preserved exactly, and the v2 launch flow is an explicit
per-launch opt-in. This profile is the deliberate choice for a
deployment that wants the strongest guarantee; changing the defaults
would be a design decision, not a fix.

See [`docs/launcher.md`](launcher.md) for the full `launch` contract
and [`docs/anchoring-protocol.md`](anchoring-protocol.md) for the
journal, checkpoint cache, and anchoring layer.
