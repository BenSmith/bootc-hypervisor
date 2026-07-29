# ADR 005: `/var` state records the deployment that provisioned it

**Status:** **Implemented** 2026-07-29 (code review 2026-07-26 follow-up, Q1 Gap 1).
`lib/deployment.py` plus a `provenance.json` marker written by
`workload-ensure-user` and read by `cleanup`.

**Date:** 2026-07-29.

## Context

On an ostree/bootc host `/etc` is **per-deployment** and `/var` is **shared by
every deployment**. That split runs straight through a workload:

| lives in `/etc` (per-deployment) | lives in `/var` (shared) |
|---|---|
| the TOML under `workloads.d/<name>/` | `/var/lib/workloads/<name>/data` — precious |
| the `_wl-<name>` line in `passwd` | `…/state` — podman graphroot, VM disks |
| the subordinate range in `subuid`/`subgid` | |

So every piece of a workload's **identity** is per-deployment and every piece of
its **precious state** is shared. `bootc rollback` deletes nothing, and precisely
because it deletes nothing it *manufactures orphans*: it takes a workload's
identity away while the state stays behind.

`cleanup`'s definition of an orphan — "state whose workload has no config at all"
— is then satisfied by state that is not orphaned, merely invisible from where you
happen to have booted. Observed on onepiece 2026-07-28: two workloads present on
the booted deployment and absent from the rollback target, their `/var` trees
owned by UIDs that would not resolve after a rollback. `cleanup --apply` on the
older deployment would have swept live data, and the operator's mental model —
"rollback is the safe direction" — is exactly backwards here.

Nothing in `/var` could distinguish the two cases, because nothing in `/var` said
where it came from.

## Decision

**Make `/var` self-describing.** Each workload root carries a `provenance.json`
naming the deployment that last provisioned it; `cleanup` reads it back before
calling anything an orphan.

`workload-ensure-user` writes it (so it lands on the workload's first start, on
whichever deployment provisioned it), and it sits in the root itself — root-owned,
with `state/` and `data/` below it chowned to the workload user — so a workload
cannot rewrite the stamp that decides whether its own state may be swept.

The resulting rule:

| config present? | marker | verdict |
|---|---|---|
| yes | — | not an orphan *(unchanged)* |
| no | absent | orphan — pre-marker or hand-made state |
| no | deployment == booted | orphan — the config was deleted here |
| no | deployment exists, not booted | **skip** — another deployment's |
| no | deployment gone | orphan — defunct |

Two properties of that table are load-bearing:

- **`== booted` must be an orphan.** Delete a TOML on the booted deployment and
  the marker still names a deployment that exists — the booted one. Without this
  row, cleanup would skip the ordinary "operator removed a config" sweep that is
  the command's whole reason to exist.
- **The marker means *last provisioned*, not *created*.** With create-only
  semantics: a workload created under A, carried forward to B by the `/etc` 3-way
  merge, then deleted under B still names A — and A still exists as the rollback
  target, so again the ordinary sweep is skipped. Rewriting on every ensure-user
  run is what keeps the table honest. Unchanged content is not rewritten, so a
  boot that provisions nothing new does not dirty `/var`.

**Every uncertainty resolves to "we can't say."** No `/ostree` at all (a plain-RPM
host — workloadctl is deliberately bootc-independent), an unreadable or corrupt
marker, a marker naming a different workload, a cmdline that can't be resolved:
each falls back to the behavior `cleanup` had before this module existed. Nothing
here can ever *cause* a sweep, only withhold one. In particular
`deployments_readable()` gates the whole rule, because treating an unreadable
`/ostree` as "every deployment is gone" would invert a missing directory into a
licence to delete `/var`.

## The four ways to get deployment identity wrong

Each of these produces code that looks right, which is why they are recorded
rather than left to be rediscovered:

| trap | reality |
|---|---|
| use the `ostree=` value from `/proc/cmdline` as the id | that is the **boot** checksum. Only the resolved symlink target gives the deployment id |
| identify the booted deployment by inode against `/` | on onepiece `/` is device 36 and the deployment dir is 64512 |
| use `.origin` for identity | both deployments there carry an identical `container-image-reference`; only the csum differs |
| store bootc's `imageDigest` | a different identifier entirely — don't store one and compare the other |

The id is therefore the resolved deployment directory basename,
`<commit-checksum>.<serial>`: `ostree=/ostree/boot.1/default/<BOOT-csum>/0` →
`../../../deploy/default/deploy/<DEPLOY-csum>.0`. Verified on onepiece
2026-07-29.

Existence is checked by globbing `*/deploy/<id>` rather than hardcoding the
`default` stateroot. The stateroot is a real variable, and hardcoding it is
correct on a one-stateroot host and quietly wrong on a two-stateroot one. This
matters *because* `/var` may be shared across stateroots: a separate `/var`
filesystem is a normal bootc layout (onepiece mounts `/dev/mapper/os-var` at
`/var`), and this repo prescribes neither layout — it ships an empty kickstart so
partitioning stays an interactive choice. The glob is correct under both.

## Deliberately not in the marker

**The workload's UID and subordinate range.** They are *derivable*: the owning UID
of `<root>/data` **is** the answer, one `stat` away, and the subordinate range is
derived from the UID (`600100000 + (uid - UID_MIN) * 65536`). A copy in a file
could only go stale and would compete with `/etc/subuid` as a second source of
truth.

The rollback hazard those fields would have addressed — passwd-absent but
`/var`-present, so re-enabling allocates a *fresh* UID that re-points the derived
range onto a tree owned by the old one — is real, and is handled where it belongs,
by `claim_uid()` in `lib/workload_lib.py` adopting the existing owner at
allocation time.

## Consequences

- `cleanup` gains a fourth output section, **"State from another deployment — not
  swept"**; to remove that state for good, boot that deployment and
  `disable --purge` there. Documented under `cleanup` in `docs/cli.md`.
- A new root-owned file appears in every workload root. It is **not** a workload
  run-file: run-files live in `/run` and are removed on `disable`, whereas the
  removable view of that set is "every kind but `env-file`" — so joining it would
  make a plain `disable` unlink the provenance of state that plain `disable`
  exists to leave untouched. `drift` also has nothing to diff it against, being
  runtime-written and host-specific. `status --json`'s `state_deployment` key is
  how it stays discoverable instead.
- **Known residual, unverified.** If a pruned commit is deployed again, the same
  `<csum>.<serial>` directory name is expected to reappear and revive a marker
  that pointed at the pruned deployment. The effect is a *skip* of state that
  could have been swept — it errs toward never deleting, which is the safe
  direction. Confirming it needs two deployments of one commit on a real host.
