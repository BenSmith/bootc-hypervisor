> **Superseded.** This document describes the `--cgroups=split` + `Delegate=yes`
> design (option 1 in ADR 001). That design was replaced by option 1b
> (`user@<uid>.service` slice redirect) in Stage 1 on 2026-06-11. See
> [`docs/adr/001-container-cgroup-placement.md`](adr/001-container-cgroup-placement.md)
> for the current architecture. This file is kept for historical context.

# Review: resource caps via `--cgroups=split`

**Branch:** `resource-caps-split` · **Reviewed:** 2026-06-06 · **Reviewer:** code review pass

This is a post-implementation review of the work that makes container workloads
actually respect their `[resources]` limits, plus the follow-on fixes that were
needed to keep `exec`/`shell` and health checks working once the cgroup layout
changed.

> **Scope note.** The prompt framed this as "resource constraints *and*
> very-tightly scoped SELinux". This branch contains **only** the resource /
> cgroup-split / health work — there are no SELinux changes in the diff against
> `main` (that work lives on `selinux-per-workload-types`). This review covers
> what is on this branch.

## TL;DR

The core change is small and correct: two lines in the generator
(`--cgroups=split` + `Delegate=yes`) make systemd's resource directives bind to
the container's cgroup instead of being silently ignored. **It is not
over-engineered** — the surrounding machinery (cgroup-placed `exec`, the
system-manager health timer) is *inherent complexity* forced by cgroup v2's
cross-cgroup migration rules, not gold-plating.

One real **functional gap** and two **behavioural changes** are worth knowing
about; all are now reflected in the docs. The most important is that **pod-mode
workloads get no per-unit resource enforcement** — a limitation, not a bug, but
one the docs previously implied did not exist.

## What the branch does

| Commit | Change |
|--------|--------|
| `96e8d2a` | Add `--cgroups=split` + `Delegate=yes` to single/bridge units so resource directives bind the container cgroup. |
| `1ac0836` | `workloadctl exec/shell` now joins the container's delegated cgroup before dropping privileges (`lib/cgroup_exec.py`), because a plain `sudo -u` can no longer exec into a split container. |
| `353c528`, `643b3e2`, `88cab80` | Health checks: podman's own `--user` healthcheck timer can't exec into a split container, so the generator emits a system-manager `workload-<name>-health.timer` → `libexec/workload-healthcheck`, and pins podman's own `--health-on-failure` to `none`. |
| `ca1fad9`, `8d6d24c` | Avahi interface scoping + forgejo VM resilience (incidental). |

### The root cause, in one paragraph

cgroup v2 only lets a process move into a sibling cgroup if it already sits
inside the delegated subtree. Without `--cgroups=split`, conmon migrates the
container into a transient scope under `user@<uid>.service`, so (a) the unit's
`MemoryMax`/`CPUQuota`/etc. never bind, and (b) anyone outside that subtree
(`sudo -u`, podman's user-manager health timer) gets `EPERM` trying to exec in.
Split keeps the payload under `workloads.slice/workload-<name>.service`; the
exec/health helpers then park themselves in a uid-owned leaf of that unit cgroup
before dropping privileges.

## Over-engineering assessment

**Verdict: justified complexity, not over-engineering.** Specifics:

- **`lib/cgroup_exec.py` (leaf cgroup + privilege drop without PAM).** Necessary.
  The leaf is required by the cgroup v2 "no internal processes" rule (the unit
  cgroup already has a `libpod-payload-*` child, so it can't hold processes
  directly), and the leaf must be *owned* by the workload uid so the dropped-priv
  crun can migrate out of it. The `mkdir`/`chown`/`rmdir` dance is the minimum
  that works. Sharing this module between the CLI and the libexec (rather than
  copy-pasting) is the right call and is covered by `test_exec_cgroup.py`.

- **System-manager health timer (`workload-healthcheck`).** This *reimplements*
  podman's probe-and-act loop, which feels heavy, but there is no lighter option:
  systemd can't probe container health itself, and podman's own timer is broken
  under split. The implementation correctly delegates the verdict to
  `podman healthcheck run` (so `--health-retries`/`--health-start-period` still
  apply) and only adds the on-failure *action*. Always-exit-0 and the
  `BindsTo=`/`Wants=` wiring are appropriate.

- **Generator additions.** Gated cleanly on `mode != "pod"` and `split_health`;
  pod mode is left on podman's working path. Good.

### Smaller things worth a look (low priority)

1. **Duplicated "inspect → locate cgroup → place → fall back" flow.** It appears
   twice: `WorkloadManager.run_podman_exec` (bin/workloadctl) and `main()`
   (libexec/workload-healthcheck). They differ only in *how* they run podman as
   the user (`self.run_podman` vs `sudo -u`). Could be consolidated into one
   helper in `cgroup_exec.py` taking a "run podman as user" callable. Not urgent
   — both are small and well-commented — but it's the one spot that can drift.

2. **`exec`/`shell` run with a minimised environment.** `cgroup_placed_podman`
   builds `env` from scratch (`XDG_RUNTIME_DIR`, `HOME`, `PATH`, `TERM`) and
   passes it as the *complete* environment, whereas the old `sudo -E` path
   inherited the caller's env. Interactive shells now lose `LANG`/`LC_*`, which
   can degrade UTF-8 rendering in `workloadctl shell`. Cosmetic; add the locale
   vars to `extra_env` if it bites.

## Findings reflected in the docs

### 1. Pod-mode resource limits do not bind (functional gap)

`--cgroups=split` is skipped for pod members (podman rejects it). The
consequence — **not previously documented** — is that a pod-mode workload's
`[resources]` directives are emitted into the member units but never bind, which
is exactly the bug split fixes for single/bridge. Because the pod cgroup lives
under the user manager rather than the unit, the pod's containers likely also
escape the `workloads.slice` aggregate ceiling (worth confirming on a live host
— it follows from the same mechanism). Net: **per-workload memory/CPU caps are
not enforced for pod-mode workloads.**

- *Recommendation:* keep it documented as a limitation (done), and if pod-mode
  enforcement is ever needed, investigate parenting the pod cgroup under the
  unit (e.g. `podman pod create` cgroup options) rather than per-member split.

### 2. `on_failure` semantics changed under split (behavioural)

Under split, the action is taken by `workload-healthcheck` via a `systemctl`
verb on the unit, not by podman. So:

| `on_failure` | Old (podman) | New (split) |
|--------------|--------------|-------------|
| `kill`    | kill container → systemd `Restart=on-failure` restarts | `systemctl restart` (same net effect) |
| `restart` | podman-level restart, no systemd involvement | `systemctl restart` |
| `stop`    | stop container → exit non-zero → systemd restarts | `systemctl stop` — **unit stays down** |

The `kill`/`restart` distinction collapses, and `stop` now means "stay down"
rather than "stop then restart". The new `stop` behaviour is arguably more
intuitive, but it diverges from what the schema doc claimed. Docs updated to
match.

### 3. Docs implied resource limits "just work" everywhere

`schema-reference.toml` said limits "work seamlessly with rootless podman" with
no mention of the split/Delegate mechanism or the pod-mode caveat. Updated.

## Edits made in this review

- `generators/workload-generate` — rewrote the misleading `--cgroups=split`
  comment (it claimed the flag was "pod-mode-safe" while actually being skipped
  in pod mode) and called out the pod-mode enforcement gap.
- `docs/schema-reference.toml` — `[resources]` intro now documents the
  split/Delegate mechanism and the pod-mode limitation; `on_failure` options
  rewritten to match the system-manager timer's actual `systemctl` semantics.
- `docs/workloads.md` — added an enforcement/pod-mode callout to *Resource
  Constraints*.
- `llms.txt` — architecture summary now mentions split/Delegate, the
  cgroup-placed exec, and the split health timer.

## Test status

All branch-specific tests pass (`test_generator`, `test_exec_cgroup`,
`test_workloads` generation tests). The `systemd-analyze verify` integration
tests initially failed on the review machine because `/usr/bin/podman` isn't
installed there (`Command /usr/bin/podman is not executable`) — environmental,
not a regression. The verify tests have since been taught to patch absent
binaries to `/bin/true` (and stub `nvidia-cdi-generator.service`) on
podman-less hosts, so the full suite now passes on dev containers too; real
hosts keep strict verification.
