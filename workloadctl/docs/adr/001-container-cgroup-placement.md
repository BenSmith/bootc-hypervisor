# ADR 001: Container cgroup placement — system units + split vs user slices

**Status:** option 1b is **implemented** (Stage 1, branch `caps-and-security`,
2026-06-11). Options 1 and 2 are superseded. Decided against options 3 and 4
(recorded here so they aren't re-litigated).

> **Implementation note (2026-07-09, branch `test-suite-runtime`).** The
> `Slice=workloads.slice` drop-in alone is *not* sufficient: when linger starts
> `user@<uid>.service` it goes through logind's start path, which parks the
> manager under `user-<uid>.slice` and ignores the drop-in — `systemctl show`
> then reports the configured `Slice=workloads.slice` while the real
> `ControlGroup` stays under `user-<uid>.slice`. Only a PID1 restart
> (`systemctl restart user@<uid>.service`) honors the drop-in and migrates the
> manager, and logind re-parks it every boot. So `workload-ensure-user`
> (`ensure_manager_slice`) restarts the manager at enable-time `ExecStartPre` —
> before the payload starts, gated on "only if mis-placed" so it's idempotent —
> to make the migration actually happen. The runtime rung's
> `tests/cli_surface/test_runtime_cgroup.py` (B3) is the regression proof; the
> spike originally only checked `systemctl show`, which is why the gap went
> unnoticed until B3 read `/proc/<pid>/cgroup` directly.

**Date:** 2026-06-10 (capturing a decision originally made on branch
`resource-caps-split`).
Updated 2026-06-11 with option 1b spike results.

## Context

Workload `[resources]` caps must bind the *container payload's* cgroup. Rootless
podman's native behavior is for conmon to migrate the payload into the workload
user's manager (`user.slice/user-<uid>.slice/user@<uid>.service`), where
system-unit directives don't reach — pre-split, `MemoryMax=` etc. were emitted
but silently ignored. cgroup v2's migration rules additionally mean that any
process outside the payload's delegated subtree (a plain `sudo -u`, podman's own
`--user` healthcheck timer) gets `EPERM` trying to exec in.

Constraint that shapes everything: logind hardwires `user-<uid>.slice` under
`user.slice`; it cannot be reparented. So a unified all-workloads slice and
podman's native user-manager placement are **mutually exclusive**.

```
-.slice
├── system.slice
├── workloads.slice                  ← option 1 puts payloads here (one aggregate knob)
│   └── workload-foo.service
└── user.slice
    ├── user-1000.slice              ← human user
    └── user-10000.slice             ← option 2 puts payloads here (per-workload knob)
        └── user@10000.service
```

## Options

### 1. System units + `--cgroups=split` + `Delegate=yes` — CHOSEN (current)

Payload stays under `workloads.slice/workload-<name>.service`; unit directives
bind it directly.

- ✅ Unified aggregate: `workloads.slice` caps **all** workloads with one knob
  (`MemoryMax=90%`, `CPUWeight=80`, `IOWeight=80`) and protects the host.
- ✅ `systemctl status workload-foo` shows real payload memory/tasks; symmetric
  with VM workloads (also system units under `workloads.slice`).
- ✅ Per-container caps in bridge mode via per-unit directives;
  `custom_directives` escape hatch works.
- ❌ Pays a permanent tax: `lib/cgroup_exec.py` (uid-owned-leaf placement) for
  `exec`/`shell`, the system-manager healthcheck timer + `workload-healthcheck`
  + `DISABLE_HC_SYSTEMD`, and recurring debugging cost (e.g. the non-interactive
  exec fix, commit `3b1e668`). (Note: this split topology is in fact the *only*
  one where `Type=notify` works — conmon lands in the unit's own cgroup, so
  `READY=1` is attributed correctly; under 1b's non-split placement notify fails.
  See spike item 8 + the 2026-07-12 addendum. Since 1b is shipped, notify is
  unavailable in practice.)
- ❌ Pod mode can't use split, so pods get **no** per-unit enforcement —
  mitigated by `user-<uid>.slice` drop-ins. The rejection is
  structural (verified in the podman source, `.reference/podman`): pod members
  inherit `CgroupParent = <pod cgroup>` (`libpod/runtime_ctr.go:421-433`) and
  split+cgroup-parent is rejected outright
  (`libpod/container_validate.go:51`) — split means "use the caller's unit
  cgroup", which a pod's shared cgroup contradicts. Don't expect a podman
  release to lift this.

### 2. User slices for everything (re-evaluation candidate)

Keep system units as lifecycle drivers but drop split/Delegate; let payloads
migrate to `user@<uid>.service` (where pod mode already lives). Enforce:
workload-level caps via `user-<uid>.slice` drop-ins (one user == one workload,
so user scope *is* workload scope); per-container caps via podman's own flags
(`--memory`, `--cpus`, `--cpu-shares`, `--pids-limit`, `--device-read-bps`, …),
which work rootless because `user@.service` delegates cpu/cpuset/io/memory/pids
on current systemd.

- ✅ Deletes `cgroup_exec.py` entirely (plain `sudo -u podman exec` works for
  user-manager-resident containers — today's pod-mode fallback path), the
  generated health timer units, `workload-healthcheck`, `DISABLE_HC_SYSTEMD`;
  podman's native healthchecks and `--health-on-failure` work again.
- ✅ Pod-mode parity gap dissolves: every mode behaves identically.
- ✅ Per-container OOM scoping improves: podman `--memory` confines the OOM
  killer to the container's scope (a slice/unit-level cap lets it pick anything
  in the subtree, including the user manager).
- ✅ Migration is cheap: units live in `/run` and regenerate every boot — this
  is a generator change + reboot; storage/users/secrets untouched.
- ❌ **The unified `workloads.slice` pool is unrecoverable** (logind constraint
  above). "All workloads together ≤ 90%" becomes a sum of per-workload caps —
  not a shared pool. Best approximation: mirror `CPUWeight`/`IOWeight` on each
  `user-<uid>.slice` and size `MemoryMax` sums to budget.
- ❌ Hierarchy goes asymmetric: VMs stay system units under `workloads.slice`
  (correct for QEMU — no conmon, no migration problem), containers move to
  `user.slice` — two cgroup-path regimes for exporter/stats/substrate work.
- ❌ `systemctl status` observability degrades (unit holds only the podman
  client); `custom_directives` stops binding the payload and must be removed or
  re-documented.
- ❌ Workloads compete with the human session as siblings under `user.slice`
  (default weights) instead of being collectively deprioritized.

### 1b. `user@<uid>.service` slice redirect — **VERIFIED** (spike passed on the dev host, 2026-06-11)

Keep system units as lifecycle drivers and keep native user-manager placement
(no split, no `Delegate=yes`), but move each workload user manager under
`workloads.slice` by emitting a per-UID drop-in:

```ini
# /run/systemd/system/user@10000.service.d/50-workload.conf
[Service]
Slice=workloads.slice
```

`user@.service` is an ordinary system unit template — `Slice=` in a drop-in
should reparent it into `workloads.slice`. The migrated container payload
follows the user manager (its cgroup path is rooted at the user manager's
cgroup), so the whole subtree — user manager, conmon, payload — lands under
`workloads.slice`. The generator already emits per-uid drop-ins for C11's pod
caps; this would be an additional property on the same file.

If it works, the cgroup tree looks like:

```
-.slice
├── system.slice
├── workloads.slice                       ← aggregate cap lives here
│   ├── workload-foo.service              ← podman client + lifecycle (option 1 style)
│   └── user@10000.service                ← user manager, MOVED from user.slice
│       └── user@10000.service/...
│           └── libpod-<id>.scope         ← container payload
└── user.slice
    └── user-10000.slice                  ← logind tracking slice (empty / nearly so)
```

**Upside vs option 1 (verified in the spike except where noted):**
- ✅ Keeps the unified `workloads.slice` aggregate — the whole point of option 1
- ✅ Deletes `cgroup_exec.py` (exec works natively against user-manager payloads)
- ✅ Deletes the generated health timer units, `workload-healthcheck`,
  `DISABLE_HC_SYSTEMD` — podman's native healthchecks and `--health-on-failure`
  work again
- ✅ Pod-mode parity gap dissolves (no split rejection, every mode identical)
- ✅ Per-container `--memory`/`--cpus`/`--pids-limit` bind natively via user
  manager delegation (same as option 2)
- ✅ Migration is a generator change + reboot (same as option 2)
- ⏳ System-unit hardening (`ProtectSystem`, `RestrictAddressFamilies`) stays on
  the podman client unit; payload inherits namespace/seccomp properties across
  the cgroup migration (expected — fork-chain inheritance is cgroup-independent
  — but needs real non-split generated units to verify; do so during
  implementation)

**Spike results (dev host, Fedora 44, systemd 259, workload `alloy`/UID 10008,
2026-06-11)** — every gate passed; per the criterion below, 1b supersedes
options 1 and 2:

- **logind does not interfere.** After the drop-in + a `user@10008.service`
  restart: `Slice=workloads.slice`, manager cgroup at
  `/workloads.slice/user@10008.service/init.scope`. `user-10008.slice` remains
  under `user.slice` as empty bookkeeping. (The stock `user@.service` ships
  `Slice=user-%i.slice` as ordinary unit config; a drop-in override is the
  supported mechanism, not a fight with logind internals.)
- **The payload follows the user manager.** A non-split container landed at
  `/workloads.slice/user@10008.service/user.slice/libpod-<id>.scope/container`
  — inside the aggregate slice, matching the source analysis (manager-relative
  `user.slice:libpod:<id>` parent).
- **Per-container caps bind natively.** `--memory 256m --pids-limit 64
  --cpus 0.5` produced `memory.max=268435456`, `pids.max=64`,
  `cpu.max=50000 100000` in the scope's cgroup files. `--device-read-bps`
  bound too (`io.max rbps=1048576`): with `Delegate=yes`, the delegated subtree
  exposes `cpuset cpu io memory pids` even though `DelegateControllers` only
  reports `cpu memory pids` — trust `cgroup.controllers`, not the property.
- **Per-container OOM is confined.** A 600M hog inside the 256M container was
  killed (exit 137); the container's PID 1 and the workload survived.
  `memory.oom.group=0`, so the kernel kills the hog task, not the whole scope.
- **The aggregate cap binds the migrated payload.** With a tight runtime
  `MemoryMax` on `workloads.slice` *and `MemorySwapMax=0`*, an uncapped 1G hog
  was OOM-killed (`oom_memcg=/workloads.slice/...`), victim = the hog's `tail`
  (366M RSS); the user manager, alloy, and a sibling container all survived.
  **Swap caveat:** without `MemorySwapMax`, Fedora's default zram absorbed the
  overflow and no OOM fired — the cap clamps RAM but excess swaps out. This is
  equally true of shipped option 1; if "workloads can't starve the host" must
  cover zram pressure, `workloads.slice` needs a `MemorySwapMax` regardless of
  this ADR's outcome.
- **Exec works without `cgroup_exec.py`.** Plain non-interactive
  `sudo -u _wl-alloy podman exec` (incl. `-w`/`-e`) against the user-manager
  payload — the whole deletion is real.
- **Native healthchecks work.** `--health-cmd` created podman's transient
  timer in the user manager and the container reported `healthy` — the timer
  units, `workload-healthcheck`, and `DISABLE_HC_SYSTEMD` are all deletable.

Procedural corrections vs the spike as originally written (for re-runs):
`Slice=` only takes effect when the **user manager** restarts — linger keeps
`user@<uid>.service` alive across workload restarts, so restarting only the
workload does nothing (stop the workload, `systemctl restart user@<uid>.service`,
start the workload). With the shipped units still using `--cgroups=split`, the
payload-follows test needs a *native* container started via the user manager
(`sudo -u _wl-X XDG_RUNTIME_DIR=/run/user/<uid> podman run …`), not a workload
restart. And `$UID` is readonly in bash — use another variable name.

**Costs vs option 1 (accepted; carry into implementation):**
- **Stop/cleanup semantics change.** The payload leaves the unit's cgroup, so
  `systemctl stop` no longer reaches it via `KillMode=control-group`; cleanup
  relies on the foreground podman client proxying SIGTERM, and a SIGKILLed
  client orphans the payload in the user manager. This is pod mode's existing
  behavior becoming universal; mitigation: `ExecStopPost=-podman rm -f -t0 …`
  on the generated units.
- **C11's `user-<uid>.slice` drop-ins stop binding** the moment the user
  manager leaves that slice. Per-workload caps (incl. `MemoryHigh`, which has
  no per-container podman equivalent) become `[Service]` directives on the
  *same* `user@<uid>.service.d` drop-in as the slice redirect — one file, one
  knob per workload. Don't ship C11 against `user-<uid>.slice` first and
  rewrite it; sequence them together.
- **A `user@<uid>.service` restart kills every container of that workload.**
  Resource-control properties reapply on daemon-reload, but slice membership
  does not — only the one-time migration (and any future `Slice=` change)
  needs manager restarts; day-2 cap changes apply live.
- **`systemctl status workload-foo` shows only the podman client** (payload is
  a grandchild via the user manager), and the exporter gets two cgroup-path
  regimes (containers under `user@<uid>.service`, VMs under
  `workload-<name>.service`) — but unlike option 2, everything is under
  `workloads.slice`, so aggregate accounting and `systemd-cgls workloads.slice`
  as the one place to look both survive. Measure exactly what
  `workloadctl status` / the exporter lose during implementation.

---

### 3. Quadlet `.container` units in the user managers — REJECTED

Most podman-native; everything in option 2's ✅ list plus working sdnotify and
`podman auto-update`. Rejected because: same loss of the unified slice as
option 2, *plus* lifecycle moves into per-user managers (`systemctl --user -M
_wl-foo@` management, weaker host-side ordering, can't depend on system units),
*plus* it can't express the system-unit hardening
(`ProtectSystem`/`RestrictAddressFamilies`) currently applied to the podman
process. Net: option 2 dominates it for this codebase — if we leave option 1,
we'd go to 2, not 3.

### 4. Rootful podman + `--userns=auto` — REJECTED

Deletes the entire per-user machinery (no `_wl-` users, linger, subuid
management — finding S4 becomes structurally impossible) and every cgroup hack;
system units bind natively. Rejected on the security premise: conmon/crun run
as real root, so a container-runtime bug is a root compromise, whereas under
the rootless design it's an unprivileged-user compromise. For a hypervisor
host the stronger model wins. This is the deliberate trade: we pay the cgroup
machinery for the rootless boundary.

## Decision

**Adopt option 1b** (spike passed 2026-06-11, see results above). The original
deciding question — "is the unified `workloads.slice` guarantee load-bearing?"
— is dissolved: 1b keeps the unified aggregate *and* deletes the split tax
(`cgroup_exec.py`, the healthcheck shim stack, the pod-mode parity gap). The
mechanism is pod mode's existing runtime path plus one verified drop-in.
Option 1 remains the shipped design until the generator change + reboot lands;
every ❌ on option 1's list goes away with it, and 1b's new costs (stop
semantics, status observability) are ones pod mode already pays today.

C11 changes shape under this decision: do **not** implement pod caps as
`user-<uid>.slice` drop-ins — under 1b the user manager leaves that slice and
they stop binding. Per-workload caps go on the `user@<uid>.service.d` drop-in
alongside the `Slice=` redirect (see costs above).

Implementation checklist — Stage 1 complete, follow-ups verified 2026-06-12:
- ✅ `ExecStopPost=-podman rm -f -t0` added to generated container units
- ✅ `cgroup_exec.py` + healthcheck-shim stack deleted
- ✅ `MemorySwapMax=90%` set on `workloads.slice`
- ✅ `ProtectSystem`/`RestrictAddressFamilies` confirmed on the dev host (see spike item 5)
- ✅ Health-verified update + rollback cycle confirmed on the dev host (see below)

Still open (subsequent stages):
- ✅ `systemctl status` / exporter measurement — see spike item 6 below

## Source-verified mechanics (podman clone at `.reference/podman`, 2026-06)

- **Where non-split payloads go:** rootless + systemd cgroup manager passes the
  cgroup to crun as `user.slice:libpod:<id>`
  (`SystemdDefaultRootlessCgroupParent = "user.slice"`, `libpod/container.go:39`;
  `getOCICgroupPath`, `libpod/container_internal_linux.go:359-365`) — crun asks
  the *user's* systemd manager for a transient `libpod-<id>.scope`, which is how
  payloads end up under `user@<uid>.service`. Resource flags ride along as
  scope properties / delegated cgroupfs writes, so spike item 1 below is
  expected to pass; the open question is only controller breadth.
- **Where split payloads go:** `<own unit cgroup>/libpod-payload-<id>`, created
  directly on cgroupfs (`libpod/container_internal_linux.go:353-358`) — no
  systemd involvement, which is why `Delegate=yes` is required and why the unit
  directives bind.
- **`--memory-reservation` maps to `memory.low`**, not `memory.high`
  (`vendor/github.com/opencontainers/cgroups/fs2/memory.go:71-75`), and no
  podman flag writes `memory.high`. So spike item 3 is **answered**:
  per-container throttle-before-kill has no podman equivalent; under option 2,
  `MemoryHigh` semantics survive only at workload level via the
  `user-<uid>.slice` drop-in.
- **Podman's systemd resource translation** (`resourcesToProps`,
  `vendor/go.podman.io/common/pkg/cgroups/systemd_linux.go:147`) covers
  `MemoryMax`/`MemorySwapMax`/`CPUWeight`/`CPUQuotaPerSecUSec`/`AllowedCPUs`/
  `IOWeight`/IO bandwidth maxes — no `TasksMax`, `MemoryLow`, `MemoryHigh`.
  (This path applies to pod cgroups; per-container limits go through the OCI
  spec into crun's cgroupfs writes, where `--pids-limit` does work.)

## Re-evaluation spike (status after the 2026-06-11 run on the dev host)

1. ~~`podman run --memory 256m --pids-limit 64 --cpus 0.5` rootless, *without*
   `--cgroups=split`, under a linger user manager~~ **Confirmed 2026-06-11:**
   limits land in the scope's cgroup files (`memory.max=268435456`,
   `pids.max=64`, `cpu.max=50000 100000`).
2. ~~Confirm io delegation~~ **Confirmed 2026-06-11:** `--device-read-bps`
   binds (`io.max rbps=1048576`). `Delegate=yes` exposes
   `cpuset cpu io memory pids` in `cgroup.controllers` even though the
   `DelegateControllers` property only reports `cpu memory pids`.
3. ~~Find the `MemoryHigh` equivalent~~ **Answered from source** (above):
   `--memory-reservation` → `memory.low`; nothing maps to `memory.high`.
   Under 1b this is moot at workload level: `MemoryHigh` goes on the
   `user@<uid>.service` drop-in. Per-container `memory.high` remains
   unavailable.
4. ~~Confirm plain `sudo -u` exec + healthcheck timers~~ **Confirmed
   2026-06-11 (direct) + 2026-06-12 (generated units):** non-interactive
   `sudo -u` exec (incl. `-w`/`-e`) works; `--health-cmd` fires podman's
   native user-manager timer and reports `healthy` under real non-split
   generated units. `workloadctl update alloy --force` waited for the native
   health check and confirmed healthy after restart; `workloadctl rollback`
   also confirmed functional.
5. ~~Confirm the unit's `ProtectSystem`/`RestrictAddressFamilies` still
   constrain the migrated payload~~ **Confirmed 2026-06-12 on the dev host (alloy,
   UID 10008, Fedora 44/systemd 259, non-split generated units):**
   `ProtectSystem=strict` and `RestrictAddressFamilies=~AF_ALG AF_PACKET`
   apply to the `workload-alloy.service` system unit process (the podman
   client). Key findings: (a) the system unit's mount namespace is private and
   distinct from the container's (`mnt:[4026532522]` vs `mnt:[4026532672]`);
   `/usr` is read-only in the system unit's namespace (`EROFS` confirmed) but
   the container has its own overlay rootfs. (b) The system unit process has
   `Seccomp_filters: 2` (systemd's `RestrictAddressFamilies` filter active);
   the container has `Seccomp_filters: 3` (adds crun's OCI profile on top).
   Clarification vs the original framing: these are constraints on the
   **podman client process in the system unit**, not on the container payload
   — crun always creates a fresh mount namespace and applies its own seccomp
   profile. This was equally true under split. The hardening protects the
   podman client from host filesystem writes and disallowed address families,
   and is unchanged under 1b.
6. ~~Measure what `systemctl status workload-X` / `workloadctl status` lose
   and what the exporter's cgroup paths become~~ **Measured 2026-06-12 on the dev host
   (alloy, UID 10008):**
   - `systemctl status workload-alloy.service` shows only the podman client
     (202838) and catatonit (202855) under its CGroup entry. Memory/tasks
     figures are for the podman client only: 25.4M RAM, 13 tasks. The
     container payload (alloy: 79MB RAM, 17 PIDs, plus conmon + pasta) is
     NOT visible in this view — it is under `user@10008.service`.
   - `workloadctl status` proxies to `systemctl status` and has the same
     limitation. `workloadctl stats` uses `podman stats` directly and shows
     the correct container-level figures (79MB / 512MB cap, 17 PIDs).
   - `systemd-cgls /workloads.slice` remains the authoritative whole-tree
     view: `workload-alloy.service` (podman client) and
     `user@10008.service/user.slice/libpod-<id>.scope/container` (payload)
     are both visible as siblings under `workloads.slice`.
   - The exporter (`workload-exporter`) uses the 1b cgroup path
     (`/sys/fs/cgroup/workloads.slice/user@{uid}.service/.../libpod-*.scope`)
     and correctly reports container-level metrics: `workload_memory_current_bytes`
     = 79MB (matches `podman stats`), `workload_pids_current` = 17,
     `workload_memory_max_bytes` = 512MB (the `--memory` cap). No observability
     gap at the Prometheus layer.
7. ~~OOM behavior~~ **Confirmed 2026-06-11:** per-container `--memory` kills
   only the hog task inside the container (`memory.oom.group=0`, PID 1
   survives); a tight slice-level cap OOM-kills the largest consumer in the
   subtree, sparing the user manager and sibling containers. Caveat: with
   `MemorySwapMax` unset, zram absorbs overflow and no OOM fires — see the
   swap caveat in the 1b spike results.
8. ~~Re-test `Type=notify` under 1b (the topology changed, result was unknown)~~
   **Resolved 2026-06-21 on the dev host (Fedora 44 / systemd 259)** — *framing refined
   2026-07-12, see the addendum below: this result holds for 1b's non-split
   placement; `Type=notify` **does** work under `--cgroups=split` (option 1). The
   "structurally incompatible with rootless+linger" wording overstates it — the
   incompatibility is with the non-split topology specifically. The decision
   (exec stays default) is unchanged.* Original finding: under 1b, `Type=notify`
   does not work — 1b does not fix it, and there is no conmon-independent
   workaround within the non-split topology. systemd attributes an
   sd_notify datagram to the unit owning the *sender's* cgroup, and the process
   that emits `READY=1` always lives in `user@<uid>.service`'s cgroup, never in
   `workload-<name>.service`'s. Tested both policies with the container reaching
   readiness; both left the unit stuck `activating`:
   - `--sdnotify=conmon`: the sender (conmon) sits in
     `…/user@<uid>.service/…/podman-*.scope`.
   - `--sdnotify=healthy` (requires a healthcheck): podman *does* send `READY=1`
     once healthy (confirmed by pointing it at a private datagram listener), but
     the emitter is the re-exec'd libpod podman (`waitForHealthy`,
     `libpod/container_internal.go`), which has migrated into the **same**
     user-manager scope as conmon. systemd logged the proof:
     `user@<uid>.service: Got notification message from PID <re-exec'd podman>,
     but reception only permitted for main PID <user manager>`.
   No `NotifyAccess` tweak on the workload unit helps (the sender is not in its
   cgroup at all); the only unit that *could* accept the message is the user
   manager, which is the wrong unit. Readiness gating instead uses podman-native
   `--health-cmd` (works under 1b, item 4) + `workloadctl health`/`update`'s
   health-verified flow. The VM substrate's `Type=notify` is unaffected:
   `workload-vm-notify` sends `READY=1` from inside the system unit's own cgroup.

## Addendum (2026-07-12): `Type=notify` works under split — item 8 refined

Item 8's "structurally incompatible with the rootless+linger design" is
imprecise. A controlled spike on the dev host (Fedora 44, systemd 259, podman 5.8.3)
shows the failure is a property of 1b's **non-split** placement, not of
rootless+linger per se: restoring `--cgroups=split` + `Delegate=yes` — i.e.
option 1's topology — makes `Type=notify` + `--sdnotify=conmon` reach `active`.

Three faithful units, each run as the same lingering workload user (pasta net,
`--userns=keep-id`, `TimeoutStartSec=20`; `systemctl start` on a `Type=notify`
unit blocks until `READY=1` or timeout, so its exit code is the verdict):

| unit | cgroups mode | `--sdnotify` | result | conmon cgroup |
|------|--------------|--------------|--------|---------------|
| control | enabled | `ignore` (never READY) | failed / timeout 20s | — |
| 1b (shipped) | enabled | `conmon` | failed / timeout 20s | `…/user@<uid>.service/…/podman-*.scope` |
| option 1 | **split** + `Delegate=yes` | `conmon` | **active in 0s** | `/workloads.slice/<unit>.service/runtime` |

The negative control failing — and the 1b unit failing *identically* to it —
validates the harness and reproduces item 8; the split unit passing is the new
result. Mechanism re-confirmed against systemd v261 source (`src/core/manager.c`
`manager_get_units_for_pidref` + `src/core/service.c`
`service_notify_message_authorized`): a notify datagram is only delivered to a
unit that owns the sender's cgroup **or** watches the sender's PID, and
`NotifyAccess` gates *authorization*, never *candidacy* — so 1b's out-of-cgroup
sender is unreachable regardless of `NotifyAccess=all`, while split's in-cgroup
conmon is delivered. This is the same reason Quadlet's notify path works: Quadlet
defaults to `--cgroups=split` (upstream podman docs, `options/cgroups.md`;
local clone under the gitignored `.reference/podman`).

**Decision unchanged.** Adopting split to gain notify would reintroduce exactly
the tax 1b was chosen to shed — `cgroup_exec.py`, the healthcheck-timer shim
stack, and the pod-mode parity gap (pods can't use split; see option 1's ❌
list). So `Type=exec` + `--health-cmd` + the CLI health-verified flow remains
the shipped design. What changes is only the *rationale*: notify is a capability
traded away with the split topology, not a fundamental impossibility — and if
per-workload readiness gating ever justifies the split tax for single-mode
workloads, the mechanism is proven. Not covered by this spike (prerequisites
before any such change): `--sdnotify=healthy` under split (the re-exec'd libpod
podman's placement), and where `[resources]` caps land under split's
two-sub-cgroup (`conmon` vs payload) layout.
