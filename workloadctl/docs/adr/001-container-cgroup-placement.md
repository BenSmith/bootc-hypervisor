# ADR 001: Container cgroup placement — system units + split vs user slices

**Status:** Option 1b is implemented. Options 1 and 2 are superseded; options 3
and 4 were rejected and are recorded so they are not re-litigated.

## Context

Workload `[resources]` caps must bind the *container payload's* cgroup. Rootless
podman's native behaviour is for conmon to migrate the payload into the workload
user's manager (`user.slice/user-<uid>.slice/user@<uid>.service`), where
system-unit directives do not reach — before this decision, `MemoryMax=` and kin
were emitted and silently ignored. cgroup v2's migration rules additionally mean
any process outside the payload's delegated subtree (a plain `sudo -u`, podman's
own healthcheck timer) gets `EPERM` trying to exec in.

The constraint that shapes everything: logind hardwires `user-<uid>.slice` under
`user.slice` and it cannot be reparented. So a unified all-workloads slice and
podman's native user-manager placement are **mutually exclusive** — unless the
user manager itself is moved, which is option 1b.

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

### 1. System units + `--cgroups=split` + `Delegate=yes` — superseded

The payload stays under `workloads.slice/workload-<name>.service` and unit
directives bind it directly.

- ✅ `workloads.slice` caps all workloads with one knob and protects the host.
- ✅ `systemctl status workload-foo` shows real payload memory and tasks;
  symmetric with VM workloads, which are also system units under the slice.
- ✅ Per-container caps in bridge mode via per-unit directives.
- ✅ The only topology in which `Type=notify` works — conmon lands in the unit's
  own cgroup, so `READY=1` is attributed correctly (see *`Type=notify`* below).
- ❌ Pays a permanent tax: a `cgroup_exec.py` placement shim for `exec`/`shell`,
  a system-manager healthcheck timer plus `workload-healthcheck` and
  `DISABLE_HC_SYSTEMD`, and recurring debugging cost.
- ❌ Pod mode cannot use split, so pods get no per-unit enforcement. The
  rejection is structural, not a bug awaiting a release: pod members inherit
  `CgroupParent = <pod cgroup>` (`libpod/runtime_ctr.go`) and split plus
  cgroup-parent is rejected outright (`libpod/container_validate.go`) — split
  means "use the caller's unit cgroup", which a pod's shared cgroup contradicts.

### 1b. `user@<uid>.service` slice redirect — **chosen**

Keep system units as lifecycle drivers and keep native user-manager placement (no
split, no `Delegate=yes`), but move each workload's user manager under
`workloads.slice` with a per-UID drop-in:

```ini
# /run/systemd/system/user@10000.service.d/50-workload.conf
[Service]
Slice=workloads.slice
```

`user@.service` is an ordinary system unit template, so `Slice=` in a drop-in
reparents it. The payload's cgroup path is rooted at the user manager's, so the
whole subtree — manager, conmon, payload — follows:

```
-.slice
├── system.slice
├── workloads.slice                       ← aggregate cap lives here
│   ├── workload-foo.service              ← podman client + lifecycle
│   └── user@10000.service                ← user manager, MOVED from user.slice
│       └── …/libpod-<id>.scope           ← container payload
└── user.slice
    └── user-10000.slice                  ← logind tracking slice, near-empty
```

- ✅ Keeps the unified `workloads.slice` aggregate — the whole point of option 1.
- ✅ Deletes `cgroup_exec.py`: `sudo -u … podman exec` works natively against a
  user-manager-resident payload.
- ✅ Deletes the generated health timers, `workload-healthcheck` and
  `DISABLE_HC_SYSTEMD`; podman's native `--health-cmd` and `--health-on-failure`
  work again.
- ✅ Pod-mode parity gap dissolves — no split rejection, every mode identical.
- ✅ Per-container `--memory`, `--cpus`, `--pids-limit` and IO bandwidth limits
  bind natively through the user manager's delegated subtree.
- ❌ Stop and cleanup semantics change (see *Consequences*).
- ❌ `systemctl status workload-foo` shows only the podman client.

### 2. User slices for everything — superseded by 1b

Keep system units as lifecycle drivers, drop split and `Delegate`, and let
payloads migrate to `user@<uid>.service` where they land natively. Enforce
workload-level caps via `user-<uid>.slice` drop-ins and per-container caps via
podman's own flags.

It buys every deletion 1b buys, and pays for them with **the unified
`workloads.slice` pool**, which is unrecoverable under the logind constraint:
"all workloads together ≤ 90%" degrades into a sum of per-workload caps rather
than a shared pool. It also splits the hierarchy in two — VMs stay under
`workloads.slice`, containers move to `user.slice` — and leaves workloads
competing with the human session as siblings. 1b gets the deletions without
either cost, which is why this option is not the fallback it once was.

### 3. Quadlet `.container` units in the user managers — rejected

Most podman-native; everything in option 2's upside plus working sdnotify and
`podman auto-update`. Rejected because it loses the unified slice as option 2
does, *and* moves lifecycle into per-user managers (weaker host-side ordering,
cannot depend on system units), *and* cannot express the system-unit hardening
applied to the podman process. Option 2 dominates it for this codebase.

### 4. Rootful podman + `--userns=auto` — rejected

Deletes the entire per-user machinery (no `_wl-` users, no linger, no subuid
management) and every cgroup hack; system units bind natively. Rejected on the
security premise: conmon and crun would run as real root, so a container-runtime
bug becomes a root compromise rather than an unprivileged-user compromise. For a
hypervisor host the stronger model wins — the cgroup machinery is what we pay for
the rootless boundary.

## Decision

**Adopt option 1b.** The original deciding question — "is the unified
`workloads.slice` guarantee load-bearing?" — dissolves: 1b keeps the aggregate
*and* sheds the split tax. The mechanism is pod mode's existing runtime path plus
one drop-in.

Per-workload caps go on the `user@<uid>.service.d` drop-in alongside the `Slice=`
redirect — **not** on `user-<uid>.slice`, which the user manager leaves under
this decision and where the directives would silently stop binding.

## What the mechanism actually requires

Four things are easy to get wrong and are not visible from configuration alone.

**The drop-in alone does not migrate the manager.** When linger starts
`user@<uid>.service` it goes through logind's start path, which parks the manager
under `user-<uid>.slice` and ignores the drop-in — and `systemctl show` then
reports the configured `Slice=workloads.slice` while the real `ControlGroup`
stays under `user.slice`. Only a PID1 restart of `user@<uid>.service` honours the
drop-in, and logind re-parks it every boot. So `workload-ensure-user`
(`ensure_manager_slice`) restarts the manager at `ExecStartPre`, before the
payload starts, gated on "only if mis-placed" so it is idempotent. Any test of
this must read `/proc/<pid>/cgroup`; a test that reads `systemctl show` passes
while the manager sits in the wrong slice.

**Restarting the manager is not free.** It kills every container of that
workload. Resource-control properties reapply on daemon-reload, but slice
membership does not — so only the one-time migration and any future `Slice=`
change need a restart. Day-2 cap changes apply live. Linger also keeps
`user@<uid>.service` alive across workload restarts, so restarting a workload
alone never re-reads `Slice=`.

**The aggregate cap needs `MemorySwapMax`.** With it unset, Fedora's default zram
absorbs the overflow and no OOM ever fires — the cap clamps RAM while the excess
swaps out. `workloads.slice` therefore sets `MemorySwapMax=90%` alongside
`MemoryMax=`. This was equally true under option 1.

**Trust `cgroup.controllers`, not `DelegateControllers`.** The delegated subtree
exposes `cpuset cpu io memory pids` even though the `DelegateControllers`
property reports only `cpu memory pids`, which is why `--device-read-bps` binds
despite the property suggesting otherwise.

## Source-verified mechanics

From the podman clone under the gitignored `.reference/`:

- **Non-split payloads** get the cgroup `user.slice:libpod:<id>`
  (`SystemdDefaultRootlessCgroupParent`, `libpod/container.go`; `getOCICgroupPath`,
  `libpod/container_internal_linux.go`) — crun asks the *user's* systemd manager
  for a transient `libpod-<id>.scope`, which is how payloads end up under
  `user@<uid>.service`.
- **Split payloads** get `<own unit cgroup>/libpod-payload-<id>`, created directly
  on cgroupfs with no systemd involvement — which is why `Delegate=yes` is
  required there and why unit directives bind.
- **`--memory-reservation` maps to `memory.low`**, not `memory.high`, and no
  podman flag writes `memory.high`. Per-container throttle-before-kill therefore
  has no podman equivalent; `MemoryHigh` survives at workload level only, on the
  `user@<uid>.service` drop-in.
- **Podman's systemd resource translation** (`resourcesToProps`) covers
  `MemoryMax`/`MemorySwapMax`/`CPUWeight`/`CPUQuotaPerSecUSec`/`AllowedCPUs`/
  `IOWeight` and IO bandwidth maxes — no `TasksMax`, `MemoryLow` or `MemoryHigh`.
  That path applies to pod cgroups; per-container limits go through the OCI spec
  into crun's cgroupfs writes, where `--pids-limit` does work.

## `Type=notify` is unavailable under 1b, and that is a trade

Under 1b, `Type=notify` does not work and there is no conmon-independent
workaround within the non-split topology. systemd attributes an sd_notify
datagram to the unit owning the *sender's* cgroup, and the process emitting
`READY=1` always lives in `user@<uid>.service`'s cgroup:

- `--sdnotify=conmon` — the sender is conmon, in the user manager's subtree.
- `--sdnotify=healthy` — podman does send `READY=1` once healthy, but the emitter
  is the re-exec'd libpod podman (`waitForHealthy`), which has migrated into the
  same user-manager scope.

No `NotifyAccess` setting helps. Against systemd's source
(`manager_get_units_for_pidref`, `service_notify_message_authorized`), a notify
datagram is only delivered to a unit that owns the sender's cgroup or watches its
PID; `NotifyAccess` gates *authorization*, never *candidacy*. So an out-of-cgroup
sender is unreachable regardless.

This is a property of the non-split placement, not of rootless plus linger:
restoring `--cgroups=split` + `Delegate=yes` puts conmon at
`/workloads.slice/<unit>.service/runtime` and a `Type=notify` unit reaches
`active` immediately. (It is the same reason Quadlet's notify path works —
Quadlet defaults to split.) Adopting split to regain notify would reintroduce
exactly the tax 1b was chosen to shed, so `Type=exec` plus `--health-cmd` and the
CLI's health-verified flow remains the shipped design. Notify is a capability
traded away with the split topology, not a fundamental impossibility.

The VM substrate is unaffected: `workload-vm-notify` sends `READY=1` from inside
the system unit's own cgroup.

## Consequences

- **Stop and cleanup change.** The payload leaves the unit's cgroup, so
  `systemctl stop` no longer reaches it via `KillMode=control-group`; cleanup
  relies on the foreground podman client proxying SIGTERM, and a SIGKILLed client
  would orphan the payload. Generated units carry
  `ExecStopPost=-podman rm -f -t0` for that reason. This is pod mode's existing
  behaviour becoming universal.
- **`systemctl status workload-<name>` shows only the podman client** — the
  payload is a grandchild via the user manager. `workloadctl status` inherits the
  limitation; `workloadctl stats` uses `podman stats` and reports correctly, and
  `systemd-cgls /workloads.slice` remains the authoritative whole-tree view since
  both halves are siblings there.
- **No observability gap at the Prometheus layer.** `workload-exporter` reads the
  1b path (`/sys/fs/cgroup/workloads.slice/user@<uid>.service/…/libpod-*.scope`)
  and reports container-level memory, PIDs and limits.
- **Unit hardening constrains the podman client, not the payload.**
  `ProtectSystem=strict` and `RestrictAddressFamilies=` apply to the system unit's
  process; crun always creates a fresh mount namespace and applies its own seccomp
  profile to the container. This was equally true under split — the hardening is
  worth having, but it is not a container confinement.
