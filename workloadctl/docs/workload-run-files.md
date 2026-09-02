# Workload run-files

This is the authoritative definition of the **run-files a single workload owns** —
the per-workload artifacts the Python generator (`generators/workload-generate`)
materializes under `/run` at boot (and that `workloadctl enable` writes before the
first boot). Lifecycle and introspection code (`disable`/`--purge`, `drift`,
`diagnose`, `list`/`status`, the metrics exporter, backup) must agree on this exact set:
a workload's run-files are what `disable` removes, what `drift` diffs against the
generator's would-be output, and what `status`/`diagnose` enumerate.

Getting the *boundary* wrong is a real bug class — under-scoping orphans files on
`disable`; over-scoping (treating a shared or cross-referenced unit as owned) can
delete another workload's unit or host-global infrastructure.

## The term

A workload run-file is a per-workload file that lives in the systemd runtime tree
(`/run/systemd/system/`) or the workload env tree (`/run/workload-env/`). Most are
systemd unit files; a few are not (see below), so the correct scope is
**"per-workload generated run-files,"** not strictly "systemd units." Membership
depends on the workload's **mode** (`single` / `pod` / `bridge`) and **kind**
(container vs VM).

Two properties cut across the set and a single enumeration must track both, because
callers slice the set differently along each:

- **Producer** — most run-files are written by the **generator** (`generators/workload-generate`)
  at boot / `enable`. The `.env` and `.secrets` files are the exception: they are
  written at **runtime** by `workload-ensure-user` / `workload-write-env`, so the
  generator never emits them. `drift` (which diffs against the generator's would-be
  output) and any generator-parity check must consider generator-written files only.
- **Removal lifecycle** — systemd units, the sysusers `.conf`, and the cgroup drop-in
  are removed on **every `disable`** (plain and `--purge`). The `.env` / `.secrets`
  files are removed **only on `--purge`** (a plain `disable` deliberately leaves a
  stopped workload's decrypted secrets in place until purge). So "what `disable`
  removes" is *not* the whole owned set — it is the owned set minus the env-tree files.

A durable helper therefore tags each entry with enough to reconstruct every view:
its `kind` (`unit` / `wants-symlink` / `sysusers` / `dropin` / `env-file`) determines
both its tree and its removal lifecycle, and a per-config **emitted** flag separates
files that exist for *this* config from the over-listed topology superset (see the
lifecycle note under "The set").

## The set

### Always present
| File | Role |
|------|------|
| `/run/systemd/system/workload-<name>.service` | **Main** unit. In `single` mode this *is* the container runner; in `pod`/`bridge`/multi it is an **umbrella** (`PartOf` parent) that groups the per-container services. This is the unit that gets the autostart symlink. |
| `/run/systemd/system/workload-<name>-setup.service` | Per-workload host-setup oneshot: runs `workload-ensure-user` as `ExecStartPre`, ordering the `/var` work (subuid/subgid, home + volume dirs, EnvironmentFile, linger) before the main unit. |
| `/run/systemd/system/multi-user.target.wants/workload-<name>.service` | Autostart symlink for the main unit. A reference, but materialized as a file on disk, so lifecycle code owns it. |

### Conditional on mode / kind
| File | Condition |
|------|-----------|
| `/run/systemd/system/workload-<name>-build.service` | **VM workloads only** — the oneshot that creates `system.qcow2`. Unconditional for a VM; no container workload gets one, whatever it declares |
| `/run/systemd/system/workload-<name>-pod.service` | `pod` mode |
| `/run/systemd/system/workload-<name>-net.service` | `bridge` mode (the auto-created `workload-<name>-net` network) |
| `/run/systemd/system/workload-<name>-<cname>.service` | one per container, in `pod`/`bridge`/multi |
| `/run/systemd/system/workload-<name>-virtiofs-<tag>.service` | one per virtiofs volume, VM workloads |
| `/run/systemd/system/workload-<name>-inspect.socket` + `-inspect.service` | VM workloads whose egress is inspected (`vm_uses_inspect`). Enumerated for every VM regardless, on the superset rule below |
| `/run/systemd/system/workload-<name>-resolve.socket` + `-resolve.service` | the synthesising responder — inspected **and** `resolver` not `"none"` (`vm_uses_resolve`). Same superset rule |
| `/run/systemd/system/workload-<name>-broker.service` | VM workloads declaring `[[vm.network.credential]]` material and inspected (`vm_uses_credentials`). Same superset rule |
| `/run/systemd/system/workload-<name>-proxy.service` | **Nothing emits this.** A migration entry: the retired hostname-policy proxy, listed so an in-place RPM upgrade's leftover unit has something that knows its name. `emitted=False` always. Deletable once every host has rebooted past the rung-2 upgrade |

The socket/service pairs are listed unconditionally on purpose: a workload that
switches inspection (or the resolver, or its last credential) *off* has to have
the stale units unlinked, not left behind arming a listener for a guest that no
longer expects one.

> **Emitted vs. removable (the deletion superset).** The generator writes exactly the
> conditional units a given mode/kind needs. The *removal* path, by contrast,
> over-lists: it enumerates `-pod.service` **and** `-net.service` for **every**
> container workload regardless of mode and relies on `missing_ok`, so disabling
> `foo` can never miss a unit the topology might have produced. Both are correct views
> of the same set: the **emitted** view (what exists for *this* config — used by the
> generator, `drift`, `status`, metrics) and the **removable** superset (what
> `disable` may safely `unlink` — the mode-family union). A single flat set serves
> neither caller correctly, which is why `workload_run_files()` tags each entry with
> `emitted` rather than returning two lists or one.

### Sysusers config and the cgroup drop-in

These are generator-written, per-workload, and removed on `disable` alongside the
units — but they are not `.service` files:

| File | Role |
|------|------|
| `/run/systemd/system/workload-<name>.conf` | Per-workload **sysusers** config. `SYSUSERS_DIR` defaults to the services dir (`/run/systemd/system` in production), so despite the `.conf` suffix it lands beside the units and is removed from there on `disable`. |
| `/run/systemd/system/user@<uid>.service.d/50-workload.conf` | Cgroup-placement **drop-in** for the workload user's manager (containers only; VMs have none). Keyed by the workload UID from the passwd db — omitted once the user is gone, since the UID can't be reconstructed. |

### Owned run-files that are **not** systemd units
| File | Role |
|------|------|
| `/run/workload-env/workload-<name>.env` | Per-workload EnvironmentFile written at runtime by `workload-ensure-user` (`XDG_RUNTIME_DIR`, `HOST_IP`, …). Always present once the workload has started. **Owned by the workload**, cleaned up on **`--purge`**. |
| `/run/workload-env/workload-<name>[-<container>].secrets` | Decrypted-secret EnvironmentFile written at runtime by `workload-write-env`, referenced by the container service. One per container. **Owned by the workload**, cleaned up on **`--purge`**. |

> **Enumerated unconditionally.** The `.secrets` file is listed for *every* container,
> not just containers that declare secrets, and removal relies on `missing_ok`
> (the same over-list-and-tolerate pattern the systemd superset uses — see the
> lifecycle note below). So "owned" here means "could exist for this topology," not
> "is known to exist for this config."

> No per-workload `tmpfiles` config is generated today (an earlier draft of this doc
> claimed one; there is no writer for it in `generators/` or `libexec/`). The only
> non-unit generated configs are the sysusers `.conf` (above) and, at `enable` time,
> the sysusers line re-emitted inline by `_provision_user` — the B6 duplication.
>
> `/run/sysusers.d/` (`RUN_SYSUSERS_D`) is **read** but never written. UID
> allocation scans it alongside `/run/systemd/system` so a UID pinned in a
> pending conf is not handed out twice, and the constant exists for that scan
> and a staging path that no longer has a writer — the docstring on
> `_reserved_uids_in_pending_sysusers` still describes `enable` copying a conf
> there, and nothing in `lib/`, `generators/` or `libexec/` does. Either way it
> is not a run-file: it is never in the owned set and `disable` does not touch it.

## Explicitly **not** a workload's run-files

These are easy to blur and enumerating them as workload-owned is a bug:

- **`workload-generate.service`** and the generator itself — one **global** unit, not
  per-workload.
- **`workload-bridge.service`** + dnsmasq — **shared** VM bridge infrastructure:
  one per host, refcounted across all VM workloads, and so never owned by a
  workload. Neither exists (a VM uses passt, ADR 006) and the generator emits
  neither, but both stay named here and asserted absent by the boundary test,
  which states where the line falls rather than what the generator happens to
  write today.
- **Dependency *references*** to `workload-<other>.service` in `Requires=` / `After=` /
  `--pod=` / `--network=` lines — these point at *other* workloads (inter-workload
  ordering); they are not files this workload owns. Removing them as if owned would
  delete a different workload's unit.

## Naming helpers

`lib/workload_lib.py` provides `workload_service_name(name)` →
`workload-<name>.service` and `workload_container_name(name)` → `workload-<name>`.
These cover only the two simplest names. Everything **derived** — `-setup`,
`-build`, `-pod`, `-net`, `-inspect`, `-resolve`, `-broker`, `-proxy`,
`-virtiofs-<tag>`, `-<cname>`, the `.wants` symlink, the sysusers `.conf`, the
`user@<uid>` drop-in and the `.env` / `.secrets` env files — comes from
`workload_run_files(config)` in the same module, which returns one
`WorkloadRunFile(path, kind, role, emitted)` per entry in this table. That is
the single source of truth; do not re-spell a name at a call site.

Its companion is `RUN_TREE_SCANS`, a per-kind glob table for callers that walk
the whole run tree rather than one config (`workloadctl drift`, which has to
compare generated-vs-live in both directions and so cannot start from a config).
`TestRunTreeScansCoverRunFiles` in `tests/test_workload_run_files.py` pins the two together.

## Maintenance note

This table used to be hand-enumerated at half a dozen call sites and re-derived
in the generator, and the mode→run-files membership drifted between the copies —
two past bugs (the exporter `workload_health` miss and disable/purge
completeness) came from exactly that. `workload_run_files()` is the durable fix
and has landed.

**Adding or renaming a per-workload run-file is now a three-place change:** the
generator that writes it, `workload_run_files()` (with the right `emitted`
predicate — superset if a config can switch it off), and this table. If the file
lands under `/run/systemd/system` and its `kind` is new, add a `RUN_TREE_SCANS`
row too, or `drift` will never look at it.
