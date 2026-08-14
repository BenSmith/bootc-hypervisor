# Workload run-files

This is the authoritative definition of the **run-files a single workload owns** —
the per-workload artifacts the Python generator (`generators/workload-generate`)
materializes under `/run` at boot (and that `workloadctl enable` writes before the
first boot). Lifecycle and introspection code (`disable`/`--purge`, `drift`,
`diagnose`, `inspect`, the metrics exporter, backup) must agree on this exact set:
a workload's run-files are what `disable` removes, what `drift` diffs against the
generator's would-be output, and what `inspect`/`diagnose` enumerate.

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
| `/run/systemd/system/workload-<name>-build.service` | workload declares a declarative build |
| `/run/systemd/system/workload-<name>-pod.service` | `pod` mode |
| `/run/systemd/system/workload-<name>-net.service` | `bridge` mode (the auto-created `workload-<name>-net` network) |
| `/run/systemd/system/workload-<name>-<cname>.service` | one per container, in `pod`/`bridge`/multi |
| `/run/systemd/system/workload-<name>-virtiofs-<tag>.service` | one per virtiofs volume, VM workloads |
| `/run/systemd/system/workload-<name>-proxy.service` | VM workloads with `[vm.network].hosts` (the per-VM filtering proxy). Enumerated for every VM regardless, on the same superset rule as `-pod`/`-net` below |

> **Emitted vs. removable (the deletion superset).** The generator writes exactly the
> conditional units a given mode/kind needs. The *removal* path, by contrast,
> over-lists: it enumerates `-pod.service` **and** `-net.service` for **every**
> container workload regardless of mode and relies on `missing_ok`, so disabling
> `foo` can never miss a unit the topology might have produced. Both are correct views
> of the same set: the **emitted** view (what exists for *this* config — used by the
> generator, `drift`, `inspect`, metrics) and the **removable** superset (what
> `disable` may safely `unlink` — the mode-family union). A shared helper must expose
> both; a single flat set serves neither caller correctly.

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
These cover only the two simplest names; the **derived** run-files above
(`-setup`, `-build`, `-pod`, `-net`, `-proxy`, `-virtiofs-<tag>`, `-<cname>`, the `.wants`
symlink, the sysusers `.conf`, the `user@<uid>` drop-in, and the `.env` / `.secrets`
env files) are currently spelled by hand at each call site.

## Maintenance note

Because the derived set is hand-enumerated in several places (`_workload_run_files`
and `helper_services` in `lib/cmd_disable.py`, plus `cmd_interact`, `cmd_diagnose`,
`cmd_drift`, `cmd_inspect`, `substrate.py`) **and** re-derived in the generator, the
mode→run-files membership can drift between copies. Two past bugs (the exporter
`workload_health` miss and disable/purge-completeness) came from exactly that drift.

**When adding or renaming a per-workload run-file in the generator, treat it as a
fan-out change:** grep `f"workload-{` across `lib/ generators/ libexec/` and update
every enumeration. The intended durable fix is a single
`workload_run_files(config)` family in `workload_lib` that encodes this table once
and is called by every site *and* the generator.
