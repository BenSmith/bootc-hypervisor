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

A workload run-file is a file the generator writes **for one named workload**, into
the systemd runtime tree (`/run/systemd/system/`) or the workload env tree
(`/run/workload-env/`). Most are systemd unit files; a few are not (see below), so
the correct scope is **"per-workload generated run-files,"** not strictly "systemd
units." Membership depends on the workload's **mode** (`single` / `pod` / `bridge`)
and **kind** (container vs VM).

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

### Owned run-files that are **not** systemd units
| File | Role |
|------|------|
| `/run/workload-env/<container>.secrets` | Decrypted-secret EnvironmentFile referenced by the container service. One per container that uses secrets. **Owned by the workload** (cleaned up on `disable`), but not a systemd unit — the reason the scope is "run-files," not "units." |

> Boot also writes per-workload `sysusers.d` and `tmpfiles` configs; those follow the
> same "generated for one workload" ownership but live outside `/run/systemd/system`.

## Explicitly **not** a workload's run-files

These are easy to blur and enumerating them as workload-owned is a bug:

- **`workload-generate.service`** and the generator itself — one **global** unit, not
  per-workload.
- **`workload-bridge.service`** + dnsmasq — **shared** VM bridge infrastructure, one
  per host, refcounted across all VM workloads.
- **Dependency *references*** to `workload-<other>.service` in `Requires=` / `After=` /
  `--pod=` / `--network=` lines — these point at *other* workloads (inter-workload
  ordering); they are not files this workload owns. Removing them as if owned would
  delete a different workload's unit.

## Naming helpers

`lib/workload_lib.py` provides `workload_service_name(name)` →
`workload-<name>.service` and `workload_container_name(name)` → `workload-<name>`.
These cover only the two simplest names; the **derived** units above
(`-setup`, `-build`, `-pod`, `-net`, `-virtiofs-<tag>`, `-<cname>`, the `.wants`
symlink, the `.secrets` env files) are currently spelled by hand at each call site.

## Maintenance note

Because the derived set is hand-enumerated in several places (`_workload_run_files`
and `helper_services` in `lib/cmd_lifecycle.py`, plus `cmd_interact`, `cmd_admin`,
`cmd_drift`, `cmd_inspect`, `substrate.py`) **and** re-derived in the generator, the
mode→run-files membership can drift between copies. Two past bugs (the exporter
`workload_health` miss and disable/purge-completeness) came from exactly that drift.

**When adding or renaming a per-workload run-file in the generator, treat it as a
fan-out change:** grep `f"workload-{` across `lib/ generators/ libexec/` and update
every enumeration. The intended durable fix is a single
`workload_run_files(config)` family in `workload_lib` that encodes this table once
and is called by every site *and* the generator.
