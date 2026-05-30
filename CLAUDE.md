# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Two coupled projects in one repo:

1. **Bootc hypervisor images** (repo root) — immutable Fedora bootc OS images for a homelab virtualization host. Built as a layered chain of Containerfiles, published to `ghcr.io/bensmith/`, signed with cosign (keyless OIDC). Atomic upgrades + instant rollback via `bootc`.
2. **workloadctl** (`workloadctl/`) — a standalone, RPM-packaged Python tool (no bootc dependency) that turns `/etc/workloads.d/*.toml` files into isolated rootless-podman container workloads. It ships inside the hypervisor image but is developed and tested independently.

The image is the *delivery vehicle*; workloadctl is where almost all application logic lives.

## Image build chain

```
fedora-bootc-minimal (built from upstream Fedora bootc manifests)
  └── hypervisor-bootc            (hypervisor.Containerfile — full stack)
      ├── hypervisor-nvidia:rpmfusion / :negativo17
      └── hypervisor-amd
```

`fedora-versions.yml` is the single source of truth for which Fedora versions build and which is `:latest`/`stable`. The root `justfile` `{{tag}}` and `{{fedora_version}}` are derived from it (via `yq`).

## Common commands

All build/test orchestration is in the root `justfile` (image builds) and `workloadctl/justfile` (Python tests, RPM). The root `test*` recipes just delegate into `workloadctl/`.

```bash
# --- workloadctl development (most day-to-day work) ---
cd workloadctl
just test                 # all unit tests (unittest discover)
just test-unit            # fast subset (lib, generator, write-env, metrics)
just test-integration     # tests.test_integration only
just lint                 # py_compile syntax check of all scripts
just rpm-build            # build the RPM from local checkout
just rpm-install          # build + dnf install/upgrade locally

# run a single test module / case (PYTHONPATH=lib is required)
PYTHONPATH=lib python3 -m unittest tests.test_workloads -v
PYTHONPATH=lib python3 -m unittest tests.test_workloads.SomeClass.test_method

# --- image builds (root, requires podman; *-local skip the registry push) ---
just build-base-local                 # hypervisor-bootc from local minimal
just build-nvidia-rpmfusion-local
just build-all-local
just build-iso-base                    # installer ISO
just aio-local                         # build + qcow2 + deploy to a libvirt VM

# --- full VM integration tests (root; needs sudo, QEMU, swtpm) ---
just test-vm-build && just test-vm     # boots the bootc image, runs tests/vm/run-vm-tests.sh inside it

# --- throwaway manual test VM (workloadctl/, Fedora cloud image) ---
cd workloadctl && just vm-up && just vm-deploy && just vm-ssh 'workloadctl list'
```

There is no Python package manager / venv — scripts run against the system `python3` (3.11+) with `PYTHONPATH=lib`. `lib/` has no third-party deps; everything is stdlib + `tomllib`.

## workloadctl architecture

The hard-won design rationale lives in `workloadctl/llms.txt` and `workloadctl/docs/` — read those before changing boot/generator/secret behavior. Key points:

- **Boot flow is split deliberately.** A tiny *shell* systemd generator (`generators/workload-generator`) emits one oneshot, `workload-generate.service`, which runs the *Python* `generators/workload-generate` during early boot (`After=sysinit.target Before=basic.target`) to write sysusers configs + per-workload unit files into `/run/systemd/system/`. Python is kept out of generator context on purpose — generators must be fast/minimal and Python import overhead blows the systemd 258+ budget. Both layers always exit 0 so a failure never blocks boot. The generate step is read-only w.r.t. `/var`.
- **All `/var` work is deferred** to `libexec/workload-ensure-user`, run as `ExecStartPre` of each workload service (subuid/subgid ranges, home + volume dirs, EnvironmentFile, linger).
- **One dedicated locked-down system user per workload** (`_wl-<name>`, UID 10000+, `/usr/sbin/nologin`), each with its own rootless podman instance. No privileged containers.
- **Default service type is `Type=exec`.** `Type=notify`/`--sdnotify=conmon` is broken when linger is active (conmon migrates cgroups and the `READY=1` is dropped) — don't switch the default. See the comment block in `generators/workload-generate` around `service_type`.
- **`lib/podman.py`** is the typed podman wrapper: it parses `podman inspect --format=json` into structured data. Use it rather than shelling out with go-template format strings.

### Code layout (workloadctl/)

- `bin/workloadctl` — the CLI (~4100 lines, argparse). One `cmd_<name>(args, manager)` function per subcommand, wired up in `main()`. Mutating commands call `require_root()`.
- `lib/workload_lib.py` — `WorkloadConfig` / `WorkloadManager`, TOML loading, paths, UID math.
- `generators/`, `libexec/` — boot-time and helper scripts (also `workload-exporter` for Prometheus metrics).
- `workloads.d/` — real example/shipped workload TOMLs. `docs/schema-reference.toml` is the annotated full schema.
- `tests/` — `test_*.py` unittest modules.
- `containers/<name>/` — custom container images that some workloads use, each with its own `Containerfile` + `build.sh`.

### Workload topologies

`workload.mode` selects how a TOML maps to units: `single` (one `[container]`), `pod` (multiple `[[containers]]` sharing a netns, talk on localhost), `bridge` (per-container netns on an auto-created `workload-<name>-net`, resolve by container name). The generator's `normalize_containers()` collapses single/multi shapes so single-container TOMLs produce byte-identical units. Container-targeted CLI commands accept `<workload>/<container>`. `workloads.d/webproxy-demo.toml` is the smallest bridge-mode example.

## Secrets

systemd credentials (`systemd-creds`), AES256-GCM with TPM2 (or host key fallback), decrypted into tmpfs at runtime. Encrypted blobs are safe to commit into images. Reference in env with `${SECRET:name}`. Managed via `workloadctl secret`.

## CI

GitHub Actions (`.github/workflows/`) and a mirrored Forgejo runner (`.forgejo/workflows/`) build images on a weekly cadence (minimal Sat, variants Sun). Note (from project memory): Forgejo itself runs in a container, so container-in-container CI builds don't work there.
