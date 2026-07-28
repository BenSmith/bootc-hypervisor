# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Two coupled projects in one repo:

1. **Bootc hypervisor images** (repo root) — immutable Fedora bootc OS images for a homelab virtualization host. Built as a layered chain of Containerfiles, published to `ghcr.io/bensmith/`, signed with a cosign key (not keyless OIDC) and verified against the tracked `cosign.pub` — see `docs/ci-image-signing.md`. Atomic upgrades + instant rollback via `bootc`.
2. **workloadctl** (`workloadctl/`) — a standalone, RPM-packaged Python tool (no bootc dependency) that turns `/etc/workloads.d/<name>/workload.toml` bundles into isolated rootless-podman container workloads *and* KVM/QEMU VMs. It ships inside the hypervisor image but is developed and tested independently.

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

# run a single test module / case (from workloadctl/; no PYTHONPATH needed)
python3 -m unittest tests.test_workloads -v
python3 -m unittest tests.test_workloads.SomeClass.test_method

# --- image builds (root, requires podman; *-local skip the registry push) ---
just build-base-local                 # hypervisor-bootc from local minimal
just build-nvidia-rpmfusion-local
just build-all-local
just build-iso-base                    # installer ISO
just aio-local                         # build + qcow2 + deploy to a libvirt VM

# --- runtime rung (workloadctl/; boots a harness-owned VM, runs runtime checks) ---
cd workloadctl && just test-runtime    # WLRT_MODE=dev (default): cached Fedora Cloud image + local RPM
WLRT_MODE=gate just test-runtime       # gate: real bootc image via bootc-image-builder + swtpm (B1b)
                                       # both skip cleanly without /dev/kvm + QEMU
```

There is no Python package manager / venv — scripts run against the system `python3` (3.14; Fedora 43 and 44 both ship it). `lib/` has no third-party deps; everything is stdlib + `tomllib`.

`lib/` is a flat set of top-level modules, not a package. On a host the RPM installs every entrypoint (the CLI, generator, and libexec helpers) *into* `/usr/libexec/workloadctl` alongside the modules, so each finds them via its own `sys.path[0]` — no `.pth`, nothing on any other process's path. The CLI reaches PATH through a thin `%{_bindir}/workloadctl` exec wrapper into that private dir. In the test suite, `tests/__init__.py` puts `lib/` on `sys.path` (and provides `load_script()` for the extension-less entrypoints and `script_env()` for subprocess launches). Test modules import as `tests.<name>` — hence `just test` runs `unittest discover -t .` — and no test module does its own `sys.path` surgery.

## workloadctl architecture

The hard-won design rationale lives in `workloadctl/llms.txt` and `workloadctl/docs/` — read those before changing boot/generator/secret behavior. Key points:

- **Boot flow is split deliberately.** A tiny *shell* systemd generator (`generators/workload-generator`) emits one oneshot, `workload-generate.service`, which runs the *Python* `generators/workload-generate` during early boot (`After=sysinit.target Before=basic.target`) to write sysusers configs + per-workload unit files into `/run/systemd/system/`. Python is kept out of generator context on purpose — generators must be fast/minimal and Python import overhead blows the systemd 258+ budget. Both layers always exit 0 so a failure never blocks boot. The generate step is read-only w.r.t. `/var`.
- **All `/var` work is deferred** to `libexec/workload-ensure-user`, run as `ExecStartPre` of each workload service (subuid/subgid ranges, home + volume dirs, EnvironmentFile, linger).
- **One dedicated locked-down system user per workload** (`_wl-<name>`, UID 10000+, `/usr/sbin/nologin`), each with its own rootless podman instance. No privileged containers.
- **Default service type is `Type=exec`.** `Type=notify`/`--sdnotify=conmon` is broken when linger is active (conmon migrates cgroups and the `READY=1` is dropped) — don't switch the default. See the comment block in `generators/workload-generate` around `service_type`.
- **`lib/podman.py`** is the typed podman wrapper: it parses `podman inspect --format=json` into structured data. Use it rather than shelling out with go-template format strings.
- **Reading workload container logs:** units run `--log-driver=passthrough`, so `podman logs` fails (`cannot read logs: this container is not logging output`). Use `workloadctl logs <name>` — it wraps journalctl OR-ing `_SYSTEMD_UNIT=`/`UNIT=` with `SYSLOG_IDENTIFIER=`, because journald attributes passthrough app output to the rootless user manager's cgroup (`user@<uid>.service`), not the workload unit — a unit-only filter shows just systemd's start/stop lines. Raw per-container output: `journalctl -t workload-<name>-<container>` (add `-f` to tail).

### Code layout (workloadctl/)

- `bin/workloadctl` — the CLI (argparse). One `cmd_<name>(args, manager)` function per subcommand, wired up in `main()`. Mutating commands call `require_root()`.
- `lib/workload_lib.py` — `WorkloadConfig` / `WorkloadManager`, TOML loading, paths, constants (`VM_BRIDGE_NAME`, UID math).
- `generators/`, `libexec/` — boot-time and helper scripts (also the `workload-vm-*` VM helpers and `workload-exporter` for Prometheus metrics).
- `workloads/<name>/` — the shipped bundles. Each is a directory with `workload.toml` at minimum, plus optional extras it needs: a `Containerfile` for self-built images, `README.md`, `cloud-init/`, additional unit files. `docs/schema-reference.toml` is the annotated full schema.
- `tests/` — `test_*.py` unittest modules.

### Workload topologies

`workload.mode` selects how a TOML maps to units: `single` (one `[container]`), `pod` (multiple `[[containers]]` sharing a netns, talk on localhost), `bridge` (per-container netns on an auto-created `workload-<name>-net`, resolve by container name). The generator's `normalize_containers()` collapses single/multi shapes so single-container TOMLs produce byte-identical units. Container-targeted CLI commands accept `<workload>/<container>`. `workloads/webproxy-demo/` is the smallest bridge-mode example.

### VM workloads

A TOML with a `[vm]` section (mutually exclusive with `[container]`/`[[containers]]`) runs as raw QEMU/KVM instead of a container — shared `_workload-br` bridge (`VM_BRIDGE_NAME`) + dnsmasq, UEFI/OVMF, split `system.qcow2`/`data.qcow2` with generational rollback (`system.qcow2.gen-N`), virtiofs volumes, cloud-init seed, per-workload SSH key. CLI VM paths use SSH/QMP (`_vm_*` helpers, `libexec/workload-vm-*`) instead of podman. `workloads/virtual-forgejo/` is the live example; see `docs/schema-reference.toml` `[vm]` section.

## Docs policy: tracked files may not cite untracked docs

A citation has to be followable from a clean checkout. `workloadctl/docs/wip/` is gitignored, so nothing tracked may point into it — and don't cite a doc you intend to write later; write it, or state the fact inline instead. `workloadctl/tests/test_doc_citations.py` enforces this repo-wide (every `*.md` reference in every tracked file must resolve to a tracked file) and runs in the normal `just test`.

## Secrets

systemd credentials (`systemd-creds`), AES256-GCM with TPM2 (or host key fallback), decrypted into tmpfs at runtime. Encrypted blobs are safe to commit into images. Reference in env with `${SECRET:name}`. Managed via `workloadctl secret`.

## CI

GitHub Actions (`.github/workflows/`) and a mirrored Forgejo runner (`.forgejo/workflows/`) build images on a weekly cadence (minimal Sat, variants Sun). Note (from project memory): Forgejo itself runs in a container, so container-in-container CI builds don't work there — VM workloads exist partly to provide a native build host for that.

workloadctl has its own test workflows separate from the image builds:

- `workloadctl-test.yml` (GitHub) — **PR gate**: lint + `just test` (unit + integration) on every PR/push touching `workloadctl/`. No VM, no secrets.
- `workloadctl-runtime.yml` (GitHub + mirrored Forgejo) — **cadence gate, not a PR gate**: `just test-runtime` (`WLRT_MODE=dev`, boots a harness-owned VM), scheduled weekly (GitHub Mon, Forgejo Tue) and on `workflow_dispatch`. Both skip cleanly without `/dev/kvm`; the Forgejo mirror runs on a `native` runner (the git VM, per the container-in-container note above) with a persistent image cache.
