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
- `lib/workload_lib.py` — `WorkloadConfig` / `WorkloadManager`, TOML loading, paths, constants (UID math). VM-specific constants live in `lib/vm.py`.
- `generators/`, `libexec/` — boot-time and helper scripts (also the `workload-vm-*` VM helpers and `workload-exporter` for Prometheus metrics). `libexec/agent-broker` is the odd one out: a whole standalone program, not a helper — see below.
- `workloads/<name>/` — the shipped bundles. Each is a directory with `workload.toml` at minimum, plus optional extras it needs: a `Containerfile` for self-built images, `README.md`, `cloud-init/`, additional unit files. `docs/schema-reference.toml` is the annotated full schema.
- `tests/` — `test_*.py` unittest modules.

### Workload topologies

`workload.mode` selects how a TOML maps to units: `single` (one `[container]`), `pod` (multiple `[[containers]]` sharing a netns, talk on localhost), `bridge` (per-container netns on an auto-created `workload-<name>-net`, resolve by container name). The generator's `normalize_containers()` collapses single/multi shapes so single-container TOMLs produce byte-identical units. Container-targeted CLI commands accept `<workload>/<container>`. `workloads/webproxy-demo/` is the smallest bridge-mode example.

### VM workloads

A TOML with a `[vm]` section (mutually exclusive with `[container]`/`[[containers]]`) runs as raw QEMU/KVM instead of a container — UEFI/OVMF, split `system.qcow2`/`data.qcow2` with generational rollback (`system.qcow2.gen-N`), virtiofs volumes, cloud-init seed, per-workload SSH key. CLI VM paths use SSH/QMP (`_vm_*` helpers, `libexec/workload-vm-*`) instead of podman. `workloads/virtual-forgejo/` is the live example; see `docs/schema-reference.toml` `[vm]` section.

Networking is **passt, not a bridge** (ADR 006, `workloadctl/docs/adr/006-vm-networking-passt-not-managed-bridge.md`). There is no `_workload-br`, no `workload-bridge.service` and no dnsmasq of ours — passt terminates the guest's stack in userspace and re-originates its traffic as host sockets owned by `_wl-<name>`, which is what makes the workload uid an unforgeable selector for `meta skuid` egress policy. Consequences that catch people out: the guest has **no LAN identity of its own** (it is assigned the host's address), `workloadctl exec`/`shell` reach it on a uid-derived management address (`127.128.x.y:2222`, never routable, never configurable), and inbound otherwise needs an explicit `[vm.network].ports`. `[vm.network].bridge` is an escape hatch for a VM that needs a real LAN address; the operator provisions that bridge, workloadctl does not.

Virtiofs volumes have their own design doc, `workloadctl/docs/vm-virtiofs.md` — every guest id squashes to the workload user on the host, the sidecar runs unprivileged with an empty capability bounding set, and the unit must never gain `NoNewPrivileges=` (it breaks the SELinux domain transition and fails with a bare `203/EXEC`).

### The credential broker

`libexec/agent-broker` holds a provider API key that a sandboxed coding-agent VM
is never given, and attaches it to outbound requests the guest makes through it.
It is a whole program (stdlib only, ~600 lines) shipped by the workloadctl RPM.
Callers are identified by the uid owning the far end of the connection.

**One instance per workload, and the guest is never told where it is.** A
workload declaring `[[vm.network.credential]]` material gets
`workload-<name>-broker.service` — written by the generator, `DynamicUser=yes`,
bound to `vm_broker_listen_address(uid)` (`127.129.0.0` + the uid offset), with
a `broker.toml` regenerated into `/run` at every start. Its only caller is that
workload's own egress inspector, which recognises a host whose
`[[vm.network.policy]]` entry names a `credential` and sends that request to the
broker instead of to the origin. So a guest cannot name the broker, cannot
choose to use it, and cannot be pointed at another workload's.

`libexec/workload-vm-broker` is not the broker: it is the one-verb helper that
writes an instance's `broker.toml` (`workload-vm-broker config <name>`), run as
that unit's `ExecStartPre`. `tests/test_vm_broker.py` covers both halves.

There was a host-wide `agent-broker.service` reached by every guest at an
advertised `192.0.2.1:8081` through a uid-keyed nft map. All of it is deleted —
the unit, the map, the skeleton, `WORKLOAD_BROKER_URL`, and `[vm.network].broker`,
which is now a validation error naming `credential` as the replacement. Design,
threat model and operating instructions: `workloadctl/docs/agent-broker.md`.

**The end-to-end seam is proven for this shape, and it took five fixes to get
there.** The rig that proved the old shape (`broker_rig.py`, 18/18 on
2026-08-14) was built around the advertised endpoint and was deleted with it;
its replacement runs on two throwaway workloads and was 35/35 on a KVM host
under enforcing on 2026-09-02. Every defect it found had passed the whole unit
suite, and two of them made the brokered path inert on a real guest: the
terminated session seeded the upstream pool with the ORIGIN connection, so a
brokered request was handed that socket and the broker was never dialled; and
the broker's own 127.129.x.y address is inside `wl_internal4`, so once it WAS
dialled the packet was dropped by the rule that stops a guest reaching the LAN.
The other three: the generated config could not name a provider's
`auth_header`/`auth_format`, so any provider wanting `Authorization: Bearer`
got a 401 on a fully authorised request; two policy entries for one host
rendered a `broker.toml` TOML refuses; and a brokered host was dialled at the
origin and never written to, making the origin's reachability a prerequisite
for a request that goes to loopback. None is visible without a real packet
([[unit-gates-dont-see-the-seam]]). See `workloadctl/tests/manual/README.md`.

## Docs policy: tracked files may not cite untracked docs

A citation has to be followable from a clean checkout. `workloadctl/docs/wip/` is gitignored, so nothing tracked may point into it — and don't cite a doc you intend to write later; write it, or state the fact inline instead. `workloadctl/tests/test_doc_citations.py` enforces this repo-wide (every `*.md` reference in every tracked file must resolve to a tracked file) and runs in the normal `just test`.

## Secrets

systemd credentials (`systemd-creds`), AES256-GCM with TPM2 (or host key fallback), decrypted into tmpfs at runtime. Encrypted blobs are safe to commit into images. Reference in env with `${SECRET:name}`. Managed via `workloadctl secret`.

## CI

GitHub Actions (`.github/workflows/`) and a mirrored Forgejo runner (`.forgejo/workflows/`) build images on a weekly cadence (minimal Sat, variants Sun). Note (from project memory): Forgejo itself runs in a container, so container-in-container CI builds don't work there — VM workloads exist partly to provide a native build host for that.

workloadctl has its own test workflows separate from the image builds:

- `workloadctl-test.yml` (GitHub) — **PR gate**: lint + `just test` (unit + integration) on every PR/push touching `workloadctl/`. No VM, no secrets.
- `workloadctl-runtime.yml` (GitHub + mirrored Forgejo) — **cadence gate, not a PR gate**: `just test-runtime` (`WLRT_MODE=dev`, boots a harness-owned VM), scheduled weekly (GitHub Mon, Forgejo Tue) and on `workflow_dispatch`. Both skip cleanly without `/dev/kvm`; the Forgejo mirror runs on a `native` runner (the git VM, per the container-in-container note above) with a persistent image cache.

<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (60-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk go test             # Go test failures only (90%)
rtk jest                # Jest failures only (99.5%)
rtk vitest              # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk pytest              # Python test failures only (90%)
rtk rake test           # Ruby test failures only (90%)
rtk rspec               # RSpec test failures only (60%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->