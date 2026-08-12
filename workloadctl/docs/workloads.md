> **Disclaimer:** This documentation and the software it describes are provided as-is, without warranty of fitness for any particular purpose. The implementation is largely AI-assisted. Validate behavior against your own requirements before relying on it in production.

# Rootless Workload Provisioning System

## Table of Contents

- [Quick Start](#quick-start)
- [Common Commands](#common-commands)
- [Core Concepts](#core-concepts)
- [Configuration Guide](#configuration-guide)
  - [Basic Configuration](#basic-configuration)
  - [Systemd Containers](#systemd-containers)
  - [Host Setup Scripts](#host-setup-scripts)
  - [Extra UID/GID Maps](#extra-uidgid-maps)
  - [Resource Constraints](#resource-constraints)
  - [Secrets Management](#secrets-management)
- [Multi-Container Workloads](#multi-container-workloads)
- [VM Workloads](#vm-workloads)
- [Managing Workloads](#managing-workloads)
- [Device Access](#device-access)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)
- [Security Considerations](#security-considerations)
- [Additional Resources](#additional-resources)
- [CLI Reference](cli.md)

---

## Quick Start

There are several ways to create a workload — all produce the same result (a TOML config in `/etc/workloads.d/`):

| Approach | Best for |
|---|---|
| **[From a bundle (`init`)](#bundle-approach)** | Enabling a shipped workload (alloy, jellyfin, vncdesktop, …) |
| **`workloadctl init --scratch <name>`** | Novel container workload with no bundle — generates a stub TOML, no `/usr` fallback |
| **`workloadctl init --scratch-vm <name>`** | Novel **VM** workload — stamps a Fedora Cloud `[vm]` stub + `cloud-init/` seed, enable-ready (see [Scaffolding a new VM](#scaffolding-a-new-vm)) |
| **`workloadctl create`** (below) | From-scratch container workload with no bundle |
| **[Manual TOML](#manual-toml)** | Fine-grained control, scripting, or adapting an example |
| **[bootc image](#bootc-approach)** | Baking workloads into an immutable OS image |

See [cli.md](cli.md) for the full command reference.

---

### Bundle-based approach (`init`) {#bundle-approach}

Shipped workloads arrive as **bundles** — directories under
`/usr/share/workloadctl/workloads/<bundle>/` that pair a template `workload.toml`
with their control files (Containerfile, `setup.sh`, `policy.cil`, etc.). List
what's available:

```bash
workloadctl catalog
```

Instantiate a bundle into `/etc/workloads.d/`:

```bash
sudo workloadctl init alloy
```

This stamps the bundle's template TOML at `/etc/workloads.d/alloy/workload.toml`. Control
files are **not** copied — they're resolved from the `/usr` bundle tree at
build/enable time, so the instance picks up changes automatically when the package
upgrades.

**Typical flows:**

*Pull-only bundle (image is pre-built):*
```bash
sudo workloadctl init alloy
sudo workloadctl edit alloy        # set CENTRAL_HOST, HOST_LABEL, etc.
sudo workloadctl enable alloy
```

*Build-from-source bundle:*
```bash
sudo workloadctl init vncdesktop-sway
sudo workloadctl edit vncdesktop-sway   # configure as needed
sudo workloadctl build vncdesktop-sway
sudo workloadctl enable vncdesktop-sway
```

*Override a control file (copy-on-write, like `systemctl edit`):*
```bash
sudo workloadctl init vncdesktop-sway
sudo workloadctl edit vncdesktop-sway Containerfile   # seeds from /usr, opens $EDITOR
sudo workloadctl build vncdesktop-sway
sudo workloadctl enable vncdesktop-sway
```

The override is kept only if you change it — a byte-identical file is discarded so
it never freezes the bundle's upgrade tracking. Use `info --files` to see the merged
control-file view (which source wins for each file). See [`init`](cli.md#init) and
[`edit`](cli.md#edit) in the command reference.

**Multiple instances of the same bundle:**

```bash
sudo workloadctl init alloy --as alloy-lan
```

`--as` names the instance; `init` records `[workload] bundle = "alloy"` in the new
TOML so control-file lookups still resolve to the source bundle. Both instances share
the same Containerfile and support scripts; each has its own TOML, user, and state.

**Installing a custom workload directory (`install`):**

If you have a workload directory (e.g., checked out from a repo or written locally)
that you want to promote into the system, use `install`:

```bash
sudo workloadctl install ./my-workloads/myapp/
```

This copies the entire directory into `/etc/workloads.d/<name>/` where `<name>` is
taken from `[workload].name` in the source `workload.toml` (not the directory name).
File modes are preserved, so an executable `setup.sh` stays executable. Errors if the
workload already exists (edit in place or use `duplicate` to rename). The source is
never modified. See [`install`](cli.md#install) in the command reference.

---

### CLI approach

Deploy a web server in just one command:

```bash
sudo workloadctl create webserver \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --ports 8080:8080 \
  --enable

# Or with host networking for maximum performance:
sudo workloadctl create webserver \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --network host \
  --enable
```

Your web server is now running, will start automatically at boot, and runs as an isolated unprivileged user with rootless podman.

Check it's running:
```bash
workloadctl status webserver
curl http://localhost:8080
```

---

### Manual TOML approach {#manual-toml}

Useful when you want full control over the config or are adapting an existing example:

1. Create a config file:
```bash
sudo nano /etc/workloads.d/webserver/workload.toml
```

2. Add this minimal configuration:
```toml
[workload]
name = "webserver"

[container]
image = "docker.io/nginxinc/nginx-unprivileged:alpine"

[network]
ports = ["8080:8080"]
```

3. Enable and start:
```bash
sudo workloadctl enable webserver
```

See [schema-reference.toml](schema-reference.toml) for all available config options.

---

### bootc approach {#bootc-approach}

For immutable OS images, place workload configs directly in the image:

```dockerfile
# In your hypervisor.Containerfile
COPY workloads.d/ /etc/workloads.d/
```

Workloads that carry a `.enabled` marker (created by `workloadctl enable`, or shipped alongside the config in the image) will be provisioned automatically on first boot. The TOML format is identical — only the delivery mechanism differs. See the [Bootc Integration section in secrets.md](secrets.md#bootc-integration) for handling secrets in immutable images.

---

## Common Commands

### Quick Command Reference

| Task | Command |
|------|---------|
| **Create workload** | `sudo workloadctl create NAME --image IMAGE [OPTIONS]` |
| **List all workloads** | `workloadctl list` |
| **Enable workload** | `sudo workloadctl enable NAME` |
| **Disable workload** | `sudo workloadctl disable NAME` |
| **Cleanup orphans** | `sudo workloadctl cleanup [--apply]` |
| **View status** | `workloadctl status NAME` |
| **View logs** | `workloadctl logs [-f] NAME` |
| **Shell access** | `sudo workloadctl shell NAME` |
| **Execute command** | `workloadctl exec NAME COMMAND` |
| **Update image** | `sudo workloadctl update NAME` |
| **Rollback image** | `sudo workloadctl rollback NAME` |
| **Recreate** | `sudo workloadctl recreate NAME` |
| **Show details** | `workloadctl info NAME` |
| **Validate config** | `workloadctl validate NAME` |
| **Edit config** | `sudo workloadctl edit NAME` |
| **Monitor resources** | `workloadctl stats [-f] [NAME]` |
| **Check health** | `workloadctl health NAME` |
| **Copy files** | `workloadctl cp SRC DEST` |
| **Manage images** | `workloadctl images list\|prune` |
| **Manage secrets** | `sudo workloadctl secret create\|list\|show\|rotate\|delete NAME` |
| **Export/import secrets** | `sudo workloadctl secret export\|import NAME` |
| **Backup workload** | `sudo workloadctl backup NAME` |
| **Backup all** | `sudo workloadctl backup --all` |
| **Restore workload** | `sudo workloadctl restore ARCHIVE [--enable]` |

### Key Features

- ✅ Declarative configuration with simple TOML files
- ✅ Automatic startup at boot via systemd
- ✅ Rootless containers for security isolation
- ✅ GPU and hardware device access when needed
- ✅ Docker/kubectl-like CLI for easy management
- ✅ No root required for read-only operations

---

## Core Concepts

### Architecture

The workload provisioning system allows you to declaratively define long-running containerized workloads that start automatically at boot. Each workload runs as a dedicated system user with rootless podman, providing isolation while maintaining access to host hardware when explicitly configured.

**Boot Flow:**
```
1. systemd-generators → workload-generator (tiny shell generator)
   emits workload-generate.service into /run/systemd/generator/
2. workload-generate.service (early-boot oneshot, After=sysinit.target
   Before=basic.target) runs the Python workload-generate script, which
   writes sysusers configs and per-workload unit files into /run/systemd/system/
3. workload-{name}-setup.service (per-workload oneshot) runs systemd-sysusers
   and workload-ensure-user to create the user, subuid/subgid, home directory,
   EnvironmentFile, and linger
4. workload-{name}.service → individual containers start
```

### Components

- **Shell generator** (`/usr/lib/systemd/system-generators/workload-generator`, source: `generators/workload-generator`): A minimal shell generator that emits a single oneshot service unit (`workload-generate.service`). Does not read workload configs; its only job is to schedule the Python script as an early-boot service. Kept tiny so it fits comfortably inside the generator execution budget systemd enforces.
- **Workload generator script** (`/usr/libexec/workloadctl/workload-generate`): The Python script that actually reads `/etc/workloads.d/*/workload.toml` and emits per-workload unit files + sysusers configs into `/run/systemd/system/`. Runs as an early-boot oneshot service (not as a systemd generator — see "Why the split?" below).
- **User Setup** (`/usr/libexec/workloadctl/workload-ensure-user`): Runs as `ExecStartPre` in each workload service to configure subordinate UID/GID ranges, create home and volume directories, write the EnvironmentFile, and enable linger. Handles all `/var` work, which must not happen from generator or early-boot-oneshot context.
- **Workload Services**: Per-workload systemd services that run `podman run` as dedicated users
- **Management Tool** (`workloadctl`): Docker/kubectl-like CLI for managing workloads

**Why the split?** systemd expects generators to be fast, minimal, and side-effect-free (see `systemd.generator(7)`). A Python script that parses TOML, validates configs, and emits hundreds of lines of unit files does not fit that contract — Python import overhead alone can exceed the execution budget systemd 258+ enforces on generators. So we keep the real generator tiny (shell, emits one unit) and move the actual generation work into an early-boot oneshot service that runs after the generator phase but before `basic.target`.

### User Management

Each enabled workload gets a dedicated system user:
- **Username:** `_wl-{name}` (e.g., `_wl-webserver`)
- **UID:** Auto-assigned from range 10000-52948
- **Subuid range:** Automatically allocated with 65536 UIDs per workload
- **Home directory:** `/var/lib/workloads/{name}`
- **Shell:** `/usr/sbin/nologin` (service user, no interactive login)
- **Isolation:** Rootless podman with user namespaces, SELinux, and systemd service boundaries

### Network Modes

**Default:** The default network mode is `pasta`, providing network isolation with port forwarding.

**Available modes:**
- **pasta** (default): Isolated networking with port forwarding - secure and works reliably in Podman 5.3+
- **host**: Share host network namespace - no isolation, maximum performance, no port mapping needed
- **none**: No networking at all - complete isolation
- **custom**: User-defined network name for container-to-container communication

**When to use host mode:**
- Apps requiring network discovery (mDNS, UPnP, DLNA) - examples: Plex, Home Assistant
- Maximum network performance needed
- Apps that dynamically bind many ports

**When to use pasta mode (default):**
- Security-sensitive workloads needing network isolation
- Standard web services with known ports
- Most containerized applications

```toml
[network]
mode = "pasta"  # Default - isolated network with port forwarding (recommended)
# mode = "host"   # Share host network, no isolation
# mode = "none"   # No networking at all
# mode = "mynet"  # Custom network (create first: podman network create mynet)
ports = ["8080:8080"]  # Port forwarding for pasta and custom network modes
```

### Privileged Ports (< 1024)

Rootless workloads bind ports as the unprivileged `_wl-<name>` user, so by
default they cannot use ports below 1024. The hypervisor image ships a
sysctl drop-in (`/usr/lib/sysctl.d/50-privileged-ports.conf`) that sets:

```
net.ipv4.ip_unprivileged_port_start = 0
```

This lifts the restriction across the host, so workloads can bind 53, 80,
443, etc. directly — no `setcap`, no DNAT redirects, no NET_BIND_SERVICE
capability. This is what lets `smb-server` use 139/445, `pihole` answer DNS
on 53, and reverse-proxy workloads bind 80/443 as ordinary users.

If you are running outside the hypervisor image and need this behavior, add
the same drop-in yourself:

```bash
echo 'net.ipv4.ip_unprivileged_port_start = 0' | sudo tee /etc/sysctl.d/50-privileged-ports.conf
sudo sysctl --system
```

Tradeoff: any unprivileged user on the host (not just workload users) can
bind low ports. On a single-purpose hypervisor with no interactive users
this is fine; in shared environments, consider per-binary `setcap
cap_net_bind_service=+ep` instead.

---

## Configuration Guide

### Basic Configuration

Workload configurations are TOML files in `/etc/workloads.d/`. See [schema-reference.toml](schema-reference.toml) for full documentation.

**Minimal Example:**

```toml
[workload]
name = "webserver"

[container]
image = "docker.io/nginxinc/nginx-unprivileged:alpine"

[network]
ports = ["8080:8080"]
```

**Applying Changes:**

After modifying a workload TOML:

```bash
sudo workloadctl recreate NAME
```

That re-runs the per-workload unit generator, reloads systemd, and restarts the service. **Plain `systemctl daemon-reload` is not enough.** Daemon-reload only re-runs the *systemd shell-generator*, which emits the `workload-generate.service` oneshot but does not run it — so the per-workload unit files in `/run/systemd/system/` keep their previous content until the next boot (or until you call `recreate`, which runs the Python generator explicitly).

This trips most often on `[container.environment]` and `[security.extra_groups]` changes, because those values are inlined into the unit file at generate time. Values that flow through `EnvironmentFile=` (UID-derived `XDG_RUNTIME_DIR`, the auto-detected `HOST_IP`, and decrypted `${SECRET:...}` env vars) are re-read on each service start, so for those a plain restart is sufficient.

`workloadctl edit NAME` is the validated path — it opens the TOML in `$EDITOR`, validates on save, and then runs the same regen + restart as `recreate`.

---

### Systemd Containers

Containers that run systemd as PID 1 (e.g., desktop environments, multi-service containers) need special handling. Set `container.systemd` to control this:

```toml
[container]
systemd = "always"  # or "true", "false"
```

| Value | Behavior |
|-------|----------|
| (unset) | Default: `--init` for zombie reaping, podman auto-detects systemd |
| `"always"` | Force `--systemd=always`, skip `--init`, add `KillSignal=SIGRTMIN+3` |
| `"true"` | Force `--systemd=true`, skip `--init`, add `KillSignal=SIGRTMIN+3` |
| `"false"` | Force `--systemd=false`, skip `--init` (container has its own init) |

Use `"always"` for containers with systemd as PID 1. Any value skips `--init` — if you set this field, you're opting out of podman's default init process.

The shared memory size can also be configured for containers that need more than the 64MB default (common for Firefox, GPU apps, databases):

```toml
[resources]
shm_size = "2g"
```

---

### Host Setup Scripts

Some workloads need host-level configuration (kernel modules, udev rules, SELinux policies) that can't be handled from inside the container. The `[host]` section lets you declare a setup script:

```toml
[host]
setup = "setup.sh"  # relative to /usr/share/workloadctl/workloads/{name}/
```

- `workloadctl enable` runs `setup.sh enable`
- `workloadctl disable` runs `setup.sh disable`
- `workloadctl doctor` / `diagnose` run `setup.sh artifacts` — see below
- The script runs as root and should be idempotent in both directions
- Absolute paths are supported: `setup = "/home/myuser/my-setup.sh"`

**Declaring what you install (`artifacts`).** Anything the script puts on the
host outside `/run/systemd/system` — a unit file, an avahi service, a minted
cert — is invisible to `doctor`, `diagnose`, `drift` and `health`, which model a
workload from the generator's output alone. A sidecar can restart-loop for a
week behind a clean report. So the script declares its own artifacts: on
`artifacts` it prints one `<kind> <ref>` per line and exits 0, where kind is
`unit` (a systemd unit name) or `file` (an absolute path).

```
unit  games-udev-relay.service
file  /etc/avahi/services/games-sunshine.service
```

Rules that matter:

- **Read-only.** This runs from report verbs. Don't mutate anything, and print
  nothing else on stdout.
- **Key refs to `${WORKLOAD_NAME}`, not the bundle** — the same rule as the rest
  of the script, since `init --as` makes those different names.
- **Declare conditionally where `enable()` is conditional.** An artifact you
  deliberately skip on this host (a cert you can't mint for want of a CA) must
  not be declared, or a documented skip is reported as a fault.
- **Don't declare what you don't own.** A system-wide SELinux boolean or an
  image-shipped udev rule is shared; two workloads declaring it would each
  report the other's teardown as their own breakage.
- **Omitting the action is fine.** A script without it falls through its own
  dispatch to a nonzero exit, which reads as *undeclared* — unknown, reported,
  not a failure. Only an exit-0 empty answer means "installs nothing".

#### Customizing control files (Containerfile, setup.sh, policy.cil)

Control files ship read-only under `/usr/share/workloadctl/workloads/<bundle>/` (immutable on bootc/ostree). Don't copy the directory — use the copy-on-write override, the same `/usr`→`/etc` idiom systemd uses for unit drop-ins:

```bash
workloadctl edit <name> Containerfile   # seeds /etc/workloads.d/<name>/Containerfile from the shipped default, then opens $EDITOR
workloadctl info <name> --files         # merged view: which file wins — /etc (override) or /usr (shipped)
sudo workloadctl build <name>           # rebuild the image from the override-resolved context
```

The override at `/etc/workloads.d/<name>/<file>` wins over the shipped default and is what `build` (and enable's setup/SELinux steps) resolve. Untouched control files keep tracking the image across upgrades; only the files you actually change live in `/etc`. An edit that ends up byte-identical to the shipped default is discarded, so nothing freezes needlessly.

To use a custom setup script with `workloadctl enable`, set an absolute path in your workload config:

```toml
[host]
setup = "/home/myuser/sunshine-custom/setup.sh"
```

Example setup script pattern:

```bash
#!/bin/bash
set -euo pipefail

WORKLOAD_NAME="${WORKLOAD_NAME:?run via workloadctl enable/disable}"
RELAY_UNIT="${WORKLOAD_NAME}-udev-relay.service"

enable() {
    # Load kernel module, add udev rules, install SELinux policy...
}

disable() {
    # Reverse the above
}

artifacts() {
    # Read-only: what enable() installs on the host, for `workloadctl doctor`.
    echo "unit ${RELAY_UNIT}"
    return 0
}

case "${1:-}" in
    enable)    enable ;;
    disable)   disable ;;
    artifacts) artifacts ;;
    *)         echo "Usage: $0 {enable|disable|artifacts}" >&2; exit 1 ;;
esac
```

#### Tuning the per-workload SELinux policy

When `selinux_policy = true`, each workload runs under its own type `wl_<name>.process` (dashes become underscores), loaded from the bundle's `policy.cil` by `workloadctl enable`. That file is a [udica](https://github.com/containers/udica)-generated CIL module — a `blockinherit container` scaffold plus hand-appended `(allow …)` rules. **udica is the authoring tool**; reach for it instead of writing `.te`/`checkpolicy` by hand.

**1. Generate the base** from the container's *static* access surface (devices, mounts, ports, caps):

```bash
u=$(id -u _wl-<name>)
sudo -u _wl-<name> XDG_RUNTIME_DIR=/run/user/$u podman inspect <container> > /tmp/<name>.json
udica -j /tmp/<name>.json wl_<name>
```

**2. Capture runtime denials.** The access an app only needs once it's *running* — JIT `execmem`, a debugger's `ptrace`, GTK/glycin's `bwrap` image-decode sandbox mounts — never appears in the container config, so you collect it by exercising the app. Mark **just this workload's type** permissive so it runs unimpeded, and disable `dontaudit` so suppressed denials are logged too (many userns-mount denials are `dontaudit`'d and are otherwise invisible even to `ausearch`):

```bash
sudo semanage permissive -a wl_<name>.process   # log-but-allow — this domain only, rest of host stays enforcing
sudo semodule -DB                                # also log dontaudit-suppressed denials
#   … exercise the app: launch it, open a project, index, build, run the debugger …
sudo ausearch -m avc -ts recent | grep wl_<name> > /tmp/<name>-avcs.log
```

**3. Fold them in** with udica's append mode (`-a`), then return to enforcing:

```bash
udica -j /tmp/<name>.json -a /tmp/<name>-avcs.log wl_<name>   # regenerate CIL including the runtime rules
sudo semodule -B
sudo semanage permissive -d wl_<name>.process                # back to enforcing — do not skip this
```

**4. Transplant into the bundle.** The bundle's `policy.cil` uses a `__WL_MODULE__` placeholder that `enable` substitutes with the name-keyed block, so don't drop udica's whole module in verbatim — lift its generated `(allow process … )` lines into the existing `__WL_MODULE__ (block …)`. Then edit the bundle (or `workloadctl edit <name> policy.cil` for a CoW override) and re-run `sudo workloadctl enable <name>` to reinstall the module. A policy-only change applies **live** to the running container — no `recreate` needed.

> **If a denial never appears even under `semanage permissive`**, it's usually `dontaudit`-suppressed — capture with `semodule -DB` as above (and remember `semodule -B` afterward). Symptom-level tell: if a syscall is *allowed by seccomp* but the operation still fails with `EPERM`, suspect a missing SELinux `allow` rather than seccomp.

---

### Extra UID/GID Maps

When using `userns = "keep-id"` with `extra_groups`, the generator automatically maps the workload user's UID/GID and all extra group GIDs into the container's user namespace. This is needed for containers that run systemd (which needs valid UIDs/GIDs inside the namespace) while still using keep-id for host device access.

The maps are deferred — computed at service start by `workload-ensure-user` rather than at generator time, since the workload user may not exist yet on first boot.

For most workloads, auto-population from `extra_groups` is sufficient:

```toml
[security]
userns = "keep-id"
extra_groups = ["video", "render", "input"]
# uidmaps/gidmaps auto-generated from workload user + these groups
```

For advanced cases, you can add explicit maps:

```toml
[security]
extra_uidmaps = ["+1000:@1000:1"]
extra_gidmaps = ["+1000:@1000:1"]
```

If a group from `extra_groups` doesn't exist on the host, the generator warns and skips that gidmap.

---

### Resource Constraints

Control CPU, memory, I/O, and process limits for workloads using systemd cgroup v2 controls. Resource limits prevent workloads from consuming excessive system resources and allow you to prioritize critical workloads.

> **How enforcement works.** The generator redirects each workload's user manager (`user@<uid>.service`) into `workloads.slice` via a drop-in, so the container payload lands inside the aggregate slice. Workload-level caps (`memory_max`, `memory_high`, `cpu_weight`, etc.) become `[Service]` directives on that drop-in and bind the whole workload subtree. Per-container caps (`memory_max` on a `[[containers]]` entry, `cpu_quota`, `pids_max`, etc.) are passed as podman flags (`--memory`, `--cpus`, `--pids-limit`, …) and bind natively. All modes (single, pod, bridge) enforce equally. See [docs/adr/001-container-cgroup-placement.md](adr/001-container-cgroup-placement.md).

#### Workloads Slice (aggregate protection)

All workloads run inside `workloads.slice` by default, which provides aggregate resource limits that protect the host even if individual workloads have no limits set:

| Resource | Slice Default | Effect |
|----------|--------------|--------|
| `CPUWeight` | 80 | Workloads yield CPU to system services under contention |
| `MemoryMax` | 90% | All workloads combined can never exceed 90% of system RAM |
| `MemoryHigh` | 85% | Throttling begins at 85% to avoid hitting the hard limit |
| `MemorySwapMax` | 90% | Workloads can use up to 90% of RAM worth of swap (prevents unbounded zram inflation) |
| `IOWeight` | 80 | System I/O gets priority under contention |

To override the slice for a specific workload:

```toml
[resources]
slice = "gpu-workloads.slice"  # Use a different slice
# slice = "system.slice"       # Or opt out of workloads.slice entirely
```

The default `workloads.slice` is shipped with workloadctl and can be customized via a systemd drop-in (e.g., `/etc/systemd/system/workloads.slice.d/override.conf`).

#### Per-workload limits

Individual workloads have no per-workload limits by default (they share the slice budget). It's good practice to set at least `memory_max` on production workloads to provide a per-workload ceiling within the slice:

```toml
[resources]
memory_max = "4G"   # Hard ceiling — container is OOM-killed if exceeded
memory_high = "3G"  # Soft limit — starts throttling before the ceiling
```

#### Quick Reference

| Resource Type | Option | Example | Effect |
|--------------|---------|---------|---------|
| **CPU Quota** | `cpu_quota` | `"50%"` | Limit to 0.5 cores (hard limit) |
| **CPU Priority** | `cpu_weight` | `500` | Higher scheduling priority (1-10000) |
| **Memory Hard Limit** | `memory_max` | `"2G"` | OOM kill at 2GB |
| **Memory Soft Limit** | `memory_high` | `"1.5G"` | Start throttling at 1.5GB |
| **Swap Limit** | `memory_swap_max` | `"0"` | Disable swap (or set size like `"1G"`) |
| **I/O Priority** | `io_weight` | `500` | Higher I/O priority (1-10000) |
| **I/O Bandwidth** | `io_read_bandwidth_max` | `["/dev/sda 50M"]` | Limit disk reads to 50 MB/s |
| **Process Limit** | `tasks_max` | `100` | Max 100 threads/processes |
| **Start Timeout** | `timeout_start_sec` | `600` | 10 minutes for slow image pulls |
| **Stop Timeout** | `timeout_stop_sec` | `60` | 1 minute for graceful shutdown |

#### Common Patterns

**Lightweight web server (limit resources):**
```toml
[workload]
name = "nginx"

[container]
image = "nginx:alpine"

[resources]
cpu_quota = "50%"      # Half a CPU core max
memory_max = "512M"    # 512MB hard limit
memory_high = "384M"   # Start throttling at 384MB
tasks_max = 50         # Limit worker processes
```

**High-priority workload:**
```toml
[workload]
name = "gaming"

[container]
image = "gaming-vm:latest"

[resources]
cpu_weight = 500        # Higher CPU priority when competing
memory_max = "8G"       # Generous memory limit
memory_swap_max = "0"   # Disable swap for low latency
io_weight = 500         # Higher I/O priority
```

**Database with I/O limits:**
```toml
[workload]
name = "postgres"

[container]
image = "postgres:16"

[resources]
cpu_quota = "200%"      # 2 CPU cores
memory_max = "4G"
memory_high = "3G"
memory_swap_max = "0"   # No swap for databases
io_weight = 500         # High I/O priority
io_read_bandwidth_max = ["/dev/sda 200M"]
io_write_bandwidth_max = ["/dev/sda 100M"]
```

#### Using workloadctl create with resource limits

```bash
# Lightweight web server
sudo workloadctl create nginx \
  --image nginx:alpine \
  --ports 8080:80 \
  --cpu-quota "50%" \
  --memory-max "512M" \
  --memory-high "384M" \
  --tasks-max 50 \
  --enable

# High-priority workload
sudo workloadctl create gaming \
  --image gaming-vm:latest \
  --network host \
  --gpu amd \
  --cpu-weight 500 \
  --memory-max "8G" \
  --memory-swap-max "0" \
  --enable
```

**Available resource flags:**
- `--cpu-quota PERCENT` - CPU quota (e.g., 50%, 100%, 200%)
- `--cpu-weight WEIGHT` - CPU scheduling weight (1-10000)
- `--memory-max SIZE` - Maximum memory (e.g., 512M, 2G)
- `--memory-high SIZE` - Memory soft limit (e.g., 384M, 1.5G)
- `--memory-swap-max SIZE` - Max swap (0 to disable, or size)
- `--io-weight WEIGHT` - I/O scheduling weight (1-10000)
- `--tasks-max NUM` - Maximum tasks/threads

For advanced options like I/O bandwidth limits or custom directives, edit the config file with `workloadctl edit <name>`.

#### Advanced: Custom Systemd Directives

For fine-grained control not covered by convenience options:

```toml
[resources]
# Standard options
cpu_quota = "200%"
memory_max = "2G"

# Custom systemd directives (escape hatch)
custom_directives = {
  LimitNOFILE = "65536",           # Max open file descriptors
  OOMScoreAdjust = "-500",         # Less likely to be OOM killed
  CPUAffinity = "0-3",             # Pin to CPU cores 0-3
  Nice = "-5",                     # Process priority (-20 to 19)
  IOSchedulingClass = "realtime",  # Real-time I/O scheduling
  IOSchedulingPriority = "0"       # Highest I/O priority (0-7)
}
```

**Warning:** Custom directives are passed directly to systemd. Typos or invalid values will cause service failures.

**Reference:** See `man systemd.exec` and `man systemd.resource-control` for all available directives.

#### Monitoring Resource Usage

```bash
# Real-time stats with workloadctl
workloadctl stats webserver
workloadctl stats -f              # All workloads, live updating

# Check with systemd
systemctl status workload-{name}.service
systemd-cgtop

# Check memory limits
cat /sys/fs/cgroup/workloads.slice/workload-{name}.service/memory.max
cat /sys/fs/cgroup/workloads.slice/workload-{name}.service/memory.current

# Check CPU limits
systemctl show workload-{name}.service -p CPUQuota
systemctl show workload-{name}.service -p CPUWeight

# Check slice aggregate usage
systemctl status workloads.slice
systemd-cgtop /workloads.slice
```

For complete resource documentation with detailed examples, see [schema-reference.toml](schema-reference.toml).

---

### Secrets Management

The workload system uses **systemd credentials** for secure secrets management. This allows you to safely store API keys, passwords, certificates, and other sensitive data.

#### Quick Start with Secrets

1. **Create an encrypted credential:**
```bash
# Interactive (recommended)
sudo workloadctl secret create my-api-key

# From a file (for certificates, keys)
sudo workloadctl secret create tls-cert --file /path/to/cert.pem
```

2. **Reference the secret in your workload config:**
```toml
[workload]
name = "myapp"

[container]
image = "myapp:latest"

[container.environment]
API_KEY = "${SECRET:my-api-key}"
DATABASE_PASSWORD = "${SECRET:db-password}"
PUBLIC_URL = "https://example.com"  # Plain values work too
# Credentials auto-detected from ${SECRET:...} references
```

3. **Enable the workload:**
```bash
sudo workloadctl enable myapp
```

The secrets are automatically decrypted at boot and injected as environment variables into your container.

#### Secret Commands

| Command | Description |
|---------|-------------|
| `sudo workloadctl secret create NAME` | Create secret interactively |
| `sudo workloadctl secret create NAME --file PATH` | Create from file |
| `sudo workloadctl secret list` | List all secrets |
| `sudo workloadctl secret show NAME` | Show decrypted secret |
| `sudo workloadctl secret rotate NAME` | Update and restart affected workloads |
| `sudo workloadctl secret delete NAME` | Delete secret |
| `sudo workloadctl secret export NAME [-o FILE]` | Export with passphrase (portable) |
| `sudo workloadctl secret import NAME FILE [--force]` | Import and re-encrypt with TPM |

#### Mounting Secrets as Files

For TLS certificates, SSH keys, or config files:

```toml
[secrets]
# Credentials auto-detected from files[] entries
files = [
    { credential = "tls-cert", path = "/etc/ssl/cert.pem" },
    { credential = "tls-key", path = "/etc/ssl/key.pem" },
    { credential = "ssh-key", path = "/home/user/.ssh/id_rsa" }
]
```

#### Security Features

- **Encrypted at rest** with AES256-GCM
- **TPM2-backed encryption** (hardware security)
- **Decrypted into RAM only** (tmpfs, never touches disk unencrypted)
- **Per-workload isolation** (workloads can't see each other's secrets)
- **Automatic cleanup** when service stops
- **Safe to commit to git** (encrypted credential files)

#### Encryption Key Types

- **tpm2** (recommended): Hardware-backed, machine-specific
- **host**: Software key, machine-specific
- **host+tpm2**: Both required (maximum security)

Example with custom key type:
```bash
sudo workloadctl secret create my-secret --key-type host+tpm2
```

#### Complete Documentation

For comprehensive secrets management documentation, see:
- [docs/secrets.md](secrets.md) - Complete guide
- [examples/example-with-secrets.toml](examples/example-with-secrets.toml) - Working example
- [schema-reference.toml](schema-reference.toml) - Full schema with secrets

---

## Multi-Container Workloads

A single workload can run **multiple containers** together under one workload
user (`_wl-<name>`). This suits stacks where containers belong together — a
reverse proxy in front of an app, a service plus its database — so they share
a lifecycle, a home directory, and a single `systemctl`/`workloadctl` target.

Instead of one top-level `[container]` block, a multi-container workload uses
an array of `[[containers]]` tables, each with a unique `name`:

```toml
[workload]
name = "myapp"
mode = "pod"          # or "bridge" — see below

[[containers]]
name = "web"
[containers.container]
image = "myapp:latest"

[[containers]]
name = "db"
[containers.container]
image = "postgres:16"
```

Single-container TOMLs are unchanged — keep using the top-level `[container]`
block. The generator normalizes them internally, so their generated units stay
byte-for-byte identical.

### Pod mode vs. bridge mode

`workload.mode` selects how the containers network. If omitted, a workload with
`[[containers]]` defaults to `pod`.

| | **pod** | **bridge** |
|---|---|---|
| Network namespace | One, shared by all containers | One per container |
| Container-to-container | `localhost` | By container name (DNS) |
| Port publishing | Once, workload-level `[network]` | Per container, `[containers.network]` |
| User namespace | Workload-level (the pod's infra container owns it) | Per container |
| Best for | Tightly coupled sidecars; one public port surface | Services that talk over a network and need name resolution (app + database) |

**Pod mode** puts every container in one network namespace via `podman pod
create`. Containers reach each other on `localhost`. Publish ports once in the
top-level `[network]` block. Because the pod's infra container owns the shared
user namespace, `userns` / `extra_uidmaps` / `extra_gidmaps` are **workload-level**
(top-level `[security]`) in pod mode — a per-container value is warned and ignored.

**Bridge mode** (`mode = "bridge"`) gives each container its own network
namespace, all joined to an auto-created bridge network (`workload-<name>-net`).
Containers resolve each other by container name. Publish ports per container in
`[containers.network]`; the workload-level `[network].ports` is ignored.

For the field-allocation breakdown (which sections are workload-level vs.
per-container) and full pod/bridge examples, see the **MULTI-CONTAINER
WORKLOADS** section in
[schema-reference.toml](schema-reference.toml).

### Generated units and naming

| Object | Single-container | Multi-container |
|---|---|---|
| Workload user | `_wl-<name>` | `_wl-<name>` (one, shared) |
| Top-level service | `workload-<name>.service` (the container) | `workload-<name>.service` (oneshot **umbrella**) |
| Per-container service | — | `workload-<name>-<ctr>.service` |
| Pod / network service | — | `workload-<name>-pod.service` (pod) or `workload-<name>-net.service` (bridge) |
| Container name | `workload-<name>` | `workload-<name>-<ctr>` |

`systemctl start workload-<name>.service` targets the umbrella, which pulls in
the pod/network service and every container. Stopping it tears the whole
workload down (`PartOf=`). Container names follow the same rules as workload
names: `^[a-z][a-z0-9-]*$`, max 27 characters.

### CLI usage with `NAME/CTR`

`workloadctl` commands accept either the whole workload (`<name>`) or a single
container (`<name>/<ctr>`):

```bash
workloadctl status myapp        # umbrella + pod/net + every container
workloadctl logs myapp          # merged logs from all sub-services
workloadctl logs myapp/web      # just the "web" container
workloadctl exec myapp/db psql  # exec into a specific container
workloadctl shell myapp/web     # shell in a specific container
workloadctl health myapp        # per-container health table
```

Container-targeted commands (`exec`, `shell`) require the `NAME/CTR` form on a
multi-container workload — a bare `NAME` errors and lists the available
containers. Lifecycle commands (`enable`, `disable`, `start`, `stop`, `update`,
`rollback`) always operate on the whole workload: `update` pulls every
container's image and `rollback` reverts them all.

Two example workloads ship as bundles under `workloads/` (both disabled by
default):

- [`webproxy-demo`](../workloads/webproxy-demo/workload.toml) — bridge mode,
  Caddy reverse proxy + a `whoami` backend. No setup required; pulls only
  public images. The smallest end-to-end demonstration of sibling DNS and a
  single published front-end port.
- [`example-multi-container`](../workloads/example-multi-container/workload.toml)
  — bridge mode, Forgejo + PostgreSQL. Closer to a real stack: needs an
  encrypted DB password and may need a registry-policy entry for the Forgejo
  image. Use this as the template for production-shaped workloads.

---

## VM Workloads

In addition to rootless containers, workloadctl can manage KVM/QEMU virtual machines using the same TOML config format and the same CLI commands. A workload is a VM when its config contains a `[vm]` section instead of `[container]` or `[[containers]]`.

### Prerequisites

```bash
sudo dnf install qemu-kvm edk2-ovmf
```

The `workloadctl preflight` command checks these and reports any missing pieces before you try to enable a VM workload.

### Scaffolding a new VM {#scaffolding-a-new-vm}

Rather than hand-writing the `[vm]` section, scaffold a self-contained VM workload the same way you would a container — two symmetric entry points:

```bash
# Stamp a blank, enable-ready VM stub directly into /etc/workloads.d/<name>/
sudo workloadctl init --scratch-vm myvm

# …or instantiate the shipped generic VM bundle (identical starting point)
sudo workloadctl init vm-base --as myvm
```

Both create `/etc/workloads.d/myvm/` containing a `workload.toml` and a `cloud-init/user-data` seed. The stub is **enable-ready out of the box**: it pins the current Fedora Cloud-Base image (`cloud_image_url` + `cloud_image_checksum`) with the `local_image` and `image` alternatives stamped as commented one-line swaps, sane `vcpus`/`memory`/`system_disk_size` defaults, and `user = "fedora"`. It starts disabled (no `.enabled` marker) until you run `workloadctl enable`. The seed already wires up `${WORKLOADCTL_SSH_KEY}` and `${WORKLOADCTL_WORKLOAD_NAME}` (see [Bootstrapping a VM with cloud-init](#bootstrapping-a-vm-with-cloud-init)).

Edit to taste, then enable:

```bash
sudo workloadctl edit myvm        # change base image, sizing, cloud-init
sudo workloadctl enable myvm      # downloads the image, builds the disk, boots
```

> The default base image is a fixed Fedora Cloud-Base release (the download path requires a known checksum, so there is no base-image argument — swap it in the stub instead). Bump it alongside `fedora-versions.yml` when the host's Fedora version moves.

### Basic Configuration

```toml
[workload]
name = "fedora-vm"

[vm]
vcpus = 2
memory = "2048M"
cloud_image_url = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
cloud_image_checksum = "sha256:28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f"
data_disk_size = "50G"
user = "fedora"
```

See [`docs/examples/example-vm-fedora.toml`](examples/example-vm-fedora.toml) for a ready-to-use example, and [`docs/schema-reference.toml`](schema-reference.toml) for all `[vm]` options.

### Image Sources

Exactly one image source is required:

| Key | Description |
|---|---|
| `cloud_image_url` + `cloud_image_checksum` | Download a cloud qcow2 image. Downloaded once to `.image-cache/`, verified by sha256. |
| `local_image` | Copy/reflink from a local path (e.g., a pre-built qcow2). |
| `image` | Build from a bootc OCI container image via `bootc-image-builder`. Requires nested KVM. |

### Disk Layout

Each VM workload keeps its disks in `/var/lib/workloads/<name>/`:

```
/var/lib/workloads/fedora-vm/
  state/                ← reconstructible; skipped by `backup`
    system.qcow2        ← active system disk (cloud image + cloud-init)
    system.qcow2.gen-1  ← previous generation (created by `update`)
    nvram.fd            ← per-workload UEFI NVRAM (copy of OVMF_VARS.fd)
    .ssh/id_ed25519     ← workload SSH keypair (injected via cloud-init)
    .image-cache/       ← downloaded image cache (cloud_image_url source)
  data/                 ← precious; captured by `backup`
    data.qcow2          ← secondary data disk (created if data_disk_size is set)
```

The split is what makes a backup small: everything under `state/` can be rebuilt from the image source, so only `data/` is archived — which is also why anything a VM must keep belongs on the data disk rather than in the guest's root filesystem.

Cloud-init mounts the data disk at `/data` in the guest on first boot, formatting it only when it has no filesystem yet (`blkid` guard). The format, the `/etc/fstab` entry and the mount are guarded separately, so a data disk that arrives already formatted — from a `restore`, whose archive holds `data/` but not the `state/` that carried the old fstab — is mounted rather than left attached and empty.

### Networking

VM workloads use **passt**, a userspace network backend, and have no bridge at all (see [ADR 006](adr/006-vm-networking-passt-not-managed-bridge.md)). passt terminates the guest's network stack in userspace and re-originates its traffic as ordinary host sockets owned by the workload's own user, so it needs no host privilege — no bridge, no dnsmasq, no host-global `ip_forward`, and no setuid-root `qemu-bridge-helper`. Each VM still gets a stable MAC derived from its workload name.

The consequence worth understanding first: **the guest is assigned the host's own address.** A VM under passt has no LAN identity of its own, so nothing on the network can address it directly. Traffic *from* the guest leaves as though the host sent it.

That is also what makes per-VM policy possible. Because guest traffic arrives on the host as sockets with a known owner, **the workload uid is the VM's network identity** — the guest cannot forge it, it is unique per workload with no allocation step, and nftables can match it as `meta skuid`. Three values derive from the uid with no registry:

| Derived value | Formula | Used for |
|---|---|---|
| Management address | `127.128.0.0 + (uid - UID_MIN)` | inbound SSH for `exec` / `shell` |
| nflog group | `uid - UID_MIN` | per-workload packet capture |
| Policy key | the uid itself | `meta skuid` in nftables |

`workloadctl diagnose <name>` prints the derived values, since they are not inferable from the TOML.

> **VM egress is not filtered yet.** The uid-keyed nftables policy the design above exists to enable has not been built; VMs today reach whatever the host can reach. `[vm.network].egress` and `[vm.network].allow` are therefore **rejected by `validate`** rather than accepted and ignored — a config that claimed a confinement which is not in force would be worse than no key at all.

#### What the guest can reach on the host

- **Host loopback: unreachable.** passt is run with `--map-host-loopback none`; its default would otherwise map the host's loopback onto the gateway address, exposing exactly the services that skip authentication *because* they are not reachable off-box.
- **The host's default-route address: unreachable, structurally** — the guest is assigned that same address, so traffic to it never leaves the guest's own stack.
- **Any other host address** — a secondary IP, a second interface — is an ordinary routable destination and *is* reachable.

This is why there is no longer a firewalld zone: on the two addresses that matter, passt's default posture is stricter than the zone was.

#### DNS

passt intercepts the guest's DNS and forwards it to the host's resolver, so the guest is never told a real resolver address. The advertised address and the resolver behind it are derived from the host at unit start by `workload-vm-netdev` — the generator runs before the network is up, so it cannot compute them.

Two things follow. On a host running a stub resolver, the query is made *by the host*, which means guest DNS is invisible to uid-keyed egress policy; log at the host resolver rather than expecting to filter it. And `[vm.network].resolver = "none"` gives the guest no resolver at all — the only setting that closes DNS tunnelling, at the cost of breaking anything not proxy-aware, including cloud-init and package installs.

#### Published ports

VMs can publish ports onto the host, following the same convention as containers. This is new capability: managed-bridge VMs had no port publishing at all.

```toml
[vm.network]
ports = ["8080:80", "5353:53/udp", "127.0.0.1:9090:9090"]
```

`workloadctl exec` / `shell` do not need this — they reach the guest on its management address at a fixed port, which is never routable and never configurable.

#### Pinning egress to an interface

`[vm.network].outbound_if` binds passt's host-side sockets to one interface, so a VM can be made structurally unable to originate on a management VLAN — per-VM egress scoping with no firewall rules involved.

#### Egress filtering

Because passt re-originates guest traffic as host sockets owned by `_wl-<name>`, the workload uid is a complete and unforgeable selector for that VM's outbound traffic. Policy is one nftables table, `inet workload_filter`, applied from a skeleton at every VM start; units add and remove *set elements*, never rules.

```toml
[vm.network]
egress = "filtered"
allow  = ["192.168.0.10:22", "[2001:db8::1]:443"]
```

Two things about this are easy to get wrong:

- **`allow` takes addresses and ports, never hostnames.** The entries become elements of a set keyed on `ip daddr` / `ip6 daddr`, which has no representation for a name. Accepting one would mean resolving it once at unit start and pinning that answer for the life of the VM — silently wrong the moment the record moves, and wrong permissively if the address is later reassigned. Hostname policy is the proxy's job; `allow` is for the non-HTTP exceptions a proxy cannot carry.
- **`egress` currently has to be stated.** It defaults to `"filtered"`, and the design pairs that default with an automatic allow to the workload's own proxy — which is not built yet. Until it is, `"filtered"` with an empty `allow` is a validation error rather than a VM that boots and can reach nothing. Say `egress = "open"` for a VM that should not be filtered; the shipped bundles do, with their reasons inline.

`workloadctl diagnose <name>` reports whether the policy is actually in force. The case it exists for is a config that says `filtered` while the uid is absent from the set: that VM is wide open, and every other signal — unit active, guest online, `status` green — looks correct. It also prints the drop counter, which is **shared across every filtered VM** rather than per-workload; there is one drop rule, so the number is a host total.

If the filter itself is the problem, `nft delete table inet workload_filter` removes it wholesale; the next VM start rebuilds it. An abandoned table is inert — the chain's policy is `accept` and the drop rule matches only uids present in the set.

#### Custom bridge — the unfiltered escape hatch

A VM that needs a **real LAN identity** (its own address, reachable by other hosts — e.g. one serving TLS on its own name) attaches directly to a host bridge instead. passt cannot provide this, because the guest takes the host's address.

```toml
[vm.network]
bridge = "br0"
```

This is a **supported configuration, not a lapse** — but such a VM is **unfiltered**: its traffic never becomes a host socket, so no host egress policy can reach it. `diagnose` reports this as an informational line. You provision the bridge yourself (NetworkManager or `systemd-networkd`) and add it to `/etc/qemu/bridge.conf`; workloadctl does neither. The bridge name must be a valid Linux interface name (≤15 chars, letters/digits/`_`/`-`). No shipped bundle sets one, because a bridge name is site-specific and need not exist on the target host.

### Memory Balloon

By default the VM includes a `virtio-balloon-pci` device so the host can reclaim idle guest memory at runtime. The guest kernel handles this automatically (`virtio_balloon` module, included in Fedora Cloud).

To disable it (e.g., for latency-sensitive workloads):

```toml
[vm]
balloon = false
```

### Accessing a VM

**Serial console** (works at any boot stage, no network required):
```bash
sudo workloadctl shell fedora-vm
# Press Ctrl+] to detach
```

**SSH** (requires guest to be running and network up):
```bash
workloadctl exec fedora-vm -- bash
workloadctl exec fedora-vm -- dnf upgrade -y
```

The SSH key is injected via cloud-init on first boot, and `exec`/`shell` resolve the guest's address automatically — see [Address resolution](#address-resolution) for the sources and their order.

#### Address resolution

Every VM is wired with a `qemu-guest-agent` channel (a virtio-serial port named `org.qemu.guest_agent.0`), and that agent is the **first** source consulted for the guest's address. It is the only one that asks the guest itself, so it is equally correct on the managed bridge and on a custom LAN bridge, and it cannot go stale. Install and enable `qemu-guest-agent` in the guest to benefit — the shipped `virtual-forgejo` bundle's cloud-init does.

Only the interface bearing the VM's derived MAC is trusted from the agent's reply. A guest reports every interface it has — podman/docker bridges, VPN tunnels, a nested VM's bridge — and none of those is reachable from the host; handing one back would be worse than returning nothing, since a non-empty answer stops the fallback chain. A guest that re-homes its NIC's address behind a MAC of its own (a bond, a macvlan) therefore falls through to the sources below, which key off the same MAC and would not have found it either.

When the agent doesn't answer (not installed, not started, guest still booting) the lookup falls back to, in order: the **DHCP lease file** — managed bridge only, since a VM on a custom bridge leases from that network's own DHCP server; the **host neighbour table**, matched on the VM's derived MAC; and **mDNS** (`<name>.local`).

The neighbour-table source is passive: it can only report a guest the host has spoken to recently, so a healthy but long-idle VM on a custom bridge falls out of it. That is precisely the gap the guest agent closes — without it, `exec` on such a VM can fail to find an address while the VM is up and serving traffic. The serial console works regardless.

### virtiofs Volumes

Share host directories into the VM:

```toml
[vm]
vcpus = 2
memory = "4096M"
image = "quay.io/myorg/myapp:latest"

[[vm.volumes]]
host_path = "/data/myapp"
guest_path = "/mnt/data"
tag = "mydata"
```

virtiofs requires shared memory (`memory-backend-memfd`). The generator adds this automatically when volumes are configured. The host path is served by a `virtiofsd` sidecar service (`workload-<name>-virtiofs-<tag>.service`) started before the VM.

**A volume outside the workload's own tree needs an SELinux label.** The
workload's directory is labelled `svirt_image_t` at enable, and the sidecar is
confined (see below), so a share under `/var/lib/workloads/<name>/` works with
no extra steps. A `host_path` elsewhere carries whatever label that path already
has — `/srv` is `var_t`, for instance — and the sidecar will be denied it. Give
the path a label the sidecar is allowed:

```bash
sudo semanage fcontext -a -t svirt_image_t '/data/myapp(/.*)?'
sudo restorecon -RF /data/myapp
```

`workloadctl diagnose <name>` reports the resulting denial rather than leaving
you with a share that mounts empty.

### SELinux Confinement

VM workloads run QEMU as `svirt_t`, the domain the distro policy already
maintains for a hypervisor process hosting an untrusted guest. This is
unconditional — there is no flag to set — and applies to every VM workload.
`[security].selinux_policy` is a separate, opt-in mechanism for shipping a
*delta* on top of it (see [Security](#security)).

Three things follow that are worth knowing:

- **passt and swtpm are confined for free.** The shipped policy transitions them
  out of `svirt_t` automatically, so guest networking and vTPM need no
  configuration.
- **On a host with SELinux disabled, VMs run unconfined** rather than failing to
  start. `workloadctl diagnose` says which of the two you have.
- **virtiofsd gets its own domain**, shipped as
  `/usr/share/workloadctl/workload-vm.cil` and loaded by the RPM. Without it a
  confined QEMU cannot connect to the sidecar and volumes do not mount.

That last one has a delivery caveat on bootc hosts: the SELinux policy store
lives in `/etc`, which ostree 3-way-merges, so a `bootc upgrade` does not
deliver a changed module to a machine whose store carries local modules — which
is any host that has ever enabled a workload with `[security].selinux_policy`.
`diagnose` reports whether the module is loaded; to load it by hand:

```bash
sudo semodule -i /usr/share/workloadctl/workload-vm.cil
sudo restorecon /usr/libexec/virtiofsd
```

The same caveat applies to the proxy's domain, which ships alongside it:

```bash
sudo semodule -i /usr/share/workloadctl/workload-proxy.cil
sudo restorecon /usr/bin/tinyproxy
```

### Hostname Egress Policy

Kernel rules match addresses; policy is usually written about names.
`[vm.network].hosts` closes that gap by giving the workload its own HTTP forward
proxy, which reads `CONNECT host:443` in plaintext before any TLS handshake — so
it allowlists the *name*, with no interception and no CA:

```toml
[vm.network]
egress = "filtered"
hosts  = ["example.com", "*.fedoraproject.org"]
allow  = ["192.168.0.10:22"]      # non-HTTP exceptions only
```

Resolving names into addresses at rule-install time is the alternative, and it
is worse in three ways: it races DNS, it breaks on CDN churn, and it opens
everything sharing an address.

How it fits together:

- One **tinyproxy instance per workload**, running as `_wl-<name>`, listening on
  the workload's own management address — which no guest can reach.
- Every guest is told the same proxy address, **`192.0.2.1:3128`** on a
  dedicated `workload-proxy` dummy link, and an nftables redirect keyed on the
  workload uid decides which instance it lands on. Cross-workload proxy access
  is therefore structurally unavailable rather than denied by rule.
- The endpoint is an **IP literal**, so the proxy path has no DNS dependency —
  which matters, because DNS is what a compromised guest would attack to escape
  hostname policy.
- CONNECT is permitted to **443 only**. Anything else belongs in `allow`.

**The proxy is advisory on its own; the default-deny chain is what binds it.** A
guest process free to ignore `HTTPS_PROXY` does — and is then dropped by the
kernel, because `egress = "filtered"` permits nothing the allowlists do not name.
Verified: a guest that bypasses the proxy entirely cannot reach an allowlisted
host.

Which is why **`hosts` requires `egress = "filtered"`**, and `validate` rejects
the pair otherwise. Under `"open"` there is no drop, so the allowlist would bind
only the guests that choose to be bound — while still standing up a daemon that
parses guest-controlled HTTP, with its own SELinux domain and an egress
exemption the guest's uid does not get. That is attack surface bought for a
control that does not hold, so the combination is refused rather than built. It
joins `hosts` with `bridge` (no uid in that guest's path) and `hosts = ["*"]`
(`egress = "open"` spelled so nobody notices in review).

**Only the built-in cloud-config sets the guest's proxy environment.** A
workload supplying its own `[vm.cloud_init].user_data_file` owns its guest
configuration; set `http_proxy`/`https_proxy` to `http://192.0.2.1:3128`
yourself, or the guest will simply be dropped by the filter.

Patterns match the hostname only, so a scheme, a path or a port in a `hosts`
entry is a validation error rather than a pattern that silently matches nothing.

`workloadctl diagnose <name>` reports whether the redirect is actually armed —
the proxy can be listening while the guest has no path to it, and every other
signal looks correct when that happens.

### Packet Capture

`workloadctl pcap` captures a workload's traffic. The surface is tcpdump's, and
the one new idea is that **a vantage is an interface** — which tcpdump users
already accept from `any`, `lo` and `nflog:3`:

```bash
workloadctl pcap -D fedora-vm                       # what this workload offers
workloadctl pcap fedora-vm                          # decode to the terminal
workloadctl pcap -w /var/tmp/cap.pcap fedora-vm port 443
workloadctl pcap -i host -i guest --detach -w /var/tmp/cap fedora-vm
workloadctl pcap --list                             # running captures
workloadctl pcap --stop fedora-vm
```

**Two vantages, because under passt they genuinely differ.**

| | sees | mechanism |
|---|---|---|
| `host` (default) | the real host socket, after passt/pasta re-originated the traffic | an nftables `log` rule + `tcpdump -i nflog:<group>` |
| `guest` | the workload's own framing, before translation | a QEMU `filter-dump` object (VM) or tcpdump in the netns (container) |

The guest side is what shows you DHCP, ARP/NDP and the DNS passt or pasta
answers itself — traffic that never becomes a host socket and so cannot appear
host-side at any snaplen. The host side is the only mechanism that can produce
a per-workload capture at all: by the time a packet is on the wire the owning
socket is not part of it, so only netfilter sees `meta skuid`.

`-D` reports which vantages a workload has and why any are missing — a bridged
VM has no host vantage, a `mode = "host"` container has no guest vantage.

**A VM's guest side is a dumb backend.** `filter-dump` accepts only a file and
a length, so it takes no BPF filter, cannot honor `-Q`, and does not rotate.
`-D` says so before you hit it, and a filter that cannot be applied to *every*
selected vantage is rejected rather than applied to one — two captures narrowed
differently cannot be compared, and comparing them is the only reason to select
two.

**Nothing is written without `-w`**, exactly as tcpdump behaves. Captures are
bounded at 5 minutes or 100 MB by default, whichever trips first, and both
vantages stop together so the files cover the same window.

**The snaplen default is 1500, not "everything".** passt hands the guest a
65520-byte MTU and segments are captured whole — measured at 10.9 KB per packet,
so an untruncated capture reaches a 100 MB bound in seconds. 1500 keeps the
first segment of each connection, where the TLS SNI and the HTTP request line
live. Truncation loses payload only: packet counts and true lengths stay exact.

**`--dry-run` is an audit step, not a preview.** `pcap` is the one
read-flavoured command that writes into the security-critical
`inet workload_filter` table, so it prints the exact rule before installing it —
letting you confirm it is a non-terminating `log` rule that cannot change
accept/drop semantics. `diagnose` also reports a live capture, so an operator
who finds that rule is told what put it there.

**Teardown belongs to systemd.** The capture runs in a transient
`workload-pcap-<name>.service` whose `ExecStopPost` removes the nftables rule
and the QEMU object, so a dropped session, a `kill -9` or a reboot cannot leave
either behind. `--list` and `--stop` read systemd rather than a registry of our
own, which is why a reboot ending every capture is self-correcting.

> **Guest-side timestamps are corrected on finalize.** QEMU stamps
> `filter-dump` packets with a clock that counts from VM start, then adds the
> guest's UTC RTC reinterpreted as host local time — so raw timestamps are off
> by the VM's uptime *plus* this host's standard-time UTC offset (measured at
> −29,407 s: 28,800 + ~607 s of uptime). `pcap` measures the offset with a probe
> packet and shifts every record by it, which needs nothing from the guest and
> no extra tools. Relative deltas inside a file are correct either way; the
> correction is what makes two vantages comparable.

### Update and Rollback

**Update** rebuilds `system.qcow2` from the configured image source:

```bash
sudo workloadctl update fedora-vm
# Building system disk for VM workload: fedora-vm
#   Cached image found: Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2
#   Checksum verified (sha256:28680fe5...)
#   Rotating system.qcow2 → system.qcow2.gen-1
#   Copying qcow2 to system disk (reflink if supported)...
#   ✓ fedora-vm: rebuilt and restarted
```

The old disk is rotated to `system.qcow2.gen-N` before the new disk is written. `vm.rollback_keep` (default 2) counts the *older* generations kept in addition to the one just rotated, so the total number of retained `system.qcow2.gen-*` files is `rollback_keep + 1` (default 3).

For `cloud_image_url`, the download is cached at `.image-cache/<filename>` and the cache is keyed by `cloud_image_checksum`. `update` re-downloads only when the cached file fails the configured checksum (or is missing) — bumping the upstream image means changing both `cloud_image_url` and `cloud_image_checksum` in the TOML first. For `local_image`, `update` re-copies the file every run.

> **No auto-rollback.** Container `update` watches health checks and auto-rolls back on failure. VM `update` does **not** verify the guest after restart: if the new disk fails to boot, you must run `sudo workloadctl rollback <name>` manually. Use the serial console (`workloadctl shell <name>`) to diagnose before deciding.

If the rebuild itself fails (download error, checksum mismatch, bootc-image-builder failure) the just-rotated `system.qcow2.gen-N` is renamed back to `system.qcow2` so the service still has a usable disk.

**Rollback** restores the most recent generation and restarts:

```bash
sudo workloadctl rollback fedora-vm
# Rolling back VM 'fedora-vm':
#   system.qcow2.gen-1 → system.qcow2
# ✓ Rolled back fedora-vm to generation 1
```

### Boot Flow

```
workload-fedora-vm-build.service   (oneshot, builds system.qcow2 on first enable)
  └─ workload-fedora-vm-virtiofs-*.service  (virtiofsd sidecars, one per volume)
  └─ workload-fedora-vm.service    (Type=notify; workload-vm-notify starts QEMU,
                                    polls QMP, sends READY=1 when guest is running)
```

### Bootstrapping a VM with cloud-init

By default workloadctl generates a small built-in `#cloud-config` seed for each VM — enough to inject the workload's SSH key, mount any virtiofs shares, and format the data disk. That's all `workloadctl exec` needs.

For anything more (clone a repo, install packages, register a daemon, drop config files into the guest), set `[vm.cloud_init].user_data_file` and ship your own `#cloud-config`. The file *is* the entire user-data; workloadctl does plain text substitution only, so the structure is fully yours and no YAML library is involved.

```toml
[vm.cloud_init]
user_data_file = "./cloud-init/user-data"     # relative to the TOML's dir

[vm.cloud_init.template_vars]
REPO_URL = "https://forgejo.local/me/myproject.git"
VERSION  = "1.4.2"
```

Inside the user-data file, three substitution forms are recognised:

| Placeholder | Source |
| --- | --- |
| `${VAR}` | `[vm.cloud_init.template_vars]` first, then the environment. Unresolved → build fails loudly. |
| `${SECRET:name}` | `systemd-creds decrypt /etc/credstore.encrypted/<name>` (falls back to `/etc/credstore/<name>`). Missing → build fails. |
| `${SECRET?name}` | Same as `${SECRET:name}` but missing credential substitutes to `""` instead of erroring. Useful for runtime opt-ins gated by a shell check on the rendered value. |
| `$$` | Collapses to a literal `$` — use `$${shellvar}` to keep `${shellvar}` literal in the rendered file. |

These magic variables are always injected:

- `${WORKLOADCTL_SSH_KEY}` — the workload's generated SSH pubkey. Drop into `users[].ssh_authorized_keys` to keep `workloadctl exec` working.
- `${WORKLOADCTL_WORKLOAD_NAME}` — the workload name (useful for `hostname:`).
- `${WORKLOADCTL_VM_HOST_KEY_B64}` — the workload's SSH **host** private key, base64-encoded (single line). `${WORKLOADCTL_VM_HOST_PUBKEY}` is the matching public key.

**Host-key pinning (required for custom seeds).** The CLI verifies the guest with `StrictHostKeyChecking=yes` against a pinned host key, so a custom `user_data_file` **must install that host key or provisioning fails** (no trust-on-first-use). Drop this into the seed — base64 keeps the multi-line PEM on one line, which a YAML `write_files` block scalar can't otherwise carry:

```yaml
# Required alongside write_files — see below.
ssh_deletekeys: false

write_files:
  - path: /etc/ssh/ssh_host_ed25519_key
    permissions: '0600'
    owner: root:root
    encoding: b64
    content: ${WORKLOADCTL_VM_HOST_KEY_B64}
  - path: /etc/ssh/ssh_host_ed25519_key.pub
    permissions: '0644'
    owner: root:root
    content: ${WORKLOADCTL_VM_HOST_PUBKEY}
```

`ssh_deletekeys: false` is not optional here. cloud-init's `ssh` module runs
*after* `write_files` and defaults to deleting `/etc/ssh/ssh_host_*` and
generating fresh keys — which discards the key you just wrote, leaving a guest
that fails the pin with `REMOTE HOST IDENTIFICATION HAS CHANGED`. Seed rendering
rejects a `write_files` injection that omits it.

The default seed (no `user_data_file`) installs and pins the host key automatically.

**Encrypting a runtime secret** for `${SECRET:name}`:

```sh
sudo systemd-creds encrypt --name=runner-token \
  - /etc/credstore.encrypted/runner-token <<< 'PASTE-TOKEN-HERE'
sudo chmod 0600 /etc/credstore.encrypted/runner-token
```

The decrypted value is baked into the seed ISO at build time. The ISO lives in the workload's home dir (root-only path, mode 0640), so the secret is at rest on disk for the lifetime of the VM — rotate by re-encrypting and re-running `workloadctl enable` (the seed rebuilds when the user-data file's mtime changes).

A complete worked example lives at [`workloads/virtual-forgejo/`](../workloads/virtual-forgejo/README.md) (workload TOML at [`workloads/virtual-forgejo/workload.toml`](../workloads/virtual-forgejo/workload.toml)): a Fedora 44 VM that boots, installs workloadctl from source, runs Forgejo + Caddy + Avahi as containerized sidecars, and registers a native `forgejo-runner` against the in-VM Forgejo. Everything for the bundle is co-located under `workloads/virtual-forgejo/` — the workload TOML alongside its cloud-init bootstrap content.

---

## Managing Workloads

### Using workloadctl (Recommended)

The `workloadctl` command provides a convenient interface for managing workloads.

#### Create a New Workload

```bash
sudo workloadctl create NAME --image IMAGE [OPTIONS]
```

Creates a new workload configuration file in `/etc/workloads.d/`. This is the easiest way to get started on regular Fedora systems.

**Required arguments:**
- `NAME` - Workload name (lowercase letters, numbers, hyphens only)
- `--image IMAGE` - Container image to use

**Common optional arguments:**
- `--groups GROUP...` - Additional system groups (e.g., `video render input dialout audio kvm`)
- `--ports PORT...` - Port mappings (e.g., `8080:80 8443:443`)
- `--network MODE` - Network mode: `pasta` (default), `host`, `none`, or custom network name
- `--volumes VOL...` - Volume mounts (e.g., `/host/path:/container/path:ro`)
- `--device DEVICE...` - Generic device passthrough (e.g., `/dev/ttyUSB0 /dev/video0`)
- `--gpu TYPE` - GPU convenience flag: `amd`, `nvidia`, or `none`
- `--input` - Input device convenience flag
- `--audio` - Audio convenience flag
- `--virtualization` - KVM convenience flag
- `--enable` - Enable and start the workload immediately

**Examples:**

```bash
# Minimal workload (auto-assigns ID)
sudo workloadctl create jellyfin --image=jellyfin/jellyfin:latest

# With common options
sudo workloadctl create sunshine \
  --image=ghcr.io/lizardbyte/sunshine:latest \
  --gpu=nvidia \
  --groups video input \
  --ports 47984:47984 47989:47989 \
  --network=host \
  --enable

# With volumes
sudo workloadctl create minecraft \
  --image=itzg/minecraft-server:latest \
  --volumes /mnt/games/minecraft:/data \
  --ports 25565:25565 \
  --enable

# Home Assistant with Zigbee USB device
sudo workloadctl create homeassistant \
  --image=ghcr.io/home-assistant/home-assistant:stable \
  --device /dev/ttyACM0 \
  --groups dialout \
  --network=host \
  --enable
```

**Note for bootc users:** On bootc images, it's recommended to create TOML configs manually and bake them into your image for immutability. The `create` command is most useful on regular (mutable) Fedora systems.

#### Other Common Operations

**List all workloads:**
```bash
workloadctl list
```

**Enable/disable workload:**
```bash
sudo workloadctl enable NAME
sudo workloadctl disable NAME
sudo workloadctl disable --purge NAME  # Also removes user, home dir, and subuid/subgid
```

**Clean up orphaned users and directories:**
```bash
# Preview what would be removed (safe, no changes)
workloadctl cleanup

# Actually remove orphaned users and directories
sudo workloadctl cleanup --apply
```

Finds and removes workload users that no longer have a corresponding *enabled* config, and any directories under `/var/lib/workloads/` with no corresponding user. Useful after disabling workloads, renaming them, or upgrading from an older version. The dry run (default) shows exactly what would be removed including whether each user has a home directory and subuid/subgid entries.

On a bootc host it also declines to sweep state belonging to *another deployment*. `/etc` is per-deployment and `/var` is shared, so a `bootc rollback` removes a workload's config and user while leaving its data behind — which looks exactly like an orphan. Each workload root carries a `provenance.json` recording the deployment that last provisioned it; state whose deployment still exists but isn't the one you booted is reported under "State from another deployment — not swept" and left alone. To remove it, boot that deployment and run `disable --purge` there. See [`cli.md`](cli.md#cleanup).

#### What `enable` does automatically vs. what you must provide

When you run `workloadctl enable`, it performs pre-flight checks and setup before starting the workload:

**Auto-created by `enable`:**
- Any volume directories declared in `[storage].volumes` whose host path is relative (starts with `./`), i.e. lives inside the workload's home directory (`/var/lib/workloads/{name}/`). These are created owned by root and immediately chowned to the workload user after the workload user account is created.

**Must exist before `enable` can complete:**
- Files declared in `[setup].required_files` — `enable` prints instructions (with hints) and exits if any are missing. These files require user-supplied content (config files, keys, etc.) so they cannot be created automatically.
- Volume paths declared with absolute host paths (outside the workload home) — `enable` aborts if these don't exist. These are system paths (e.g. `/run/systemd/journal/socket`) that must already be present.
- Volume paths whose host path has a file extension — treated as files, not directories; `enable` aborts if missing.

**Workflow for workloads with required config files:**

Run `enable` once to create the directory structure, then copy the required files and run it again:

```bash
sudo workloadctl enable smb-server
# → fails, but creates /var/lib/workloads/smb-server/ and all subdirectories

sudo cp /usr/share/workloadctl/workloads/smb-server/smb.conf /var/lib/workloads/smb-server/smb.conf
# → edit as needed

sudo workloadctl enable smb-server
# → succeeds
```

**Example:** for `smb-server`, the volumes `./exports`, `./samba-state`, `./samba-run`, and `./samba-logs` are auto-created on the first enable attempt; `./smb.conf` is listed in `required_files` so you must provide it before the second enable call completes.

**Recreate workload (destroys overlay):**
```bash
sudo workloadctl recreate NAME
```

**Check status:**
```bash
workloadctl status NAME
```

**View logs:**
```bash
workloadctl logs NAME
workloadctl logs -f NAME              # Follow logs in real-time
workloadctl logs -n 50 NAME           # Last 50 lines
workloadctl logs --since "10 minutes ago" NAME
```

**Shell and command execution:**
```bash
workloadctl shell NAME                # Open interactive shell
workloadctl exec NAME COMMAND         # Execute command
workloadctl exec NAME ls -la /data
```

**Update workload image:**
```bash
sudo workloadctl update NAME          # Pull latest image, restart if changed
sudo workloadctl update NAME --force  # Pull and restart even if image unchanged
sudo workloadctl update --all         # Update all enabled workloads (skips pull=never)
```

**Show detailed information:**
```bash
workloadctl info NAME                 # Comprehensive workload info (ports, subids, …)
workloadctl stats NAME                # Resource usage
workloadctl stats -f                  # All workloads, live updating
```

**Configuration management:**
```bash
workloadctl validate NAME             # Check config for errors
workloadctl validate --all            # Validate all configs
sudo workloadctl edit NAME            # Edit with validation and auto-restart
```

**Health checking:**
```bash
workloadctl health NAME               # Comprehensive health check
```

**File operations:**
```bash
workloadctl cp NAME:/path/in/container ./local/path
workloadctl cp ./local/path NAME:/path/in/container
```

**Image management:**
```bash
workloadctl images list               # Show images used by workloads
workloadctl images prune              # Remove unused images
```

### Manual Enable/Disable (Without workloadctl)

If you prefer to manage workloads manually:

Enabled-ness is a marker file, `/etc/workloads.d/<name>/.enabled` — `workloadctl enable`/`disable` just create and remove it. To do the same by hand:

**Enable a workload:**
```bash
# 1. Create the enable marker (the generator only emits units when it's present)
sudo touch /etc/workloads.d/example-webserver/.enabled

# 2. Reload systemd and start
sudo systemctl daemon-reload
sudo systemctl start workload-webserver.service
```

**Disable a workload:**
```bash
# 1. Stop the service
sudo systemctl stop workload-webserver.service

# 2. Remove the enable marker
sudo rm -f /etc/workloads.d/example-webserver/.enabled

# 3. Reload systemd
sudo systemctl daemon-reload
```

**Disable and purge manually:**
```bash
# 1. Stop and disable
sudo systemctl stop workload-webserver.service
sudo rm -f /etc/workloads.d/example-webserver/.enabled
sudo systemctl daemon-reload

# 2. Get user info and remove
id _wl-webserver
sudo loginctl terminate-user 10001  # Use actual UID
sudo loginctl disable-linger 10001
sudo sed -i '/^_wl-webserver:/d' /etc/subuid /etc/subgid
sudo userdel -r _wl-webserver
```

### Image Updates

For **container workloads**, pull the latest image and restart if it changed. For **VM workloads**, rebuild the system disk from its image source (see [VM Workloads — Update and Rollback](#update-and-rollback)).

```bash
sudo workloadctl update pihole
# Updating pihole (docker.io/pihole/pihole:latest)...
#   ✓ Updated a1b2c3d4e5f6 → f6e5d4c3b2a1
#   Waiting 90s for health check... healthy
```

If the image hasn't changed, the workload is not restarted:

```bash
sudo workloadctl update pihole
# Updating pihole (docker.io/pihole/pihole:latest)...
#   ✓ Already up to date (a1b2c3d4e5f6)
```

Update all enabled workloads at once:

```bash
sudo workloadctl update --all
# Updating pihole (docker.io/pihole/pihole:latest)...
#   ✓ Updated a1b2c3d4e5f6 → f6e5d4c3b2a1
#
# Updating grafana (docker.io/grafana/grafana:latest)...
#   ✓ Already up to date (1a2b3c4d5e6f)
#
# Done: 1 updated, 4 skipped (pull=never)
```

Workloads with `pull = "never"` (local images) are silently skipped during `--all`, or produce an error when targeted directly:

```bash
sudo workloadctl update wireguard-vpn
# Error: wireguard-vpn uses pull=never (local image). Build it manually.
```

Use `--force` to restart even if the image hasn't changed:

```bash
sudo workloadctl update pihole --force
```

#### Auto-rollback

For workloads with a `[container.health]` section, `update` automatically waits for the health check to pass after restarting. If the health check fails, the previous image is restored:

```bash
sudo workloadctl update pihole
# Updating pihole (docker.io/pihole/pihole:latest)...
#   ✓ Updated a1b2c3d4e5f6 → f6e5d4c3b2a1
#   Waiting 90s for health check... unhealthy
#   ✗ Rolled back to previous image (a1b2c3d4e5f6)
```

The wait time is calculated from the workload's health config: `start_period` + `interval`. If the check is still in "starting" state after that, it waits one more `interval` before giving up.

Workloads without health checks get a 5-second service liveness check instead — this catches hard crashes but can't detect subtle failures.

#### Manual rollback

Each update saves the previous image. If you need to roll back manually (e.g., a problem discovered later):

```bash
sudo workloadctl rollback pihole
# ✓ Rolled back pihole: f6e5d4c3b2a1 → a1b2c3d4e5f6
```

The previous image is tagged as `localhost/workload-rollback/{name}:latest` in the workload user's podman storage. Each update overwrites the rollback tag, so exactly one previous image is kept per workload (same two-slot model as bootc).

For **VM workloads**, rollback restores the latest `system.qcow2.gen-N` (created during `update`) rather than a container image tag. See [VM Workloads — Update and Rollback](#update-and-rollback).

### Backup and Restore

Backup creates a zstd-compressed tar archive containing the workload config, home directory (volume data), and any referenced encrypted credentials.

#### Backup a single workload

```bash
sudo workloadctl backup pihole
```

The service is stopped during backup for a consistent snapshot, then restarted. Archives go to `/var/lib/workloads/backups/` by default.

```bash
# Backup to a specific path
sudo workloadctl backup pihole --output /mnt/backup/

# Live backup (no service stop). For containers this may be inconsistent;
# for VMs the vCPUs are paused via QMP for the copy (crash-consistent).
sudo workloadctl backup pihole --consistency crash

# Backup all workloads
sudo workloadctl backup --all
```

#### Restore a workload

```bash
sudo workloadctl restore /var/lib/workloads/backups/pihole-20260315-120000.tar.zst --enable
```

Restore extracts the config, home directory, and credentials, then optionally enables the workload. It refuses to overwrite an existing workload unless `--force` is given.

```bash
# Restore without starting (manual enable later)
sudo workloadctl restore pihole-20260315-120000.tar.zst

# Overwrite existing workload
sudo workloadctl restore pihole-20260315-120000.tar.zst --force --enable
```

#### Cross-machine restore

Encrypted credentials are TPM-bound to the original machine. When restoring on a different machine, re-encrypt each credential:

```bash
sudo workloadctl secret rotate api-key
sudo workloadctl secret rotate db-password
```

The restore command prints which credentials need re-encryption.

Alternatively, use `secret export/import` to transfer credentials portably with a passphrase — see [Portable Credential Transfer](#portable-credential-transfer) below.

#### What's in a backup

```
pihole-20260315-120000.tar.zst
├── workload.toml              # /etc/workloads.d/pihole/workload.toml
├── credentials/               # Referenced credentials from /etc/credstore.encrypted/
│   └── pihole-webpassword
└── home/                      # /var/lib/workloads/pihole/
    ├── etc-pihole/
    └── etc-dnsmasq.d/
```

Everything else (system user, subuid/subgid, linger, SELinux labels, podman images) is recreated automatically by `workloadctl enable`.

### Portable Credential Transfer

Credentials created with `workloadctl secret create` are encrypted with `systemd-creds` and bound to the machine's TPM. They can't be decrypted on another machine. `secret export` and `secret import` solve this by converting between TPM-bound and passphrase-based encryption.

#### Export a credential

On the source machine, decrypt the TPM-bound credential and re-encrypt it with a passphrase:

```bash
sudo workloadctl secret export api-key
# Passphrase for export: ****
# Confirm passphrase: ****
# ✓ Exported credential 'api-key' to api-key.secret
```

The output `.secret` file is encrypted with AES-256-CBC using PBKDF2 (600,000 iterations) and carries an HMAC-SHA256 integrity tag, so tampering or truncation is detected on import (format v2; import still accepts legacy v1 blobs — see [ADR 004](adr/004-secret-export-versioned-crypto.md)). It can be safely transferred to another machine via scp, USB drive, etc.

```bash
# Export to a specific path
sudo workloadctl secret export api-key --output /mnt/usb/api-key.secret
```

#### Import a credential

On the target machine, decrypt with the passphrase and re-encrypt with the local TPM:

```bash
sudo workloadctl secret import api-key api-key.secret
# Passphrase: ****
# ✓ Imported credential 'api-key' → /etc/credstore.encrypted/api-key
#   Encryption: tpm2
#
#   Restart affected workloads:
#     sudo workloadctl recreate myapp
```

Import automatically scans workload configs to find which workloads reference the credential and suggests restart commands.

```bash
# Overwrite an existing credential
sudo workloadctl secret import api-key api-key.secret --force

# Use host-only encryption (no TPM required)
sudo workloadctl secret import api-key api-key.secret --key-type host
```

#### How it works

```
Source machine                          Target machine
┌─────────────────────┐                 ┌─────────────────────┐
│ /etc/credstore.encrypted/api-key      │                     │
│ (TPM-bound)         │                 │                     │
│         │           │                 │                     │
│  systemd-creds decrypt                │                     │
│         │           │                 │                     │
│    [plaintext]      │                 │                     │
│         │           │                 │                     │
│  openssl enc -aes-256-cbc             │                     │
│  (passphrase)       │                 │                     │
│         │           │                 │                     │
│  api-key.secret ────┼── transfer ──── │→ api-key.secret     │
│                     │                 │         │           │
│                     │                 │  openssl enc -d     │
│                     │                 │  (passphrase)       │
│                     │                 │         │           │
│                     │                 │    [plaintext]      │
│                     │                 │         │           │
│                     │                 │  systemd-creds encrypt
│                     │                 │  (local TPM)        │
│                     │                 │         │           │
│                     │                 │  /etc/credstore.encrypted/api-key
│                     │                 │  (TPM-bound)        │
└─────────────────────┘                 └─────────────────────┘
```

The passphrase never appears in process arguments (`/proc/*/cmdline`) — it's written to a temporary file and passed to openssl via `-pass file:...`. The plaintext exists only in memory during the operation.

#### Cross-machine workflow

Putting it together — moving a workload with credentials to a new machine:

```bash
# Source machine: backup workload + export credentials
sudo workloadctl backup pihole
sudo workloadctl secret export pihole-webpassword -o /mnt/usb/pihole-webpassword.secret

# Target machine: restore workload + import credentials
sudo workloadctl restore /mnt/usb/pihole-20260315-120000.tar.zst --enable
sudo workloadctl secret import pihole-webpassword /mnt/usb/pihole-webpassword.secret --force
sudo workloadctl recreate pihole
```

---

## Device Access

The workload system supports passing host devices to containers for GPU access, USB devices, audio, input devices, and more. Use generic `--device` for maximum flexibility, or convenience flags for complex multi-device scenarios.

### Generic Device Passthrough

Use `--device` for any device path. This is the most flexible approach and works with any device.

**Using workloadctl create:**
```bash
# USB serial device (Zigbee/Z-Wave stick)
sudo workloadctl create homeassistant \
  --image ghcr.io/home-assistant/home-assistant:stable \
  --device /dev/ttyACM0 \
  --groups dialout \
  --network host \
  --enable

# Webcam for video surveillance
sudo workloadctl create frigate \
  --image ghcr.io/blakeblackshear/frigate:stable \
  --device /dev/video0 \
  --device /dev/video1 \
  --groups video \
  --enable

# Mix multiple devices
sudo workloadctl create myapp \
  --image myapp:latest \
  --device /dev/ttyUSB0 \
  --device /dev/video0 \
  --device /dev/sdb \
  --groups dialout video disk \
  --enable
```

**Manual TOML configuration:**
```toml
[devices]
# Generic device array - works with ANY device
devices = ["/dev/ttyACM0", "/dev/video0", "/dev/tpm0"]

[security]
# Add groups as needed for device access
extra_groups = ["dialout", "video", "input", "audio"]
```

### Convenience Flags

For scenarios requiring multiple devices or special handling, use convenience flags:

| Flag | Expands To | Common Groups | Use Case |
|------|-----------|---------------|----------|
| `--gpu amd` | `/dev/kfd`, `/dev/dri` | `video`, `render` | AMD GPU access |
| `--gpu nvidia` | `nvidia.com/gpu=all`, `/dev/dri` | `video` | NVIDIA GPU access |
| `--input` | `/dev/input`, `/dev/uinput` | `input` | Keyboard/mouse access |
| `--audio` | `/dev/snd` + PulseAudio/PipeWire sockets | `audio` | Audio devices |
| `--virtualization` | `/dev/kvm`, `/dev/vhost-*` | `kvm` | KVM virtualization |

**Examples with convenience flags:**

```bash
# AMD GPU gaming workload
sudo workloadctl create gaming \
  --image myapp:latest \
  --gpu amd \
  --input \
  --audio \
  --groups video render input audio \
  --enable

# NVIDIA streaming server
sudo workloadctl create sunshine \
  --image lizardbyte/sunshine:latest \
  --gpu nvidia \
  --input \
  --groups video input \
  --network host \
  --enable

# KVM virtualization
sudo workloadctl create qemu \
  --image tianon/qemu:latest \
  --virtualization \
  --groups kvm \
  --enable
```

### Common Device Use Cases

**USB Serial Devices (Zigbee, Z-Wave, Serial Adapters):**
```bash
sudo workloadctl create homeassistant \
  --image ghcr.io/home-assistant/home-assistant:stable \
  --device /dev/ttyACM0 \
  --groups dialout \
  --network host \
  --enable
```

**Webcams and Capture Cards:**
```bash
sudo workloadctl create frigate \
  --image ghcr.io/blakeblackshear/frigate:stable \
  --device /dev/video0 \
  --device /dev/video1 \
  --groups video \
  --enable
```

**Block Devices for VMs:**
```bash
# ⚠️ WARNING: Block device access grants low-level disk access!
sudo workloadctl create qemu-vm \
  --image tianon/qemu:latest \
  --device /dev/sdb \
  --virtualization \
  --groups kvm disk \
  --enable
```

**TPM Devices:**
```bash
sudo workloadctl create vault \
  --image vault:latest \
  --device /dev/tpm0 \
  --groups tpm \
  --enable
```

### Stable Device Names with udev

Device paths like `/dev/ttyUSB0` or `/dev/video0` may change when you reboot. Use **udev rules** for stable device names.

**Create `/etc/udev/rules.d/99-usb-devices.rules`:**
```bash
# Zigbee stick (check vendor/product ID with lsusb)
SUBSYSTEM=="tty", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6015", SYMLINK+="zigbee"

# Z-Wave stick
SUBSYSTEM=="tty", ATTRS{idVendor}=="0658", ATTRS{idProduct}=="0200", SYMLINK+="zwave"

# Or use serial number for stability
SUBSYSTEM=="tty", ATTRS{serial}=="ABC123XYZ", SYMLINK+="mydevice"
```

**Apply udev rules:**
```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

**Find device vendor/product ID:**
```bash
lsusb  # Look for your device
udevadm info -a -n /dev/ttyACM0 | grep serial
```

**Use stable symlink in config:**
```toml
[devices]
devices = ["/dev/zigbee", "/dev/zwave"]  # Stable names instead of ttyACM0
```

### Device Access Groups

Adding a user to device access groups grants specific hardware access:
- `video`/`render`: Full GPU access (compute workloads, video memory)
- `input`: Can read keyboard/mouse input and inject events
- `audio`: Access to `/dev/snd` sound devices
- `dialout`: Serial device access (USB serial ports like `/dev/ttyUSB*`, `/dev/ttyACM*`)
- `disk`: Block device access (**DANGEROUS** - full read/write to raw disks!)
- `kvm`: KVM virtualization access
- `tpm`: TPM device access

Only grant these to trusted workloads.

### Group Names Appear as Numbers in Containers

**Expected behavior:** Device access groups use host GIDs explicitly via `--group-add=GID`.

Inside the container, `id` shows group memberships as numbers, not names:
```bash
# Host:
$ id _wl-workload
uid=10001(_wl-workload) gid=10001(_wl-workload) groups=10001,39(video),104(input),105(render)

# Container:
$ podman exec workload-1 id
uid=10001 gid=10001 groups=10001,39,104,105
```

**Why:** The container's `/etc/group` has different GIDs for these groups. We use host GIDs because device files (like `/dev/dri/renderD128`) have host GIDs, and the kernel checks permissions using host GIDs.

**Impact:** This is cosmetic - device access works correctly. Group names just don't appear in containers.

---

## Troubleshooting

### Quick Diagnostic Commands

```bash
# Check workload status and details
workloadctl list
workloadctl status NAME
workloadctl info NAME
workloadctl health NAME              # Comprehensive health check

# View logs
workloadctl logs NAME
workloadctl logs -f NAME             # Follow in real-time

# Validate configuration
workloadctl validate NAME
workloadctl validate --all

# Debug inside container
workloadctl shell NAME
workloadctl exec NAME id
workloadctl exec NAME df -h
workloadctl exec NAME ps aux

# Monitor resources
workloadctl stats NAME
```

### Common Issues and Solutions

#### 1. Workload Name Too Long

**Symptom:** Generator logs error about username length.

```
workload-generate: ERROR processing /etc/workloads.d/my-workload/workload.toml:
Username '_wl-my-very-long-workload-name' is 33 chars (max 32)
```

**Fix:** Shorten the workload name. With the `_wl-` prefix (4 chars), names can be up to **27 characters**:
```toml
[workload]
name = "my-very-long-workload-name"  # Bad (29 chars → 33 total)
name = "long-workload"               # Good (14 chars → 18 total)
```

#### 2. Port Already in Use

**Symptom:** Container fails to start, journal shows "address already in use".

```bash
$ sudo journalctl -u workload-webserver
Error: rootlessport listen tcp 0.0.0.0:8080: bind: address already in use
```

**Causes:**
- Another container or service is using the same port
- Conflicting workloads both using host mode
- Port mapping conflict in pasta mode

**Fix:**
```bash
# Check what's using the port
sudo ss -tlnp | grep :8080

# Check all workload ports
workloadctl list
workloadctl info NAME

# Either change the port in config or stop conflicting service
sudo workloadctl edit NAME  # Change port mapping
```

#### 3. Workload Not Starting (no `.enabled` marker)

**Symptom:** Config file exists but service never starts.

**Cause:** The workload has no enable marker (`/etc/workloads.d/<name>/.enabled`), so the generator skips it.

**Fix:** `sudo workloadctl enable NAME`

Or by hand: `sudo touch /etc/workloads.d/NAME/.enabled && sudo systemctl daemon-reload`

#### 4. SELinux Denying Device Access

**Symptom:** Container can't access GPU/input devices despite correct groups.

**Check:**
```bash
sudo ausearch -m avc -ts recent
```

**Fix:**
- Check home directory has correct context: `ls -Z /var/lib/workloads/`
- Temporarily set permissive mode for testing: `sudo setenforce 0`
- Create a custom policy module for permanent fix

#### 5. Image Pull Failures

**Symptom:** Service fails with "unable to pull image".

**Causes:**
- Registry requires authentication
- Image name typo
- Network issues
- Rate limiting

**Debug:**
```bash
# Test image pull manually
sudo -u _wl-{name} XDG_RUNTIME_DIR=/run/user/{uid} podman pull {image}
```

**Fix:** Set appropriate pull policy:
```toml
[container]
pull = "missing"  # Default - only pull if not cached
# pull = "always"   # Always check for updates (slower)
# pull = "never"    # Fail if image not in cache
```

#### 6. Container Immediately Exits

**Symptom:** Service status shows "activating" briefly, then stops.

**Cause:** Container command exits immediately.

**Fix:** Ensure container command runs in foreground:
```toml
[container]
command = ["sleep", "infinity"]  # For testing
# command = ["nginx", "-g", "daemon off;"]  # Foreground mode
```

**Debug:**
```bash
# Check logs for what happened
sudo journalctl -u workload-{name} -n 50

# Try running manually
sudo -u _wl-{name} XDG_RUNTIME_DIR=/run/user/{uid} podman run --rm {image} {command}
```

#### 7. Subuid/Subgid Not Configured

**Symptom:** Container fails with "newuidmap: write to uid_map failed: Operation not permitted".

**Cause:** User doesn't have subordinate UID/GID ranges.

**Fix:**
```bash
# Check ranges exist
grep _wl-{name} /etc/subuid /etc/subgid

# If missing, re-run user setup
sudo /usr/libexec/workloadctl/workload-ensure-user NAME

# Or re-enable the workload
sudo workloadctl enable NAME
```

#### 8. Volume Mount Permission Denied

**Symptom:** Container can't read/write mounted volumes.

**Causes:**
- Volume path doesn't exist on host
- Incorrect ownership on host path
- SELinux blocking access

**Fix:**
```bash
# Create directory with correct ownership
sudo mkdir -p /path/to/volume
sudo chown 10001:10001 /path/to/volume  # Use workload UID:GID
sudo chmod 0755 /path/to/volume

# Set SELinux context
sudo chcon -t container_file_t /path/to/volume

# Verify inside container
workloadctl exec NAME ls -la /path/in/container
```

### Advanced Debugging

**Generator debugging:**
```bash
# View workload-generate script logs (kmsg, written during early boot)
dmesg | grep workload-generate

# View the oneshot service that runs the script
systemctl status workload-generate.service
journalctl -u workload-generate.service -b

# Manually run the script for testing (writes to a tmp dir instead of
# /run/systemd/system — safe to run on a live system)
sudo /usr/libexec/workloadctl/workload-generate /tmp/test-output

# Check generated configs
systemd-sysusers --cat-config | grep workload
systemctl cat workload-{name}
```

**Check user and permissions:**
```bash
# Check if user exists
getent passwd _wl-{name}

# Check user groups
id _wl-{name}

# Check container is running
sudo -u _wl-{name} XDG_RUNTIME_DIR=/run/user/{uid} podman ps

# Get shell in container (manual method)
sudo -u _wl-{name} XDG_RUNTIME_DIR=/run/user/{uid} \
  podman exec -it workload-{name} /bin/sh
```

**Reset a workload completely:**
```bash
# Stop service
sudo systemctl stop workload-{name}

# Remove user and data
sudo userdel -r _wl-{name}
sudo sed -i "/^_wl-{name}:/d" /etc/subuid /etc/subgid

# Recreate
sudo systemctl daemon-reload
sudo systemctl start workload-{name}
```

---

## Known Limitations

### Current Implementation Status

#### Networking (PARTIALLY COMPLETE)

**Working:**
- `network.mode = "pasta"` - Isolated network with port forwarding (default, Podman 5.3+)
- `network.mode = "host"` - Shares host network namespace
- `network.mode = "none"` - No networking
- `network.mode = "<network-name>"` - Custom user-defined networks
- `network.ports` - Port mappings (pasta and custom networks)

**Not yet implemented:**
- Automatic network creation - users must manually create custom networks with `podman network create`
- Network lifecycle management - networks are not automatically created/deleted with workloads
- DNS configuration - custom DNS servers, search domains
- Network policies - firewall rules, traffic shaping
- Multiple networks per container
- IPv6 support (untested)

**Example - Custom network:**
```bash
# Create the network as the workload user. `incant` supplies the rootless
# invocation (sudo -u _wl-app + XDG_RUNTIME_DIR) for you:
workloadctl incant app -- network create mynetwork

# Configure workloads to use it
[network]
mode = "mynetwork"
ports = ["8080:8080"]
```

#### Storage (INCOMPLETE)

**Working:**
- `storage.volumes` - Array of volume mounts in `host:container:options` format
- Automatic home directory at `/var/lib/workloads/{name}` on the host, `/data` inside the container

**Not yet implemented:**
- Named volumes - Podman volume management
- Shared volumes - volumes shared between multiple workloads
- tmpfs mounts - in-memory filesystem support
- Bind mount options - more granular control
- Storage quotas - limit container storage size
- Automatic cleanup - remove old container images and volumes
- Volume drivers - different storage backends

### Known Tradeoffs

#### 1. Username Length Limit (32 characters)

Linux usernames are limited to 32 characters (LOGIN_NAME_MAX). Workload names are used in usernames as `_wl-{name}`, leaving ~27 characters for the name.

**Fix:** Keep workload names short. The generator rejects configs with names that result in usernames longer than 32 characters.

#### 2. Bootc Immutable Groups

On bootc systems, most groups are defined in `/usr/lib/group` (immutable via nss-altfiles) rather than `/etc/group` (mutable).

**Solution:** The Containerfile copies device access groups (video, render, input) to `/etc/group` at build time:
```dockerfile
RUN grep -E "^(video|render|input):" /usr/lib/group >> /etc/group || true
```

**Impact:** Adding new device groups requires rebuilding the bootc image. You cannot add arbitrary groups at runtime.

#### 3. No Automatic Cleanup of Disabled Workloads

When you disable a workload (`workloadctl disable`, which removes the `.enabled` marker), the generator stops creating the service, but:
- The user account persists
- Home directory remains
- Subuid/subgid entries remain

**Rationale:** Safety - we don't want to accidentally delete user data or UIDs that might be referenced elsewhere.

**Cleanup options:**
- `workloadctl disable --purge NAME` - removes user/home/subuid when disabling
- `sudo workloadctl cleanup --apply` - bulk-removes all orphaned users and directories

#### 4. Subuid/Subgid Range Allocation

Each workload needs a unique subordinate UID/GID range for rootless containers.

**Formula:** `600100000 + (uid_offset * 65536)` with 65536 UIDs/GIDs, where `uid_offset = uid - 10000`
- Workload UID 10000: subuid range 600100000:65536
- Workload UID 10001: subuid range 600165536:65536
- Workload UID 10002: subuid range 600231072:65536

The `600100000` base puts every range above the window Fedora's own `useradd`
allocates from (`SUB_UID_MIN=524288`, `SUB_UID_MAX=600100000` in
`/etc/login.defs`). A lower base overlaps that window at low UIDs, so a workload
and a `useradd`-created user could be handed the same subordinate IDs — which
would let one workload's containers map into another's UID space. The formula is
authoritative in `workload_lib.derived_subid_range()`; nothing else derives it.

**Which side the protection is on.** `useradd` reads `/etc/subuid` and refuses
to allocate over an entry already listed there — measured on Fedora 44: park a
range at 589824 and successive `useradd`s take 524288, then *655360*; leave it
no non-overlapping candidate and it fails with "Can't get unique subordinate UID
range" rather than sharing. `append_subid_entries` extends no such courtesy in
the other direction: it writes the derived range without consulting existing
entries. So the base is what makes collisions impossible, not a runtime check —
a workload provisioned onto a range a human user already holds would simply
take it.

`workload-ensure-user` **grandfathers** an existing entry rather than correcting
it — shifting a UID mapping under a running container corrupts its namespace —
so a range that predates the formula survives every `enable` and every upgrade,
silently. Two `diagnose`/`doctor` checks catch that:

- `subid_derived` — the entry does not equal the derived range. The
  load-bearing one, per the paragraph above: off the formula is off the only
  guarantee.
- `subid_overlap` — the entry starts below `SUB_UID_MAX`, i.e. inside the
  window `useradd` allocates from. Corroboration rather than an alarm, since
  `useradd` skips what it can see. What it covers is ordering: a workload
  provisioned after a colliding range, and the rollback case — `/etc` is
  per-deployment while `/etc/subuid` entries accrue at runtime, so an older
  deployment's file may not list a workload enabled later, and a `useradd`
  there can take its range legitimately. Host-state-dependent, so no test in
  this repo can cover it; omitted (not passed) if `/etc/login.defs` is
  unreadable.

Note that UID 10000's derived range starts exactly at `SUB_UID_MAX`, which
shadow treats as inclusive. Not a gap: `useradd` cannot take that id while the
entry is listed, per the refusal measured above.

Remapping is manual and must be done with the workload **stopped**: rewrite both
files, then `chown` only `state/`. Every file in `data/` is owned by the workload
UID itself rather than out of the subordinate range, so scoping the remap to the
reconstructible graphroot leaves durable data untouched by construction.

**Impact:**
- UIDs are capped at 52948, supporting up to **42,949 workloads** per host. That
  bound is retained from an earlier allocation scheme rather than being a limit of
  this one: the top of the range lands at 3,414,805,663, leaving ~880M of headroom
  below the uint32 ceiling that `/etc/subuid` consumers require. Raising it is a
  deliberate change to `UID_MAX`, not a formula fix.
- Changing a workload's UID requires manual `/etc/subuid` and `/etc/subgid` cleanup

### Areas Needing Improvement

#### 1. Configuration Validation

**Current:** Basic validation in generator (username length, required fields). `workloadctl validate` provides pre-flight checks.

**Missing:**
- Port conflict detection
- Subuid range overlap detection
- Image name validation
- Volume path validation

**Risk:** Some invalid configs cause service failures at startup rather than at `daemon-reload` time. Run `workloadctl validate` before enabling.

#### 2. GPU Support Completeness

**Current:** Basic AMD and NVIDIA GPU support.

**Missing:**
- Intel GPU support (needs testing with `/dev/dri` access)
- Multi-GPU selection (always uses all GPUs)
- GPU memory limits
- Compute vs graphics workload optimization

#### 3. SELinux Policy

**Current:** Uses `restorecon` to set container_file_t on home directories.

**Missing:**
- Custom policy for specific device access patterns
- Better integration with container_t domain transitions
- Audit logs for permission denials

**Impact:** Some hardware access patterns may be denied by SELinux. Check `ausearch -m avc` and create custom policies if needed.

### Future Enhancements

Potential future improvements:
1. **Better networking:** Automatic network creation and lifecycle management
2. **Storage management:** Named volumes, quotas, backup/restore functionality
3. **Health checks:** Automatic restart on container health failures
4. **Multi-container workloads:** Pod support for related containers
5. **Template system:** Pre-configured workload templates
6. **Web UI:** Cockpit integration for workload management
7. **Improved validation:** Runtime port conflict detection, resource validation

---

## Security Considerations

### Rootless Containers

While containers run as unprivileged users, keep in mind:
- Containers share the kernel with the host
- User namespace mapping provides UID/GID isolation
- SELinux provides mandatory access control
- Device access (GPU, input) grants real hardware access to trusted workloads only

### Device Access Implications

Adding a user to device access groups grants specific hardware access:

| Group | Access Granted | Risk Level |
|-------|---------------|------------|
| `video`/`render` | Full GPU access (compute workloads, video memory) | Medium - can run arbitrary GPU code |
| `input` | Read keyboard/mouse input, inject events | High - can capture passwords, inject keystrokes |
| `audio` | Access `/dev/snd` sound devices | Low - audio capture only |
| `dialout` | Serial device access (`/dev/ttyUSB*`, `/dev/ttyACM*`) | Medium - can control serial devices |
| `disk` | Block device access | **CRITICAL** - full read/write to raw disks! |
| `kvm` | KVM virtualization | Medium - can run VMs |
| `tpm` | TPM device access | High - hardware security operations |

**Only grant device access groups to trusted workloads.**

### Network Access

With `network.mode = "host"`:
- Container can bind to any host port
- Container can access all network services
- No isolation from other containers

With `network.mode = "pasta"` (default):
- Container has isolated network namespace
- Only specified ports are forwarded
- Better security for untrusted workloads

Consider firewall rules for untrusted workloads.

### VM SSH host-key verification

`workloadctl exec` / `shell` into a VM verify the guest against a per-workload
`known_hosts` written at provisioning time (`StrictHostKeyChecking=yes`). The pin is
keyed by the stable workload name via `HostKeyAlias`, so address churn never
invalidates it — there is no trust-on-first-use.

The alias matters more under passt than it did on a bridge: every workload's
management address is a loopback address, so without it `ssh` would key its entries
on near-identical `127.128.x.y` hosts.

This closes the man-in-the-middle exposure the earlier `StrictHostKeyChecking=no`
behaviour left open for a VM on a shared LAN bridge, where a spoofed guest on the same
segment could otherwise have been connected to transparently. (Recorded as decision D4
in the 2026-07 code review, which accepted the caveat; S1 subsequently closed it.)

### Block Device Access

**⚠️ WARNING:** Block device access grants low-level disk access and can:
- Corrupt filesystems
- Bypass filesystem permissions
- Read/write any data on the device

**Best practices:**
- Only grant to fully trusted workloads
- Consider read-only mounts: use `ro` option in volumes
- Audit access regularly

```toml
# Safer: read-only block device
[storage]
volumes = ["/dev/sdb:/dev/sdb:ro"]
```

### Seccomp Filtering

All workloads run with a hardened seccomp profile that restricts which kernel syscalls containers can make. This limits the damage a compromised container can do even if it escapes the user namespace.

**What's blocked (beyond the podman default):**

| Syscall | Why |
|---------|-----|
| `ptrace` | Inspect or control other processes; container escape vector |
| `bpf` | Load eBPF programs; can read kernel memory, bypass LSM policies |
| `perf_event_open` | Performance counters; side-channel leakage between containers |
| `process_vm_readv/writev` | Read/write another process's memory directly |
| `keyctl` | Kernel keyring manipulation |

Most service containers (web servers, databases, media servers) never call these syscalls. If your workload does, you'll see `Operation not permitted` errors at startup — see the [troubleshooting guide](../../docs/TROUBLESHOOTING.md) for diagnosis steps.

**Override for workloads that need a blocked syscall:**
```toml
[security]
# Use the less-strict podman default instead:
security_opt = ["seccomp=/usr/share/containers/seccomp.json"]

# Or provide your own profile:
security_opt = ["seccomp=/etc/containers/my-profile.json"]

# Disable entirely (not recommended):
security_opt = ["seccomp=unconfined"]
```

Note: `privileged = true` disables seccomp automatically, as privileged containers bypass all filtering.

Some operations are gated by **both** seccomp and the per-workload SELinux type — e.g. a debugger's `ptrace` must be unblocked here *and* have an `allow` in the SELinux policy. If a syscall is permitted by seccomp but the operation still fails with `EPERM`, see [Tuning the per-workload SELinux policy](#tuning-the-per-workload-selinux-policy).

### Secrets Management

The systemd credentials system provides strong security:
- Encrypted at rest with AES256-GCM
- TPM2-backed encryption (hardware security)
- Decrypted into RAM only (tmpfs)
- Per-workload isolation
- Automatic cleanup

**Best practices:**
- Use TPM2 encryption when available: `--key-type tpm2`
- Rotate secrets regularly: `workloadctl secret rotate NAME`
- Never commit unencrypted secrets to version control
- Use PCR policies to bind decryption to boot state for critical secrets

---

## Additional Resources

- **Configuration schema:** [schema-reference.toml](schema-reference.toml)
- **Example workloads:** `workloads.d/example-*.toml`
- **Secrets management:** `docs/secrets.md`
- **Shell generator source:** `generators/workload-generator` (emits `workload-generate.service`)
- **Python generator script source:** `generators/workload-generate` (runs as the oneshot)
- **User setup script:** `libexec/workload-ensure-user`
- **Management tool:** `bin/workloadctl`

For questions or issues, see the project documentation or file issues in the project repository.
