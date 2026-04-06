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
- [Managing Workloads](#managing-workloads)
- [Device Access](#device-access)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)
- [Security Considerations](#security-considerations)
- [Additional Resources](#additional-resources)
- [CLI Reference](cli.md)

---

## Quick Start

There are three ways to create a workload — all produce the same result (a TOML config in `/etc/workloads.d/`):

| Approach | Best for |
|---|---|
| **`workloadctl create`** (below) | Interactive use on a running system |
| **[Manual TOML](#manual-toml)** | Fine-grained control, scripting, or working from an example |
| **[bootc image](#bootc-approach)** | Baking workloads into an immutable OS image |

See [cli.md](cli.md) for the full command reference.

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
sudo nano /etc/workloads.d/webserver.toml
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

See [workloads.d/schema-reference.toml](../workloads.d/schema-reference.toml) for all available config options.

---

### bootc approach {#bootc-approach}

For immutable OS images, place workload configs directly in the image:

```dockerfile
# In your hypervisor.Containerfile
COPY workloads.d/ /etc/workloads.d/
```

Workloads with `enabled = true` will be provisioned automatically on first boot. The TOML format is identical — only the delivery mechanism differs. See the [Bootc Integration section in secrets.md](secrets.md#bootc-integration) for handling secrets in immutable images.

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
| **Show ports** | `workloadctl ports NAME` |
| **Check health** | `workloadctl health NAME` |
| **Copy files** | `workloadctl cp SRC DEST` |
| **List containers** | `workloadctl ps` |
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
1. systemd-generators → workload-generator creates sysusers configs and service files
2. systemd-sysusers.service → creates workload users with group memberships
3. ExecStartPre=+workload-ensure-user → configures subuid/subgid, home directory, EnvironmentFile, linger
4. workload-{name}.service → individual containers start
```

### Components

- **Generator** (`/usr/lib/systemd/system-generators/workload-generator`): Reads TOML configs from `/etc/workloads.d/` and generates systemd-sysusers configs and systemd services
- **User Setup** (`/usr/libexec/workloadctl/workload-ensure-user`): Runs as `ExecStartPre` in each workload service to configure subordinate UID/GID ranges, create home and volume directories, write the EnvironmentFile, and enable linger
- **Workload Services**: Per-workload systemd services that run `podman run` as dedicated users
- **Management Tool** (`workloadctl`): Docker/kubectl-like CLI for managing workloads

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

---

## Configuration Guide

### Basic Configuration

Workload configurations are TOML files in `/etc/workloads.d/`. See `workloads.d/schema-reference.toml` for full documentation.

**Minimal Example:**

```toml
[workload]
name = "webserver"
enabled = true

[container]
image = "docker.io/nginxinc/nginx-unprivileged:alpine"

[network]
ports = ["8080:8080"]
```

**Applying Changes:**

After modifying configs:
```bash
sudo systemctl daemon-reload  # Regenerates configs
sudo systemctl restart workload-{name}.service
```

Or use `workloadctl`:
```bash
sudo workloadctl edit NAME    # Edit with validation
sudo workloadctl recreate NAME # Apply changes
```

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
setup = "setup.sh"  # relative to /usr/share/workloadctl/containers/{name}/
```

- `workloadctl enable` runs `setup.sh enable`
- `workloadctl disable` runs `setup.sh disable`
- The script runs as root and should be idempotent in both directions
- Absolute paths are supported: `setup = "/home/myuser/my-setup.sh"`

#### Customizing container build scripts and setup scripts

The bundled scripts in `/usr/share/workloadctl/containers/` are read-only on immutable (bootc/ostree) systems. To customize them, copy the entire container directory to a writable location and make your changes there:

```bash
cp -r /usr/share/workloadctl/containers/sunshine-game-streaming ~/sunshine-custom
cd ~/sunshine-custom
# edit Containerfile, setup.sh, etc.
sudo ./build.sh
```

All bundled scripts use `dirname "$0"` to locate sibling files (Containerfiles, SELinux policies, configs), so they work correctly from any directory.

To use a custom setup script with `workloadctl enable`, set an absolute path in your workload config:

```toml
[host]
setup = "/home/myuser/sunshine-custom/setup.sh"
```

Example setup script pattern:

```bash
#!/bin/bash
set -euo pipefail

enable() {
    # Load kernel module, add udev rules, install SELinux policy...
}

disable() {
    # Reverse the above
}

case "${1:-}" in
    enable)  enable ;;
    disable) disable ;;
    *)       echo "Usage: $0 {enable|disable}" >&2; exit 1 ;;
esac
```

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

#### Workloads Slice (aggregate protection)

All workloads run inside `workloads.slice` by default, which provides aggregate resource limits that protect the host even if individual workloads have no limits set:

| Resource | Slice Default | Effect |
|----------|--------------|--------|
| `CPUWeight` | 80 | Workloads yield CPU to system services under contention |
| `MemoryMax` | 90% | All workloads combined can never exceed 90% of system RAM |
| `MemoryHigh` | 85% | Throttling begins at 85% to avoid hitting the hard limit |
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

For complete resource documentation with detailed examples, see `workloads.d/schema-reference.toml`.

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
- [workloads.d/example-with-secrets.toml](../workloads.d/example-with-secrets.toml) - Working example
- [workloads.d/schema-reference.toml](../workloads.d/schema-reference.toml) - Full schema with secrets

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

sudo cp /usr/share/workloadctl/containers/smb-server/smb.conf /var/lib/workloads/smb-server/smb.conf
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
workloadctl info NAME                 # Comprehensive workload info
workloadctl ports NAME                # Port information
workloadctl stats NAME                # Resource usage
workloadctl stats -f                  # All workloads, live updating
workloadctl ps                        # List all running containers
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
workloadctl attach NAME               # Attach to container process
```

**Image management:**
```bash
workloadctl images list               # Show images used by workloads
workloadctl images prune              # Remove unused images
```

### Manual Enable/Disable (Without workloadctl)

If you prefer to manage workloads manually:

**Enable a workload:**
```bash
# 1. Edit the config file
sudo nano /etc/workloads.d/example-webserver.toml
# Change: enabled = false → enabled = true

# 2. Reload systemd and start
sudo systemctl daemon-reload
sudo systemctl start workload-webserver.service
```

**Disable a workload:**
```bash
# 1. Stop the service
sudo systemctl stop workload-webserver.service

# 2. Edit the config file
sudo nano /etc/workloads.d/example-webserver.toml
# Change: enabled = true → enabled = false

# 3. Reload systemd
sudo systemctl daemon-reload
```

**Disable and purge manually:**
```bash
# 1. Stop and disable
sudo systemctl stop workload-webserver.service
sudo nano /etc/workloads.d/example-webserver.toml  # Set enabled = false
sudo systemctl daemon-reload

# 2. Get user info and remove
id _wl-webserver
sudo loginctl terminate-user 10001  # Use actual UID
sudo loginctl disable-linger 10001
sudo sed -i '/^_wl-webserver:/d' /etc/subuid /etc/subgid
sudo userdel -r _wl-webserver
```

### Image Updates

Pull the latest version of a workload's container image and restart if it changed.

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

# Live backup (no service stop — may be inconsistent)
sudo workloadctl backup pihole --no-stop

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
├── workload.toml              # /etc/workloads.d/pihole.toml
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

The output `.secret` file is encrypted with AES-256-CBC (PBKDF2 key derivation) and can be safely transferred to another machine via scp, USB drive, etc.

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
workloadctl ps                       # All running containers

# Check ports
workloadctl ports NAME
```

### Common Issues and Solutions

#### 1. Workload Name Too Long

**Symptom:** Generator logs error about username length.

```
workload-generator: ERROR processing /etc/workloads.d/my-workload.toml:
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
workloadctl ports NAME

# Either change the port in config or stop conflicting service
sudo workloadctl edit NAME  # Change port mapping
```

#### 3. Workload Not Starting (enabled = false)

**Symptom:** Config file exists but service never starts.

**Fix:**
```toml
[workload]
enabled = true  # Must be true!
```

Then reload: `sudo systemctl daemon-reload`

Or use: `sudo workloadctl enable NAME`

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
# View generator logs (appears in early boot)
dmesg | grep workload-generator

# Manually run generator for testing
sudo WORKLOAD_CONFIG_DIR=/etc/workloads.d \
  /usr/lib/systemd/system-generators/workload-generator \
  /tmp/test-output /tmp/test-early /tmp/test-late

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
# Create network as workload user
sudo -u _wl-app XDG_RUNTIME_DIR=/run/user/10001 podman network create mynetwork

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

When you disable a workload (`enabled = false`), the generator stops creating the service, but:
- The user account persists
- Home directory remains
- Subuid/subgid entries remain

**Rationale:** Safety - we don't want to accidentally delete user data or UIDs that might be referenced elsewhere.

**Cleanup options:**
- `workloadctl disable --purge NAME` - removes user/home/subuid when disabling
- `sudo workloadctl cleanup --apply` - bulk-removes all orphaned users and directories

#### 4. Subuid/Subgid Range Allocation

Each workload needs a unique subordinate UID/GID range for rootless containers.

**Formula:** `100000 + (uid_offset * 100000)` with 65536 UIDs/GIDs, where `uid_offset = uid - 10000`
- Workload UID 10001: subuid range 200000:65536
- Workload UID 10002: subuid range 300000:65536

**Impact:**
- UIDs are capped at 52948, supporting up to **42,948 workloads** per host before the subuid range would overflow uint32. This limit is unlikely to be reached in practice but is worth knowing if you are planning large-scale deployments.
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

Most service containers (web servers, databases, media servers) never call these syscalls. If your workload does, you'll see `Operation not permitted` errors at startup — see the [troubleshooting guide](TROUBLESHOOTING.md) for diagnosis steps.

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

- **Configuration schema:** `workloads.d/schema-reference.toml`
- **Example workloads:** `workloads.d/example-*.toml`
- **Secrets management:** `docs/secrets.md`
- **Generator source:** `generators/workload-generator`
- **User setup script:** `libexec/workload-ensure-user`
- **Management tool:** `bin/workloadctl`

For questions or issues, see the project documentation or file issues in the project repository.
