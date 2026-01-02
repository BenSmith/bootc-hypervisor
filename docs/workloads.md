# DRAFT DRAFT DRAFT DRAFT

# Rootless Workload Provisioning System

## Quick Start

Deploy a web server in just one command:

**Easy way (using create command):**
```bash
sudo workload-ctl create webserver \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --ports 8080:8080 \
  --enable

# Or with host networking for maximum performance:
sudo workload-ctl create webserver \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --network host \
  --enable
```

That's it! Your web server is now running, will start automatically at boot, and runs as an isolated unprivileged user with rootless podman.

Check it's running:
```bash
workload-ctl status webserver
curl http://localhost:8080
```

---

**Manual way (for bootc images or advanced use):**

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
id = "1"

[network]
ports = ["8080:8080"]
```

3. Enable and start:
```bash
sudo workload-ctl enable webserver
```

## What Can You Do?

The `workload-ctl` command gives you Docker/kubectl-like management for your workloads:

```bash
# Create a new workload
sudo workload-ctl create jellyfin --image=jellyfin/jellyfin:latest --enable

# List all workloads
workload-ctl list

# Get detailed info
workload-ctl info webserver

# View logs in real-time
workload-ctl logs -f webserver

# Open a shell in the container
workload-ctl shell webserver

# Update to latest image
sudo workload-ctl update webserver

# Monitor resource usage
workload-ctl stats -f

# Check health
workload-ctl health webserver

# And much more...
```

**Key benefits:**
- ✅ Declarative configuration with simple TOML files
- ✅ Automatic startup at boot via systemd
- ✅ Rootless containers for security isolation
- ✅ GPU and hardware device access when needed
- ✅ Docker/kubectl-like CLI for easy management
- ✅ No root required for read-only operations

## Configuration

Workload configurations are TOML files in `/etc/workloads.d/`. See `workloads.d/schema-reference.toml` for full documentation.

### Minimal Example

```toml
[workload]
name = "webserver"
enabled = true

[container]
image = "docker.io/nginxinc/nginx-unprivileged:alpine"
id = "1"

[gpu]
type = "none"

[devices]
input = false

[security]
extra_groups = []

[network]
# mode = "pasta"  # Default - isolated networking with port forwarding
# mode = "host"   # Share host network (no isolation, maximum performance)
# mode = "none"   # No networking
ports = ["8080:8080"]
```

### Applying Changes

After modifying configs:
```bash
sudo systemctl daemon-reload  # Regenerates configs
sudo systemctl restart workload-{name}-{id}.service
```

## Managing Workloads

### Using workload-ctl (Recommended)

The `workload-ctl` command provides a convenient interface for managing workloads:

**Create a new workload:**
```bash
sudo workload-ctl create NAME --image IMAGE [OPTIONS]
```
Creates a new workload configuration file in `/etc/workloads.d/`. This is the easiest way to get started on regular Fedora systems.

**Required arguments:**
- `NAME` - Workload name (lowercase letters, numbers, hyphens only)
- `--image IMAGE` - Container image to use (e.g., `docker.io/library/nginx:alpine`)

**Optional arguments:**
- `--id N` - Explicit workload ID (default: auto-assign next available)
- `--gpu TYPE` - GPU type: `amd`, `nvidia`, or `none`
- `--groups GROUP...` - Additional system groups (e.g., `video render input`)
- `--ports PORT...` - Port mappings (e.g., `8080:80 8443:443`)
- `--network MODE` - Network mode: `pasta` (default), `host`, `none`, or custom network name
- `--volumes VOL...` - Volume mounts (e.g., `/host/path:/container/path:ro`)
- `--enable` - Enable and start the workload immediately after creation
- `--disabled` - Create as disabled (`enabled = false`)

**Examples:**

Minimal workload (auto-assigns ID):
```bash
sudo workload-ctl create jellyfin --image=jellyfin/jellyfin:latest
```

With common options:
```bash
sudo workload-ctl create sunshine \
  --image=ghcr.io/lizardbyte/sunshine:latest \
  --gpu=nvidia \
  --groups video input \
  --ports 47984:47984 47989:47989 \
  --network=host \
  --enable
```

With volumes and explicit ID:
```bash
sudo workload-ctl create minecraft \
  --image=itzg/minecraft-server:latest \
  --id=42 \
  --volumes /mnt/games/minecraft:/data \
  --ports 25565:25565 \
  --enable
```

Create but don't enable:
```bash
sudo workload-ctl create test-app \
  --image=myapp:latest \
  --disabled
```

**How it works:**
1. Validates the workload name (must be lowercase, numbers, hyphens)
2. Auto-assigns the next available ID (0-49999) if `--id` not specified
3. Checks for naming conflicts and ID collisions
4. Validates username length (must be < 32 characters)
5. Creates `/etc/workloads.d/NAME.toml` with specified options
6. Validates the generated configuration
7. If `--enable` is used, runs the enable process immediately

After creation, you can:
- Edit the config: `sudo workload-ctl edit NAME`
- Enable it: `sudo workload-ctl enable NAME`
- View it: `workload-ctl info NAME`

**Note for bootc users:** On bootc images, it's recommended to create TOML configs manually and bake them into your image for immutability. The `create` command is most useful on regular (mutable) Fedora systems.

**List all workloads:**
```bash
workload-ctl list
```
Shows all configs in `/etc/workloads.d/` with their enabled status, name, and ID.

**Enable a workload:**
```bash
sudo workload-ctl enable example-webserver
```
This will:
1. Set `enabled = true` in the config file
2. Run `systemctl daemon-reload` to regenerate systemd units
3. Run `systemd-sysusers` to create the user
4. Run `workload-setup.service` to configure subuid/subgid and home directory
5. Start the workload service

**Disable a workload:**
```bash
sudo workload-ctl disable example-webserver
```
This will:
1. Stop the workload service
2. Set `enabled = false` in the config file

The user, home directory, and subuid/subgid entries remain on the system (safe default).

**Disable and purge a workload:**
```bash
sudo workload-ctl disable --purge example-webserver
```
This will:
1. Stop the workload service
2. Set `enabled = false` in the config file
3. Terminate user sessions and disable linger
4. Remove the user account
5. Remove the home directory
6. Remove subuid/subgid entries

**Warning:** `--purge` deletes all data in the workload's home directory.

**Restart a workload:**
```bash
sudo workload-ctl restart example-webserver
```
Restarts the systemd service (useful after config changes).

**Check workload status:**
```bash
workload-ctl status example-webserver
```
Shows the systemd service status (no sudo needed for read-only status).

**Open interactive shell in container:**
```bash
workload-ctl shell example-webserver
```
Opens an interactive shell (tries `/bin/bash`, falls back to `/bin/sh`). Useful for debugging, inspecting files, or running ad-hoc commands.

**Execute command in container:**
```bash
workload-ctl exec example-webserver ls -la /data
workload-ctl exec example-webserver cat /etc/os-release
```
Runs arbitrary commands inside the container without opening a shell. Perfect for quick inspections or scripting.

**View workload logs:**
```bash
workload-ctl logs example-webserver
workload-ctl logs -f example-webserver              # Follow logs in real-time
workload-ctl logs -n 50 example-webserver           # Last 50 lines
workload-ctl logs --since "10 minutes ago" example-webserver
```
Shows container logs from systemd journal. Wrapper around `journalctl` with automatic service name lookup.

**Show all running containers:**
```bash
workload-ctl ps
```
Lists all running workload containers across all users. Shows which user owns each container and their status.

**Update workload image:**
```bash
sudo workload-ctl update example-webserver
sudo workload-ctl update --force example-webserver  # Force pull even if cached
sudo workload-ctl update --all                      # Update all workloads
```
Pulls the latest image and restarts the workload. Shows before/after image IDs. Use `--force` to bypass cache and force a fresh pull. Use `--all` to update all enabled workloads at once.

**Show detailed workload information:**
```bash
workload-ctl info example-webserver
```
Displays comprehensive information about a workload including container details, user configuration, network settings, storage usage, and service status. No sudo needed for read-only info display. Output includes:
- Container name, image, and ID
- User name, UID, home directory, and groups
- Network mode and port mappings
- Storage usage
- Service status and uptime
- Quick command references

**Validate workload configuration:**
```bash
workload-ctl validate example-webserver
workload-ctl validate --all
```
Checks configuration for errors before enabling. Validates:
- Required fields (name, image, id)
- Username length (< 32 chars)
- ID range and uniqueness
- Volume paths exist
- System groups exist
Provides clear error messages and suggested fixes for any issues found.

**Edit workload configuration:**
```bash
sudo workload-ctl edit example-webserver
```
Opens the workload config in your `$EDITOR` (nano by default). After saving:
1. Validates the new configuration
2. Shows a diff of changes
3. Prompts for confirmation
4. Applies changes with `daemon-reload` and service restart if confirmed

**Monitor resource usage:**
```bash
workload-ctl stats example-webserver
workload-ctl stats                    # All workloads
workload-ctl stats -f                 # Follow in real-time
workload-ctl stats --follow           # Same as -f
```
Shows CPU usage, memory usage/limits, network I/O, and block I/O for workload containers. Use `-f` or `--follow` for live updating display.

**Show port information:**
```bash
workload-ctl ports example-webserver
```
Displays network mode, container ports, and accessibility information. For host networking mode, shows which ports the container listens on and where they're accessible. For pasta mode, shows port mappings.

**Copy files to/from container:**
```bash
workload-ctl cp example-webserver:/etc/nginx/nginx.conf ./nginx.conf
workload-ctl cp ./config.json example-webserver:/app/config.json
```
Copies files between the host and container. Use `workload:path` syntax for container paths, similar to `docker cp` and `kubectl cp`.

**Attach to container process:**
```bash
workload-ctl attach example-webserver
```
Attaches to the container's main process stdin/stdout/stderr. Different from `shell` - this connects to the running process rather than starting a new shell. Use Ctrl+C to detach.

**Manage container images:**
```bash
workload-ctl images list             # Show images used by workloads
workload-ctl images prune            # Remove unused images
```
Lists all images used by workloads with size and age information, or cleans up unused images to free disk space. Prune runs `podman image prune` for each workload user.

**Check workload health:**
```bash
workload-ctl health example-webserver
```
Performs comprehensive health checks on a workload including:
- Service status (systemd active state)
- User existence
- Container running state
- Port accessibility (tests TCP connections to configured ports)
- Recent log errors (scans last 100 lines)
- Uptime information

Returns exit code 0 if healthy, 1 if unhealthy. Supports `--json` for structured output. Perfect for monitoring systems and automated health checks.

**Equivalent systemctl commands:**

For reference, `workload-ctl` commands map to systemctl:
```bash
# These are equivalent:
workload-ctl restart webserver
sudo systemctl restart workload-webserver-1.service

# workload-ctl is just more convenient - shorter names, no need to know the ID
```

### Manual Enable/Disable (Without workload-ctl)

If you prefer to manage workloads manually or need more control:

**Enable a workload:**
```bash
# 1. Edit the config file
sudo nano /etc/workloads.d/example-webserver.toml
# Change: enabled = false
# To:     enabled = true

# 2. Reload systemd (triggers generator to create service units)
sudo systemctl daemon-reload

# 3. Start the service (use actual name-id from config)
#    The service automatically runs systemd-sysusers and workload-setup.service via ExecStartPre
sudo systemctl start workload-webserver-1.service
```

**Disable a workload:**
```bash
# 1. Stop the service
sudo systemctl stop workload-webserver-1.service

# 2. Edit the config file
sudo nano /etc/workloads.d/example-webserver.toml
# Change: enabled = true
# To:     enabled = false

# 3. Reload systemd (generator will remove the service unit)
sudo systemctl daemon-reload
```

**Disable and purge manually:**
```bash
# 1. Stop and disable as above
sudo systemctl stop workload-webserver-1.service
sudo nano /etc/workloads.d/example-webserver.toml  # Set enabled = false
sudo systemctl daemon-reload

# 2. Get user info
id _wl-webserver-1

# 3. Remove user and data
sudo loginctl terminate-user 10001  # Use actual UID
sudo loginctl disable-linger 10001
sudo sed -i '/^_wl-webserver-1:/d' /etc/subuid /etc/subgid
sudo userdel -r _wl-webserver-1
```

### Configuration Changes

For changes to existing workload configs (image, ports, volumes, etc.):

**With workload-ctl:**
```bash
# Edit config
sudo nano /etc/workloads.d/example-webserver.toml

# Apply changes
sudo workload-ctl restart example-webserver
```

**Manually:**
```bash
# Edit config
sudo nano /etc/workloads.d/example-webserver.toml

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart workload-webserver-1.service
```

**Note:** The `daemon-reload` step is important - it re-runs the generator to update the systemd service with new podman arguments.

## Architecture

Understanding how the system works internally:

```
Boot Flow:
1. systemd-generators → workload-generator creates user and service configs
2. systemd-sysusers.service → creates workload users with group memberships
3. workload-setup.service → configures subuid/subgid ranges and home directories
4. workload-{name}-{id}.service → individual containers start
```

### Components

- **Generator** (`/usr/lib/systemd/system-generators/workload-generator`): Reads TOML configs from `/etc/workloads.d/` and generates systemd-sysusers configs and systemd services
- **Setup Service** (`workload-setup.service`): Configures subordinate UID/GID ranges, creates home directories, enables linger
- **Workload Services**: Per-workload systemd services that run `podman run` as dedicated users
- **Management Tool** (`workload-ctl`): Docker/kubectl-like CLI for managing workloads

### User Management

Each enabled workload gets a dedicated system user:
- **Username:** `_wl-{name}-{id}` (e.g., `_wl-webserver-1`)
- **UID:** `10000 + id` (e.g., id=1 → UID 10001)
- **Subuid range:** `100000 + (uid_offset * 100000)` with 65536 UIDs
- **Home directory:** `/var/lib/workloads/{name}-{id}`
- **Shell:** `/usr/sbin/nologin` (service user, no interactive login)
- **Isolation:** Rootless podman with user namespaces, SELinux, and systemd service boundaries

The workload provisioning system allows you to declaratively define long-running containerized workloads that start automatically at boot. Each workload runs as a dedicated system user with rootless podman, providing isolation while maintaining access to host hardware like GPUs and input devices when explicitly configured.

## Important Limitations and Tradeoffs

### 1. Network Modes

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

### 2. Group Names Appear as Numbers in Containers

**Issue:** Containers use user namespaces with different UID/GID mappings than the host. Device access groups (video, render, input) use host GIDs explicitly via `--group-add=GID`.

**Result:** Inside the container, `id` shows group memberships as numbers, not names:
```bash
# Host:
$ id _wl-workload-1
uid=10001(_wl-workload-1) gid=10001(_wl-workload-1) groups=10001,39(video),104(input),105(render)

# Container:
$ podman exec workload-1 id
uid=10001 gid=10001 groups=10001,39,104,105
```

**Why:** The container's `/etc/group` has different GIDs for these groups. We use host GIDs because device files (like `/dev/dri/renderD128`) have host GIDs, and the kernel checks permissions using host GIDs.

**Impact:** This is cosmetic - device access works correctly. Group names just don't appear in containers.

### 3. Username Length Limit (32 characters)

**Issue:** Linux usernames are limited to 32 characters (LOGIN_NAME_MAX).

**Impact:** Workload names are used in usernames as `_wl-{name}-{id}`, leaving ~26 characters for the name.

**Workaround:** Keep workload names short. The generator will reject configs with names that result in usernames longer than 32 characters.

```toml
[workload]
name = "webserver"  # Good: _wl-webserver-1 = 17 chars
# name = "my-very-long-descriptive-workload-name"  # Bad: 46 chars total
```

### 4. Bootc Immutable Groups

**Issue:** On bootc systems, most groups are defined in `/usr/lib/group` (immutable via nss-altfiles) rather than `/etc/group` (mutable).

**Solution:** The Containerfile copies device access groups (video, render, input) to `/etc/group` at build time:
```dockerfile
RUN grep -E "^(video|render|input):" /usr/lib/group >> /etc/group || true
```

**Impact:** Adding new device groups requires rebuilding the bootc image. You cannot add arbitrary groups at runtime.

### 5. No Automatic Cleanup of Disabled Workloads

**Issue:** When you disable a workload (`enabled = false`), the generator stops creating the service, but:
- The user account persists
- Home directory remains
- Subuid/subgid entries remain

**Rationale:** Safety - we don't want to accidentally delete user data or UIDs that might be referenced elsewhere.

**Workaround:** Manual cleanup if needed:
```bash
sudo userdel -r _wl-{name}-{id}
sudo sed -i "/^_wl-{name}-{id}:/d" /etc/subuid /etc/subgid
```

### 6. Subuid/Subgid Range Allocation

**Issue:** Each workload needs a unique subordinate UID/GID range for rootless containers.

**Formula:** `100000 + (uid_offset * 100000)` with 65536 UIDs/GIDs
- Workload ID 1 (UID 10001): 200000:65536
- Workload ID 2 (UID 10002): 300000:65536

**Impact:**
- Maximum ~40 workloads before ranges approach the 32-bit UID limit
- Changing a workload's ID requires manual `/etc/subuid` and `/etc/subgid` cleanup

## Known Incomplete Areas (TODOs)

### Networking (PARTIALLY COMPLETE)

**Status:** Basic networking implemented and working. Advanced features still TODO.

**Current implementation:**
- `network.mode = "pasta"` - Isolated network with port forwarding (default, works reliably in Podman 5.3+)
- `network.mode = "host"` - Shares host network namespace (no isolation, maximum performance)
- `network.mode = "none"` - No networking (complete isolation)
- `network.mode = "<network-name>"` - Custom user-defined networks (user creates with `podman network create`)
- `network.ports` - Port mappings (works with pasta and custom network modes)

**Missing / Needs work:**
- **Automatic network creation** - Currently users must manually create custom networks with `podman network create`
- **Network lifecycle management** - Networks are not automatically created/deleted with workloads
- **DNS configuration** - Custom DNS servers, search domains
- **Network policies** - Firewall rules, traffic shaping
- **Multiple networks per container** - Connecting single container to multiple networks
- **IPv6 support** - Currently untested
- **Network inspection** - Better visibility into network configuration and connectivity

**Example - Custom network for container-to-container communication:**
```bash
# Create network as workload user
sudo -u _wl-app-1 XDG_RUNTIME_DIR=/run/user/10001 podman network create mynetwork

# Configure workloads to use it
[network]
mode = "mynetwork"
ports = ["8080:8080"]  # External access
```

### Storage (TODO)

**Status:** INCOMPLETE - Only basic volume mounts are implemented.

**Current implementation:**
- `storage.home` - Custom home directory path (default: `/var/lib/workloads/{name}-{id}`)
- `storage.volumes` - Array of volume mounts in `host:container:options` format
- Automatic home directory at `/data` inside container

**Missing / Needs work:**
- **Named volumes** - Podman volume management (create, delete, inspect)
- **Shared volumes** - Volumes shared between multiple workloads
- **tmpfs mounts** - In-memory filesystem support
- **Bind mount options** - More granular control (ro, rw, nosuid, noexec, etc.)
- **Storage quotas** - Limit container storage size
- **Automatic cleanup** - Remove old container images and volumes
- **Backup/restore** - Snapshot and restore volume data
- **Volume drivers** - Support for different storage backends
- **Data migration** - Moving data between workloads or hosts

**Why it's incomplete:** Current implementation is minimal - just passes volumes through to podman. A complete solution would include:
1. Volume lifecycle management (create/delete with workload)
2. Integration with system backup tools
3. Quota enforcement via systemd or filesystem features
4. Validation of volume paths and permissions

## Things That Could Use Improvement

### 1. Configuration Validation

**Current:** Basic validation in generator (username length, required fields).

**Missing:**
- Port conflict detection
- Subuid range overlap detection
- Image name validation
- Volume path validation

**Risk:** Invalid configs cause service failures at startup rather than at `daemon-reload` time.

### 2. Error Messages and Debugging

**Current:** Errors logged to kmsg (dmesg) and journal. Validation available via `workload-ctl validate`.

**Implemented:**
- ✅ `workload-ctl validate` - Pre-flight config validation
- ✅ `workload-ctl info` - Detailed diagnostic information
- ✅ Clear error messages with suggested fixes

**Remaining issues:**
- Generator runs early, errors may not be in journal
- Service failures can still be cryptic without running validation first

### 3. GPU Support Completeness

**Current:** Basic AMD and NVIDIA GPU support.

**Missing:**
- Intel GPU support (needs testing with `/dev/dri` access)
- Multi-GPU selection (always uses all GPUs)
- GPU memory limits
- Compute vs graphics workload optimization

### 4. SELinux Policy

**Current:** Uses `restorecon` to set container_file_t on home directories.

**Missing:**
- Custom policy for specific device access patterns
- Better integration with container_t domain transitions
- Audit logs for permission denials

**Impact:** Some hardware access patterns may be denied by SELinux. Workaround: Check `ausearch -m avc` and create custom policies.

## Common Pitfalls and How to Avoid Them

### 1. Workload Name Too Long

**Symptom:** Generator logs error about username length.

```
workload-generator: ERROR processing /etc/workloads.d/my-workload.toml:
Username '_wl-my-very-long-workload-name-1' is 34 chars (max 32)
```

**Fix:** Shorten the workload name:
```toml
[workload]
name = "long-name"  # Bad
name = "app"        # Good
```

### 2. Port Already in Use

**Symptom:** Container fails to start, journal shows "address already in use".

```bash
$ sudo journalctl -u workload-webserver-1
Error: rootlessport listen tcp 0.0.0.0:8080: bind: address already in use
```

**Common causes:**
- Another container or service is using the same port
- Conflicting workloads both using host mode
- Port mapping conflict in pasta mode

**Fix:** Either:
- Change the port in the config (different host port)
- Stop the conflicting service
- Check all workloads: `workload-ctl list` and `workload-ctl ports <name>`

### 3. Forgetting to Enable Workload

**Symptom:** Config file exists but service never starts.

**Cause:** `enabled = false` in config.

**Fix:**
```toml
[workload]
enabled = true  # Not false!
```

Then reload: `sudo systemctl daemon-reload`

### 4. SELinux Denying Device Access

**Symptom:** Container can't access GPU/input devices despite correct groups.

**Check:**
```bash
sudo ausearch -m avc -ts recent
```

**Fix:** If SELinux is blocking access, either:
- Create a custom policy module
- Temporarily set permissive mode for testing: `sudo setenforce 0`
- Check that home directory has correct context: `ls -Z /var/lib/workloads/`

### 5. Image Pull Failures

**Symptom:** Service fails with "unable to pull image".

**Common causes:**
- Registry requires authentication (use `podman login` as root for system-wide creds)
- Image name typo
- Network issues
- Rate limiting

**Debug:**
```bash
# Test image pull manually
sudo -u _wl-{name}-{id} XDG_RUNTIME_DIR=/run/user/{uid} podman pull {image}
```

**Fix:** Set appropriate pull policy:
```toml
[container]
pull = "missing"  # Default - only pull if not cached
# pull = "always"   # Always check for updates (slower)
# pull = "never"    # Fail if image not in cache
```

### 6. Container Immediately Exits

**Symptom:** Service status shows "activating" briefly, then stops.

**Cause:** Container command exits immediately (e.g., shell exits in foreground).

**Fix:** Ensure container command runs in foreground and doesn't exit:
```toml
[container]
command = ["sleep", "infinity"]  # For testing
# command = ["nginx", "-g", "daemon off;"]  # Foreground mode for nginx
```

**Debug:**
```bash
# Check what command ran
sudo journalctl -u workload-{name}-{id} -n 50

# Try running manually
sudo -u _wl-{name}-{id} XDG_RUNTIME_DIR=/run/user/{uid} podman run --rm {image} {command}
```

### 7. Subuid/Subgid Not Configured

**Symptom:** Container fails with "newuidmap: write to uid_map failed: Operation not permitted".

**Cause:** User doesn't have subordinate UID/GID ranges.

**Fix:** Ensure workload-setup.service ran successfully:
```bash
sudo systemctl status workload-setup.service

# Check ranges exist
grep _wl-{name}-{id} /etc/subuid /etc/subgid
```

If missing, restart setup service:
```bash
sudo systemctl restart workload-setup.service
```

### 8. Volume Mount Permission Denied

**Symptom:** Container can't read/write mounted volumes.

**Cause:** Either:
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
```

## Troubleshooting Guide

### Checking Workload Status

**Using workload-ctl (easiest):**
```bash
# List all workloads with status
workload-ctl list

# Check specific workload status
workload-ctl status example-webserver

# Get detailed information
workload-ctl info example-webserver

# View logs
workload-ctl logs example-webserver
workload-ctl logs -f example-webserver  # Follow in real-time

# Monitor resource usage
workload-ctl stats example-webserver
workload-ctl stats -f  # All workloads, live updating

# Show all running containers
workload-ctl ps

# Check port configuration
workload-ctl ports example-webserver

# Validate configuration
workload-ctl validate example-webserver

# Open shell in container for debugging
workload-ctl shell example-webserver

# Run diagnostic commands
workload-ctl exec example-webserver id
workload-ctl exec example-webserver df -h
workload-ctl exec example-webserver ps aux
```

**Using systemctl and podman directly:**
```bash
# List all workload services
systemctl list-units 'workload-*'

# Check specific workload
sudo systemctl status workload-{name}-{id}

# View logs
sudo journalctl -u workload-{name}-{id} -f

# Check if user exists
getent passwd _wl-{name}-{id}

# Check user groups
id _wl-{name}-{id}

# Check container is running
sudo -u _wl-{name}-{id} XDG_RUNTIME_DIR=/run/user/{uid} podman ps

# Get shell in container (manual method)
sudo -u _wl-{name}-{id} XDG_RUNTIME_DIR=/run/user/{uid} \
  podman exec -it workload-{name}-{id} /bin/sh
```

### Generator Debugging

```bash
# View generator logs (appears in early boot)
dmesg | grep workload-generator

# Manually run generator for testing
sudo WORKLOAD_CONFIG_DIR=/etc/workloads.d \
  /usr/lib/systemd/system-generators/workload-generator \
  /tmp/test-output /tmp/test-early /tmp/test-late

# Check generated configs
systemd-sysusers --cat-config | grep workload
systemctl cat workload-{name}-{id}
```

### Common Fixes

**Reload after config changes:**
```bash
sudo systemctl daemon-reload
sudo systemctl restart workload-{name}-{id}
```

**Force image update:**
```bash
# Easy way with workload-ctl:
sudo workload-ctl update --force example-webserver

# Manual way:
sudo -u _wl-{name}-{id} XDG_RUNTIME_DIR=/run/user/{uid} podman pull {image}
sudo systemctl restart workload-{name}-{id}
```

**Reset a workload completely:**
```bash
# Stop service
sudo systemctl stop workload-{name}-{id}

# Remove user and data
sudo userdel -r _wl-{name}-{id}
sudo sed -i "/^_wl-{name}-{id}:/d" /etc/subuid /etc/subgid

# Recreate
sudo systemctl daemon-reload
sudo systemctl start workload-{name}-{id}
```

## Security Considerations

### Rootless Containers

While containers run as unprivileged users, keep in mind:
- Containers share the kernel with the host
- User namespace mapping provides UID/GID isolation
- SELinux provides mandatory access control
- Device access (GPU, input) grants real hardware access

### Device Access Groups

Adding a user to `video`, `render`, or `input` groups grants:
- `video`/`render`: Full GPU access (can run arbitrary compute workloads, access video memory)
- `input`: Can read keyboard/mouse input and inject events

Only grant these to trusted workloads.

### Network Access

With `network.mode = "host"`:
- Container can bind to any host port
- Container can access all network services
- No isolation from other containers

Consider firewall rules for untrusted workloads.

## Future Improvements

**Implemented features:**
- ✅ **Interactive management tool:** `workload-ctl` with update, info, validate, edit, stats, cp, ports, images, attach commands
- ✅ **Resource monitoring:** Real-time stats with `workload-ctl stats`
- ✅ **Configuration validation:** Pre-flight checks with `workload-ctl validate`
- ✅ **Image management:** Update and prune commands

**Potential future enhancements:**
1. **Better networking:** Solve pasta port forwarding for proper network isolation
2. **Resource limits:** CPU, memory, storage quotas via systemd (can be added to configs)
3. **Health checks:** Automatic restart on container health failures
4. **Backup/restore:** Built-in snapshot and restore functionality
5. **Multi-container workloads:** Pod support for related containers
6. **Template system:** Pre-configured workload templates with `workload-ctl create`
7. **Web UI:** Cockpit integration for workload management
8. **JSON output:** Add `--json` flag for all commands for scripting integration

## Additional Resources

- Configuration schema: `workloads.d/schema-reference.toml`
- Example workloads: `workloads.d/example-*.toml`
- Generator source: `generators/workload-generator`
- Setup script: `libexec/workload-setup.py`
- Management tool: `bin/workload-ctl`
- Systemd units: `systemd/workload-setup.service`
