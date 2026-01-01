# Rootless Workload Provisioning System

## Overview

The workload provisioning system allows you to declaratively define long-running containerized workloads that start automatically at boot. Each workload runs as a dedicated system user with rootless podman, providing isolation while maintaining access to host hardware like GPUs and input devices.

## Architecture

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

### User Management

Each enabled workload gets a dedicated user:
- **Username:** `_wl-{name}-{id}` (e.g., `_wl-webserver-1`)
- **UID:** `10000 + id` (e.g., id=1 → UID 10001)
- **Subuid range:** `100000 + (uid_offset * 100000)` with 65536 UIDs
- **Home directory:** `/var/lib/workloads/{name}-{id}`
- **Shell:** `/usr/sbin/nologin` (service user, no interactive login)

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

## Important Limitations and Tradeoffs

### 1. Network Mode Defaults to Host

**Issue:** Rootless containers run as system services cannot use pasta (rootless bridge networking) with reliable port forwarding.

**Tradeoff:** The default network mode is `host`, meaning:
- Containers share the host network namespace
- No port mapping needed (container ports are directly accessible)
- No network isolation between containers
- Port conflicts possible if multiple containers use the same port

**Workaround:** Set `network.mode = "pasta"` for isolation, but be aware of potential port forwarding issues with rootless containers started by system services.

```toml
[network]
mode = "host"  # Default - shares host network, no isolation
# mode = "pasta"  # Isolated network, but port forwarding may not work reliably
ports = ["8080:8080"]  # Only used with pasta mode
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

### Networking (TODO)

**Status:** INCOMPLETE - Only basic host and pasta modes are implemented.

**Current implementation:**
- `network.mode = "host"` - Shares host network namespace (default)
- `network.mode = "pasta"` - Isolated network with pasta, but port forwarding is unreliable for rootless containers in system services
- `network.ports` - Port mappings (only works with pasta mode)

**Missing / Needs work:**
- **Bridge networking** - Proper isolated networks with reliable port forwarding
- **Network namespaces** - Better isolation between workloads
- **DNS configuration** - Custom DNS servers, search domains
- **Network policies** - Firewall rules, traffic shaping
- **Multiple networks** - Connecting containers to multiple networks
- **Network sharing** - Shared networks between workloads
- **IPv6 support** - Currently untested

**Why it's incomplete:** Rootless containers started by system services have fundamental limitations with pasta port forwarding. A proper solution requires either:
1. CNI plugin configuration for rootless containers
2. Bridge networking with slirp4netns improvements
3. Alternative approaches like VPN tunnels or proxy containers

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

**Current:** Errors logged to kmsg (dmesg) and journal.

**Issues:**
- Generator runs early, errors may not be in journal
- No clear feedback when configs are invalid
- Service failures can be cryptic

**Improvement:** Better validation with clear error messages, and a `workload-ctl validate` command.

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

### 2. Port Already in Use (Host Networking)

**Symptom:** Container fails to start, journal shows "address already in use".

```bash
$ sudo journalctl -u workload-webserver-1
Error: rootlessport listen tcp 0.0.0.0:8080: bind: address already in use
```

**Fix:** Either:
- Change the port in the config
- Stop the conflicting service
- Use pasta mode (if port forwarding works for your use case)

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

Potential enhancements:
1. **Interactive management tool:** `workload-ctl create`, `workload-ctl logs`, etc.
2. **Better networking:** Solve pasta port forwarding for proper network isolation
3. **Resource limits:** CPU, memory, storage quotas via systemd
4. **Health checks:** Automatic restart on container health failures
5. **Backup/restore:** Built-in snapshot and restore functionality
6. **Multi-container workloads:** Pod support for related containers
7. **Template system:** Pre-configured workload templates for common use cases
8. **Web UI:** Cockpit integration for workload management

## Additional Resources

- Configuration schema: `workloads.d/schema-reference.toml`
- Example workloads: `workloads.d/example-*.toml`
- Generator source: `generators/workload-generator`
- Setup script: `libexec/workload-setup.py`
- Management tool: `bin/workload-ctl`
- Systemd units: `systemd/workload-setup.service`
