# Workload Troubleshooting Guide

This guide covers common issues when working with the workload system and how to resolve them.

## Quick Diagnostics

### Check workload health
```bash
# Verify all aspects of workload setup
sudo workloadctl verify <workload>

# Check service status
sudo workloadctl status <workload>

# View recent logs
sudo workloadctl logs -n 50 <workload>
```

### Common failure pattern
When a workload fails to start, you'll typically see:
- Service shows as "failed" or "activating"
- Container exits immediately with code 125 or 126
- Logs show cryptic error messages

Run `workloadctl verify` to diagnose the root cause.

## Common Issues

### 1. Image not found / Image extraction failed

**Symptoms:**
- `Error: short-name resolution enforced but cannot prompt without a TTY`
- `Error: creating blob layer: opening file: permission denied`
- Service fails with exit code 125

**Causes:**
- Image not pulled yet
- Subuid/subgid not configured
- Wrong image URI (localhost vs registry.local:5000)

**Fix:**
```bash
# Check if subuid/subgid configured
sudo workloadctl verify <workload>

# If missing, re-run user setup
sudo /usr/libexec/workloadctl/workload-ensure-user <name>

# For pull=never images, pull manually
sudo -u _wl-<name> \
  -E XDG_RUNTIME_DIR=/run/user/$(id -u _wl-<name>) \
  podman pull registry.local:5000/<image>:latest

# Then restart workload
sudo workloadctl restart <workload>
```

### 2. Permission denied errors

**Symptoms:**
- `permission denied` when accessing files/devices
- Container can't write to mounted volumes

**Causes:**
- Volume directories don't exist
- Wrong file ownership (especially with userns=host)
- Missing group memberships

**Fix:**
```bash
# Check volume paths exist
sudo workloadctl verify <workload>

# Create missing directories
sudo mkdir -p /var/lib/workloads/<name>/<subdir>

# For userns=host: Check UID mapping
sudo workloadctl uid-map <workload>

# Fix ownership using the mapped UID shown by uid-map command
# Example: Container UID 1000 → Host UID (subuid_start + 999)
# If subuid_start=100000, then: 100000 + 999 = 100999
sudo chown -R <mapped-uid>:<mapped-gid> /var/lib/workloads/<name>/
```

### 3. Service not starting

**Symptoms:**
- `systemctl status` shows service failed
- No container running

**Causes:**
- User not created
- Linger not enabled
- Service file not generated

**Fix:**
```bash
# Run full enable process
sudo workloadctl disable <workload>
sudo systemctl daemon-reload
sudo workloadctl enable <workload>

# Check if user exists
id _wl-<name>

# Check if linger enabled
ls /var/lib/systemd/linger/_wl-<name>

# Enable linger if missing
sudo loginctl enable-linger $(id -u _wl-<name>)
```

### 4. Configuration changes not applied

**Symptoms:**
- Changed TOML file but service still uses old settings
- Container arguments unchanged

**Causes:**
- Systemd not reloaded
- Service not restarted
- Need to disable/enable cycle

**Fix:**
```bash
# For most changes: reload and restart
sudo systemctl daemon-reload
sudo workloadctl restart <workload>

# For structural changes (ID, name, network mode): disable/enable
sudo workloadctl disable <workload>
sudo systemctl daemon-reload
sudo workloadctl enable <workload>
```

### 5. Network issues

**Symptoms:**
- Can't access ports
- Network timeout
- `bind: address already in use`

**Causes:**
- Port conflict
- Wrong network mode
- Firewall blocking

**Fix:**
```bash
# Check what ports are configured
sudo workloadctl ports <workload>

# Check if port is already in use
sudo ss -tlnp | grep :<port>

# For pasta mode, ensure Podman 5.3+
podman --version

# Check firewall (if using host mode)
sudo firewall-cmd --list-all
```

### 6. UID mapping confusion (userns=host)

**Symptoms:**
- Files owned by unexpected UIDs (high numbers like 100000+)
- Permission denied even with correct container UID

**Explanation:**
With `userns=host`, container UIDs are shifted by the workload's subuid range:
- Container UID N → Host UID (subuid_start + N - 1)
- Example: Container UID 1000 → Host UID 100999 (if subuid_start=100000)

**Fix:**
```bash
# Check UID mapping
sudo workloadctl uid-map <workload>

# This will show the formula and example mappings
# Follow the chown command shown in the output
```

### 7. SSH auth failures (for SSH-based workloads)

**Symptoms:**
- `Permission denied (publickey)`
- SSH connects but auth fails

**Causes:**
- Wrong file ownership on .ssh directory
- Incorrect UID mapping with userns=host

**Fix:**
```bash
# For userns=host workloads with SSH:
# 1. Calculate the mapped UID
sudo workloadctl uid-map <workload>

# 2. Fix ownership of .ssh directory
# Example: borgbackup with container UID 1000 → host UID shown by uid-map
sudo chown -R <mapped-uid>:<mapped-gid> /var/lib/workloads/borgbackup/.ssh
sudo chmod 700 /var/lib/workloads/borgbackup/.ssh
sudo chmod 600 /var/lib/workloads/borgbackup/.ssh/authorized_keys
```

### 8. Systemd service inside container fails

**Symptoms:**
- `Failed to set up mount namespacing: Permission denied`
- `Failed to set RLIMIT_CORE: Operation not permitted`

**Causes:**
- Missing capabilities (SYS_ADMIN, SYS_RESOURCE, etc.)
- Wrong userns mode for systemd (need userns=host)

**Fix:**
```toml
# In workload TOML config:
[security]
userns = "host"

capabilities = [
    "SYS_ADMIN",     # For systemd namespace setup
    "SYS_RESOURCE",  # For setting resource limits
    "SETUID",        # For user switching
    "SETGID",        # For group switching
    # Add others as needed
]
```

Then regenerate and restart:
```bash
sudo workloadctl disable <workload>
sudo systemctl daemon-reload
sudo workloadctl enable <workload>
```

### 9. Syscall blocked by seccomp profile

**Symptoms:**
- `Operation not permitted` in logs at startup
- Container exits immediately with code 1 (not 125/126 — this is the application, not podman)
- Error message references a specific operation: `ptrace: Operation not permitted`, `bpf: Operation not permitted`, etc.
- Workload starts fine with `seccomp=unconfined` but fails normally

**Cause:**
All workloads run with a hardened seccomp profile (`/usr/share/containers/seccomp-workload-baseline.json`) that blocks syscalls commonly used in container escapes and side-channel attacks. Most services never call these syscalls, but some applications (debuggers, eBPF tools, performance profilers) do.

The blocked syscalls are: `ptrace`, `bpf`, `perf_event_open`, `process_vm_readv`, `process_vm_writev`, `keyctl`.

**Confirm seccomp is the cause:**
```bash
# Test with seccomp disabled - if it starts, seccomp is blocking something
sudo -u _wl-<name> \
  -E XDG_RUNTIME_DIR=/run/user/$(id -u _wl-<name>) \
  podman run --rm --security-opt seccomp=unconfined <image>
```

**Fix — use the system default (less strict):**
```toml
[security]
security_opt = ["seccomp=/usr/share/containers/seccomp.json"]
```

**Fix — disable seccomp entirely (not recommended):**
```toml
[security]
security_opt = ["seccomp=unconfined"]
```

**Fix — use a custom profile:**
```toml
[security]
security_opt = ["seccomp=/etc/containers/my-custom-profile.json"]
```

Then apply the change:
```bash
sudo systemctl daemon-reload
sudo workloadctl restart <workload>
```

### 10. Container exits immediately (code 125/126)

**Symptoms:**
- Service starts then immediately fails
- journalctl shows `Main process exited, code=exited, status=125`

**Causes:**
- Podman error during container startup
- Image not found
- Invalid command/entrypoint
- Missing dependencies

**Fix:**
```bash
# Check detailed logs
sudo journalctl -u workload-<name>.service -n 100

# Try running container manually to see full error
sudo -u _wl-<name> \
  -E XDG_RUNTIME_DIR=/run/user/$(id -u _wl-<name>) \
  podman run --rm <image> <command>

# Common fixes:
# - Pull image if missing
# - Fix command syntax in TOML
# - Add required volumes or devices
```

## Viewing Logs

All container logs are sent to the systemd journal using the journald log driver. This provides powerful querying and filtering capabilities.

### Basic log viewing

```bash
# View all logs for a workload (service + container)
sudo journalctl -u workload-<name>.service

# View only container logs (excludes systemd service messages)
sudo journalctl CONTAINER_NAME=workload-<name>

# Follow logs in real-time
sudo journalctl -fu workload-<name>.service
sudo journalctl -f CONTAINER_NAME=workload-<name>

# Last N lines
sudo journalctl -u workload-<name>.service -n 50

# Since a specific time
sudo journalctl -u workload-<name>.service --since "1 hour ago"
sudo journalctl -u workload-<name>.service --since "2024-01-01 10:00:00"
```

### Advanced log queries

```bash
# Combine service and container filters
sudo journalctl -u workload-squid.service CONTAINER_NAME=workload-squid

# Search for specific text
sudo journalctl CONTAINER_NAME=workload-squid | grep "ERROR"

# Show with extra metadata
sudo journalctl -u workload-squid.service -o verbose

# Show in JSON format
sudo journalctl -u workload-squid.service -o json-pretty

# Export to file
sudo journalctl -u workload-squid.service > /tmp/workload.log
```

### For systemd containers

Containers running systemd inside (like borgbackup) have their internal journal entries forwarded to the host:

```bash
# View sshd logs from inside borgbackup container
sudo journalctl CONTAINER_NAME=workload-borgbackup | grep sshd

# View all systemd messages from inside container
sudo journalctl CONTAINER_NAME=workload-borgbackup | grep systemd

# Combine with time filters
sudo journalctl CONTAINER_NAME=workload-borgbackup --since "10 minutes ago" | grep sshd
```

### Using podman logs (alternative)

You can also use podman's logs command directly:

```bash
# Get workload user and UID
WORKLOAD_USER="_wl-<name>"
WORKLOAD_UID=$(id -u $WORKLOAD_USER)

# View logs
sudo -u $WORKLOAD_USER \
  -E XDG_RUNTIME_DIR=/run/user/$WORKLOAD_UID \
  podman logs workload-<name>

# Follow logs
sudo -u $WORKLOAD_USER \
  -E XDG_RUNTIME_DIR=/run/user/$WORKLOAD_UID \
  podman logs -f workload-<name>

# Last 50 lines
sudo -u $WORKLOAD_USER \
  -E XDG_RUNTIME_DIR=/run/user/$WORKLOAD_UID \
  podman logs --tail 50 workload-<name>
```

Note: `journalctl` is generally preferred as it integrates service lifecycle events (restarts, failures) with container logs.

## Debugging Techniques

### 1. Run container manually
```bash
# Get workload user and UID
WORKLOAD_USER="_wl-<name>"
WORKLOAD_UID=$(id -u $WORKLOAD_USER)

# Run container interactively
sudo -u $WORKLOAD_USER \
  -E XDG_RUNTIME_DIR=/run/user/$WORKLOAD_UID \
  podman run --rm -it <image> /bin/sh
```

### 2. Check UID mapping
```bash
# Inside container (with podman unshare)
sudo -u $WORKLOAD_USER \
  -E XDG_RUNTIME_DIR=/run/user/$WORKLOAD_UID \
  podman unshare cat /proc/self/uid_map
```

### 3. Examine generated service file
```bash
# View the generated systemd service
cat /run/systemd/generator/workload-<name>.service

# Check what podman command is actually run
systemctl cat workload-<name>.service
```

### 4. Monitor in real-time
```bash
# Follow logs in real-time
sudo journalctl -fu workload-<name>.service

# Watch service status
watch -n 1 'systemctl status workload-<name>.service'
```

## Typical Workflow

When enabling a new workload, expect this sequence:

1. **Edit TOML config** - Set image, ports, volumes, etc.
2. **Validate** - `workloadctl validate <workload>`
3. **Enable** - `workloadctl enable <workload>`
   - Creates user via systemd-sysusers
   - Runs workload-ensure-user to configure subuid/subgid
   - Enables linger
   - Starts service
4. **Verify** - `workloadctl verify <workload>`
5. **Monitor** - `workloadctl logs -f <workload>`

If it fails:
1. **Check logs** - `journalctl -u workload-<name>.service -n 50`
2. **Verify setup** - `workloadctl verify <workload>`
3. **Fix issues** - Follow suggestions from verify command
4. **Restart** - `workloadctl restart <workload>` (or disable/enable if needed)

## Reference

### User namespace modes

| Mode | Container root | Isolation | Use case |
|------|----------------|-----------|----------|
| `keep-id` | Maps to workload user | Maximum | Default, most secure |
| `host` | Maps to subuid range | Reduced | Systemd containers, complex UID requirements |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean exit |
| 125 | Podman error (wrong command, missing image, etc.) |
| 126 | Container command not executable |
| 127 | Container command not found |
| 130 | Killed by Ctrl+C (SIGINT) |
| 137 | Killed by SIGKILL |
| 143 | Killed by SIGTERM |

### File locations

| Path | Purpose |
|------|---------|
| `/etc/workloads.d/*.toml` | Workload configs |
| `/run/systemd/generator/workload-*.service` | Generated service files (temporary) |
| `/run/sysusers.d/workload-*.conf` | Generated sysusers configs |
| `/var/lib/workloads/<name>/` | Default home directory |
| `/run/workload-env/workload-*.env` | EnvironmentFiles with XDG_RUNTIME_DIR |
| `/run/user/<uid>/` | Runtime directory (requires linger) |
| `/etc/subuid` `/etc/subgid` | UID/GID mapping ranges |
| `/var/lib/systemd/linger/<user>` | Linger enabled marker |
| `/usr/share/containers/seccomp-workload-baseline.json` | Hardened seccomp profile (applied by default) |
| `/usr/share/containers/seccomp.json` | Podman default seccomp profile (less strict) |

### Useful commands

```bash
# User management
id _wl-<name>                          # Check if user exists
grep _wl-<name> /etc/subuid /etc/subgid  # Check UID/GID ranges
loginctl show-user _wl-<name>          # Show user session info

# Service management
systemctl status workload-<name>       # Service status
systemctl restart workload-<name>      # Restart service
systemctl daemon-reload                      # Reload after config changes

# Podman operations (as workload user)
sudo -u _wl-<name> -E XDG_RUNTIME_DIR=/run/user/<uid> podman ps
sudo -u _wl-<name> -E XDG_RUNTIME_DIR=/run/user/<uid> podman images
sudo -u _wl-<name> -E XDG_RUNTIME_DIR=/run/user/<uid> podman logs <container>
sudo -u _wl-<name> -E XDG_RUNTIME_DIR=/run/user/<uid> podman system migrate

# Debugging
journalctl -u workload-<name> -n 100   # View recent logs
systemctl cat workload-<name>          # View service file
dmesg | grep workload-generator              # Check generator logs
```
