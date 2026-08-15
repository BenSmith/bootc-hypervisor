# Workload Troubleshooting Guide

This guide covers common issues when working with the workload system and how to resolve them.

> **Supported Fedora versions and the current stable release** are defined in [`fedora-versions.yml`](../fedora-versions.yml) at the repo root. That file is the single source of truth — edit it to add a new version, promote a new stable, or drop an EOL version.

## Quick Diagnostics

### Check workload health
```bash
# Everything at once: generator log, unit states, setup checks, drift, health
sudo workloadctl doctor <workload>

# Just the runtime setup checks (user, subids, linger, SELinux)
sudo workloadctl diagnose <workload>

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

Run `workloadctl doctor` to diagnose the root cause.

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
sudo workloadctl diagnose <workload>

# If missing, re-run user setup
sudo /usr/libexec/workloadctl/workload-ensure-user <name>

# For pull=never images, pull manually
sudo -u _wl-<name> \
  -E XDG_RUNTIME_DIR=/run/user/$(id -u _wl-<name>) \
  podman pull registry.local:5000/<image>:latest

# Then restart workload
sudo workloadctl recreate <workload>
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
sudo workloadctl diagnose <workload>

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
sudo workloadctl recreate <workload>

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
sudo workloadctl recreate <workload>
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

### 11. Rootless runtime torn down (`pause.pid`, `/run/user/<uid>` missing)

**Symptoms:**
- `Error: ... unable to create a new pause process: open /run/user/10000/libpod/tmp/pause.pid: no such file or directory. Try running "/usr/bin/podman system migrate" ...`
- `error creating temporary file: No such file or directory`
- `Failed to obtain podman configuration: lstat /run/user/10000: no such file or directory`
- `Failed to add pause process to systemd sandbox cgroup: dial unix /run/user/10000/bus: connection refused`
- Service fails with `226/NAMESPACE`

**Cause:**
The workload user's runtime directory (`/run/user/<uid>`) or its user manager
(`user@<uid>.service`) is gone. Rootless podman needs both: the runtime dir holds
the pause process and libpod's temp state, and the user D-Bus on that socket is
what crun's cgroup manager talks to. Linger is what keeps them alive between
logins, so this shows up either when linger was never enabled, or — far more
often — after something tore the session down while linger was still on.

The usual cause of the second case is `loginctl terminate-user`, which removes
`/run/user/<uid>` along with the session. It is the natural-looking command and
it is the wrong one.

**Fix:**
```bash
# diagnose already knows this one — it reports it as runtime_dir / user_session
# and prints the correct command for your case
sudo workloadctl diagnose <workload>

# Session died but linger is on — restart the manager, which recreates /run/user/<uid>
sudo systemctl restart user@<uid>.service

# Linger was never enabled — this both enables it and creates the runtime dir
sudo loginctl enable-linger <uid>

# If podman still complains about stale subid mappings after the above
sudo -u _wl-<name> -E XDG_RUNTIME_DIR=/run/user/<uid> podman system migrate
```

> **Do NOT run `loginctl terminate-user`** on a workload user. It removes
> `/run/user/<uid>`, and every workload owned by that user then fails with
> `226/NAMESPACE` until the manager is restarted. `systemctl restart
> user@<uid>.service` is the operation you want in every case where you were
> reaching for it.

### 12. SELinux labels silently not applied (`semanage` lock contention)

**Symptoms:**
- Permission denied writing to the workload's own directories, with no obvious cause and nothing wrong in the config
- `workloadctl diagnose` reports `selinux_labels` failing, naming a type other than `container_file_t` (usually `var_lib_t`)
- Earlier — often at a boot days or weeks before — the journal contains:
```
workload-ensure-user: WARNING: semanage fcontext -l failed: Could not get direct read lock
    at /var/lib/selinux/targeted/semanage.read.LOCK. (Resource temporarily unavailable)
workload-ensure-user: BlockingIOError: Resource temporarily unavailable
```

**Cause:**
`workload-ensure-user` registers a persistent fcontext rule mapping
`/var/lib/workloads(/.*)?` to `container_file_t`, then runs `restorecon` over the
workload's tree. The registration takes the semanage read lock, which is
contended when several workloads enable at once or start together at boot. That
step is best-effort by design — it logs the warning above and returns rather than
failing the workload — but the `restorecon` immediately after it then runs
against a policy with no rule for that path, and applies the *default* type. The
container is subsequently denied access to its own home.

Nothing re-raises it: the warning scrolls out of the journal, and the denial
appears much later with no visible connection to the boot where the labeling was
skipped. This is why `diagnose` checks the labels themselves rather than relying
on anyone seeing the warning.

**Fix:**
```bash
# Confirm: does the rule exist, and what is the tree actually labeled?
sudo semanage fcontext -l | grep /var/lib/workloads
ls -Zd /var/lib/workloads/<name>

# Re-run the provisioning step — idempotent, and registers the rule if missing
sudo /usr/libexec/workloadctl/workload-ensure-user <name>

# Or do the two halves by hand
sudo semanage fcontext -a -t container_file_t '/var/lib/workloads(/.*)?'
sudo restorecon -R /var/lib/workloads

sudo workloadctl restart <workload>
```

Note the case where the tree is labeled correctly but the rule was never
registered: everything works until the next relabel, which resets the tree to the
default type. `diagnose` fails on this deliberately — the fix is the same
`semanage fcontext -a` above.

### 13. VM workload fails with `QMP socket not ready after 60s`

**Symptoms:**
- A VM workload will not start; the unit fails and restarts until systemd gives
  up with `Start request repeated too quickly`
- `systemctl status workload-<name>` shows:
```
Status: "Timeout waiting for QMP: QMP socket not ready after 60s: /run/workload-vm/<name>/qmp.sock"
```
- The journal shows QEMU starting each time and nothing else — no QEMU error
- Every VM workload on the host fails the same way; container workloads are fine
- **On a VM with volumes you may never see the QMP message at all.** virtiofsd
  reaches the directory before QEMU does, so the workload fails on a dependency
  instead, and the visible error is a plain DAC-looking one:
```
virtiofsd: Error creating pid file '/run/workload-vm/<name>/virtiofs-<vol>.sock.pid':
    Permission denied (os error 13)
workload-<name>.service: A dependency job for workload-<name>.service failed.
```
  Same cause, one layer earlier. The audit log names the domain that was
  actually denied — `wlvfsd_t` here, `svirt_t` for QEMU.

**Cause:**
Almost always SELinux, and nothing in the message says so. QEMU runs confined as
`svirt_t` and cannot create a socket under `/run`'s default `var_run_t`, so it
dies creating its first socket — before it ever binds QMP, which is why the only
symptom is the wrapper's timeout. Confirm with the audit log, which is where the
real evidence is:

```bash
sudo grep -a denied /var/log/audit/audit.log | grep -aE 'qemu|virtiofsd' | tail
# avc: denied { create } for comm="qemu-system-x86" name="ga.sock"
#     scontext=...:svirt_t tcontext=...:var_run_t tclass=sock_file
# avc: denied { write } for comm="virtiofsd" name="<workload>"
#     scontext=...:wlvfsd_t tcontext=...:var_run_t tclass=dir
```

The directory gets its correct type from an fcontext rule the RPM's `%post`
registers (`/run/workload-vm(/.*)? -> svirt_var_run_t`) plus the `restorecon`
that `workload-ensure-user` runs at each boot — `/run` is a tmpfs, so the
directory is recreated every time. Without the rule that relabel is a silent
no-op. A host rebuild or a failed install that drops the rule therefore breaks
every VM on the machine at the *next* boot, not at the moment the rule was lost.

Two things make it stick, and both mislead:
- **`systemctl restart` cannot fix it.** The unit sets
  `RuntimeDirectoryPreserve=yes`, so a directory that came up mislabelled
  survives every restart. The fix has to name the directory.
- **`workload-ensure-user` runs once per boot**, from
  `workload-<name>-setup.service` — not on each service start — so re-running
  the service does not re-run the relabel either.

**Fix:**
```bash
# Confirm both halves. The rule is written with the alias svirt_var_run_t;
# the kernel reports its real name, qemu_var_run_t.
sudo semanage fcontext -l -C | grep workload
sudo ls -Zd /run/workload-vm /run/workload-vm/<name>

sudo semanage fcontext -a -t svirt_var_run_t '/run/workload-vm(/.*)?'
sudo systemctl stop workload-<name>
sudo restorecon -R /run/workload-vm      # no -F: this type is not customizable
sudo systemctl daemon-reexec             # PID 1 caches file_contexts
sudo systemctl start workload-<name>
```

Then run `workloadctl diagnose <name>`. It checks this rule and the directory's
label directly (`vm_socket_dir_selinux`), and it also catches the per-workload
`svirt_image_t` rule for `/var/lib/workloads/<name>`, which is registered at
`workloadctl enable` and is lost by the same reinstall — units regenerate at
boot, so `enable` never re-runs to put it back.

Since the loss is what matters, `%post` now reports a rule that did not
register, on stderr, at install time. If you see that warning during a
`dnf install`/`upgrade`, act on it then: nothing re-runs `%post`.

## Viewing Logs

Container stdout/stderr go straight into the systemd journal via podman's passthrough log driver — each line is stored exactly once, tagged with the container name as the syslog identifier (`SyslogIdentifier=workload-<name>`, or `workload-<wl>-<ctr>` for pod/bridge member containers). Log lines read `workload-<name>[pid]: message`.

### Basic log viewing

```bash
# View all logs for a workload (service lifecycle + container output)
sudo journalctl -u workload-<name>.service

# View only container output (excludes systemd service messages)
sudo journalctl -t workload-<name>

# Follow logs in real-time
sudo journalctl -fu workload-<name>.service
sudo journalctl -ft workload-<name>

# Last N lines
sudo journalctl -u workload-<name>.service -n 50

# Since a specific time
sudo journalctl -u workload-<name>.service --since "1 hour ago"
sudo journalctl -u workload-<name>.service --since "2024-01-01 10:00:00"
```

### Advanced log queries

```bash
# Container output for one member of a multi-container workload
sudo journalctl -t workload-stack-db

# Search for specific text
sudo journalctl -t workload-squid | grep "ERROR"

# Show with extra metadata
sudo journalctl -u workload-squid.service -o verbose

# Show in JSON format
sudo journalctl -u workload-squid.service -o json-pretty

# Export to file
sudo journalctl -u workload-squid.service > /tmp/workload.log
```

### For systemd containers

Containers running systemd inside (like borgbackup) forward console output to the host journal under the same identifier:

```bash
# View sshd logs from inside borgbackup container
sudo journalctl -t workload-borgbackup | grep sshd

# View all systemd messages from inside container
sudo journalctl -t workload-borgbackup | grep systemd

# Combine with time filters
sudo journalctl -t workload-borgbackup --since "10 minutes ago" | grep sshd
```

### Why `podman logs` does not work

`podman logs` refuses to run against containers using the passthrough log driver — podman never stores its own copy of the output. Use `journalctl` (or `workloadctl logs`, which wraps it) instead; it also integrates service lifecycle events (restarts, failures) with container output.

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
4. **Verify** - `workloadctl diagnose <workload>`
5. **Monitor** - `workloadctl logs -f <workload>`

If it fails:
1. **Check logs** - `journalctl -u workload-<name>.service -n 50`
2. **Verify setup** - `workloadctl diagnose <workload>`
3. **Fix issues** - Follow the fix suggestions printed by diagnose
4. **Restart** - `workloadctl recreate <workload>` (or disable/enable if needed)

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

| Path                                                   | Purpose |
|--------------------------------------------------------|---------|
| `/etc/workloads.d/*.toml`                              | Workload configs |
| `/run/systemd/generator/workload-*.service`            | Generated service files (temporary) |
| `/run/systemd/system/workload-*.conf`                  | Generated sysusers configs |
| `/var/lib/workloads/<name>/`                           | Default home directory |
| `/run/workload-env/workload-*.env`                     | EnvironmentFiles with XDG_RUNTIME_DIR |
| `/run/user/<uid>/`                                     | Runtime directory (requires linger) |
| `/etc/subuid` `/etc/subgid`                            | UID/GID mapping ranges |
| `/var/lib/systemd/linger/<user>`                       | Linger enabled marker |
| `/usr/share/containers/seccomp-workload-baseline.json` | Hardened seccomp profile (applied by default) |
| `/usr/share/containers/seccomp.json`                   | Podman default seccomp profile (less strict) |

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
sudo -u _wl-<name> -E XDG_RUNTIME_DIR=/run/user/<uid> podman system migrate

# Debugging
journalctl -u workload-<name> -n 100   # View recent logs
systemctl cat workload-<name>          # View service file
dmesg | grep workload-generator              # Check generator logs
```
