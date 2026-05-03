# workloadctl Command Reference

`workloadctl` is the CLI for managing rootless workloads. Most commands that mutate state require `sudo`; read-only commands can be run as any user.

## Global Options

```
workloadctl [-h] <command> [options]
```

---

## Lifecycle Commands

### `create`

Generate a new workload config file at `/etc/workloads.d/<name>.toml`.

```
workloadctl create <name> --image IMAGE [OPTIONS]
```

| Argument | Description |
|---|---|
| `name` | Workload name: lowercase letters, numbers, hyphens, max 27 chars |
| `--image IMAGE` | Container image (required) |
| `--gpu {amd,nvidia,none}` | GPU type for hardware acceleration |
| `--groups GROUP ...` | Additional system groups (e.g., `video render audio kvm`) |
| `--ports PORT ...` | Port mappings (e.g., `8080:80 8443:443`) |
| `--network MODE` | Network mode: `pasta` (default), `host`, `none`, or a custom network name |
| `--volumes VOL ...` | Volume mounts (e.g., `/host/path:/container/path:ro`) |
| `--device DEVICE ...` | Generic device passthrough (e.g., `/dev/ttyUSB0`) |
| `--input` | Enable input devices (`/dev/input` + `/dev/uinput`) |
| `--audio` | Enable audio (`/dev/snd` + auto-mount PulseAudio/PipeWire sockets) |
| `--virtualization` | Enable KVM (`/dev/kvm` + vhost devices) |
| `--systemd {always,true,false}` | Systemd container mode (skips `--init`, adds `KillSignal`) |
| `--shm-size SIZE` | Shared memory size (e.g., `256m`, `2g`; default: `64m`) |
| `--cpu-quota PERCENT` | CPU quota (e.g., `50%`, `200%` for 2 cores) |
| `--cpu-weight WEIGHT` | CPU scheduling weight (1–10000, default 100) |
| `--memory-max SIZE` | Hard memory limit (e.g., `512M`, `2G`) |
| `--memory-high SIZE` | Soft memory limit for throttling (e.g., `1.5G`) |
| `--memory-swap-max SIZE` | Swap limit (`0` to disable) |
| `--io-weight WEIGHT` | I/O scheduling weight (1–10000, default 100) |
| `--tasks-max NUM` | Maximum number of tasks/threads |
| `--enable` | Enable and start the workload immediately after creating the config |

**Example:**
```bash
sudo workloadctl create webserver \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --ports 8080:8080 \
  --memory-max 256M \
  --enable
```

See also: [Manual TOML approach](workloads.md#manual-toml) and [bootc approach](workloads.md#bootc-approach).

---

### `enable`

Run preflight checks, create the workload user, set up subuid/linger, transfer the image if needed, and start the service.

```
sudo workloadctl enable <workload>
```

This is idempotent — safe to re-run if a previous enable was interrupted.

---

### `disable`

Stop the workload service and set `enabled = false` in its config.

```
sudo workloadctl disable [--purge] <workload>
```

| Option | Description |
|---|---|
| `--purge` | Also delete the workload user, home directory, and subuid/subgid entries |

---

### `reboot`

Soft-reboot a systemd container: re-executes systemd (PID 1) and restarts all services inside the container without destroying the overlay filesystem. Useful for picking up config changes made inside the container.

```
sudo workloadctl reboot <workload>
```

Only works with systemd containers (`container.systemd` set). Requires systemd 254+ inside the container.

---

### `recreate`

Recreate a workload container from its image. This **destroys the overlay** — any changes made inside the container are lost.

```
sudo workloadctl recreate <workload>
```

---

### `update`

Pull the latest image and restart the workload. After restarting, monitors health checks (or service liveness for workloads without health checks) and automatically rolls back on failure.

```
sudo workloadctl update [--force] [--all] [<workload>]
```

| Option | Description |
|---|---|
| `--force` | Restart even if the image hasn't changed |
| `--all` | Update all enabled workloads (skips `pull=never`) |

With `--all`, all workloads are pulled and restarted first, then verified in a single wait period. Workloads that fail verification are automatically rolled back.

---

### `rollback`

Roll back a workload to its previous image (saved during the last `update`).

```
sudo workloadctl rollback <workload>
```

The rollback image is tagged during `update` as `localhost/workload-rollback/<name>:latest`. If no rollback image exists, the command exits with an error.

---

### `edit`

Open the workload's TOML config in `$EDITOR`, validate after saving, and apply changes via `daemon-reload`.

```
sudo workloadctl edit <workload>
```

Restores the previous config if validation fails.

---

## Introspection Commands

### `list`

List all workloads and their enabled/running state.

```
workloadctl list [--json]
```

### `status`

Show the systemd service status for a workload.

```
workloadctl status [--json] <workload>
```

| Option | Description |
|---|---|
| `--json` | Output state, PID, memory, and timestamps as JSON |

### `info`

Show detailed workload information: config, user, UID, home directory, image, ports, volumes.

```
workloadctl info [--json] <workload>
```

### `logs`

View workload logs via `journalctl`.

```
workloadctl logs [-f] [-n N] [--since TIME] <workload> [extra journalctl args]
```

| Option | Description |
|---|---|
| `-f` / `--follow` | Stream live log output |
| `-n N` / `--lines N` | Show last N lines |
| `--since TIME` | Show logs since TIME (journalctl format, e.g., `"1 hour ago"`) |

### `ps`

Show all currently running workload containers.

```
workloadctl ps [--json]
```

### `ports`

Show port mappings for a workload.

```
workloadctl ports [--json] <workload>
```

### `stats`

Show live resource usage (CPU, memory, I/O) for a workload or all workloads.

```
workloadctl stats [--json] [-f] [<workload>]
```

| Option | Description |
|---|---|
| `-f` / `--follow` | Keep updating (live view); incompatible with `--json` |
| `--json` | Output raw numeric stats as JSON |

### `health`

Check the health status of a workload container.

```
workloadctl health [--json] <workload>
```

### `images`

List or prune container images for workload users.

```
workloadctl images [--json] [list|prune]
```

### `uid-map`

Show the UID/GID mapping for a workload (host UID → container UID via user namespace).

```
workloadctl uid-map [--json] <workload>
```

| Option | Description |
|---|---|
| `--json` | Output host UIDs, subuid ranges, and mapped container UIDs as JSON |

---

## Container Access Commands

### `shell`

Open an interactive shell inside the running workload container.

```
sudo workloadctl shell <workload>
```

If the workload config defines `CONTAINER_USER` or `CONTAINER_UID` in `[container.environment]`, the shell runs as that user in their home directory. Otherwise it enters as root.

### `exec`

Execute a command inside the running workload container.

```
workloadctl exec <workload> <command> [args...]
```

**Example:**
```bash
workloadctl exec webserver nginx -t
```

### `attach`

Attach to the container's main process (stdin/stdout/stderr).

```
workloadctl attach <workload>
```

### `cp`

Copy files to or from a running workload container.

```
workloadctl cp <source> <destination>
```

Use `workload:path` syntax for container paths:

```bash
workloadctl cp webserver:/etc/nginx/nginx.conf ./nginx.conf
workloadctl cp ./nginx.conf webserver:/etc/nginx/nginx.conf
```

---

## Validation & Diagnostics

### `validate`

Validate a workload's TOML configuration for syntax and semantic errors.

```
workloadctl validate [--all] [--json] [<workload>]
```

| Option | Description |
|---|---|
| `--all` | Validate all workload configs |
| `--json` | Output results as JSON |

### `verify`

Verify a workload's runtime setup: user exists, subuid configured, linger active, image present, service file generated.

```
workloadctl verify [--json] <workload>
```

| Option | Description |
|---|---|
| `--json` | Output per-check results as JSON; exit non-zero if any check failed |

Useful for diagnosing a workload that fails to start.

### `cleanup`

Find (and optionally remove) orphaned workload users and home directories — system users in the `_wl-*` range whose config file no longer exists.

```
sudo workloadctl cleanup [--apply] [--json]
```

| Option | Description |
|---|---|
| `--apply` | Actually remove orphans (default is dry-run) |
| `--json` | Output orphan lists and removal results as JSON |

---

## Data Management

### `backup`

Archive a workload's home directory and config to a compressed tarball (`.tar.zst`).

```
sudo workloadctl backup [--json] [--all] [--output PATH] [--no-stop] [<workload>]
```

| Option | Description |
|---|---|
| `--all` | Back up all enabled workloads |
| `--output PATH` | Directory to write archive(s) to (default: current directory) |
| `--no-stop` | Skip stopping the workload before archiving (may produce inconsistent data) |
| `--json` | Output archive paths and sizes as JSON instead of printing progress |

### `restore`

Restore a workload from a backup archive created by `backup`.

```
sudo workloadctl restore <archive>
```

---

## Networking

### `network create`

Create a named podman network for use with `network.mode` in a workload config.

```
sudo workloadctl network create <network-name> <workload>
```

---

## Secret Management

Manage encrypted systemd credentials in `/etc/credstore.encrypted/`. See [secrets.md](secrets.md) for full details.

```
workloadctl secret {create,list,show,rotate,delete,export,import}
```

### `secret create`

Encrypt a new credential and store it in `/etc/credstore.encrypted/`.

```
sudo workloadctl secret create [--key-type {tpm2,host,host+tpm2}] [--file FILE] [--force] <name>
```

Interactive prompt to create secret:
```
systemd-ask-password -n | sudo systemd-creds encrypt --with-key=host --name=KRDP_PASSWORD - /etc/credstore.encrypted/KRDP_PASSWORD
```

| Option | Description |
|---|---|
| `--key-type` | Encryption key type (default: `tpm2`) |
| `--file FILE` | Read secret from a file instead of stdin |
| `--force` | Overwrite if the credential already exists |

Reads from stdin if `--file` is not given.

**Example:**
```bash
echo -n "my-api-key" | sudo workloadctl secret create --key-type tpm2 myapp-api-key
```

### `secret list`

List all credentials in `/etc/credstore.encrypted/`.

```
workloadctl secret list [--json]
```

| Option | Description |
|---|---|
| `--json` | Output credential names, sizes, and modification timestamps as JSON |

### `secret show`

Decrypt and print a credential's value to stdout.

```
sudo workloadctl secret show <name>
```

### `secret rotate`

Replace a credential's encrypted value (re-reads from stdin) and restart any workloads that reference it.

```
sudo workloadctl secret rotate [--key-type {tpm2,host,host+tpm2}] <name>
```

### `secret delete`

Delete an encrypted credential file.

```
sudo workloadctl secret delete [--force] <name>
```

| Option | Description |
|---|---|
| `--force` | Skip confirmation prompt |

### `secret export`

Export an encrypted credential as a passphrase-protected portable file (`.secret`). The exported file is not TPM-bound and can be transferred to another machine.

```
sudo workloadctl secret export [--output FILE] <name>
```

| Option | Description |
|---|---|
| `--output FILE` | Output path (default: `./<name>.secret`) |

### `secret import`

Import a previously exported `.secret` file and re-encrypt it as a local credential.

```
sudo workloadctl secret import [--force] [--key-type {tpm2,host,host+tpm2}] <name> <file>
```

| Option | Description |
|---|---|
| `--force` | Overwrite if the credential already exists |
| `--key-type` | Encryption key type for the new credential (default: `tpm2`) |
