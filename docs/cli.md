# workload-ctl Command Reference

`workload-ctl` is the CLI for managing rootless workloads. Most commands that mutate state require `sudo`; read-only commands can be run as any user.

## Global Options

```
workload-ctl [-h] <command> [options]
```

---

## Lifecycle Commands

### `create`

Generate a new workload config file at `/etc/workloads.d/<name>.toml`.

```
workload-ctl create <name> --image IMAGE [OPTIONS]
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
sudo workload-ctl create webserver \
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
sudo workload-ctl enable <workload>
```

This is idempotent — safe to re-run if a previous enable was interrupted.

---

### `disable`

Stop the workload service and set `enabled = false` in its config.

```
sudo workload-ctl disable [--purge] <workload>
```

| Option | Description |
|---|---|
| `--purge` | Also delete the workload user, home directory, and subuid/subgid entries |

---

### `restart`

Restart a running workload's systemd service.

```
sudo workload-ctl restart <workload>
```

---

### `update`

Pull the latest image and restart the workload. After restarting, monitors health checks (or service liveness for workloads without health checks) and automatically rolls back on failure.

```
sudo workload-ctl update [--force] [--all] [<workload>]
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
sudo workload-ctl rollback <workload>
```

The rollback image is tagged during `update` as `localhost/workload-rollback/<name>:latest`. If no rollback image exists, the command exits with an error.

---

### `edit`

Open the workload's TOML config in `$EDITOR`, validate after saving, and apply changes via `daemon-reload`.

```
sudo workload-ctl edit <workload>
```

Restores the previous config if validation fails.

---

## Introspection Commands

### `list`

List all workloads and their enabled/running state.

```
workload-ctl list [--json]
```

### `status`

Show the systemd service status for a workload.

```
workload-ctl status <workload>
```

### `info`

Show detailed workload information: config, user, UID, home directory, image, ports, volumes.

```
workload-ctl info [--json] <workload>
```

### `logs`

View workload logs via `journalctl`.

```
workload-ctl logs [-f] [-n N] [--since TIME] <workload> [extra journalctl args]
```

| Option | Description |
|---|---|
| `-f` / `--follow` | Stream live log output |
| `-n N` / `--lines N` | Show last N lines |
| `--since TIME` | Show logs since TIME (journalctl format, e.g., `"1 hour ago"`) |

### `ps`

Show all currently running workload containers.

```
workload-ctl ps [--json]
```

### `ports`

Show port mappings for a workload.

```
workload-ctl ports [--json] <workload>
```

### `stats`

Show live resource usage (CPU, memory, I/O) for a workload or all workloads.

```
workload-ctl stats [-f] [<workload>]
```

| Option | Description |
|---|---|
| `-f` / `--follow` | Keep updating (live view) |

### `health`

Check the health status of a workload container.

```
workload-ctl health [--json] <workload>
```

### `images`

List or prune container images for workload users.

```
workload-ctl images [--json] [list|prune]
```

### `uid-map`

Show the UID/GID mapping for a workload (host UID → container UID via user namespace).

```
workload-ctl uid-map <workload>
```

---

## Container Access Commands

### `shell`

Open an interactive shell inside the running workload container.

```
sudo workload-ctl shell <workload>
```

If the workload config defines `CONTAINER_USER` or `CONTAINER_UID` in `[container.environment]`, the shell runs as that user in their home directory. Otherwise it enters as root.

### `exec`

Execute a command inside the running workload container.

```
workload-ctl exec <workload> <command> [args...]
```

**Example:**
```bash
workload-ctl exec webserver nginx -t
```

### `attach`

Attach to the container's main process (stdin/stdout/stderr).

```
workload-ctl attach <workload>
```

### `cp`

Copy files to or from a running workload container.

```
workload-ctl cp <source> <destination>
```

Use `workload:path` syntax for container paths:

```bash
workload-ctl cp webserver:/etc/nginx/nginx.conf ./nginx.conf
workload-ctl cp ./nginx.conf webserver:/etc/nginx/nginx.conf
```

---

## Validation & Diagnostics

### `validate`

Validate a workload's TOML configuration for syntax and semantic errors.

```
workload-ctl validate [--all] [--json] [<workload>]
```

| Option | Description |
|---|---|
| `--all` | Validate all workload configs |
| `--json` | Output results as JSON |

### `verify`

Verify a workload's runtime setup: user exists, subuid configured, linger active, image present, service file generated.

```
workload-ctl verify <workload>
```

Useful for diagnosing a workload that fails to start.

### `cleanup`

Find (and optionally remove) orphaned workload users and home directories — system users in the `_wl-*` range whose config file no longer exists.

```
sudo workload-ctl cleanup [--apply]
```

| Option | Description |
|---|---|
| `--apply` | Actually remove orphans (default is dry-run) |

---

## Networking

### `network create`

Create a named podman network for use with `network.mode` in a workload config.

```
sudo workload-ctl network create <network-name> <workload>
```

---

## Secret Management

Manage encrypted systemd credentials in `/etc/credstore.encrypted/`. See [secrets.md](secrets.md) for full details.

```
workload-ctl secret {create,list,show,rotate,delete,export,import}
```

### `secret create`

Encrypt a new credential and store it in `/etc/credstore.encrypted/`.

```
sudo workload-ctl secret create [--key-type {tpm2,host,host+tpm2}] [--file FILE] [--force] <name>
```

| Option | Description |
|---|---|
| `--key-type` | Encryption key type (default: `tpm2`) |
| `--file FILE` | Read secret from a file instead of stdin |
| `--force` | Overwrite if the credential already exists |

Reads from stdin if `--file` is not given.

**Example:**
```bash
echo -n "my-api-key" | sudo workload-ctl secret create --key-type tpm2 myapp-api-key
```

### `secret list`

List all credentials in `/etc/credstore.encrypted/`.

```
workload-ctl secret list
```

### `secret show`

Decrypt and print a credential's value to stdout.

```
sudo workload-ctl secret show <name>
```

### `secret rotate`

Replace a credential's encrypted value (re-reads from stdin) and restart any workloads that reference it.

```
sudo workload-ctl secret rotate [--key-type {tpm2,host,host+tpm2}] <name>
```

### `secret delete`

Delete an encrypted credential file.

```
sudo workload-ctl secret delete [--force] <name>
```

| Option | Description |
|---|---|
| `--force` | Skip confirmation prompt |

### `secret export`

Export an encrypted credential as a passphrase-protected portable file (`.secret`). The exported file is not TPM-bound and can be transferred to another machine.

```
sudo workload-ctl secret export [--output FILE] <name>
```

| Option | Description |
|---|---|
| `--output FILE` | Output path (default: `./<name>.secret`) |

### `secret import`

Import a previously exported `.secret` file and re-encrypt it as a local credential.

```
sudo workload-ctl secret import [--force] [--key-type {tpm2,host,host+tpm2}] <name> <file>
```

| Option | Description |
|---|---|
| `--force` | Overwrite if the credential already exists |
| `--key-type` | Encryption key type for the new credential (default: `tpm2`) |
