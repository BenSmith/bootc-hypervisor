# workloadctl Command Reference

`workloadctl` is the CLI for managing rootless workloads. Most commands that mutate state require `sudo`; read-only commands can be run as any user.

## Global Options

```
workloadctl [-h] <command> [options]
```

---

## Targeting a Container in a Multi-Container Workload

A workload may run more than one container (see [Multi-Container Workloads](workloads.md#multi-container-workloads)). Commands that operate on a container — `exec`, `shell`, `logs`, `health` — accept either the workload alone or a `<workload>/<container>` reference:

```bash
workloadctl logs   myapp           # merged logs from every container
workloadctl logs   myapp/web       # just the "web" container
workloadctl exec   myapp/db psql   # exec into a specific container
workloadctl shell  myapp/proxy     # shell in a specific container
workloadctl health myapp           # per-container health table
```

For multi-container workloads, `exec` and `shell` **require** the `<workload>/<container>` form — a bare `<workload>` errors and lists the available containers. `logs` and `health` accept both forms.

Lifecycle commands (`enable`, `disable`, `start`, `stop`, `recreate`, `reboot`, `update`, `rollback`) always operate on the whole workload. For **container** workloads, `update` pulls every container's image and `rollback` reverts them all. For **VM** workloads, `update` rebuilds the system disk from its image source and `rollback` restores the previous disk generation. `status`, `info`, `stats`, `cp` likewise take a bare workload name.

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

Soft-reboot a workload: re-executes systemd (PID 1) and restarts all services inside the guest without destroying its disk. Useful for picking up config changes made inside the workload.

```
sudo workloadctl reboot <workload>
```

**Container workloads:** runs `systemctl soft-reboot` in the container (overlay preserved). Only works with systemd containers (`container.systemd` set).

**VM workloads:** runs the same `systemctl soft-reboot` inside the guest over SSH (the disk is preserved). Requires the VM to be reachable (see `exec`/`shell` IP resolution).

Requires systemd 254+ inside the guest.

---

### `recreate`

Apply a TOML edit (or rebuild a workload). This re-runs the per-workload unit generator, reloads systemd, and restarts the service.

```
sudo workloadctl recreate <workload>
```

**Container workloads:** this **destroys the container overlay**, so any state written inside the container is lost.

**VM workloads:** this also restarts the setup oneshot (`workload-<name>-setup.service`) so the cloud-init seed is re-rendered from the current TOML — `[vm.cloud_init].template_vars`, volumes, etc. — before QEMU reboots onto the fresh ISO. The system disk and data disk are preserved. (Restarting only the main VM service would **not** rebuild the seed, because the setup oneshot is `RemainAfterExit=yes` and doesn't re-run on a plain restart.)

Use this whenever you change a workload's TOML and want the change to take effect. A plain `systemctl daemon-reload && systemctl restart workload-NAME.service` is **not** equivalent — daemon-reload only re-runs the systemd shell-generator (which emits a oneshot that won't fire until next boot), so the unit file content keeps its previous values. Inlined fields like `[container.environment]`, `[security.extra_groups]`, resource limits, and image references all need `recreate` to take effect.

Values that flow through `EnvironmentFile=` (`XDG_RUNTIME_DIR`, `HOST_IP`, decrypted `${SECRET:...}` env vars) are re-read on each service start, so for those a plain `systemctl restart` is sufficient.

---

### `update`

Pull the latest image and restart the workload.

```
sudo workloadctl update [--force] [--all] [<workload>]
```

| Option | Description |
|---|---|
| `--force` | Restart even if the image hasn't changed |
| `--all` | Update all enabled workloads (skips `pull=never` containers) |

**Container workloads:** Pulls the latest image, restarts, then monitors health checks (or service liveness) and automatically rolls back on failure. With `--all`, all workloads are pulled and restarted first, then verified in a single wait period.

**VM workloads:** Rebuilds `system.qcow2` from the configured image source, rotating the old disk to `system.qcow2.gen-N` for rollback. The VM is restarted after the new disk is ready. `--force` has no effect on VM workloads (disk is always rebuilt). `--all` includes VM workloads; a VM whose rebuild or restart fails is reported in the summary and makes the command exit nonzero (other workloads still run).

For `cloud_image_url`, the downloaded image is cached at `.image-cache/<filename>` and keyed by `cloud_image_checksum`. `update` only re-downloads when the cached file fails its checksum or is missing — to pull a newer upstream image, update both `cloud_image_url` and `cloud_image_checksum` in the config first.

> **No auto-rollback for VMs.** Unlike container updates, a VM update does not verify guest health after restart and does not auto-rollback on failure. If the new disk fails to boot, restore the previous generation manually with `sudo workloadctl rollback <name>`.

---

### `rollback`

Roll back a workload to its previous image or disk generation.

```
sudo workloadctl rollback [--list] <workload>
```

| Option | Description |
|---|---|
| `--list` | List the available rollback targets instead of rolling back |

**Container workloads:** Restores the image saved during the last `update` (tagged as `localhost/workload-rollback/<name>:latest`) and restarts the service. Exits with an error if no rollback image exists.

**VM workloads:** Restores the latest `system.qcow2.gen-N` saved during the last `update` and restarts the VM. `vm.rollback_keep` (default 2) is the number of *older* generations retained beyond the one created by the current update, so `rollback_keep + 1` generations are kept in total (default: 3). Exits with an error if no generation exists. A `pet` VM never rotates `system.qcow2`, so it has no generations to roll back to.

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

Show detailed workload information: config, user, UID, subuid/subgid ranges, home directory, image, ports, volumes.

```
workloadctl info [--json] <workload>
```

### `logs`

View workload logs via `journalctl`.

```
workloadctl logs [-f] [-n N] [--since TIME] <workload>[/<container>] [extra journalctl args]
```

| Option | Description |
|---|---|
| `-f` / `--follow` | Stream live log output |
| `-n N` / `--lines N` | Show last N lines |
| `--since TIME` | Show logs since TIME (journalctl format, e.g., `"1 hour ago"`) |

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
workloadctl health [--json] <workload>[/<container>]
```

### `images`

List or prune container images for workload users.

```
workloadctl images [--json] [list|prune]
```

---

## Container Access Commands

### `shell`

Open an interactive shell inside the running workload.

```
sudo workloadctl shell <workload>[/<container>] [--console]
```

**Container workloads:** Enters the running container. If `CONTAINER_USER` or `CONTAINER_UID` is set in `[container.environment]`, the shell runs as that user; otherwise it enters as root. For multi-container workloads, the `/<container>` suffix is required.

**VM workloads:** Connects over SSH by default (same path as `exec`), so the guest tty inherits the host terminal's window size and signal handling. Falls back to the QEMU serial console via `socat` if the VM has no IP yet or SSH can't connect — press `Ctrl+]` to detach from the console. Pass `--console` to skip the SSH attempt and go straight to the serial console, which is the right tool when the VM is broken enough that the network is unreachable.

### `exec`

Execute a command inside the running workload.

```
workloadctl exec <workload>[/<container>] <command> [args...]
```

**Container workloads:** Runs the command inside the container. For multi-container workloads, the `/<container>` suffix is required.

**VM workloads:** Runs the command over SSH using the per-workload key at `/var/lib/workloads/<name>/.ssh/id_ed25519`. The guest IP is resolved from the DHCP lease file. The guest user defaults to `vm.user` from the workload config (or `root`).

**Examples:**
```bash
workloadctl exec webserver nginx -t
workloadctl exec myapp/db psql -U app
workloadctl exec fedora-vm -- dnf upgrade -y
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

### `incant`

Run a raw command against the workload's runtime **control plane** as the owning identity, with the fiddly invocation supplied for you. This is an escape hatch — it bypasses the declarative TOML → units model, so prefer the purpose-built verbs (`update`, `rollback`, `shell`, `exec`, …) when they cover your use case.

```
workloadctl incant <workload>[/<container>] -- <command> [args...]
```

**Container workloads:** runs `podman <command>` as the owning `_wl-<name>` user with the correct rootless environment (`XDG_RUNTIME_DIR`/session bus) — you never hand-build the `sudo … podman` invocation yourself. This replaces the old `network create` verb.

**VM workloads:** sends a QMP command to the QEMU monitor. The first token after `--` is the QMP command name; additional `key=value` tokens become the arguments dict. The JSON reply is printed.

> **Note:** `incant` reaches the *manager* of the runtime (podman / the QEMU monitor), not the workload interior. To run a command *inside* the workload, use `exec`/`shell`.

**Examples:**
```bash
workloadctl incant webproxy -- network create mynet
workloadctl incant webproxy -- volume ls
workloadctl incant git -- query-status        # VM: QMP command
workloadctl incant git -- system_powerdown     # VM: QMP command
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

### `diagnose`

Diagnose a workload's runtime setup: user exists, subuid/subgid configured, linger active, SELinux label correct.

```
workloadctl diagnose [--json] <workload>
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
sudo workloadctl backup [--json] [--all] [--output PATH] [--consistency {cold,crash}] [<workload>]
```

| Option | Description |
|---|---|
| `--all` | Back up all enabled workloads |
| `--output PATH` | Directory to write archive(s) to (default: current directory) |
| `--consistency {cold,crash}` | Consistency level (default `cold`). `cold` stops the service, copies, then restarts — always safe. `crash` copies without stopping the service: for VMs the vCPUs are paused via QMP for the copy (crash-consistent, resume-safe); for containers the rootfs/volumes are copied live (may be inconsistent). |
| `--json` | Output archive paths and sizes as JSON instead of printing progress |

VM backups exclude rebuildable artifacts (`system.qcow2`, `system.qcow2.gen-N`, `*.image-cache`) — only the durable disk and home are archived.

### `restore`

Restore a workload from a backup archive created by `backup`.

```
sudo workloadctl restore <archive>
```

> **DR caveat — secrets are host-bound.** A backup archives the encrypted
> credential blobs from `/etc/credstore` but not the unlock material. Secrets
> are sealed to this host (TPM2 binding, or `/var/lib/systemd/credential.secret`
> for the host-key fallback). An in-place restore on the same machine decrypts
> normally; a restore on different hardware — or after a TPM reset — cannot
> decrypt them. For cross-host DR, also preserve `/var/lib/systemd/credential.secret`
> (host-key case), or re-encrypt the affected secrets on the target with
> `workloadctl secret`.

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
