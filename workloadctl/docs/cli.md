# workloadctl Command Reference

`workloadctl` is the CLI for managing rootless workloads. Most commands that mutate state require `sudo`; read-only commands can be run as any user.

## Commands

| Command | Description |
|---|---|
| [`backup`](#backup) | Archive a workload's `data/` subtree to a `.tar.zst` |
| [`build`](#build) | Build a workload's container image from its bundle build context |
| [`catalog`](#catalog) | List shippable bundles |
| [`cleanup`](#cleanup) | Find (and optionally remove) orphaned `_wl-*` users and home directories |
| [`cp`](#cp) | Copy files to/from a running container |
| [`create`](#create) | Scaffold a from-scratch workload TOML (no bundle) |
| [`diagnose`](#diagnose) | Check runtime setup: user, subuid/subgid, linger, SELinux label |
| [`disable`](#disable) | Stop the service and remove the `.enabled` marker (optionally `--purge`) |
| [`drift`](#drift) | Diff running systemd units against what would be generated from current TOMLs |
| [`duplicate`](#duplicate-alias-clone) / `clone` | Copy a live workload's TOML under a new name |
| [`edit`](#edit) | Edit the workload TOML, or copy-on-write override a bundle control file |
| [`enable`](#enable) | Create user, transfer image, start service (idempotent) |
| [`exec`](#exec) | Run a command inside a container or VM (via SSH) |
| [`health`](#health) | Show container health check status |
| [`images`](#images) | List or prune container images across workload users |
| [`incant`](#incant) | Raw podman command as the workload user, or QMP command for VMs |
| [`info`](#info) | Show config, user, UID, image, ports, volumes (`--files` for control-file view) |
| [`init`](#init) | Instantiate a catalog bundle into `/etc/workloads.d/` |
| [`install`](#install) | Promote a local workload directory into `/etc/workloads.d/` |
| [`list`](#list) | List all workloads and their enabled/running state |
| [`logs`](#logs) | View workload logs via `journalctl` |
| [`reboot`](#reboot) | Soft-reboot a workload (systemd re-exec inside container or VM) |
| [`recreate`](#recreate) | Regenerate units and restart (apply TOML edits or post-build) |
| [`restart`](#restart) | Bounce a workload service, keeping its overlay/disk (does not apply TOML edits) |
| [`restore`](#restore) | Restore a workload from a `backup` archive (optionally `--force`, `--enable`) |
| [`rollback`](#rollback) | Revert to the previous container image or VM disk generation |
| [`secret`](#secret-management) | Manage encrypted systemd credentials (subcommands: `create list show rotate delete export import`) |
| [`shell`](#shell) | Open an interactive shell in a container or VM (SSH or serial console) |
| [`start`](#start) | Start a workload service without changing its `enabled` state |
| [`stats`](#stats) | Show live CPU/memory/I/O usage |
| [`status`](#status) | Show systemd service status |
| [`stop`](#stop) | Stop a workload service without changing its `enabled` state |
| [`update`](#update) | Pull the latest image (or rebuild VM disk) and restart with auto-rollback |
| [`validate`](#validate) | Validate a workload TOML for syntax and semantic errors |

---

## Global Options

```
workloadctl [-h] <command> [options]
```

---

## Output Options on Mutating Commands

`build`, `disable`, `enable`, `reboot`, `recreate`, `restart`, `rollback`,
`start`, `stop` and `update` each take two output flags. They are offered only
on these verbs because only these verbs *narrate* — the read/report commands
(`list`, `status`, `drift`, …) print output rather than progress, and have
carried their own `--json` for a long time.

| Flag | Effect |
|------|--------|
| `-q`, `--quiet` | Drop the progress narration. Warnings and errors still print, on stderr — `--quiet` silences the commentary, never a failure. |
| `--json` | Print a JSON result object on stdout instead of the narration, so `workloadctl update --all --json \| jq` is safe. |

Progress goes to stdout, warnings and errors to stderr, so the two survive a
redirect (`workloadctl update --all >run.log 2>errors.log`).

A command's *output* — a `--dry-run` plan, `rollback --list`'s targets — is not
narration and is never suppressed: with `--quiet` it still prints, and with
`--json` it moves into the result object.

### The result object

Every mutating verb reports the same shape, so a script can treat them alike:

```console
$ sudo workloadctl update --all --json
{
  "command": "update",
  "ok": true,
  "workloads": [
    {
      "workload": "web",
      "kind": "container",
      "result": "updated",
      "images": {
        "web": {
          "image": "docker.io/library/nginx:alpine",
          "old": "sha256:1f2e3d4c5b6a",
          "new": "sha256:9a8b7c6d5e4f"
        }
      },
      "verify": "healthy"
    },
    {
      "workload": "cache",
      "kind": "container",
      "result": "rolled-back",
      "verify": "crashed"
    },
    {
      "workload": "builder",
      "kind": "container",
      "result": "skipped",
      "reason": "builder uses pull=never (local image) — build it manually"
    }
  ],
  "summary": {
    "updated": 1, "rolled-back": 1, "skipped": 1, "failed": 0, "unchanged": 0
  }
}
```

- `ok` is the command's overall verdict, and tracks the exit code. A rollback is
  a *handled* outcome, not a failure: auto-rollback working as designed leaves
  `ok: true` and exit 0. A failed pull, or a VM rebuild that didn't come back,
  gives `ok: false` and exit 1.
- `result` per workload is one of `enabled`, `already-running`, `disabled`,
  `purged`, `started`, `stopped`, `restarted`, `rebooted`, `recreated`, `built`,
  `updated`, `unchanged`, `skipped`, `failed`, `rolled-back`, `listed`, or
  `dry-run`.
- `reason` explains a `skipped` or `failed` row; `verify` carries the
  post-restart health verdict; `images` the per-container old→new image IDs.
- `summary` (update only) counts the rows by result.
- A command that dies before it can report — bad arguments, not root, an
  unexpected crash — still emits the document, with `ok: false` and an `error`
  string. The human-readable diagnostic is on stderr, as always.

---

## The Operations Log

Every command that changes a workload appends one JSON object per touched
workload to `/var/lib/workloads/<name>/operations.log`, whether or not you passed
`--json`. It answers the question the journal can't: not *that* someone ran
`workloadctl update web` — `sudo` already logs that — but what the update
actually did.

That covers the lifecycle verbs (`enable`, `disable`, `start`, `stop`,
`restart`, `recreate`, `reboot`, `build`, `update`, `rollback`) and the ones that
author or rewrite a workload (`create`, `init`, `duplicate`, `install`, `edit`,
`backup`, `restore`, `cp` *into* a workload). Two stay out by design: `secret`,
whose credstore is host-global and belongs to no single workload, and `cleanup`,
which reaps orphans — workloads whose config is already gone, leaving nothing to
own the record.

```console
$ sudo tail -1 /var/lib/workloads/web/operations.log | jq
{
  "ts": "2026-07-13T18:04:22Z",
  "command": "update",
  "ok": true,
  "user": "ben",
  "user_source": "login",
  "workload": "web",
  "kind": "container",
  "result": "rolled-back",
  "verify": "crashed",
  "images": {
    "web": {
      "image": "docker.io/library/nginx:alpine",
      "old": "sha256:1f2e3d4c5b6a",
      "new": "sha256:9a8b7c6d5e4f"
    }
  }
}
```

Each line is the `--json` result row plus `ts`, `command`, `ok`, `user` and
`user_source` — the same dict, so the log and `--json` cannot drift apart.

`user_source` says how much to trust `user`:

| Source | Means | Notes |
|--------|-------|-------|
| `login` | The kernel's audit loginuid (`/proc/self/loginuid`) | The human who logged in, even several privilege hops later. Survives `su -`, which `SUDO_USER` does not, and is the one field here that userspace cannot forge. |
| `sudo` | `$SUDO_USER` | Fallback when the kernel has no audit support. Just an environment variable, so spoofable — which costs nothing, since root can rewrite this file anyway. |
| `system` | No login session at all | A systemd unit, a timer, cron. Distinguishing this from a person at a root console is why `loginuid` is consulted first. |

- **It is a record, not an audit trail.** Only root can run these verbs, and
  root can equally edit or delete the file. It is not tamper-evident and is not
  offered as a security control.
- **It lives beside the workload**, not in a host-global file. Lines lead with a
  UTC timestamp, so `cat /var/lib/workloads/*/operations.log | sort` still gives
  a host-wide timeline.
- **Backup skips it.** Only `data/` is captured, so a restore doesn't import
  another host's history into a fresh workload.
- **`disable --purge` deletes it** along with the rest of the workload
  directory. The workload is gone; its history goes with it.
- **Nothing that changed nothing is recorded.** Dry-runs and reports
  (`--dry-run`, `rollback --list`), and — this is the one that matters — an
  `update` that found the image already current. `update --all` is the verb most
  likely to be on a timer, and a quiet fleet must leave the log exactly as it
  found it rather than burying its own history under one "nothing happened" line
  per workload per run.
- **Writing is best-effort.** If the workload doesn't exist at all, the command
  warns on stderr and carries on. A log line that didn't land is never why an
  operation fails.

There is no rotation, and with no-ops excluded it doesn't need one: a line per
*real* change is a few kilobytes a year.

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

Lifecycle commands (`enable`, `disable`, `start`, `stop`, `restart`, `recreate`, `reboot`, `update`, `rollback`) always operate on the whole workload. For **container** workloads, `update` pulls every container's image and `rollback` reverts them all. For **VM** workloads, `update` rebuilds the system disk from its image source and `rollback` restores the previous disk generation. `status`, `info`, `stats`, `cp` likewise take a bare workload name.

---

## Bundle Commands

Shipped workloads live as **bundles** under `/usr/share/workloadctl/workloads/<bundle>/`,
each co-locating a template `workload.toml` with its control files (Containerfile,
`build.sh`, `setup.sh`, `policy.cil`, cloud-init seed). These verbs turn a bundle —
or an existing workload — into a new authoritative declaration in `/etc/workloads.d/`.
Control files are **not** copied: the new TOML's resolved `bundle` falls through to
the shared `/usr` tree until you override something.

### `catalog`

List shippable bundles.

```
workloadctl catalog [--json]
```

[↑ top](#workloadctl-command-reference)

### `init`

Instantiate a catalog bundle into `/etc/workloads.d/<name>/workload.toml`.

```
sudo workloadctl init <bundle> [--as <name>]
sudo workloadctl init --scratch <name>
```

Stamps the bundle's template `workload.toml` at `/etc/workloads.d/<name>/workload.toml`.
Control files (Containerfile, `setup.sh`, `policy.cil`, …) are **not** copied —
they're resolved from `/usr/share/workloadctl/workloads/<bundle>/` at build/enable
time and automatically inherit package upgrades. Use `workloadctl edit <name> <file>`
to override individual control files copy-on-write.

`--as` names the instance (default: the bundle name). When the instance name diverges
from the bundle, `init` records `[workload] bundle = "<bundle>"` so the new TOML's
control-file lookups still resolve to the source bundle's tree.

See [Bundle-based approach](workloads.md#bundle-approach) for typical workflows.

`--scratch <name>` creates a self-contained stub with no bundle backing — for novel
workloads that aren't shipped as bundles. The generated TOML has no `bundle` field and
resolves all control files from `/etc/workloads.d/<name>/` only. Mutually exclusive
with the `<bundle>` positional.

[↑ top](#workloadctl-command-reference)

### `duplicate` (alias `clone`)

Copy a live workload's declaration under a new name.

```
sudo workloadctl duplicate <source> <new>
```

The copy's `[workload] bundle` is set to the source's **resolved** bundle
(`source.bundle or source.name`), so a duplicate-of-a-duplicate still points at the
original `/usr` bundle. Name uniqueness is the only hard requirement; `duplicate`
**lints** (warns, never blocks) on host-global settings a verbatim copy inherits —
published host ports, absolute volume paths, and a mutable image tag shared with
another enabled workload — which you resolve by editing the copy before enabling it.

[↑ top](#workloadctl-command-reference)

### `install`

Promote a local workload directory into `/etc/workloads.d/<name>/`. The
destination name is derived from `[workload].name` in the source `workload.toml`,
not the source directory name.

```
sudo workloadctl install <src>
```

| Argument | Description |
|---|---|
| `src` | Path to a directory containing `workload.toml` |

The entire directory is copied (`.git` and `__pycache__` excluded, file modes
preserved). Errors if a workload with that name already exists in
`/etc/workloads.d/`. The source directory is never modified.

[↑ top](#workloadctl-command-reference)

### `create`

Scaffold a from-scratch workload config (no bundle) at `/etc/workloads.d/<name>/workload.toml`.

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

[↑ top](#workloadctl-command-reference)

---

### `build`

Build a container workload's image from its bundle build context — the **merged**
`/usr` bundle tree with any `/etc/workloads.d/<name>/` overrides laid on top, so an
overridden `Containerfile` (or a `COPY`-ed asset) actually takes effect. Runs as
root, building into root's store; `enable`/`recreate` then transfer the resulting
`pull = never` image to the workload user.

```
sudo workloadctl build <workload>
```

Applies to **container** workloads only (VMs provision via `update`/`recreate`). The
built image is tagged exactly as `[container].image`, so a `pull = never` container
always matches what was built — there is no separate build tag to drift out of sync.
What gets built is driven by the optional `[build]` section (see
[schema-reference.toml](schema-reference.toml)): the built-in `podman build` of the
merged context by default, or an escape-hatch `[build].script` run against that same
context. A workload that pulls a published image has nothing to build and says so.

Typical override-and-rebuild flow: `init` → `edit <name> Containerfile` → `build` →
`recreate` (if already enabled) or `enable`.

[↑ top](#workloadctl-command-reference)

---

### `enable`

Run preflight checks, create the workload's `.enabled` marker (`/etc/workloads.d/<name>/.enabled`, which is what tells the generator to emit its units), create the workload user, set up subuid/linger, transfer the image if needed, and start the service.

```
sudo workloadctl enable <workload>
```

This is idempotent — safe to re-run if a previous enable was interrupted.

[↑ top](#workloadctl-command-reference)

---

### `disable`

Stop the workload service and remove its `.enabled` marker (`/etc/workloads.d/<name>/.enabled`), so the generator stops emitting its units.

```
sudo workloadctl disable [--purge] [--dry-run] <workload>
```

| Option | Description |
|---|---|
| `--purge` | Also delete the workload user, home directory, and subuid/subgid entries |
| `--dry-run` | Print the teardown plan and exit without changing anything |

`--dry-run` enumerates exactly what teardown would touch — the units it would stop, the generated unit files it would remove, and (with `--purge`) the subuid/subgid entries, the user, and the data directory with its size. It reports only what is actually present, so anything it doesn't list, `disable` won't touch.

[↑ top](#workloadctl-command-reference)

---

### `start`

Start a workload service without changing its `enabled` state.

```
sudo workloadctl start <workload>
```

[↑ top](#workloadctl-command-reference)

---

### `stop`

Stop a workload service without changing its `enabled` state.

```
sudo workloadctl stop <workload>
```

[↑ top](#workloadctl-command-reference)

---

### `restart`

Bounce a workload service without changing its `enabled` state.

```
sudo workloadctl restart <workload>
```

This restarts the workload's main unit and nothing else. **Container workloads:** the container overlay is preserved. **VM workloads:** the system and data disks and the existing cloud-init seed are preserved — QEMU is power-cycled onto them.

`restart` does **not** apply TOML edits: the unit files are not regenerated and the VM's cloud-init seed is not re-rendered. Use [`recreate`](#recreate) for that.

[↑ top](#workloadctl-command-reference)

---

### `reboot`

Soft-reboot a workload: re-executes systemd (PID 1) and restarts all services inside the guest without destroying its disk. Useful for picking up config changes made inside the workload.

```
sudo workloadctl reboot <workload>
```

**Container workloads:** runs `systemctl soft-reboot` in the container (overlay preserved). Only works with systemd containers (`container.systemd` set).

**VM workloads:** runs the same `systemctl soft-reboot` inside the guest over SSH (the disk is preserved). Requires the VM to be reachable (see `exec`/`shell` IP resolution).

Requires systemd 254+ inside the guest.

[↑ top](#workloadctl-command-reference)

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

[↑ top](#workloadctl-command-reference)

---

### `update`

Pull the latest image and restart the workload.

```
sudo workloadctl update [--force] [--all] [--dry-run] [<workload>]
```

| Option | Description |
|---|---|
| `--force` | Restart even if the image hasn't changed |
| `--all` | Update all enabled workloads (skips `pull=never` containers) |
| `--dry-run` | Print what would be pulled and restarted, without changing anything |

`--dry-run` names the images it would pull (with the image ID each would roll back to), the workloads it would skip as `pull=never`, and the services it would restart. It does not contact the registry, so it reports the plan rather than predicting whether a pull would actually find a new image.

**Container workloads:** Pulls the latest image, restarts, then monitors health checks (or service liveness) and automatically rolls back on failure. With `--all`, all workloads are pulled and restarted first, then verified in a single wait period.

**VM workloads:** Rebuilds `system.qcow2` from the configured image source, rotating the old disk to `system.qcow2.gen-N` for rollback. The VM is restarted after the new disk is ready. `--force` has no effect on VM workloads (disk is always rebuilt). `--all` includes VM workloads; a VM whose rebuild or restart fails is reported in the summary and makes the command exit nonzero (other workloads still run).

For `cloud_image_url`, the downloaded image is cached at `.image-cache/<filename>` and keyed by `cloud_image_checksum`. `update` only re-downloads when the cached file fails its checksum or is missing — to pull a newer upstream image, update both `cloud_image_url` and `cloud_image_checksum` in the config first.

> **No auto-rollback for VMs.** Unlike container updates, a VM update does not verify guest health after restart and does not auto-rollback on failure. If the new disk fails to boot, restore the previous generation manually with `sudo workloadctl rollback <name>`.

[↑ top](#workloadctl-command-reference)

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

[↑ top](#workloadctl-command-reference)

---

### `edit`

Two modes, selected by whether you name a control file.

**Edit the workload TOML** (no file argument) — opens the config in `$EDITOR`,
validates after saving, shows a diff, and (when the workload is enabled) offers to
apply the change by regenerating units and restarting. Restores the previous config
if validation fails.

```
sudo workloadctl edit [-y] <workload>
```

| Option | Description |
|---|---|
| `-y` / `--yes` | Apply changes without the interactive confirmation prompt |

**Edit a bundle control file** (`<file>` argument) — the copy-on-write override
ergonomic, mirroring systemd's `systemctl edit`. Seeds `/etc/workloads.d/<name>/<file>`
from the shipped `/usr` default (or an empty file if the bundle ships none), opens it
in `$EDITOR`, then keeps the override **only if you actually changed it** — an edit
byte-identical to the default, or an untouched empty new file, is discarded so it
never freezes upgrade-tracking. Once kept, the override wins control-file resolution
for `build`/`enable`/`recreate`. Nested paths (e.g. `rootfs/Containerfile`) are
allowed; traversal and symlink escapes are rejected.

```
sudo workloadctl edit <workload> <file>
```

Use `info --files` to see what can be overridden, `build`/`recreate` to apply it,
and revert to the shipped default by deleting the override:
`sudo rm /etc/workloads.d/<name>/<file>`.

[↑ top](#workloadctl-command-reference)

---

## Introspection Commands

### `list`

List all workloads and their enabled/running state.

```
workloadctl list [--json]
```

[↑ top](#workloadctl-command-reference)

### `status`

Show the systemd service status for a workload.

```
workloadctl status [--json] <workload>
```

| Option | Description |
|---|---|
| `--json` | Output state, PID, memory, and timestamps as JSON |

[↑ top](#workloadctl-command-reference)

### `info`

Show detailed workload information: config, user, UID, subuid/subgid ranges, home directory, image, ports, volumes.

```
workloadctl info [--json] <workload>
workloadctl info --files [--json] <workload>
```

| Option | Description |
|---|---|
| `--files` | Show the **merged control-file view** instead: every control file (Containerfile, `setup.sh`, `policy.cil`, …) from the shipped `/usr` bundle, unioned with any `/etc/workloads.d/<name>/` overrides — each tagged with its winning source: `override` (your `/etc` copy), `shipped` (the `/usr` default), or `missing` (declared but absent). The `systemctl cat` analogue for bundle control files; nested paths are shown. Edit any of them with `edit <workload> <file>`. |
| `--json` | Output as JSON |

[↑ top](#workloadctl-command-reference)

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

[↑ top](#workloadctl-command-reference)

### `stats`

Show live resource usage (CPU, memory, I/O) for a workload or all workloads.

```
workloadctl stats [--json] [-f] [<workload>]
```

| Option | Description |
|---|---|
| `-f` / `--follow` | Keep updating (live view); incompatible with `--json` and with VM workloads |
| `--json` | Output raw numeric stats as JSON |

**Container workloads** are measured with `podman stats`. **VM workloads** are measured over QEMU's read-only QMP monitor: CPU percent is derived from the vCPU thread times sampled twice, memory from the guest's balloon against the configured `[vm] memory`. A VM reports `null` for network and block I/O — QEMU is not asked for them, and a zero would read as an idle disk rather than as a gap.

[↑ top](#workloadctl-command-reference)

### `health`

Check the health status of a workload container.

```
workloadctl health [--json] <workload>[/<container>]
```

[↑ top](#workloadctl-command-reference)

### `images`

List or prune container images for workload users.

```
workloadctl images [--json] [list|prune]
```

[↑ top](#workloadctl-command-reference)

---

## Container Access Commands

### `shell`

Open an interactive shell inside the running workload.

```
sudo workloadctl shell <workload>[/<container>] [--console]
```

**Container workloads:** Enters the running container. If `CONTAINER_USER` or `CONTAINER_UID` is set in `[container.environment]`, the shell runs as that user; otherwise it enters as root. For multi-container workloads, the `/<container>` suffix is required.

**VM workloads:** Connects over SSH by default (same path as `exec`), so the guest tty inherits the host terminal's window size and signal handling. Falls back to the QEMU serial console via `socat` if the VM has no IP yet or SSH can't connect — press `Ctrl+]` to detach from the console. Pass `--console` to skip the SSH attempt and go straight to the serial console, which is the right tool when the VM is broken enough that the network is unreachable.

[↑ top](#workloadctl-command-reference)

### `exec`

Execute a command inside the running workload.

```
workloadctl exec <workload>[/<container>] <command> [args...]
```

**Container workloads:** Runs the command inside the container. For multi-container workloads, the `/<container>` suffix is required.

**VM workloads:** Runs the command over SSH using the per-workload key at `/var/lib/workloads/<name>/.ssh/id_ed25519`. The guest user defaults to `vm.user` from the workload config (or `root`).

Under passt — the default — the guest has no address of its own to resolve: it is assigned the *host's* address, and `exec`/`shell` reach it on the workload's own management address (`127.128.x.y`, derived from the uid).

On an operator-provided `[vm.network].bridge` the guest does have its own LAN address, and the host infers it from three sources, in descending order of authority:

1. **qemu-guest-agent**, over the `org.qemu.guest_agent.0` virtio-serial channel every VM is wired with. The guest's own answer, so it never goes stale — install and enable `qemu-guest-agent` in the guest to get it. Only the interface carrying the MAC workloadctl assigned the VM is trusted; a guest reports its podman/docker bridges and VPN tunnels too, and those are not addresses the host can reach.
2. **The host neighbour table**, matched on the VM's derived MAC. Passive — it only lists a guest the host has talked to recently, so a healthy but idle VM can drop out of it.
3. **mDNS** (`<name>.local`), when the host has avahi/nss-mdns wired up.

If none resolve, `workloadctl shell <name>` still reaches the serial console.

Both substrates pass the command as argv, not as a shell line: the arguments you write are the arguments the process receives, with no second round of word-splitting inside the guest. Shell syntax therefore needs an explicit shell, exactly as it does for a container:

```bash
workloadctl exec fedora-vm -- sh -c 'dnf list --installed | wc -l'
```

**Examples:**
```bash
workloadctl exec webserver nginx -t
workloadctl exec myapp/db psql -U app
workloadctl exec fedora-vm -- dnf upgrade -y
```

[↑ top](#workloadctl-command-reference)

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

[↑ top](#workloadctl-command-reference)

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

[↑ top](#workloadctl-command-reference)

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

[↑ top](#workloadctl-command-reference)

### `diagnose`

Diagnose a workload's runtime setup: user exists, subuid/subgid configured, linger active, SELinux label correct.

```
workloadctl diagnose [--json] <workload>
```

| Option | Description |
|---|---|
| `--json` | Output per-check results as JSON; exit non-zero if any check failed |

Useful for diagnosing a workload that fails to start.

**VM workloads get a narrower battery.** The subuid/subgid, linger, user-session,
`/run/user/<uid>` and container-running checks describe how a *container*
workload runs; a VM uses no user namespaces and its QEMU is a system service with
its own runtime directory, so `workload-ensure-user` skips those setup steps for
`[vm]` bundles and `diagnose`/`doctor` skip the matching checks. What remains —
identity, home directory, unit files and service state — applies to both
substrates.

**Subid range checks.** Beyond "subuid/subgid configured", two checks assert the
range is the *right* one. `subid_derived` compares it against the derived range
for the workload's UID. `subid_overlap` fails if it starts below `SUB_UID_MAX`
from `/etc/login.defs`, i.e. inside the window `useradd` allocates from; it is
omitted entirely — not passed — when `/etc/login.defs` cannot be read.

`useradd` reads `/etc/subuid` and skips ranges already listed there, so a range
inside the window is not an imminent collision. The exposure runs the other way:
nothing stops *workloadctl* writing over a range a human user already holds, so
what keeps the two apart is the derivation placing workload ranges above the
window at all. That makes `subid_derived` the load-bearing check, and the
residual `subid_overlap` covers is ordering — a workload provisioned after a
colliding range, or a rollback booting an `/etc/subuid` that never listed it.

Neither can self-heal: `workload-ensure-user` grandfathers an existing entry on
purpose, because shifting a UID mapping under a running container corrupts its
namespace. Remap by hand with the workload stopped, and `chown` only `state/` —
`data/` is owned by the workload UID itself, not out of the subordinate range.

**Trust anchor check.** `ca_trust_anchors` fails when a certificate in
`/etc/pki/ca-trust/source/anchors` is absent from the extracted TLS bundle —
the anchor is installed but grants no trust, so pulls from a registry it signs
fail `unable to get local issuer certificate` while the trust store looks
correct. Run for container workloads only, and omitted rather than passed when
the store cannot be read.

On a bootc host the usual cause is the ostree `/etc` merge: `update-ca-trust`
writes into `/etc/pki/ca-trust/extracted/`, so a host that has ever run it by
hand has that path marked locally modified and keeps its own copy forever,
discarding the image's extraction. New anchor *files* still land; nothing
extracts them.

The fix depends on whether any anchor is locally added. When they all come from
the image, restoring `extracted/` from `/usr/etc` is preferred over
`update-ca-trust` — it brings `ostree admin config-diff` clean, so the merge
tracks the image again and later anchor rotations apply by themselves. When the
host carries a hand-added anchor, the check names `update-ca-trust` instead:
restoring would drop that anchor from the bundle and revoke trust the operator
installed deliberately.

[↑ top](#workloadctl-command-reference)

### `cleanup`

Find (and optionally remove) orphaned workload users and home directories — system users in the `_wl-*` range whose config file no longer exists.

```
sudo workloadctl cleanup [--apply] [--json]
```

| Option | Description |
|---|---|
| `--apply` | Actually remove orphans (default is dry-run) |
| `--json` | Output orphan lists and removal results as JSON |

**Rollback safety.** On a bootc host `/etc` is per-deployment and `/var` is shared,
so `bootc rollback` takes a workload's config, `_wl-*` user and subuid range away
while its `/var/lib/workloads/<name>` tree stays behind — which fits this
command's definition of an orphan exactly, without the state being orphaned at
all. Each workload root therefore carries a `provenance.json` naming the
deployment that last provisioned it (written by `workload-ensure-user`, so it
appears on the workload's first start). State stamped with a deployment that
still exists but is not the booted one is listed under **"State from another
deployment — not swept"** and left alone; boot that deployment and
`disable --purge` there to remove it for good. State stamped with the booted
deployment, with a deployment that has since been pruned, or with no stamp at
all (anything predating this, and any non-bootc host) is treated exactly as
before. See [ADR 005](adr/005-var-state-deployment-provenance.md) for why the
marker records *last provisioned* rather than *created*, and what is deliberately
left out of it.

[↑ top](#workloadctl-command-reference)

---

### `drift`

Diff running systemd units against what would be generated from the current TOMLs. Outputs nothing if units are in sync; exits 1 if drift is detected. Read-only — no changes are applied.

```
workloadctl drift [--json] [<workload>]
```

| Option | Description |
|---|---|
| `<workload>` | Filter to units belonging to a specific workload (default: all workloads) |
| `--json` | Output diff as JSON instead of unified diff text |

Useful after editing a TOML without running `recreate`, or to verify that the running units match the current config after a `bootc upgrade`.

[↑ top](#workloadctl-command-reference)

---

## Data Management

### `backup`

Archive a workload's precious `data/` subtree, referenced credentials, and config to a compressed tarball (`.tar.zst`).

```
sudo workloadctl backup [--json] [--all] [--output PATH] [--consistency {cold,crash}] [<workload>]
```

| Option | Description |
|---|---|
| `--all` | Back up all enabled workloads |
| `--output PATH` | Directory to write archive(s) to (default: current directory) |
| `--consistency {cold,crash}` | Consistency level (default `cold`). `cold` stops the service, copies, then restarts — always safe. `crash` copies without stopping the service: for VMs the vCPUs are paused via QMP for the copy (crash-consistent, resume-safe); for containers the rootfs/volumes are copied live (may be inconsistent). |
| `--json` | Output archive paths and sizes as JSON instead of printing progress |

**Backup stops at mount points.** Anything mounted inside `data/` — a network
share, a second disk, a bind mount — is skipped, with a warning naming each path,
because capturing it would pull a whole foreign filesystem into the archive and
`restore` would refuse to write it back. Whatever owns the mount owns its backup.
See [Mounts under `data/` are not captured](workloads.md#mounts-under-data-are-not-captured).

A backup captures **only the precious `data/` subtree** (for every substrate). The reconstructible `state/` subtree — podman graphroot, container images, and a VM's `system.qcow2` (+ `system.qcow2.gen-N`, `*.image-cache`) — is deliberately excluded and rebuilt on `enable`/`update`. For VMs this means the durable `data.qcow2` is archived but the OS disk is not: a **`pet` VM's in-place changes to `system.qcow2` are not recoverable from a backup** (a `pet` VM never rotates its system disk, so it also has no generation to roll back to). Bake durable VM state into a `data.qcow2` volume, or into the guest image, rather than the system disk.

[↑ top](#workloadctl-command-reference)

### `restore`

Restore a workload from a backup archive created by `backup`.

```
sudo workloadctl restore [--force] [--enable] <archive>
```

| Option | Description |
|---|---|
| `--force` | Overwrite existing config, credentials, and home directory if they exist |
| `--enable` | Enable the workload immediately after restoring |

> **Restore refuses to run over a mounted `data/`.** If anything is mounted
> under the data directory — or if `data/` is itself a mount — the command stops
> and names the path, on both paths and not just `--force`. Unmounting is a
> deliberate operator action, and a half-replaced `data/` is worse than a restore
> that declined to start: `--force` empties the target first, so following a
> mount would delete the mounted filesystem's contents (for a bind mount, the
> original directory's) and only then fail on the busy mount point. Without
> `--force` nothing is deleted, but the merge would write *through* the mount.
> See [Mounts under `data/` are not captured](workloads.md#mounts-under-data-are-not-captured).

> **DR caveat — secrets are host-bound.** A backup archives the encrypted
> credential blobs from `/etc/credstore` but not the unlock material. Secrets
> are sealed to this host (TPM2 binding, or `/var/lib/systemd/credential.secret`
> for the host-key fallback). An in-place restore on the same machine decrypts
> normally; a restore on different hardware — or after a TPM reset — cannot
> decrypt them. For cross-host DR, also preserve `/var/lib/systemd/credential.secret`
> (host-key case), or re-encrypt the affected secrets on the target with
> `workloadctl secret`.

[↑ top](#workloadctl-command-reference)

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

[↑ top](#workloadctl-command-reference)

### `secret list`

List all credentials in `/etc/credstore.encrypted/`.

```
workloadctl secret list [--json]
```

| Option | Description |
|---|---|
| `--json` | Output credential names, sizes, and modification timestamps as JSON |

[↑ top](#workloadctl-command-reference)

### `secret show`

Decrypt and print a credential's value to stdout.

```
sudo workloadctl secret show <name>
```

[↑ top](#workloadctl-command-reference)

### `secret rotate`

Replace a credential's encrypted value (re-reads from stdin) and restart any workloads that reference it.

```
sudo workloadctl secret rotate [--key-type {tpm2,host,host+tpm2}] <name>
```

[↑ top](#workloadctl-command-reference)

### `secret delete`

Delete an encrypted credential file.

```
sudo workloadctl secret delete [--force] <name>
```

| Option | Description |
|---|---|
| `--force` | Skip confirmation prompt |

[↑ top](#workloadctl-command-reference)

### `secret export`

Export an encrypted credential as a passphrase-protected portable file (`.secret`). The exported file is not TPM-bound and can be transferred to another machine.

The blob uses a versioned format (v2): AES-256-CBC with PBKDF2 (600,000 iterations) plus an HMAC-SHA256 integrity tag, so a tampered or truncated file is detected on import. `secret import` still reads legacy v1 exports (see [ADR 004](adr/004-secret-export-versioned-crypto.md)).

```
sudo workloadctl secret export [--output FILE] <name>
```

| Option | Description |
|---|---|
| `--output FILE` | Output path (default: `./<name>.secret`) |

[↑ top](#workloadctl-command-reference)

### `secret import`

Import a previously exported `.secret` file and re-encrypt it as a local credential.

```
sudo workloadctl secret import [--force] [--key-type {tpm2,host,host+tpm2}] <name> <file>
```

| Option | Description |
|---|---|
| `--force` | Overwrite if the credential already exists |
| `--key-type` | Encryption key type for the new credential (default: `tpm2`) |

[↑ top](#workloadctl-command-reference)
