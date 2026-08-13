# workloadctl

Declarative rootless workload manager for Linux. Define workloads as TOML files,
and workloadctl handles user creation, systemd service generation, volume
management, secrets, and lifecycle. A workload is either a **container** (rootless
podman, running as an isolated unprivileged user — the common case) or a **VM**
(KVM/QEMU, declared with a `[vm]` section); both share one TOML model and one
command surface.

## What's different about Quadlets?

Podman Quadlets generate systemd units from container specs — workloadctl goes
further by managing the full workload lifecycle:

- **Declarative TOML configs** instead of systemd unit syntax and raw podman flags
- **Automatic user isolation** — each workload gets a dedicated system user
  (`_wl-<name>`) with its own UID, subuid/subgid ranges, and rootless podman instance.
  Quadlets typically run all containers under a single user.
- **Lifecycle management** — user creation, home/volume directory setup, image
  transfer, update with automatic rollback, backup/restore, orphan cleanup
- **Hardware shortcuts** — `--gpu amd`, `--audio`, `--input`, `--virtualization`
  expand to the right devices, groups, and mounts
- **TPM2-encrypted secrets** via systemd credentials, with portable export/import
- **bootc-ready** — drop TOMLs into an image, encrypted secrets safe to commit,
  everything self-provisions on first boot

Quadlets solve "generate a systemd unit from a container spec." workloadctl
solves "declare a workload and have everything from OS user to running container
handled automatically."

## Requirements

- Fedora 43+ (or any systemd + podman 5.3+ Linux)
- Python 3.14+
- No bootc or immutable OS required (works on standard Fedora too)

## Install

From RPM (local build):

```bash
cd workloadctl
rpmbuild -bb --define "_topdir $(pwd)/rpmbuild" \
  --define "_sourcedir $(pwd)" rpm/workloadctl.spec
sudo dnf install rpmbuild/RPMS/noarch/workloadctl-*.rpm
```

## Quick start

```bash
# Create and start a workload in one command
sudo workloadctl create webserver \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --ports 8080:8080 \
  --enable

# Check status
workloadctl status webserver

# View logs
workloadctl logs webserver
```

Or write a TOML config directly:

```bash
sudo mkdir -p /etc/workloads.d/webserver
sudo tee /etc/workloads.d/webserver/workload.toml <<'EOF'
[workload]
name = "webserver"

[container]
image = "docker.io/nginxinc/nginx-unprivileged:alpine"

[network]
mode = "pasta"
ports = ["8080:8080"]
EOF

sudo workloadctl enable webserver
```

## How it works

Each workload gets:

- A dedicated locked-down system user (`_wl-<name>`)
- Its own UID/subuid namespace for rootless podman
- A systemd service generated at boot from its TOML config
- Automatic volume directory creation under `/var/lib/workloads/<name>/`
- Optional TPM2-encrypted secrets via systemd credentials

At boot, a tiny shell systemd generator emits an early-boot oneshot service
(`workload-generate.service`) that runs the Python `workload-generate` script.
The script reads `/etc/workloads.d/*/workload.toml` and writes per-workload unit files
into `/run/systemd/system/` before `basic.target` is reached. The Python work
is kept out of generator context because systemd expects generators to be
fast and minimal (see `systemd.generator(7)`) — see `docs/workloads.md` for
the full architecture.

## Key commands

| Command | Description |
|---|---|
| `workloadctl create` | Generate a workload TOML config |
| `workloadctl disable` | Stop service, optionally purge user/data |
| `workloadctl enable` | Create user, transfer image, start service |
| `workloadctl list` | List all configured workloads |
| `workloadctl logs` | View workload logs (container output / VM journal) |
| `workloadctl reboot` | Restart the workload (container: keeps overlay; VM: guest reboot) |
| `workloadctl recreate` | Recreate from config (container: destroys overlay; VM: rotates disk) |
| `workloadctl secret` | Manage TPM2-encrypted credentials |
| `workloadctl status` | Show workload status and resource usage |
| `workloadctl update` | Pull new image or rebuild VM disk, then recreate (auto-rollback on failure) |

Most mutating commands require `sudo`. Read-only commands work as any user.

## Documentation

- [Workload guide](docs/workloads.md) — full configuration reference with examples
- [CLI reference](docs/cli.md) — complete command documentation
- [Secrets management](docs/secrets.md) — TPM2-encrypted credentials
- [Filtered VM walkthrough](docs/vm-egress-walkthrough.md) — one VM's egress policy, TOML to packet
- [Schema reference](docs/schema-reference.toml) — annotated TOML schema
- [Example configs](workloads/) — real-world workload definitions, one bundle per directory

## License

MIT
