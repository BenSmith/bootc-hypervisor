# workloadctl

Declarative rootless container workload manager for Linux. Define workloads as
TOML files, and workloadctl handles user creation, systemd service generation,
volume management, secrets, and container lifecycle — all running as isolated
unprivileged users with rootless podman.

## Requirements

- Fedora 41+ (or any systemd + podman 5.3+ Linux)
- Python 3.11+
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
sudo tee /etc/workloads.d/webserver.toml <<'EOF'
[workload]
name = "webserver"
image = "docker.io/nginxinc/nginx-unprivileged:alpine"
enabled = true

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
- A systemd service generated at boot by a systemd generator
- Automatic volume directory creation under `/var/lib/workloads/<name>/`
- Optional TPM2-encrypted secrets via systemd credentials

The systemd generator reads `/etc/workloads.d/*.toml` at boot and produces
service units automatically — no `systemctl daemon-reload` needed after reboot.

## Key commands

| Command | Description |
|---|---|
| `workloadctl create` | Generate a workload TOML config |
| `workloadctl enable` | Create user, transfer image, start service |
| `workloadctl disable` | Stop service, optionally purge user/data |
| `workloadctl status` | Show workload status and resource usage |
| `workloadctl logs` | View workload container logs |
| `workloadctl update` | Pull new image and restart |
| `workloadctl list` | List all configured workloads |
| `workloadctl secret` | Manage TPM2-encrypted credentials |

Most mutating commands require `sudo`. Read-only commands work as any user.

## Documentation

- [Workload guide](docs/workloads.md) — full configuration reference with examples
- [CLI reference](docs/cli.md) — complete command documentation
- [Secrets management](docs/secrets.md) — TPM2-encrypted credentials
- [Schema reference](docs/schema-reference.toml) — annotated TOML schema
- [Example configs](workloads.d/) — real-world workload definitions

## License

MIT
