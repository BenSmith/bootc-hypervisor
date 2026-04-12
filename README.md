# Bootc Hypervisor

Homelab virtualization platform delivered as immutable [Fedora bootc](https://bootc-dev.github.io/) images with rootless
container workloads, KVM/QEMU VMs, and Incus system containers.

Atomic OS upgrades with instant rollback, declarative workload management via TOML configs, GPU passthrough 
(AMD/NVIDIA), and TPM2-backed secrets. No cloud dependencies.

Run local services like Pi-hole, VPN proxies, container registry, GPU-accelerated game streaming, AI workloads on an 
immutable OS that can't be broken by bad upgrades. Each service runs as a locked-down rootless container under its own
system user. Updates are pulled from a container registry and applied atomically.

## Why
I was no longer willing to struggle with what happens when I update the base OS on my home server. Invariably one or 
more things would break, sometimes in complex entagled ways. This system gives instant rollback for the base system, 
and the workloadctl package allows for independent isolation for various services and workloads. 

## Quick Start

**Already running a bootc system:**
```bash
sudo bootc switch ghcr.io/bensmith/hypervisor-bootc:latest
sudo systemctl reboot
```

**Install from ISO:**
```bash
just build-iso-base
sudo dd if=output/bootiso/install.iso of=/dev/sdX bs=4M status=progress
# Boot from USB and install
```

**Create a workload:**
```bash
sudo workloadctl create webserver \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --ports 8080:8080 \
  --enable

workloadctl status webserver
curl http://localhost:8080
```

## Images

```
fedora-bootc-minimal              Minimal Fedora bootc (kernel, systemd, bootc) - built from Fedora's bootc project
  └── hypervisor-bootc             Full stack: libvirt, QEMU/KVM, Incus, Podman 5
      ├── hypervisor-nvidia:rpmfusion   NVIDIA via RPMFusion (akmod-nvidia, CUDA)
      ├── hypervisor-nvidia:negativo17  NVIDIA via negativo17 (nvidia-driver-cuda)
      └── hypervisor-amd                AMD ROCm + Mesa
```

All images published to `ghcr.io/bensmith/` with datetime tags, signed with cosign (keyless OIDC).

### What's in hypervisor-bootc

The base image is headless and includes:

- **Virtualization**: libvirt, QEMU/KVM, virt-install
- **System containers**: Incus (LXC)
- **Application containers**: Podman 5, podman-compose, crun, skopeo
- **Workload management**: [workloadctl](#workload-system-workloadctl)
- **Networking**: firewalld, NetworkManager, bridge-utils, wireguard-tools, dnsmasq
- **Storage**: btrfs-progs, xfsprogs, lvm2, mdadm, cifs-utils, NVMe tools
- **Monitoring**: btop, htop, iotop, sysstat, smartmontools, lm_sensors
- **Security**: fail2ban, SELinux, audit, seatd
- **Utilities**: tmux, neovim, just, jq, distrobox, fwupd

### GPU Variants

Each inherits from hypervisor-bootc and adds kernel GPU drivers:

| Variant | Driver | Includes |
|---|---|---|
| `hypervisor-nvidia:rpmfusion` | akmod-nvidia | CUDA libs, nvidia-container-toolkit, CDI |
| `hypervisor-nvidia:negativo17` | nvidia-driver-cuda | More granular packaging, earlier updates |
| `hypervisor-amd` | ROCm + Mesa | HIP, OpenCL, rocm-smi, VA-API |

### Image Tags

```
hypervisor-bootc:YYYYMMDD-HHMM        # Timestamped
hypervisor-bootc:latest                # Latest build
hypervisor-nvidia:rpmfusion            # Latest NVIDIA (RPMFusion)
hypervisor-nvidia:negativo17           # Latest NVIDIA (negativo17)
hypervisor-amd:latest                  # Latest AMD
fedora-bootc-minimal:43               # Latest for Fedora 43
```

## Workload System (workloadctl)

[`workloadctl`](workloadctl/) is a standalone tool (RPM-packaged, **no bootc dependency**) that manages rootless podman
containers as declarative TOML configs. It should work on systemd Linuxes with Podman 5.3+.

Each workload gets:

- A dedicated system user (`_wl-<name>`) with its own UID/subuid namespace
- A systemd service generated at boot
- Automatic volume directory creation
- Optional TPM2-encrypted secrets via systemd credentials

```bash
# Create and start
sudo workloadctl create pihole \
  --image pihole/pihole:latest \
  --ports 53:53 80:80 \
  --enable

# Manage
workloadctl list                    # List all workloads
workloadctl status pihole           # Service status
workloadctl logs -f pihole          # Follow logs
sudo workloadctl update pihole      # Pull new image, auto-rollback on failure
sudo workloadctl shell pihole       # Interactive shell

# Secrets
echo -n "my-key" | sudo workloadctl secret create api-key
sudo workloadctl secret list
```

Or write a TOML config directly:

```toml
# /etc/workloads.d/webserver.toml
[workload]
name = "webserver"

[container]
image = "docker.io/nginxinc/nginx-unprivileged:alpine"

[network]
ports = ["8080:8080"]
```

See the [workloadctl README](workloadctl/README.md) for install instructions and the full feature set.

## Installation and Updates

### Install

**From a bootc system:**
```bash
sudo bootc switch ghcr.io/bensmith/hypervisor-bootc:latest
sudo systemctl reboot
```

**From installer ISO** (build locally or download from releases):
```bash
just build-iso-base              # Or: just build-iso-nvidia-rpmfusion
sudo dd if=output/bootiso/install.iso of=/dev/sdX bs=4M status=progress
```

### Update

```bash
bootc upgrade --check            # Check for updates
sudo bootc upgrade               # Apply atomically
sudo systemctl reboot
```

### Switch Variants

```bash
sudo bootc switch ghcr.io/bensmith/hypervisor-nvidia:negativo17
sudo systemctl reboot
```

## Building Locally

Requires [just](https://github.com/casey/just) and podman.

```bash
# Container images
just build-base-local                    # Base hypervisor (from local minimal)
just build-amd-local                     # AMD GPU variant
just build-nvidia-rpmfusion-local        # NVIDIA variant
just build-all-local                     # Everything

# ISOs (rootfs: xfs, btrfs, or ext4)
just build-iso-base                      # Base hypervisor ISO
just build-all-isos                      # All variant ISOs

# Development: build, create qcow2, deploy to libvirt VM
just aio-local

# Tests
just test                                # workloadctl unit tests
just test-vm-build && just test-vm       # Full VM integration tests (libvirt + SWTPM)

# Push to local registry
just push-all
```

Weekly automated builds via GitHub Actions: `fedora-bootc-minimal` on Saturdays, all hypervisor variants on Sundays.

## Design

- **Bootc for immutability** — `/usr` is read-only, `/etc` is mutable config, `/var` is persistent data. Atomic updates with instant rollback.
- **Rootless containers via dedicated users** — Each workload gets a unique `_wl-{name}` user with its own UID namespace. No privileged containers.
- **systemd-native** — Generators for boot-time provisioning, credentials for secrets, cgroup v2 for resource limits, journal for logging.
- **TPM2-backed secrets** — Hardware encryption, machine-specific, safe to commit encrypted blobs to images.
- **Explicit hardware opt-in** — No device access by default; convenience flags (`--gpu`, `--audio`, `--input`, `--virtualization`) for common scenarios.

## Documentation

- [workloadctl README](workloadctl/README.md) — Workload system overview
- [Workload guide](workloadctl/docs/workloads.md) — Full configuration reference
- [CLI reference](workloadctl/docs/cli.md) — All commands and options
- [Secrets management](workloadctl/docs/secrets.md) — TPM2-encrypted credentials
- [Schema reference](workloadctl/docs/schema-reference.toml) — Annotated TOML schema
- [Example configs](workloadctl/workloads.d/) — Real-world workload definitions
- [Troubleshooting](docs/TROUBLESHOOTING.md) — Common issues and fixes
- [Emergency recovery](docs/emergency-recovery.md) — Boot recovery procedures

## License

MIT (Containerfiles, configs, tooling). Fedora packages and upstream components under their respective licenses.
