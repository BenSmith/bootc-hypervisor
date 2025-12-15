# Bootc Hypervisor Images

Bootable container images for running KVM/QEMU hypervisors with optional GPU support (NVIDIA, AMD). 

[bootc](https://bootc-dev.github.io/) allows for atomic system upgrades with quick rollback.

## Images

### Base Images

- **`fedora-bootc-minimal`** - Minimal Fedora bootc base (kernel, systemd, bootc only)
  - Built from [Fedora bootc base-images](https://gitlab.com/fedora/bootc/base-images)
  - Podman 4 compatible fork (see `fedora-bootc-minimal.Containerfile`)
  - Weekly builds with rechunking for efficient updates

- **`hypervisor-bootc`** - Full hypervisor stack
  - Based on `fedora-bootc-minimal:43`
  - Includes: libvirt, QEMU/KVM, Incus, Podman, Cockpit, monitoring tools
  - Headless (no X/Wayland)

### GPU Variants

These include the approp

All variants inherit from `hypervisor-bootc`:

- **`hypervisor-nvidia:rpmfusion`** - NVIDIA drivers via RPMFusion
  - Driver: akmod-nvidia 580+
  - Includes CUDA libraries, nvidia-container-toolkit

- **`hypervisor-nvidia:negativo17`** - NVIDIA drivers via negativo17 repo
  - Driver: nvidia-driver-cuda
  - More granular package structure, headless-optimized

- **`hypervisor-amd`** - AMD GPU support
  - ROCm for compute (HIP, OpenCL)
  - Mesa drivers for graphics/video

## Build Schedule

Automated weekly builds via GitHub Actions:

- **Saturday 2am UTC**: `fedora-bootc-minimal` (Fedora 43 + rawhide)
- **Sunday 3am UTC**: Hypervisor images (all variants)

Images are pushed to `ghcr.io/bensmith/` with datetime tags.

## Image Tags

```
fedora-bootc-minimal:43-YYYYMMDD-HHMM    # Timestamped build
fedora-bootc-minimal:43                  # Latest for version 43
fedora-bootc-minimal:latest              # Latest stable (43)
fedora-bootc-minimal:rawhide-YYYYMMDD-HHMM
fedora-bootc-minimal:rawhide

hypervisor-bootc:YYYYMMDD-HHMM
hypervisor-bootc:latest

hypervisor-nvidia:rpmfusion-YYYYMMDD-HHMM
hypervisor-nvidia:rpmfusion
hypervisor-nvidia:negativo17-YYYYMMDD-HHMM
hypervisor-nvidia:negativo17

hypervisor-amd:YYYYMMDD-HHMM
hypervisor-amd:latest
```

## Local Builds

Using [just](https://github.com/casey/just):

```bash
# Build base hypervisor
just build-base

# Build GPU variants
just build-nvidia-rpmfusion
just build-nvidia-negativo17
just build-amd

# Build everything
just build-all

# Build ISOs (requires bootc-image-builder)
just build-iso-base
just build-iso-nvidia-rpmfusion
just build-all-isos
```

Datetime tags are automatically generated (YYYYMMDD-HHMM).

### Proxy Configuration

If you have a cacheing proxy - set `HTTP_PROXY` environment variable:

```bash
HTTP_PROXY=http://proxy:3128 just build-base
```

## Podman 4 Compatibility

Upstream (https://gitlab.com/fedora/bootc/base-images) fedora-bootc is built using podman 5.x.

The `fedora-bootc-minimal.Containerfile` in this repo is a backported version for GitHub Actions (podman 4.9.3):

- **No heredoc syntax** - uses inline `sh -c` instead
- **COPY instead of bind mount** - rpm-ostree needs writable `/repos`
- **No explicit `rw` on cache mount** - avoids duplicate option bug

These workarounds are temporary until GitHub Actions upgrades to podman 5.x.

## Using the Images

### Install to bare metal

```bash
# Download and install if you're already running a bootc system
sudo bootc switch ghcr.io/bensmith/hypervisor-bootc:latest
sudo systemctl reboot

# Or write an iso to usb and boot/install
sudo dd if=hypervisor-bootc-20250214-1430.iso of=/dev/sdX bs=4M status=progress
```

### Update

```bash
# Check for updates
bootc upgrade --check

# Apply updates
sudo bootc upgrade
sudo systemctl reboot
```

### Switch variants

```bash
# Switch to NVIDIA variant
sudo bootc switch ghcr.io/bensmith/hypervisor-nvidia:negativo17
sudo systemctl reboot
```

## Architecture

```
fedora-bootc-minimal (upstream fork, podman 4 compatible)
  └── hypervisor-bootc (libvirt, qemu, cockpit, monitoring)
      ├── hypervisor-nvidia:rpmfusion (RPMFusion drivers)
      ├── hypervisor-nvidia:negativo17 (negativo17 drivers)
      └── hypervisor-amd (ROCm, Mesa)
```

## Enabled Services

- `sshd` - Remote access
- `libvirtd` - Virtualization (KVM/QEMU)
- `incus.socket` - Incus system container management
- `firewalld` - Firewall
- `prometheus-node-exporter` - Metrics (port 9100)
- `tuned` - Performance tuning
- `nvidia-persistenced` - NVIDIA variants only

**Not enabled by default (for security):**
- `cockpit.socket` - Web management UI

### Using Cockpit Web UI

Cockpit is installed but not enabled by default for security.

**Enable Cockpit:**
```bash
sudo systemctl enable --now cockpit.socket
```

**Access via SSH tunnel (recommended):**
```bash
# On your local machine
ssh -L 9090:localhost:9090 user@hypervisor

# Browse to http://localhost:9090
```

**Or open firewall for network access:**
```bash
sudo firewall-cmd --add-service=cockpit --permanent
sudo firewall-cmd --reload

# Browse to http://hypervisor-ip:9090
```

## Virtualization & Containers

The hypervisor provides multiple options for different workload types:

- **KVM/QEMU** (via libvirt) - Full VMs for any OS, hardware emulation
- **Incus** - Lightweight Linux system containers, VM-like but more efficient
- **Podman** - Application containers, stateless microservices

Choose the right tool for your workload: VMs for Windows/isolation, Incus for lightweight Linux instances, Podman for applications.

## GitHub Actions Workflows

### `build-minimal-bootc.yml`
- Builds Fedora minimal bootc base
- Rechunks for efficient updates [hhd-dev/rechunk v1.2.4](https://github.com/hhd-dev/rechunk)
- Pushes to ghcr.io
- Weekly on Saturdays at 2am UTC

### `build-hypervisor.yml`
- Builds hypervisor + GPU variants
- Selectable variants (manual trigger)
- Pushes to ghcr.io
- Weekly on Sundays at 3am UTC

## License

Containerfiles and configurations: MIT

Fedora packages and upstream components: Their respective licenses
