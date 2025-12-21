# Bootc Hypervisor Images

Bootable container images for running VMs (KVM/QEMU), system containers (Incus/LXC), and application containers (Podman)

[bootc](https://bootc-dev.github.io/) allows for atomic system upgrades with quick rollback

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
  - If you're not doing GPU things, this is the image to use

### GPU Variants

These include the appropriate kernel GPU drivers but not all user-space tools.

All variants inherit from `hypervisor-bootc`:

- **`hypervisor-nvidia:rpmfusion`** - NVIDIA drivers via RPMFusion
  - Driver: akmod-nvidia
  - Includes CUDA libraries, nvidia-container-toolkit

- **`hypervisor-nvidia:negativo17`** - NVIDIA drivers via negativo17 repo
  - Driver: nvidia-driver-cuda
  - More granular nvidia package structure, can update earlier

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

# Build ISOs with custom filesystem (default: xfs)
just build-iso-base btrfs
just build-iso-amd ext4
just build-all-isos btrfs
```

Datetime tags are automatically generated (YYYYMMDD-HHMM).

ISO builds support custom root filesystems via the `rootfs` parameter (xfs, btrfs, ext4). Defaults to xfs if not specified.

### Proxy Configuration

If you're building the images yourself and you have a caching proxy configured appropriately for handling package mirroring (2+ GB of cache, packages can be a little over 100 MB) - set `HTTP_PROXY` environment variable

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

#### Existing bootc system:
```bash
# Download and install if you're already running a bootc system
sudo bootc switch ghcr.io/bensmith/hypervisor-bootc:latest
sudo systemctl reboot
```

#### Make an installer ISO from a container image:
```bash
# make an installer iso from one of these images:
mkdir -p store && mkdir -p output && mkdir -p rpmmd
sudo podman pull ghcr.io/bensmith/hypervisor-bootc
sudo podman run \
  --privileged \
  --pull=newer \
  --rm \
  --security-opt label=type:unconfined_t \
  -v $(pwd)/config.toml:/config.toml:ro \
  -v $(pwd)/output:/output \
  -v $(pwd)/rpmmd:/rpmmd \
  -v $(pwd)/store:/store \
  -v /var/lib/containers/storage:/var/lib/containers/storage \
  quay.io/centos-bootc/bootc-image-builder:latest build \
    --chown $(id -u):$(id -g) \
    --output /output \
    --rootfs xfs \
    --rpmmd /rpmmd \
    --store /store \
    --type anaconda-iso \
  ghcr.io/bensmith/hypervisor-bootc

# write it to a usb drive and boot/install
sudo dd if=output/bootiso/install.iso of=/dev/sdX bs=4M status=progress
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

### Verify image signatures

The `fedora-bootc-minimal` base images are signed with cosign using keyless signing (OIDC).

Verify signatures before use:

```bash
# Install cosign
curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
sudo install cosign-linux-amd64 /usr/local/bin/cosign

# Verify image signature
cosign verify \
  --certificate-identity-regexp "https://github.com/.*/bootc-hypervisor" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/bensmith/fedora-bootc-minimal:latest
```

Signatures are stored in Sigstore's public transparency log and tied to GitHub Actions OIDC tokens.

## Architecture

```
fedora-bootc-minimal (upstream fork, podman 4 compatible)
  └── hypervisor-bootc (libvirt, qemu, cockpit, monitoring)
      ├── hypervisor-nvidia:rpmfusion (RPMFusion drivers)
      ├── hypervisor-nvidia:negativo17 (negativo17 drivers)
      └── hypervisor-amd (ROCm, Mesa)
```

## Enabled Services

- `cockpit.socket` - Web management UI
- `firewalld` - Firewall
- `incus.socket` - Incus system container management
- `libvirtd` - Virtualization (KVM/QEMU)
- `prometheus-node-exporter` - Metrics (port 9100)
- `nvidia-persistenced` - NVIDIA variants only
- `sshd` - Remote access
- `tuned` - Performance tuning

### Using Cockpit Web UI

Cockpit is installed but not exposed to the network by default for security.

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

### Build Flow

All images follow this standardized build pipeline:

```
1. Build          → Create container image with podman
2. Copy to root   → Transfer to root storage for rechunking
3. Rechunk        → Optimize with composefs chunking (hhd-dev/rechunk)
4. Retag          → Update tags to point to rechunked image
5. Push           → Upload to ghcr.io
6. Cleanup        → Free disk space for next variant
7. Sign           → Cryptographically sign with cosign (keyless)
```

### `build-minimal-bootc.yml`

Builds Fedora minimal bootc base images.

**Flow:**
1. Build with 3 tags: `{version}-{timestamp}`, `{version}`, `latest`
2. Copy to root storage
3. Rechunk with [hhd-dev/rechunk v1.2.4](https://github.com/hhd-dev/rechunk)
4. Retag version and latest to rechunked image
5. Push all tags to ghcr.io
6. Sign all tags with cosign

**Matrix builds:** Fedora 43 and rawhide in parallel

### `build-hypervisor.yml`

Builds base hypervisor and GPU variants.

**Flow (per variant):**
1. Build with 2 tags: `{timestamp}`, `latest` (or variant name)
2. Copy to root storage
3. Rechunk with composefs optimization
4. Retag latest/variant to rechunked image
5. Push both tags to ghcr.io
6. Cleanup to free space for next variant
7. Sign all pushed images (batched at end)

**Variants:**
- `base` - Base hypervisor (always built)
- `nvidia-rpmfusion` - NVIDIA via RPMFusion
- `nvidia-negativo17` - NVIDIA via negativo17
- `amd` - AMD GPU support

## License

Containerfiles and configurations: MIT

Fedora packages and upstream components: Their respective licenses
