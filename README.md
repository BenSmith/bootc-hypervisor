# Bootc Hypervisor

This is a homelab container/VM manager, inspired by Proxmox and Kubernetes based on an immutable OS, Fedora [bootc](https://bootc-dev.github.io/).

This allows for atomic OS upgrades with quick and easy rollbacks, and a read-only root filesystem.

Bootc-based systems can be installed from an ISO/USB image or a running bootc container, updates are pulled from container registries. Bootc images can also run as containers, and can be derived from base images in a Dockerfile/Containerfile like any other container.

## Why

I made this because I wanted a simple way to run local services like pihole, vpn-proxied services, container registry, git host, home assistant, etc along with GPU-acceleration experiments. And I liked the bootc/immutable approach because I've broken my entire system with hypervisor upgrades gone wrong.  

I hit on a pretty simple way to manage the various services as .toml config files that can use public images fairly easily, or use locally-customized container images. 

With podman shenanigans, a workload uses rootless podman with a very locked-down single-purpose user that is only able to write to its own, self-owned storage. Since the OS is bootc and most of it is mounted read-only, it is exceedingly difficult to break into the system or interfere with other running workloads. 

In addition, Linux gaming has really taken off and the same hardware can be used for locally-hosted AI workloads. 

I wanted to be able to stream games from my heavy server to a lighter system, or spin up a local llm/ai container for trying out untrusted agentic tooling in a sandbox that couldn't easily gain access to sensitive info.

Some of this is still a work in progress, but what I've made so far I find intriguing. It's entirely possible to run a rootless headless desktop environment in a container, as a workload, with GPU acceleration. 

It's possible but not yet simple. 

This could run a complete dev environment with inference and all the right libraries, or it could run Sunshine for high-performace game streaming to moonlight clients. Instead of having a dev computer that has rust dev, a zillion python virtual envs, 12 versions of Boost, 4 IDEs, and 5 versions of node, make a workload desktop environment per variant turn 'em off and on, and enjoy your OP homelab mainframe.

I do not yet know whether rootless containerized desktops can run flatpacked applications due to their containerization, and the same goes for Steam games.

## Images

### Base Images

- **`fedora-bootc-minimal`** - Minimal Fedora bootc base (kernel, systemd, bootc only)
  - Built from [Fedora bootc base-images](https://gitlab.com/fedora/bootc/base-images)
  - Build with Podman 4 for github ci/cd (see `fedora-bootc-minimal.Containerfile`)
  - Weekly builds with rechunking for efficient updates

- **`hypervisor-bootc`** - Full hypervisor stack
  - Based on `fedora-bootc-minimal:43`
  - Includes: libvirt, QEMU/KVM, Incus, Podman, monitoring tools
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
# Build fedora bootc minimal
just build-minimal 43 

# Build base hypervisor
just build-base-local

# Build GPU variants
just build-nvidia-rpmfusion-local
just build-nvidia-negativo17-local
just build-amd-local

# Build everything
just build-all-local

# Build ISOs (this will podman pull bootc-image-builder)
just build-iso-base-local
just build-iso-nvidia-rpmfusion-local
just build-all-isos-local

```

Datetime tags are automatically generated (YYYYMMDD-HHMM).

The images are signed with cosign using keyless signing (OIDC).

ISO builds support custom root filesystems via the `rootfs` parameter (xfs, btrfs, ext4). Defaults to xfs if not specified.

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
If you're running an install from an ISO of a locally built image, you'll need to switch to the "unverified" image first, for live updates:
```bash
sudo bootc switch ghcr.io/bensmith/hypervisor-bootc:latest
sudo reboot
```

To update to a signed image from an unverified:
```bash
sudo bootc switch ghcr.io/bensmith/hypervisor-bootc:latest --enforce-container-sigpolicy
sudo reboot
```

Regular updates:
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

## Workload System

The workload provisioning system ([`workloadctl`](workloadctl/)) manages rootless
podman containers as declarative TOML configs. Each workload gets a dedicated
locked-down system user, its own UID/subuid namespace, systemd service, and
automatic volume management.

```bash
# Create and start a workload
sudo workloadctl create webserver \
  --image docker.io/nginxinc/nginx-unprivileged:alpine \
  --ports 8080:8080 --enable

# Or write a TOML config and enable it
sudo workloadctl enable my-service
```

`workloadctl` has **no bootc dependency** — it works on any Linux system with
systemd and podman 5.3+. It is available as a standalone RPM; see
[`workloadctl/README.md`](workloadctl/README.md) for install instructions.

**Documentation:**

- [Workload guide](workloadctl/docs/workloads.md) — configuration, host setup, customization
- [CLI reference](workloadctl/docs/cli.md) — all commands and options
- [Secrets management](workloadctl/docs/secrets.md) — TPM2-encrypted credentials
- [Schema reference](workloadctl/docs/schema-reference.toml) — annotated TOML schema
- [Example configs](workloadctl/workloads.d/) — real-world workload definitions
- [Emergency recovery](docs/emergency-recovery.md) — boot recovery procedures
- [Troubleshooting](docs/TROUBLESHOOTING.md) — common issues and fixes

## Architecture

```
fedora-bootc-minimal
  └── hypervisor-bootc (libvirt, qemu, podman, incus, workloadctl, cosy)
      ├── hypervisor-nvidia:rpmfusion (RPMFusion drivers)
      ├── hypervisor-nvidia:negativo17 (negativo17 drivers)
      └── hypervisor-amd (ROCm, Mesa)
```

## Enabled Services

- `firewalld` - Firewall
- `incus.socket` - Incus system container management
- `libvirtd` - Virtualization (KVM/QEMU)
- `nvidia-persistenced` - NVIDIA variants only
- `sshd` - Remote access
- `tuned` - Performance tuning

## Virtualization & Containers

The hypervisor provides multiple options for different workload types:

- **KVM/QEMU** (via libvirt) - Full VMs for any OS, hardware emulation
- **Incus** - Lightweight Linux system containers, VM-like but more efficient
- **Podman 5** - Application containers, stateless microservices

Choose the right tool for your workload: VMs for Windows/isolation, Incus for lightweight Linux instances, Podman for applications.

## Podman 4 Pipeline Build

Upstream (https://gitlab.com/fedora/bootc/base-images) fedora-bootc is built using podman 5.x.

The `fedora-bootc-minimal.Containerfile` in this repo is a backported version for GitHub Actions (podman 4.9.3):

These workarounds are temporary until GitHub Actions upgrades to podman 5.x.

## License

Containerfiles and configurations: MIT

Fedora packages and upstream components: Their respective licenses
