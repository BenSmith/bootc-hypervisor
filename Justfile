#!/usr/bin/env just --justfile

proxy := env_var_or_default('HTTP_PROXY', '')

tag := `date +%Y%m%d-%H%M`

build-minimal version="43" rechunk="false":
  #!/usr/bin/env bash
  set -euo pipefail

  # Clone Fedora bootc manifests if not already present
  if [ ! -d "manifests" ]; then
    echo "Cloning Fedora bootc manifests..."
    git clone --depth 1 https://gitlab.com/fedora/bootc/base-images.git manifests
  fi

  cp policy-local.json manifests/policy.json

  # Build the minimal bootc image (requires sudo for nested containerization)
  echo "Building fedora-bootc-minimal:{{version}}..."
  http_proxy={{proxy}} https_proxy={{proxy}} \
  sudo podman build \
    --network=host \
    --security-opt=label=disable \
    --cap-add=all \
    --device /dev/fuse \
    --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
    -f fedora-bootc-minimal.Containerfile \
    --build-arg MANIFEST=minimal \
    --build-arg BUILDER_IMAGE=quay.io/fedora/fedora:{{version}} \
    --build-arg REPOS_IMAGE=quay.io/fedora/fedora:{{version}} \
    -t localhost/fedora-bootc-minimal:{{version}}-{{tag}} \
    -t localhost/fedora-bootc-minimal:{{version}} \
    -t localhost/fedora-bootc-minimal:latest \
    -t ghcr.io/bensmith/fedora-bootc-minimal:{{version}} \
    -t ghcr.io/bensmith/fedora-bootc-minimal:latest \
    manifests

  # Optionally rechunk the image for better efficiency
  if [ "{{rechunk}}" == "true" ]; then
    echo "Rechunking image (requires sudo)..."
    sudo podman run --rm --privileged \
      -v /var/lib/containers:/var/lib/containers \
      quay.io/fedora/fedora-bootc:{{version}} \
      /usr/libexec/bootc-base-imagectl rechunk \
      localhost/fedora-bootc-minimal:{{version}}-{{tag}} \
      localhost/fedora-bootc-minimal:rechunked

    # Re-tag rechunked image
    sudo podman tag localhost/fedora-bootc-minimal:rechunked \
      localhost/fedora-bootc-minimal:{{version}}-{{tag}}
    sudo podman tag localhost/fedora-bootc-minimal:rechunked \
      localhost/fedora-bootc-minimal:{{version}}
    sudo podman tag localhost/fedora-bootc-minimal:rechunked \
      localhost/fedora-bootc-minimal:latest

    # Clean up temporary tag
    sudo podman rmi localhost/fedora-bootc-minimal:rechunked
  fi

  # Copy image from root storage to user storage for local development
  echo "Copying image to user storage..."
  sudo podman save localhost/fedora-bootc-minimal:{{version}} | podman load
  sudo podman save localhost/fedora-bootc-minimal:latest | podman load

  echo "Build complete: localhost/fedora-bootc-minimal:{{version}}"
  echo "Image available in both root and user storage"

build-base:
  #!/usr/bin/env bash
  set -euo pipefail
  # Use permissive policy for local builds
  cp policy-local.json policy.json
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-bootc:{{tag}} \
  -t localhost/hypervisor-bootc:latest \
  -t ghcr.io/bensmith/hypervisor-bootc:{{tag}} \
  -t ghcr.io/bensmith/hypervisor-bootc:latest \
  -f hypervisor.Containerfile .

# Local testing - use locally-built minimal (whatever version you built)
build-base-local:
  #!/usr/bin/env bash
  set -euo pipefail
  # Use permissive policy for local builds
  cp policy-local.json policy.json
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --network=host \
  --layers=false \
  --from localhost/fedora-bootc-minimal:latest \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-bootc:local \
  -t localhost/hypervisor-bootc:latest \
  -t box:5000/hypervisor-bootc:latest \
  -t box:5000/hypervisor-bootc:local \
  -f hypervisor.Containerfile .

build-nvidia-rpmfusion:
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-nvidia:rpmfusion-{{tag}} \
  -t localhost/hypervisor-nvidia:rpmfusion \
  -t ghcr.io/bensmith/hypervisor-nvidia:rpmfusion-{{tag}} \
  -t ghcr.io/bensmith/hypervisor-nvidia:rpmfusion \
  -f hypervisor-nvidia-rpmfusion.Containerfile .

build-nvidia-negativo17:
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-nvidia:negativo17-{{tag}} \
  -t localhost/hypervisor-nvidia:negativo17 \
  -t ghcr.io/bensmith/hypervisor-nvidia:negativo17-{{tag}} \
  -t ghcr.io/bensmith/hypervisor-nvidia:negativo17 \
  -f hypervisor-nvidia-negativo17.Containerfile .

build-amd:
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-amd:{{tag}} \
  -t localhost/hypervisor-amd:latest \
  -f hypervisor-amd.Containerfile .

# Local testing variants - use locally-built base instead of GHCR
build-amd-local: build-base-local
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --network=host \
  --from localhost/hypervisor-bootc:latest \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-amd:local \
  -t box:5000/hypervisor-amd:latest \
  -t box:5000/hypervisor-amd:local \
  -f hypervisor-amd.Containerfile .

build-nvidia-rpmfusion-local: build-base-local
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --network=host \
  --from localhost/hypervisor-bootc:latest \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-nvidia:rpmfusion-local \
  -f hypervisor-nvidia-rpmfusion.Containerfile .

build-nvidia-negativo17-local: build-base-local
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --network=host \
  --from localhost/hypervisor-bootc:latest \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-nvidia:negativo17-local \
  -f hypervisor-nvidia-negativo17.Containerfile .

build-all: build-base build-nvidia-rpmfusion build-nvidia-negativo17 build-amd

build-all-local: build-base build-amd-local build-nvidia-rpmfusion-local build-nvidia-negativo17-local

build-iso-base rootfs="xfs":
  @mkdir -p store output/base rpmmd
  @echo "Copying image to rootful storage..."
  sudo podman pull ghcr.io/bensmith/hypervisor-bootc:latest
  sudo podman run \
    --privileged \
    --pull=newer \
    --rm \
    --security-opt label=type:unconfined_t \
    -v $(pwd)/config.toml:/config.toml:ro \
    -v $(pwd)/output/base:/output \
    -v $(pwd)/rpmmd:/rpmmd \
    -v $(pwd)/store:/store \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest build \
      --chown $(id -u):$(id -g) \
      --output /output \
      --rootfs {{rootfs}} \
      --rpmmd /rpmmd \
      --store /store \
      --type anaconda-iso \
    ghcr.io/bensmith/hypervisor-bootc
  @echo "Relabeling and copying ISO..."
  @just relabel-iso output/base/bootiso/install.iso output/hypervisor-bootc-{{tag}}.iso "HV-BASE"
  @echo "ISO ready: output/hypervisor-bootc-{{tag}}.iso (label: HV-BASE)"

build-iso-base-local rootfs="xfs":
  @mkdir -p store output/base rpmmd
  @echo "Copying image to rootful storage..."
  sudo podman pull box:5000/hypervisor-bootc:latest
  sudo podman run \
    --privileged \
    --pull=newer \
    --rm \
    --security-opt label=type:unconfined_t \
    -v $(pwd)/config.toml:/config.toml:ro \
    -v $(pwd)/output/base:/output \
    -v $(pwd)/rpmmd:/rpmmd \
    -v $(pwd)/store:/store \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest build \
      --chown $(id -u):$(id -g) \
      --output /output \
      --rootfs {{rootfs}} \
      --rpmmd /rpmmd \
      --store /store \
      --type anaconda-iso \
    box:5000/hypervisor-bootc
  @echo "Relabeling and copying ISO..."
  @just relabel-iso output/base/bootiso/install.iso output/hypervisor-bootc-{{tag}}.iso "HV-BASE"
  @echo "ISO ready: output/hypervisor-bootc-{{tag}}.iso (label: HV-BASE)"

build-iso-nvidia-rpmfusion rootfs="xfs":
  @mkdir -p store output/nvidia-rpmfusion rpmmd
  @echo "Pulling image from ghcr.io..."
  sudo podman pull ghcr.io/bensmith/hypervisor-nvidia:rpmfusion
  sudo podman run \
    --privileged \
    --pull=newer \
    --rm \
    --security-opt label=type:unconfined_t \
    -v $(pwd)/config.toml:/config.toml:ro \
    -v $(pwd)/output/nvidia-rpmfusion:/output \
    -v $(pwd)/rpmmd:/rpmmd \
    -v $(pwd)/store:/store \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest build \
      --chown $(id -u):$(id -g) \
      --output /output \
      --rootfs {{rootfs}} \
      --rpmmd /rpmmd \
      --store /store \
      --type anaconda-iso \
    ghcr.io/bensmith/hypervisor-nvidia:rpmfusion
  @echo "Relabeling and copying ISO..."
  @just relabel-iso output/nvidia-rpmfusion/bootiso/install.iso output/hypervisor-nvidia-rpmfusion-{{tag}}.iso "HV-NV-RPMFUSION"
  @echo "ISO ready: output/hypervisor-nvidia-rpmfusion-{{tag}}.iso (label: HV-NV-RPMFUSION)"

build-iso-nvidia-negativo17 rootfs="xfs":
  @mkdir -p store output/nvidia-negativo17 rpmmd
  @echo "Pulling image from ghcr.io..."
  sudo podman pull ghcr.io/bensmith/hypervisor-nvidia:negativo17
  sudo podman run \
    --privileged \
    --pull=newer \
    --rm \
    --security-opt label=type:unconfined_t \
    -v $(pwd)/config.toml:/config.toml:ro \
    -v $(pwd)/output/nvidia-negativo17:/output \
    -v $(pwd)/rpmmd:/rpmmd \
    -v $(pwd)/store:/store \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest build \
      --chown $(id -u):$(id -g) \
      --output /output \
      --rootfs {{rootfs}} \
      --rpmmd /rpmmd \
      --store /store \
      --type anaconda-iso \
    ghcr.io/bensmith/hypervisor-nvidia:negativo17
  @echo "Relabeling and copying ISO..."
  @just relabel-iso output/nvidia-negativo17/bootiso/install.iso output/hypervisor-nvidia-negativo17-{{tag}}.iso "HV-NV-NEG17"
  @echo "ISO ready: output/hypervisor-nvidia-negativo17-{{tag}}.iso (label: HV-NV-NEG17)"

build-iso-amd rootfs="xfs":
  @mkdir -p store output/amd rpmmd
  @echo "Pulling image from ghcr.io..."
  sudo podman pull ghcr.io/bensmith/hypervisor-amd
  sudo podman run \
    --privileged \
    --pull=newer \
    --rm \
    --security-opt label=type:unconfined_t \
    -v $(pwd)/config.toml:/config.toml:ro \
    -v $(pwd)/output/amd:/output \
    -v $(pwd)/rpmmd:/rpmmd \
    -v $(pwd)/store:/store \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest build \
      --chown $(id -u):$(id -g) \
      --output /output \
      --rootfs {{rootfs}} \
      --rpmmd /rpmmd \
      --store /store \
      --type anaconda-iso \
    ghcr.io/bensmith/hypervisor-amd
  @echo "Relabeling and copying ISO..."
  @just relabel-iso output/amd/bootiso/install.iso output/hypervisor-amd-{{tag}}.iso "HV-AMD"
  @echo "ISO ready: output/hypervisor-amd-{{tag}}.iso (label: HV-AMD)"

build-qcow2-base rootfs="xfs":
  @mkdir -p store output/base-qcow2 rpmmd
  @echo "Pulling image from ghcr.io..."
  sudo podman pull ghcr.io/bensmith/hypervisor-bootc:latest
  sudo podman run \
    --privileged \
    --pull=newer \
    --rm \
    --security-opt label=type:unconfined_t \
    -v $(pwd)/config.toml:/config.toml:ro \
    -v $(pwd)/output/base-qcow2:/output \
    -v $(pwd)/rpmmd:/rpmmd \
    -v $(pwd)/store:/store \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest build \
      --chown $(id -u):$(id -g) \
      --output /output \
      --rootfs {{rootfs}} \
      --rpmmd /rpmmd \
      --store /store \
      --type qcow2 \
    ghcr.io/bensmith/hypervisor-bootc
  @echo "QCOW2 image ready: output/base-qcow2/qcow2/disk.qcow2"
  @echo "To use: sudo cp output/base-qcow2/qcow2/disk.qcow2 /var/lib/libvirt/images/hypervisor-{{tag}}.qcow2"

build-qcow2-base-local rootfs="xfs":
  @mkdir -p store output/base-qcow2 rpmmd
  @echo "Pulling image from local registry..."
  sudo podman pull box:5000/hypervisor-bootc:latest
  sudo podman run \
    --privileged \
    --pull=newer \
    --rm \
    --security-opt label=type:unconfined_t \
    -v $(pwd)/config.toml:/config.toml:ro \
    -v $(pwd)/output/base-qcow2:/output \
    -v $(pwd)/rpmmd:/rpmmd \
    -v $(pwd)/store:/store \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest build \
      --chown $(id -u):$(id -g) \
      --output /output \
      --rootfs {{rootfs}} \
      --rpmmd /rpmmd \
      --store /store \
      --type qcow2 \
    box:5000/hypervisor-bootc
  @echo "QCOW2 image ready: output/base-qcow2/qcow2/disk.qcow2"
  @echo "To use: sudo cp output/base-qcow2/qcow2/disk.qcow2 /var/lib/libvirt/images/hypervisor-{{tag}}.qcow2"


# All-in-one: build container, build qcow2, and deploy to libvirt VM
aio-local vmname="hypervisor-test" memory="4096" vcpus="2" rootfs="xfs":
  #!/usr/bin/env bash
  set -euo pipefail
  echo "=== Step 1: Building container image ==="
  just build-base-local

  echo ""
  echo "=== Step 1.5: Pushing image to local registry ==="
  podman push box:5000/hypervisor-bootc:latest

  echo ""
  echo "=== Step 2: Building qcow2 disk image ==="
  just build-qcow2-base-local {{rootfs}}

  echo ""
  echo "=== Step 3: Deploying to VM '{{vmname}}' ==="

  # Copy to system libvirt storage
  sudo mkdir -p /var/lib/libvirt/images
  sudo cp output/base-qcow2/qcow2/disk.qcow2 /var/lib/libvirt/images/{{vmname}}-{{tag}}.qcow2

  # Destroy old VM if it exists
  if sudo virsh dominfo {{vmname}} &>/dev/null; then
    echo "Destroying existing VM '{{vmname}}'..."
    sudo virsh destroy {{vmname}} 2>/dev/null || true
    sudo virsh undefine {{vmname}}
  fi

  # Create and start new VM (system libvirt for proper networking)
  echo "Creating VM '{{vmname}}' ({{memory}}MB RAM, {{vcpus}} vCPUs)..."
  sudo virt-install \
    --name {{vmname}} \
    --memory {{memory}} \
    --vcpus {{vcpus}} \
    --disk path=/var/lib/libvirt/images/{{vmname}}-{{tag}}.qcow2,format=qcow2 \
    --import \
    --os-variant fedora41 \
    --network network=default \
    --noautoconsole

  echo ""
  echo "=== Waiting for VM to boot and obtain IP address ==="

  # Wait up to 60 seconds for IP address
  timeout=60
  elapsed=0
  ip_addr=""

  while [ $elapsed -lt $timeout ]; do
    sleep 2
    elapsed=$((elapsed + 2))

    # Try to get IP address
    ip_line=$(sudo virsh domifaddr {{vmname}} 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)

    if [ -n "$ip_line" ]; then
      ip_addr="$ip_line"
      break
    fi

    echo -n "."
  done

  echo ""
  echo ""
  echo "=== Deployment complete! ==="
  echo "VM name: {{vmname}}"
  echo "Disk: /var/lib/libvirt/images/{{vmname}}-{{tag}}.qcow2"

  if [ -n "$ip_addr" ]; then
    echo "IP address: $ip_addr"
    echo ""
    echo "To connect:"
    echo "  ssh ben@$ip_addr"
    echo "  sudo virsh console {{vmname}}         # Serial console (Ctrl+] to exit)"
  else
    echo "IP address: (timeout waiting for DHCP - check with: sudo virsh domifaddr {{vmname}})"
    echo ""
    echo "To connect:"
    echo "  sudo virsh domifaddr {{vmname}}       # Get IP address"
    echo "  sudo virsh console {{vmname}}         # Serial console (Ctrl+] to exit)"
  fi

  echo ""
  echo "VM management:"
  echo "  sudo virsh start {{vmname}}           # Start VM"
  echo "  sudo virsh shutdown {{vmname}}        # Graceful shutdown"
  echo "  sudo virsh destroy {{vmname}}         # Force power off"
  echo "  sudo virsh undefine {{vmname}}        # Delete VM config"

# Relabel an ISO with a custom volume label and update boot configs
relabel-iso input output label:
  #!/usr/bin/env bash
  set -euo pipefail

  echo "Relabeling {{input}} -> {{output}} with label '{{label}}'"

  # Create temporary directory for ISO extraction
  TMPDIR=$(mktemp -d)
  trap "rm -rf $TMPDIR" EXIT

  # Mount the original ISO
  MOUNT_DIR="$TMPDIR/mount"
  mkdir -p "$MOUNT_DIR"
  sudo mount -o loop,ro "{{input}}" "$MOUNT_DIR"

  # Copy ISO contents to working directory
  WORK_DIR="$TMPDIR/iso"
  mkdir -p "$WORK_DIR"
  sudo cp -a "$MOUNT_DIR"/* "$WORK_DIR/" 2>/dev/null || true
  sudo cp -a "$MOUNT_DIR"/.[!.]* "$WORK_DIR/" 2>/dev/null || true
  sudo umount "$MOUNT_DIR"

  # Get the original volume label
  ORIG_LABEL=$(isoinfo -d -i "{{input}}" | grep "Volume id:" | sed 's/Volume id: //')
  echo "Original label: $ORIG_LABEL"
  echo "New label: {{label}}"

  # Update grub configs to replace old label with new label
  for grub_cfg in "$WORK_DIR/boot/grub2/grub.cfg" "$WORK_DIR/EFI/BOOT/grub.cfg"; do
    if [ -f "$grub_cfg" ]; then
      echo "Updating $grub_cfg..."
      sudo sed -i "s/$ORIG_LABEL/{{label}}/g" "$grub_cfg"
    fi
  done

  # Create new ISO with updated label and configs
  sudo xorriso -as mkisofs \
    -V "{{label}}" \
    -r -J \
    -b images/eltorito.img \
    -c boot.cat \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    -eltorito-alt-boot \
    -e images/efiboot.img \
    -no-emul-boot \
    -o "{{output}}" \
    "$WORK_DIR"

  # Fix ownership
  sudo chown $(id -u):$(id -g) "{{output}}"

  echo "ISO relabeled successfully: {{output}}"

build-all-isos rootfs="xfs":
  just build-iso-base {{rootfs}}
  just build-iso-nvidia-rpmfusion {{rootfs}}
  just build-iso-nvidia-negativo17 {{rootfs}}
  just build-iso-amd {{rootfs}}
