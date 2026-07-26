#!/usr/bin/env just --justfile

proxy := env_var_or_default('HTTP_PROXY', '')
build_dir := env_var_or_default('BUILD_DIR', '/var/tmp/hypervisor-build')
local_registry := 'registry.local'
tag := `date +%Y%m%d-%H%M`
fedora_version := env_var_or_default('FEDORA_VERSION', `yq '.stable' fedora-versions.yml`)

# Rechunk an image in user storage (copies to root, rechunks, copies back)
_rechunk image:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Rechunking {{image}}..."
  podman save {{image}} | sudo podman load
  sudo podman run --rm --privileged \
    -v /var/lib/containers:/var/lib/containers \
    quay.io/fedora/fedora-bootc:rawhide \
    /usr/libexec/bootc-base-imagectl rechunk \
    {{image}} \
    {{image}}-rechunked
  sudo podman save {{image}}-rechunked | podman load
  podman tag {{image}}-rechunked {{image}}
  podman rmi {{image}}-rechunked
  sudo podman rmi {{image}} {{image}}-rechunked || true
  echo "Rechunked {{image}}"

# Install git hooks from .githooks/ into .git/hooks/
install-hooks:
  #!/usr/bin/env bash
  set -euo pipefail
  for hook in .githooks/*; do
    name=$(basename "$hook")
    install -m 0755 "$hook" ".git/hooks/$name"
    echo "installed .git/hooks/$name"
  done

# === Container image builds =================================================

build-minimal version=fedora_version rechunk="false":
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -d "manifests" ]; then
    echo "Cloning Fedora bootc manifests..."
    git clone --depth 1 https://gitlab.com/fedora/bootc/base-images.git manifests
  fi
  cp policy-local.json manifests/policy.json
  echo "Building fedora-bootc-minimal:{{version}}..."
  cd manifests
  FEDORA_VERSION={{version}} TIER=minimal BUILDER="sudo podman" \
    BUILDER_EXTRA="--network=host --env=http_proxy={{proxy}} --env=https_proxy={{proxy}}" \
    http_proxy={{proxy}} https_proxy={{proxy}} \
    just build
  cd ..
  # Upstream tags as localhost/fedora-bootc:minimal — add our tags
  sudo podman tag localhost/fedora-bootc:minimal \
    localhost/fedora-bootc-minimal:{{version}}-{{tag}} \
    localhost/fedora-bootc-minimal:{{version}} \
    localhost/fedora-bootc-minimal:latest \
    ghcr.io/bensmith/fedora-bootc-minimal:{{version}} \
    ghcr.io/bensmith/fedora-bootc-minimal:latest
  if [ "{{rechunk}}" == "true" ]; then
    echo "Rechunking image..."
    sudo podman run --rm --privileged \
      -v /var/lib/containers:/var/lib/containers \
      quay.io/fedora/fedora-bootc:{{version}} \
      /usr/libexec/bootc-base-imagectl rechunk \
      localhost/fedora-bootc-minimal:{{version}}-{{tag}} \
      localhost/fedora-bootc-minimal:rechunked
    sudo podman tag localhost/fedora-bootc-minimal:rechunked \
      localhost/fedora-bootc-minimal:{{version}}-{{tag}} \
      localhost/fedora-bootc-minimal:{{version}} \
      localhost/fedora-bootc-minimal:latest
    sudo podman rmi localhost/fedora-bootc-minimal:rechunked
  fi
  echo "Copying image to user storage..."
  sudo podman save localhost/fedora-bootc-minimal:{{version}} | podman load
  sudo podman save localhost/fedora-bootc-minimal:latest | podman load
  echo "Build complete: localhost/fedora-bootc-minimal:{{version}}"

sync-cosy:
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p bin man
  if [ -f ../cosy/src/cosy ] && [ -f ../cosy/src/cosy.1 ]; then
    cp ../cosy/src/cosy bin/cosy
    cp ../cosy/src/cosy.1 man/cosy.1
  else
    echo "Local cosy not found, fetching from GitHub..."
    curl -fsSL https://raw.githubusercontent.com/BenSmith/cosy/main/cosy -o bin/cosy
    curl -fsSL https://raw.githubusercontent.com/BenSmith/cosy/main/cosy.1 -o man/cosy.1
  fi

build-base: sync-cosy
  #!/usr/bin/env bash
  set -euo pipefail
  # Release recipe: it tags ghcr.io/bensmith/... below, so the image must ship
  # the *enforcing* policy the CI pipelines ship — "default": reject, plus
  # cosign sigstoreSigned for our own namespaces. Rendered from the same
  # template CI uses. policy-local.json ("insecureAcceptAnything" for
  # everything) belongs to build-base-local only; baking it into a
  # ghcr.io-tagged image means one `podman push` from publishing a host that
  # trusts any registry. The namespace is the canonical publish namespace,
  # matching the -t tags below and Forgejo's hardcoded OWNER.
  sed -e 's|__REGISTRY_NAMESPACE__|bensmith|g' \
      policy-hypervisor.json.template > policy.json
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
    --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
    --build-arg BASE_IMAGE=ghcr.io/bensmith/fedora-bootc-minimal:{{fedora_version}} \
    -t localhost/hypervisor-bootc:{{fedora_version}}-{{tag}} \
    -t localhost/hypervisor-bootc:{{fedora_version}} \
    -t localhost/hypervisor-bootc:latest \
    -t {{local_registry}}/hypervisor-bootc:latest \
    -t ghcr.io/bensmith/hypervisor-bootc:{{fedora_version}}-{{tag}} \
    -t ghcr.io/bensmith/hypervisor-bootc:latest \
    -f hypervisor.Containerfile .

build-base-local: sync-cosy
  #!/usr/bin/env bash
  set -euo pipefail
  cp policy-local.json policy.json
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
    --network=host \
    --from localhost/fedora-bootc-minimal:{{fedora_version}} \
    --build-arg ENABLE_PASSWORDLESS_SUDO=true \
    --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
    -t localhost/hypervisor-bootc:{{fedora_version}} \
    -t localhost/hypervisor-bootc:latest \
    -t {{local_registry}}/hypervisor-bootc:latest \
    -f hypervisor.Containerfile .

build-nvidia-rpmfusion:
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
    --pull=never \
    --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
    --build-arg BASE=localhost/hypervisor-bootc:{{fedora_version}} \
    -t localhost/hypervisor-nvidia:rpmfusion-{{fedora_version}}-{{tag}} \
    -t localhost/hypervisor-nvidia:rpmfusion-{{fedora_version}} \
    -t localhost/hypervisor-nvidia:rpmfusion \
    -t ghcr.io/bensmith/hypervisor-nvidia:rpmfusion-{{fedora_version}}-{{tag}} \
    -t ghcr.io/bensmith/hypervisor-nvidia:rpmfusion \
    -t {{local_registry}}/hypervisor-nvidia:rpmfusion \
    -f hypervisor-nvidia-rpmfusion.Containerfile .

build-nvidia-negativo17:
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
    --pull=never \
    --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
    --build-arg BASE=localhost/hypervisor-bootc:{{fedora_version}} \
    -t localhost/hypervisor-nvidia:negativo17-{{fedora_version}}-{{tag}} \
    -t localhost/hypervisor-nvidia:negativo17-{{fedora_version}} \
    -t localhost/hypervisor-nvidia:negativo17 \
    -t ghcr.io/bensmith/hypervisor-nvidia:negativo17-{{fedora_version}}-{{tag}} \
    -t ghcr.io/bensmith/hypervisor-nvidia:negativo17 \
    -t {{local_registry}}/hypervisor-nvidia:negativo17 \
    -f hypervisor-nvidia-negativo17.Containerfile .

build-amd:
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
    --pull=never \
    --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
    --build-arg BASE=localhost/hypervisor-bootc:{{fedora_version}} \
    -t localhost/hypervisor-amd:{{fedora_version}}-{{tag}} \
    -t localhost/hypervisor-amd:{{fedora_version}} \
    -t localhost/hypervisor-amd:latest \
    -t {{local_registry}}/hypervisor-amd:latest \
    -f hypervisor-amd.Containerfile .

# Local variants - build from locally-built base instead of GHCR
build-amd-local:
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
    --network=host \
    --from localhost/hypervisor-bootc:{{fedora_version}} \
    --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
    -t localhost/hypervisor-amd:{{fedora_version}} \
    -t localhost/hypervisor-amd:latest \
    -t {{local_registry}}/hypervisor-amd:latest \
    -f hypervisor-amd.Containerfile .

build-nvidia-rpmfusion-local: build-base-local
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
    --network=host \
    --from localhost/hypervisor-bootc:{{fedora_version}} \
    --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
    -t localhost/hypervisor-nvidia:rpmfusion-{{fedora_version}} \
    -t localhost/hypervisor-nvidia:rpmfusion \
    -f hypervisor-nvidia-rpmfusion.Containerfile .

build-nvidia-negativo17-local: build-base-local
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
    --network=host \
    --from localhost/hypervisor-bootc:{{fedora_version}} \
    --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
    -t localhost/hypervisor-nvidia:negativo17-{{fedora_version}} \
    -t localhost/hypervisor-nvidia:negativo17 \
    -f hypervisor-nvidia-negativo17.Containerfile .

build-all: build-base build-nvidia-rpmfusion build-nvidia-negativo17 build-amd
build-all-local: build-base-local build-amd-local build-nvidia-rpmfusion-local build-nvidia-negativo17-local

# Tag and push all locally-built images to a registry
# Usage: just local_registry=registry.local:5000 push-all
push-all:
  #!/usr/bin/env bash
  set -euo pipefail
  images=(
    hypervisor-bootc:latest
    hypervisor-amd:latest
    hypervisor-nvidia:rpmfusion
    hypervisor-nvidia:negativo17
  )
  for img in "${images[@]}"; do
    echo "Tagging and pushing ${img}..."
    podman tag "localhost/${img}" "{{local_registry}}/${img}"
    podman push "{{local_registry}}/${img}"
  done
  echo "All images pushed to {{local_registry}}"

# === Disk image builds (ISO / qcow2) ========================================

# Internal: build an anaconda ISO from a bootc image
_build-iso image subdir label iso_name rootfs:
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p {{build_dir}}/store {{build_dir}}/output/{{subdir}} {{build_dir}}/rpmmd
  echo "Pulling image..."
  sudo podman pull {{image}}
  sudo podman run \
    --privileged --pull=newer --rm \
    --security-opt label=type:unconfined_t \
    -v $(pwd)/config-iso.toml:/config.toml:ro \
    -v {{build_dir}}/output/{{subdir}}:/output \
    -v {{build_dir}}/rpmmd:/rpmmd \
    -v {{build_dir}}/store:/store \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest build \
      --chown $(id -u):$(id -g) \
      --output /output \
      --rootfs {{rootfs}} \
      --rpmmd /rpmmd \
      --store /store \
      --type anaconda-iso \
    {{image}}
  echo "Relabeling ISO..."
  just relabel-iso \
    {{build_dir}}/output/{{subdir}}/bootiso/install.iso \
    {{build_dir}}/output/{{iso_name}}-{{tag}}.iso \
    "{{label}}"
  echo "ISO ready: {{build_dir}}/output/{{iso_name}}-{{tag}}.iso (label: {{label}})"

build-iso-minimal rootfs="xfs":
  @just _build-iso ghcr.io/bensmith/fedora-bootc-minimal:latest minimal BOOTC-MIN fedora-bootc-minimal {{rootfs}}

build-iso-minimal-local rootfs="xfs":
  @just _build-iso {{local_registry}}/fedora-bootc-minimal:latest minimal BOOTC-MIN fedora-bootc-minimal {{rootfs}}

build-iso-base rootfs="xfs":
  @just _build-iso ghcr.io/bensmith/hypervisor-bootc:latest base HV-BASE hypervisor-bootc {{rootfs}}

build-iso-base-local rootfs="xfs":
  @just _build-iso {{local_registry}}/hypervisor-bootc:latest base HV-BASE hypervisor-bootc {{rootfs}}

build-iso-nvidia-rpmfusion rootfs="xfs":
  @just _build-iso ghcr.io/bensmith/hypervisor-nvidia:rpmfusion nvidia-rpmfusion HV-NV-RPMFUSION hypervisor-nvidia-rpmfusion {{rootfs}}

build-iso-nvidia-rpmfusion-local rootfs="xfs":
  @just _build-iso {{local_registry}}/hypervisor-nvidia:rpmfusion-latest nvidia-rpmfusion HV-NV-RPMFUSION hypervisor-nvidia-rpmfusion {{rootfs}}

build-iso-nvidia-negativo17 rootfs="xfs":
  @just _build-iso ghcr.io/bensmith/hypervisor-nvidia:negativo17 nvidia-negativo17 HV-NV-NEG17 hypervisor-nvidia-negativo17 {{rootfs}}

build-iso-nvidia-negativo17-local rootfs="xfs":
  @just _build-iso {{local_registry}}/hypervisor-nvidia:negativo17 nvidia-negativo17 HV-NV-NEG17 hypervisor-nvidia-negativo17 {{rootfs}}

build-iso-amd rootfs="xfs":
  @just _build-iso ghcr.io/bensmith/hypervisor-amd:latest amd HV-AMD hypervisor-amd {{rootfs}}

build-iso-amd-local rootfs="xfs":
  @just _build-iso {{local_registry}}/hypervisor-amd:latest amd HV-AMD hypervisor-amd {{rootfs}}

build-all-isos rootfs="xfs":
  #!/usr/bin/env bash
  rc=0
  just build-iso-minimal {{rootfs}} || rc=1
  just build-iso-base {{rootfs}} || rc=1
  just build-iso-nvidia-rpmfusion {{rootfs}} || rc=1
  just build-iso-nvidia-negativo17 {{rootfs}} || rc=1
  just build-iso-amd {{rootfs}} || rc=1
  exit $rc

build-all-isos-local rootfs="xfs":
  #!/usr/bin/env bash
  rc=0
  just build-iso-minimal-local {{rootfs}} || rc=1
  just build-iso-base-local {{rootfs}} || rc=1
  just build-iso-nvidia-rpmfusion-local {{rootfs}} || rc=1
  just build-iso-nvidia-negativo17-local {{rootfs}} || rc=1
  just build-iso-amd-local {{rootfs}} || rc=1
  exit $rc

# Generate config.toml for bootc-image-builder (VM user credentials)
# Reads from env vars: VM_USER (default: current user), VM_PASSWORD (default: random),
# VM_SSH_KEY (default: first key in ~/.ssh/)
_generate-vm-config:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ -f config.toml ]; then
    exit 0
  fi
  user="${VM_USER:-$(whoami)}"
  password="${VM_PASSWORD:-}"
  ssh_key="${VM_SSH_KEY:-}"
  if [ -z "$ssh_key" ]; then
    for f in ~/.ssh/id_ed25519.pub ~/.ssh/id_rsa.pub ~/.ssh/id_ecdsa.pub; do
      if [ -f "$f" ]; then
        ssh_key=$(cat "$f")
        echo "Using SSH key from $f"
        break
      fi
    done
  fi
  if [ -z "$password" ]; then
    echo "Error: VM_PASSWORD must be set (no config.toml found)"
    echo "Usage: VM_PASSWORD=mypass just <recipe>"
    exit 1
  fi
  {
    echo '[[customizations.user]]'
    echo "name = \"$user\""
    echo "password = \"$password\""
    echo 'groups = ["wheel"]'
    if [ -n "$ssh_key" ]; then
      echo "key = \"$ssh_key\""
    fi
  } > config.toml
  echo "Generated config.toml for user '$user'"

# Internal: build a qcow2 disk image from a bootc image
_build-qcow2 image rootfs size="": _generate-vm-config
  #!/usr/bin/env bash
  set -euo pipefail
  mkdir -p {{build_dir}}/store {{build_dir}}/output/qcow2 {{build_dir}}/rpmmd
  echo "Pulling image..."
  sudo podman pull {{image}}
  sudo podman run \
    --privileged --pull=newer --rm \
    --security-opt label=type:unconfined_t \
    -v $(pwd)/config.toml:/config.toml:ro \
    -v {{build_dir}}/output/qcow2:/output \
    -v {{build_dir}}/rpmmd:/rpmmd \
    -v {{build_dir}}/store:/store \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    quay.io/centos-bootc/bootc-image-builder:latest build \
      --chown $(id -u):$(id -g) \
      --output /output \
      --rootfs {{rootfs}} \
      --rpmmd /rpmmd \
      --store /store \
      --type qcow2 \
    {{image}}
  if [ -n "{{size}}" ]; then
    echo "Resizing disk to {{size}}..."
    qemu-img resize {{build_dir}}/output/qcow2/qcow2/disk.qcow2 {{size}}
  fi
  echo "QCOW2 ready: {{build_dir}}/output/qcow2/qcow2/disk.qcow2"
  echo "To use: sudo cp {{build_dir}}/output/qcow2/qcow2/disk.qcow2 /var/lib/libvirt/images/hypervisor-{{tag}}.qcow2"

build-qcow2-base rootfs="xfs":
  @just _build-qcow2 ghcr.io/bensmith/hypervisor-bootc:latest {{rootfs}}

build-qcow2-base-local rootfs="xfs" size="20G":
  @just _build-qcow2 {{local_registry}}/hypervisor-bootc:latest {{rootfs}} {{size}}

# === Relabel ISO ============================================================

relabel-iso input output label:
  #!/usr/bin/env bash
  set -euo pipefail
  echo "Relabeling {{input}} -> {{output}} with label '{{label}}'"
  TMPDIR=$(mktemp -d)
  trap "sudo rm -rf $TMPDIR" EXIT
  MOUNT_DIR="$TMPDIR/mount"
  mkdir -p "$MOUNT_DIR"
  sudo mount -o loop,ro "{{input}}" "$MOUNT_DIR"
  WORK_DIR="$TMPDIR/iso"
  mkdir -p "$WORK_DIR"
  sudo cp -a "$MOUNT_DIR"/* "$WORK_DIR/" 2>/dev/null || true
  sudo cp -a "$MOUNT_DIR"/.[!.]* "$WORK_DIR/" 2>/dev/null || true
  sudo umount "$MOUNT_DIR"
  ORIG_LABEL=$(isoinfo -d -i "{{input}}" | grep "Volume id:" | sed 's/Volume id: //')
  echo "Original label: $ORIG_LABEL"
  echo "New label: {{label}}"
  for grub_cfg in "$WORK_DIR/boot/grub2/grub.cfg" "$WORK_DIR/EFI/BOOT/grub.cfg"; do
    if [ -f "$grub_cfg" ]; then
      echo "Updating $grub_cfg..."
      sudo sed -i "s/$ORIG_LABEL/{{label}}/g" "$grub_cfg"
    fi
  done
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
  sudo chown $(id -u):$(id -g) "{{output}}"
  echo "ISO relabeled successfully: {{output}}"

# === All-in-one local dev ===================================================

aio-local vmname="hypervisor-test" memory="4096" vcpus="2" rootfs="xfs" size="20G":
  #!/usr/bin/env bash
  set -euo pipefail
  echo "=== Step 1: Building container image ==="
  just build-base-local

  echo ""
  echo "=== Step 1.5: Pushing image to local registry ==="
  podman push {{local_registry}}/hypervisor-bootc:latest

  echo ""
  echo "=== Step 2: Building qcow2 disk image ==="
  just build-qcow2-base-local {{rootfs}} {{size}}

  echo ""
  echo "=== Step 3: Deploying to VM '{{vmname}}' ==="
  sudo mkdir -p /var/lib/libvirt/images
  sudo cp {{build_dir}}/output/qcow2/qcow2/disk.qcow2 /var/lib/libvirt/images/{{vmname}}-{{tag}}.qcow2

  if sudo virsh dominfo {{vmname}} &>/dev/null; then
    echo "Destroying existing VM '{{vmname}}'..."
    sudo virsh destroy {{vmname}} 2>/dev/null || true
    sudo virsh undefine {{vmname}}
  fi

  echo "Creating VM '{{vmname}}' ({{memory}}MB RAM, {{vcpus}} vCPUs)..."
  sudo virt-install \
    --name {{vmname}} \
    --memory {{memory}} \
    --vcpus {{vcpus}} \
    --disk path=/var/lib/libvirt/images/{{vmname}}-{{tag}}.qcow2,format=qcow2 \
    --import \
    --os-variant fedora41 \
    --network network=default \
    --graphics spice,gl.enable=yes,listen=none \
    --video virtio \
    --noautoconsole

  echo ""
  echo "=== Waiting for VM to boot and obtain IP address ==="
  timeout=60
  elapsed=0
  ip_addr=""
  while [ $elapsed -lt $timeout ]; do
    sleep 2
    elapsed=$((elapsed + 2))
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

# === Tests ==================================================================

test:
  cd workloadctl && just test

test-unit:
  cd workloadctl && just test-unit

test-integration:
  cd workloadctl && just test-integration

# Run CLI-surface acceptance harness (all verbs, both substrates)
test-cli target:
  cd workloadctl && just test-cli {{target}}

# CLI surface — container substrate only (no VM boot; much faster)
test-cli-containers target:
  cd workloadctl && just test-cli-containers {{target}}

# CLI surface — VM substrate only (requires /dev/kvm on target)
test-cli-vm target:
  cd workloadctl && just test-cli-vm {{target}}

# CLI surface — deploy current tree to target first, then run all tests
test-cli-deploy target:
  cd workloadctl && just test-cli-deploy {{target}}

# Full KVM-host verification sweep — CLI surface + runtime rung (dev + gate).
# Run ON a KVM host (boots QEMU locally); target defaults to `local`.
test-all-runtime target="local":
  cd workloadctl && just test-all-runtime {{target}}

# As above, driven from your laptop against a REMOTE prepared KVM host (e.g. tp):
# rsync the tree over, run the sweep there, stream output back.
test-all-runtime-remote host target="local":
  cd workloadctl && just test-all-runtime-remote {{host}} {{target}}

# Build workloadctl RPM
workload-rpm:
  cd workloadctl && just rpm-build
