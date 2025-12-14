#!/usr/bin/env just --justfile

# Proxy configuration - uses HTTP_PROXY env var if set, otherwise no proxy
proxy := env_var_or_default('HTTP_PROXY', '')

# Time-based tag: YYYYMMDD-HHMM (e.g., 20250213-1430)
tag := `date +%Y%m%d-%H%M`

echo:
  echo "http_proxy={{proxy}} https_proxy={{proxy}} podman build --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} --cap-add=all --security-opt=label=type:container_runtime_t --device /dev/fuse -f bootc.minimal.Dockerfile -t bootsey:latest ."

build-base:
  http_proxy={{proxy}} https_proxy={{proxy}} podman build --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} -t localhost/hypervisor-bootc:{{tag}} -t localhost/hypervisor-bootc:latest -t ghcr.io/bensmith/hypervisor-bootc:{{tag}} -t ghcr.io/bensmith/hypervisor-bootc:latest -f hypervisor.Containerfile .

build-nvidia-rpmfusion: build-base
  http_proxy={{proxy}} https_proxy={{proxy}} podman build --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} -t localhost/hypervisor-nvidia:rpmfusion-{{tag}} -t localhost/hypervisor-nvidia:rpmfusion -f hypervisor-nvidia-rpmfusion.Containerfile .

build-nvidia-negativo17: build-base
  http_proxy={{proxy}} https_proxy={{proxy}} podman build --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} -t localhost/hypervisor-nvidia:negativo17-{{tag}} -t localhost/hypervisor-nvidia:negativo17 -f hypervisor-nvidia-negativo17.Containerfile .

build-amd: build-base
  http_proxy={{proxy}} https_proxy={{proxy}} podman build --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} -t localhost/hypervisor-amd:{{tag}} -t localhost/hypervisor-amd:latest -f hypervisor-amd.Containerfile .

build-all: build-base build-nvidia-rpmfusion build-nvidia-negativo17 build-amd

build-iso-base:
  @mkdir -p output/base
  @echo "Copying image to rootful storage..."
  podman save localhost/hypervisor-bootc:latest | sudo podman load
  sudo podman run --rm --privileged \
    --security-opt label=type:unconfined_t \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    -v $(pwd)/output/base:/output \
    quay.io/centos-bootc/bootc-image-builder:latest \
    build --type iso --rootfs xfs --output /output \
    localhost/hypervisor-bootc:latest
  @echo "Renaming ISO..."
  @cp output/base/bootiso/install.iso output/hypervisor-bootc-{{tag}}.iso
  @echo "ISO ready: output/hypervisor-bootc-{{tag}}.iso"

# Build ISO installer for NVIDIA RPMFusion variant
build-iso-nvidia-rpmfusion:
  @mkdir -p output/nvidia-rpmfusion
  @echo "Copying image to rootful storage..."
  podman save localhost/hypervisor-nvidia:rpmfusion | sudo podman load
  sudo podman run --rm --privileged \
    --security-opt label=type:unconfined_t \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    -v $(pwd)/output/nvidia-rpmfusion:/output \
    quay.io/centos-bootc/bootc-image-builder:latest \
    build --type iso --rootfs xfs --output /output \
    localhost/hypervisor-nvidia:rpmfusion
  @echo "Renaming ISO..."
  @cp output/nvidia-rpmfusion/bootiso/install.iso output/hypervisor-nvidia-rpmfusion-{{tag}}.iso
  @echo "ISO ready: output/hypervisor-nvidia-rpmfusion-{{tag}}.iso"

# Build ISO installer for NVIDIA negativo17 variant
build-iso-nvidia-negativo17:
  @mkdir -p output/nvidia-negativo17
  @echo "Copying image to rootful storage..."
  podman save localhost/hypervisor-nvidia:negativo17 | sudo podman load
  sudo podman run --rm --privileged \
    --security-opt label=type:unconfined_t \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    -v $(pwd)/output/nvidia-negativo17:/output \
    quay.io/centos-bootc/bootc-image-builder:latest \
    build --type iso --rootfs xfs --output /output \
    localhost/hypervisor-nvidia:negativo17
  @echo "Renaming ISO..."
  @cp output/nvidia-negativo17/bootiso/install.iso output/hypervisor-nvidia-negativo17-{{tag}}.iso
  @echo "ISO ready: output/hypervisor-nvidia-negativo17-{{tag}}.iso"

build-iso-amd:
  @mkdir -p output/amd
  @echo "Copying image to rootful storage..."
  podman save localhost/hypervisor-amd:latest | sudo podman load
  sudo podman run --rm --privileged \
    --security-opt label=type:unconfined_t \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    -v $(pwd)/output/amd:/output \
    quay.io/centos-bootc/bootc-image-builder:latest \
    build --type iso --rootfs xfs --output /output \
    localhost/hypervisor-amd:latest
  @echo "Renaming ISO..."
  @cp output/amd/bootiso/install.iso output/hypervisor-amd-{{tag}}.iso
  @echo "ISO ready: output/hypervisor-amd-{{tag}}.iso"

# Build all ISOs
build-all-isos: build-iso-base build-iso-nvidia-rpmfusion build-iso-nvidia-negativo17 build-iso-amd
