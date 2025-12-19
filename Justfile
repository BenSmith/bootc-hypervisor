#!/usr/bin/env just --justfile

proxy := env_var_or_default('HTTP_PROXY', '')

tag := `date +%Y%m%d-%H%M`

build-base:
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-bootc:{{tag}} \
  -t localhost/hypervisor-bootc:latest \
  -t ghcr.io/bensmith/hypervisor-bootc:{{tag}} \
  -t ghcr.io/bensmith/hypervisor-bootc:latest \
  -f hypervisor.Containerfile .

build-nvidia-rpmfusion: build-base
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-nvidia:rpmfusion-{{tag}} \
  -t localhost/hypervisor-nvidia:rpmfusion \
  -t ghcr.io/bensmith/hypervisor-nvidia:rpmfusion-{{tag}} \
  -t ghcr.io/bensmith/hypervisor-nvidia:rpmfusion \
  -f hypervisor-nvidia-rpmfusion.Containerfile .

build-nvidia-negativo17: build-base
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-nvidia:negativo17-{{tag}} \
  -t localhost/hypervisor-nvidia:negativo17 \
  -t ghcr.io/bensmith/hypervisor-nvidia:negativo17-{{tag}} \
  -t ghcr.io/bensmith/hypervisor-nvidia:negativo17 \
  -f hypervisor-nvidia-negativo17.Containerfile .

build-amd: build-base
  http_proxy={{proxy}} https_proxy={{proxy}} \
  podman build \
  --env=http_proxy={{proxy}} --env=https_proxy={{proxy}} \
  -t localhost/hypervisor-amd:{{tag}} \
  -t localhost/hypervisor-amd:latest \
  -f hypervisor-amd.Containerfile .

build-all: build-base build-nvidia-rpmfusion build-nvidia-negativo17 build-amd

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
  @echo "Renaming ISO..."
  @cp output/base/bootiso/install.iso output/hypervisor-bootc-{{tag}}.iso
  @echo "ISO ready: output/hypervisor-bootc-{{tag}}.iso"

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
  @echo "Renaming ISO..."
  @cp output/nvidia-rpmfusion/bootiso/install.iso output/hypervisor-nvidia-rpmfusion-{{tag}}.iso
  @echo "ISO ready: output/hypervisor-nvidia-rpmfusion-{{tag}}.iso"

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
  @echo "Renaming ISO..."
  @cp output/nvidia-negativo17/bootiso/install.iso output/hypervisor-nvidia-negativo17-{{tag}}.iso
  @echo "ISO ready: output/hypervisor-nvidia-negativo17-{{tag}}.iso"

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
  @echo "Renaming ISO..."
  @cp output/amd/bootiso/install.iso output/hypervisor-amd-{{tag}}.iso
  @echo "ISO ready: output/hypervisor-amd-{{tag}}.iso"

build-all-isos rootfs="xfs":
  just build-iso-base {{rootfs}}
  just build-iso-nvidia-rpmfusion {{rootfs}}
  just build-iso-nvidia-negativo17 {{rootfs}}
  just build-iso-amd {{rootfs}}
