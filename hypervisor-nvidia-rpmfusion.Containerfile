FROM ghcr.io/bensmith/hypervisor-bootc:latest

# Add RPMFusion repositories for NVIDIA proprietary drivers
RUN dnf install -y \
    https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm \
    https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm

# Add NVIDIA official container toolkit repository
RUN curl -s -L https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo | \
    tee /etc/yum.repos.d/nvidia-container-toolkit.repo

# Install NVIDIA drivers and tools, headless
RUN dnf install --setopt=install_weak_deps=False -y \
    akmod-nvidia \
    nvidia-modprobe \
    nvidia-persistenced \
    xorg-x11-drv-nvidia-cuda-libs \
    nvidia-container-toolkit && \
    dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* /boot/*

# Generate CDI specification for nvidia-container-toolkit (modern approach for podman/crun)
RUN mkdir -p /etc/cdi && \
    systemctl enable nvidia-persistenced && \
    bootc container lint

# Define required labels for this bootc image to be recognized as such
LABEL containers.bootc 1
LABEL ostree.bootable 1
LABEL org.opencontainers.image.title="Hypervisor Bootc Image - NVIDIA (RPMFusion)"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with NVIDIA GPU support via RPMFusion (driver 580.105.08)"

# https://pagure.io/fedora-kiwi-descriptions/pull-request/52
ENV container=oci

# Optional labels that only apply when running this image as a container. These keep the default entry point running under systemd.
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
