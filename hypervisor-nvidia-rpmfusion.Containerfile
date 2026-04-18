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
    nvidia-container-toolkit \
    nvidia-gpu-firmware \
    nvidia-modprobe \
    nvidia-persistenced && \
    dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* /boot/*

# Generate CDI specification for nvidia-container-toolkit (modern approach for podman/crun)
# Install service to generate CDI spec on first boot
COPY systemd/nvidia-cdi-generator.service /etc/systemd/system/nvidia-cdi-generator.service
RUN mkdir -p /etc/cdi && \
    systemctl enable nvidia-persistenced && \
    systemctl enable nvidia-cdi-generator.service && \
    bootc container lint

LABEL org.opencontainers.image.title="Hypervisor Bootc Image - NVIDIA (RPMFusion)"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with NVIDIA GPU support via RPMFusion"
