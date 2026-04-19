ARG BASE=ghcr.io/bensmith/hypervisor-bootc:latest
ARG BASE_DIGEST=""

# Stage 1: Build the NVIDIA kernel module RPM
FROM ${BASE}${BASE_DIGEST:+@${BASE_DIGEST}} AS kmod-builder

RUN curl -s -L https://negativo17.org/repos/fedora-nvidia.repo \
    -o /etc/yum.repos.d/fedora-nvidia.repo

RUN KERNEL_VERSION=$(rpm -q kernel --qf '%{version}-%{release}.%{arch}\n' | tail -1) && \
    dnf install --setopt=install_weak_deps=False -y \
        akmod-nvidia \
        "kernel-devel-${KERNEL_VERSION}" && \
    dnf clean all

RUN mkdir -p /var/log/akmods && \
    chmod 1777 /tmp /var/tmp && \
    KERNEL_VERSION=$(rpm -q kernel --qf '%{version}-%{release}.%{arch}\n' | tail -1) && \
    akmods --force --kernels "${KERNEL_VERSION}" && \
    find /var/cache/akmods -name '*.rpm' | tee /dev/stderr | grep -q . || \
        { find /var/cache/akmods -name '*.failed.log' -exec cat {} +; exit 1; }

# Stage 2: Final bootc image
FROM ${BASE}${BASE_DIGEST:+@${BASE_DIGEST}}

# Add negativo17 NVIDIA repository (modular alternative to RPMFusion)
RUN curl -s -L https://negativo17.org/repos/fedora-nvidia.repo \
    -o /etc/yum.repos.d/fedora-nvidia.repo

# Add NVIDIA official container toolkit repository
RUN curl -s -L https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo | \
    tee /etc/yum.repos.d/nvidia-container-toolkit.repo

# Install NVIDIA drivers and tools, headless
RUN dnf install --setopt=install_weak_deps=False -y \
    nvidia-container-toolkit \
    nvidia-driver \
    nvidia-driver-cuda \
    nvidia-driver-cuda-libs \
    nvidia-gpu-firmware \
    nvidia-modprobe \
    nvidia-persistenced && \
    dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* /boot/*

# Install pre-built kmod RPM from builder stage
COPY --from=kmod-builder /var/cache/akmods/ /tmp/akmods/
RUN find /tmp/akmods -name '*.rpm' -exec rpm -ivh {} + && \
    rm -rf /tmp/akmods

# Blacklist nouveau and configure proprietary driver for KMS/Wayland
RUN echo -e "blacklist nouveau\noptions nouveau modeset=0" \
    > /etc/modprobe.d/blacklist-nouveau.conf && \
    echo -e "options nvidia-drm modeset=1 fbdev=1\noptions nvidia NVreg_PreserveVideoMemoryAllocations=1" \
    > /etc/modprobe.d/nvidia-kms.conf

# Generate CDI specification for nvidia-container-toolkit (modern approach for podman/crun)
# Install service to generate CDI spec on first boot
COPY systemd/nvidia-cdi-generator.service /etc/systemd/system/nvidia-cdi-generator.service
RUN mkdir -p /etc/cdi && \
    systemctl enable nvidia-persistenced && \
    systemctl enable nvidia-cdi-generator.service && \
    bootc container lint

LABEL org.opencontainers.image.title="Hypervisor Bootc Image - NVIDIA (negativo17)"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with NVIDIA GPU support via negativo17 repository"
