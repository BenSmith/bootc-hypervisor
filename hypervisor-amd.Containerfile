ARG BASE=ghcr.io/bensmith/hypervisor-bootc:latest
ARG BASE_DIGEST=""

FROM ${BASE}${BASE_DIGEST:+@${BASE_DIGEST}}

# Install core dependencies that ROCm needs (missing from minimal base)
RUN dnf install -y \
    libdrm \
    elfutils-libelf \
    libgcc \
    numactl-libs \
    python3 && \
    dnf clean all

# Install AMD GPU support (ROCm for compute, Mesa for graphics)
RUN dnf install -y \
    linux-firmware \
    linux-firmware-whence \
    amd-gpu-firmware \
    rocm-hip \
    rocm-opencl \
    rocm-smi && \
    dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* /boot/*

# ROCm KFD device for AI workloads - render group access
RUN printf '# AMD ROCm KFD device - render group access for AI workloads\n' > /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'SUBSYSTEM=="kfd", KERNEL=="kfd", GROUP="render", MODE="0660"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules

# AMD GPUs work with podman automatically via CDI
RUN mkdir -p /etc/cdi && \
    bootc container lint

# rocm-smi tries to use libdrm_amdgpu.so, this is a workaround to provide it
RUN ln -s /usr/lib64/libdrm_amdgpu.so.1 /usr/lib64/libdrm_amdgpu.so

LABEL org.opencontainers.image.title="Hypervisor Bootc Image - AMD GPU"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with AMD GPU support (ROCm)"
