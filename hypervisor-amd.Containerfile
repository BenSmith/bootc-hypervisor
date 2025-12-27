FROM ghcr.io/bensmith/hypervisor-bootc:latest

# Install AMD GPU support (ROCm for compute, Mesa for graphics)
RUN dnf clean all && \
    dnf install --setopt=install_weak_deps=False -y \
    elfutils-libelf \
    linux-firmware \
    linux-firmware-whence \
    amd-gpu-firmware \
    rocm-hip \
    rocm-opencl \
    rocm-smi && \
    dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* /boot/*

# Add AMD-specific device access rules (extends base hypervisor rules)
# ROCm KFD device for AI workloads
RUN printf '# AMD ROCm KFD device - world accessible for AI workloads\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'SUBSYSTEM=="kfd", KERNEL=="kfd", MODE="0666"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules

# AMD GPUs work with podman automatically via CDI
RUN mkdir -p /etc/cdi && \
    bootc container lint

# rocm-smi tries to use libdrm_amdgpu.so, this is a workaround to provide it
RUN ln -s /usr/lib64/libdrm_amdgpu.so.1 /usr/lib64/libdrm_amdgpu.so

# Define required labels for this bootc image to be recognized as such
LABEL containers.bootc 1
LABEL ostree.bootable 1
LABEL org.opencontainers.image.title="Hypervisor Bootc Image - AMD GPU"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with AMD GPU support (ROCm)"

# https://pagure.io/fedora-kiwi-descriptions/pull-request/52
ENV container=oci

# Optional labels that only apply when running this image as a container. These keep the default entry point running under systemd.
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
