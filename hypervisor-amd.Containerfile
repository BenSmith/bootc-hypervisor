FROM ghcr.io/bensmith/hypervisor-bootc:latest

# Install AMD GPU support (ROCm for compute, Mesa for graphics)
RUN dnf install --setopt=install_weak_deps=False -y \
    rocm-hip \
    rocm-opencl \
    rocm-smi \
    mesa-vulkan-drivers \
    mesa-va-drivers \
    libva-utils && \
    dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* /boot/*

# AMD GPUs work with podman automatically via CDI
RUN mkdir -p /etc/cdi && \
    bootc container lint

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
