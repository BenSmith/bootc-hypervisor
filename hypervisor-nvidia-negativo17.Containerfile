FROM ghcr.io/bensmith/hypervisor-bootc:latest

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
    nvidia-gpu-firmware \
    nvidia-modprobe \
    nvidia-persistenced && \
    dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* /boot/*

# Add NVIDIA-specific device access rules (extends base hypervisor rules)
# NVIDIA devices need special permissions for rootless containers
RUN printf '# NVIDIA GPU devices - group accessible\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'KERNEL=="nvidia[0-9]*", MODE="0666"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'KERNEL=="nvidiactl", MODE="0666"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'KERNEL=="nvidia-uvm", MODE="0666"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'KERNEL=="nvidia-uvm-tools", MODE="0666"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'KERNEL=="nvidia-modeset", MODE="0666"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules

# Generate CDI specification for nvidia-container-toolkit (modern approach for podman/crun)
RUN mkdir -p /etc/cdi && \
    systemctl enable nvidia-persistenced && \
    bootc container lint

# Define required labels for this bootc image to be recognized as such
LABEL containers.bootc 1
LABEL ostree.bootable 1
LABEL org.opencontainers.image.title="Hypervisor Bootc Image - NVIDIA (negativo17)"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with NVIDIA GPU support via negativo17 repository"

# https://pagure.io/fedora-kiwi-descriptions/pull-request/52
ENV container=oci

# Optional labels that only apply when running this image as a container. These keep the default entry point running under systemd.
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
