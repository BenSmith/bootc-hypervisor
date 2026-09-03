ARG BASE=ghcr.io/bensmith/hypervisor-bootc:latest
ARG BASE_DIGEST=""

# Stage 1: Build the NVIDIA kernel module RPM
FROM ${BASE}${BASE_DIGEST:+@${BASE_DIGEST}} AS kmod-builder

RUN dnf install -y \
    https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm \
    https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm

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

# Add RPMFusion repositories for NVIDIA proprietary drivers
RUN dnf install -y \
    https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm \
    https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm

# Add NVIDIA official container toolkit repository
RUN curl -s -L https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo | \
    sed '/^sslcacert=/d' | \
    tee /etc/yum.repos.d/nvidia-container-toolkit.repo

# Copied into every image that needs it rather than inherited from the base:
# the variant `FROM` is a published registry tag, so a variant-only
# workflow_dispatch can build against a base predating this file. A COPY from
# the repo (all four builds share this build context) cannot go stale that way.
COPY security/selinux-store-copyup /usr/libexec/hypervisor-build/selinux-store-copyup
COPY security/selinux-store-verify /usr/libexec/hypervisor-build/selinux-store-verify

# Install NVIDIA drivers and tools, headless
RUN /usr/libexec/hypervisor-build/selinux-store-copyup && \
    dnf install --setopt=install_weak_deps=False -y \
    nvidia-container-toolkit \
    nvidia-gpu-firmware \
    nvidia-modprobe \
    nvidia-persistenced \
    xorg-x11-drv-nvidia \
    xorg-x11-drv-nvidia-cuda \
    xorg-x11-drv-nvidia-cuda-libs \
    xorg-x11-drv-nvidia-libs && \
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

# SELinux: let containers use the NVIDIA device nodes. The base image grants no
# device access host-wide (see the SELinux block in hypervisor.Containerfile);
# this is the one place where blanket access to a device type is the image's
# whole purpose, so it is on by default here and nowhere else.
#
# xserver_misc_device_t is what /dev/nvidia*, nvidiactl, nvidia-uvm{,-tools} and
# nvidia-caps/* are labelled — the complete device surface of the CDI spec, the
# rest of which is dri_device_t and already allowed. Note the stock boolean is
# written against container_t, NOT the container_domain attribute, so it does
# not reach udica-derived wl_<name>.process types; workloads with their own
# policy.cil state the grant themselves (vncdesktop-sway, vncdesktop-wayfire,
# sunshine-streaming do).
RUN /usr/libexec/hypervisor-build/selinux-store-copyup && \
    setsebool -P container_use_xserver_devices on

# Assert the policy store holds every module the installed packages ship. A
# failed semodule inside a %post does not fail the transaction, so without this
# a build can go green having silently dropped policy. Runs before the lint: a
# store defect should report itself, not surface later as something else.
RUN /usr/libexec/hypervisor-build/selinux-store-verify

# Generate CDI specification for nvidia-container-toolkit (modern approach for podman/crun)
# Install service to generate CDI spec on first boot
COPY systemd/nvidia-cdi-generator.service /etc/systemd/system/nvidia-cdi-generator.service
RUN systemctl enable nvidia-persistenced && \
    systemctl enable nvidia-cdi-generator.service && \
    bootc container lint --fatal-warnings \
        --skip var-tmpfiles --skip var-log --skip nonempty-run-tmp
# ^ Same exemptions as the base image; see the comment on the lint call in
# hypervisor.Containerfile for why each is skipped and why warnings are fatal.

LABEL org.opencontainers.image.title="Hypervisor Bootc Image - NVIDIA (RPMFusion)"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with NVIDIA GPU support via RPMFusion"
