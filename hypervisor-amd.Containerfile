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

# Copied into every image that needs it rather than inherited from the base:
# the variant `FROM` is a published registry tag, so a variant-only
# workflow_dispatch can build against a base predating this file. A COPY from
# the repo (all four builds share this build context) cannot go stale that way.
COPY security/selinux-store-copyup /usr/libexec/hypervisor-build/selinux-store-copyup
COPY security/selinux-store-verify /usr/libexec/hypervisor-build/selinux-store-verify

# Install AMD GPU support (ROCm for compute, Mesa for graphics)
RUN /usr/libexec/hypervisor-build/selinux-store-copyup && \
    dnf install -y \
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

# Assert the policy store holds every module the installed packages ship. A
# failed semodule inside a %post does not fail the transaction, so without this
# a build can go green having silently dropped policy. Runs before the lint: a
# store defect should report itself, not surface later as something else.
RUN /usr/libexec/hypervisor-build/selinux-store-verify

# AMD GPUs work with podman automatically via CDI
RUN mkdir -p /etc/cdi && \
    bootc container lint --fatal-warnings \
        --skip var-tmpfiles --skip var-log --skip nonempty-run-tmp
# ^ Same exemptions as the base image; see the comment on the lint call in
# hypervisor.Containerfile for why each is skipped and why warnings are fatal.

# rocm-smi tries to use libdrm_amdgpu.so, this is a workaround to provide it
RUN ln -s /usr/lib64/libdrm_amdgpu.so.1 /usr/lib64/libdrm_amdgpu.so

LABEL org.opencontainers.image.title="Hypervisor Bootc Image - AMD GPU"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with AMD GPU support (ROCm)"
