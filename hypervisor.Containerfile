FROM ghcr.io/bensmith/fedora-bootc-minimal:latest

# Build argument for local development (enables passwordless sudo)
ARG ENABLE_PASSWORDLESS_SUDO=false

LABEL org.opencontainers.image.title="Hypervisor Bootc Image"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with podman/lxc/libvirt/QEMU/KVM"

COPY --link policy.json /etc/containers/policy.json
COPY --link security/pwquality-no-dictionary.conf /etc/security/pwquality.conf.d/no-dictionary.conf

# Break ostree hardlinks on rpmdb: fuse-overlayfs preserves hardlinks during
# copy-up, so modifying rpmdb.sqlite also propagates to the ostree object and
# rpm-ostree base-db (which share the same lower inode). This corrupts the
# database. Breaking the hardlink first ensures only the live db is copied up.
RUN cp /usr/share/rpm/rpmdb.sqlite /usr/share/rpm/rpmdb.sqlite.tmp && \
    mv /usr/share/rpm/rpmdb.sqlite.tmp /usr/share/rpm/rpmdb.sqlite

# the pcp and gssproxy bootc lint warnings are because these packages (upon which others depend)
# store data in /var/lib, and bootc would prefer they're in /usr/lib
RUN dnf install --setopt=install_weak_deps=False --nodocs -y \
    alsa-sof-firmware \
    amd-ucode-firmware \
    atheros-firmware \
    attr \
    audit \
    bash-completion \
    bind-utils \
    brcmfmac-firmware \
    bridge-utils \
    btop \
    btrfs-progs \
    cifs-utils \
    criu \
    criu-libs \
    crun \
    cryptsetup \
    curl \
    distrobox \
    dmidecode \
    dnsmasq \
    dosfstools \
    e2fsprogs \
    efibootmgr \
    ethtool \
    exfatprogs \
    fail2ban \
    firewalld \
    fwupd \
    grub2 \
    grub2-efi-x64 \
    hdparm \
    hostname \
    htop \
    hwloc \
    incus \
    incus-tools \
    intel-audio-firmware \
    intel-gpu-firmware \
    iotop \
    iperf3 \
    iproute \
    iptables-nft \
    iputils \
    iwlwifi-mld-firmware \
    iwlwifi-mvm-firmware \
    jq \
    just \
    less \
    libbpf-tools \
    libtpms \
    libvirt-client \
    libvirt-daemon \
    libvirt-daemon-config-network \
    libvirt-daemon-kvm \
    libvirt-dbus \
    linux-firmware \
    lm_sensors \
    lshw \
    lsof \
    lsscsi \
    lvm2 \
    mdadm \
    mdevctl \
    mediatek-firmware \
    microcode_ctl \
    mt7xxx-firmware \
    mtr \
    nano \
    nc \
    neovim \
    NetworkManager \
    NetworkManager-wifi \
    numactl \
    nvme-cli \
    nxpwireless-firmware \
    openssh-clients \
    openssh-server \
    openssl \
    parted \
    pciutils \
    perf \
    podman \
    podman-compose \
    podman-docker \
    policycoreutils-python-utils \
    polkit \
    powertop \
    qemu-img \
    qemu-kvm \
    rasdaemon \
    realtek-firmware \
    rpm-ostree \
    rsync \
    samba-client \
    seatd \
    shim \
    skopeo \
    smartmontools \
    sos \
    strace \
    sudo \
    sysstat \
    tar \
    tcpdump \
    tmux \
    traceroute \
    tuned \
    tzdata \
    usbutils \
    virglrenderer \
    virt-install \
    virt-top \
    wget \
    wireguard-tools \
    wpa_supplicant \
    xfsprogs \
    zram-generator && \
    dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* && \
    rm -rf /boot && mkdir -p /boot && \
    systemctl enable firewalld && \
    systemctl enable libvirtd && \
    systemctl enable incus.socket && \
    systemctl enable seatd && \
    systemctl enable sshd && \
    systemctl enable tuned && \
    find /var -type f \
        -not -path '/var/lib/gssproxy/*' \
        -not -path '/var/lib/pcp/*' \
        -not -path '/var/lib/rpm-state/*' \
        -not -path '/var/lib/rpm/*' \
        -delete && \
    find /var -depth -type d -empty -delete && \
    bootc container lint || echo "Note: Some /var warnings expected from gssproxy/pcp/rpm packages"

# Ensure device access groups exist, propagate to /etc/group, set privileged port sysctl.
# /usr/lib/group is immutable on bootc; /etc/group is mutable and needed for usermod.
# Groups: audio, dialout, disk, input, kvm, render, seat, tpm, video
RUN printf 'g seat - -\n' >> /usr/lib/sysusers.d/hypervisor-groups.conf && \
    printf 'g tpm - -\n' >> /usr/lib/sysusers.d/hypervisor-groups.conf && \
    grep -E "^(video|render|input|audio|dialout|disk|kvm|seat|tpm):" /usr/lib/group >> /etc/group || true && \
    echo 'net.ipv4.ip_unprivileged_port_start = 0' > /usr/lib/sysctl.d/50-privileged-ports.conf && \
    semanage fcontext -a -t container_file_t '/var/lib/prometheus/node-exporter(/.*)?' || true

# SELinux: allow containers to connect to host seatd socket (KMS desktop workloads)
# and allow containers to access host devices (GPU, input)
RUN setsebool -P container_use_devices on

COPY --link security/seatd_container.te /tmp/seatd_container.te
RUN rm -rf /etc/selinux/targeted/tmp /etc/selinux/targeted/previous 2>/dev/null; \
    checkmodule -M -m -o /tmp/seatd_container.mod /tmp/seatd_container.te && \
    semodule_package -o /tmp/seatd_container.pp -m /tmp/seatd_container.mod && \
    semodule -i /tmp/seatd_container.pp && \
    rm -f /tmp/seatd_container.te /tmp/seatd_container.mod /tmp/seatd_container.pp

# Optional: Enable passwordless sudo for local development
# Enabled with: podman build --build-arg ENABLE_PASSWORDLESS_SUDO=true
RUN if [ "$ENABLE_PASSWORDLESS_SUDO" = "true" ]; then \
        echo '%wheel ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/wheel-nopasswd && \
        chmod 0440 /etc/sudoers.d/wheel-nopasswd; \
    fi

# Install workload provisioning system
COPY --link lib/workload_lib.py /tmp/workload_lib.py
RUN mkdir -p "$(python3 -c 'import sysconfig; print(sysconfig.get_path("purelib"))')" && \
    install -m 0644 /tmp/workload_lib.py \
        "$(python3 -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"/workload_lib.py && \
    rm /tmp/workload_lib.py
COPY --link generators/workload-generator-wrapper /usr/lib/systemd/system-generators/workload-generator
COPY --link generators/workload-generate /usr/libexec/
COPY --link systemd/workloads-dirs.conf /usr/lib/tmpfiles.d/workloads-dirs.conf
COPY --link systemd/emergency-access.conf /usr/lib/systemd/system/emergency.target.d/emergency-access.conf
COPY --link libexec/workload-ensure-user /usr/libexec/
COPY --link libexec/workload-write-env /usr/libexec/
COPY --link libexec/workload-metrics /usr/libexec/
COPY --link systemd/workload-metrics.service /usr/lib/systemd/system/
COPY --link systemd/workload-metrics.timer /usr/lib/systemd/system/
COPY --link bin/workload-ctl /usr/bin/
COPY --link bin/cosy /usr/bin/
COPY --link man/cosy.1 /usr/share/man/man1/cosy.1
COPY --link completions/workload-ctl-completion.bash /usr/share/bash-completion/completions/workload-ctl
COPY --link docs/workloads.md /usr/share/doc/workload-ctl/
COPY --link workloads.d/schema-reference.toml /usr/share/doc/workload-ctl/
COPY --link containers/ /usr/share/workload-containers/
COPY --link seccomp-workload-baseline.json /usr/share/containers/

RUN chmod 0755 /usr/lib/systemd/system-generators/workload-generator && \
    chmod 0755 /usr/libexec/workload-generate && \
    chmod 0755 /usr/libexec/workload-ensure-user && \
    chmod 0755 /usr/libexec/workload-write-env && \
    chmod 0755 /usr/libexec/workload-metrics && \
    chmod 0644 /usr/lib/systemd/system/workload-metrics.service && \
    chmod 0644 /usr/lib/systemd/system/workload-metrics.timer && \
    chmod 0755 /usr/bin/workload-ctl && \
    chmod 0755 /usr/bin/cosy && \
    chmod 0644 /usr/share/man/man1/cosy.1 && \
    chmod 0644 /usr/lib/tmpfiles.d/workloads-dirs.conf && \
    chmod 0644 /usr/lib/systemd/system/emergency.target.d/emergency-access.conf && \
    chmod 0644 /usr/share/bash-completion/completions/workload-ctl && \
    chmod 0644 /usr/share/doc/workload-ctl/*.md && \
    chmod 0644 /usr/share/doc/workload-ctl/*.toml && \
    chmod 0644 /usr/share/containers/seccomp-workload-baseline.json && \
    find /usr/share/workload-containers -name 'build.sh' -exec chmod 0755 {} \; && \
    find /usr/share/workload-containers -name 'entrypoint.sh' -exec chmod 0755 {} \; && \
    mkdir -p /var/lib/workloads /etc/workloads.d && \
    chmod 0755 /var/lib/workloads && \
    systemctl enable workload-metrics.timer

# Copy workload configurations - disabled by default
COPY --link workloads.d/ /etc/workloads.d/

# Define required labels for this bootc image to be recognized as such
LABEL containers.bootc 1
LABEL ostree.bootable 1

# https://pagure.io/fedora-kiwi-descriptions/pull-request/52
ENV container=oci

# Optional labels that only apply when running this image as a container. These keep the default entry point running under systemd.
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
