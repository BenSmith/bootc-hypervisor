ARG BASE_IMAGE=ghcr.io/bensmith/fedora-bootc-minimal:latest
FROM ${BASE_IMAGE}

# Build argument for local development (enables passwordless sudo)
ARG ENABLE_PASSWORDLESS_SUDO=false

LABEL org.opencontainers.image.title="Hypervisor Bootc Image"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with podman/lxc/libvirt/QEMU/KVM"

COPY policy.json /etc/containers/policy.json
COPY cosign.pub /etc/pki/containers/cosign.pub
COPY registries.d/ghcr.io.yaml /etc/containers/registries.d/ghcr.io.yaml
COPY security/pwquality-no-dictionary.conf /etc/security/pwquality.conf.d/no-dictionary.conf

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
    avahi \
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
    edk2-ovmf \
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
    nss-mdns \
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
    python3 \
    python3-pip \
    qemu-img \
    qemu-kvm \
    rasdaemon \
    realtek-firmware \
    rpm-ostree \
    rsync \
    samba-client \
    seatd \
    setools-console \
    shim \
    skopeo \
    smartmontools \
    socat \
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
    udica \
    usbutils \
    virglrenderer \
    virtiofsd \
    virt-install \
    virt-top \
    wget \
    wireguard-tools \
    wpa_supplicant \
    xdg-dbus-proxy \
    xfsprogs \
    zram-generator && \
    dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* && \
    rm -rf /boot && mkdir -p /boot && \
    systemctl unmask avahi-daemon avahi-daemon.socket && \
    systemctl enable avahi-daemon && \
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
    semanage fcontext -a -t container_file_t '/var/lib/prometheus/node-exporter(/.*)?' || true && \
    sed -i 's/^hosts:.*/hosts:      files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns/' /etc/nsswitch.conf && \
    mkdir -p /etc/systemd/resolved.conf.d && \
    printf '[Resolve]\nMulticastDNS=resolve\n' > /etc/systemd/resolved.conf.d/10-mdns.conf

# SELinux: allow containers to access host devices (GPU, input)
RUN setsebool -P container_use_devices on

# SELinux: gate container access to the host seatd socket (KMS desktops) behind
# the seatd_container_connect boolean, shipped OFF so the host-wide container_t
# grant is inert until a KMS desktop is run:
#   sudo setsebool -P seatd_container_connect on
COPY security/seatd_container.cil /tmp/seatd_container.cil
RUN rm -rf /etc/selinux/targeted/tmp /etc/selinux/targeted/previous 2>/dev/null; \
    semodule -i /tmp/seatd_container.cil && \
    rm -f /tmp/seatd_container.cil

# Optional: Enable passwordless sudo for local development
# Enabled with: podman build --build-arg ENABLE_PASSWORDLESS_SUDO=true
RUN if [ "$ENABLE_PASSWORDLESS_SUDO" = "true" ]; then \
        echo '%wheel ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/wheel-nopasswd && \
        chmod 0440 /etc/sudoers.d/wheel-nopasswd; \
    fi

# Install workload provisioning system from the homelab RPM repo.
# The repo is removed after install — git.local is not reachable outside
# the homelab build environment. The RPM is also cached at a known path so
# workload-ensure-user can bundle it into VM cloud-init ISOs at runtime.
RUN printf '[workloadctl]\nname=workloadctl\nbaseurl=https://git.local/api/packages/ben/rpm\nenabled=1\ngpgcheck=0\nsslverify=false\n' \
        > /etc/yum.repos.d/workloadctl.repo && \
    dnf install -y workloadctl && \
    mkdir -p /tmp/wl-rpms && \
    dnf download --destdir /tmp/wl-rpms workloadctl && \
    rpm=$(echo /tmp/wl-rpms/workloadctl-*.rpm) && \
    test -f "$rpm" && \
    install -Dpm 0644 "$rpm" /usr/share/workloadctl/workloadctl.rpm && \
    rm -rf /tmp/wl-rpms /etc/yum.repos.d/workloadctl.repo && \
    dnf clean all

# Bootc-specific: emergency access, cosy
COPY systemd/emergency-access.conf /usr/lib/systemd/system/emergency.target.d/emergency-access.conf
COPY bin/cosy /usr/bin/
COPY man/cosy.1 /usr/share/man/man1/cosy.1
RUN chmod 0755 /usr/bin/cosy && \
    chmod 0644 /usr/share/man/man1/cosy.1 && \
    chmod 0644 /usr/lib/systemd/system/emergency.target.d/emergency-access.conf && \
    /usr/bin/cosy completion bash > /usr/share/bash-completion/completions/cosy && \
    chmod 0644 /usr/share/bash-completion/completions/cosy

LABEL org.opencontainers.image.title="Hypervisor bootc Image"
LABEL org.opencontainers.image.description="generic bootc-based hypervisor"
