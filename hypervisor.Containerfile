FROM ghcr.io/bensmith/fedora-bootc-minimal:43

LABEL org.opencontainers.image.title="Hypervisor Bootc Image"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with libvirt/QEMU/KVM"

COPY policy.json /etc/containers/policy.json
COPY freeipmi.conf /usr/lib/tmpfiles.d/freeipmi.conf

RUN rm -f /etc/yum.repos.d/fedora-cisco-openh264.repo || true

RUN dnf install --setopt=install_weak_deps=False --nodocs -y \
    alsa-sof-firmware \
    amd-ucode-firmware \
    atheros-firmware \
    attr \
    bash-completion \
    bind-utils \
    borgbackup \
    brcmfmac-firmware \
    bridge-utils \
    btop \
    btrfs-progs \
    cifs-utils \
    cockpit \
    cockpit-bridge \
    cockpit-machines \
    cockpit-networkmanager \
    cockpit-ostree \
    cockpit-podman \
    cockpit-selinux \
    cockpit-sosreport \
    cockpit-system \
    cockpit-ws \
    cockpit-ws-selinux \
    criu \
    criu-libs \
    crun \
    cryptsetup \
    curl \
    distrobox \
    dmidecode \
    dnsmasq \
    efibootmgr \
    ethtool \
    fail2ban \
    fastfetch \
    firewalld \
    fwupd \
    git \
    grub2 \
    grub2-efi-x64 \
    guestfs-tools \
    hostname \
    htop \
    incus \
    incus-tools \
    intel-audio-firmware \
    intel-gpu-firmware \
    inxi \
    iotop \
    ipmitool \
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
    lvm2 \
    mdevctl \
    mediatek-firmware \
    microcode_ctl \
    mt7xxx-firmware \
    nano \
    nc \
    neovim \
    NetworkManager \
    NetworkManager-openvpn \
    NetworkManager-wifi \
    nfs-utils \
    nxpwireless-firmware \
    openssh-clients \
    openssh-server \
    parted \
    pciutils \
    perf \
    podman \
    podman-compose \
    podman-docker \
    polkit \
    prometheus-node-exporter \
    qemu-img \
    qemu-kvm \
    realtek-firmware \
    rpm-ostree \
    rsync \
    shim \
    skopeo \
    smartmontools \
    sos \
    strace \
    sudo \
    sysstat \
    tailscale \
    tar \
    tcpdump \
    tmux \
    traceroute \
    tree \
    tuned \
    tzdata \
    usbutils \
    vim-minimal \
    virt-install \
    virt-top \
    wget \
    wireguard-tools \
    wpa_supplicant \
    zram-generator

# cockpit is enabled but blocked by firewall intentionally. To allow on network:
# sudo firewall-cmd --add-service=cockpit --permanent
# sudo firewall-cmd --reload
# the pcp and gssproxy bootc lint warnings are because these packages (upon which others depend)
# store data in /var/lib, and bootc would prefer they're in /usr/lib
RUN dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* && \
    rm -rf /boot && mkdir -p /boot && \
    systemctl enable cockpit.socket && \
    systemctl enable firewalld && \
    systemctl enable libvirtd && \
    systemctl enable incus.socket && \
    systemctl enable prometheus-node-exporter && \
    systemctl enable sshd && \
    systemctl enable tuned && \
    find /var -type f \
        -not -path '/var/lib/gssproxy/*' \
        -not -path '/var/lib/pcp/*' \
        -not -path '/var/lib/rpm-state/*' \
        -delete && \
    find /var -depth -type d -empty -delete && \
    bootc container lint || echo "Note: Some /var warnings expected from gssproxy/pcp/rpm packages"

# Configure device access for containerized workloads
# These udev rules set host device permissions that containers inherit
RUN printf '# Hypervisor Device Access for Containerized Workloads\n' > /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf '# GPU render nodes - world accessible for container compute\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'SUBSYSTEM=="drm", KERNEL=="renderD[0-9]*", MODE="0666"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf '# GPU card nodes - group accessible for display/rendering\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'SUBSYSTEM=="drm", KERNEL=="card[0-9]*", GROUP="video", MODE="0660"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf '# Input devices - group accessible for container passthrough\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'SUBSYSTEM=="input", GROUP="input", MODE="0660"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'KERNEL=="uinput", GROUP="input", MODE="0660"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules && \
    printf 'KERNEL=="event[0-9]*", GROUP="input", MODE="0660"\n' >> /usr/lib/udev/rules.d/71-hypervisor-device-access.rules

# Ensure device access groups exist
RUN printf 'g video - -\n' > /usr/lib/sysusers.d/hypervisor-groups.conf && \
    printf 'g render - -\n' >> /usr/lib/sysusers.d/hypervisor-groups.conf && \
    printf 'g input - -\n' >> /usr/lib/sysusers.d/hypervisor-groups.conf

# Configure PAM to automatically add users to device groups at login
# This enables rootless containers (user quadlets) to access devices
RUN mkdir -p /etc/security/group.conf.d && \
    printf '# Automatically add all users to device access groups on login\n' > /etc/security/group.conf.d/50-hypervisor-device-access.conf && \
    printf '# Format: services;ttys;users;times;groups\n' >> /etc/security/group.conf.d/50-hypervisor-device-access.conf && \
    printf '*;*;*;Al0000-2400;video,render,input\n' >> /etc/security/group.conf.d/50-hypervisor-device-access.conf && \
    if ! grep -q "pam_group.so" /etc/pam.d/systemd-user 2>/dev/null; then \
        echo "session     optional      pam_group.so" >> /etc/pam.d/systemd-user; \
    fi && \
    if ! grep -q "pam_group.so" /etc/pam.d/password-auth 2>/dev/null; then \
        sed -i '/session.*pam_systemd\.so/a session     optional      pam_group.so' /etc/pam.d/password-auth; \
    fi

# Define required labels for this bootc image to be recognized as such
LABEL containers.bootc 1
LABEL ostree.bootable 1

# https://pagure.io/fedora-kiwi-descriptions/pull-request/52
ENV container=oci

# Optional labels that only apply when running this image as a container. These keep the default entry point running under systemd.
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
