FROM ghcr.io/bensmith/fedora-bootc-minimal:43

LABEL org.opencontainers.image.title="Hypervisor Bootc Image"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with libvirt/QEMU/KVM"

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
RUN dnf clean all && \
    rm -rf /var/log/* /var/cache/* /var/lib/dnf/* /boot/* && \
    systemctl enable cockpit.socket && \
    systemctl enable firewalld && \
    systemctl enable libvirtd && \
    systemctl enable incus.socket && \
    systemctl enable prometheus-node-exporter && \
    systemctl enable sshd && \
    systemctl enable tuned && \
    bootc container lint

# Define required labels for this bootc image to be recognized as such
LABEL containers.bootc 1
LABEL ostree.bootable 1

# https://pagure.io/fedora-kiwi-descriptions/pull-request/52
ENV container=oci

# Optional labels that only apply when running this image as a container. These keep the default entry point running under systemd.
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
