from localhost/minimal-bootc

RUN dnf install --setopt=install_weak_deps=False --nodocs -y \
    attr \
    bash-completion \
    cockpit \
    cockpit-bridge \
    cockpit-machines \
    cockpit-networkmanager \
    cockpit-podman \
    cockpit-selinux \
    cockpit-ws \
    cockpit-ws-selinux \
    criu \
    criu-libs \
    crun \
    cryptsetup \
    distrobox \
    efibootmgr \
    fwupd \
    grub2 \
    grub2-efi-x64 \
    hostname \
    ipmitool \
    iproute \
    iptables-nft \
    jq \
    just \
    less \
    libbpf-tools \
    libvirt-daemon \
    libvirt-dbus \
    libtpms \
    linux-firmware \
    lvm2 \
    microcode_ctl \
    nano \
    nc \
    NetworkManager \
    openssh-clients \
    openssh-server \
    parted \
    podman \
    podman-compose \
    podman-docker \
    polkit \
    qemu-guest-agent \
    qemu-img \
    rpm-ostree \
    shim \
    skopeo \
    strace \
    sudo \
    tar \
    tzdata \
    vim-minimal \
    virsh \
    virt-install \
    zram-generator

# cockpit-machines cockpit-ostree cockpit-ws ipmitool nc strace syncthing wayland-devel wayland-utils

RUN dnf clean all && \
    systemctl enable qemu-guest-agent && \
    systemctl enable cockpit.socket && \
    bootc container lint

CMD ["sleep", "infinity"]
