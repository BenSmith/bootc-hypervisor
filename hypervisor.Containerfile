FROM ghcr.io/bensmith/fedora-bootc-minimal:43

LABEL org.opencontainers.image.title="Hypervisor Bootc Image"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with libvirt/QEMU/KVM"

RUN dnf install --setopt=install_weak_deps=False --nodocs -y \
    attr \
    bash-completion \
    bind-utils \
    bridge-utils \
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
    distrobox \
    dmidecode \
    dnsmasq \
    efibootmgr \
    firewalld \
    fwupd \
    grub2 \
    grub2-efi-x64 \
    guestfs-tools \
    hostname \
    htop \
    ipmitool \
    iproute \
    iptables-nft \
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
    lsof \
    lvm2 \
    mdevctl \
    microcode_ctl \
    nano \
    nc \
    NetworkManager \
    nfs-utils \
    openssh-clients \
    openssh-server \
    parted \
    pciutils \
    podman \
    podman-compose \
    podman-docker \
    polkit \
    prometheus-node-exporter \
    qemu-img \
    qemu-kvm \
    rpm-ostree \
    rsync \
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
    vim-minimal \
    virt-install \
    virt-top \
    zram-generator

RUN dnf clean all && \
    systemctl enable cockpit.socket && \
    systemctl enable firewalld && \
    systemctl enable libvirtd && \
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
