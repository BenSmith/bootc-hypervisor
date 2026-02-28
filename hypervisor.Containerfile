FROM ghcr.io/bensmith/fedora-bootc-minimal:43

# Build argument for local development (enables passwordless sudo)
ARG ENABLE_PASSWORDLESS_SUDO=false

LABEL org.opencontainers.image.title="Hypervisor Bootc Image"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with podman/lxc/libvirt/QEMU/KVM"

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
    policycoreutils-python-utils \
    prometheus-node-exporter \
    qemu-img \
    qemu-kvm \
    virglrenderer \
    realtek-firmware \
    rpm-ostree \
    rsync \
    seatd \
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
#
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
        -not -path '/var/lib/rpm/*' \
        -delete && \
    find /var -depth -type d -empty -delete && \
    bootc container lint || echo "Note: Some /var warnings expected from gssproxy/pcp/rpm packages"

# Ensure device access groups exist (only define groups not provided by base packages)
# Most device groups (kvm, video, audio, etc.) are already defined by system packages
# We only need to ensure seat and tpm exist for workload device access
RUN \
    printf 'g seat - -\n' >> /usr/lib/sysusers.d/hypervisor-groups.conf && \
    printf 'g tpm - -\n' >> /usr/lib/sysusers.d/hypervisor-groups.conf

# Copy device groups from /usr/lib/group (immutable) to /etc/group (mutable)
# This is needed on bootc systems to allow usermod to add workload users to these groups
# Groups needed for device access:
#   audio - audio devices (/dev/snd)
#   dialout - serial devices (USB serial, Zigbee, Z-Wave)
#   disk - block devices (raw disk access)
#   input - input devices (/dev/input, /dev/uinput)
#   kvm - KVM virtualization (/dev/kvm)
#   seat - seatd for GPU/input access
#   tpm - TPM devices (/dev/tpm0)
#   video, render - GPU access
RUN grep -E "^(video|render|input|audio|dialout|disk|kvm|seat|tpm):" /usr/lib/group >> /etc/group || true

# Optional: Enable passwordless sudo for local development
# Enabled with: podman build --build-arg ENABLE_PASSWORDLESS_SUDO=true
RUN if [ "$ENABLE_PASSWORDLESS_SUDO" = "true" ]; then \
        echo '%wheel ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/wheel-nopasswd && \
        chmod 0440 /etc/sudoers.d/wheel-nopasswd; \
    fi

# Install workload provisioning system
COPY generators/workload-generator /usr/lib/systemd/system-generators/
COPY systemd/workload-setup.service /usr/lib/systemd/system/
COPY libexec/workload-setup.py /usr/lib/systemd/
COPY bin/workload-ctl /usr/local/bin/
COPY bin/test-workload-ctl.sh /usr/local/bin/
COPY completions/workload-ctl-completion.bash /usr/share/bash-completion/completions/workload-ctl

RUN mkdir -p /usr/share/doc/workload-ctl
COPY docs/workloads.md /usr/share/doc/workload-ctl/
COPY workloads.d/schema-reference.toml /usr/share/doc/workload-ctl/

RUN chmod 0755 /usr/lib/systemd/system-generators/workload-generator && \
    chmod 0755 /usr/lib/systemd/workload-setup.py && \
    chmod 0755 /usr/local/bin/workload-ctl && \
    chmod 0755 /usr/local/bin/test-workload-ctl.sh && \
    chmod 0644 /usr/share/bash-completion/completions/workload-ctl && \
    chmod 0644 /usr/share/doc/workload-ctl/*.md && \
    chmod 0644 /usr/share/doc/workload-ctl/*.toml

RUN systemctl enable workload-setup.service

# Create workload directory and tmpfiles.d config
RUN mkdir -p /var/lib/workloads /etc/workloads.d && \
    printf 'd /var/lib/workloads 0755 root root - -\n' > \
    /usr/lib/tmpfiles.d/workloads.conf

# Copy example workload configurations (workloads are disabled by default)
COPY workloads.d/ /etc/workloads.d/

# Define required labels for this bootc image to be recognized as such
LABEL containers.bootc 1
LABEL ostree.bootable 1

# https://pagure.io/fedora-kiwi-descriptions/pull-request/52
ENV container=oci

# Optional labels that only apply when running this image as a container. These keep the default entry point running under systemd.
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
