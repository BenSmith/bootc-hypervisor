ARG BASE_IMAGE=ghcr.io/bensmith/fedora-bootc-minimal:latest

FROM fedora:latest AS rpm-builder
COPY workloadctl/ /workloadctl/
# openssl is the CLI, not the library: the test suite mints a CA and its leaves
# by shelling out to it (tests/test_vm_ca.py, test_vm_mint.py and three others),
# and the fedora base image ships openssl-libs without it. Absent, `just test`
# fails here with FileNotFoundError rather than in the PR gate, whose runner
# happens to have it.
RUN dnf install -y --nodocs --setopt=install_weak_deps=False \
        rpm-build python3 just systemd-rpm-macros python3-rpm-macros openssl && \
    dnf clean all && \
    cd /workloadctl && \
    rm -rf rpmbuild && \
    just test && just rpm-build

FROM ${BASE_IMAGE}

# Build argument for local development (enables passwordless sudo)
ARG ENABLE_PASSWORDLESS_SUDO=false

LABEL org.opencontainers.image.title="Hypervisor Bootc Image"
LABEL org.opencontainers.image.description="Bootc-based hypervisor with podman/lxc/libvirt/QEMU/KVM"

COPY policy.json /etc/containers/policy.json
COPY cosign.pub /etc/pki/containers/cosign.pub
COPY registries.d/ghcr.io.yaml /etc/containers/registries.d/ghcr.io.yaml
COPY registries.d/registry-local.yaml /etc/containers/registries.d/registry-local.yaml
COPY security/pwquality-no-dictionary.conf /etc/security/pwquality.conf.d/no-dictionary.conf
# Work around pasta's loopback splice() throughput regression (see the file's
# header) — without this, large pulls through the Caddy->zot reverse proxy hang.
COPY containers.conf.d/10-pasta-no-splice.conf /etc/containers/containers.conf.d/10-pasta-no-splice.conf
# NOTE: registries.conf.d/mirrors.conf is deliberately NOT copied here. It is
# installed further down, only when a homelab CA is being injected — see the
# ca-trust-inject block.
# fail2ban's /var/lib/fail2ban state dir is emptied with the rest of /var during
# the build; recreate it at boot so fail2ban-server can open its sqlite db.
COPY tmpfiles.d/fail2ban-statedir.conf /usr/lib/tmpfiles.d/fail2ban-statedir.conf

# Virtual-input support for the game-streaming workloads (Sunshine/Wolf). They
# run their compositor + Sunshine as a rootless container user in the `input`
# group and synthesize the client's mouse/keyboard/gamepad through /dev/uinput.
# The module autoload + the group-access rule are shipped in the image (not
# written to /etc by each workload's enable hook) so they survive bootc
# upgrades: the ostree /etc 3-way merge was dropping the enable-time
# /etc/udev/rules.d rule, leaving /dev/uinput 0600 root:root, so Sunshine hit
# "Unable to create virtual mouse: Permission denied" and the stream took no
# input. Image-owned files under /usr are immutable and can't drift.
RUN printf 'uinput\n' > /usr/lib/modules-load.d/uinput.conf && \
    printf '# Virtual input devices for rootless game-streaming workloads\n' \
        > /usr/lib/udev/rules.d/72-uinput-input.rules && \
    printf 'KERNEL=="uinput", GROUP="input", MODE="0660"\n' \
        >> /usr/lib/udev/rules.d/72-uinput-input.rules

# CI-injectable trust anchors, and the registry mirror that depends on them.
#
# The Forgejo pipeline drops the homelab root CA (public cert) into
# ca-trust-inject/ from the HOMELAB_ROOT_CA secret before building, so internal
# images trust the shared homelab CA. The dir is empty in git and on the public
# GitHub pipeline, so this is a no-op there. Only *.crt are installed; the
# README is ignored.
#
# The registry.local pull-through mirror is gated on the same signal, and the
# gate is the point. registry.local resolves over mDNS (this image enables
# avahi and puts mdns4_minimal ahead of dns in nsswitch, and .local is mDNS's
# own domain), so the name is claimable by anything on the link. In an image
# that carries the homelab CA that is fine — TLS verification against the CA
# is what proves the responder is the real cache. In the public ghcr image it
# is not: there is no CA to verify against, registry.local means nothing on a
# stranger's network, and a mirror entry there is at best inert and at worst a
# hijack of every docker.io/ghcr.io/quay.io pull. So the mirror ships only
# where the anchor that secures it also ships.
COPY ca-trust-inject/ /tmp/ca-trust-inject/
COPY registries.conf.d/mirrors.conf /tmp/mirrors.conf
RUN if ls /tmp/ca-trust-inject/*.crt >/dev/null 2>&1; then \
        cp /tmp/ca-trust-inject/*.crt /etc/pki/ca-trust/source/anchors/ && \
        update-ca-trust && \
        install -Dpm 0644 /tmp/mirrors.conf \
            /etc/containers/registries.conf.d/mirrors.conf && \
        echo "Installed CI-injected trust anchors + registry.local mirror"; \
    else \
        echo "No CI-injected trust anchors; skipping the registry.local mirror"; \
    fi && rm -rf /tmp/ca-trust-inject /tmp/mirrors.conf
# KNOWN GAP, no image-side fix: the `update-ca-trust` above does not reach an
# existing host whose trust store was ever edited by hand. It writes the
# extracted bundle into /etc/pki/ca-trust/extracted/, and `update-ca-trust` run
# on the host at any point in the past marks that path locally modified — so
# ostree's /etc 3-way merge keeps the host's copy forever and the image's
# extraction is discarded. An untouched host merges it normally.
# Same mechanism as the SELinux NOTE below (policy store in /etc): a *new*
# anchor file under source/anchors/ does land, but nothing extracts it.
#
# The symptom is silent and points away from the cause: the anchor is plainly
# present in source/anchors/, so the trust store looks correct, while every
# registry.local pull fails "unable to get local issuer certificate" because the
# bundle predates the anchor. Confirm with `ostree admin config-diff` — an
# affected host reports M on the files under extracted/; an unaffected one
# reports no pki/ca-trust entries at all.
#
# To repair a host: restore extracted/ from the booted deployment's copy
# (`cp -a /usr/etc/pki/ca-trust/extracted ...`, then restorecon), which brings
# config-diff back clean so the merge tracks the image again and later anchor
# rotations apply by themselves. Verify with
# `diff -r /usr/etc/pki/ca-trust /etc/pki/ca-trust`. A plain `update-ca-trust`
# also restores working trust, but leaves the divergence in place.
#
# Watch /etc/pki/tls/certs while doing that: it is an openssl CApath, so a hash
# link there grants trust independently of the bundle — a link to a superseded
# root is trust that no bundle inspection would reveal. `find /etc/pki -xtype l`
# to check, `-delete` to sweep.
#
# Settled 2026-08-09: detection, not a boot-time fix. `workloadctl diagnose`
# carries `ca_trust_anchor_check` (lib/cmd_diagnose.py), which asks whether each
# configured anchor is actually in the extracted bundle and names the right
# repair — restoring extracted/ from the booted deployment where every anchor is
# the image's, `update-ca-trust` where the host carries local anchors that
# restoring would revoke.
#
# The rejected alternative was a boot-time oneshot running `update-ca-trust`.
# It self-heals without an operator, but it writes /etc unconditionally and so
# *guarantees* the divergence described above on every host forever — trading
# the merge away to fix a problem that only occurs once the merge is already
# lost. Detection keeps /etc tracking the image, which is what makes later
# anchor rotations apply by themselves.

# Build-time helper, not a shipped feature: every RUN below that reaches
# semodule/semanage/setsebool has to re-materialise the SELinux policy store in
# its own layer first, or libsemanage's overlayfs EXDEV fallback corrupts it.
# The script explains the mechanism in full and refuses to run outside a build.
# It lives in the image because the -nvidia/-amd variants build FROM it and
# need it too.
COPY security/selinux-store-copyup /usr/libexec/hypervisor-build/selinux-store-copyup
COPY security/selinux-store-verify /usr/libexec/hypervisor-build/selinux-store-verify

# Break ostree hardlinks on rpmdb: fuse-overlayfs preserves hardlinks during
# copy-up, so modifying rpmdb.sqlite also propagates to the ostree object and
# rpm-ostree base-db (which share the same lower inode). This corrupts the
# database. Breaking the hardlink first ensures only the live db is copied up.
RUN cp /usr/share/rpm/rpmdb.sqlite /usr/share/rpm/rpmdb.sqlite.tmp && \
    mv /usr/share/rpm/rpmdb.sqlite.tmp /usr/share/rpm/rpmdb.sqlite

# the pcp and gssproxy bootc lint warnings are because these packages (upon which others depend)
# store data in /var/lib, and bootc would prefer they're in /usr/lib
RUN /usr/libexec/hypervisor-build/selinux-store-copyup && \
    dnf install --setopt=install_weak_deps=False --nodocs -y \
    acl \
    alsa-sof-firmware \
    amd-ucode-firmware \
    atheros-firmware \
    attr \
    audit \
    avahi \
    bash-completion \
    bind-utils \
    bpftrace \
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
    fio \
    firewalld \
    fwupd \
    grub2 \
    grub2-efi-x64 \
    hdparm \
    hostname \
    htop \
    hwloc \
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
    ncdu \
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
    passt \
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
    systemctl enable fail2ban && \
    systemctl enable firewalld && \
    systemctl enable libvirtd && \
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
    bootc container lint --fatal-warnings \
        --skip var-tmpfiles --skip var-log --skip nonempty-run-tmp
# ^ Warnings are FATAL, minus three named exemptions. This replaced a
# `LINT_OUT=$(...) || { grep -v <paths>; }` allowlist that could never fire:
# every lint it filtered for is type `warning`, and without --fatal-warnings
# bootc exits 0 on warnings, so the `||` branch was unreachable and the lint
# was decorative. `--skip` is the supported mechanism (`--list` names them).
#
# The three exemptions, all verified against the published image:
#   var-tmpfiles     the four /var trees the find above deliberately preserves
#                    (gssproxy, pcp, rpm-state, rpm) plus dnf repo metadata
#   var-log          /var/log/dnf5.log, recreated by dnf layers after this one
#   nonempty-run-tmp /run/{fail2ban,gluster,lock,...}, created by package
#                    install; masked by the runtime tmpfs anyway
# Everything else — including every fatal lint — now fails the build. Adding a
# skip should mean "we looked and accepted it", so name the lint, don't widen.

# Ensure device access groups exist, propagate to /etc/group, set privileged port sysctl.
# /usr/lib/group is immutable on bootc; /etc/group is mutable and needed for usermod.
# Groups: audio, dialout, disk, input, kvm, render, seat, tpm, video
RUN /usr/libexec/hypervisor-build/selinux-store-copyup && \
    printf 'g seat - -\n' >> /usr/lib/sysusers.d/hypervisor-groups.conf && \
    printf 'g tpm - -\n' >> /usr/lib/sysusers.d/hypervisor-groups.conf && \
    grep -E "^(video|render|input|audio|dialout|disk|kvm|seat|tpm):" /usr/lib/group >> /etc/group || true && \
    echo 'net.ipv4.ip_unprivileged_port_start = 0' > /usr/lib/sysctl.d/50-privileged-ports.conf && \
    semanage fcontext -a -t container_file_t '/var/lib/prometheus/node-exporter(/.*)?' || true && \
    sed -i 's/^hosts:.*/hosts:      files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns/' /etc/nsswitch.conf && \
    mkdir -p /etc/systemd/resolved.conf.d && \
    printf '[Resolve]\nMulticastDNS=resolve\n' > /etc/systemd/resolved.conf.d/10-mdns.conf

# force lvm into initramfs so it will activate the lv during boot
RUN printf 'add_dracutmodules+=" lvm dm "\n' \
      > /usr/lib/dracut/dracut.conf.d/50-lvm.conf; \
    kver=$(cd /usr/lib/modules && echo *); \
    mkdir -p /tmp/dracut /var/roothome; \
    dracut --reproducible -f --no-hostonly --add ostree --tmpdir /tmp/dracut \
      /usr/lib/modules/$kver/initramfs.img $kver; \
    rm -rf /tmp/dracut; \
    rmdir /var/roothome 2>/dev/null || true

# SELinux: device access is NOT granted host-wide here. This image used to run
# `setsebool -P container_use_devices on`, which reads like "GPU access" but
# expands to read/write/ioctl/map on every device_node type — ~200 of them,
# including fixed_disk_device_t, lvm_control_t, kvm_device_t and tpm_device_t —
# for the container_domain *attribute*, which every udica-derived
# wl_<name>.process type is a member of. It was the one grant a per-workload
# policy.cil could not scope down.
#
# Nothing needs that breadth. What GPU workloads actually touch (verified
# against a live /run/cdi/nvidia.yaml) is two types:
#   dri_device_t          /dev/dri/card*, renderD*  — already allowed with no
#                         boolean at all (open+map via container_use_dri_devices,
#                         on by default); also covers AMD, alongside
#                         hsa_device_t (/dev/kfd) which is unconditional
#   xserver_misc_device_t /dev/nvidia*, nvidiactl, nvidia-uvm*, nvidia-caps/*
#                         — granted in the hypervisor-nvidia-* variants only,
#                         via container_use_xserver_devices
# and /dev/input for KMS desktops, gated below.
#
# NOTE for existing hosts: the SELinux policy store lives in /etc and is rebuilt
# locally by `workloadctl enable` (semodule -i), so ostree's 3-way merge keeps
# the host's copy and this removal does NOT reach a machine on `bootc upgrade`.
# Fresh installs only. On an already-deployed host, run:
#   sudo setsebool -P container_use_devices off
# `workloadctl doctor` reports the boolean's state against this intent.

# SELinux: two host-wide container_t grants whose consumers are bare containers
# (desktop-containers/desktop-*-kms), which have no per-workload type to carry
# them. Both ship OFF, so the grants are inert until a KMS desktop is run — and
# a KMS desktop needs both:
#   sudo setsebool -P seatd_container_connect on
#   sudo setsebool -P container_input_devices on
COPY security/seatd_container.cil security/container_input_devices.cil \
     security/pasta_sandbox.cil /tmp/
RUN /usr/libexec/hypervisor-build/selinux-store-copyup && \
    semodule -i /tmp/seatd_container.cil /tmp/container_input_devices.cil \
                /tmp/pasta_sandbox.cil && \
    rm -f /tmp/seatd_container.cil /tmp/container_input_devices.cil \
          /tmp/pasta_sandbox.cil

# Optional: Enable passwordless sudo for local development
# Enabled with: podman build --build-arg ENABLE_PASSWORDLESS_SUDO=true
RUN if [ "$ENABLE_PASSWORDLESS_SUDO" = "true" ]; then \
        echo '%wheel ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/wheel-nopasswd && \
        chmod 0440 /etc/sudoers.d/wheel-nopasswd; \
    fi

# Install workload provisioning system, built from source in the rpm-builder stage.
# The RPM is also cached at a known path so workload-ensure-user can bundle it
# into VM cloud-init ISOs at runtime.
COPY --from=rpm-builder /workloadctl/rpmbuild/RPMS/noarch/ /tmp/wl-rpms/
# Exactly one RPM, asserted out loud. The release is timestamped, so the only way
# to name it is a glob — and a glob that matches several expands to a list that
# `dnf install` would happily take, silently installing whichever came last and
# caching the wrong one at /usr/share/workloadctl. A glob matching none expands
# to itself. Both are build-stopping, so say which happened: the failure lands
# hundreds of layers deep and reads as unexplained if it doesn't.
RUN /usr/libexec/hypervisor-build/selinux-store-copyup && \
    set -- /tmp/wl-rpms/workloadctl-*.rpm && \
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then \
        echo "expected exactly one workloadctl RPM in /tmp/wl-rpms, got $#:" >&2; \
        ls -l /tmp/wl-rpms >&2; \
        exit 1; \
    fi && \
    dnf install -y "$1" && \
    install -Dpm 0644 "$1" /usr/share/workloadctl/workloadctl.rpm && \
    rm -rf /tmp/wl-rpms && \
    dnf clean all

# The tinyproxy sysusers fragment is gone, and its absence has a reason.
#
# workloadctl used to hard-require tinyproxy — one instance per VM workload that
# set [vm.network].hosts — and tinyproxy-1.11.2-8.fc44 creates its account the
# legacy way (`groupadd -r` / `useradd -r` in %pre, no sysusers.d fragment).
# That writes /etc/passwd and /etc/group entries with no declaration behind
# them, which bootc's `etc-sysusers` lint reports, so this file carried a
# fragment under /usr/lib to regenerate the account deterministically.
#
# workloadctl retired the proxy on 2026-08-25: hostname policy is now a
# uid-keyed redirect into a per-workload egress inspector that ships inside the
# workloadctl RPM itself. The `Requires: tinyproxy` is gone with it, nothing
# else in this image pulls the package in, and a fragment declaring an account
# for an absent package would create a user nothing on the host can use.
#
# Kept as a comment rather than deleted outright because the ORDERING LESSON it
# produced is still live, and is recorded at the second lint call below: the
# gap surfaced as a hypervisor-amd build failure, hundreds of layers from its
# cause. If a future dependency creates accounts the legacy way, that is the
# shape the failure will take again.

# Bootc-specific: emergency access, cosy
COPY systemd/emergency-access.conf /usr/lib/systemd/system/emergency.target.d/emergency-access.conf
COPY bin/cosy /usr/bin/
COPY man/cosy.1 /usr/share/man/man1/cosy.1
# cosy desktop-container recipes (build contexts an operator runs with `cosy`).
# Not workloadctl workloads — kept in the image but scoped out of the RPM.
COPY desktop-containers/ /usr/share/cosy/desktop-containers/
RUN chmod 0755 /usr/bin/cosy && \
    chmod 0644 /usr/share/man/man1/cosy.1 && \
    chmod 0644 /usr/lib/systemd/system/emergency.target.d/emergency-access.conf && \
    /usr/bin/cosy completion bash > /usr/share/bash-completion/completions/cosy && \
    chmod 0644 /usr/share/bash-completion/completions/cosy

# Assert the policy store actually holds every module the installed packages
# ship. A failed semodule inside a %post does not fail the transaction, so
# without this a build can go green having silently dropped policy — which is
# how four modules went missing unnoticed. Runs before the lint: a store defect
# should report itself, not surface later as something else.
RUN /usr/libexec/hypervisor-build/selinux-store-verify

# Lint again, after everything.
#
# The lint above runs partway through this file, before the workloadctl RPM and
# the layers that follow it. So the base image never re-checked the /etc entries
# its own dependencies create, and a tinyproxy packaging gap surfaced instead as
# a hypervisor-amd build failure — a lint about a workloadctl dependency,
# reported by the GPU image, hundreds of layers from its cause. (That specific
# dependency is gone; the ordering it exposed is not.)
#
# The variants have always covered this ground incidentally, by linting on top
# of the finished base. That is the wrong place to find out: it is a slower
# feedback loop, it fails three images for one defect, and it points at the
# wrong file.
#
# The earlier call stays where it is rather than moving here. Two lints cost
# seconds, and keeping the first one means a regression in the packages layer
# still fails at the packages layer instead of at the bottom of the file.
#
# Same three exemptions, deliberately not widened — see the earlier call for
# what each covers. Verified clean at this point on a full build (10 checks
# passed, 0 warnings) before this was added, so it carries no accepted debt.
RUN bootc container lint --fatal-warnings \
    --skip var-tmpfiles --skip var-log --skip nonempty-run-tmp

LABEL org.opencontainers.image.title="Hypervisor bootc Image"
LABEL org.opencontainers.image.description="generic bootc-based hypervisor"
