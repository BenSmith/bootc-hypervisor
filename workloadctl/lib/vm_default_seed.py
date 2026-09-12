"""The built-in cloud-init user-data a VM gets when its bundle ships none.

One document, rendered from what the host knows: the guest user and the
workload's SSH pubkey, the VM host keypair, the virtiofs mounts with the
SELinux context each needs to be usable, the data disk, the egress CA
placement and the paravirtual clock lines. `virtiofs_mount_opts` is also
what the seed builder applies to a bundle's own document, so a custom seed
and the built-in one mount a share the same way. Pure text in, text out;
the ISO around it is ensure_vm's.

Installed to /usr/libexec/workloadctl/vm_default_seed.py.
"""

from pathlib import PurePosixPath

from egress_ca import CA_BUNDLE_PATH
from vm_defs import VM_GUEST_UID, VM_HOME_SELINUX_CONTEXT
from vm_ptp import vm_ptp_kvm_runcmd_lines, vm_ptp_kvm_seed_files


def uncommented(text: str) -> str:
    """The seed with its comment lines removed, for the substring contracts.

    THE CONTRACTS BELOW ARE SUBSTRING PINS, which is a deliberate choice -- they
    establish that a seed refers to a thing at all, not that it wires it up
    correctly -- and a commented-out recipe satisfies one without doing
    anything. That is not hypothetical: the reference seed at
    workloads/vm-base/cloud-init/user-data carries both recipes commented out,
    because it is `egress = "open"` and must not install an empty anchor, and
    copying it forward is the intended way to start a filtered workload. A pin
    that counted the copy would pass every seed that was started and never
    finished, which is the false green this style has to be watched for.

    Only a line whose FIRST non-space character is `#` is dropped. A `#` part
    way through a line is content in YAML as often as it is a comment, and
    guessing which would make the contract's answer depend on a reading of the
    seed that cloud-init does not share.
    """
    return "\n".join(line for line in text.splitlines()
                      if not line.lstrip().startswith("#"))


def covers_guest_home(guest_path: str, guest_home: PurePosixPath) -> bool:
    """Whether a volume mounted at `guest_path` contains the guest's home.

    The shared predicate behind both halves of the home-context rule: the
    built-in cloud-config adds `context=` to exactly these mounts
    (virtiofs_mount_opts), and the seed contract in build_cloud_init_iso
    refuses a custom seed that mounts one of them without it. Split out so the
    two halves cannot disagree about which volume is the home share.
    """
    try:
        guest_home.relative_to(PurePosixPath(guest_path))
    except ValueError:
            return False
    return True


def virtiofs_mount_opts(guest_path: str, opts_str: str,
                          guest_home: PurePosixPath) -> str:
    """Add an SELinux `context=` option when `guest_path` covers guest_home.

    A share covering the guest's home directory carries ~/.ssh, and virtiofs
    has no xattr passthrough here (no `--xattr` flag on the virtiofsd sidecar,
    see generate_virtiofs_service), so every file under it lands in the guest
    labelled bare `virtiofs_t` — a type sshd has no policy access to. That is
    silent and late: the denial is logged but not enforced for however long
    the guest happens to keep running its *current* loaded policy, then bites
    on the next boot that actually reloads one — a `dnf upgrade` touching
    selinux-policy is exactly such a boot, and the guest may run for hours on
    the old policy first. `context=` pins every file under the mount to a type
    sshd already has broad, correct access to, so login stops depending on a
    hand-run `semanage permissive` surviving the guest's own next upgrade.

    Only applied when `opts_str` is still the "rw" parse_volume_spec default —
    a spec that already sets its own mount options made this call once and
    should not be overridden.
    """
    if not covers_guest_home(guest_path, guest_home):
        return opts_str
    if opts_str != "rw":
        return opts_str
    return opts_str + f',context="{VM_HOME_SELINUX_CONTEXT}"'


def render_default_user_data(name: str, guest_user: str, pubkey: str,
                              mounts: list, has_data_disk: bool,
                              host_private_key: str = "",
                              host_public_key: str = "",
                              guest_env: dict | None = None,
                              ca_cert: str = "") -> str:
    """Render the built-in #cloud-config when no user_data_file is set.

    Stays in a simple, controlled subset of YAML so we never need a YAML
    library — the structure here is small and fully owned by us.
    """
    lines = [
        "#cloud-config",
        f"hostname: {name}",
        f"fqdn: {name}.local",
        "users:",
        f"  - name: {guest_user}",
        # Pin the primary user to VM_GUEST_UID so virtiofsd's uid/gid
        # translation (guest 1000 <-> host workload uid) is deterministic and
        # the guest user can write virtiofs shares. Cloud images already assign
        # the default user 1000, so this only makes the convention explicit.
        f"    uid: {VM_GUEST_UID}",
        "    sudo: ALL=(ALL) NOPASSWD:ALL",
        "    ssh_authorized_keys:",
        f"      - {pubkey}",
    ]
    # Host-key pinning (S1): install the host-generated SSH host key into the
    # guest via cloud-init's ssh_keys module, so sshd presents a key the host
    # already pinned in vm_known_hosts on first boot — no trust-on-first-use.
    # The block scalar content is indented 4 spaces under `ed25519_private: |`.
    if host_private_key and host_public_key:
        lines.append("ssh_keys:")
        lines.append("  ed25519_private: |")
        for keyline in host_private_key.splitlines():
            lines.append(f"    {keyline}")
        lines.append(f"  ed25519_public: {host_public_key}")
    # The guest environment block. Two files rather than one because they cover
    # different consumers — /etc/environment is read by PAM so login sessions and
    # systemd services inherit it, and profile.d covers interactive shells that
    # never go through PAM. dnf, curl and git all read these names from the
    # environment.
    #
    # WHAT IS AND IS NOT IN IT, AFTER RUNG 2. Through rung 1 this block carried
    # http_proxy/https_proxy/no_proxy and the enforcement was advisory by
    # construction: a guest process free to ignore the variables simply did, and
    # only the default-deny chain turned that into a failure rather than a
    # bypass. Those variables are gone. Egress filtering is now transparent — a
    # uid-keyed redirect the guest is not told about and cannot opt out of — so
    # NOTHING written here affects whether the guest is filtered. What remains
    # is the CA bundle the inspector's spliced connections are presented under
    # and the credential PLACEHOLDERS a guest's client library needs in order to
    # send a request at all: conveniences, not controls. The broker endpoint used
    # to be here too and is not, because rung 6 stopped telling the guest where
    # the broker is -- a guest that cannot name it cannot choose to use it.
    #
    # That is worth stating because the block LOOKS the same and its failure
    # mode inverted. A guest missing this block used to be a guest reaching
    # nothing; now it is a guest that reaches everything it is allowed to and
    # cannot verify a certificate.
    #
    # Only the built-in cloud-config gets this. A workload supplying its own
    # user_data_file owns its guest configuration entirely, and this is
    # documented there rather than merged into a file we do not parse.
    #
    # THE CA IS SEEDED FOR EVERY FILTERED VM, WHATEVER `tls` SAYS, and it goes
    # in by TWO routes because they reach different clients. `ca_certs.trusted`
    # below installs it into the guest's system trust store, which §5 measured
    # as covering almost everything; the write_files entry puts the same PEM at
    # a fixed path, which is what the five environment variables above name for
    # the runtimes that carry their own root list and never consult the system
    # store. Either alone leaves a measured population of clients failing.
    # write_files is unconditional now: every built-in seed carries the two
    # files that give the guest a paravirtual clock (see vm_ptp.py).
    lines.append("write_files:")
    for path, permissions, content in vm_ptp_kvm_seed_files():
        lines.append(f"  - path: {path}")
        lines.append(f"    permissions: '{permissions}'")
        lines.append("    content: |")
        for contentline in content.splitlines():
            lines.append(f"      {contentline}")
    if ca_cert:
        lines.append(f"  - path: {CA_BUNDLE_PATH}")
        lines.append("    permissions: '0644'")
        lines.append("    content: |")
        for certline in ca_cert.splitlines():
            lines.append(f"      {certline}")
    if guest_env:
        lines.append("  - path: /etc/environment")
        lines.append("    append: true")
        lines.append("    content: |")
        for key, value in guest_env.items():
            lines.append(f"      {key}={value}")
        # Filename kept as -proxy though it now carries the CA bundle and the
        # credential placeholders and no proxy variable at all: renaming it
        # would leave the
        # old file behind on every existing guest, still exporting the retired
        # https_proxy, since cloud-config runs once at first boot. A guest that
        # keeps that stale export dials an address where nothing listens.
        lines.append("  - path: /etc/profile.d/99-workload-proxy.sh")
        lines.append("    permissions: '0644'")
        lines.append("    content: |")
        for key, value in guest_env.items():
            lines.append(f"      export {key}={value}")
    # cc_ca_certs, present in Fedora 44 Cloud-Base. This is the half that
    # reaches clients using the system store, and it is why a guest usually
    # works without any of the environment variables at all.
    if ca_cert:
        lines.append("ca_certs:")
        lines.append("  trusted:")
        lines.append("    - |")
        for certline in ca_cert.splitlines():
            lines.append(f"      {certline}")
    if mounts:
        lines.append("mounts:")
        for tag, mp, fstype, opts in mounts:
            lines.append(
                f"  - [{tag!r}, {mp!r}, {fstype!r}, {opts!r}, '0', '0']"
            )
    # runcmd is assembled from independent blocks and emitted once, below.
    # Each block is a single `- |` shell fragment, so a failure in one does not
    # decide whether the next one runs.
    runcmd_blocks = [vm_ptp_kvm_runcmd_lines()]
    if has_data_disk:
        # Mount /dev/vdb at /data on first boot, formatting it only if it has no
        # filesystem yet. Formatting and mounting are separate steps on purpose:
        # /etc/fstab lives on the *system* disk, which is reconstructible and is
        # rebuilt by a restore or a re-provision, while data.qcow2 comes back
        # from the archive already formatted. Gating the fstab line on the mkfs
        # (as this once did) meant a restored data disk was attached and never
        # mounted — the disk was there, /data was empty, and nothing said why.
        # Each step is guarded independently so the whole block is idempotent.
        runcmd_blocks.append([
            "if [ -b /dev/vdb ]; then",
            "  blkid /dev/vdb | grep -q TYPE || mkfs.ext4 -L workload-data /dev/vdb",
            "  mkdir -p /data",
            "  grep -q '^LABEL=workload-data ' /etc/fstab ||"
            " echo 'LABEL=workload-data /data ext4 defaults 0 2' >> /etc/fstab",
            "  mountpoint -q /data || mount /data",
            "fi",
        ])
    lines.append("runcmd:")
    for block in runcmd_blocks:
        lines.append("  - |")
        lines += [f"    {shline}" for shline in block]
    lines += [
        "package_update: false",
        "package_upgrade: false",
        f'final_message: "workload {name} cloud-init complete after $UPTIME seconds"',
        "",
    ]
    return "\n".join(lines)
