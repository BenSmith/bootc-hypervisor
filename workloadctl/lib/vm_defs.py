#!/usr/bin/env python3
"""The VM layer's vocabulary: paths, modes, nft object names, small parsers.

Split out of vm.py, where it was the first four hundred lines and everything
below it was written against it. Three kinds of thing, all of them leaves:
where files and sockets live and which binaries are called; the fixed sets of
modes a TOML may name; and the nftables set and map names, each already
paired v4/v6 by FamilyPair so that no caller downstream ever names one family
of an object on its own.

The small parsers travel with them rather than with the validators, because
what they enforce IS the constant beside them -- parse_memory_mib against the
bounds, parse_vm_port against the reserved ranges -- and separating a bound
from the code that checks it is how a bound stops being checked.

Nothing here imports vm; vm imports this and re-exports every public name, so
no caller changed.

Installed to /usr/libexec/workloadctl/vm_defs.py.
"""

import hashlib
import ipaddress
import re
from pathlib import Path
from typing import NamedTuple

from workload_addr import VmInspectAddress  # noqa: F401  (FamilyPair annotation)


# Runtime socket directory for VM workloads: /run/workload-vm/{name}/
VM_SOCKET_DIR = Path("/run/workload-vm")


# virtio-serial port name qemu-guest-agent binds to inside the guest. Fixed by
# the agent, not by us — qemu-ga only attaches to a virtserialport with exactly
# this name, so both the generator's -device line and any host-side client have
# to agree on it.
VM_GUEST_AGENT_PORT = "org.qemu.guest_agent.0"

# UID/GID of the guest's primary interactive user. Cloud images assign the
# first user (cloud-init's default user) uid/gid 1000, and our default
# cloud-config pins it there explicitly. virtiofsd internally translates this
# guest id <-> the host workload uid so the guest user can write the share
# (which on the host is owned by _wl-<name>); see generate_virtiofs_service.
VM_GUEST_UID = 1000

# The guest login account when [vm].user is unset, and where cloud-init puts its
# home. Both halves matter to workload-ensure-user: it renders the account into
# the built-in cloud-config AND has to recognise a [vm].volumes share mounted at
# that home, which would otherwise hide the authorized_keys the CLI logs in with
# (seed_vm_home_share_ssh_key; docs/vm-virtiofs.md §8).
VM_DEFAULT_GUEST_USER = "workload"
VM_GUEST_HOME_BASE = "/home"

# The SELinux context a virtiofs share covering the guest home must be mounted
# with, and the types that satisfy it.
#
# virtiofs carries no xattrs here (the sidecar gets no --xattr), so every file
# under such a share lands in the guest labelled bare `virtiofs_t` — a type
# sshd has no access to at all. `~/.ssh/authorized_keys` then becomes
# unreadable and key auth fails for a guest whose only account has no password.
# A `context=` mount option is the only fix: it labels the whole mount at once,
# which is also why the type has to be one sshd can read through to a home.
#
# BOTH HALVES MUST AGREE. workload-ensure-user emits this value into the
# built-in cloud-config (_virtiofs_mount_opts) and separately REFUSES a custom
# seed that does not carry one of these types (the seed contract in
# build_cloud_init_iso). A drift between the emitter and the check looks like
# the contract rejecting workloadctl's own output, which is what
# test_default_mode_emits_what_the_contract_demands pins.
#
# `ssh_home_t` is accepted alongside `user_home_t` because both carry the
# `user_home_type` attribute that stock policy grants sshd:
#   allow sshd_t user_home_type:file { getattr ioctl lock open read };
# An operator using some other locally-granted type opts out with
# [vm.cloud_init].seed_provides = ["home_context"].
VM_HOME_SELINUX_TYPES = ("user_home_t", "ssh_home_t")
VM_HOME_SELINUX_CONTEXT = "system_u:object_r:user_home_t:s0"


# The advertised DNS address is derived at unit start, not here: the generator
# runs Before=basic.target, where there is no default route yet. See
# libexec/workload-vm-netdev and generate_vm_service.

# Exit code workload-vm-notify uses to report a guest *reboot* (as opposed to a
# poweroff, which exits 0). QEMU runs with -no-reboot, so both a guest reboot and
# a guest poweroff make QEMU exit 0 — only the QMP SHUTDOWN event's reason tells
# them apart. For [vm].restart = "on-reboot" the wrapper translates a reboot into
# this nonzero code so systemd's Restart=on-failure cycles the VM, while a
# poweroff (exit 0) leaves it down. Nonzero and outside QEMU's own 0/1 range.
VM_REBOOT_EXIT_CODE = 133

# OVMF firmware search order (distro paths differ)
OVMF_CODE_CANDIDATES = [
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
    "/usr/share/ovmf/OVMF.fd",
]
OVMF_VARS_CANDIDATES = [
    "/usr/share/edk2/ovmf/OVMF_VARS.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
    "/usr/share/ovmf/OVMF_VARS.fd",
]


# --- VM helpers ---

def vm_guest_agent_socket(name: str) -> Path:
    """Host-side unix socket for this VM's qemu-guest-agent channel.

    Separate from the QMP monitors: this carries the *guest agent* protocol
    (qemu-ga inside the guest), not QEMU's own monitor protocol, so it can never
    contend with qmp.sock's ExecStop system_powerdown or the exporter's
    qmp-metrics.sock.
    """
    return VM_SOCKET_DIR / name / "ga.sock"


def vm_mac_address(name: str) -> str:
    """Derive a stable, locally-administered unicast MAC from the workload name."""
    h = hashlib.md5(f"wl-vm-{name}".encode(), usedforsecurity=False).digest()
    first = (h[0] & 0xFE) | 0x02  # locally administered, unicast
    return ":".join(f"{b:02x}" for b in [first, h[1], h[2], h[3], h[4], h[5]])


def vm_mac_collisions(name: str, other_names) -> list[str]:
    """Return the subset of other_names whose derived VM MAC equals name's.

    vm_mac_address hashes the name into a MAC with no allocation registry, so
    two distinct names can (rarely) collide. Under passt that is harmless —
    each guest is alone on its own link — but two VMs sharing an
    operator-provided LAN bridge ([vm.network].bridge) are on one segment and
    would fight over one address. This lets `validate` flag it up front.
    """
    mine = vm_mac_address(name)
    return sorted(other for other in set(other_names)
                  if other != name and vm_mac_address(other) == mine)


def find_ovmf_code() -> str | None:
    """Return the first existing OVMF_CODE path, or None."""
    for p in OVMF_CODE_CANDIDATES:
        if Path(p).exists():
            return p
    return None


def find_ovmf_vars() -> str | None:
    """Return the first existing OVMF_VARS path, or None."""
    for p in OVMF_VARS_CANDIDATES:
        if Path(p).exists():
            return p
    return None


def parse_memory_mib(value) -> int:
    """Parse memory in QEMU notation ("2048", "2048M", "4G") to MiB as int.

    Raises ValueError if the value is not a recognized form. Used by both
    [vm].memory validation and the systemd unit generator so they agree.
    """
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        raise ValueError("empty memory value")
    suffix = s[-1].upper()
    if suffix.isdigit():
        return int(s)
    n = int(s[:-1])
    if suffix == "M":
        return n
    if suffix == "G":
        return n * 1024
    if suffix == "K":
        # qemu accepts K but it's not useful for VM RAM
        return max(1, n // 1024)
    raise ValueError(f"unknown memory unit suffix {suffix!r} in {value!r}")


# --- Validation ---

# Published-port spec, following the container convention already in the schema
# ([network].ports = ["8080:80"]): an optional bind address, a host port, an
# optional guest port, an optional /proto. Parsed rather than passed through
# because passt spells the same thing differently (addr/host:guest, and TCP and
# UDP on separate netdev properties), so the generator has to take it apart.
# The bind-address branch must be a dotted quad or bracketed, never a bare run
# of digits — otherwise "8080:80" parses as address 8080, port 80.
VM_PORT_RE = re.compile(
    r"^(?:(?P<addr>\[[0-9a-fA-F:]+\]|\d{1,3}(?:\.\d{1,3}){3}):)?"
    r"(?P<host>\d+)"
    r"(?::(?P<guest>\d+))?"
    r"(?:/(?P<proto>tcp|udp))?$"
)


def parse_vm_port(spec: str) -> tuple[str | None, int, int, str]:
    """Parse a [vm.network].ports entry into (bind_addr, host, guest, proto).

    Raises ValueError on anything malformed. `bind_addr` is None when the
    operator did not pin one, in which case passt binds every address — the
    same meaning `-p 8080:80` has for podman.
    """
    m = VM_PORT_RE.match(spec.strip())
    if not m:
        raise ValueError(
            f"{spec!r} is not a port spec — use '8080:80', '8080', "
            f"'127.0.0.1:8080:80', or any of those with '/udp'")
    host = int(m.group("host"))
    guest = int(m.group("guest") or host)
    for label, port in (("host", host), ("guest", guest)):
        if not 1 <= port <= 65535:
            raise ValueError(f"{spec!r} has a {label} port out of range: {port}")
    addr = m.group("addr")
    if addr:
        addr = addr.strip("[]")
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            raise ValueError(f"{spec!r} has an invalid bind address: {addr!r}")
    return (addr, host, guest, m.group("proto") or "tcp")


VM_EGRESS_MODES = ("filtered", "open")
VM_EGRESS_DEFAULT = "filtered"


# Modes named but not built, mapped to when they arrive. Empty today, and KEPT
# empty rather than deleted: the refusal it drives says WHEN a mode lands
# instead of
# listing valid values, which is the difference between "you asked for a
# property that is coming" and "you made a typo". A future mode belongs here
# from the moment it is written down, not from the moment it works, because a
# key that accepted the word and quietly did something weaker would be a config
# claiming a property it does not have.
VM_TLS_UNBUILT: dict[str, str] = {}

# Parents anyone can register a label under, where a wildcard in a host list
# authorises a name the *guest* chooses. Warning-only, deliberately: the list
# cannot be exhaustive, and a stale copy shipped in an RPM that hard-fails a
# valid config is worse than a line of output.
VM_REGISTRATION_DOMAIN_PARENTS = (
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app",
    "vercel.app", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
    "web.app", "firebaseapp.com", "blogspot.com", "wordpress.com",
    "s3.amazonaws.com", "r2.dev", "ngrok.io", "trycloudflare.com",
)


# The private ranges the skeleton's internal drop matches on, restated here so
# the arming path can refuse an element the drop would never have caught.
#
# Duplicating them is the lesser evil and the test is what makes it safe:
# tests/test_vm_egress.py asserts these against the elements the .nft actually
# arms, so a range added on one side and not the other fails rather than
# silently making the refusal wrong. Parsing the .nft at runtime was the
# alternative and it puts a parser on the start path of every VM to answer a
# question about a constant.
VM_INTERNAL_PREFIXES4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.2.0/24", "192.168.0.0/16",
    "255.255.255.255",
)
VM_INTERNAL_PREFIXES6 = (
    "::/128", "::1/128", "::ffff:0.0.0.0/96", "64:ff9b::/96",
    "64:ff9b:1::/48", "2002::/16", "fc00::/7", "fe80::/10",
)
# fixed names of objects the code below creates and the code above reads, and
# a name that appears in two files is a name that can disagree with itself.

# Kernel rules match addresses; policy is written about names, and the
# resolution is transparent interception rather than a proxy.
#
# A PROXY IS ADVISORY. A guest process that ignores HTTPS_PROXY simply does not
# use it, and a default-deny chain can only turn that into a failure — never
# into a filtered request; every language runtime, every static binary and
# every vendored HTTP client is one more place the variables would have to be
# honoured. So the guest is told nothing, dials 80 and 443 normally, and a
# uid-keyed DNAT lands it on this workload's own inspector, which reads the
# Host header or the SNI and applies the `hosts` patterns. The guest's
# cooperation is not part of the enforcement path.
#
# There is no advertised endpoint. Every workload's broker is on a uid-derived
# loopback address the guest is never told (ADR 007 decision 6), so nothing
# needs one; the dummy link carries each filtered workload's own
# 198.18.x.y/32 and 2001:2::/128 inspector addresses and that is its whole job.
#
# 192.0.2.0/24 is therefore an ordinary internal-drop range: a documentation
# range no guest can legitimately want. It must be in VM_INTERNAL_PREFIXES4
# AND in the skeleton, because that list is also what decides whether an
# operator may write a [[vm.network.internal]] exemption (_internal_refusal).
# Armed on one side only, a site that genuinely routes TEST-NET-1 internally
# would be refused with no writable escape hatch.

# What [vm.cloud_init].seed_provides may name — the concerns a custom seed can
# declare it handles itself, suppressing the matching completeness check in
# build_cloud_init_iso.
#
# "proxy" was one of these and is not merely dropped: a seed that still declares
# it is REFUSED, by name, in validate_vm_config. Silently ignoring it would let
# a custom seed opt out of a check that no longer exists while never being told
# the check it now needs — the CA bundle the inspector's spliced connections
# will be presented under — and the operator would learn that at the first
# certificate error inside the guest rather than at validation.
#
# "home_context" is narrower than "mounts": a seed that mounts the home share
# itself but labels it by some means we cannot read from the seed text (an
# image-baked fstab entry, a local policy granting sshd another type) opts out
# of the SELinux check alone and keeps the mount check.
SEED_PROVIDES_CHOICES = {"ca", "mounts", "home_context"}

# The retired opt-out and what an operator should write instead. Kept as data
# rather than spelled into the error string so the accepted set and the message
# naming its replacement cannot drift.
SEED_PROVIDES_RETIRED = {
    "proxy": "ca",
}

# workload-ensure-user exits with this when a custom seed fails one of the
# contracts build_cloud_init_iso enforces (host key, CA bundle, volume mounts,
# home-share SELinux context).
# Distinct from a plain 1 so the caller can tell "the operator's seed is wrong,
# and the helper already said how" from "the helper broke": provisioning maps
# it to UsageError, which keeps the CLI's bug-report banner — and the traceback
# it prints — off an error the operator is expected to hit and can fix.
VM_SEED_CONTRACT_EXIT = 2


class SeedContractError(RuntimeError):
    """A custom [vm.cloud_init].user_data_file does not satisfy a contract the
    built-in seed would have satisfied. The message is written for the operator
    and names the fix."""
# The sidecar slice. Pinned rather than taken from [resources].slice so the
# cgroup path is always exactly two components and the rule's `level 2` is
# exact. These sidecars are not the payload; resource control belongs on the VM.
VM_SIDECAR_SLICE = "workloads.slice"

def vm_allowed_hosts(net: dict) -> list[str]:
    """The hostname allowlist for one workload, or [] if it has none."""
    hosts = net.get("hosts", [])
    return list(hosts) if isinstance(hosts, list) else []


def vm_runtime_dir(name: str) -> str:
    """Where one instance's config, allowlist, log and pid file live."""
    return f"{VM_SOCKET_DIR}/{name}"


