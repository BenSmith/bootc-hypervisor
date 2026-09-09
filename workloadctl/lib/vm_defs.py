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

import fnmatch
import hashlib
import ipaddress
import re
from pathlib import Path
from typing import NamedTuple

from workload_lib import normalise_hostname
from workload_addr import VmInspectAddress  # noqa: F401  (FamilyPair annotation)


# Runtime socket directory for VM workloads: /run/workload-vm/{name}/
VM_SOCKET_DIR = Path("/run/workload-vm")

# The SELinux type that directory must carry, and the fcontext pattern the RPM's
# %post registers to give it that type. A confined QEMU cannot create a socket
# under /run's default var_run_t, so without this the guest dies before it binds
# QMP and the only symptom is a timeout that names nothing SELinux.
#
# Two spellings, both needed. svirt_var_run_t is an ALIAS: it is what the rule
# is written with (and what the policy and every doc call it), but the kernel
# stores the real name, so getfattr, `ls -Z` and matchpathcon all report
# qemu_var_run_t. A label comparison that knows only one of them is wrong half
# the time, which is why the check below accepts either.
VM_SOCKET_SELINUX_TYPE = "svirt_var_run_t"
VM_SOCKET_SELINUX_TYPE_REAL = "qemu_var_run_t"
VM_SOCKET_FCONTEXT_PATTERN = f"{VM_SOCKET_DIR}(/.*)?"

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

# What a filtered workload's redirected TLS connections get.
#
# `splice` reads the ClientHello's SNI, matches it against `hosts`, and replays
# those exact bytes upstream. Nothing is decrypted; the guest's handshake is
# with the origin, and this host never holds a key to it.
#
# `inspect` terminates. The inspector completes the guest's handshake itself
# with a leaf minted by this workload's own CA, opens a separately verified
# session to the origin, and authorises every REQUEST inside. It is the default
# because the property the allowlist claims -- that the guest reaches these
# hosts and no others -- is only true per request under termination: under
# `splice` a name is checked once, at the front of a connection whose contents
# nothing can see.
#
# THE DEFAULT MOVED, AND IT IS NOT A FREE CHANGE. A terminated guest must trust
# the workload's CA, which reaches it through the seed, which cloud-init applies
# once per instance-id. An EXISTING filtered guest does not gain that trust by
# upgrading the RPM: it gets certificate errors on every HTTPS request until it
# is re-seeded. `tls = "splice"` is the answer for a guest that cannot be, and
# is still fully supported -- it is a weaker property, not a deprecated one.
#
# IT COSTS A SENTENCE. `splice` here is the widest bypass in this schema: every
# host, not a named one, and the three narrower hatches beside it (.allow,
# .internal, .splice, .http2) have each carried a written `reason` since they
# existed. So this one requires `tls_reason`, for the reason those do -- the
# person deciding whether a bypass is still needed is not the person who opened
# it, and "spliced because this guest cannot hold the CA" and "spliced because
# nobody tried" are the same two words in a config without it. The key is a
# sibling scalar rather than a table because `tls` is a mode, not a list: a
# polymorphic `tls` that was sometimes a string and sometimes a table would
# make the commonest line in the section the one hardest to read.
VM_TLS_MODES = ("splice", "inspect")
VM_TLS_DEFAULT = "inspect"

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

# The uid-keyed egress layer (ADR 006 §4). One table shared by every VM;
# units manage set *elements* only, never rules.
NFT_BIN = "/usr/sbin/nft"
IP_BIN = "/usr/sbin/ip"
NFT_TABLE = "inet workload_filter"
NFT_SET_FILTERED = "wl_filtered"
NFT_SET_ALLOW4 = "wl_allow4"
NFT_SET_ALLOW6 = "wl_allow6"


# --- One object, two families ---
#
# In the inet family `ip daddr` matches v4 only and `ip6 daddr` v6 only, so
# every address-bearing object here is two nftables objects. The RULES have to
# be written twice; the Python does not, and writing it twice is how the v6
# half goes missing. It has: the reserved-range check was v4 by construction
# and 2001:2::/48 went unchecked for a whole rung (TestReservedRanges), and an
# element in the wrong family's set matches nothing at all -- a silent failure,
# because a set that never matches looks exactly like a set nothing dialled.
#
# So the two names are ONE value, and the builders below take a FamilyPair and
# fill both halves rather than naming either. A builder cannot emit one family:
# there is no line in it that says `.v4`.

class FamilyPair(NamedTuple):
    """The v4 and v6 names of one logical nftables set or map."""
    v4: str
    v6: str

    def of(self, version: int) -> str:
        return self.v6 if version == 6 else self.v4


def _both_families(pair: FamilyPair, addr: "VmInspectAddress",
                   build) -> dict[str, list[str]]:
    """Both halves of one object, built from this workload's address in each.

    BOTH, unconditionally: these objects are derived from a uid rather than
    from operator input, so there is no such thing as a workload with a v4
    inspector and no v6 one, and an empty half would mean the derivation
    broke.
    """
    return {pair.v4: build(addr.v4), pair.v6: build(addr.v6)}


def _split_by_family(pair: FamilyPair, elements) -> dict[str, list[str]]:
    """Bucket (address, element-expression) pairs into their family's half.

    Empty halves are dropped rather than emitted, because these objects come
    from operator input -- an allowlist naming only v4 names is ordinary --
    and `nft add element ... { }` is an error, not a no-op.
    """
    buckets: dict[str, list[str]] = {pair.v4: [], pair.v6: []}
    for addr, element in elements:
        buckets[pair.of(addr.version)].append(element)
    return {name: entries for name, entries in buckets.items() if entries}


NFT_PAIR_ALLOW = FamilyPair(NFT_SET_ALLOW4, NFT_SET_ALLOW6)
# Internal destination prefixes the egress inspector may not connect OUT to. The
# elements are constant and live in the skeleton, not here -- nothing in Python
# manages them. The names exist so tests can name the sets and so
# `vm_egress_check` can tell a loaded guard from a table that predates it,
# which it cannot infer from wl_filtered membership: nft state is kernel state
# until reboot, so a VM started before an upgrade keeps the older chain.
NFT_SET_INTERNAL4 = "wl_internal4"
NFT_SET_INTERNAL6 = "wl_internal6"
NFT_PAIR_INTERNAL = FamilyPair(NFT_SET_INTERNAL4, NFT_SET_INTERNAL6)
# The per-workload exceptions to those drops -- [[vm.network.internal]]. Per
# workload, so unlike the interval sets above these ARE managed from Python and
# are never flushed by the skeleton.
NFT_SET_INTERNAL_OK4 = "wl_internal_ok4"
NFT_SET_INTERNAL_OK6 = "wl_internal_ok6"
NFT_PAIR_INTERNAL_OK = FamilyPair(NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6)

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
# The inspector's listener-range guard sets (§7.2/§7.2.1/§7.2.3). Elements are
# per workload and are armed by the same script that arms the DNAT maps, not
# by the filter helper: the dst sets hold the TRANSLATED tuple, which only the
# redirect's installer knows. The self sets carry a per-element counter —
# the load-bearing half, since it is what attributes a wrong-port self-dial to
# its workload instead of the cross-workload guard's shared number. None of
# these is flushed in the skeleton; the ones that hold per-workload state are
# never emptied by it.
NFT_SET_INSPECT_DST = "wl_inspect_dst"
NFT_SET_INSPECT_DST6 = "wl_inspect_dst6"
NFT_PAIR_INSPECT_DST = FamilyPair(NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6)
NFT_SET_INSPECT_SELF = "wl_inspect_self"
NFT_SET_INSPECT_SELF6 = "wl_inspect_self6"
NFT_PAIR_INSPECT_SELF = FamilyPair(NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6)
# The cross-workload guard's destination sets: every LIVE inspector address on
# the host, one plain address per armed workload and no uid. Armed alongside
# the four above, by the same helper, for the same reason.
#
# WHY A SET AND NOT THE /16. Naming 198.18.0.0/16 outright would make a
# workload-scoped tool drop every non-root packet on the host bound for a /16
# workloadctl does not own -- an operator using that range for anything of
# their own would lose it whether or not they run workloads. Bounded to the
# addresses workloadctl ITSELF allocated, the guard reaches exactly as far as
# workloadctl's own listeners, and the drop stays guarded on set membership:
# an abandoned table holds an empty set and is inert.
NFT_SET_INSPECT_LIVE = "wl_inspect_live"
NFT_SET_INSPECT_LIVE6 = "wl_inspect_live6"
NFT_PAIR_INSPECT_LIVE = FamilyPair(NFT_SET_INSPECT_LIVE, NFT_SET_INSPECT_LIVE6)


# The inspector's plumbing, named here for the same reason: these are the
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

# Dummy link carrying the advertised address and every per-workload listener
# address. Host-global and shared, created on demand and never torn down by a
# workload stop: it is refcount-free because it holds no per-workload state,
# costs nothing idle, and an orphan is inert.
#
# The DEVICE name still reads "workload-proxy" after the proxy it was named for
# was deleted, and that is deliberate. A link name is an object that exists on
# running hosts: renaming it would leave the old link in place holding this
# workload's 127.128.x.y and 198.18.x.y addresses, with the new link claiming
# the same addresses — two links answering for one address is a routing
# ambiguity, and it would arrive on upgrade rather than on a fresh install.
VM_ADVERTISED_IFACE = "workload-proxy"

# The host-side process that re-originates a workload's egress — the egress
# inspector, and it alone; the synthesising responder re-originates nothing,
# see below — runs as the workload's own user, so `meta skuid` cannot separate
# its traffic from the guest's, and under default-deny the drop catches it too,
# leaving the workload's own enforcement path unable to reach anything. The control group is the discriminator that
# survives the shared uid: systemd assigns it, a guest can neither enter nor
# forge it, and it widens no destination or port, so a guest that dials 443
# past the inspector is still dropped.
#
# ONE MEMBER: the egress inspector. The synthesising responder is not a second
# one -- it answers from memory and opens no socket, so there is no
# vm_resolve_cgroup and nothing arms one. Its twin in the nat table,
# wl_inspect_cg, exempts the
# same process from the REDIRECT; this one exempts it from the DROP. A process
# needs both or it either reaches nothing or loops into the listener it is
# dialling past.
#
# The slice is pinned rather than taken from [resources].slice so the cgroup
# path is always exactly two components and the rule's `level 2` is exact.
# These sidecars are not the payload; resource control belongs on the VM.
NFT_SET_EGRESS_CG = "wl_egress_cg"
VM_SIDECAR_SLICE = "workloads.slice"
NFT_PROXY_SKELETON = "/usr/share/workloadctl/workload-proxy.nft"
NFT_PROXY_TABLE = "inet workload_proxy"

# The transparent redirect's objects (§7.1). The two maps carry one element per
# workload per redirected port, keyed uid . original port -> (listener address,
# listener port), one map per family because `dnat ip` and `dnat ip6` are
# different translations in the inet family; the set exempts the ONE process
# that re-originates workload-uid traffic -- the inspector, on the same terms
# and for the same reason as wl_egress_cg above -- so its own dials are not
# translated into the listener it is dialing past. All three live in table
# inet workload_proxy and are declared in workload-proxy.nft.
NFT_MAP_INSPECT4 = "wl_inspect4"
NFT_MAP_INSPECT6 = "wl_inspect6"
NFT_PAIR_INSPECT_MAP = FamilyPair(NFT_MAP_INSPECT4, NFT_MAP_INSPECT6)
NFT_SET_INSPECT_CG = "wl_inspect_cg"

def vm_allowed_hosts(net: dict) -> list[str]:
    """The hostname allowlist for one workload, or [] if it has none."""
    hosts = net.get("hosts", [])
    return list(hosts) if isinstance(hosts, list) else []


def vm_uses_inspect(config: dict) -> bool:
    """Whether this workload's egress is redirected into an inspector.

    The single source of the predicate that decides whether the inspect
    socket/service units exist at all: not bridged (a bridged guest has no
    host socket in its data path, so there is no uid to key the redirect on)
    and `egress` filtered (an unfiltered VM would be the one the redirect
    breaks — its dial to a port-443 service it is allowed to reach would be
    translated into a listener that would refuse it, having no policy naming
    it). `workload-vm-inspect`'s
    inspection_applies delegates here rather than re-stating it, so the
    generator and the helper cannot drift apart.

    A workload with no [vm] section is not a VM and is never inspected. That is
    tested here rather than left to the callers: every caller happens to be
    behind a VM-only branch today, so a container config reaching this returned
    True and nothing noticed. A predicate documented as the single source of a
    decision has to be right standing alone, or the next caller inherits a bug
    that reads as correct at its own call site.
    """
    if "vm" not in config:
        return False
    vm_cfg = config.get("vm", {}) or {}
    net = vm_cfg.get("network", {}) or {}
    if not isinstance(net, dict) or net.get("bridge"):
        return False
    return net.get("egress", VM_EGRESS_DEFAULT) == "filtered"


def vm_runtime_dir(name: str) -> str:
    """Where one instance's config, allowlist, log and pid file live."""
    return f"{VM_SOCKET_DIR}/{name}"


# Hostname vocabulary: the one normalisation, the character class that is
# refused at the parse, and the one comparison. Down here because both
# substrates and three entrypoints ask the same questions of a name, and a
# second answer to "what is this name" is a name the guest can spell twice.

# workload_lib.normalise_hostname, under the name the listener, egress_mint and the
# tests already import. Moved down rather than copied when the container half
# needed it too: a second normalisation is a second answer to "what is this
# name", and the guest picks which one it gets by how it spells the host.
vm_normalise_hostname = normalise_hostname


def vm_hostname_control_character(host: str) -> str | None:
    """The first control character in a name, or None if it carries none.

    A name read off the wire — an SNI, a DNS label — is bytes a guest chose,
    and both readers of one decode ASCII rather than refusing it: a control
    character is ASCII. The name then reaches a `print()` whose destination is
    the journal, where a bare LF ends the record and the rest of the name
    becomes a SECOND entry, indistinguishable from one this program wrote. A
    guest that can write `evil.com\\nsplice plane=tls … host=github.com` can
    forge the evidence an operator reads a decision from. The same name is also
    carried into the status document that `workloadctl diagnose` renders.

    Refused, not escaped, and refused at the parse — the reason
    `_reject_controls` in the cleartext plane gives for the same character
    class: a field with a line ending inside it has no reading both ends share,
    and rewriting one into something harmless is picking a reading. No name
    that reaches a decision here needs one, so the parse is where it stops
    rather than every log site having to remember.

    Returns the character so the caller can name it in ITS own exception type
    and disposition: an unreadable hello and a malformed query are already
    counted differently, and a shared raise would flatten them.
    """
    for ch in host:
        if ch < " " or ch == "\x7f":
            return ch
    return None


def vm_hostname_match(host: str, patterns) -> bool:
    """Whether a hostname is authorised by a list of fnmatch patterns.

    `fnmatch.fnmatchcase`, not `fnmatch.fnmatch`. The plain form normalises its
    arguments through os.path.normcase, which is a no-op on Linux and lowercases
    on other platforms — so it is case-insensitive only by accident of platform,
    and the operators' patterns were written against fnmatch's case-sensitive
    behaviour. Both sides are normalised here instead, which is the same answer
    everywhere.

    The apex trap is preserved, not fixed: `*.example.com` does not authorise
    `example.com`. That is fnmatch's behaviour, it is what the proxy this
    replaced did with the same list, and three tracked files document it. A rung that
    quietly widened it would silently grant every existing config a destination
    its operator did not write down.
    """
    host = vm_normalise_hostname(host)
    if not host:
        return False
    return any(fnmatch.fnmatchcase(host, vm_normalise_hostname(p))
               for p in patterns)


# The environment variables that point a guest's HTTP clients at that bundle.
# Five, because there is no single one: OpenSSL reads SSL_CERT_FILE, Node reads
# NODE_EXTRA_CA_CERTS, python-requests reads REQUESTS_CA_BUNDLE, git reads
# GIT_SSL_CAINFO and pip reads PIP_CERT. A guest missing any one of them fails
# only in that ecosystem, which is the hardest kind of failure to attribute.
VM_CA_ENV_VARS = (
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
)


# The guest variables workloadctl seeds itself, and therefore the ones a
# credential's `env` may not be. Derived from the producers rather than listed,
# so a sixth CA variable cannot leave this behind: the failure a stale copy
# produces is a silent overwrite in the seed, not an error anywhere.
#
# No broker variable is reserved, because nothing seeds one -- the guest is
# never told a broker address (ADR 007 decision 6).
VM_RESERVED_GUEST_ENV = frozenset(VM_CA_ENV_VARS)
