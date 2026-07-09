"""
Shared constants and utilities for the workload provisioning system.

Used by workload-generate (the early-boot oneshot Python script),
workload-ensure-user, and workloadctl.
Installed to /usr/libexec/workloadctl/workload_lib.py.
"""

import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import pwd
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# --- Constants ---

# Config directory (override with WORKLOAD_CONFIG_DIR env var for testing)
WORKLOAD_CONFIG_DIR = Path(os.environ.get("WORKLOAD_CONFIG_DIR", "/etc/workloads.d"))


def workload_config_dir() -> Path:
    """Canonical call-time reader for the workloads config dir. Resolves
    WORKLOAD_CONFIG_DIR against this module at call time, so a single
    patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", tmp) is honored everywhere.
    Also re-checks the env var at call time so in-process module loaders that
    set WORKLOAD_CONFIG_DIR in os.environ before exec_module() work correctly."""
    env_val = os.environ.get("WORKLOAD_CONFIG_DIR")
    if env_val:
        return Path(env_val)
    return WORKLOAD_CONFIG_DIR

# Persistent workload data directory
WORKLOADS_BASE = Path("/var/lib/workloads")

# systemd-creds credential store. Secrets are created here (`workloadctl secret`),
# loaded from here by the generator, and decrypted at runtime by
# workload-ensure-user. Single source of truth so backup/restore/rotate can't
# drift onto the wrong path (the plain /etc/credstore is only a legacy fallback).
CREDSTORE_DIR = Path("/etc/credstore.encrypted")

# Shipped bundle control-file tree (Containerfile/build.sh/setup.sh/policy.cil),
# keyed by `[workload] bundle`. Env-overridable so the control-file resolver can
# be unit-tested against a temp /usr tree. The operator override leg lives under
# WORKLOAD_CONFIG_DIR/<name>/ (see WorkloadConfig.resolve_control_file).
WORKLOAD_BUNDLES_DIR = Path(
    os.environ.get("WORKLOAD_BUNDLES_DIR", "/usr/share/workloadctl/workloads")
)

# Username prefix for workload system users
USERNAME_PREFIX = "_wl-"

# UID range reserved for workload users.
UID_MIN = 10000
UID_MAX = 52948

# Maximum workload name length (32-char Linux username limit - 4-char prefix - 1)
MAX_NAME_LENGTH = 27

# Workload name pattern: lowercase letter, then lowercase letters/digits/hyphens
NAME_PATTERN = re.compile(r'^[a-z][a-z0-9-]*$')

# Container name pattern (same shape as workload name)
CONTAINER_NAME_PATTERN = re.compile(r'^[a-z][a-z0-9-]*$')
MAX_CONTAINER_NAME_LENGTH = 27
VALID_WORKLOAD_MODES = ("single", "pod", "bridge")

# Directives written by the generator — custom_directives should not override these
GENERATOR_OWNED_DIRECTIVES = frozenset({
    "Type", "NotifyAccess", "User", "Group", "Environment", "EnvironmentFile",
    "ExecStartPre", "ExecStart", "ExecStop",
    "StandardOutput", "StandardError",
    "Restart", "RestartSec",
    "ProtectSystem", "ReadWritePaths", "PrivateTmp",
})

# --- VM constants ---

# Runtime socket directory for VM workloads: /run/workload-vm/{name}/
VM_SOCKET_DIR = Path("/run/workload-vm")

# UID/GID of the guest's primary interactive user. Cloud images assign the
# first user (cloud-init's default user) uid/gid 1000, and our default
# cloud-config pins it there explicitly. virtiofsd internally translates this
# guest id <-> the host workload uid so the guest user can write the share
# (which on the host is owned by _wl-<name>); see generate_virtiofs_service.
VM_GUEST_UID = 1000

# Default bridge for VM workloads.  _workload-br is the workloadctl-managed
# isolated NAT bridge (auto-provisioned by workload-bridge.service). The name
# is deliberately distinctive (and reserved) so the always-manage bridge setup
# won't adopt an unrelated interface; it must stay <=15 chars (Linux IFNAMSIZ).
# Override to e.g. "br0" to attach VMs directly to a pre-existing LAN bridge.
VM_BRIDGE_NAME = "_workload-br"
# Managed-bridge network config is HOST-LEVEL, not per-VM (ADR 002): the bridge
# is one host-global refcounted resource, so its subnet/DNS can't coherently
# take per-VM overrides. Single source of truth = the subnet CIDR
# (WORKLOADCTL_VM_BRIDGE_SUBNET), from which the gateway IP, CIDR, and — the
# ADR-002 fix — the DHCP range are all DERIVED, so a relocated bridge hands
# guests addresses on its own subnet instead of a stale hardcoded window.
def managed_bridge_params(subnet_cidr: str) -> tuple[str, str, str, str]:
    """Derive (gateway_ip, gateway_cidr, normalized_subnet, dhcp_range) for the
    managed VM bridge from a single subnet CIDR.

    The gateway is the first host address; the DHCP window is offsets .100–.199
    within the subnet (reproducing the historical 192.168.200.100–199 range on
    the /24 default). On a subnet too small for that window the range falls
    back to the full usable span (first host after the gateway through the
    last host) instead of collapsing onto a single clamped address. Deriving
    the range from the subnet is the ADR-002 fix: the range used to be
    hardcoded, so a non-default subnet handed guests addresses off the wrong
    subnet. Raises ValueError if the subnet leaves no leasable address after
    the gateway (/31, /32).
    """
    net = ipaddress.ip_network(subnet_cidr, strict=False)
    gateway = net.network_address + 1
    first_usable = net.network_address + 2  # +1 is the gateway
    last_usable = net.broadcast_address - 1
    if last_usable < first_usable:
        raise ValueError(
            f"VM bridge subnet {net} has no leasable address after the "
            f"gateway; use a /30 or larger")
    dhcp_start = net.network_address + 100
    dhcp_end = min(net.network_address + 199, last_usable)
    if dhcp_start > dhcp_end:
        dhcp_start = first_usable
    return (str(gateway), f"{gateway}/{net.prefixlen}", str(net),
            f"{dhcp_start},{dhcp_end},12h")


VM_BRIDGE_IP, VM_BRIDGE_CIDR, VM_BRIDGE_SUBNET, VM_DHCP_RANGE = managed_bridge_params(
    os.environ.get("WORKLOADCTL_VM_BRIDGE_SUBNET", "192.168.200.0/24"))
VM_BRIDGE_DNS = [s.strip() for s in os.environ.get(
    "WORKLOADCTL_VM_BRIDGE_DNS", "1.1.1.1,8.8.8.8").split(",") if s.strip()]
# dnsmasq for the bridge runs confined in the SELinux dnsmasq_t domain, which
# may only write its lease/pid files in dnsmasq-owned, dnsmasq_lease_t-labeled
# locations. /var/lib/workloads is labeled container_file_t (rootless podman),
# so dnsmasq_t can neither write nor traverse it — putting the lease there made
# dnsmasq fail to start on enforcing systems (the default), leaving VMs with no
# DHCP. /var/lib/dnsmasq ships with the dnsmasq package, already labeled
# dnsmasq_lease_t, and policy allows dnsmasq_t to create/write files there.
VM_DHCP_LEASE_FILE = Path("/var/lib/dnsmasq/workload-bridge.leases")
VM_DHCP_PIDFILE = Path("/var/lib/dnsmasq/workload-bridge.pid")

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


# --- Config locator ---

def workload_config_path(name: str) -> Path:
    """Instance config path for a workload, under the config dir."""
    return workload_config_dir() / name / "workload.toml"


# Enabled-ness is denoted by the presence of this marker file in the workload's
# own config dir — NOT by a field in workload.toml. `enable`/`disable` touch and
# unlink it; the boot generator and `WorkloadConfig.enabled` read it. This keeps
# workload.toml purely declarative (no command ever rewrites it) and makes the
# state a single atomic 1-byte file living right beside the config.
ENABLED_MARKER_NAME = ".enabled"


def workload_enabled_marker(name: str) -> Path:
    """Path to a workload's enable marker; its presence == enabled."""
    return workload_config_dir() / name / ENABLED_MARKER_NAME


def workload_is_enabled(name: str) -> bool:
    """Single source of truth for enabled-ness: the marker file is present."""
    return workload_enabled_marker(name).exists()


def iter_workloads(base: Path | None = None) -> list[tuple[str, Path]]:
    """(name, config_path) for every workload under `base`, sorted by name.

    `base` defaults to the config dir (the common case); pass BUNDLES_DIR to
    discover shipped bundles instead. Either way the name is derived from the
    directory so no caller knows the on-disk shape — this is the single place
    discovery encodes the layout.
    """
    if base is None:
        base = workload_config_dir()
    return sorted(
        (p.parent.name, p)                                    # name from dir, not stem
        for p in base.glob("*/workload.toml")
    )


# --- Kind routing ---

def infer_workload_kind(config: dict) -> str:
    """Return 'vm' if the config has a top-level [vm] section, else 'container'."""
    return "vm" if "vm" in config else "container"


# --- VM helpers ---

def vm_mac_address(name: str) -> str:
    """Derive a stable, locally-administered unicast MAC from the workload name."""
    h = hashlib.md5(f"wl-vm-{name}".encode(), usedforsecurity=False).digest()
    first = (h[0] & 0xFE) | 0x02  # locally administered, unicast
    return ":".join(f"{b:02x}" for b in [first, h[1], h[2], h[3], h[4], h[5]])


def vm_socket_dir(name: str) -> Path:
    """Return the runtime socket directory for a VM workload."""
    return VM_SOCKET_DIR / name


def vm_home_dir(name: str) -> Path:
    return WORKLOADS_BASE / name


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


# --- QMP ---

class QMPClient:
    """Minimal QMP client over QEMU's newline-delimited JSON monitor.

    Single source of truth for the QMP wire protocol — workload-vm-notify,
    workload-vm-qmp, workload-exporter, and workloadctl all build on this so
    the connect/retry, capabilities handshake, and async-event draining can't
    drift between them. Usable as a context manager.

    Note on monitor contention: a `-qmp unix:...,server=on,wait=off` socket
    serves only one client at a time. The always-on metrics exporter therefore
    connects to a *separate* QMP monitor (qmp-metrics.sock) so its polling can
    never block the control monitor (qmp.sock) used for system_powerdown etc.
    """

    def __init__(self):
        self._sock = None
        self._buf = b""

    def connect(self, path, timeout: float = 10.0, recv_timeout: float = 5.0):
        """Connect to the QMP unix socket, retrying until `timeout` elapses.

        Raises TimeoutError if the socket never becomes available.
        """
        deadline = time.monotonic() + timeout
        while True:
            # The socket is closed on the way out of this block unless the
            # connect succeeds, in which case pop_all() detaches it so it
            # survives as self._sock. This releases the fd on *any* failure in
            # the attempt — not just the OSError below — so a retry loop against
            # a not-yet-ready monitor can't leak descriptors.
            with contextlib.ExitStack() as stack:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                stack.callback(s.close)
                s.settimeout(recv_timeout)
                try:
                    s.connect(str(path))
                except (OSError, ConnectionRefusedError):
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"QMP socket not ready after {timeout:.0f}s: {path}"
                        )
                    time.sleep(0.2)
                    continue
                self._sock = s
                stack.pop_all()  # success: keep the socket open
                return

    def _readline(self) -> dict:
        """Read one newline-delimited JSON object from the socket."""
        while True:
            if b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                return json.loads(line.decode())
            assert self._sock is not None
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("QMP socket closed")
            self._buf += chunk

    def _send(self, obj: dict):
        assert self._sock is not None
        self._sock.sendall((json.dumps(obj) + "\n").encode())

    def negotiate(self):
        """Read the QMP greeting and switch the monitor into command mode."""
        self._readline()  # {"QMP": {"version": ..., "capabilities": [...]}}
        self._send({"execute": "qmp_capabilities"})
        self._readline()  # {"return": {}}

    def execute(self, command: str, arguments: dict | None = None,
                max_events: int = 20) -> dict:
        """Run one QMP command, draining async events until its reply arrives.

        Returns the full reply dict ({"return": ...} or {"error": ...}).
        Raises ConnectionError if no reply arrives within max_events messages.
        """
        cmd: dict[str, Any] = {"execute": command}
        if arguments:
            cmd["arguments"] = arguments
        self._send(cmd)
        for _ in range(max_events):
            msg = self._readline()
            if "return" in msg or "error" in msg:
                return msg
        raise ConnectionError(
            f"no QMP reply for {command!r} after {max_events} messages"
        )

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --- virtiofs ---

def virtiofs_tag(container_path: str, index: int = 0) -> str:
    """Derive a virtiofs mount tag (<=36 chars) from a guest mountpoint.

    Single source of truth: the generator, the cloud-init builder, and any
    runtime helpers must derive tags through this function or they will drift.
    """
    tag = container_path.lstrip("/").replace("/", "-") or f"vol{index}"
    tag = re.sub(r'[^a-zA-Z0-9_-]', '-', tag)
    return tag[:36]


def virtiofs_tags(volume_specs) -> list[str]:
    """Collision-free virtiofs tags for a VM's ordered volume list (B3).

    virtiofs_tag() sanitizes then truncates a guest mountpoint to <=36 chars, so
    two distinct mountpoints can collapse to the same tag. The generator keys
    both the virtiofsd sidecar unit filename (workload-<name>-virtiofs-<tag>) and
    the QEMU chardev/device tag off this string, so a collision silently
    overwrites one sidecar unit and emits duplicate chardev tags. Disambiguate
    any colliding tag by suffixing the volume index (kept inside the 36-char
    budget). Order matches the input list.

    Single source of truth: the generator, workload-ensure-user (cloud-init
    mounts), and cmd_lifecycle purge must all derive the tag SET through this so
    unit names / chardev tags / fstab entries stay in sync.
    """
    base = [virtiofs_tag(parse_volume_spec(v)[1], i)
            for i, v in enumerate(volume_specs)]
    counts = {}
    for t in base:
        counts[t] = counts.get(t, 0) + 1
    # Every assigned tag is checked against ALL previously assigned tags, not
    # just the base counts: a suffixed tag ("data" -> "data-1") could otherwise
    # re-collide with another volume's natural un-suffixed tag ("data-1").
    used = set()
    tags = []
    for i, t in enumerate(base):
        cand = t
        bump = i
        while cand in used or (cand == t and counts[t] > 1):
            suffix = f"-{bump}"
            cand = t[:36 - len(suffix)] + suffix
            bump += 1
        used.add(cand)
        tags.append(cand)
    return tags


def parse_volume_spec(vol_spec: str) -> tuple[str, str, str]:
    """Parse a "host:guest[:opts]" volume spec, returning (host, guest, opts).

    A bare token (no ':') is treated as host == guest. opts defaults to "rw".
    Only the first two ':' delimit fields, so opts may itself contain a colon
    (e.g. mount options). This is the single source of truth for the grammar;
    expand_volume_path builds on it.
    """
    parts = vol_spec.split(":", 2)
    host = parts[0]
    guest = parts[1] if len(parts) > 1 else parts[0]
    opts = parts[2] if len(parts) > 2 else "rw"
    return host, guest, opts


# --- Naming conventions ---

def workload_username(name: str) -> str:
    """Return the system username for a workload: _wl-{name}."""
    return f"{USERNAME_PREFIX}{name}"


# Flock guarding the subuid/subgid UID-allocation critical section (#4). Must be
# the identical path across every participant (workload-ensure-user, cmd_lifecycle
# enable + disable/purge) or the flock stops mutexing.
SUBID_LOCK = Path("/run/lock/workload-subid.lock")

# Reentrancy state for subid_lock(): the enable path holds the lock across
# allocation *through* the sysusers write, and get_next_uid() (called inside
# that span) now takes the lock too. Nesting on a single cached fd makes the
# inner acquire a no-op instead of a same-process deadlock (a second fd's
# flock() would block against the outer hold). Single-threaded by design —
# both callers (the boot generator, the CLI) run one allocation at a time.
_subid_lock_fd = None
_subid_lock_depth = 0


@contextlib.contextmanager
def subid_lock():
    """Hold SUBID_LOCK for the UID/subid allocation critical section.

    Reentrant within a process (see _subid_lock_depth): only the outermost
    acquire flocks, only the outermost release unlocks. Cross-process this is a
    plain exclusive flock, so a boot-time generate and a concurrent
    `workloadctl enable` can't hand out the same UID.

    Best-effort *only* for a permission failure: if the caller can't open the
    root-owned lock (an unprivileged caller — /run/lock is root-owned) the body
    runs unlocked rather than blocking. Any other OSError (a transient flock
    EINTR, ENOSPC, EIO …) propagates so allocation fails loudly instead of
    silently running without the mutex — the isolation stakes are too high to
    swallow those. Both real callers run as root where the open+flock succeed,
    so the guarantee holds where allocation actually happens; the permission
    escape hatch only keeps the exit-0 boot generator (whose per-workload loop
    already logs-and-continues) from being the thing that trips.
    """
    global _subid_lock_fd, _subid_lock_depth
    if _subid_lock_depth == 0:
        try:
            SUBID_LOCK.parent.mkdir(parents=True, exist_ok=True)
            _subid_lock_fd = open(SUBID_LOCK, "w")
            fcntl.flock(_subid_lock_fd.fileno(), fcntl.LOCK_EX)
        except OSError as e:
            # Drop any half-open fd first (the finally below never runs — we
            # raise before _subid_lock_depth is incremented — so clean up here).
            if _subid_lock_fd is not None:
                _subid_lock_fd.close()
            _subid_lock_fd = None
            # Permission failure → unprivileged caller can't take the root-owned
            # lock; degrade to unlocked. Anything else is a real fault.
            if not isinstance(e, PermissionError):
                raise
    _subid_lock_depth += 1
    try:
        yield
    finally:
        _subid_lock_depth -= 1
        if _subid_lock_depth == 0 and _subid_lock_fd is not None:
            fcntl.flock(_subid_lock_fd.fileno(), fcntl.LOCK_UN)
            _subid_lock_fd.close()
            _subid_lock_fd = None


# Per-run tracking set: `get_next_uid` records UIDs allocated during this
# process invocation so multiple workloads enabled in the same run don't race.
_allocated_uids: set[int] = set()


def _reserved_uids_in_pending_sysusers() -> set[int]:
    """UIDs handed out in pending sysusers configs but not yet in /etc/passwd.

    Between allocation and `systemd-sysusers` creating the user, a workload's
    UID lives only in its sysusers .conf: the boot generator writes it into
    /run/systemd/system and defers user creation to the workload's setup
    service (potentially much later), while enable stages a copy in
    /run/sysusers.d. During that gap the UID is invisible to `pwd.getpwall()`,
    so a concurrent allocator would re-hand-out the slot. get_next_uid() unions
    these in — provided every allocator writes its .conf while still holding
    SUBID_LOCK — to close that window. /run is tmpfs (no cross-boot staleness)
    and disable removes the conf, so this set tracks live allocations.
    """
    reserved: set[int] = set()
    for d in (RUN_SYSTEMD_SYSTEM, RUN_SYSUSERS_D):
        try:
            confs = list(d.glob("workload-*.conf"))
        except OSError:
            continue
        for conf in confs:
            try:
                text = conf.read_text()
            except OSError:
                continue
            for line in text.splitlines():
                # sysusers user line: `u <name> <uid|uid:gid> "gecos" <home>`.
                fields = line.split()
                if len(fields) >= 3 and fields[0] == "u":
                    try:
                        reserved.add(int(fields[2].split(":", 1)[0]))
                    except ValueError:
                        pass
    return reserved


def get_next_uid() -> int:
    """Return the next free UID in the workload range [UID_MIN, UID_MAX].

    Combines the live /etc/passwd snapshot with UIDs already allocated in this
    process invocation and UIDs pinned in pending sysusers configs (see
    _reserved_uids_in_pending_sysusers — covers slots handed out but not yet
    created). Takes SUBID_LOCK itself so every caller — including the boot
    generator, which used to allocate unlocked — is mutexed against a concurrent
    allocator picking the same free slot. Reentrant, so the enable path can keep
    the lock held across the subsequent sysusers write.
    """
    with subid_lock():
        used = set(_allocated_uids)
        used |= _reserved_uids_in_pending_sysusers()
        try:
            for pw in pwd.getpwall():
                if UID_MIN <= pw.pw_uid <= UID_MAX:
                    used.add(pw.pw_uid)
        except Exception:
            pass
        for uid in range(UID_MIN, UID_MAX + 1):
            if uid not in used:
                _allocated_uids.add(uid)
                return uid
        raise RuntimeError(f"No free UIDs in range {UID_MIN}-{UID_MAX}")


def workload_service_name(name: str) -> str:
    """Return the systemd service name for a workload."""
    return f"workload-{name}.service"


def workload_container_name(name: str) -> str:
    """Return the podman container name for a workload."""
    return f"workload-{name}"


def workload_podman_container_name(
    name: str, container_name: str, *, is_multi: bool
) -> str:
    """The podman --name for one container of a workload.

    Single source of the single-vs-multi name formula shared by
    WorkloadConfig.podman_container_name and the metrics exporter (which reads
    raw TOML and can't build a WorkloadConfig). Single-container workloads use
    the bare `workload-<name>`; each member of a pod/bridge workload gets
    `workload-<name>-<container>`.
    """
    if not is_multi:
        return workload_container_name(name)
    return f"workload-{name}-{container_name}"


# Generated unit files live in the systemd runtime tree (transient; rewritten on
# boot by workload-generate.service and on every `workloadctl enable`).
RUN_SYSTEMD_SYSTEM = Path("/run/systemd/system")

# Where enable stages a workload's sysusers .conf to apply immediately (the
# generator writes its copy into RUN_SYSTEMD_SYSTEM). Both are scanned by
# _reserved_uids_in_pending_sysusers to spot pinned-but-uncreated UIDs.
RUN_SYSUSERS_D = Path("/run/sysusers.d")

# --- Workload run-files (B15) ---------------------------------------------- #
#
# The single source of truth for "the per-workload files a workload owns" — see
# docs/workload-run-files.md for the authoritative table and rationale.
#
# Every caller slices this one list along whichever axis it cares about, instead
# of re-deriving the set:
#   * emitted view (rf.emitted True) — files that exist for THIS exact config;
#     used by the generator-parity oracle, drift, inspect, and metrics.
#   * removable superset (all kinds but env-file) — the mode-family union the
#     disable/purge path may safely unlink() with missing_ok; over-lists -pod/-net
#     for every container workload so disabling can never miss a topology's unit.
#   * env-tree files (kind == 'env-file') — the runtime-written .env/.secrets that
#     only --purge removes.
# Filter by `kind` for tree/lifecycle and by `role` for a specific unit family.


def workload_env_dir() -> Path:
    """Runtime env tree (.env/.secrets). Honors WORKLOAD_ENV_DIR for tests."""
    return Path(os.environ.get("WORKLOAD_ENV_DIR", "/run/workload-env"))


@dataclass(frozen=True)
class WorkloadRunFile:
    """One file a workload owns, tagged so every caller can filter one list.

    kind  — which tree + removal lifecycle it belongs to:
            'unit' | 'wants-symlink' | 'sysusers' | 'dropin' | 'env-file'.
    role  — which unit family, for callers that want a specific member:
            'main' | 'setup' | 'build' | 'pod' | 'net' | 'container' |
            'virtiofs' | 'sysusers' | 'dropin' | 'env' | 'secrets'.
    emitted — True iff the generator writes this file for THIS config (the
            emitted view). False marks the removable-only superset entries
            (-pod/-net listed for non-matching modes) and the runtime-written
            env-files the generator never produces.
    """

    path: Path
    kind: str
    role: str
    emitted: bool


def workload_run_files(config) -> list[WorkloadRunFile]:
    """The complete set of run-files owned by one workload.

    MUST stay in sync with generators/workload-generate (generate_*_workload) and
    with the removal path. Never includes shared infra (workload-generate.service,
    workload-bridge.service, dnsmasq) or references to *other* workloads' units.

    Superset semantics: -pod.service and -net.service are listed for every
    container workload (emitted only for the matching mode) so the removable view
    can unlink() the full topology with missing_ok. The cgroup drop-in is keyed by
    the workload UID from the passwd db; if the user is gone the UID can't be
    reconstructed, so it is omitted rather than raising.
    """
    # Lazy import: workloadctl_core imports this module, so a top-level import
    # would be circular.
    from workloadctl_core import WorkloadUserNotFound

    run = RUN_SYSTEMD_SYSTEM
    env = workload_env_dir()
    name = config.name
    files: list[WorkloadRunFile] = [
        WorkloadRunFile(run / f"workload-{name}.conf", "sysusers", "sysusers", True),
        WorkloadRunFile(run / f"workload-{name}-setup.service", "unit", "setup", True),
        WorkloadRunFile(run / f"workload-{name}.service", "unit", "main", True),
        WorkloadRunFile(
            run / "multi-user.target.wants" / f"workload-{name}.service",
            "wants-symlink", "main", True,
        ),
    ]

    if config.is_vm:
        files.append(
            WorkloadRunFile(run / f"workload-{name}-build.service", "unit", "build", True)
        )
        for tag in virtiofs_tags(config.config.get("vm", {}).get("volumes", [])):
            files.append(WorkloadRunFile(
                run / f"workload-{name}-virtiofs-{tag}.service", "unit", "virtiofs", True
            ))
    else:
        # cgroup-placement drop-in (containers only). Keyed by the workload UID
        # from the passwd db; omitted once the user is gone (UID unreconstructable).
        # A pure query helper must not allocate a UID.
        try:
            files.append(WorkloadRunFile(
                run / f"user@{config.uid}.service.d" / "50-workload.conf",
                "dropin", "dropin", True,
            ))
        except WorkloadUserNotFound:
            pass
        mode = config.mode
        files.append(WorkloadRunFile(
            run / f"workload-{name}-pod.service", "unit", "pod", mode == "pod"
        ))
        files.append(WorkloadRunFile(
            run / f"workload-{name}-net.service", "unit", "net", mode == "bridge"
        ))
        # Per-container units key on topology, matching the generator and the
        # -pod/-net gates above; the per-container .secrets below key on the same
        # `mode != "single"` so disable/purge lists units and secrets together.
        if mode != "single":
            for cname in config.container_names():
                files.append(WorkloadRunFile(
                    run / f"workload-{name}-{cname}.service", "unit", "container", True
                ))

    # Runtime-written env tree — never produced by the generator (emitted False),
    # removed only on --purge. .secrets is over-listed per container (missing_ok).
    files.append(WorkloadRunFile(env / f"workload-{name}.env", "env-file", "env", False))
    files.append(
        WorkloadRunFile(env / f"workload-{name}.secrets", "env-file", "secrets", False)
    )
    # Per-container .secrets gate on the SAME discriminator as the per-container
    # units above (mode != "single"), not is_multi — a split discriminator here
    # strands loaded units when the two disagree (cmd_disable would unlink these
    # .secrets but never list the matching .service units). Correctly False for
    # VMs too (mode "single"; they own no per-container secrets).
    if config.mode != "single":
        for cname in config.container_names():
            files.append(WorkloadRunFile(
                env / f"workload-{name}-{cname}.secrets", "env-file", "secrets", False
            ))

    return files


@dataclass(frozen=True)
class RunTreeScan:
    """How to find one run-file kind when scanning the whole run tree.

    Companion to workload_run_files(): that lists the files ONE config owns;
    this lists the glob per kind so a tree-walker (workloadctl drift) can compare
    generated-vs-live for every workload at once, in both directions, without
    re-deriving the workload-<name>* name formulas. Kinds mirror
    WorkloadRunFile.kind for the files that land under RUN_SYSTEMD_SYSTEM — the
    env-file kinds live in the env tree and never appear here.

    glob          — pattern under the run root (drift's scratch dir or the live
                    tree); may descend a subdir (wants/, user@*.service.d/).
    content       — True: drift is a byte diff of the file. False: the file is an
                    enablement symlink whose only drift is presence/absence.
    name_filtered — True: the file is named workload-<name>* so `drift <name>`
                    can scope to it. False: drop-ins are keyed by UID, so the
                    name filter can't apply and they are always in scope.
    """

    kind: str
    glob: str
    content: bool
    name_filtered: bool


# Every run-file kind that lands under RUN_SYSTEMD_SYSTEM, as a scan table for
# drift. Adding a kind here (alongside its workload_run_files entry) is all drift
# needs to start comparing it — there is no per-kind block to duplicate.
# test_run_tree_scans_cover_run_files pins this to workload_run_files' tree kinds.
RUN_TREE_SCANS: list[RunTreeScan] = [
    RunTreeScan("unit", "workload-*.service", content=True, name_filtered=True),
    RunTreeScan("sysusers", "workload-*.conf", content=True, name_filtered=True),
    RunTreeScan(
        "wants-symlink",
        "multi-user.target.wants/workload-*.service",
        content=False,
        name_filtered=True,
    ),
    RunTreeScan(
        "dropin",
        "user@*.service.d/50-workload.conf",
        content=True,
        name_filtered=False,
    ),
]


def workload_service_units(config, *, roles=None) -> list[str]:
    """Emitted systemd .service unit names for THIS config.

    A convenience view over workload_run_files(): the services the generator
    actually writes — main, setup, the matching pod/net helper or per-container
    services, and for VMs the build and virtiofs units. Pass roles to keep only
    a subset, e.g. roles={"setup", "build"} for a VM's gating units.
    """
    return [
        rf.path.name
        for rf in workload_run_files(config)
        if rf.kind == "unit" and rf.emitted and (roles is None or rf.role in roles)
    ]


def render_sysusers_config(
    *,
    name: str,
    user_name: str,
    uid: int,
    home_dir: str,
    extra_groups=(),
    is_vm: bool = False,
) -> str:
    """Render the systemd-sysusers config for a workload's dedicated user.

    Single source of truth shared by enable-time provisioning
    (cmd_lifecycle._provision_user) and the boot generator, so the .conf a
    workload is enabled with is byte-identical to the one regenerated at boot.
    UID must be pre-allocated by the caller — this is a pure render and never
    allocates. A VM gets implicit `kvm` membership, de-duplicated against
    extra_groups so it is never emitted twice.
    """
    lines = [
        f"# Workload user for {name}" + (" (VM)" if is_vm else ""),
        f'u {user_name} {uid} "{name} workload" {home_dir}',
    ]
    groups: list[str] = []
    if is_vm:
        groups.append("kvm")
    for group in extra_groups:
        if group not in groups:
            groups.append(group)
    for group in groups:
        lines.append(f"m {user_name} {group}")
    return "\n".join(lines) + "\n"


def units_outdated(name: str) -> bool:
    """True if the workload's config TOML is newer than its generated unit file.

    `systemctl daemon-reload` re-runs the *shell* generator only (which emits a
    boot oneshot), NOT the Python unit-writer — so editing a workload.toml does
    not regenerate the per-workload units until `workloadctl enable <name>` is
    re-run. This mtime comparison is the cheap heads-up for that foot-gun; the
    authoritative content-level check is `workloadctl drift`.

    Returns False if either file is absent (workload never enabled / no config)
    so callers can treat "can't tell" as "nothing to warn about". A 1s slack
    swallows same-second writes from an enable that wrote both.
    """
    try:
        unit_mtime = (RUN_SYSTEMD_SYSTEM / workload_service_name(name)).stat().st_mtime
        config_mtime = workload_config_path(name).stat().st_mtime
    except OSError:
        return False
    return config_mtime > unit_mtime + 1.0


STATE_SUBDIR = "state"
DATA_SUBDIR = "data"


def workload_root_dir(name: str) -> Path:
    """Per-workload durable-state root: /var/lib/workloads/<name>.

    Spans both the reconstructible state/ subtree and the precious data/ subtree;
    use this for writable-path grants and containment checks.
    """
    return WORKLOADS_BASE / name


def workload_state_dir(name: str) -> Path:
    """Reconstructible state subtree (= $HOME / podman graphroot / VM disks).

    Backup-skipped (rebuildable from registries/Containerfiles).
    """
    return WORKLOADS_BASE / name / STATE_SUBDIR


def workload_data_dir(name: str) -> Path:
    """Precious data subtree. './' volume anchors resolve here. Backup-captured."""
    return WORKLOADS_BASE / name / DATA_SUBDIR


def workload_home_dir(name: str) -> Path:
    """Workload $HOME — the state/ subdir (podman graphroot lives here)."""
    return workload_state_dir(name)


# Per-container keys that may appear at *either* nesting depth in a
# [[containers]] entry:
#   [containers.container.environment] / [containers.container.health]   (nested)
#   [containers.environment]           / [containers.health]              (sibling)
# Single-mode TOMLs always nest these under [container], so we normalize the
# multi-container form to match. The generator reads from container["container"]
# only, so callers do not need to care which form the TOML used.
_LIFTED_CONTAINER_KEYS = ("environment", "health")


def normalize_containers(config: dict) -> list[dict]:
    """Return a list of per-container config dicts in a single canonical shape.

    Single-container TOMLs (top-level [container] block plus top-level
    [security], [storage], [devices], [secrets], [resources]) become a
    one-element list with all per-container fields gathered into it.

    Multi-container TOMLs ([[containers]] arrays) keep their per-entry
    structure, but sibling [containers.environment] / [containers.health]
    are lifted into entry["container"]["environment"] / ["health"] so the
    generator and helpers see the same shape regardless of which TOML form
    the user wrote.
    """
    if "containers" in config:
        result = []
        for entry in config["containers"]:
            normalized = dict(entry)
            container = dict(normalized.get("container", {}))
            for key in _LIFTED_CONTAINER_KEYS:
                if key in normalized:
                    container[key] = normalized.pop(key)
            normalized["container"] = container
            result.append(normalized)
        return result

    container = {
        "name": config["workload"]["name"],
        "container": dict(config.get("container", {})),
        "security": dict(config.get("security", {})),
        "storage":  {"volumes": list(config.get("storage", {}).get("volumes", []))},
        "devices":  dict(config.get("devices", {})),
        "secrets":  dict(config.get("secrets", {})),
        "resources": dict(config.get("resources", {})),
    }
    return [container]


# --- Validation ---

def validate_container_name(name: str):
    """Validate a per-container name. Raises ValueError on invalid names."""
    if len(name) > MAX_CONTAINER_NAME_LENGTH:
        raise ValueError(
            f"Container name too long: {len(name)} (max {MAX_CONTAINER_NAME_LENGTH})"
        )
    if not CONTAINER_NAME_PATTERN.match(name):
        raise ValueError(f"Invalid container name: {name!r}")


def infer_workload_mode(config: dict) -> str:
    """Return 'single', 'pod', or 'bridge'. Validates the value if explicit."""
    mode = config.get("workload", {}).get("mode")
    if mode is not None:
        if mode not in VALID_WORKLOAD_MODES:
            raise ValueError(
                f"Invalid workload.mode {mode!r}; must be one of {VALID_WORKLOAD_MODES}"
            )
        return mode
    return "pod" if "containers" in config else "single"


def validate_vm_config(config: dict) -> list[str]:
    """Validate the [vm] section. Returns a list of error strings."""
    errors = []
    vm = config.get("vm", {})

    if "container" in config or "containers" in config:
        errors.append("[vm] and [container]/[[containers]] are mutually exclusive")

    sources = [bool(vm.get("image")), bool(vm.get("cloud_image_url")), bool(vm.get("local_image"))]
    if sum(sources) == 0:
        errors.append(
            "[vm] requires exactly one image source: "
            "vm.image (bootc ref), vm.cloud_image_url, or vm.local_image"
        )
    elif sum(sources) > 1:
        errors.append("[vm] must specify exactly one image source; got multiple")

    if vm.get("cloud_image_url") and not vm.get("cloud_image_checksum"):
        errors.append("[vm].cloud_image_checksum is required when cloud_image_url is set")

    checksum = vm.get("cloud_image_checksum", "")
    if checksum and not checksum.startswith("sha256:"):
        errors.append(f"[vm].cloud_image_checksum must start with 'sha256:', got {checksum!r}")

    memory = vm.get("memory", "")
    if memory:
        try:
            m = parse_memory_mib(memory)
            if m < 256:
                errors.append(f"[vm].memory must be at least 256 MiB, got {m}")
        except (ValueError, TypeError):
            errors.append(
                f"[vm].memory must be in QEMU notation (e.g. 2048, '2048M', '4G'), got {memory!r}"
            )

    vcpus = vm.get("vcpus", 1)
    if not isinstance(vcpus, int) or vcpus < 1:
        errors.append(f"[vm].vcpus must be a positive integer, got {vcpus!r}")

    rollback_keep = vm.get("rollback_keep", 2)
    if not isinstance(rollback_keep, int) or rollback_keep < 1:
        errors.append(f"[vm].rollback_keep must be a positive integer, got {rollback_keep!r}")

    # Restart policy for the VM service. "always" (default) treats a guest
    # reboot — which QEMU's -no-reboot turns into a clean exit — as a reason to
    # relaunch; "on-failure" keeps the VM down on a clean exit; "on-reboot" is
    # reserved for reason-aware restart (not implemented yet; falls back to
    # "always"). See generate_vm_service.
    restart = vm.get("restart", "always")
    if restart not in ("always", "on-failure", "on-reboot"):
        errors.append(
            "[vm].restart must be one of 'always', 'on-failure', 'on-reboot', "
            f"got {restart!r}"
        )

    # [vm.network].bridge — defaults to _workload-br (managed NAT bridge); set to e.g.
    # "br0" to attach to a pre-existing LAN bridge instead.
    bridge = vm.get("network", {}).get("bridge", VM_BRIDGE_NAME)
    if not isinstance(bridge, str) or not bridge:
        errors.append(f"[vm.network].bridge must be a non-empty string, got {bridge!r}")
    elif not re.match(r"^[a-zA-Z0-9_-]+$", bridge) or len(bridge) > 15:
        # Linux IFNAMSIZ is 16, max 15 visible chars.
        errors.append(
            f"[vm.network].bridge {bridge!r} is not a valid interface name "
            "(letters/digits/_/-, max 15 chars)"
        )

    # The managed bridge's subnet/DNS are HOST-LEVEL config (ADR 002), no longer
    # per-VM: reject the removed fields with a pointer to the host-level knob
    # rather than silently ignoring them.
    net_cfg = vm.get("network", {})
    for removed in ("subnet", "dns"):
        if removed in net_cfg:
            errors.append(
                f"[vm.network].{removed} is no longer a per-VM setting — the "
                f"managed bridge's subnet/DNS are host-level (set "
                f"WORKLOADCTL_VM_BRIDGE_SUBNET / WORKLOADCTL_VM_BRIDGE_DNS). "
                f"See ADR 002."
            )

    # [vm.cloud_init] — optional override of the seed user-data.
    ci = vm.get("cloud_init", {})
    if ci:
        if not isinstance(ci, dict):
            errors.append("[vm.cloud_init] must be a table")
        else:
            ud = ci.get("user_data_file")
            if ud is not None and not isinstance(ud, str):
                errors.append(
                    f"[vm.cloud_init].user_data_file must be a string path, got {ud!r}"
                )
            tv = ci.get("template_vars", {})
            if not isinstance(tv, dict):
                errors.append("[vm.cloud_init].template_vars must be a table of strings")
            else:
                for k, v in tv.items():
                    if not isinstance(v, (str, int, float, bool)):
                        errors.append(
                            f"[vm.cloud_init].template_vars.{k} must be a scalar, got {type(v).__name__}"
                        )

    # Disk sizes are passed verbatim to `qemu-img create`/`resize`, which reads
    # a bare number as *bytes*. Require an explicit unit so a typo like "60"
    # isn't silently interpreted as a 60-byte disk (failing only at build time).
    for key in ("system_disk_size", "data_disk_size"):
        size = vm.get(key)
        if size is not None and (
            not isinstance(size, str)
            or not re.match(r"^\d+(\.\d+)?[KkMmGgTtPp]i?B?$", size)
        ):
            errors.append(
                f"[vm].{key} must be a size with a unit suffix "
                f"(e.g. '40G', '512M'), got {size!r}"
            )

    balloon = vm.get("balloon")
    if balloon is not None and not isinstance(balloon, bool):
        errors.append(f"[vm].balloon must be a boolean, got {balloon!r}")

    volumes = vm.get("volumes", [])
    if not isinstance(volumes, list):
        errors.append(
            f"[vm].volumes must be an array of 'host:guest[:opts]' strings, "
            f"got {type(volumes).__name__}"
        )
    else:
        for v in volumes:
            if not isinstance(v, str):
                errors.append(f"[vm].volumes entries must be strings, got {v!r}")
                continue
            host, guest, _ = parse_volume_spec(v)
            if not host or not guest:
                errors.append(
                    f"[vm].volumes entry {v!r} must have non-empty host and guest "
                    "paths (format 'host:guest[:opts]')"
                )

    return errors


def validate_workload_config(config: dict) -> list[str]:
    """Run schema-level checks. Returns a list of error strings (empty = OK)."""
    errors = []

    kind = infer_workload_kind(config)

    if kind == "vm":
        errors.extend(validate_vm_config(config))
        return errors

    # --- container validation ---
    has_container = "container" in config
    has_containers = "containers" in config

    if has_container and has_containers:
        errors.append("config has both [container] and [[containers]]; use one or the other")

    if has_containers:
        ctrs = config["containers"]
        if not isinstance(ctrs, list) or not ctrs:
            errors.append("[[containers]] must be a non-empty array")
        else:
            seen = set()
            for i, c in enumerate(ctrs):
                if "name" not in c:
                    errors.append(f"containers[{i}] missing required 'name' field")
                    continue
                try:
                    validate_container_name(c["name"])
                except ValueError as e:
                    errors.append(f"containers[{i}]: {e}")
                if c["name"] in seen:
                    errors.append(f"duplicate container name: {c['name']!r}")
                seen.add(c["name"])
                if "container" not in c or "image" not in c.get("container", {}):
                    errors.append(f"containers[{c['name']}].container.image is required")
                # environment/health may live at either nesting depth, but not
                # both — normalize_containers lifts the sibling form, and
                # ambiguity would make precedence implementation-defined.
                for key in _LIFTED_CONTAINER_KEYS:
                    if key in c and key in c.get("container", {}):
                        errors.append(
                            f"containers[{c['name']}]: '{key}' set both as "
                            f"[containers.{key}] and [containers.container.{key}]; "
                            f"use one form"
                        )

    try:
        infer_workload_mode(config)
    except ValueError as e:
        errors.append(str(e))

    # Keep the shape (is_multi = "containers" in config) and the topology
    # (mode) in lockstep so `is_multi <=> mode != "single"` holds. The generator
    # emits per-container units on mode, while ~30 call sites read is_multi as
    # the same discriminator; an explicit mode that contradicts the block shape
    # would desync them (orphaned units, dropped containers).
    explicit_mode = config.get("workload", {}).get("mode")
    if explicit_mode in ("pod", "bridge") and not has_containers:
        errors.append(
            f"workload.mode = {explicit_mode!r} requires [[containers]] "
            f"(a single [container] block is always 'single' mode)"
        )
    if explicit_mode == "single" and has_containers:
        errors.append(
            "workload.mode = 'single' is incompatible with [[containers]]; "
            "use [container] for a single-container workload"
        )

    # [workload].requires / .after — must be lists of valid workload name strings
    wl = config.get("workload", {})
    for key in ("requires", "after"):
        val = wl.get(key)
        if val is None:
            continue
        if not isinstance(val, list) or not all(isinstance(n, str) for n in val):
            errors.append(f"[workload].{key} must be a list of workload name strings")
        else:
            for n in val:
                try:
                    validate_workload_name(n)
                except ValueError as e:
                    errors.append(f"[workload].{key}: {e}")

    return errors


def validate_workload_name(name: str):
    """Validate a workload name. Raises ValueError on invalid names."""
    if len(name) > MAX_NAME_LENGTH:
        raise ValueError(
            f"Workload name too long: {len(name)} chars (max {MAX_NAME_LENGTH})"
        )
    if not NAME_PATTERN.match(name):
        raise ValueError(
            "Workload name must start with a letter and contain only "
            "lowercase letters, numbers, and hyphens"
        )


# --- Per-workload SELinux identifiers ---
#
# Each workload that ships extra rights gets its own name-keyed type instead of
# widening the shared container_t: a CIL module `wl_<name>` defining the process
# domain `wl_<name>.process`. The CLI (which loads the policy) and the generator
# (which labels the container) both derive identifiers through these functions
# so they can't drift. See llms.txt "SELinux confinement" for the rationale.
#
# hyphen->underscore is injective: NAME_PATTERN forbids underscores, so two
# distinct workload names can never collide on the same type.

def selinux_module_name(name: str) -> str:
    """SELinux/CIL module (block) name for a workload, e.g. 'wl_wayfire_bob'."""
    return "wl_" + name.replace("-", "_")


def selinux_type_name(name: str) -> str:
    """SELinux process type for a workload, e.g. 'wl_wayfire_bob.process'.

    Passed to `podman --security-opt label=type:`.
    """
    return selinux_module_name(name) + ".process"


# --- Volume path expansion ---

def _safe_anchor_subpath(sub: str) -> str:
    """Reject traversal/absolute escapes from a workload-relative anchor."""
    if sub.startswith("/") or ".." in Path(sub).parts:
        raise ValueError(f"unsafe anchored volume subpath: {sub!r}")
    return sub


def _expand_anchor(host: str, home_dir: str) -> str:
    """Resolve a workload-relative volume anchor to an absolute host path.

    home_dir is the workload STATE dir (= $HOME). The DATA dir is its sibling.
      data/sub  (sugar ./sub)  -> <root>/data/sub        (precious)
      state/sub (sugar @/sub)  -> <root>/state/volumes/sub (reconstructible)
    Anything else is returned unchanged.
    """
    data_root = str(Path(home_dir).parent / DATA_SUBDIR)
    state_vol_root = home_dir + "/volumes"
    # ./ and @/ are sugar for the canonical data/ and state/ prefixes. An empty
    # subpath (e.g. "./" or bare "data") resolves to the anchor root itself.
    for prefix, root in (("./", data_root), ("@/", state_vol_root),
                         ("data/", data_root), ("state/", state_vol_root)):
        if host.startswith(prefix):
            sub = _safe_anchor_subpath(host[len(prefix):])
            return root + "/" + sub if sub else root
    if host == "data":
        return data_root
    if host == "state":
        return state_vol_root
    return host


def expand_volume_path(vol_spec: str, home_dir: str) -> str:
    """Expand a workload-relative anchor in a volume spec's host path.

    Args:
        vol_spec: "host:guest[:opts]" — host may use ./ @/ data/ state/ anchors.
        home_dir: the workload STATE dir (= $HOME); data/ is its sibling.

    Returns the spec with the host path made absolute, original arity preserved.
    """
    host, guest, opts = parse_volume_spec(vol_spec)
    host = _expand_anchor(host, home_dir)
    ncolons = vol_spec.count(':')
    if ncolons == 0:
        return host
    if ncolons == 1:
        return f"{host}:{guest}"
    return f"{host}:{guest}:{opts}"


# --- Environment variables ---

# POSIX env var key: starts with letter or underscore, then alphanumeric/underscore
ENV_KEY_PATTERN = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def validate_env_key(key: str) -> bool:
    """Check that an environment variable key is a valid POSIX name."""
    return bool(ENV_KEY_PATTERN.match(key))


# --- Secrets ---

# Pattern matching ${SECRET:name} references in env var values
SECRET_PATTERN = re.compile(r'\$\{SECRET:([a-zA-Z0-9_-]+)}')

# Pattern matching ${SECRET?name} — optional variant used by cloud-init
# templates. Unlike SECRET_PATTERN, an unresolved name substitutes to the
# empty string (mirrors shell ${VAR?default} semantics) so user-data can
# include a credential reference that callers opt into without forcing
# every operator to pre-seed a placeholder credstore entry.
OPTIONAL_SECRET_PATTERN = re.compile(r'\$\{SECRET\?([a-zA-Z0-9_-]+)}')

# Pattern matching ${VAR} substitutions in cloud-init user-data templates.
# Deliberately distinct from SECRET_PATTERN so secret refs aren't swept up
# by the plain template-var pass; the resolver below handles both.
_TEMPLATE_VAR_PATTERN = re.compile(r'(?<!\$)\$\{([a-zA-Z_][a-zA-Z0-9_]*)}')

# Single combined pattern for substitute_template. Folding the three forms into
# one left-to-right pass (rather than three sequential .sub() calls) is a
# security property, not just an optimization: re.sub never re-scans the text it
# inserts, so a resolved value — e.g. a decrypted secret whose plaintext happens
# to contain "${PATH}" or "${SECRET:other}" — is emitted verbatim instead of
# being re-expanded by a later pass (which would leak host env/other secrets
# into the rendered guest user-data). The SECRET? / SECRET: alternatives precede
# VAR so a secret ref is never captured as a plain var. All three branches carry
# the (?<!\$) lookbehind so `$$` escaping is uniform: `$${VAR}`, `$${SECRET:name}`
# and `$${SECRET?name}` all survive the pass untouched and collapse to a literal
# `${...}` in the final $$→$ step. (A missing lookbehind on the SECRET branches
# silently broke that escape: `$${SECRET:name}` still matched and tried to resolve
# a secret named "name", aborting substitution — see tests/test_substitution.)
_SUBSTITUTION_PATTERN = re.compile(
    r'(?<!\$)\$\{SECRET\?(?P<optsecret>[a-zA-Z0-9_-]+)}'
    r'|(?<!\$)\$\{SECRET:(?P<secret>[a-zA-Z0-9_-]+)}'
    r'|(?<!\$)\$\{(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)}'
)


def substitute_template(
    text: str,
    template_vars: dict | None = None,
    env: dict | None = None,
    secret_resolver=None,
) -> str:
    """Resolve ${VAR}, ${SECRET:name}, and ${SECRET?name} placeholders.

    Resolution order for ${VAR}: template_vars first, then env. Unresolved
    placeholders raise KeyError so a missing var fails loudly at ISO build
    time rather than producing a broken guest.

    ${SECRET:name} is delegated to secret_resolver(name) -> str so callers
    decide where secrets come from (encrypted credstore, raw file, mock for
    tests). If secret_resolver is None, ${SECRET:...} refs raise KeyError.

    ${SECRET?name} is the *optional* variant: missing credentials (resolver
    raises FileNotFoundError or KeyError) substitute to the empty string
    instead of failing. This lets user-data reference a credential that the
    operator may or may not pre-seed — the rendered shell can check whether
    the resulting value is non-empty before using it.

    ``$$`` collapses to a literal ``$`` after substitution, matching the
    convention used by Python's string.Template and shell here-docs.
    """
    template_vars = template_vars or {}
    env = env or {}

    def _resolve(match):
        opt = match.group("optsecret")
        if opt is not None:
            if secret_resolver is None:
                return ""
            try:
                return secret_resolver(opt)
            except (FileNotFoundError, KeyError):
                return ""
        secret = match.group("secret")
        if secret is not None:
            if secret_resolver is None:
                raise KeyError(f"${{SECRET:{secret}}} present but no resolver provided")
            return secret_resolver(secret)
        name = match.group("var")
        if name in template_vars:
            return str(template_vars[name])
        if name in env:
            return env[name]
        raise KeyError(f"unresolved ${{{name}}} in cloud-init template")

    # One left-to-right pass: replacements are not re-scanned, so a resolved
    # secret/var value can't be re-expanded by a "later" pass (see the pattern's
    # comment). The $$→$ collapse stays a final step so `$${VAR}` escapes.
    out = _SUBSTITUTION_PATTERN.sub(_resolve, text)
    return out.replace("$$", "$")


def auto_detect_credentials(config: dict) -> set[str]:
    """Auto-detect which credentials are needed by scanning a TOML config.

    Scans:
    - Top-level [container.environment] (single-container TOMLs and the
      per-container slices the generator passes in).
    - [[containers]] entries, both sibling [containers.environment] and
      nested [containers.container.environment], plus per-container
      [containers.secrets].files.
    - Top-level [secrets].files.

    Returns a set of credential names.
    """
    needed = set()

    def _scan_env(env: dict):
        for value in env.values():
            for match in SECRET_PATTERN.finditer(str(value)):
                needed.add(match.group(1))

    _scan_env(config.get("container", {}).get("environment", {}))

    for entry in config.get("containers", []):
        # Multi-container TOMLs may write env at either nesting depth;
        # normalize_containers lifts the sibling form, but this helper is
        # called on the raw config too (CLI commands, backup bundling), so
        # check both.
        _scan_env(entry.get("environment", {}))
        _scan_env(entry.get("container", {}).get("environment", {}))
        for file_spec in entry.get("secrets", {}).get("files", []):
            if "credential" in file_spec:
                needed.add(file_spec["credential"])

    for file_spec in config.get("secrets", {}).get("files", []):
        if "credential" in file_spec:
            needed.add(file_spec["credential"])

    return needed


def resolve_secret_env_vars(config: dict, creds_dir: str) -> dict[str, str]:
    """Resolve environment variables that contain ${SECRET:name} references.

    Reads credential files from creds_dir and substitutes their contents
    into the env var values.

    Args:
        config: Parsed TOML workload config.
        creds_dir: Path to the credentials directory (e.g., /run/credentials/unit/).

    Returns:
        Dict of {KEY: resolved_value} for env vars that contained secrets.

    Raises:
        FileNotFoundError: If a referenced credential file is missing.
    """
    env_vars = config.get("container", {}).get("environment", {})
    resolved = {}

    for key, value in env_vars.items():
        value_str = str(value)
        if not SECRET_PATTERN.search(value_str):
            continue

        def _read_credential(match):
            cred_name = match.group(1)
            cred_path = Path(creds_dir) / cred_name
            if not cred_path.exists():
                raise FileNotFoundError(
                    f"Credential '{cred_name}' not found at {cred_path}"
                )
            return cred_path.read_text()

        resolved[key] = SECRET_PATTERN.sub(_read_credential, value_str)

    return resolved


# --- Quoting ---

def dq(s: str) -> str:
    """Quote a string as a LITERAL token for a systemd Exec* command line.

    Use for all tokens: paths, image names, command args, container names, env
    keys, and plain env VALUES.

    systemd applies two expansions to Exec directives that shell-style quoting
    does NOT suppress, so a bare double-quote is not enough:

      * `%` specifiers (`%i`, `%H`, …) are expanded at unit load, before quote
        parsing — a literal `%` must be written `%%`.
      * `$VAR` / `${VAR}` environment expansion runs on each argument *after*
        the command line is split and quotes are removed — so neither single nor
        double quotes stop it; a literal `$` must be written `$$`.

    (This is why single-quoting env values with shlex.quote was wrong: systemd
    still expands `$` inside them, and shlex's `'"'"'` escaping for an embedded
    single quote is shell syntax, not systemd's.)

    Backslash and double-quote are escaped for the surrounding double quotes;
    `$` and `%` are doubled to defeat the two expansions above. A single quote
    needs no escaping inside double quotes.
    """
    return (
        '"'
        + s.replace('\\', '\\\\')
           .replace('"', '\\"')
           .replace('$', '$$')
           .replace('%', '%%')
        + '"'
    )
