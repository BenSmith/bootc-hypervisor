"""
Shared constants and utilities for the workload provisioning system.

Used by workload-generate (the early-boot oneshot Python script),
workload-ensure-user, and workloadctl.
Installed to /usr/libexec/workloadctl/workload_lib.py.
"""

import hashlib
import json
import os
import re
import socket
import time
from pathlib import Path


# --- Constants ---

# Config directory (override with WORKLOAD_CONFIG_DIR env var for testing)
WORKLOAD_CONFIG_DIR = Path(os.environ.get("WORKLOAD_CONFIG_DIR", "/etc/workloads.d"))

# Persistent workload data directory
WORKLOADS_BASE = Path("/var/lib/workloads")

# Username prefix for workload system users
USERNAME_PREFIX = "_wl-"

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

# Default bridge for VM workloads.  _workload-br is the workloadctl-managed
# isolated NAT bridge (auto-provisioned by workload-bridge.service). The name
# is deliberately distinctive (and reserved) so the always-manage bridge setup
# won't adopt an unrelated interface; it must stay <=15 chars (Linux IFNAMSIZ).
# Override to e.g. "br0" to attach VMs directly to a pre-existing LAN bridge.
VM_BRIDGE_NAME = "_workload-br"
VM_BRIDGE_SUBNET = "192.168.200.0/24"
VM_BRIDGE_IP = "192.168.200.1"
VM_DHCP_RANGE = "192.168.200.100,192.168.200.199,12h"
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


# --- Kind routing ---

def infer_workload_kind(config: dict) -> str:
    """Return 'vm' if the config has a top-level [vm] section, else 'container'."""
    return "vm" if "vm" in config else "container"


# --- VM helpers ---

def vm_mac_address(name: str) -> str:
    """Derive a stable, locally-administered unicast MAC from the workload name."""
    h = hashlib.md5(f"wl-vm-{name}".encode()).digest()
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
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(recv_timeout)
                s.connect(str(path))
                self._sock = s
                return
            except (OSError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"QMP socket not ready after {timeout:.0f}s: {path}"
                    )
                time.sleep(0.2)

    def _readline(self) -> dict:
        """Read one newline-delimited JSON object from the socket."""
        while True:
            if b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                return json.loads(line.decode())
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("QMP socket closed")
            self._buf += chunk

    def _send(self, obj: dict):
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
        cmd = {"execute": command}
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


def workload_service_name(name: str) -> str:
    """Return the systemd service name for a workload."""
    return f"workload-{name}.service"


def workload_container_name(name: str) -> str:
    """Return the podman container name for a workload."""
    return f"workload-{name}"


def workload_home_dir(name: str) -> Path:
    """Return the home directory path for a workload."""
    return WORKLOADS_BASE / name


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
# Each workload that ships extra rights gets its OWN SELinux type rather than
# widening the shared container_t/container_init_t domains (a semodule load is
# global, so allow-rules on the stock domains leak to every container on the
# host). The type is keyed on the workload NAME (not its bundle) so that a
# duplicated workload gets an independently loadable/removable module — see
# docs/workload-bundles.md "SELinux: per-workload types".
#
# The policy is shipped as a udica-style CIL block, `(block wl_<name>
# (blockinherit container) ...)`. The CIL block name is the module name
# (wl_<name>); the process domain it defines is the namespaced type
# wl_<name>.process, which is what the container is labelled with. A plain
# `typeattribute container_domain` is NOT enough — the container won't even
# launch (crun fails on /proc/self/attr/keycreate); inheriting the udica
# `container` base block is what supplies the missing process-attr permissions.
#
# Identifier chars: SELinux allows [a-zA-Z0-9_] (plus '.' as the CIL namespace
# separator). NAME_PATTERN forbids underscores, so the hyphen->underscore
# sanitize is injective — two distinct workload names can never collide. Both
# the CLI (load) and the generator (label injection) must derive identifiers
# through these functions or they will drift.

def selinux_module_name(name: str) -> str:
    """SELinux/CIL module (block) name for a workload, e.g. 'wl_wayfire_bob'."""
    return "wl_" + name.replace("-", "_")


def selinux_type_name(name: str) -> str:
    """SELinux process type for a workload, e.g. 'wl_wayfire_bob.process'.

    This is the CIL-namespaced type emitted by `(block wl_<name> ...)` and is
    what gets passed to `podman --security-opt label=type:`.
    """
    return selinux_module_name(name) + ".process"


# --- Volume path expansion ---

def expand_volume_path(vol_spec: str, home_dir: str) -> str:
    """Expand ./ prefix in volume host path to the workload home directory.

    Args:
        vol_spec: Volume specification like "./data:/container/path:rw"
        home_dir: Workload home directory path (string)

    Returns:
        Volume spec with ./ expanded to home directory
    """
    host, guest, opts = parse_volume_spec(vol_spec)
    if host.startswith('./'):
        host = home_dir + '/' + host[2:]
    # Preserve the original arity: a bare path or a host:guest spec must not
    # gain a synthesized opts field.
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

    def _var(match):
        name = match.group(1)
        if name in template_vars:
            return str(template_vars[name])
        if name in env:
            return env[name]
        raise KeyError(f"unresolved ${{{name}}} in cloud-init template")

    def _secret(match):
        name = match.group(1)
        if secret_resolver is None:
            raise KeyError(f"${{SECRET:{name}}} present but no resolver provided")
        return secret_resolver(name)

    def _optional_secret(match):
        name = match.group(1)
        if secret_resolver is None:
            return ""
        try:
            return secret_resolver(name)
        except (FileNotFoundError, KeyError):
            return ""

    out = OPTIONAL_SECRET_PATTERN.sub(_optional_secret, text)
    out = SECRET_PATTERN.sub(_secret, out)
    out = _TEMPLATE_VAR_PATTERN.sub(_var, out)
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
    """Double-quote a string for systemd ExecStart (and shell wrapper) contexts.

    Use for all tokens: paths, image names, command args, container names, env keys.

    The one exception is plain env var VALUES — use shlex.quote() for those,
    because single quotes prevent $-expansion in both systemd and shell contexts.
    """
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
