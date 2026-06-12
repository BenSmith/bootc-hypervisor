"""
workloadctl_core — shared types, helpers, and manager used by all cmd modules.

Import chain:
    workload_lib, podman  (no changes)
        ↑
    workloadctl_core      (this file)
        ↑
    cmd_*.py modules
        ↑
    bin/workloadctl       (thin entry point)
"""

import datetime
import difflib
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib

from workload_lib import (
    auto_detect_credentials,
    expand_volume_path,
    GENERATOR_OWNED_DIRECTIVES,
    get_next_uid,
    infer_workload_kind,
    infer_workload_mode,
    MAX_NAME_LENGTH,
    NAME_PATTERN,
    normalize_containers,
    QMPClient,
    selinux_module_name,
    selinux_type_name,
    UID_MIN,
    UID_MAX,
    USERNAME_PREFIX,
    validate_workload_name,
    VM_SOCKET_DIR,
    WORKLOADS_BASE,
    WORKLOAD_CONFIG_DIR,
    VM_BRIDGE_NAME,
    VM_DHCP_LEASE_FILE,
    vm_mac_address,
    workload_container_name,
    workload_home_dir,
    workload_service_name,
    workload_username,
)
from podman import Podman, PodmanError

WORKLOAD_DIR = WORKLOAD_CONFIG_DIR


def _get_workload_dir() -> "Path":
    """Return the current WORKLOAD_DIR.

    When bin/workloadctl is loaded as the 'workloadctl' or 'workload_ctl'
    module (as test harnesses do), defer to that module's WORKLOAD_DIR so
    that patch.object(wctl, 'WORKLOAD_DIR', tmp) affects WorkloadConfig and
    WorkloadManager at call time.
    """
    import sys as _sys
    for _mod_name in ('workloadctl', 'workload_ctl'):
        _mod = _sys.modules.get(_mod_name)
        if _mod is not None and hasattr(_mod, 'WORKLOAD_DIR'):
            return _mod.WORKLOAD_DIR
    return WORKLOAD_DIR


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_workload_ref(ref: str) -> tuple[str, str | None]:
    """Parse 'workload[/container]' into (workload, container_or_None)."""
    if "/" in ref:
        wl, ctr = ref.split("/", 1)
        return wl, ctr
    return ref, None


def resolve_container_target(config, container, workload):
    """Resolve a (workload, container) ref to a podman container name.

    For single-container workloads, `container` must be None. For
    multi-container workloads, `container` is required; a bare workload name
    errors with the list of available containers (exit 2).
    """
    if not config.is_multi:
        if container is not None:
            print(f"Error: workload '{workload}' is single-container; "
                  f"drop the '/{container}' suffix.", file=sys.stderr)
            sys.exit(2)
        return config.container_name
    names = config.container_names()
    if container is None:
        print(f"Error: workload '{workload}' has multiple containers; "
               "specify with NAME/CTR.", file=sys.stderr)
        print(f"  Available: {', '.join(names)}", file=sys.stderr)
        sys.exit(2)
    if container not in names:
        print(f"Error: container '{container}' not in workload '{workload}'. "
              f"Available: {', '.join(names)}", file=sys.stderr)
        sys.exit(2)
    return config.podman_container_name(container)


def _format_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f} {u}"
        f /= 1024
    return f"{n} B"


def _format_created(ts: str | int | None) -> str:
    """Render podman's image Created (Unix int or ISO string) as 'N days ago'."""
    if ts is None or ts == "":
        return "unknown"
    try:
        if isinstance(ts, (int, float)):
            created = datetime.datetime.fromtimestamp(int(ts))
        else:
            s = str(ts).rstrip("Z").split(".")[0]
            try:
                created = datetime.datetime.fromisoformat(s)
            except ValueError:
                created = datetime.datetime.fromtimestamp(int(float(ts)))
        delta = datetime.datetime.now() - created
        days = delta.days
        if days >= 1:
            return f"{days} day{'s' if days != 1 else ''} ago"
        hours = delta.seconds // 3600
        if hours >= 1:
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        minutes = max(1, delta.seconds // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    except Exception:
        return "unknown"


def _created_unix(ts) -> int | None:
    """Convert podman Created field (int, ISO string, or float string) to Unix int."""
    if ts is None or ts == "":
        return None
    try:
        if isinstance(ts, (int, float)):
            return int(ts)
        s = str(ts).rstrip("Z").split(".")[0]
        try:
            return int(datetime.datetime.fromisoformat(s).timestamp())
        except ValueError:
            return int(float(ts))
    except Exception:
        return None


def _parse_size_bytes(s) -> int:
    """Parse podman size strings like '1.23 GB', '456B', '0 B' to bytes."""
    if isinstance(s, int):
        return s
    s = str(s).strip()
    sl = s.lower()
    for suffix, mul in [("tib", 1024**4), ("gib", 1024**3), ("mib", 1024**2),
                         ("kib", 1024), ("tb", 10**12), ("gb", 10**9),
                         ("mb", 10**6), ("kb", 10**3), ("b", 1)]:
        if sl.endswith(suffix):
            try:
                return int(float(s[:-len(suffix)].strip()) * mul)
            except ValueError:
                return 0
    try:
        return int(float(s))
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class WorkloadMasked(Exception):
    """Raised when a workload config is masked (symlinked to /dev/null)."""
    def __init__(self, name: str):
        self.name = name
        super().__init__(f"Workload '{name}' is masked.")


class WorkloadUserNotFound(Exception):
    """Raised when a workload's system user does not exist yet."""
    def __init__(self, name: str):
        self.name = name
        super().__init__(
            f"User not found for workload '{name}'. "
            f"Run 'workloadctl enable {name}' first."
        )


def toml_string(value: str) -> str:
    """Return a TOML-safe double-quoted string literal."""
    result = value.replace('\\', '\\\\').replace('"', '\\"')
    result = result.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    result = ''.join(f'\\u{ord(c):04x}' if ord(c) < 0x20 else c for c in result)
    return '"' + result + '"'


def require_root():
    """Ensure running as root"""
    if os.geteuid() != 0:
        print("Error: This command must be run as root (use sudo)", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# WorkloadConfig
# ---------------------------------------------------------------------------

class WorkloadConfig:
    """Represents a workload configuration file"""

    def __init__(self, filename: str):
        self.filename = filename
        self.path = _get_workload_dir() / f"{filename}.toml"

        # Masked workload: symlink to /dev/null (same semantics as systemd masking)
        if self.path.is_symlink() and self.path.resolve() == Path('/dev/null'):
            raise WorkloadMasked(filename)

        if not self.path.exists():
            raise FileNotFoundError(f"Config not found: {self.path}")

        with open(self.path, "rb") as f:
            self.config = tomllib.load(f)

        name = self.config["workload"]["name"]

        if name != filename:
            raise ValueError(f"Workload name '{name}' must match filename '{filename}'")

        validate_workload_name(name)

    @property
    def name(self) -> str:
        return self.config["workload"]["name"]

    @property
    def kind(self) -> str:
        return infer_workload_kind(self.config)

    @property
    def is_vm(self) -> bool:
        return self.kind == "vm"

    @property
    def image(self) -> str:
        if self.is_vm:
            vm = self.config.get("vm", {})
            return (vm.get("image") or vm.get("cloud_image_url")
                    or vm.get("local_image") or "(vm)")
        return self.config["container"]["image"]

    @property
    def enabled(self) -> bool:
        return self.config.get("workload", {}).get("enabled", False)

    @property
    def selinux_policy(self) -> bool:
        """Whether this workload ships a per-workload SELinux type (wl_<name>.process).

        When set, enable/disable load/remove the bundle's CIL policy
        (`<bundle>.cil`) as a name-keyed module, and the generator labels the
        container with the matching type. See docs/workload-bundles.md.

        `selinux_policy` may be `true` (source the bundle named after this
        workload) or a string naming the bundle directory to source the CIL
        from — see `selinux_bundle`.
        """
        return bool(self.config.get("security", {}).get("selinux_policy", False))

    @property
    def selinux_bundle(self) -> str | None:
        """The `containers/<bundle>/` directory to source the CIL from.

        `selinux_policy = true` keys off the workload name (the bundle is named
        after the workload); a string value names the bundle explicitly, which
        decouples the policy source from the (renameable) workload name so a
        renamed workload can keep using its original bundle. None when policy is
        disabled. The loaded module and label stay keyed to the workload name
        (`wl_<name>.process`) regardless.
        """
        val = self.config.get("security", {}).get("selinux_policy", False)
        if not val:
            return None
        return val if isinstance(val, str) else self.name

    @property
    def username(self) -> str:
        return workload_username(self.name)

    @property
    def uid(self) -> int:
        """Get UID from passwd database."""
        try:
            return pwd.getpwnam(self.username).pw_uid
        except KeyError:
            raise WorkloadUserNotFound(self.name)

    @property
    def gid(self) -> int:
        """Get primary GID from passwd database."""
        try:
            return pwd.getpwnam(self.username).pw_gid
        except KeyError:
            raise WorkloadUserNotFound(self.name)

    @property
    def service_name(self) -> str:
        return workload_service_name(self.name)

    @property
    def container_name(self) -> str:
        return workload_container_name(self.name)

    @property
    def home_dir(self) -> Path:
        return workload_home_dir(self.name)

    @property
    def vm_bridge(self) -> str:
        return self.config.get("vm", {}).get("network", {}).get("bridge", VM_BRIDGE_NAME)

    def get_network_mode(self) -> str:
        return self.config.get("network", {}).get("mode", "pasta")

    def get_ports(self) -> list[str]:
        return self.config.get("network", {}).get("ports", [])

    def get_volumes(self) -> list[str]:
        return self.config.get("storage", {}).get("volumes", [])

    def get_extra_groups(self) -> list[str]:
        return self.config.get("security", {}).get("extra_groups", [])

    def has_health_check(self) -> bool:
        """True if any container in this workload has a health check."""
        for c in normalize_containers(self.config):
            if c.get("container", {}).get("health", {}).get("cmd"):
                return True
        return False

    def container_health_blocks(self) -> list[tuple[str, str, dict]]:
        """Return [(container-local-name, podman-name, health-dict), ...] for
        every container with a non-empty health.cmd. The podman-name is what
        `podman inspect` and container_health() use; for single-container
        workloads that's self.container_name."""
        result = []
        for c in normalize_containers(self.config):
            health = c.get("container", {}).get("health", {})
            if not health.get("cmd"):
                continue
            local = c.get("name", self.name)
            podman_name = self.podman_container_name(local)
            result.append((local, podman_name, health))
        return result

    @property
    def is_multi(self) -> bool:
        return "containers" in self.config

    @property
    def mode(self) -> str:
        return infer_workload_mode(self.config)

    def container_names(self) -> list[str]:
        """Ordered list of container names. For single workloads, [name]."""
        if self.is_multi:
            return [c["name"] for c in self.config["containers"]]
        return [self.name]

    def sub_service_names(self) -> list[str]:
        """systemd unit names for each container (multi) or [service_name]."""
        if not self.is_multi:
            return [self.service_name]
        return [f"workload-{self.name}-{c}.service" for c in self.container_names()]

    def container_image(self, container_name: str) -> str:
        """Image for a given container name. For single workloads, self.image."""
        if not self.is_multi:
            return self.image
        for c in self.config["containers"]:
            if c["name"] == container_name:
                return c["container"]["image"]
        raise KeyError(f"container '{container_name}' not in workload '{self.name}'")

    def container_images(self) -> list[tuple[str, str]]:
        """Return [(container_name, image), ...]."""
        return [(c, self.container_image(c)) for c in self.container_names()]

    def container_specs(self) -> list[tuple[str, str, str]]:
        """Return [(container_name, image, pull_policy), ...] for every container.

        For single-container workloads this is a one-element list built from
        the top-level [container] block.
        """
        if self.is_multi:
            return [(c["name"], c["container"]["image"],
                     c["container"].get("pull", "missing"))
                    for c in self.config["containers"]]
        return [(self.name, self.image,
                 self.config.get("container", {}).get("pull", "missing"))]

    def all_volumes(self) -> list[str]:
        """Volume specs across every container (single: [storage].volumes)."""
        if not self.is_multi:
            return self.get_volumes()
        vols: list[str] = []
        for c in self.config["containers"]:
            vols.extend(c.get("storage", {}).get("volumes", []))
        return vols

    def podman_container_name(self, container_name: str) -> str:
        """Podman --name for a given container."""
        if not self.is_multi:
            return self.container_name
        return f"workload-{self.name}-{container_name}"

    def get_required_files(self) -> list[dict]:
        """Return list of {path, hint} dicts from [setup].required_files."""
        entries = self.config.get("setup", {}).get("required_files", [])
        result = []
        for entry in entries:
            if "path" not in entry:
                continue
            path = entry["path"]
            if path.startswith("./"):
                path = str(self.home_dir) + "/" + path[2:]
            result.append({"path": path, "hint": entry.get("hint")})
        return result


# ---------------------------------------------------------------------------
# WorkloadManager
# ---------------------------------------------------------------------------

class WorkloadManager:
    """Manages workload operations"""

    def __init__(self):
        self.workload_dir = _get_workload_dir()

    def run_podman_exec(self, config: WorkloadConfig, args,
                        check=False, capture_output=False):
        """Run `podman exec <args>` against a workload container.

        Under ADR 001 option 1b, containers run inside the user manager
        (user@<uid>.service → workloads.slice), so crun's cgroup migration stays
        within the delegated subtree and plain sudo -u exec works without any
        cgroup placement shim.
        """
        return self.podman(config).run("exec", *args,
                                       check=check, capture_output=capture_output)

    def run_podman(self, config: WorkloadConfig, *args, check=False,
                  capture_output=False):
        """Run an arbitrary podman subcommand as the workload user."""
        return self.podman(config).run(*args, check=check,
                                       capture_output=capture_output)

    def podman(self, config: WorkloadConfig) -> Podman:
        """Return a memoized Podman wrapper for this workload's user."""
        if not hasattr(self, "_podman_clients"):
            self._podman_clients: dict[int, Podman] = {}
        if config.uid not in self._podman_clients:
            self._podman_clients[config.uid] = Podman.for_user(
                config.username, config.uid, config.home_dir
            )
        return self._podman_clients[config.uid]

    def get_image_id(self, config: WorkloadConfig) -> str:
        """Get current image ID. Returns '' if image not present.

        Raises PodmanError on unexpected failures (sudo, malformed output, etc.)
        """
        return self.podman(config).image_id(config.image)

    def get_all_configs(self, enabled_only=False) -> list[WorkloadConfig]:
        """Get all workload configs"""
        configs = []
        for path in sorted(self.workload_dir.glob("*.toml")):
            try:
                config = WorkloadConfig(path.stem)
                if not enabled_only or config.enabled:
                    configs.append(config)
            except WorkloadMasked:
                pass  # Intentionally masked; not a warning
            except Exception as e:
                print(f"Warning: Failed to load {path.name}: {e}", file=sys.stderr)
        return configs

    def user_exists(self, config: WorkloadConfig) -> bool:
        """Check if workload user exists"""
        try:
            pwd.getpwnam(config.username)
            return True
        except KeyError:
            return False
