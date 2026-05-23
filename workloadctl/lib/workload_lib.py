"""
Shared constants and utilities for the workload provisioning system.

Used by workload-generate (the early-boot oneshot Python script),
workload-ensure-user, and workloadctl.
Installed to /usr/libexec/workloadctl/workload_lib.py.
"""

import os
import re
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


def validate_workload_config(config: dict) -> list[str]:
    """Run schema-level checks. Returns a list of error strings (empty = OK)."""
    errors = []
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


# --- Volume path expansion ---

def expand_volume_path(vol_spec: str, home_dir: str) -> str:
    """Expand ./ prefix in volume host path to the workload home directory.

    Args:
        vol_spec: Volume specification like "./data:/container/path:rw"
        home_dir: Workload home directory path (string)

    Returns:
        Volume spec with ./ expanded to home directory
    """
    if ':' not in vol_spec:
        if vol_spec.startswith('./'):
            return home_dir + '/' + vol_spec[2:]
        return vol_spec

    parts = vol_spec.split(':', 2)
    if parts[0].startswith('./'):
        parts[0] = home_dir + '/' + parts[0][2:]
    return ':'.join(parts)


# --- Environment variables ---

# POSIX env var key: starts with letter or underscore, then alphanumeric/underscore
ENV_KEY_PATTERN = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def validate_env_key(key: str) -> bool:
    """Check that an environment variable key is a valid POSIX name."""
    return bool(ENV_KEY_PATTERN.match(key))


# --- Secrets ---

# Pattern matching ${SECRET:name} references in env var values
SECRET_PATTERN = re.compile(r'\$\{SECRET:([a-zA-Z0-9_-]+)}')


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
