"""
Shared constants and utilities for the workload provisioning system.

Used by workload-generator, workload-ensure-user, and workload-ctl.
Installed to /usr/lib/workloads/workload_lib.py.
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


# --- Validation ---

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
    - Environment variables for ${SECRET:name} references
    - secrets.files for credential field references

    Returns a set of credential names.
    """
    needed = set()

    for value in config.get("container", {}).get("environment", {}).values():
        for match in SECRET_PATTERN.finditer(str(value)):
            needed.add(match.group(1))

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
