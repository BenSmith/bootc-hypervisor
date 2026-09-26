"""
Where a workload's config lives, and how it parses into validated records.

The bottom of the layering, next to credential_entries and egress_plane.
Both substrates read the same TOML grammar, so the parse loops live below
the shared plane rather than in either substrate's module -- a second copy is
how two spellings of the same rule come to disagree. The hostname
normalisation is one rung lower still, in inspect_document, because the
listener normalises too and must not import this grammar to do it. The credential block has its own module, credential_entries,
for the same reason. Each substrate's own record types and readers sit above,
in vm_network_config and container_network_config.

Installed to /usr/libexec/workloadctl/config_parser.py.
"""

import re
from pathlib import Path
from customs.egress_plane import CLEARTEXT, TLS


# Persistent workload data directory
WORKLOADS_BASE = Path("/var/lib/workloads")

# Per-instance runtime directory, /run/workload-vm/<name>/, for BOTH
# substrates: a VM keeps its QMP and guest-agent sockets there, and any
# workload with an egress inspector -- container or VM -- keeps the
# inspector's policy and status documents there. The path keeps the name it
# shipped with; it is an SELinux fcontext pattern and live state on deployed
# hosts, not just a string.
SOCKET_DIR = Path("/run/workload-vm")


VALID_WORKLOAD_MODES = ("single", "pod", "bridge")


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


def workload_root_dir(name: str) -> Path:
    """Per-workload durable-state root: /var/lib/workloads/<name>.

    Spans both the reconstructible state/ subtree and the precious data/ subtree;
    use this for writable-path grants and containment checks.
    """
    return WORKLOADS_BASE / name


def runtime_dir(name: str) -> str:
    """Where one instance's config, allowlist, log and pid file live."""
    return f"{SOCKET_DIR}/{name}"


# --- Validation ---

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


# --- Shared policy parsing ---
#
# One parse loop per table, shared by both substrates. The TYPES stay
# separate -- see the ContainerPolicyEntry note in container_network_config
# for why -- but the loops that fill them do not: they were verbatim copies
# of each other, and a copy is how the two come to disagree about what a
# malformed entry means after only one of them is fixed. The entry class is
# the parameter, so a substrate keeps its own vocabulary and shares the
# shape-tolerance rules.
#
# Every function here is shape-tolerant on purpose. Real validation lives in
# the per-substrate validate_* functions, and the boot generator skips a
# workload that does not validate.

def normalise_policy_list(value, *, upper: bool = False) -> tuple | None:
    """One `methods` or `paths` value as a tuple, or None where it was absent.

    None and () are different answers and the caller depends on it; see
    egress_policy.VmPolicyEntry and ContainerPolicyEntry below.
    """
    if value is None:
        return None
    if not isinstance(value, list):
        return ()
    out = []
    for item in value:
        if not isinstance(item, str):
            continue
        # NOT stripped: validation refuses a padded token or path outright,
        # so nothing that reaches here needs it, and a strip in one of the two
        # places is how they come to disagree about what the file said.
        out.append(item.upper() if upper else item)
    return tuple(out)


def parse_policy_entries(net: dict, entry_cls) -> list:
    """The `policy` entries of one network table, normalised, in file order.

    `entry_cls` is VmPolicyEntry or ContainerPolicyEntry -- field-identical
    by construction, and the only thing that differs between the substrates.
    """
    entries = []
    raw = net.get("policy", [])
    if not isinstance(raw, list):
        return entries
    for item in raw:
        if not isinstance(item, dict):
            continue
        host = item.get("host")
        if not isinstance(host, str) or not host.strip():
            continue
        credential = item.get("credential")
        if not isinstance(credential, str) or not credential.strip():
            credential = None
        else:
            credential = credential.strip()
        entries.append(entry_cls(
            host=host.strip(),
            methods=normalise_policy_list(item.get("methods"), upper=True),
            paths=normalise_policy_list(item.get("paths")),
            credential=credential))
    return entries


# --- Shared hostname matching ---
#
# The one normalisation every hostname decision in this design is made under.
# Both substrates use it: a validator that normalised with `.rstrip(".")`
# would strip a doubled trailing dot the enforcer keeps, and then disagree
# with the listener about what a name is. It lives at the bottom of the
# layering because everything above matches against it and nothing here
# needs anything above.


HOST_PATTERN_RE = re.compile(r"^[A-Za-z0-9*?.\[\]!_-]+$")


def validate_host_pattern(pattern, *, allow_key: str,
                          star_remedy: str) -> list[str]:
    """Validate one hostname pattern. Returns error strings, unprefixed --
    every caller prefixes them with the table and key it read them from.

    The two keyword arguments are the whole of what the two substrates disagree
    about: which array carries a destination that names a port, and what an
    operator who wrote `*` should do instead. Everything else -- a scheme, a
    path, a port, the character class -- is a property of an fnmatch hostname
    pattern and not of the substrate matching it, which is why this was worth
    stating once. It was stated twice for as long as this module could not
    import vm.py, and both copies were called only from functions that already
    import vm.py lazily, so the constraint never actually bound.
    """
    if not isinstance(pattern, str):
        return [f"entries must be strings, got {pattern!r}"]
    text = pattern.strip()
    if not text:
        return ["entries must not be empty"]
    if "://" in text:
        return [f"{pattern!r} looks like a URL -- patterns match the hostname "
                f"only, so drop the scheme"]
    if "/" in text:
        return [f"{pattern!r} contains a path -- patterns match the hostname "
                f"only, so a path never matches"]
    if ":" in text:
        return [f"{pattern!r} contains a port -- hostname policy applies to "
                f"the redirected ports ({CLEARTEXT.guest_port} and "
                f"{TLS.guest_port}) only; use {allow_key} for other ports"]
    if text == "*":
        return [f"'*' matches every host, {star_remedy}"]
    if not HOST_PATTERN_RE.match(text):
        return [f"{pattern!r} is not a hostname or fnmatch pattern"]
    return []
