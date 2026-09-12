"""
The shared core every entrypoint stands on: where a workload's config lives,
what its user, units and directories are called, and how its paths and tokens
expand.

Used by workload-generate (the early-boot oneshot Python script),
workload-ensure-user, and workloadctl. The uid and its subordinate range are
lib/workload_uid.py; the files a workload owns at runtime are lib/run_files.py;
the container [network] section is lib/container_network_config.py.
"""

import os
import re
import stat
import tomllib
from pathlib import Path

# The parse layer, one rung below this module: config_parser owns the TOML
# grammar both substrates read, and imports nothing of ours.
from config_parser import parse_volume_spec, workload_root_dir


# --- Constants ---

# Build identity. The RPM's %install writes a _version.py sibling of these
# modules (see rpm/workloadctl.spec) carrying %{version}-%{release} — Version
# and Release only, not a full NEVR: no Name, and the spec defines no Epoch.
# Release is 1.<build timestamp>, so each build gets a distinct string; the
# checks that read it compare for *equality* ("same build or not"), never for
# order — the timestamp orders builds by when they were produced, which is not
# the same as which code they contain.
# Absent from a source checkout and from the test tree, where "0-dev" stands in.
#
# Defined here rather than in bin/workloadctl because three things have to agree
# on one string: `--version`, the provenance stamp the generator writes into
# every unit, and the check that compares a live unit's stamp against the running
# build. Two spellings of the fallback would make a source checkout report itself
# as stale.
try:
    from _version import __version__ as WORKLOADCTL_VERSION
except ImportError:
    WORKLOADCTL_VERSION = "0-dev"

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


# The kernel's list of mount points. Lives here rather than in backup.py because
# both halves of backup/restore need it and they do not import each other.
MOUNTINFO = Path("/proc/self/mountinfo")


def _unescape_mountinfo(text: str) -> str:
    r"""Decode the octal escapes mountinfo uses for space, tab, newline and \\."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\" and text[i + 1:i + 4].isdigit() and len(text) >= i + 4:
            out.append(chr(int(text[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def mount_points(mountinfo: Path | None = None) -> set[Path]:
    """Every mount point visible to this process, from /proc/self/mountinfo.

    This is the only way to see a bind mount of a directory that lives on the
    same filesystem: it reports the same st_dev on both sides, so comparing
    devices -- which is what "stop at filesystem boundaries" naturally becomes
    in code -- cannot distinguish it from an ordinary subdirectory. Backup and
    restore both have to, since one would capture the bind source's files and
    the other would delete them.

    Field 5 (index 4) is the mount point. An unreadable mountinfo yields
    nothing rather than raising, so a host without /proc degrades to the
    narrower st_dev checks its callers still carry, rather than to no check.

    Resolved at call time, not bound as a default argument: a default is
    evaluated once when the function is defined, which would make the module
    constant unpatchable and every test of this read the real host's mounts.
    """
    mountinfo = mountinfo or MOUNTINFO
    try:
        lines = mountinfo.read_text().splitlines()
    except OSError:
        return set()
    points = set()
    for line in lines:
        fields = line.split(" ")
        if len(fields) > 4:
            points.add(Path(_unescape_mountinfo(fields[4])))
    return points


# Shipped bundle control-file tree (Containerfile/build.sh/setup.sh/policy.cil),
# keyed by `[workload] bundle`. Env-overridable so the control-file resolver can
# be unit-tested against a temp /usr tree. The operator override leg lives under
# WORKLOAD_CONFIG_DIR/<name>/ (see WorkloadConfig.resolve_control_file).
WORKLOAD_BUNDLES_DIR = Path(
    os.environ.get("WORKLOAD_BUNDLES_DIR", "/usr/share/workloadctl/workloads")
)

# Username prefix for workload system users
USERNAME_PREFIX = "_wl-"

# [security] key that opts a workload in to `userns = "host"`. Host userns
# dissolves the per-workload isolation boundary, so it is refused unless this is
# set true — an explicit acknowledgement rather than a silently-honoured default.
HOST_USERNS_OPT_IN = "unsafe_host_userns"


# Maximum workload name length (32-char Linux username limit - 4-char prefix - 1)
MAX_NAME_LENGTH = 27

# Workload name pattern: lowercase letter, then lowercase letters/digits/hyphens
NAME_PATTERN = re.compile(r'^[a-z][a-z0-9-]*$')

# Container name pattern (same shape as workload name)
CONTAINER_NAME_PATTERN = re.compile(r'^[a-z][a-z0-9-]*$')
MAX_CONTAINER_NAME_LENGTH = 27

# Directives written by the generator — custom_directives should not override these
GENERATOR_OWNED_DIRECTIVES = frozenset({
    "Type", "NotifyAccess", "User", "Group", "Environment", "EnvironmentFile",
    "ExecStartPre", "ExecStart", "ExecStop",
    "StandardOutput", "StandardError",
    "Restart", "RestartSec",
    "ProtectSystem", "ReadWritePaths", "PrivateTmp",
})

# --- Config locator ---

def workload_config_path(name: str) -> Path:
    """Instance config path for a workload, under the config dir."""
    return workload_config_dir() / name / "workload.toml"


def load_workload_config(name: str) -> dict:
    """Parse one workload's instance TOML by name.

    Every boot-time helper needs this and each used to spell it itself --
    under three different names, and six of them behind a
    `except ModuleNotFoundError: tomllib = None` fallback that no code path
    ever consulted, so the fallback could only ever turn a legible ImportError
    into an AttributeError one line later.

    Errors are NOT caught here. A helper reading a config it cannot parse has
    nothing to do but fail, and the callers that want to survive a bad config
    (cmd_drift, the generator's per-workload loop) already wrap their own read
    in the handling that says what they do about it -- which is not the same
    handling, so there is nothing to share.
    """
    with open(workload_config_path(name), "rb") as f:
        return tomllib.load(f)


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


def systemd_escape_path(path: str) -> str:
    """Escape an absolute path the way `systemd-escape --path` does.

    Used to name the .mount unit that manages a path, so a unit can be ordered
    After= it. systemd derives mount unit names from the mountpoint by this
    exact transform, so any divergence here produces an ordering edge on a unit
    that does not exist -- which systemd accepts silently, leaving the caller
    with no ordering and no error.

    The rules (see systemd's unit_name_path_escape): strip the leading and
    trailing slashes, map "" (the root) to "-", replace "/" with "-", and
    hex-escape anything outside [A-Za-z0-9:_.], plus a leading ".".

    A literal "-" in the path is therefore escaped to \\x2d -- it is the
    separator, and leaving it alone is the easy way to get a name that looks
    right and matches nothing.
    """
    trimmed = path.strip("/")
    if not trimmed:
        return "-"
    out = []
    for i, ch in enumerate(trimmed):
        if ch == "/":
            out.append("-")
        elif ch.isascii() and (ch.isalnum() or ch in ":_.") and not (i == 0 and ch == "."):
            # A leading "." would start a hidden unit file name, so systemd
            # escapes it even though "." is otherwise allowed.
            out.append(ch)
        else:
            out.append("".join(rf"\x{b:02x}" for b in ch.encode("utf-8")))
    return "".join(out)


# --- Naming conventions ---

def workload_username(name: str) -> str:
    """Return the system username for a workload: _wl-{name}."""
    return f"{USERNAME_PREFIX}{name}"


def replace_file_atomically(
    path: Path | str,
    content: str | bytes,
    *,
    default_mode: int = 0o644,
    owner: tuple[int, int] | None = None,
) -> None:
    """Replace path's whole contents with content, atomically.

    Use this for any file that already holds content worth keeping, whenever a
    reader could observe the write or a crash could outlive it. A plain
    write_text() truncates first, so it has two failure modes: a concurrent
    reader sees a partial file with no way to detect that it is partial, and an
    interrupted write leaves the file permanently truncated — destroying content
    the writer never meant to touch. Writing a sibling temp file and renaming it
    on means readers see either the whole old file or the whole new one, and a
    crash leaves the old one intact.

    Mode and ownership are carried over from the file being replaced, so the
    rename cannot silently reset them; default_mode and owner apply only when
    there is no existing file. The temp lands in path's own directory because
    rename is atomic only within a filesystem.
    """
    path = Path(path)
    tmp = path.with_name("." + path.name + ".tmp")
    try:
        st = path.stat()
        mode, uid, gid = stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid
    except FileNotFoundError:
        mode = default_mode
        uid, gid = owner if owner is not None else (0, 0)
    if owner is not None:
        uid, gid = owner
    body = content.encode() if isinstance(content, str) else content
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, body)
        # Durability before the rename: the rename is atomic w.r.t. readers, but
        # without the fsync a crash can land the rename while the data blocks
        # are still unwritten, leaving a zero-length file.
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    try:
        os.chown(tmp, uid, gid)
    except (PermissionError, OSError):
        # Non-root can't chown; the callers that need a specific owner all
        # require root anyway, so losing ownership here would be a bug
        # elsewhere, not a reason to fail the write.
        pass
    os.replace(tmp, path)


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


STATE_SUBDIR = "state"
DATA_SUBDIR = "data"


def workload_state_dir(name: str) -> Path:
    """Reconstructible state subtree (= $HOME / podman graphroot / VM disks).

    Backup-skipped (rebuildable from registries/Containerfiles).
    """
    return workload_root_dir(name) / STATE_SUBDIR


def workload_data_dir(name: str) -> Path:
    """Precious data subtree. './' volume anchors resolve here. Backup-captured."""
    return workload_root_dir(name) / DATA_SUBDIR


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


# --- Instance token expansion ---

# ${WORKLOAD_*} tokens usable in workload.toml values that must name the
# instance. Deliberately the same vocabulary provisioning.host_setup_env()
# exports to [host] setup scripts, so a bundle spells its own identity one way
# whether it's doing so from TOML or from shell.
WORKLOAD_TOKEN_PATTERN = re.compile(r'\$\{(WORKLOAD_[A-Z_]+)\}')


def workload_tokens(name: str) -> dict:
    """The ${WORKLOAD_*} token table for one instance."""
    return {
        "WORKLOAD_NAME": name,
        "WORKLOAD_INSTANCE_DIR": str(workload_config_dir() / name),
        "WORKLOAD_ROOT_DIR": str(workload_root_dir(name)),
        "WORKLOAD_STATE_DIR": str(workload_state_dir(name)),
        "WORKLOAD_DATA_DIR": str(workload_data_dir(name)),
    }


# Derived from the table itself so the two can't drift; the instance name is
# irrelevant to the key set.
WORKLOAD_TOKEN_NAMES = frozenset(workload_tokens("_"))


def expand_workload_tokens(value: str, name: str) -> str:
    """Expand ${WORKLOAD_*} tokens in a config value against instance `name`.

    Exists because a bundle can be instantiated under a different name
    (`init --as`), so any absolute path a TOML hardcodes for *itself* is wrong
    for every instance but the first. The alternative — writing
    /etc/workloads.d/<bundle>/... literally — silently points at a workload
    that doesn't exist.

    Unknown WORKLOAD_ tokens raise: a typo left to pass through would reach
    podman verbatim as a path that can never resolve, and failing at generate
    time with the token named is far easier to diagnose than a container that
    won't start.
    """
    tokens = workload_tokens(name)

    def sub(m):
        key = m.group(1)
        if key not in tokens:
            raise ValueError(
                f"unknown token ${{{key}}} (known: {', '.join(sorted(tokens))})")
        return tokens[key]

    return WORKLOAD_TOKEN_PATTERN.sub(sub, value)


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


def uq(s: str) -> str:
    """Quote a string as a LITERAL value for a NON-Exec systemd unit setting
    (RequiresMountsFor=, ReadWritePaths=, ...).

    Differs from dq() in exactly one way, and the difference matters: `$` /
    `${VAR}` expansion runs only on Exec command lines, so a `$` in an ordinary
    setting is *already* literal and doubling it would corrupt the value. `%`
    specifiers are expanded at unit load for every setting, so a literal `%`
    still has to be written `%%`.
    """
    return (
        '"'
        + s.replace('\\', '\\\\')
           .replace('"', '\\"')
           .replace('%', '%%')
        + '"'
    )
