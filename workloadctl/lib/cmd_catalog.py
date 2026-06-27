"""
cmd_catalog — bundle catalog + instantiation: catalog, init, duplicate.

A *bundle* is a shipped directory `/usr/share/workloadctl/workloads/<bundle>/`
co-locating a template declaration (`workload.toml`) with its control files.
`init` stamps a catalog bundle into `/etc/workloads.d/<name>/workload.toml`; `duplicate`
copies a live workload. Neither touches `/var` or the boot path — they only
write the authoritative `/etc` declaration. Control files are *not* copied:
the new TOML's resolved `bundle` falls through to the shared `/usr` tree until
the operator overrides something.
"""

import difflib
import json
from pathlib import Path
import re
import shutil
import sys
import tomllib

from workload_lib import validate_workload_name, workload_config_path, WORKLOAD_BUNDLES_DIR
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
    toml_string,
    WORKLOAD_DIR,
)
from cmd_admin import validate_single

BUNDLES_DIR = WORKLOAD_BUNDLES_DIR

# Edit a single field inside the [workload] section only (mirrors
# cmd_lifecycle._set_enabled): scoping keeps the regex from touching a
# same-named field in some other section.
_WORKLOAD_SECTION_RE = re.compile(
    r'(?ms)(?P<header>^\[workload\][^\n]*\n)(?P<body>.*?)(?=^\[|\Z)'
)


def _write_new(path: Path, text: str) -> bool:
    """Exclusively create `path` with `text`. Returns False if it already exists
    (closing the check→write TOCTOU; the caller's earlier exists() check is for
    the friendly message, this is the race-safe guarantee)."""
    try:
        with open(path, "x") as f:
            f.write(text)
        return True
    except FileExistsError:
        return False


# Matches a ${SECRET:name} env reference (mirrors cmd_secret's pattern).
_SECRET_REF_RE = re.compile(r'\$\{SECRET:([a-zA-Z0-9_-]+)\}')


def _config_images(cfg: WorkloadConfig) -> set[str]:
    """Container images a workload references, shape-safe across single/pod/
    bridge. VMs have no container image, so return empty. Used by the duplicate
    lint to spot a mutable tag shared with another workload without assuming a
    top-level [container] (which pod/bridge workloads don't have)."""
    if cfg.is_vm:
        return set()
    try:
        return {img for _, img in cfg.container_images()}
    except Exception:
        return set()


def _referenced_secrets(cfg: WorkloadConfig) -> list[str]:
    """Secret names a config pulls in — via [secrets].files credentials and
    ${SECRET:name} refs in any container's environment (single/pod/bridge)."""
    found: set[str] = set()
    for spec in cfg.config.get("secrets", {}).get("files", []):
        cred = spec.get("credential")
        if cred:
            found.add(cred)
    container_envs = []
    single = cfg.config.get("container", {})
    if single:
        container_envs.append(single.get("environment", {}))
    for c in cfg.config.get("containers", []):
        container_envs.append(c.get("environment", {}))
    for env in container_envs:
        for val in env.values():
            for m in _SECRET_REF_RE.finditer(str(val)):
                found.add(m.group(1))
    return sorted(found)


def _set_workload_field(content: str, field: str, value: str) -> str:
    """Set `field = value` in [workload] (value is a TOML literal). Replaces an
    existing line in place or prepends one to the section body."""
    m = _WORKLOAD_SECTION_RE.search(content)
    if not m:
        sep = "" if content.endswith("\n") else "\n"
        return content + f"{sep}[workload]\n{field} = {value}\n"
    body = m.group("body")
    # Tolerate an indented key (TOML allows leading whitespace); the comment
    # `#field` won't match because `^[ \t]*field` requires the key at a line's
    # logical start, not after a `#`.
    pat = rf'^[ \t]*{re.escape(field)}\s*=[^\n]*'
    if re.search(pat, body, re.MULTILINE):
        new_body = re.sub(pat, f'{field} = {value}', body, count=1, flags=re.MULTILINE)
    else:
        new_body = f'{field} = {value}\n' + body
    return content[:m.start("body")] + new_body + content[m.end("body"):]


# ---------------------------------------------------------------------------
# Bundle discovery
# ---------------------------------------------------------------------------

def list_bundles() -> list[str]:
    """Sorted names of shippable bundles (a dir with a workload.toml)."""
    if not BUNDLES_DIR.is_dir():
        return []
    return sorted(p.parent.name for p in BUNDLES_DIR.glob("*/workload.toml"))


def _bundle_kind(bundle: str) -> str:
    """'vm' or 'container' (best-effort; '?' if the template won't parse)."""
    try:
        data = tomllib.loads((BUNDLES_DIR / bundle / "workload.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError):
        return "?"
    return "vm" if "vm" in data else "container"


def _suggest_bundle(bundle: str) -> None:
    """Print a did-you-mean hint + the available bundle list to stderr."""
    avail = list_bundles()
    if not avail:
        return
    close = difflib.get_close_matches(bundle, avail, n=1)
    if close:
        print(f"  did you mean '{close[0]}'?", file=sys.stderr)
    print("  available bundles: " + ", ".join(avail), file=sys.stderr)


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------

def cmd_catalog(args, manager: WorkloadManager):
    """List shippable bundles under the workloads share dir."""
    bundles = list_bundles()
    if getattr(args, "json", False):
        print(json.dumps(
            [{"bundle": b, "kind": _bundle_kind(b)} for b in bundles], indent=2))
        return
    if not bundles:
        print(f"No bundles found under {BUNDLES_DIR}")
        return
    print("Available bundles (workloadctl init <bundle> [--as <name>]):")
    for b in bundles:
        print(f"  {b:<32} {_bundle_kind(b)}")


# ---------------------------------------------------------------------------
# init — instantiate a catalog bundle into /etc
# ---------------------------------------------------------------------------

def cmd_init(args, manager: WorkloadManager):
    """Stamp a catalog bundle into /etc/workloads.d/<name>/workload.toml."""
    require_root()

    scratch = getattr(args, "scratch", None)
    bundle = getattr(args, "bundle", None)

    if scratch and bundle:
        print("Error: --scratch and a bundle positional are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    if scratch:
        name = scratch
        try:
            validate_workload_name(name)
        except ValueError as e:
            print(f"Error: invalid workload name {name!r}: {e}", file=sys.stderr)
            sys.exit(1)
        stub = (
            f'[workload]\n'
            f'name = "{name}"\n'
            f'enabled = false\n'
            f'\n'
            f'[container]\n'
            f'image = "CHANGE_ME"\n'
            f'pull = "newer"\n'
        )
        dst = workload_config_path(WORKLOAD_DIR, name)
        if dst.parent.exists():
            print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
            sys.exit(1)
        dst.parent.mkdir()
        if not _write_new(dst, stub):
            print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
            sys.exit(1)
        print(f"✓ Created scratch workload '{name}'")
        print(f"  {dst}")
        _post_write_report(name, manager)
        return

    name = args.as_name or bundle

    # Validate the bundle before it's pathed (it's a directory name); the
    # existence check below would also catch a traversal, but an up-front
    # name error is clearer and consistent with how `name` is handled.
    try:
        validate_workload_name(bundle)
    except ValueError as e:
        print(f"Error: invalid bundle name {bundle!r}: {e}", file=sys.stderr)
        _suggest_bundle(bundle)
        sys.exit(1)

    try:
        validate_workload_name(name)
    except ValueError as e:
        print(f"Error: invalid workload name {name!r}: {e}", file=sys.stderr)
        sys.exit(1)

    src = BUNDLES_DIR / bundle / "workload.toml"
    if not src.exists():
        print(f"Error: no bundle '{bundle}' under {BUNDLES_DIR}", file=sys.stderr)
        _suggest_bundle(bundle)
        sys.exit(1)

    dst = workload_config_path(WORKLOAD_DIR, name)
    if dst.parent.exists():
        print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
        print(f"  choose another name with --as, or edit the existing one", file=sys.stderr)
        sys.exit(1)

    dst.parent.mkdir()
    text = src.read_text()
    text = _set_workload_field(text, "name", toml_string(name))
    # Only pin `bundle` when the instance name diverges from the bundle, so
    # the copy's control files still resolve to the source bundle's tree.
    # When name == bundle, `bundle` defaults to name and the field is noise.
    if name != bundle:
        text = _set_workload_field(text, "bundle", toml_string(bundle))
    if not _write_new(dst, text):
        print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
        sys.exit(1)

    print(f"✓ Instantiated bundle '{bundle}' as '{name}'")
    print(f"  {dst}")
    _post_write_report(name, manager)


# ---------------------------------------------------------------------------
# duplicate — copy a live workload
# ---------------------------------------------------------------------------

def cmd_duplicate(args, manager: WorkloadManager):
    """Copy a live workload's declaration under a new name (alias: clone)."""
    require_root()
    src_name = args.source
    new_name = args.new

    # Validate BOTH names before either becomes a path. src_name flows into
    # `WORKLOAD_DIR / src_name / "workload.toml"` and is read_text()'d as root
    # (directly and in the tomllib fallback below), so a `../`-laden source would
    # read an arbitrary workload.toml from outside the workloads dir — hold it to
    # the same bar as new_name even though it's only ever read.
    try:
        validate_workload_name(src_name)
    except ValueError as e:
        print(f"Error: invalid source workload name {src_name!r}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        validate_workload_name(new_name)
    except ValueError as e:
        print(f"Error: invalid workload name {new_name!r}: {e}", file=sys.stderr)
        sys.exit(1)

    src_path = workload_config_path(WORKLOAD_DIR, src_name)
    if not src_path.exists():
        print(f"Error: no workload '{src_name}' in {WORKLOAD_DIR}", file=sys.stderr)
        sys.exit(1)

    dst_path = workload_config_path(WORKLOAD_DIR, new_name)
    if dst_path.parent.exists():
        print(f"Error: workload '{new_name}' already exists: {dst_path}", file=sys.stderr)
        sys.exit(1)

    # Resolve the source's bundle: a duplicate of a duplicate must point at the
    # original /usr bundle (src.bundle or src.name), never at the source's own
    # name (which has no /usr bundle dir).
    try:
        resolved_bundle = WorkloadConfig(src_name).bundle
    except Exception:
        data = tomllib.loads(src_path.read_text())
        resolved_bundle = data.get("workload", {}).get("bundle") or src_name

    text = src_path.read_text()
    text = _set_workload_field(text, "name", toml_string(new_name))
    text = _set_workload_field(text, "bundle", toml_string(resolved_bundle))
    dst_path.parent.mkdir()
    if not _write_new(dst_path, text):
        print(f"Error: workload '{new_name}' already exists: {dst_path}", file=sys.stderr)
        sys.exit(1)

    print(f"✓ Duplicated '{src_name}' → '{new_name}' (bundle '{resolved_bundle}')")
    print(f"  {dst_path}")
    _lint_duplicate(new_name, manager)
    _post_write_report(new_name, manager)


def _lint_duplicate(name: str, manager: WorkloadManager) -> None:
    """Warn (never block) on host-global settings a verbatim copy inherits that
    two enabled instances can't both hold: published host ports, absolute volume
    paths (silent data sharing), and a mutable image tag shared with another
    enabled workload. Enforcement is at enable/bind time, not here."""
    try:
        cfg = WorkloadConfig(name)
    except Exception:
        return

    warnings = []

    ports = cfg.config.get("network", {}).get("ports", [])
    if ports:
        warnings.append(
            f"publishes host port(s) {', '.join(str(p) for p in ports)} — two "
            f"instances can't bind the same port; remap before enabling both")

    for vol in cfg.get_volumes():
        host_path = str(vol).split(":", 1)[0]
        if host_path.startswith("/"):
            warnings.append(
                f"absolute volume path '{host_path}' — both instances would "
                f"share it silently (no bind error); point the copy elsewhere")

    # Shared mutable image tag across enabled workloads (a legitimate choice for
    # :latest, but worth surfacing). Shape-safe: a pod/bridge workload has no
    # top-level [container] — `cfg.image` would KeyError — so enumerate every
    # container's image via container_images() for both this copy and each peer.
    others = [c for c in manager.get_all_configs() if c.name != name]
    for img in sorted(_config_images(cfg)):
        sharers = [c.name for c in others if img in _config_images(c)]
        if sharers:
            warnings.append(
                f"image '{img}' is also used by {', '.join(sharers)} — they "
                f"share a mutable tag (fine for :latest, intentional otherwise)")

    # Secrets are name-keyed in a global credstore, so a verbatim copy decrypts
    # fine — but it now reads the *same* credential as the source. Surface it:
    # the copy may want its own secret (rotate one without touching the other).
    secrets = _referenced_secrets(cfg)
    if secrets:
        warnings.append(
            f"references secret(s) {', '.join(secrets)} — the copy reads the same "
            f"credential as its source; give it its own if they should differ "
            f"(workloadctl secret create …)")

    if warnings:
        print()
        print("  Lint (warnings — nothing blocked):")
        for w in warnings:
            print(f"    ⚠ {w}")


def _post_write_report(name: str, manager: WorkloadManager) -> None:
    """Validate the freshly written config (non-fatal — a fresh copy commonly
    needs volume dirs created on first enable) and print next steps."""
    print()
    try:
        cfg = WorkloadConfig(name)
        validate_single(cfg, manager, json_mode=False)
    except Exception as e:
        print(f"  (could not validate yet: {e})")
    print()
    print("Next steps:")
    print(f"  Edit:    workloadctl edit {name}")
    print(f"  Enable:  workloadctl enable {name}")


# ---------------------------------------------------------------------------
# install — promote a local workload directory into /etc/workloads.d/
# ---------------------------------------------------------------------------

def cmd_install(args, manager: WorkloadManager):
    """Copy a workload directory into /etc/workloads.d/<name>/ (from workload.toml name)."""
    require_root()
    src = Path(args.src).resolve()

    toml_path = src / "workload.toml"
    if not toml_path.exists():
        print(f"Error: no workload.toml found in {src}", file=sys.stderr)
        sys.exit(1)

    try:
        data = tomllib.loads(toml_path.read_text())
    except tomllib.TOMLDecodeError as e:
        print(f"Error: workload.toml parse error: {e}", file=sys.stderr)
        sys.exit(1)

    name = data.get("workload", {}).get("name", "")
    if not name:
        print("Error: workload.toml has no [workload] name field", file=sys.stderr)
        sys.exit(1)

    try:
        validate_workload_name(name)
    except ValueError as e:
        print(f"Error: invalid workload name {name!r}: {e}", file=sys.stderr)
        sys.exit(1)

    dst_dir = workload_config_path(WORKLOAD_DIR, name).parent
    if dst_dir.exists():
        print(f"Error: workload '{name}' already exists: {dst_dir}", file=sys.stderr)
        sys.exit(1)

    shutil.copytree(src, dst_dir, ignore=shutil.ignore_patterns(".git", "__pycache__"))

    dst = workload_config_path(WORKLOAD_DIR, name)
    print(f"✓ Installed '{name}' from {src}")
    print(f"  {dst}")
    _post_write_report(name, manager)
