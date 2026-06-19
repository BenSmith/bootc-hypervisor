"""
cmd_catalog — bundle catalog + instantiation: catalog, init, duplicate.

A *bundle* is a shipped directory `/usr/share/workloadctl/workloads/<bundle>/`
co-locating a template declaration (`workload.toml`) with its control files.
`init` stamps a catalog bundle into `/etc/workloads.d/<name>.toml`; `duplicate`
copies a live workload. Neither touches `/var` or the boot path — they only
write the authoritative `/etc` declaration. Control files are *not* copied:
the new TOML's resolved `bundle` falls through to the shared `/usr` tree until
the operator overrides something.
"""

import difflib
import json
from pathlib import Path
import re
import sys
import tomllib

from workload_lib import validate_workload_name
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
    toml_string,
    WORKLOAD_DIR,
)
from cmd_admin import validate_single

BUNDLES_DIR = Path("/usr/share/workloadctl/workloads")

# Edit a single field inside the [workload] section only (mirrors
# cmd_lifecycle._set_enabled): scoping keeps the regex from touching a
# same-named field in some other section.
_WORKLOAD_SECTION_RE = re.compile(
    r'(?ms)(?P<header>^\[workload\][^\n]*\n)(?P<body>.*?)(?=^\[|\Z)'
)


def _set_workload_field(content: str, field: str, value: str) -> str:
    """Set `field = value` in [workload] (value is a TOML literal). Replaces an
    existing line in place or prepends one to the section body."""
    m = _WORKLOAD_SECTION_RE.search(content)
    if not m:
        sep = "" if content.endswith("\n") else "\n"
        return content + f"{sep}[workload]\n{field} = {value}\n"
    body = m.group("body")
    pat = rf'^{re.escape(field)}\s*=[^\n]*'
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
    """Stamp a catalog bundle into /etc/workloads.d/<name>.toml."""
    require_root()
    bundle = args.bundle
    name = args.as_name or bundle

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

    dst = WORKLOAD_DIR / f"{name}.toml"
    if dst.exists():
        print(f"Error: workload '{name}' already exists: {dst}", file=sys.stderr)
        print(f"  choose another name with --as, or edit the existing one", file=sys.stderr)
        sys.exit(1)

    text = src.read_text()
    text = _set_workload_field(text, "name", toml_string(name))
    # Only pin `bundle` when the instance name diverges from the bundle, so
    # the copy's control files still resolve to the source bundle's tree.
    # When name == bundle, `bundle` defaults to name and the field is noise.
    if name != bundle:
        text = _set_workload_field(text, "bundle", toml_string(bundle))
    dst.write_text(text)

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

    try:
        validate_workload_name(new_name)
    except ValueError as e:
        print(f"Error: invalid workload name {new_name!r}: {e}", file=sys.stderr)
        sys.exit(1)

    src_path = WORKLOAD_DIR / f"{src_name}.toml"
    if not src_path.exists():
        print(f"Error: no workload '{src_name}' in {WORKLOAD_DIR}", file=sys.stderr)
        sys.exit(1)

    dst_path = WORKLOAD_DIR / f"{new_name}.toml"
    if dst_path.exists():
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
    dst_path.write_text(text)

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
    # :latest, but worth surfacing).
    image = getattr(cfg, "image", None)
    if image and not cfg.is_vm:
        sharers = [
            c.name for c in manager.get_all_configs()
            if c.name != name and not c.is_vm
            and getattr(c, "image", None) == image
        ]
        if sharers:
            warnings.append(
                f"image '{image}' is also used by {', '.join(sharers)} — they "
                f"share a mutable tag (fine for :latest, intentional otherwise)")

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
