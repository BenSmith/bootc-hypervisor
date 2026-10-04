"""A workload's seccomp profile: the baseline, or the baseline plus the
syscalls its `[security] seccomp_allow` names.

The derived profile is rendered by the generator beside the units, from the
baseline installed at that moment, so it is rebuilt whenever the units are
and `drift` reports one an RPM update has left behind. Each allowed name is
taken out of every entry of the baseline, denials, capability gates and
argument filters alike, and allowed in one entry of its own: a name both
allowed and denied leaves the outcome to libseccomp's rule ordering, and an
ungated allow beside a gated deny undoes the gate.

Installed to /usr/libexec/workloadctl/workload_seccomp.py.
"""
import copy
import json
import os
import re
from pathlib import Path

# Baseline seccomp profile applied to all workloads unless overridden via
# security_opt.
SECCOMP_BASELINE = "/usr/share/containers/seccomp-workload-baseline.json"

SYSCALL_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")


def baseline_source() -> Path:
    """Where the generator reads the baseline. Honors
    WORKLOAD_SECCOMP_BASELINE for tests; units always name SECCOMP_BASELINE."""
    return Path(os.environ.get("WORKLOAD_SECCOMP_BASELINE", SECCOMP_BASELINE))


def seccomp_allow(config: dict) -> list[str]:
    """The syscalls the workload's top-level [security] adds to the
    baseline, sorted and without repeats; [] when it adds none."""
    names = config.get("security", {}).get("seccomp_allow") or []
    return sorted(set(names))


def derived_profile_name(name: str) -> str:
    """The derived profile's file name, beside the workload's units."""
    return f"workload-{name}.seccomp.json"


def derived_profile(baseline: dict, names) -> dict:
    """`baseline` with each of `names` taken out of every entry and allowed
    unconditionally. An entry left with no names is dropped."""
    names = set(names)
    profile = copy.deepcopy(baseline)
    syscalls = []
    for entry in profile.get("syscalls", []):
        kept = [n for n in entry["names"] if n not in names]
        if kept:
            entry["names"] = kept
            syscalls.append(entry)
    if names:
        syscalls.append({"names": sorted(names), "action": "SCMP_ACT_ALLOW"})
    profile["syscalls"] = syscalls
    return profile


def render_derived_profile(names) -> str:
    """The derived profile's text, from the baseline installed now. Raises
    OSError or ValueError when the baseline cannot be read."""
    baseline = json.loads(baseline_source().read_text())
    return json.dumps(derived_profile(baseline, names), indent=1) + "\n"


def validate_seccomp_allow(config: dict, kind: str) -> list[str]:
    """Errors for [security] seccomp_allow: a list of syscall names, on a
    container that is not privileged and names no profile of its own, and
    only in the top-level [security]."""
    errors = []
    security = config.get("security", {})
    names = security.get("seccomp_allow")
    for i, c in enumerate(config.get("containers") or []):
        if isinstance(c, dict) and \
                "seccomp_allow" in c.get("security", {}):
            errors.append(
                f"containers[{c.get('name', i)}].security.seccomp_allow: "
                f"set seccomp_allow in the top-level [security]; one profile "
                f"serves every container of the workload")
    if names is None:
        return errors
    if kind == "vm":
        return errors + ["[security].seccomp_allow: a VM runs under no "
                         "seccomp profile of workloadctl's"]
    if not isinstance(names, list) or not all(
            isinstance(n, str) and SYSCALL_NAME.match(n) for n in names):
        return errors + ["[security].seccomp_allow must be a list of "
                         "syscall names (lowercase letters, digits and _)"]
    if security.get("privileged"):
        errors.append("[security].seccomp_allow: privileged = true runs "
                      "under no seccomp profile")
    for where, sec in [("[security]", security)] + [
            (f"containers[{c.get('name', i)}].security", c.get("security", {}))
            for i, c in enumerate(config.get("containers") or [])
            if isinstance(c, dict)]:
        if any(isinstance(o, str) and o.startswith("seccomp=")
               for o in sec.get("security_opt", [])):
            errors.append(
                f"[security].seccomp_allow: {where}.security_opt names a "
                f"seccomp= profile, which replaces the baseline the names "
                f"are added to; use one or the other")
    return errors
