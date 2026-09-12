"""The [host] setup hook: a bundle's script run against an instance.

A setup script lives in the bundle and acts on an instance, so it runs with
the instance context in its environment (`host_setup_env`), in both
directions -- `run_host_setup` takes an `action` because a teardown is the
same step with the sign flipped, and keeping the pair together is what
stops enable and disable from drifting apart. The read-only third action,
`host_setup_artifacts`, asks the script what it installed, so the
diagnostics can check host-global sidecars they cannot otherwise see
(`workload_run_files()` covers only generator output). The read and the
two writes live together because they have to agree about which script
and which name, or the check inspects the wrong host.

Installed to /usr/libexec/workloadctl/host_setup.py.
"""

import os
import subprocess
from typing import NamedTuple

from cli_log import error, info, warn
from config_parser import workload_root_dir
from substrate import LifecycleError
from workload_lib import (
    workload_config_dir,
    workload_data_dir,
    workload_state_dir,
    workload_username,
)
from workloadctl_core import WorkloadConfig


def host_setup_env(config: WorkloadConfig) -> dict:
    """The instance context a [host] setup script runs against.

    A setup script lives in the *bundle* but acts on an *instance*, and those
    are different names the moment someone runs `init --as` / `duplicate`: the
    bundle stays `sunshine-streaming` while the instance is `games`. A
    script that hardcodes its own bundle name therefore touches paths belonging
    to a workload that doesn't exist — and because enable's earlier steps
    (users, units, unit symlinks) already used the *instance* name, the two
    halves disagree and the host is left half-provisioned.

    So the resolved names are passed in rather than left to the script to
    guess. Scripts should treat these as required (`${WORKLOAD_NAME:?}`) —
    defaulting to a baked-in literal reintroduces exactly the bug.
    """
    name = config.name
    return {
        "WORKLOAD_NAME": name,
        "WORKLOAD_BUNDLE": config.bundle,
        # The shipped /usr control-file tree, so a script can reach a sibling
        # helper (e.g. sunshine-streaming's udev-relay) even when it is itself
        # running
        # from an /etc override that carries only setup.sh — the override chain
        # is per-file, so ${WORKLOAD_INSTANCE_DIR}→${WORKLOAD_BUNDLE_DIR} is the
        # shell-side mirror of resolve_control_file().
        "WORKLOAD_BUNDLE_DIR": str(config.bundle_dir),
        "WORKLOAD_USER": workload_username(name),
        "WORKLOAD_INSTANCE_DIR": str(workload_config_dir() / name),
        "WORKLOAD_ROOT_DIR": str(workload_root_dir(name)),
        "WORKLOAD_STATE_DIR": str(workload_state_dir(name)),
        "WORKLOAD_DATA_DIR": str(workload_data_dir(name)),
    }


# The read-only third action. A setup script that implements it prints one
# artifact per line and exits 0; one that doesn't falls through its own dispatch
# `*)` arm and exits nonzero, which is how "unimplemented" stays distinguishable
# from "implemented, declares nothing" without a version handshake.
#
# Not spelled `declare`: that is a bash builtin, and a script defining
# `declare() { ... }` to match the action breaks every `local`/`declare` inside
# itself. `list` collides with the CLI's own list verbs.
HOST_SETUP_ARTIFACTS_ACTION = "artifacts"

# Kinds map to checks the diagnostics already know how to run. Deliberately
# short: anything richer (mode, owner, content) belongs to the script, which is
# the thing that created the artifact and the only thing that can say what
# correct looks like.
HOST_ARTIFACT_KINDS = ("unit", "file")

# Sunshine's script shells out to python3 to read a port out of the instance
# TOML before it dispatches, so this is not instant; it is still a read run by
# `doctor`, and a hung script must not hang the report.
HOST_SETUP_ARTIFACTS_TIMEOUT = 15


class HostArtifact(NamedTuple):
    kind: str   # one of HOST_ARTIFACT_KINDS
    ref: str    # a unit name for "unit", an absolute path for "file"


class HostArtifacts(NamedTuple):
    """What a workload's setup script says it installed on the host.

    Three distinct states, none of which is a failure by itself:

    - `supported=False, error=None` — the script does not implement the action
      (an older bundle, or an operator's own override under /etc). The answer
      is *unknown*, and unknown must never render as "nothing".
    - `supported=True, artifacts=[]` — the script implements it and installs
      nothing host-global. jellyfin is the real example: it flips a system-wide
      SELinux boolean it deliberately does not own.
    - `supported=True, artifacts=[...]` — the checkable set.

    `error` is set when the script could not be asked at all (timeout, not
    executable). That one *is* a finding.
    """
    supported: bool
    artifacts: list[HostArtifact]
    unparsed: list[str]
    error: str | None


def _parse_host_artifacts(text: str) -> tuple[list[HostArtifact], list[str]]:
    """Split declaration output into (artifacts, unparsed lines).

    Unparsed lines are returned rather than dropped. A script that prints
    progress chatter on this action has a bug the operator needs told about —
    silently ignoring it would let a typo'd kind erase an artifact from the
    checked set, which is the same invisibility this whole mechanism exists to
    end.
    """
    artifacts: list[HostArtifact] = []
    unparsed: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or parts[0] not in HOST_ARTIFACT_KINDS or not parts[1].strip():
            unparsed.append(line)
            continue
        artifacts.append(HostArtifact(parts[0], parts[1].strip()))
    return artifacts, unparsed


def host_setup_artifacts(config: WorkloadConfig) -> HostArtifacts | None:
    """Ask a workload's setup script what it installed on the host.

    Returns None when there is nothing to ask — no `[host] setup` configured, or
    the configured script is not on disk. (A missing script is already reported
    by the enable path; re-reporting it here would double-count one fault.)

    Read-only by contract: this runs from `doctor` and `diagnose`, so the script
    must not mutate anything on this action, and a nonzero exit is an answer
    ("I don't implement that") rather than an error — nothing here raises
    LifecycleError the way the enable path does.
    """
    setup_script = config.config.get("host", {}).get("setup", "")
    if not setup_script:
        return None

    script_path = config.resolve_control_file(setup_script)
    if not script_path.exists():
        return None

    try:
        result = subprocess.run(
            [str(script_path), HOST_SETUP_ARTIFACTS_ACTION],
            capture_output=True, text=True,
            timeout=HOST_SETUP_ARTIFACTS_TIMEOUT,
            env={**os.environ, **host_setup_env(config)},
        )
    except subprocess.TimeoutExpired:
        return HostArtifacts(False, [], [], (
            f"setup script did not answer '{HOST_SETUP_ARTIFACTS_ACTION}' within "
            f"{HOST_SETUP_ARTIFACTS_TIMEOUT}s: {script_path}"))
    except OSError as e:
        return HostArtifacts(False, [], [], f"cannot run {script_path}: {e}")

    if result.returncode != 0:
        # The `*)` usage arm every shipped script already has. Not a finding.
        return HostArtifacts(False, [], [], None)

    artifacts, unparsed = _parse_host_artifacts(result.stdout)
    return HostArtifacts(True, artifacts, unparsed, None)


def run_host_setup(config: WorkloadConfig, action: str):
    """Run host setup script if configured in [host] section.

    The setup script receives 'enable' or 'disable' as its first argument, and
    the instance context of host_setup_env() in its environment.
    It is expected to be idempotent in both directions.

    On the enable path a nonzero exit raises LifecycleError carrying the
    script's own returncode; on the disable path it is reported and tolerated.
    """
    setup_script = config.config.get("host", {}).get("setup", "")
    if not setup_script:
        return

    # Relative names resolve through the override chain (/etc override wins over
    # the shipped bundle); an absolute path is taken verbatim.
    script_path = config.resolve_control_file(setup_script)

    if not script_path.exists():
        warn(f"  WARNING: Host setup script not found: {script_path}")
        return

    info(f"  Running host setup script ({action})...")
    result = subprocess.run(
        [str(script_path), action],
        capture_output=False,
        env={**os.environ, **host_setup_env(config)},
    )
    if result.returncode != 0:
        error(f"  Error: Host setup script exited with code {result.returncode}")
        if action == "enable":
            # A teardown that fails is reported and tolerated — disable has to be
            # able to finish. An enable that fails must not proceed to start a
            # service whose host prerequisites aren't there.
            raise LifecycleError(result.returncode)
