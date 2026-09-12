"""
diagnose_provisioning — did what was supposed to be installed get installed?

Two provisioners, one question. A workload's setup.sh installs host-global
artifacts (units, files) that no generator output records, so their state is
read back from the script's own declaration. A VM's cloud-init runs inside a
guest the host cannot see, so its outcome is read from the marker the
provisioning watch writes. Both verdict functions are pure; the probes are
kept beside them.
"""
from pathlib import Path
import subprocess

from provisioning import (
    HOST_ARTIFACT_KINDS,
    HOST_SETUP_ARTIFACTS_ACTION,
    host_setup_artifacts,
)
from vm_provision import (
    PROVISION_DONE, PROVISION_FAILED, PROVISION_UNVERIFIED,
    MAX_HEAL_ATTEMPTS,
)


def _unit_props(unit: str) -> dict | None:
    """systemd properties for a host-global unit, or None if it has no unit file.

    `systemctl show` invents a stub for a nonexistent unit (LoadState=not-found)
    rather than failing, so absence is read off LoadState, not the exit code.
    """
    result = subprocess.run(
        ["systemctl", "show", unit,
         "-p", "LoadState,ActiveState,SubState,Result,NRestarts"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    props = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    if props.get("LoadState") in ("not-found", "masked", "bad-setting", "error"):
        return None
    return props


def host_artifact_check(artifact, state, name: str) -> tuple[bool, str, str | None]:
    """Verdict for one declared host artifact.

    `state` is whatever the probe for this kind produced: the `systemctl show`
    property dict for a unit (None when the unit file is absent), a bool for a
    file. Pure, so the verdicts are testable without a host — same split as
    selinux_label_check().

    NRestarts > 0 is a failure in its own right and is the reason this check
    exists: `<name>-udev-relay.service` restart-looped 2012 times over seven
    days on a deployed host while `systemctl list-units --failed` stayed clean, because
    a unit that keeps being restarted never settles into `failed`.
    """
    fix = f"sudo workloadctl enable {name}  (re-runs the workload's setup.sh)"
    if artifact.kind == "unit":
        if state is None:
            return (False,
                    f"Declared host unit is not installed: {artifact.ref}", fix)
        active = state.get("ActiveState", "unknown")
        try:
            n_restarts = int(state.get("NRestarts") or 0)
        except ValueError:
            n_restarts = 0
        if n_restarts > 0:
            return (False,
                    f"Declared host unit is restart-looping: {artifact.ref} "
                    f"(NRestarts={n_restarts}, currently {active}) — it never "
                    f"reaches 'failed', so --failed will not show it",
                    f"journalctl -u {artifact.ref} -n 50")
        if active in ("failed", "activating"):
            result = state.get("Result", "")
            detail = f"{active}" + (f", Result={result}" if result else "")
            return (False,
                    f"Declared host unit is not running: {artifact.ref} ({detail})",
                    f"journalctl -u {artifact.ref} -n 50")
        return (True,
                f"Host unit active: {artifact.ref} "
                f"({active}/{state.get('SubState', '')})", None)

    if state:
        return (True, f"Host file present: {artifact.ref}", None)
    return (False, f"Declared host file is missing: {artifact.ref}", fix)


def collect_host_artifact_checks(config, _check) -> None:
    """Check the host-global artifacts a workload's setup.sh declares.

    Fills the gap `workload_run_files()` names in its own docstring — it covers
    generator output only, so a `setup.sh` sidecar is invisible to every verb
    built on it. The set is read from the script rather than inferred, because
    the script is the only thing that knows: half of these are installed
    conditionally (sunshine mints a TLS leaf only where the homelab CA is
    readable, publishes mDNS only where avahi's service dir exists), and a
    declaration made anywhere else would report those correct absences as
    faults.

    Gated on `enabled`: disable() removes these, so a disabled workload is
    *supposed* to be missing them.
    """
    if not config.enabled:
        return
    declared = host_setup_artifacts(config)
    if declared is None:
        return  # no [host] setup, or the script is gone (enable reports that)

    if declared.error:
        _check("host_artifacts", False,
               f"Could not read host artifact declaration: {declared.error}")
        return

    if not declared.supported:
        # Unknown, not empty. Reported as a pass because an un-updated bundle is
        # not a fault of the host being diagnosed — but reported at all, so the
        # operator knows this workload's sidecars are outside the check.
        _check("host_artifacts", True,
               f"Host artifacts undeclared — setup.sh does not implement "
               f"'{HOST_SETUP_ARTIFACTS_ACTION}', so any sidecars it installs "
               f"are not checked here")
        return

    for line in declared.unparsed:
        _check("host_artifacts", False,
               f"setup.sh {HOST_SETUP_ARTIFACTS_ACTION} printed a line that is "
               f"not a declaration: {line!r}",
               fix=f"expected '<{'|'.join(HOST_ARTIFACT_KINDS)}> <ref>' per line, "
                   f"nothing else on stdout")

    if not declared.artifacts:
        _check("host_artifacts", True,
               "setup.sh declares no host-global artifacts")
        return

    for artifact in declared.artifacts:
        state = (_unit_props(artifact.ref) if artifact.kind == "unit"
                 else Path(artifact.ref).exists())
        passed, message, fix = host_artifact_check(artifact, state, config.name)
        _check(f"host_artifact[{artifact.ref}]", passed, message, fix=fix)


def vm_provisioning_check(marker, instance_id: str | None,
                          name: str) -> tuple[bool, str, str | None]:
    """Did the guest's cloud-init actually finish, and what do we do if not?

    The gap this closes: a VM whose first boot was cut short is `active`,
    answers SSH and passes every other check here, while `fedora` was never
    created, no sudo drop-in was written and cloud-init-main.service is failed
    inside the guest. The host's only view of that is the marker written by the
    VM service's provisioning watch (lib/vm_provision.py).

    Only a *recorded failure* fails this check. "Not recorded" and "not yet
    reported" are reported as facts and pass, because they mean the host could
    not observe the guest — it never answered, or it is pinned to an
    operator-provided bridge the watch does not probe — which is not evidence of
    anything being wrong.
    """
    if not instance_id:
        return (True, "cloud-init: no instance provisioned on this host yet", None)

    recorded = (marker or {}).get("instance_id")
    if recorded != instance_id:
        return (True,
                f"cloud-init outcome not recorded for instance {instance_id} "
                f"(the guest never answered, it is pinned to a bridge, or it "
                f"was provisioned by an older workloadctl)", None)

    status = marker.get("status")
    if status == PROVISION_DONE:
        return (True, f"cloud-init finished cleanly (instance {instance_id})",
                None)
    if status == PROVISION_UNVERIFIED:
        return (True,
                f"cloud-init has not reported an outcome for instance "
                f"{instance_id} yet", None)
    if status != PROVISION_FAILED:
        return (True, f"cloud-init status {status!r} for instance {instance_id}",
                None)

    errors = marker.get("errors") or []
    detail = f": {errors[0]}" if errors else ""
    attempts = marker.get("heal_attempts", 0)
    if attempts and attempts >= MAX_HEAL_ATTEMPTS:
        # The automatic re-provision has already been spent on this lineage and
        # the guest still failed, so restarting would only reuse the same id.
        # Rebuilding the system disk is the next escalation: it discards
        # /var/lib/cloud entirely, so nothing survives to be skipped.
        fix = (f"sudo workloadctl update {name}  (the one automatic "
               f"re-provision was already used and cloud-init failed again; "
               f"this rebuilds the system disk from the base image — data/ and "
               f"virtiofs volumes are untouched, anything installed inside the "
               f"guest is not)")
    else:
        fix = (f"sudo workloadctl restart {name}  (re-provisions once with a "
               f"fresh instance-id, which is what makes cloud-init re-run the "
               f"per-instance modules it already marked done)")
    return (False,
            f"cloud-init FAILED for instance {instance_id}{detail} — the guest "
            f"is half-provisioned (users, sudo drop-ins and runcmd may be "
            f"missing) and will not retry on its own", fix)
