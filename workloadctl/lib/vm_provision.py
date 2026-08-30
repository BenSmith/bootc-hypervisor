"""
vm_provision — did this VM's cloud-init ever actually finish?

A VM's first boot is the only boot on which cloud-init does its per-instance
work: users, sudo drop-ins, runcmd, bootstrap. Completion is recorded *inside
the guest* in /var/lib/cloud/instances/<instance-id>/sem/, so a first boot cut
short — a `workloadctl restart` a few seconds in, a host reboot, an OOM kill, a
power cut, or a module that simply errored — leaves the guest permanently
half-provisioned: the semaphores say those modules already ran, and they are
never retried for that instance-id.

Nothing on the host noticed. The seed ISO is rebuilt on every host boot, but
build_cloud_init_iso only rotates the instance-id when the *rendered user-data
hash* changes (deliberately — otherwise every host reboot would force a full
guest re-provision), so an unchanged config pins the broken instance forever.
Meanwhile the unit is `active`, READY=1 was sent when the vCPUs started, and
SSH answers. The VM reads healthy from every angle the host had.

This module adds the missing fact — *was this instance-id ever observed to
finish?* — and persists it beside the id it vouches for:

    <state>/.cloud-init-provisioned   {"instance_id", "status", "heal_attempts"}

Two halves write and read it:

* ``workload-vm-notify`` (the VM service's main process, running as the
  workload user) watches the guest after READY=1 and records the outcome once
  cloud-init reports one — see ``guest_provision_result``, which asks over SSH
  because the guest agent cannot read cloud-init's state (measured; the reason
  is written up above that function).
* ``workload-ensure-user`` consults it when deciding whether to reuse the
  persisted instance-id, and ``workloadctl diagnose`` reports it.

**Healing is deliberately conservative: only positive evidence of failure
rotates the id.** "No marker" and "not verified yet" mean the host could not
observe the guest (it never answered, it is pinned to an operator bridge the
watch does not probe, or a workloadctl too old to have written one provisioned
it) — which is not the same as a broken
guest, and re-provisioning on that basis would re-run every seed's runcmd on
guests that were fine. A recorded failure is capped at one heal per id lineage
by ``heal_attempts``, so a guest whose cloud-init fails *deterministically*
re-provisions exactly once and then stays put, visible to `diagnose`, instead
of churning a fresh instance on every start.
"""

from __future__ import annotations

import json
import os
import pwd
import subprocess
import time
import tomllib
from pathlib import Path

from vm import VM_DEFAULT_GUEST_USER, VM_MGMT_SSH_PORT, vm_management_address
from workload_lib import (workload_config_path, workload_state_dir,
                          workload_username)

# Written into the workload's state dir (its $HOME), beside
# .cloud-init-instance-id and .cloud-init-fingerprint.
PROVISION_MARKER_FILE = ".cloud-init-provisioned"

# cloud-init finished and reported no errors.
PROVISION_DONE = "done"
# cloud-init finished and reported at least one module error. The one status
# that authorizes a heal.
PROVISION_FAILED = "failed"
# We minted this id and have not yet heard an outcome for it. Written by the
# host at mint time so a marker always exists for the current instance, and the
# absence of a *result* is distinguishable from the absence of a *record*.
PROVISION_UNVERIFIED = "unverified"

# At most one automatic re-provision per id lineage (see module docstring).
MAX_HEAL_ATTEMPTS = 1

# Whole-probe budget: connect, authenticate, run one command, read a few KB over
# a loopback socket. Generous for a guest that answers; the point is to bound
# the wait on one that does not (sshd not up yet, or the guest wedged).
GUEST_PROBE_TIMEOUT = 15.0


# ---------------------------------------------------------------------------
# marker persistence
# ---------------------------------------------------------------------------

def provision_marker_path(state_dir: Path) -> Path:
    return Path(state_dir) / PROVISION_MARKER_FILE


def read_provision_marker(state_dir: Path) -> dict | None:
    """The recorded provisioning outcome, or None if there is no usable record.

    A missing, unreadable or malformed marker is None rather than an error: it
    means "the host has nothing to say about this guest", which every caller
    already has to handle (a workload provisioned by an older workloadctl is
    exactly that case).
    """
    try:
        data = json.loads(provision_marker_path(state_dir).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("instance_id"):
        return None
    return data


def write_provision_marker(state_dir: Path, instance_id: str, status: str,
                           heal_attempts: int = 0,
                           errors: list[str] | None = None,
                           uid: int | None = None,
                           gid: int | None = None) -> None:
    """Record `status` for `instance_id`, replacing any previous record.

    Written tmp+rename so a reader never sees a half-file, and — more to the
    point — so the two writers can take turns: the marker is created by
    ``workload-ensure-user`` as root and then overwritten by the VM service
    running as the workload user. Rename needs only write permission on the
    state dir, which the workload user has (it owns it, 0700), whereas
    rewriting a root-owned file in place would not work.
    """
    state_dir = Path(state_dir)
    payload = {
        "instance_id": instance_id,
        "status": status,
        "heal_attempts": int(heal_attempts),
        "updated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    if errors:
        payload["errors"] = [str(e) for e in errors]

    tmp = state_dir / f".{PROVISION_MARKER_FILE}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, (json.dumps(payload, indent=2) + "\n").encode())
    finally:
        os.close(fd)
    if uid is not None and gid is not None:
        os.chown(tmp, uid, gid)
    os.replace(tmp, provision_marker_path(state_dir))


def marker_vouches_for(marker: dict | None, instance_id: str | None) -> bool:
    """True when `marker` records a *successful* run of exactly `instance_id`.

    Both halves matter. A marker for a previous id says nothing about the
    current one (the operator edited the config, so the id rotated and the
    guest re-provisioned), and a marker recording a failure is the opposite of
    a vouch.
    """
    if not marker or not instance_id:
        return False
    return (marker.get("instance_id") == instance_id
            and marker.get("status") == PROVISION_DONE)


def marker_reports_failure(marker: dict | None, instance_id: str | None) -> bool:
    """True when `marker` records cloud-init *failing* for `instance_id`."""
    if not marker or not instance_id:
        return False
    return (marker.get("instance_id") == instance_id
            and marker.get("status") == PROVISION_FAILED)


def heal_attempts(marker: dict | None, instance_id: str | None) -> int:
    """How many times this id lineage has already been re-provisioned."""
    if not marker or marker.get("instance_id") != instance_id:
        return 0
    try:
        return int(marker.get("heal_attempts", 0))
    except (TypeError, ValueError):
        return 0


def should_heal(marker: dict | None, instance_id: str | None) -> bool:
    """Should we rotate the instance-id to re-run the guest's cloud-init?

    Only on a recorded failure for the id we are about to reuse, and only while
    under the attempt cap. See the module docstring for why "unverified" and
    "no marker" deliberately do not qualify.
    """
    return (marker_reports_failure(marker, instance_id)
            and heal_attempts(marker, instance_id) < MAX_HEAL_ATTEMPTS)


# ---------------------------------------------------------------------------
# asking the guest
# ---------------------------------------------------------------------------
#
# Over SSH, not qemu-guest-agent. The agent looks like the obvious channel — it
# is wired into every VM, it runs as root, and it needs no key — but it is
# confined to the guest's virt_qemu_ga_t domain, which stock Fedora policy does
# not let read cloud-init's state. Measured on a live guest: guest-file-open on
# /run/cloud-init/result.json and guest-exec of `cat` on the same path both
# return "Permission denied", so an agent-based watch would poll to its deadline
# on a perfectly healthy VM and learn nothing. SSH is the path `workloadctl
# exec` already uses, it is subject to no such confinement, and the VM service —
# the process that runs this watch — is the workload user that owns the key.

def _vm_ssh_probe_argv(name: str, guest_user: str, address: str, port: int,
                       state_dir: Path, connect_timeout: int,
                       command: str) -> list[str]:
    """ssh argv for a non-interactive probe of the guest.

    Same host-key pinning as the CLI's exec path (S1): the per-workload
    known_hosts written at provisioning time, keyed by HostKeyAlias so the
    loopback management addresses can't collide. BatchMode/IdentitiesOnly keep
    a probe from ever blocking on a prompt or trying an agent identity.
    """
    ssh_dir = state_dir / ".ssh"
    return [
        "ssh",
        "-p", str(port),
        "-i", str(ssh_dir / "id_ed25519"),
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={ssh_dir / 'vm_known_hosts'}",
        "-o", f"HostKeyAlias={name}",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "LogLevel=ERROR",
        "-o", f"ConnectTimeout={connect_timeout}",
        f"{guest_user}@{address}",
        "--", command,
    ]


# One round trip answers both questions. The instance-id comes first on its own
# line so the JSON — whose length varies with the guest's module list — is
# simply "the rest", and a guest too old to write the id file yields an empty
# first line rather than shifting the parse.
GUEST_PROBE_COMMAND = (
    "cat /var/lib/cloud/data/instance-id 2>/dev/null; echo; "
    "cloud-init status --format=json"
)


def _parse_guest_probe(output: str) -> tuple[str, str | None, list[str]] | None:
    """Turn the probe's stdout into ``(status, guest_instance_id, errors)``.

    Returns None for every answer that is not an outcome — still running, not
    yet run, or unparseable. Deliberately ignores the command's exit status:
    `cloud-init status` exits nonzero for states we treat as "keep waiting", and
    an rc of 0 with empty output is a known guest-SELinux failure shape (a
    confined tool denied the write to sshd's pipe), which must read as "no
    answer" rather than as success.
    """
    guest_id, _, rest = output.partition("\n")
    try:
        data = json.loads(rest)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None

    errors = [str(e) for e in (data.get("errors") or [])]
    status = data.get("status")
    if status == "error" or errors:
        # `errors` is the per-module failure list. recoverable_errors — the
        # deprecation and schema-validation warnings that make a healthy guest
        # report "degraded done" — is a different key and deliberately not read:
        # treating those as failure would re-provision working VMs.
        return PROVISION_FAILED, (guest_id.strip() or None), errors
    if status == "done":
        return PROVISION_DONE, (guest_id.strip() or None), []
    if status == "disabled":
        # Nothing to finish, so nothing to wait for; recording an outcome stops
        # the watch. Never heals, since only PROVISION_FAILED does.
        return PROVISION_DONE, (guest_id.strip() or None), []
    return None  # "running" / "not run" / anything unrecognised: ask again


def guest_provision_result(name: str, timeout: float = GUEST_PROBE_TIMEOUT
                           ) -> tuple[str, str | None, list[str]] | None:
    """Ask the guest whether cloud-init finished, and how.

    Returns ``(status, guest_instance_id, errors)``, or None when the guest has
    not answered — sshd not up yet, cloud-init still running, a VM pinned to an
    operator bridge (whose address this deliberately does not try to discover),
    or a reply we couldn't parse. None is "ask again later", never "the guest is
    broken"; the caller must not treat it as evidence.

    The guest's own instance-id comes back alongside so the caller can refuse to
    attribute a result to an instance it wasn't produced by.
    """
    try:
        target = _vm_probe_target(name)
    except (OSError, ValueError):
        return None
    if target is None:
        return None
    guest_user, state_dir, address, port = target

    argv = _vm_ssh_probe_argv(name, guest_user, address, port,
                              state_dir, max(1, int(timeout // 3)),
                              GUEST_PROBE_COMMAND)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return _parse_guest_probe(proc.stdout)


def _vm_probe_target(name: str) -> tuple[str, Path, str, int] | None:
    """``(guest_user, state_dir, address, port)``, or None if unprobeable.

    None for a workload that is not a VM, has no user yet, or — on an
    operator-provided bridge — has no address the host can resolve right now.
    Such a VM simply gets no record, which reads as "not observed" and never
    heals.

    Two topologies, same split as the CLI's ``_vm_ssh_endpoint``: under passt
    the address is derived from the uid and known without asking anything, while
    on a bridge the guest has a LAN address of its own that has to be
    discovered. The discovery chain is the substrate's, imported lazily so the
    VM service's main process pays for it only when a bridge VM is watched.
    """
    with open(workload_config_path(name), "rb") as f:
        config = tomllib.load(f)
    vm_cfg = config.get("vm")
    if not vm_cfg:
        return None
    try:
        uid = pwd.getpwnam(workload_username(name)).pw_uid
    except KeyError:
        return None
    guest_user = vm_cfg.get("user") or VM_DEFAULT_GUEST_USER

    bridge = (vm_cfg.get("network") or {}).get("bridge")
    if not bridge:
        return (guest_user, workload_state_dir(name),
                vm_management_address(uid), VM_MGMT_SSH_PORT)

    from substrate_vm import _vm_guest_addresses
    addresses = _vm_guest_addresses(name, bridge)
    if not addresses:
        return None
    return guest_user, workload_state_dir(name), addresses[0], 22


def record_guest_provision_result(state_dir: Path, instance_id: str,
                                  name: str,
                                  timeout: float = GUEST_PROBE_TIMEOUT) -> str | None:
    """Query the guest once and persist the outcome; return it, or None.

    Preserves the current lineage's ``heal_attempts`` so recording an outcome
    never resets the cap that stops a deterministically-failing guest from
    re-provisioning on every start.
    """
    answer = guest_provision_result(name, timeout=timeout)
    if answer is None:
        return None
    status, guest_id, errors = answer
    # A result produced by a different instance says nothing about this one.
    if guest_id and guest_id != instance_id:
        return None
    marker = read_provision_marker(state_dir)
    write_provision_marker(state_dir, instance_id, status,
                           heal_attempts=heal_attempts(marker, instance_id),
                           errors=errors)
    return status
