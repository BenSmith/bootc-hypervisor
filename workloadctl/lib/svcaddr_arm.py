"""Arm or retire a VM's own derived address on the shared dummy link.

A passt VM cannot reach a service on its own host: the address it holds is the
host's default-route address, so dialling it never leaves the guest's stack,
and map-host-loopback=none isolates the guest's loopback, so no host 127.x
address is reachable either. That is deliberate (ADR 006) — the only door a
guest has onto its own host should be the one we make.

The design already derives one non-loopback, guest-reachable address per
workload: the 198.18.x.y inspector address, put on the workload-proxy dummy
link when the workload is *filtered*. This helper puts the SAME address on the
link for every VM, filtered or open, so a host service can publish on it and
that workload's guest can reach it — e.g. a forge container's API, for a build
runner. The inspector still owns 8080/8443 on the address when the workload is
filtered; the rest of the port space carries host services.

The address is derived from the uid, so nothing is invented, registered or
configured: the guest names it through the WORKLOADCTL_VM_INSPECT_ADDR seed
variable rather than learning it from anywhere, and a re-provision that
re-allocates the uid re-derives both halves together.

For a filtered VM the address is also armed by its inspect service; arming it
here too is idempotent (an already-assigned /32 is not a failure) and needs no
predicate — which is the point, because the open VM that the inspect service
never visits is the one that needs this path. Both halves are removed on stop,
keeping the invariant that an address on the link means a workload that is
supposed to be running.
"""
import pwd

from helper_main import log, run
from nft import add_listener_addresses, remove_listener_addresses
from workload_addr import ensure_advertised_interface


def up(name: str) -> int:
    """Ensure this VM's own derived address is on the shared dummy link.

    Fails loudly: a VM that needs a host service and cannot reach it is worse
    than one that did not start. The link creation tolerates "already exists"
    because two VMs racing to start is the expected case, and the address add
    tolerates "already assigned" for the same reason.
    """
    uid = pwd.getpwnam(f"_wl-{name}").pw_uid
    ensure_advertised_interface(run)
    add_listener_addresses(uid)
    log(f"  Derived address armed for {name}")
    return 0


def down(name: str) -> int:
    """Remove this VM's own derived address. Warns rather than raising.

    The link and the advertised address are shared and stay; only this
    workload's /32 and /128 go. Absence is tolerated: a start that died before
    arming left nothing to remove, and a stop must not fail over it.
    """
    uid = pwd.getpwnam(f"_wl-{name}").pw_uid
    remove_listener_addresses(uid)
    return 0
