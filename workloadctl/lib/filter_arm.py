"""One workload's uid-keyed egress filter, armed and retired.

`up` runs as an ExecStartPre, `down` as the matching ExecStopPost (which
systemd also runs on kill and on failure, unlike ExecStop). Both operate on
set *elements* in the shared `inet workload_filter` table; neither ever
touches a rule.

THE TWO SUBSTRATES ARE ONE PROGRAM

A VM and a container are filtered by the same table, keyed on the same thing:
the workload uid, which is the one selector a passt socket and a rootless
podman socket hold in common. What differs is read from the config, not done
to the table -- which table of the TOML holds the network section, what says
the workload is filtered at all, how its allow entries are parsed, resolved
and shaped into elements, and whether a responder needs an answer document
once the elements are in. That is a `Substrate`, and `up` is written once
over it.

- A VM is filtered when `egress = "filtered"`; a VM with a `bridge` has no
  host socket carrying its uid, so there is nothing to filter and the table
  is not even loaded. A container is filtered when it has a `[network]`
  trigger (hosts, allow or policy): there is no default-deny and no `egress`
  key on that side. The one container topology where uid attribution might
  not hold (`mode = "host"`) is excluded upstream, in
  container_uses_inspect() itself, so "has a trigger" already means "uid
  attribution holds".
- Only a VM has a synthesising DNS responder, so only the VM substrate
  writes an answer document after arming. A container resolves through the
  host's own resolver.

WHY THIS IS A PROGRAM AND NOT THREE ExecStartPre= LINES

The obvious shape is to let the generator emit the nft commands directly, and
that very nearly works: `add element` is idempotent, several elements go in
one command, and one `nft` invocation is one atomic transaction.

It breaks on allowlist *edits*: ExecStopPost only deletes what the CURRENT
unit names, so an entry removed from `allow` and re-enabled stays permitted.
Closing that needs an enumerate-and-delete that is more than an Exec line
can express -- nft.purge_uid_elements, which `up` calls before adding the
configured entries.

EXIT CODES: `up` fails loudly, `down` is tolerant. See helper_main.run_helper,
which holds that asymmetry for all four arming helpers.
"""
import json
import os
import pwd
from collections.abc import Callable
from dataclasses import dataclass

from container_network_config import (
    container_allow_entries,
    container_uses_inspect,
)
from egress_policy import uses_resolve
from customs.egress_status import clear_status
from helper_main import log, run
from nft import purge_uid_elements
from nft_constants import NFT_BIN, NFT_SKELETON
from nft_elements import (
    container_allow_resolved, container_filter_commands, vm_filter_commands,
    vm_resolve_status_path,
)
from vm_defs import EGRESS_DEFAULT
from vm_network_config import (
    vm_allow_resolved,
    vm_resolve_policy,
    vm_resolve_policy_path,
)
from workload_lib import load_workload_config


@dataclass(frozen=True)
class Substrate:
    """What one substrate reads from its config; everything else is shared."""

    network: Callable[[dict], dict]
    # True when no host socket can carry the uid: nothing to filter, and the
    # table is left untouched.
    exempt: Callable[[dict], bool]
    # Why the workload is not filtered, or None when it is.
    unfiltered: Callable[[dict, dict], str | None]
    allow_entries: Callable[[dict], list]
    resolved: Callable[[list], list]
    commands: Callable[[int, list, str, list], list]
    # Run once the elements are in: (name, net, uid, resolved) -> None.
    after_arm: Callable[[str, dict, int, list], None] | None


def workload_uid(name: str) -> int:
    return pwd.getpwnam(f"_wl-{name}").pw_uid


def write_resolve_policy(name: str, net: dict, uid: int, resolved) -> str:
    """Write the responder's answer document. Returns its path.

    Written HERE, next to the arming, and from the SAME `resolved` the elements
    were built from. The responder answers named `allow` destinations with the
    addresses that are in the nftables set; a second, independent resolution is
    the same name asked twice, and a round-robin or short-TTL record answering
    differently the second time sends the guest to an address the set does not
    hold -- which is a hang against the default-deny drop, not a refusal.

    Root-owned and 0640 with the workload's group, exactly as the inspector's
    policy is: the responder runs as _wl-<name> and needs to read it, and 0640
    keeps one workload's answers from being enumerable by another. Replaced
    rather than truncated in place, so a responder starting alongside a rewrite
    cannot read a half-written document.

    Ordering is inherited rather than declared: this runs as an ExecStartPre of
    the VM, and the responder is socket-activated by a guest query, which cannot
    happen before the VM it comes from is running.
    """
    path = vm_resolve_policy_path(name)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(vm_resolve_policy(net, uid, resolved), f, indent=2,
                  sort_keys=True)
        f.write("\n")
    os.chown(tmp, 0, pwd.getpwnam(f"_wl-{name}").pw_gid)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)
    return path


def vm_after_arm(name: str, net: dict, uid: int, resolved) -> None:
    """The VM's responder document, from the resolution just armed."""
    if not uses_resolve({"vm": {"network": net}}):
        return
    # Not tolerant: a responder with no answer document fails its start, and
    # it fails it on a query the guest has already made. The guest has exactly
    # one nameserver, so that is the whole of DNS for it -- better to fail the
    # VM's start here, where the message names this helper.
    path = write_resolve_policy(name, net, uid, resolved)
    log(f"  Wrote {path}")
    # The previous instance's query counters, for the reason
    # egress_status.clear_status gives: the RuntimeDirectory is preserved
    # across a restart and the responder does not start until the guest's
    # first query, so the file on disk until then belongs to the last boot.
    clear_status(vm_resolve_status_path(name))


def _vm_unfiltered(config: dict, net: dict) -> str | None:
    egress = net.get("egress", EGRESS_DEFAULT)
    if egress == "filtered":
        return None
    return f"egress = {egress!r}"


VM = Substrate(
    network=lambda config: config.get("vm", {}).get("network", {}) or {},
    exempt=lambda net: bool(net.get("bridge")),
    unfiltered=_vm_unfiltered,
    allow_entries=lambda net: net.get("allow", []),
    resolved=vm_allow_resolved,
    commands=vm_filter_commands,
    after_arm=vm_after_arm,
)

CONTAINER = Substrate(
    network=lambda config: config.get("network", {}) or {},
    exempt=lambda net: False,
    unfiltered=lambda config, net: (
        None if container_uses_inspect(config) else "no [network] trigger"),
    allow_entries=container_allow_entries,
    resolved=container_allow_resolved,
    commands=container_filter_commands,
    after_arm=None,
)


def up(sub: Substrate, name: str) -> int:
    uid = workload_uid(name)
    config = load_workload_config(name)
    net = sub.network(config)
    if sub.exempt(net):
        return 0

    # Not tolerant: everything below depends on the table existing.
    run([NFT_BIN, "-f", NFT_SKELETON], check=True)

    stale = purge_uid_elements(uid)
    if stale:
        log(f"  Cleared {stale} stale element(s) for uid {uid}")

    why = sub.unfiltered(config, net)
    if why is not None:
        log(f"  {why}: {name} is not filtered")
        return 0

    allow = sub.allow_entries(net)
    # One resolution, every consumer. See write_resolve_policy for what a
    # second one costs, and vm_allow_resolved for why it is a function of its
    # own.
    resolved = sub.resolved(allow)
    for argv in sub.commands(uid, allow, "add", resolved):
        run(argv, check=True)
    log(f"  Filtered uid {uid} with {len(allow)} allow entr"
        f"{'y' if len(allow) == 1 else 'ies'}")

    if sub.after_arm is not None:
        sub.after_arm(name, net, uid, resolved)
    return 0


def down(name: str) -> int:
    try:
        uid = workload_uid(name)
    except KeyError:
        # The user is already gone (purge ordering); nothing can be armed.
        return 0
    purge_uid_elements(uid)
    return 0
