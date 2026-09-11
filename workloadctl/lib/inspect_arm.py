"""One workload's transparent egress inspection, armed and retired.

`up` runs as the inspect socket unit's ExecStartPre, `down` as its
ExecStopPost. `up` is the first thing in the work that writes to the kernel:
everything before it produced files. It writes to TWO tables -- the DNAT maps
in inet workload_proxy and the guard sets in inet workload_filter -- and
arming one and not the other leaves a workload that looks configured and
reaches nothing. `down` removes the per-workload elements, the per-workload
listener addresses, and the internal exemptions, and nothing else.

THE TWO SUBSTRATES ARE ONE PROGRAM

A VM and a container differ in where the network table sits in the TOML,
which predicate says the workload is inspected at all, how its policy
document renders, how its `internal` entries are read and resolved, and what
the failure message can name as the unit that will not start. Those are a
Substrate, and VM and CONTAINER are the two. Everything after them -- the
order of the writes, the purge before the add, the broker's own exemption,
the tolerant teardown -- is the one function body below, so the two helpers
cannot drift apart in the part that arms the kernel.

WHY BOTH SKELETONS ARE APPLIED EVERY START

`nft add element` into a table that does not exist fails, and a host that has
never started a filtered workload has no table of either kind. Applying both
at start makes an RPM upgrade self-heal on the next start instead of the next
reboot: a rebuild that changes a skeleton's object layout is picked up by the
next workload start, not left to a reboot the operator will never think to
perform. This program touches both tables, so it applies both skeletons.

WHAT IS NEVER TORN DOWN

The shared advertised address 192.0.2.1 and the dummy link itself. Both are
host-global and shared: two concurrent starts race for them, which is why
ensure_advertised_interface tolerates "already exists" rather than taking a
lock, and there is no refcount (ADR 006). The per-workload /32 and /128 ARE
removed on stop, so that an address on the link means an inspector that is
supposed to be running -- `diagnose` reports what it sees, and a stopped
workload's listener address is a line nobody can explain. Removal tolerates
"Cannot assign requested address" for the same reason the add tolerates
"assigned".

WHAT ELSE IS WRITTEN HERE

The inspector's policy document, inspect_policy_path(name). It is written
here rather than by the generator because /run does not exist at generate
time, and writing at start is what makes an edited `hosts` list take effect
on a plain restart. The listener reads it once, at start, and holds it for
the life of the process -- which is why the inspect service is PartOf= the
workload.

WHAT IS ARMED HERE THAT IS NOT KEYED ON A PORT

The `wl_internal_ok4/6` destination exemptions (`internal` entries). Their
key is (uid, address) and carries no port, because the exemption is about
where a name resolves to rather than about a service. The rule consulting
them carries the inspector's cgroup match, and THAT is what makes the missing
port safe -- without it the same element is an all-ports grant from the
workload to a LAN address, since the uid is shared between the workload and
the inspector.

The names are resolved here, once, at start. An unresolvable one fails the
start rather than arming nothing: an element that silently did not arm leaves
the host refused by the very drop the entry existed to except, and the
workload sees `403 <host> resolves to an internal address` on the one
destination the operator wrote the entry for.

That failure is fatal to the whole workload, not to the exemption -- this is
the socket's ExecStartPre and the workload's units Requires= the socket -- so
the error says so itself rather than leaving an operator to connect a DNS
message on one unit to a workload that will not start on another.
`workloadctl validate` warns about the same entry before it can do that, at
edit time, where the fix is cheap. See internal_failure.

WHAT IS NOT ARMED HERE

The cgroup elements in wl_egress_cg (inet workload_filter) and wl_inspect_cg
(inet workload_proxy). The builders for both live in lib/nft_elements.py, but
the element is armed by the inspector's own unit, not this program: an
element resolves to a cgroup id at add time and systemd makes a fresh cgroup
on every start, so the add belongs to the unit that owns the cgroup, and the
remove to its ExecStopPost -- the only point at which a path still resolves
to the id being retired. generate_inspect_service emits both lines.

The inspector is the ONE member of each set. The VM's synthesising DNS
responder is deliberately not a second: it originates nothing, so it opens no
socket for either set to exempt, and nothing in the tree arms an element for
it. If it ever gains an outbound socket it needs an element in BOTH sets,
added by its own unit -- see the set comments in nftables/workload-filter.nft
and nftables/workload-proxy.nft.

EXIT CODES

`up` fails loudly: an inspector whose redirect did not install leaves the
workload reaching nothing while the workload itself looks healthy. `down` is
tolerant: its elements are legitimately absent whenever the start failed
before installing them, and the stop must not block.
"""
import ipaddress
import os
import pwd
from collections.abc import Callable
from dataclasses import dataclass

from broker_config import container_uses_credentials, vm_uses_credentials
from config_parser import container_uses_inspect
from egress_policy import (
    inspect_policy_path, inspect_status_path, internal_hosts,
    vm_inspect_policy_text, vm_uses_inspect,
)
from egress_status import clear_status
from helper_main import log, run
from nft import (add_listener_addresses, purge_internal_exemptions,
                 remove_listener_addresses)
from nft_constants import NFT_BIN, NFT_PROXY_SKELETON, NFT_SKELETON
from nft_elements import (
    inspect_element_commands, internal_ok_commands, vm_internal_resolve,
)
from workload_addr import broker_listen_address, ensure_advertised_interface
from workload_lib import (
    container_inspect_policy_text, container_internal_entries,
    container_internal_resolve, load_workload_config,
)


@dataclass(frozen=True)
class Substrate:
    """What differs between a VM's inspection and a container's.

    Every callable takes the loaded config or its network table; nothing
    here reads the kernel. `applies` delegates to the same predicate the
    generator reads to decide whether the inspect units exist at all, so
    this program and the generator cannot disagree about which workloads
    have an inspector.
    """
    network: Callable[[dict], dict]
    applies: Callable[[dict], bool]
    policy_text: Callable[[dict], str]
    internal_hosts: Callable[[dict], list[str]]
    resolve: Callable[[str], list]
    uses_credentials: Callable[[dict], bool]
    entry: str
    """The TOML array an `internal` host is named in, as the operator sees it."""
    requires: Callable[[str], str]
    """The clause naming what Requires= the inspect socket, given the name."""
    subject: str
    """What the failure stops: the "guest" or the "workload"."""
    verb: str
    """What it stops it doing: "boot" or "start"."""


VM = Substrate(
    network=lambda config: config.get("vm", {}).get("network", {}) or {},
    applies=vm_uses_inspect,
    policy_text=vm_inspect_policy_text,
    internal_hosts=internal_hosts,
    resolve=vm_internal_resolve,
    uses_credentials=vm_uses_credentials,
    entry="[[vm.network.internal]]",
    requires=lambda name: f"workload-{name}.service Requires= that socket",
    subject="guest",
    verb="boot",
)

# The requiring unit is not named: it is workload-<name>.service in `single`
# mode and the pod/net head unit in `pod`/`bridge` (see _head_unit in
# generators/workload-generate), so a literal name is wrong in one topology
# and sends the operator to the wrong journal. The remedy is the same either
# way, so the unit adds nothing the operator can act on.
CONTAINER = Substrate(
    network=lambda config: config.get("network", {}) or {},
    applies=container_uses_inspect,
    policy_text=container_inspect_policy_text,
    internal_hosts=lambda net: [e.host for e in container_internal_entries(net)],
    resolve=container_internal_resolve,
    uses_credentials=container_uses_credentials,
    entry="[[network.internal]]",
    requires=lambda name: f"{name}'s own units require that socket",
    subject="workload",
    verb="start",
)


def write_policy(sub: Substrate, name: str, net: dict) -> str:
    """Write the inspector's policy document. Returns its path.

    Root-owned and 0640 with the workload's group: the listener runs as
    _wl-<name> and needs to read it, and 0640 rather than 0644 keeps one
    workload's policy from being enumerable by another. Replaced rather than
    truncated in place, because a restart racing a rewrite would otherwise
    read a half-written document and fail its start over a file that is about
    to be complete.
    """
    path = inspect_policy_path(name)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        # The substrate's one renderer, not a json.dump with its own
        # arguments: `workloadctl drift` compares this file's bytes against a
        # re-render through that function, so a formatting difference here
        # would report every inspected workload as permanently drifted.
        f.write(sub.policy_text(net))
    os.chown(tmp, 0, pwd.getpwnam(f"_wl-{name}").pw_gid)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)
    return path


def internal_failure(sub: Substrate, name: str, host: str,
                     cause: Exception) -> str:
    """Why an `internal` entry could not be armed, AND what it costs.

    The cause alone is a true statement about an exemption, and an operator
    reading it in the journal has to work out the rest: this runs as the
    inspect socket's ExecStartPre, the workload's units Requires= the socket,
    and so a name that stopped resolving does not degrade the workload's
    egress -- it stops the workload starting. Failing loudly is deliberate (an
    exemption that silently did not arm leaves the workload refused by the
    very drop the entry existed to except), but a fatal failure that does not
    say it is fatal is the worst of both: the operator sees a workload that
    will not start and an error about DNS, one unit away from each other.

    So the message states the blast radius and both ways out. Removing the
    entry is a real option and cheap to describe, because `internal`
    authorises nothing on its own -- see vm_inspect_policy. It costs exactly
    this host's reachability from this workload.
    """
    return (f"{cause}\n"
            f"  This is fatal to the START, not only to the exemption: it runs "
            f"as workload-{name}-inspect.socket's ExecStartPre, and "
            f"{sub.requires(name)}, so the {sub.subject} will not {sub.verb} "
            f"while it stands.\n"
            f"  Either make {host} resolve on this host, or drop the "
            f"{sub.entry} entry naming it -- the entry authorises nothing by "
            f"itself, so dropping it costs only this {sub.subject}'s reach to "
            f"that host, and the {sub.subject} {sub.verb}s.")


def up(sub: Substrate, name: str) -> int:
    config = load_workload_config(name)
    net = sub.network(config)
    if not sub.applies(config):
        # The unit should not have been generated at all; treat it as a no-op
        # rather than a failure so an edited config that drops its last
        # trigger stops cleanly instead of blocking the workload's start.
        log(f"  {name} is not inspected; nothing to arm")
        return 0

    uid = pwd.getpwnam(f"_wl-{name}").pw_uid

    # Before anything is armed: the listener is socket-activated, so the
    # workload's first dial can start it the instant the redirect exists, and
    # a listener that started ahead of its policy would fail its start rather
    # than read a stale one -- but it would fail it on a connection the
    # workload already made.
    write_policy(sub, name, net)
    # The previous instance's counters, which the RuntimeDirectory preserved
    # across the restart. See egress_status.clear_status: the inspector is
    # socket-activated, so without this an operator reading `diagnose` between
    # the workload's start and its first dial sees the last run's ECH alarms
    # and internal refusals presented as this one's.
    clear_status(inspect_status_path(name))

    ensure_advertised_interface(run)
    # Both skeletons, for the reason in the module docstring: the DNAT maps
    # live in the proxy table, the guard sets in the filter table, and this
    # unit starts Before= the workload whose prestart would otherwise be the
    # first to create one of them.
    run([NFT_BIN, "-f", NFT_PROXY_SKELETON], check=True)
    run([NFT_BIN, "-f", NFT_SKELETON], check=True)

    # The per-workload listener addresses, both families, v6 nodad. A
    # duplicate "Address already assigned" is tolerated for the reason
    # ensure_advertised_interface's add is: a down that raced a fast restart
    # has not removed them yet.
    add_listener_addresses(uid)

    # Eight elements, both tables, for the reason inspect_element_commands's
    # docstring carries: arming one table and not the other leaves a workload
    # that looks configured and reaches nothing. Purge before adding, because
    # `add element` on an existing key does not overwrite a stale one.
    for argv in inspect_element_commands(uid, "delete"):
        run(argv)
    for argv in inspect_element_commands(uid, "add"):
        run(argv, check=True)

    # The `internal` exemptions, resolved here and armed per address. Purged
    # first for the same reason the eight above are: an edited config that
    # dropped a host would otherwise leave its element behind, and the element
    # outliving the config line is the shape a stale exemption takes.
    #
    # The purge is by UID, not by the addresses about to be armed -- the same
    # argument the stop path makes. A name that resolved differently last time
    # left an element this config cannot name, and adding the new address
    # beside it would exempt the workload for an address nothing asked for.
    purge_internal_exemptions(uid, name)
    hosts = sub.internal_hosts(net)
    addresses = []
    for host in hosts:
        try:
            addresses.extend(sub.resolve(host))
        except ValueError as e:
            raise ValueError(internal_failure(sub, name, host, e)) from None
    # THE BROKER'S OWN ADDRESS IS AN INTERNAL DESTINATION, and without this
    # element the brokered path cannot work at all. `broker_listen_address`
    # is 127.129.x.y, which is inside 127.0.0.0/8 and therefore inside
    # wl_internal4 -- and the drop keyed on this workload's cgroup sits ABOVE
    # the `oif lo accept`, so the inspector's dial to its own broker is dropped
    # by the rule that exists to stop a workload reaching the LAN.
    #
    # It presents as a broker that is down: the connect times out, the listener
    # counts `credential broker unreachable`, and the workload gets a 502
    # telling an operator to go and look at a unit that is running perfectly.
    # Not visible to a unit test, because no unit test sends a packet.
    #
    # Armed only for a workload that HAS a broker, so a workload with no
    # credentials gains no exemption; purged by uid with the rest, so dropping
    # the last credential removes it. Port-less like every other element in
    # this set (see the skeleton's comment): the address is this workload's
    # alone, derived from its uid, and its own broker is the only thing bound
    # there.
    if sub.uses_credentials(config):
        addresses.append(ipaddress.ip_address(broker_listen_address(uid)))
    try:
        add_commands = internal_ok_commands(uid, addresses, "add")
    except ValueError as e:
        # A name that resolved, to an address the internal drop would never
        # match. Same consequence as an unresolvable one, so the same telling.
        raise ValueError(internal_failure(sub, name, ", ".join(hosts), e)) from None
    for argv in add_commands:
        run(argv, check=True)

    log(f"  Inspector redirect armed for uid {uid}, "
        f"{len(net.get('hosts', []) or [])} host pattern(s)")
    if hosts:
        log(f"  Internal exemptions armed for {len(hosts)} host(s): "
            f"{', '.join(hosts)} -> {', '.join(str(a) for a in addresses)}")
    return 0


def down(name: str) -> int:
    """Retire the workload's inspection. Nothing here needs the substrate:
    every key is the uid, which is the one thing a VM and a container hold
    in common, and the config is deliberately not consulted."""
    try:
        uid = pwd.getpwnam(f"_wl-{name}").pw_uid
    except KeyError:
        return 0
    # The values are part of the delete commands but nft matches on the key,
    # so a stale listener address here still removes the right elements. A
    # missing element is the expected state when the start failed before
    # arming, so these are not check=True.
    for argv in inspect_element_commands(uid, "delete"):
        run(argv)

    # NOT the two cgroup exemptions (wl_inspect_cg, wl_egress_cg), and their
    # absence here is a decision rather than an oversight -- substrate_vm's
    # teardown calls the VM helper precisely for the case where the units' own
    # stop path never ran, so a reader will come looking for them.
    #
    # They cannot be removed from here. The delete names the cgroup PATH, and
    # by the time a purge runs the inspect service is gone, so the path
    # resolves to nothing and nft refuses the element. The one moment it does
    # resolve is that service's own ExecStopPost, which is where the removes
    # live.
    #
    # What survives is inert, which is why this is a note and not a gap. An
    # element resolves to a cgroup ID at add time and kernfs IDs are not
    # reused, so a leftover names an ID nothing will hold again and matches no
    # packet -- the opposite of the uid-keyed elements above, where the uid IS
    # reissued by get_next_uid and a leftover is armed for whoever gets it
    # next. That difference is the whole reason this helper is called on purge
    # at all. Two dead set entries per unclean stop, cleared at reboot.

    # The `internal` exemptions, purged by uid. The config is deliberately not
    # consulted here: it names hosts, the set holds addresses, and the mapping
    # between them is a fact about DNS at this instant rather than about this
    # workload. A name that stopped resolving, or that resolves somewhere else
    # now, must still have its elements removed -- and by uid they are all
    # removable, because the uid is the half of the key that cannot rotate.
    try:
        purge_internal_exemptions(uid, name)
    except (OSError, ValueError) as e:
        log(f"  WARNING: could not clear internal exemptions: {e}")

    remove_listener_addresses(uid)
    return 0
