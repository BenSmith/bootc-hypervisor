"""
The nft half of diagnose: is the ruleset the generator armed for this
workload the one the kernel is running, and does traffic get through it.

The VM's network posture and its egress plane, the container resolver's
reachability, drift between the allow-list on disk and the sets in the
kernel, and the packet-capture chains.
"""
from pathlib import Path

from container_network_config import (
    container_allow_entries,
    container_allow_resolve,
    container_uses_inspect,
    ContainerAllowEntry,
)
from diagnose_inspect import _uses_inspect
from diagnose_probe import PROBE
from netfilter_state import (
    CONNTRACK_PRESSURE, conntrack_occupancy, nft_drop_counter,
    nft_set_elements, owned_elements,
)
from nft import nft_json
from nft_constants import (
    NFT_SET_ALLOW4, NFT_SET_ALLOW6, NFT_SET_FILTERED,
    NFT_SET_INTERNAL4, NFT_SET_INTERNAL6, NFT_TABLE,
)
from pcap import PCAP_CHAINS, pcap_unit_name
from substrate import service_active
from vm_defs import EGRESS_DEFAULT
from vm_network_config import parse_vm_allow, vm_allow_resolve
from workload_addr import MGMT_SSH_PORT, management_address, nflog_group


def vm_network_check(config) -> tuple[str, bool, str]:
    """Report a VM's network topology and its uid-derived values.

    Returns a (check_name, passed, message) triple ready for `_check`.

    This exists because ADR 006 made two facts invisible from the TOML. The
    management address and nflog group are derived from the workload's uid, so
    nothing in the config says where to ssh or what to capture; and a VM that
    names a bridge is unfiltered, which the config states only by implication.
    """
    bridge = config.vm_bridge
    if bridge is not None:
        return ("vm_network", True,
                f"VM is on operator-provided bridge {bridge} — it has a real "
                f"LAN identity and host egress policy does not reach it. This "
                f"is a supported configuration; passt is the filterable one.")

    try:
        uid = config.uid
    except Exception:
        # The user does not exist yet, which check 1 already reports. Say what
        # is true rather than claiming the network is fine or that it is broken.
        return ("vm_network", True,
                "VM uses passt; management address and nflog group are derived "
                "from the workload uid, which does not exist yet")

    return ("vm_network", True,
            f"VM uses passt (uid {uid} is its network identity) — "
            f"ssh {management_address(uid)}:{MGMT_SSH_PORT}, "
            f"capture with 'tcpdump -i nflog:{nflog_group(uid)}'")


def vm_egress_check(config) -> tuple[str, bool, str] | None:
    """Report whether a VM's declared egress posture is actually in force.

    Returns None for workloads the check does not apply to, so the caller can
    skip emitting a line at all.

    The failure this exists for: a config that says `egress = "filtered"` while
    the uid is absent from `wl_filtered`. That VM is wide open and every other
    signal — the unit is active, the guest has network, `status` is green —
    looks correct. Nothing else in `diagnose` would notice.
    """
    if config.vm_bridge is not None:
        return None                      # unfiltered by design; see vm_network
    egress = (config.vm_network or {}).get("egress", EGRESS_DEFAULT)
    try:
        uid = config.uid
    except Exception:
        return None                      # no user yet; check 1 reports it

    table = NFT_TABLE.split()
    filtered = nft_json("list", "set", *table, NFT_SET_FILTERED)
    if filtered is None:
        if egress != "filtered":
            return ("vm_egress", True,
                    f"egress is {egress!r}; no filter table present, which is "
                    f"consistent")
        return ("vm_egress", False,
                f"egress is 'filtered' but the {NFT_TABLE} table is absent, so "
                f"this VM is NOT filtered. It is rebuilt on the next start: "
                f"systemctl restart workload-{config.name}.service")

    armed = str(uid) in owned_elements(uid, nft_set_elements(filtered))
    if egress != "filtered":
        if armed:
            return ("vm_egress", False,
                    f"egress is {egress!r} but uid {uid} is still in "
                    f"{NFT_SET_FILTERED} — a stale element from an earlier "
                    f"config is filtering this VM")
        return ("vm_egress", True, f"egress is {egress!r}; VM is not filtered")

    if not armed:
        return ("vm_egress", False,
                f"egress is 'filtered' but uid {uid} is absent from "
                f"{NFT_SET_FILTERED} — this VM is running UNFILTERED while its "
                f"config says otherwise. Restart it to re-arm: "
                f"systemctl restart workload-{config.name}.service")

    # The internal-destination guard is host-global, but it only bears on a
    # workload that HAS a hostname allowlist -- it qualifies the inspector's
    # cgroup exemption and nothing else. Checked here rather than trusted
    # because the table outlives the RPM that installed it: nft state is kernel
    # state until reboot, and the skeleton is only re-applied by a VM unit's
    # ExecStartPre. A host upgraded to a workloadctl that ships the guard keeps
    # the OLD chain for every VM still running from before the upgrade, and
    # every other signal on that VM stays green while its inspector can still
    # reach RFC 1918.
    if (config.vm_network or {}).get("hosts"):
        unguarded = [name for name in (NFT_SET_INTERNAL4, NFT_SET_INTERNAL6)
                     if not nft_set_elements(
                         nft_json("list", "set", *table, name))]
        if unguarded:
            return ("vm_egress", False,
                    f"egress is filtered on uid {uid}, but {' and '.join(unguarded)} "
                    f"{'is' if len(unguarded) == 1 else 'are'} missing or empty — "
                    f"this VM's egress inspector is NOT restricted from "
                    f"connecting to internal addresses. The loaded table "
                    f"predates the guard; "
                    f"restart to reload it: "
                    f"systemctl restart workload-{config.name}.service")

    allowed = []
    for set_name in (NFT_SET_ALLOW4, NFT_SET_ALLOW6):
        payload = nft_json("list", "set", *table, set_name)
        if payload:
            allowed += owned_elements(uid, nft_set_elements(payload))

    # The drop counter is shared: one rule guarded on set membership serves
    # every filtered workload, so this is a host-wide total and saying
    # otherwise would misattribute a sibling's dropped traffic.
    dropped = nft_drop_counter(nft_json("list", "chain", *table, "output"))
    tail = ""
    if dropped is not None:
        tail = (f"; {dropped[0]} packets dropped across all filtered VMs "
                f"(the counter is shared, not per-workload)")

    # Conntrack occupancy, also host-wide. The guard rules distinguish a reply
    # from a fresh connection by conntrack state alone, so an exhausted table
    # reclassifies replies as `direction original` and drops them mid-transfer
    # -- and nothing else moves when it does: the accept counters are
    # unchanged and the guard counter climbs for what looks like the
    # cross-workload case. Reported always, because an operator reading this
    # line after "downloads keep dying" has no other path from the symptom to
    # the cause. The interpretation is added only under pressure, so a healthy
    # host gets a number and not a warning.
    ct = conntrack_occupancy()
    if ct is not None:
        count, maximum = ct
        tail += f"; conntrack {count}/{maximum}"
        if count >= maximum * CONNTRACK_PRESSURE:
            tail += (" — near capacity, which drops established replies "
                     "mid-connection and presents inside the guest as "
                     "transfers dying part-way")
    return ("vm_egress", True,
            f"egress filtered on uid {uid} with {len(allowed)} allow "
            f"entr{'y' if len(allowed) == 1 else 'ies'}{tail}")


RESOLV_CONF = Path("/etc/resolv.conf")


def host_nameservers(path=RESOLV_CONF) -> list | None:
    """Every `nameserver` address in the host's resolv.conf, or None if unread.

    None and [] are different answers and the caller must not collapse them:
    unreadable means "no opinion", an empty list means "this host names no
    resolver at all", and only one of those is a finding about the workload.
    """
    import ipaddress
    try:
        text = path.read_text()
    except OSError:
        return None
    found = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        parts = line.split()
        if len(parts) < 2 or parts[0] != "nameserver":
            continue
        # A v6 nameserver may carry a scope id (fe80::1%eth0); the address is
        # what the filter matches on, and the zone qualifies it for a sender.
        try:
            found.append(ipaddress.ip_address(parts[1].split("%", 1)[0]))
        except ValueError:
            continue
    return found


def container_resolver_check(config, *, nameservers=PROBE, armed=PROBE
                             ) -> tuple[str, bool, str] | None:
    """Can this filtered container still reach the host's resolver?

    THE ONE WAY A [network] TRIGGER BREAKS A WORKLOAD THAT HAS NOTHING TO DO
    WITH WHAT THE TRIGGER SAYS. Adding `hosts`, `allow` or `policy` puts the
    workload's uid in `wl_filtered`, and the last rule in
    nftables/workload-filter.nft's output chain drops everything from a
    `wl_filtered` uid that no earlier rule accepted. Port 53 is not one of the
    exceptions. What a filtered container gets is: the 80/443 redirect, the
    reply direction of an accepted connection, its own `[[network.allow]]`
    elements, and `oif lo`. The port-53 accept in that file is scoped to
    `wl_egress_cg` -- the INSPECTOR's own cgroup -- which a container is never
    in, so it does not cover this.

    So whether DNS survives is a property of THE HOST, not of the workload:

      - resolv.conf names a loopback stub (127.0.0.53, systemd-resolved):
        pasta re-originates the query to loopback, `oif lo` accepts it, and
        nothing breaks. This is the configuration every hardware run of the
        container egress rig has used, which is exactly why the break has
        never been observed.
      - resolv.conf names a LAN resolver (a router, a homelab DNS box, the
        plain NetworkManager default): the re-originated query is a workload-
        uid socket to a routable address on port 53, no rule accepts it, and
        it is dropped. The container resolves NOTHING -- including the very
        hostnames its `[network].hosts` allowlist names.

    The symptom carries no route to this cause. Every unit is active, the
    inspector is listening, `diagnose` passes everything else, and the failure
    surfaces inside the container as name resolution failing for everything at
    once. Hence this line: it is the only thing on the host that knows both
    halves.

    CONTAINERS ONLY. A filtered VM has a per-workload synthesising responder
    (D7 gives containers none), reached at a management address the guest is
    handed, so its resolver path does not go through this rule at all.

    A FAILURE, not a warning, and the remedy is a real one: an
    `[[network.allow]]` entry for the resolver on port 53 arms exactly the
    element the drop is missing.
    """
    import ipaddress
    if config.is_vm or not container_uses_inspect(config.config):
        return None
    try:
        uid = config.uid
    except Exception:
        return None                      # no user yet; check 1 reports it

    if nameservers is PROBE:
        nameservers = host_nameservers()
    if nameservers is None:
        return None                      # could not read; assert nothing
    if not nameservers:
        return None                      # no resolver configured is not ours

    if armed is PROBE:
        armed = set()
        for set_name in (NFT_SET_ALLOW4, NFT_SET_ALLOW6):
            payload = nft_json("list", "set", *NFT_TABLE.split(), set_name)
            if payload is None:
                continue
            for elem in owned_elements(uid, nft_set_elements(payload)):
                parts = [part.strip() for part in elem.split(" . ")]
                if len(parts) == 3:
                    armed.add((parts[1], parts[2]))

    # "domain" as well as "53": nft renders a `th dport` element numerically
    # today, but a set listed back through a service-name-aware path would
    # read the other way, and treating that as unarmed would be a false alarm
    # about a resolver that works.
    def reachable(addr):
        if addr.is_loopback:
            return True                  # `oif lo`, accepted before the drop
        return ((str(addr), "53") in armed
                or (str(addr), "domain") in armed)

    blocked = [a for a in nameservers if not reachable(a)]
    if not blocked:
        return ("container_resolver", True,
                f"every resolver in {RESOLV_CONF} is reachable from this "
                f"filtered workload "
                f"({', '.join(str(a) for a in nameservers)})")

    listed = ", ".join(str(a) for a in blocked)
    remedy = (f"add each one to [network].allow:\n"
              f"    [[network.allow]]\n"
              f"    address = \"{blocked[0]}\"\n"
              f"    port    = 53\n"
              f"    reason  = \"the host resolver; a filtered uid cannot "
              f"reach it otherwise\"\n"
              f"  then: systemctl restart workload-{config.name}.service")

    if len(blocked) == len(nameservers):
        return ("container_resolver", False,
                f"this workload is filtered (uid {uid} is in "
                f"{NFT_SET_FILTERED}) and EVERY resolver in {RESOLV_CONF} is "
                f"outside what that permits: {listed}. Port 53 is not one of "
                f"the exceptions to the default deny — a filtered uid gets "
                f"the 80/443 redirect, its own allow elements, replies, and "
                f"`oif lo`, and nothing else — so this container resolves "
                f"NOTHING, including the hostnames its own [network] "
                f"allowlist names. Inside it this reads as total DNS failure "
                f"with every unit here healthy. Fix: {remedy}")

    working = ", ".join(str(a) for a in nameservers if a not in blocked)
    return ("container_resolver", False,
            f"this workload is filtered (uid {uid} is in {NFT_SET_FILTERED}) "
            f"and {len(blocked)} of {len(nameservers)} resolvers in "
            f"{RESOLV_CONF} are dropped by the default deny: {listed}. "
            f"Resolution still works while {working} answers, so this is not "
            f"broken yet — but every fallback to the others is dropped "
            f"silently, and a resolver outage that the host would ride out "
            f"becomes total DNS failure for this workload alone. Fix: "
            f"{remedy}")


def allow_drift_check(config) -> tuple[str, bool, str] | None:
    """Does every NAMED `allow` entry still resolve to what was armed for it?

    THE ONE PROPERTY IN THE ALLOW PATH THAT NOTHING ELSE WATCHES. An entry that
    names a host is resolved exactly ONCE -- in the filter helper's `up`, by
    container_allow_resolve or vm_allow_resolve -- and what goes into nftables
    is a literal address. Nothing re-resolves it afterwards. When the name's
    answer changes underneath (a redeployment, a failover, a lease, a
    round-robin that was never stable) the workload dials an address no element
    authorises, the packet falls past every accept to the default deny, and it
    is counted on a drop counter SHARED with every other filtered workload on
    the host.

    The disposition is right. Its legibility was not, and that is what this
    check exists for. When the name behind a live `allow` entry is pointed at
    a second origin, `diagnose`, `doctor` and
    `validate` between them named neither the stale address nor the entry that
    pinned it; `egress` had no record at all, because the inspector is not in
    this path and never sees the connection; and the whole operator-visible
    symptom was a dial that used to work. There was no route from that symptom
    to this cause.

    BOTH SUBSTRATES, and the VM is not the safer one. A VM has a synthesising
    resolver, so a guest's view of an INSPECTED hostname stays current -- but
    `allow` is the path that bypasses the inspector entirely, and its element
    is pinned there exactly as it is here. The only substrate difference is
    which parser reads the entries.

    A FAILURE, not a warning: an entry that no longer resolves to what is armed
    is not a preference, it is a workload that cannot reach a destination its
    own config says it may.

    UNRESOLVABLE IS REPORTED SEPARATELY from drifted, because the remedies
    differ and a restart is right for only one of them. `up` is not tolerant of
    an unresolvable name -- it fails the start -- so a name that has stopped
    resolving since is a workload whose NEXT restart will not come back, and
    saying "restart it" there would be advice to break it.
    """
    if not _uses_inspect(config):
        return None
    try:
        uid = config.uid
    except Exception:
        return None                      # no user yet; check 1 reports it

    if config.is_vm:
        section, net = "vm.network", (config.vm_network or {})
        entries = []
        for item in (net.get("allow") or []):
            try:
                entries.append(parse_vm_allow(item))
            except Exception:            # noqa: BLE001
                continue                 # `validate` owns malformed entries
        named = [(e.host, e.port) for e in entries if e.host and e.port]
        resolve = vm_allow_resolve
    else:
        section = "network"
        net = config.config.get("network", {})
        if not isinstance(net, dict):
            net = {}
        named = [(e.host, e.port) for e in container_allow_entries(net)
                 if e.host and e.port]

        def resolve(host):
            return container_allow_resolve(
                ContainerAllowEntry(host=host, address=None, port=None,
                                    reason=None))

    if not named:
        return None                      # nothing that CAN drift

    table = NFT_TABLE.split()
    armed: set[tuple[str, str]] = set()
    for set_name in (NFT_SET_ALLOW4, NFT_SET_ALLOW6):
        payload = nft_json("list", "set", *table, set_name)
        if payload is None:
            continue
        for elem in owned_elements(uid, nft_set_elements(payload)):
            parts = [part.strip() for part in elem.split(" . ")]
            if len(parts) == 3:
                armed.add((parts[1], parts[2]))

    listed = ", ".join(f"{host}:{port}" for host, port in named)
    if not armed:
        return ("allow_drift", False,
                f"[{section}].allow names {len(named)} host-based "
                f"entr{'y' if len(named) == 1 else 'ies'} ({listed}) but uid "
                f"{uid} owns no element in {NFT_SET_ALLOW4} or "
                f"{NFT_SET_ALLOW6} — none of them is authorised, and a dial to "
                f"any of them is dropped on the shared counter with nothing "
                f"naming the entry. Re-arm: "
                f"systemctl restart workload-{config.name}.service")

    drifted, unresolvable = [], []
    for host, port in named:
        try:
            current = {str(addr) for addr in resolve(host)}
        except Exception as exc:         # noqa: BLE001
            unresolvable.append(f"{host}:{port} ({exc})")
            continue
        pinned = {addr for addr, elem_port in armed if elem_port == str(port)}
        # NO ELEMENT FOR THIS ENTRY'S PORT IS NOT "no drift". An earlier
        # version skipped this case on the grounds that the empty-`armed`
        # branch above covers it -- and it does not, because a workload with
        # two allow entries and one armed element has a non-empty `armed`.
        # That entry is simply unauthorised, and skipping it reported the
        # workload as clean. Caught by the unit test that arms the same address
        # on a DIFFERENT port; nothing on hardware would have shown it, because
        # the symptom is identical to drift.
        #
        # `armed` is pooled across the uid's whole set, so `pinned` holds every
        # address armed on this PORT, not only the ones this entry put there.
        # Two entries sharing a port therefore cover for each other in one
        # direction: if entry B drifts onto exactly the address entry A is
        # armed as, the intersection is non-empty and B reads clean. That is a
        # real hole and a deliberately unclosed one -- closing it means
        # recording which element came from which entry, which nftables does
        # not carry and this check cannot reconstruct. It costs a false
        # negative only when the drifted answer lands on a sibling entry's
        # address, in which case the dial also still works.
        if not pinned:
            drifted.append(f"{host}:{port} has no element armed for it at all")
        elif not (pinned & current):
            drifted.append(
                f"{host}:{port} is armed as {'/'.join(sorted(pinned))} but now "
                f"resolves to {'/'.join(sorted(current))}")

    if drifted:
        return ("allow_drift", False,
                f"[{section}].allow is pinned to its ARM-TIME resolution and "
                f"{len(drifted)} entr{'y is' if len(drifted) == 1 else 'ies are'} "
                f"not authorised as written: {'; '.join(drifted)}. A dial to an "
                f"address no element names matches nothing, falls through to "
                f"the default deny, and is counted on a host-wide drop counter "
                f"that names neither the workload nor the entry. Re-arm to "
                f"re-resolve: "
                f"systemctl restart workload-{config.name}.service")
    if unresolvable:
        return ("allow_drift", False,
                f"[{section}].allow names "
                f"{len(unresolvable)} host{'' if len(unresolvable) == 1 else 's'} "
                f"that no longer resolve on this host: {'; '.join(unresolvable)}. "
                f"The armed elements still work, so nothing is broken yet — but "
                f"arming is not tolerant of an unresolvable name, so the next "
                f"restart of this workload will FAIL to start. Fix the name or "
                f"the resolver before restarting it")
    return ("allow_drift", True,
            f"{len(named)} host-based [{section}].allow "
            f"entr{'y' if len(named) == 1 else 'ies'} still "
            f"resolve{'s' if len(named) == 1 else ''} to what is armed "
            f"({listed})")


def capture_check(config, *, unit_active=PROBE, log_rules=PROBE
                  ) -> tuple[str, bool, str] | None:
    """Report a running capture, so its extra rule is explained rather than found.

    `pcap` is the one read-flavoured command that writes into the
    security-critical `inet workload_filter` table. The rule it adds is
    non-terminating and cannot change accept/drop semantics, but an operator
    who finds an unexplained rule there is right to be alarmed — so diagnose
    names it, names the unit that owns it, and says how it goes away.

    Both outcomes are passes. A capture is a deliberate act, not a fault. The
    line is omitted entirely when nothing is capturing, so this costs a
    healthy workload nothing.
    """
    if unit_active is PROBE:
        # Unpack: service_active returns (active, state), and a bare tuple is
        # always truthy — which reported a running capture for every workload,
        # capture or not. The injected-argument tests never caught it because
        # they pass a bool and skip this line.
        unit_active, _ = service_active(pcap_unit_name(config.name))
    if log_rules is PROBE:
        log_rules = _log_rule_count()

    if not unit_active and not log_rules:
        return None

    unit = pcap_unit_name(config.name)
    if unit_active:
        return ("capture", True,
                f"a packet capture is running ({unit}). It adds a "
                f"non-terminating `log` rule to {NFT_TABLE}, which cannot "
                f"change accept/drop semantics and is removed when the "
                f"capture stops: workloadctl pcap --stop {config.name}")

    # Rules with no unit: a stale artefact rather than an active capture, and
    # the one state worth flagging — the unit's ExecStopPost should have taken
    # them, so something removed the unit without running it.
    return ("capture", False,
            f"{log_rules} `log` rule(s) remain in {NFT_TABLE} with no capture "
            f"unit running. They are non-terminating and change no policy, but "
            f"nothing owns them now. Clear them: nft delete table "
            f"{NFT_TABLE}  (the skeleton is rebuilt on the next VM start)")


def _log_rule_count() -> int:
    """How many `log` rules the filter table currently carries."""
    total = 0
    for chain in PCAP_CHAINS:
        total += _count_log_rules(
            nft_json("list", "chain", *NFT_TABLE.split(), chain))
    return total


def _count_log_rules(payload) -> int:
    count = 0
    for item in (payload or {}).get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        if any("log" in expr for expr in rule.get("expr", [])
               if isinstance(expr, dict)):
            count += 1
    return count
