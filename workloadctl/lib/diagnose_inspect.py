"""
The inspector half of diagnose: is this workload's egress inspected the way
its policy says, by an inspector that is running the policy and CA on disk.

inspect_check() is the one verdict; the fragments around it each explain one
way it can be wrong — a set element missing, a caller the listener refused,
a credential no policy entry uses, a request that was not HTTP. The
synthesising responder gets its own verdict in diagnose_resolve.
"""
import subprocess
import time

from broker_config import vm_broker_hosts
from container_network_config import (
    container_effective_tls_mode,
    container_uses_inspect,
)
from diagnose_probe import PROBE
from egress_ca import CA_EXPIRY_WARN_DAYS, ca_cert_path
from egress_mint import pem_fingerprint
from egress_plane import CLEARTEXT, TLS
from egress_policy import inspect_policy_path, vm_uses_inspect
from inspect_document import (
    INSPECT_DIGEST_KEY,
    inspect_policy_digest,
    inspect_digest_short,
    INSPECT_DIGEST_SHORT,
    TLS_DEFAULT,
)
from egress_record import (
    DROP_BROKER_UNREACHABLE,
    DROP_MISDIRECTED,
    DROP_MISDIRECTED_LISTED,
    DROP_NOT_HTTP,
    DROP_NOT_HTTP_POLICY,
)
from egress_status import OTHER_KEY
from inspect_figures import read_inspect_status
from netfilter_state import (
    nft_element_counter, nft_set_elements, owned_elements,
    unwrap_counted_elements,
)
from nft import nft_json
from nft_constants import (
    NFT_TABLE, NFT_PROXY_TABLE,
    NFT_MAP_INSPECT4, NFT_MAP_INSPECT6, NFT_SET_INSPECT_SELF,
    NFT_SET_INSPECT_SELF6, NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6,
    NFT_SET_INSPECT_LIVE, NFT_SET_INSPECT_LIVE6,
)
from substrate import service_active
from workload_addr import inspect_address
from workload_lib import workload_state_dir


# vm_proxy_check lived here, with _proxy_map_keys and _proxy_address_present.
# It reported whether a workload's hostname policy was REACHABLE: an element in
# wl_proxy_dest for this uid, and the advertised address present on the dummy
# link. Rung 2 deleted both objects, and inspect_check below is the same
# check against the objects that replaced them -- the redirect maps and the
# inspector's socket unit. Nothing was lost with it except the count of `hosts`
# patterns in its healthy line, which was reporting rather than diagnosis and
# belongs to rung 5's status reader.


def _map_key_uid(elem) -> str | None:
    """The leading uid of one nft map element, whatever shape nft rendered it in.

    Three shapes reach here and only one of them is the obvious dict:

        [{"concat": [10001, 80]}, {"concat": ["198.18.1.1", 8080]}]   # nft 1.1.6
        {"elem": {"key": {"concat": [10001, 80]}}}                    # counted
        "10001 . 80 : 198.18.1.1 . 8080"                              # fixture

    owned_elements handles a *set*'s concat and would return nothing for the
    first of these, because a map element is a two-item [key, value] list and
    not a dict with "concat" at the top. That exact mismatch already reported a
    working proxy redirect as missing once (see _proxy_map_keys); the inspect
    maps are keyed the same way, so reading them with the set helper would
    report every inspected VM as uninspected — a false alarm on every host.
    """
    key = elem
    if isinstance(elem, dict) and "elem" in elem:
        inner = elem["elem"]
        key = inner.get("key", inner) if isinstance(inner, dict) else inner
    if isinstance(key, list) and key:
        key = key[0]
    if isinstance(key, dict) and "concat" in key:
        parts = key["concat"]
        return str(parts[0]) if parts else None
    if isinstance(key, (int, str)):
        return str(key).split(":")[0].split(".")[0].strip() or None
    return None


def _host_has_v6_route() -> bool:
    """Whether this host can route off-link IPv6 at all."""
    try:
        result = subprocess.run(["/usr/sbin/ip", "-6", "route", "show", "default"],
                                capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return True          # unknown: do not manufacture a warning
    return result.returncode == 0 and bool(result.stdout.strip())


def _named_hosts(counts) -> str:
    """A per-host map rendered for an operator, busiest first.

    `(other)` is spelled out rather than printed as a hostname, because it is
    the one key in the map that is not one: it counts EVENTS from hosts past
    the cap, not a host called `(other)`, and an operator who reads it as a
    name goes looking for a VM that dialled it.
    """
    if not isinstance(counts, dict):
        return ""
    named = [(host, n) for host, n in counts.items()
             if host != OTHER_KEY and isinstance(n, int)]
    named.sort(key=lambda pair: (-pair[1], pair[0]))
    parts = [f"{host} ({n})" for host, n in named]
    overflow = counts.get(OTHER_KEY)
    if isinstance(overflow, int) and overflow:
        parts.append(f"plus {overflow} more from hosts past the per-host cap")
    return ", ".join(parts)


def _credential_usage_fragments(status) -> list[str]:
    """What the inspector's own document says about brokered requests.

    The counterpart to `_credential_fragments`, which reads the BUNDLE and says
    what is configured. This says what happened, and the two are wanted at
    different moments: the config fragment answers "is this host brokered at
    all", this one answers "the provider is refusing me and every unit here is
    green".

    THE 401/403 LINE IS THE POINT. Every layer of ours succeeded on those
    requests -- the policy admitted the host, the broker attached material, the
    origin answered -- so nothing else in this report is going to mention them.
    The credential NAMES are printed and the material never is; naming them is
    what turns "a provider said no" into "rotate this key", and on a workload
    with several they are what says which.

    The plain usage line is emitted only where nothing was brokered at all, and
    only where some request WAS made: a workload whose brokered hosts the guest
    has simply not used yet reads as configured-and-idle, which is exactly the
    state an operator is trying to distinguish from a broker that is not
    working. A non-zero usage count needs no sentence -- it is the healthy case
    and the figures already carry it.
    """
    # Gated on the LOADED policy, not on the config: this whole function
    # describes what the running listener did, and a workload whose TOML
    # declares no credential has nothing here to say. Read from `lists.policy`,
    # which is the listener reporting what it is enforcing -- the config is the
    # other fragment's source, deliberately, so that the two can disagree
    # visibly when a listener is enforcing an older document.
    entries = ((status.get("lists") or {}).get("policy") or [])
    if not any(isinstance(e, dict) and e.get("credential") for e in entries):
        return []
    out = []
    unauthorized = status.get("credential_unauthorized")
    if isinstance(unauthorized, int) and unauthorized:
        which = _named_hosts(status.get("per_credential"))
        where = f" using {which}" if which else ""
        out.append(
            f"{unauthorized} brokered request(s) were answered 401/403 by the "
            f"origin{where} — EVERY LAYER HERE SUCCEEDED and the provider "
            f"said no, so the cause is the material or the placeholder, not "
            f"the policy: check that the credential in the credstore is "
            f"current, and that the guest is sending the `placeholder` this "
            f"workload declares rather than a key of its own")
    brokered = status.get("credentialed")
    dropped = (status.get("drop_reasons") or {}).get(DROP_BROKER_UNREACHABLE)
    if isinstance(dropped, int) and dropped:
        out.append(
            f"{dropped} request(s) to a brokered host were dropped because "
            f"this workload's credential broker did not answer — that is a "
            f"unit on this host, not a provider outage: check "
            f"workload-<name>-broker.service, and check audit.log, because a "
            f"missing SELinux rule on that dial looks identical to a broker "
            f"that is down")
    elif (isinstance(brokered, int) and not brokered
            and isinstance(status.get("dispositions"), dict)
            and any(status["dispositions"].values())):
        out.append(
            "no request has been sent through the credential broker yet, "
            "though this guest has made requests — either it has not reached "
            "a brokered host, or it is reaching one by a name the "
            "[[vm.network.policy]] entry does not match")
    return out


def _caller_identity_fragments(status) -> list[str]:
    """The listener could not name some callers, so for those it checked nothing.

    Read because this failure is SILENT by construction. The check fails soft --
    a peer it cannot identify is admitted -- so every connection is served
    exactly as before and no functional surface changes. The counter is the
    only tell, and a counter nobody reads is worth no more than no counter:
    every functional assertion passes with the check fully inert.
    """
    unresolved = status.get("caller_unresolved")
    if not isinstance(unresolved, int) or not unresolved:
        return []
    return [
        f"{unresolved} connection(s) were served without identifying the "
        f"caller — the listener refuses a peer uid that is not this "
        f"workload's, and here it could not read the peer's uid, so for those "
        f"connections that check did nothing. The traffic still passed "
        f"`workload_filter`, which is the control that must hold. Check "
        f"audit.log for a wlinspect_t denial on proc_net_t: a missing SELinux "
        f"rule there looks EXACTLY like this, breaks nothing visible, and is "
        f"how an inert check reaches production"
    ]


def _binding_fragments(status) -> list[str]:
    """The name-to-`Host` binding rejections, as two readings and never one.

    A request inside a terminated session whose `Host` header names something
    other than the name the session's certificate was minted for is refused
    with a 421 either way. WHY it happened is the operator's whole question,
    and the two answers want opposite responses:

      * The name is on no list of this workload's. A guest reused a session it
        was legitimately given to reach a name it was never given -- which is
        the attack the binding exists to close. There is nothing to fix in the
        config; the refusal worked, and the figure is evidence.
      * The name IS allowlisted. That is ordinary connection coalescing: a
        client noticed two allowlisted names resolving to one address and
        reused the connection, which no client asks permission for. It retries
        on its own connection and nothing is lost.

    Merged into one number, every coalescing client reads as an intrusion,
    which is how an alarm stops being read at all. So they are reported as two
    sentences with two dispositions, and the allowlisted one names the hosts --
    WHICH PAIR was coalesced is the entire content of that reading, and a bare
    count cannot carry it.
    """
    reasons = status.get("drop_reasons") or {}
    per_host = status.get("per_host") or {}
    out = []
    unlisted = reasons.get(DROP_MISDIRECTED)
    if isinstance(unlisted, int) and unlisted:
        out.append(
            f"{unlisted} request(s) inside an authorised session named a host "
            f"on NO list for this workload and were refused (421) — a guest "
            f"reusing a session it was given to reach a name it was not. "
            f"Nothing here is misconfigured: read this as evidence, not as a "
            f"setting to change")
    listed = reasons.get(DROP_MISDIRECTED_LISTED)
    if isinstance(listed, int) and listed:
        hosts = _named_hosts(per_host.get(DROP_MISDIRECTED_LISTED))
        where = f" ({hosts})" if hosts else ""
        out.append(
            f"{listed} request(s) reused one session across two allowlisted "
            f"names{where} and were refused (421) — ordinary connection "
            f"coalescing, retried by the client on a connection of its own. "
            f"Benign unless that pairing is a surprise")
    return out


def _not_http_fragments(status) -> list[str]:
    """Hosts that turned out not to speak HTTP, split by whether policy named them.

    This is the operator's splice list and the only place it exists: whether a
    host speaks HTTP over 443 is not knowable from the file, only from a
    connection, which is why it is a runtime report and not a validation rule.

    The split is the whole value. Plain `not HTTP` is one line from working --
    give the host a [[vm.network.splice]] entry and it is spliced by name. A
    host a [[vm.network.policy]] entry names is two lines, and the second is a
    DELETION: `validate` refuses a host that is in both `splice` and `policy`,
    so the entry whose methods and paths can never run has to go with it. That
    second case is surfaced harder because the config states an intention the
    wire has already contradicted, and nothing at startup could have said so.
    """
    per_host = status.get("per_host") or {}
    totals = status.get("per_host_totals") or {}
    out = []
    plain = totals.get(DROP_NOT_HTTP)
    if isinstance(plain, int) and plain:
        # Guarded the way _binding_fragments guards its own, and for the reason
        # that half already knew: a total with no map behind it renders `()`,
        # an empty parenthesis where the operator is looking for the host. It
        # takes a document whose two halves disagree to get here, so the honest
        # thing is the sentence without the list rather than a blank where the
        # list was promised.
        where = f" ({hosts})" if (hosts := _named_hosts(
            per_host.get(DROP_NOT_HTTP))) else ""
        out.append(
            f"{plain} connection(s) were closed because the host did not speak "
            f"HTTP{where} — if that is what those hosts really are, each "
            f"needs a [[vm.network.splice]] entry to pass through inspected by "
            f"name instead")
    governed = totals.get(DROP_NOT_HTTP_POLICY)
    if isinstance(governed, int) and governed:
        where = f" ({hosts})" if (hosts := _named_hosts(
            per_host.get(DROP_NOT_HTTP_POLICY))) else ""
        out.append(
            f"{governed} connection(s) were closed for not speaking HTTP on "
            f"hosts a [[vm.network.policy]] entry names{where} — those "
            f"method and path rules CAN NEVER RUN. Splicing such a host means "
            f"deleting its policy entry too: a host in both `splice` and "
            f"`policy` is a validate error")
    return out


def _uses_inspect(config) -> bool:
    """Is this workload's egress redirected into an inspector, either substrate?

    D2 makes `Substrate.vm_uses_inspect()` the primitive, but the checks here are
    pure functions of a config and take no manager, and get_substrate() needs
    one. This dispatches on `config.is_vm` -- which is the ONLY thing
    get_substrate() itself dispatches on -- so the two cannot disagree, and
    the alternative (threading a manager through every check and every test
    that calls one directly) would buy nothing.
    """
    return (vm_uses_inspect(config.config) if config.is_vm
            else container_uses_inspect(config.config))


def inspect_check(config, *, elements4=PROBE, elements6=PROBE,
                     socket_active=PROBE, v6_route=PROBE, self_dials=PROBE,
                     status=PROBE, filter_sets=PROBE, disk_digest=PROBE,
                     disk_ca=PROBE) -> tuple[str, bool, str] | None:
    """Report whether a workload's egress is really redirected to its inspector.

    Returns None for workloads the redirect does not apply to (bridged, or
    unfiltered egress), so no line is emitted. NOT gated on is_vm: G7 hoisted
    the call out of the VM block because a filtered container gets the same
    inspect socket from the same generator and the same two uid-keyed maps.

    Inspection is default-on for every filtered workload, which is what makes its
    absence hard to see: unlike the hostname proxy it replaced, nothing in the
    config asked for it, so there is no declaration for an operator to compare
    reality against. A guest whose uid is missing from the inspect maps reaches the
    internet directly, at full speed, with the unit active, `status` green, and
    `vm_egress` reporting the VM correctly filtered — because it *is* filtered.
    It is simply not being looked at. That is the failure this exists for, and
    no other line in `diagnose` would notice it.

    The socket is checked separately from the maps because the two fail in
    opposite directions and an operator reading one symptom must not be sent
    after the other. Maps missing: traffic leaves uninspected and nothing
    breaks. Socket down with the maps armed: traffic is redirected at a host
    address where nothing accepts, so the guest's HTTP and HTTPS die while its
    DNS, SSH and everything else keep working — which reads as a broken guest,
    not a broken host.

    Observations are injectable (PROBE sentinel) so the verdict logic is
    testable without a live host.
    """
    # Routed for both substrates. The surface below --
    # workload-<name>-inspect.socket and the shared nft proxy maps -- exists
    # for a container as well as a VM: the
    # generator emits the container's socket from the very same
    # generate_inspect_socket(), the maps are the same two shared maps
    # keyed by the same uid, and the remedy is byte-for-byte the same unit
    # name. A justification that expires is worse than none, because nothing
    # re-reads it -- and the cost of leaving it stood is in the §7 table: a
    # container whose inspect socket is down gets NO line here, and its
    # symptom (DNS and everything else fine, HTTP and HTTPS dead) reads as a
    # broken workload rather than a broken host.
    if not _uses_inspect(config):
        return None
    try:
        uid = config.uid
    except Exception:
        return None                      # no user yet; check 1 reports it

    # Substrate-aware nouns (G7). Every check below is the same check on both
    # substrates -- same two shared maps, same accept sets, same socket unit,
    # same remedy -- so only the noun differs, and it has to: a container
    # operator told to go look at "this guest" is being sent after a VM.
    noun = "VM" if config.is_vm else "container"
    inside = "guest" if config.is_vm else "container"
    section = "vm.network" if config.is_vm else "network"
    net = (config.config.get("vm", {}).get("network", {}) if config.is_vm
           else config.config.get("network", {}))
    if not isinstance(net, dict):
        net = {}

    unit = f"workload-{config.name}-inspect.socket"
    restart = f"systemctl restart {unit}"

    if elements4 is PROBE:
        elements4 = _inspect_map_elements(NFT_MAP_INSPECT4)
    if elements6 is PROBE:
        elements6 = _inspect_map_elements(NFT_MAP_INSPECT6)

    if elements4 is None or elements6 is None:
        return ("vm_inspect", False,
                f"egress inspection is on for this {noun} but the "
                f"{NFT_PROXY_TABLE} table is absent, so nothing redirects this "
                f"{inside}'s traffic to its inspector — it is reaching the "
                f"internet directly. Rebuilt on the next start: {restart}")

    armed4 = str(uid) in {_map_key_uid(e) for e in elements4}
    armed6 = str(uid) in {_map_key_uid(e) for e in elements6}

    if not armed4 and not armed6:
        return ("vm_inspect", False,
                f"egress inspection is on for this {noun} but uid {uid} is in "
                f"neither {NFT_MAP_INSPECT4} nor {NFT_MAP_INSPECT6}, so its "
                f"traffic to ports {CLEARTEXT.guest_port}/{TLS.guest_port} "
                f"is not redirected — this "
                f"{inside} is reaching the internet uninspected while every other "
                f"signal reads correct. Re-arm it: {restart}")

    if armed4 != armed6:
        # Half-armed is worse than not armed, because the half that works is
        # what an operator checks. A v4 probe passes, the journal fills with
        # lines, and the guest's v6 traffic leaves unseen the whole time.
        missing, present = ((NFT_MAP_INSPECT6, NFT_MAP_INSPECT4) if armed4
                            else (NFT_MAP_INSPECT4, NFT_MAP_INSPECT6))
        family = "IPv6" if armed4 else "IPv4"
        return ("vm_inspect", False,
                f"uid {uid} is in {present} but not {missing}, so this {inside}'s "
                f"{family} egress is NOT inspected while its other family is. "
                f"A probe on the armed family passes and shows nothing wrong. "
                f"Re-arm both: {restart}")

    if filter_sets is PROBE:
        filter_sets = _inspect_filter_sets(uid)

    # The accept sets, checked BEFORE the socket. Their failure and the
    # socket's are the same symptom from inside the guest -- HTTP and HTTPS
    # die, DNS and SSH keep working -- so an operator handed the socket
    # sentence for a missing accept element restarts a unit that was already
    # listening and watches nothing change.
    #
    # None (unreadable) is not missing: the table's absence is already the
    # first branch of this check, so a None here means one `nft list set`
    # failed on a table that answered a moment ago, and inventing a failure out
    # of that would fire on a host under an nft upgrade.
    missing_accept = [name for name in INSPECT_ACCEPT_SETS
                      if filter_sets.get(name) is False]
    if missing_accept:
        return ("vm_inspect", False,
                f"uid {uid} is redirected to the inspector but is missing from "
                f"{' and '.join(missing_accept)}, so the redirected connection "
                f"is rewritten to the listener and then DROPPED by the default "
                f"deny — inside the {inside} this looks exactly like the "
                f"inspector being down, and the socket is fine. Re-arm both "
                f"tables: {restart}")

    if socket_active is PROBE:
        # Unpack, exactly as capture_check has to: service_active returns
        # (active, state) and a bare tuple is always truthy, so the arm below
        # never fired on a live host -- an inspect socket that was down was
        # reported as listening. The injected-argument tests pass a bool and
        # skip this line, which is why the same defect reached two checks.
        socket_active, _ = service_active(unit)

    if not socket_active:
        return ("vm_inspect", False,
                f"uid {uid} is redirected to the inspector, but {unit} is not "
                f"listening — this {inside}'s HTTP and HTTPS are being sent to a "
                f"host address where nothing accepts, while its DNS and SSH "
                f"keep working. Start it: {restart}")

    # THE LISTENER'S LOADED POLICY vs. THE ONE ON DISK -- rung 5 T4.
    #
    # A different question from `workloadctl drift`, which compares the
    # document on disk against a re-render from the TOML. That is disk vs.
    # intent; this is memory vs. disk, and the two have no overlap: both sides
    # of the drift comparison match while this one fails.
    #
    # It is reachable through THIS COMMAND'S OWN REMEDY. Every re-arm branch
    # above ends in `systemctl restart <name>-inspect.socket`; that socket's
    # ExecStartPre is `workload-vm-inspect up`, which rewrites the policy
    # document -- and the listener is PartOf= the VM, not of the socket, so it
    # is not stopped and keeps enforcing what it read at its own start. An
    # operator who follows the instruction printed here to fix a missing
    # element lands in exactly this state, with every other signal green.
    #
    # Silence, not a warning, in all three unknown cases: no status file (a
    # socket-activated inspector a guest has never dialled), no digest key (a
    # listener from before this rung), or an unreadable document (T3's report,
    # not this one). A diagnostic must not manufacture a failure out of a
    # missing diagnostic.
    if status is PROBE:
        status = read_inspect_status(config.name)
    running_digest = (status or {}).get(INSPECT_DIGEST_KEY)
    if running_digest:
        if disk_digest is PROBE:
            disk_digest = _policy_digest_on_disk(config.name)
        if disk_digest and disk_digest != running_digest:
            # DIFFERENT, not "older". Inequality is the whole of what this
            # comparison establishes, and the usual cause does put the newer
            # document on disk -- but a state restore under a running listener,
            # which is the very scenario the CA check below is written for,
            # puts the older one there instead. The remedy is the same either
            # way; naming a direction the check cannot see would send an
            # operator looking for a config edit that never happened.
            return ("vm_inspect", False,
                    f"the running inspector is enforcing a DIFFERENT policy "
                    f"than the one on disk (loaded "
                    f"{inspect_digest_short(running_digest)}, on disk "
                    f"{inspect_digest_short(disk_digest)}) — the lists in "
                    f"force are not the lists in the file, in one direction or "
                    f"the other. Restarting the socket does NOT fix this: the "
                    f"listener stops with the {noun}, not with the socket. "
                    f"Restart the {noun}: "
                    f"systemctl restart workload-{config.name}.service")

    # THE CA THE LISTENER MINTS WITH vs. THE ONE ON DISK -- rung 5 T7, and the
    # same memory-vs-disk shape as the policy comparison above.
    #
    # ADR 008 decision 4 says the CA does not rotate, and Minter.ca_identity
    # reads it once and remembers it, so under a running listener the two can
    # only diverge by something outside the design touching the file.
    # Generational rollback is that something: the CA lives in the state tree,
    # so restoring a system.qcow2.gen-N can put an older CA under a listener
    # still minting from the newer one. Every leaf then chains to an anchor the
    # guest does not trust, which reaches the operator as nothing at all -- the
    # failure is inside the guest, in a TLS library, on a host where every line
    # of this command passes.
    running_ca = _ca_report(status).get("sha256")
    if running_ca:
        if disk_ca is PROBE:
            disk_ca = _ca_fingerprint_on_disk(config.name)
        if disk_ca and disk_ca != running_ca:
            return ("vm_inspect", False,
                    f"the running inspector is minting with a DIFFERENT CA "
                    f"than the one on disk (minting with "
                    f"{_short_fingerprint(running_ca)}, on disk "
                    f"{_short_fingerprint(disk_ca)}) — every certificate this "
                    f"{inside} is being "
                    f"handed chains to an anchor it does not trust, so its "
                    f"HTTPS is failing validation inside the {inside} while "
                    f"every line here passes. The state tree was restored "
                    f"under a running listener; restart the {noun}: "
                    f"systemctl restart workload-{config.name}.service")

    addr = inspect_address(uid)
    tail = ""
    if v6_route is PROBE:
        v6_route = _host_has_v6_route()
    if not v6_route:
        # Not a fault, and deliberately not a failure: a correctly armed v6
        # redirect produces no journal lines on a host with no IPv6 uplink,
        # because a locally re-originated packet loses its routing lookup
        # before it ever reaches the nat hook. Said here because the silence is
        # otherwise read as the v6 redirect being broken -- it cost a debugging
        # session on the rig that way.
        tail = ("; note this host has no IPv6 default route, so the v6 "
                f"redirect will log nothing — the {inside}'s v6 connections "
                "fail "
                "at the routing lookup, before nftables sees them")

    # The wrong-port self-dial counter, per workload and armed per workload,
    # which is what separates it from every other counter this command reports.
    # A guest that dials its own listener address on a port the inspector does
    # not serve is dropped by the self guard -- and inside the guest that is a
    # hang, not an error, with `status` green and every other line here
    # passing. Under a synthesising resolver it is the signature of a guest
    # handed a synthetic answer for a service on a non-80/443 port
    # (`git.local:2222`, `registry.local:5000`), which is an operator one
    # `allow` line from a working config with nothing telling them so.
    #
    # Reported only when non-zero. Zero is the healthy reading and says
    # nothing an operator can act on, unlike the conntrack figure above, where
    # the number itself is the answer to "why do transfers die part-way".
    # The wrong-port sets, reported differently from the accept sets above and
    # the difference is the whole reason they are two branches: nothing the
    # guest does breaks when one of these is missing. What is lost is the
    # counter's per-workload attribution -- the drop rule is in the skeleton
    # either way, so the packets still die, and the figure the next paragraph
    # reads simply never moves for this uid. A zero that means "never armed"
    # and a zero that means "never happened" are the same zero, which is what
    # this fragment exists to separate.
    missing_self = [name for name in INSPECT_SELF_SETS
                    if filter_sets.get(name) is False]
    if missing_self:
        tail += (f"; uid {uid} is missing from "
                 f"{' and '.join(missing_self)}, so this {inside}'s wrong-port "
                 f"self-dials are still dropped but are not counted against it "
                 f"— the figure below reads 0 whether or not any happened. "
                 f"Re-arm: {restart}")

    # The third verdict, and the loudest: not a broken guest and not a lost
    # statistic, but this workload's inspector standing open to every other
    # local uid on the host. Nothing else reports it -- the guest's traffic is
    # fine, the counters reconcile, and the only visible trace is other
    # workloads' requests appearing in THIS workload's egress records, where
    # they read as its own.
    missing_guard = [name for name in INSPECT_GUARD_SETS
                     if filter_sets.get(name) is False]
    if missing_guard:
        tail += (f"; this {inside}'s inspector address is missing from "
                 f"{' and '.join(missing_guard)}, so any other local uid can "
                 f"reach its listener and its dials land in this workload's "
                 f"egress records. Re-arm: {restart}")

    if self_dials is PROBE:
        self_dials = _inspect_self_counter(uid)
    if self_dials and self_dials[0]:
        tail += (f"; {self_dials[0]} packet(s) dropped dialling this {inside}'s "
                 f"own listener on a port nothing serves — if the {inside} "
                 f"expects a service there, it needs a [{section}].allow "
                 f"entry for the real address, not the listener's")

    # The two figures rung 4's policy work landed (the name-to-Host binding
    # rejections, and the hosts that turned out not to speak HTTP), read out of
    # the inspector's own status document.
    #
    # STILL A PASSING LINE, however loud the wording. Every one of these
    # refusals is the inspector working: the request was refused, the guest was
    # told, and nothing about this workload's configuration is broken by a
    # guest behaving badly. A red line here would send an operator hunting for
    # a setting to change, and in the binding case there is none -- the setting
    # already worked. What the line owes them is the sentence, not a verdict.
    #
    # Only these two figures, and not a general rendering of the document: the
    # rest of it (minting rate, clock resyncs, the CA fingerprint, the DNS
    # counters in the responder's file beside it) gains its reader with
    # `doctor`'s aggregation and the exporter surface, where one producer and
    # no second definition of any figure is the property being built. These two
    # land with the policy they measure because their whole value is an
    # operator's next move, and a figure nothing prints is a figure nobody has.
    # Already resolved above, by the loaded-policy comparison -- which reads
    # the same document and must run before any of the tail, because it can
    # return a verdict.
    # Independent of `status`, unlike the three above: this reads the bundle,
    # and the answer it gives is most needed exactly when the inspector has
    # produced no document yet -- an operator watching a guest get 401s from a
    # provider it is sure it configured.
    for fragment in _credential_fragments(config):
        tail += f"; {fragment}"

    if status:
        for fragment in (_binding_fragments(status)
                         + _caller_identity_fragments(status)
                         + _not_http_fragments(status)
                         + _credential_usage_fragments(status)
                         + _ca_fragments(status)):
            tail += f"; {fragment}"

    # The TLS mode is named because the two are different security postures
    # with the same green line: `inspect` authorises every request and holds
    # the plaintext, `splice` checks one name per connection and holds nothing.
    # An operator reading "inspected" and getting the other one is the whole
    # reason this word is here.
    # The two substrates DEFAULT DIFFERENTLY, which is why this cannot be one
    # `net.get("tls", ...)`. A VM with no `tls` key inspects (TLS_DEFAULT);
    # a container with no `tls` key splices unless it has policy entries, per
    # container_effective_tls_mode(). Reading the key directly with the VM
    # default would tell a container operator their plaintext is being held
    # when it is not -- the exact misreport G5 and G8 stayed VM-only to avoid,
    # and the reason this line calls the container helper instead.
    if config.is_vm:
        tls_mode = net.get("tls", TLS_DEFAULT)
    else:
        tls_mode = container_effective_tls_mode(net)
    posture = "terminating" if tls_mode == "inspect" else "splicing"
    return ("vm_inspect", True,
            f"egress inspected on both families: uid {uid} redirected to "
            f"{addr.v4}/[{addr.v6}] ports {CLEARTEXT.inspect_port} "
            f"({CLEARTEXT.label}) and {TLS.inspect_port} "
            f"({TLS.label}, {posture}), "
            f"{unit} listening{tail}")


def _inspect_self_counter(uid):
    """(packets, bytes) of this uid's wrong-port self-dial drops, or None.

    Sums the two families, because the guest chose one of them and which one
    is not the operator's question -- a v6-only client and a v4-only client
    dialling the same wrong port are the same mistake, and reporting them on
    separate lines would ask the reader to add up two numbers to learn one
    thing. None only when neither family's element could be read at all.
    """
    total = None
    for set_name in (NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6):
        payload = nft_json("list", "set", *NFT_TABLE.split(), set_name)
        if payload is None:
            continue
        counter = nft_element_counter(payload, uid)
        if counter is None:
            continue
        total = (0, 0) if total is None else total
        total = (total[0] + counter[0], total[1] + counter[1])
    return total


def _inspect_map_elements(map_name):
    """Elements of one inspect map, or None if the table could not be read."""
    payload = nft_json("list", "map", *NFT_PROXY_TABLE.split(), map_name)
    return None if payload is None else nft_set_elements(payload)


# The four objects inspect_element_commands arms in the FILTER table, which
# nothing here read until rung 5. The two DNAT maps above are only half of the
# six: the accept sets hold the DNAT-rewritten tuple the filter chain sees, and
# without one the redirect still happens and the redirected connection is then
# dropped by the default deny. inspect_element_commands' own docstring names
# that state -- "the redirect without the accept set drops the redirected
# connection" -- and before this it rendered as `egress inspected on both
# families`, green, on a guest whose web traffic was dying.
INSPECT_ACCEPT_SETS = (NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6)
INSPECT_SELF_SETS = (NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6)
# The cross-workload guard's sets, a third kind with a third verdict. A missing
# element here breaks nothing this guest does and costs no statistic: it leaves
# this workload's inspector REACHABLE BY EVERY OTHER LOCAL UID, silently, on a
# workload that otherwise reads healthy end to end. That is the one of the
# three an operator most needs told, and the one with no other signal at all.
#
# Keyed on the address, not the uid: these sets hold a bare inspector address
# so the guard can match a dial from a DIFFERENT uid, which is why they cannot
# be read with owned_elements like the four above.
INSPECT_GUARD_SETS = (NFT_SET_INSPECT_LIVE, NFT_SET_INSPECT_LIVE6)


def _inspect_filter_sets(uid: int) -> dict:
    """Which of the inspector's filter-table sets carry this uid.

    `{set_name: True | False | None}` -- armed, absent, or unreadable. One
    observation covering all four rather than four PROBE parameters: they are
    read in one pass and reported as one sentence, and four more injectables
    would make this the widest signature in the file for no gain.

    Membership by UID, not by comparing against inspect_dst_elements()'s
    exact strings. An exact comparison would be stricter and would also fire on
    any nft version that renders a concatenation differently -- which is not
    hypothetical here: see _map_key_uid, where exactly that mismatch reported a
    working proxy redirect as missing on every host.

    ONE `nft list table`, not four `nft list set`. This runs on the healthy
    path of every inspected VM, and `doctor` multiplies it by the number of
    workloads on the host, so four execs each was four times the cost of the
    same answer. The table document carries every set with its elements, and
    the two states the caller distinguishes survive the change: a set the
    document does not contain at all stays None -- unreadable, and therefore
    silence -- exactly as a failed `list set` did, because a set object that is
    not there is a different fault from a uid missing out of one that is.
    """
    payload = nft_json("list", "table", *NFT_TABLE.split())
    out = {}
    # Unwrapped first: the self sets carry `counter`, so nft renders their
    # elements wrapped and owned_elements -- which matches the bare shape, the
    # shape a delete value takes -- finds nothing in them. Reading them raw
    # reports both self sets missing on every filtered workload, which both
    # hides a genuinely unarmed element and contradicts the counter the next
    # paragraph prints from those same elements.
    for set_name in INSPECT_ACCEPT_SETS + INSPECT_SELF_SETS:
        found, elements = _named_set_elements(payload, set_name)
        out[set_name] = (bool(owned_elements(
            uid, unwrap_counted_elements(elements))) if found else None)
    # The guard sets by address. owned_elements asks "does any element name
    # this uid", and these elements name no uid at all -- run over them it
    # returns empty for a correctly armed workload, i.e. it would report the
    # guard missing on every host.
    addr = inspect_address(uid)
    for set_name, want in zip(INSPECT_GUARD_SETS, (str(addr.v4), str(addr.v6))):
        found, elements = _named_set_elements(payload, set_name)
        out[set_name] = (any(want == e or want in str(e) for e in elements)
                         if found else None)
    return out


def _named_set_elements(payload, name: str) -> tuple[bool, list]:
    """`(found, elements)` for one named set or map in a `list table` document.

    Not nft_set_elements, which answers the different question a `list set`
    document asks: it returns the FIRST set it finds, because there is only one
    there. Handed a whole table it would return whichever set nft happened to
    print first, for every name asked -- so all four names would report the
    membership of one of them, and three of the four checks would be reading
    someone else's answer.
    """
    for item in (payload or {}).get("nftables", []):
        if not isinstance(item, dict):
            continue
        for kind in ("set", "map"):
            obj = item.get(kind)
            if isinstance(obj, dict) and obj.get("name") == name:
                return True, obj.get("elem", []) or []
    return False, []


def _short_fingerprint(fingerprint: str | None) -> str:
    """A certificate fingerprint as it is shown to a person.

    The same amount of digest INSPECT_DIGEST_SHORT shows for a policy, cut
    on a byte boundary rather than mid-pair: pem_fingerprint returns 95
    characters of colon-separated uppercase hex, and two of those in one
    sentence is a three-hundred-character line an operator scrolls past. There
    is one notion of "how much of a digest is enough to tell two apart by eye"
    in this module and this is the certificate spelling of it.
    """
    if not fingerprint:
        return "unknown"
    groups = fingerprint.split(":")
    keep = INSPECT_DIGEST_SHORT // 2
    if len(groups) <= keep:
        return fingerprint
    return ":".join(groups[:keep]) + ":…"


def _ca_report(status) -> dict:
    """The inspector's CA block out of its status document, or `{}`.

    THE ONE READER of that path, and it is defensive at every level on
    purpose. `read_inspect_status` guarantees only that the top level is a dict;
    a truthy non-dict under `mint` or `ca` -- which only a bug in the writer
    produces, but a bug in the writer is exactly when this command is run --
    would otherwise raise an AttributeError out of inspect_check, and
    nothing wraps that call. Twenty other checks would not run, over a figure
    that is a footnote.
    """
    mint = (status or {}).get("mint")
    ca = mint.get("ca") if isinstance(mint, dict) else None
    return ca if isinstance(ca, dict) else {}


def _ca_fingerprint_on_disk(name: str) -> str | None:
    """The fingerprint of this workload's CA as it currently sits on disk.

    egress_mint.pem_fingerprint, which is why that name lost its underscore: the
    running listener's copy of this figure comes from the same function through
    Minter.ca_identity(), and the two are compared for equality. A second
    implementation of "the fingerprint of a PEM" -- a different digest, a
    different hex case, a different separator -- would report a mismatch on
    every workload forever.

    STDLIB, no subprocess: the fingerprint is a hash of the DER and the DER is
    the base64 between the PEM markers. `pem_not_after` is the one that shells
    out to openssl, and this command deliberately does not call it (see
    _ca_fragments) -- the expiry it reports is the one the MINTER read.

    ValueError AS WELL AS OSError, and that is not belt-and-braces. A PEM is
    read as TEXT, at the locale's encoding, so a byte outside it raises
    UnicodeDecodeError -- a ValueError, which pem_fingerprint's own `except
    OSError` does not catch either. Nothing wraps inspect_check, so that
    escapes the whole command and the twenty checks after this one never run.
    The state it fires on is exactly the one this comparison exists for: a CA
    file that a restore left truncated or garbage under a running listener.
    A diagnostic must not die of the fault it was written to report.
    """
    try:
        return pem_fingerprint(ca_cert_path(workload_state_dir(name)))
    except (OSError, ValueError):
        return None


def _credential_fragments(config) -> list[str]:
    """What the credential-backed hosts oblige an operator to know.

    ONE SENTENCE, and it is about the seed rather than about the broker.
    Everything else here is derivable from something this command already
    prints or from `workloadctl validate`; this is not, because the fact it
    states is a difference between the file on disk and a guest that is
    already running.

    The placeholder is seeded by cloud-init, cloud-init runs once per
    instance-id, and the instance-id rotates only when the seed is rebuilt. So
    editing `placeholder` in the TOML changes what the broker expects to
    discard and does NOT change what the guest sends, and the guest's requests
    keep working -- the broker replaces whatever arrives. What breaks is the
    reverse edit an operator makes next, and the third occurrence of this same
    shape (the egress mode and the retired broker endpoint were the first
    two) is worth
    one line here rather than an evening.
    """
    entries = vm_broker_hosts(config.config)
    if not entries:
        return []
    hosts = ", ".join(sorted({host for host, _cred in entries}))
    return [f"credential-backed via this workload's own broker: {hosts} — the "
            f"guest holds a PLACEHOLDER for each, seeded by cloud-init at "
            f"provision time. Editing a `placeholder` in workload.toml does "
            f"not reach a running guest: cloud-init runs once per instance-id, "
            f"so it takes a re-provision"]


def _ca_fragments(status) -> list[str]:
    """What the inspector's CA report says that an operator can act on.

    NOT a rendering of the CA. The fingerprint's routine reader is `doctor`'s
    aggregation and the exporter surface, where one producer per figure is the
    property being built; here it appears only when it is the answer to
    something -- which is the expiry, inside the window
    CA_VALIDITY_DAYS' own comment already promised.

    The expiry is read out of the status document rather than off the disk, and
    that is a deliberate limit as well as a saving. The saving: pem_not_after
    shells out to openssl, so reading it here would put a subprocess and a new
    file read into this command's SELinux domain for a figure another process
    has already read. The limit: a workload whose minter has never run -- a
    `splice` workload, which has no CA in play at all, or an `inspect` one
    whose guest has not yet dialled anything -- reports nothing here. Both are
    silent for the reason every other unknown in this check is silent, and the
    second resolves itself the moment the VM does any work.
    """
    not_after = _ca_report(status).get("not_after")
    if not isinstance(not_after, (int, float)):
        return []
    remaining = (not_after - time.time()) / 86400
    if remaining > CA_EXPIRY_WARN_DAYS:
        return []
    when = time.strftime("%Y-%m-%d", time.gmtime(not_after))
    if remaining <= 0:
        return [f"this workload's egress CA EXPIRED on {when} — every HTTPS "
                f"request from this guest is now failing certificate "
                f"validation inside the guest, which no line here can see. "
                f"The CA cannot be replaced in place: cloud-init runs once per "
                f"instance-id, so the guest must be re-provisioned"]
    return [f"this workload's egress CA expires on {when} "
            f"({int(remaining)} day(s)) — replacing it means RE-PROVISIONING "
            f"the guest, because the anchor is seeded by cloud-init and "
            f"cloud-init runs once per instance-id. Schedule that before the "
            f"date, not after it"]


def _policy_digest_on_disk(name: str) -> str | None:
    """The digest of the policy document as it currently sits on disk.

    None when the document cannot be read, and the caller treats that as
    silence rather than as drift: an absent document is already T3's report
    (`workloadctl drift`), and a second line about it here would send an
    operator to the same fix twice.

    ValueError for the reason _ca_fingerprint_on_disk gives: the document is
    read as text and a byte the locale's codec rejects is a UnicodeDecodeError,
    which is a ValueError and not an OSError. The document is pure ASCII by
    construction -- vm_inspect_policy_text goes through json.dumps, whose
    ensure_ascii defaults true, which is also what makes this digest
    comparable across a systemd-launched listener and an operator's shell --
    so reaching this needs the file itself to have been damaged. That is a
    state somebody runs `diagnose` in.
    """
    try:
        with open(inspect_policy_path(name)) as fh:
            return inspect_policy_digest(fh.read())
    except (OSError, ValueError):
        return None
