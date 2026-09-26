#!/usr/bin/env python3
"""The broker instance's command line, and the predicates that decide it.

One per declaring workload, per ADR 007. This is the generator side: which
workloads get an instance, what it is told, and the argv the unit's
ExecStart= carries. What customs-broker makes of those flags at startup is
customs'. A writer and a reader that each spell the flags drift, and a flag
emitted here and not taken there is a broker that refuses to start, so
tests/test_customs_seam.py pins the command against the program's parser.

IT WAS A DOCUMENT. broker_command replaces render_broker_config, which
rendered a broker.toml that write_instance_config -- the unit's ExecStartPre,
as its DynamicUser, into its RuntimeDirectory -- wrote at every start. Every
value in that file was a pure function of the workload TOML and the uid,
which is exactly what this module holds when the unit is generated, so the
file was a second rendering of facts the ExecStart= line carries itself.
What it cost: a TOML reader in the broker, a key vocabulary at each level
for the two to agree on, a writer, a helper binary, an ExecStartPre and a
RuntimeDirectory=. What it bought, it did not: "never serving a previous
boot's credential set" is LoadCredentialEncrypted='s property, and the
file held no material.

`VmCredential` and its parse live here rather than with the rest of
`[vm.network]` because every field on a credential decides something about the
broker instance and nothing else. `validate_vm_network` reads them from the
rung above, which is the direction that works.

Installed to /usr/libexec/workloadctl/broker_config.py.
"""

import ipaddress
import socket
from pathlib import Path
from typing import NamedTuple

from container_network_config import (
    container_credential_entries,
    container_policy_entries,
    container_uses_inspect,
)
from credential_entries import parse_credential_entries
from workload_addr import (IP_BIN, ADVERTISED_IFACE, BROKER_INSTANCE_PORT,
                           broker_listen_address, inspect_address)
from egress_policy import vm_uses_inspect
from secrets_template import credential_path, CREDSTORE_DIR
from egress_policy import vm_policy_entries


# The program the generated unit runs, customs': one instance per workload,
# generated; there is no host-wide unit for an operator to enable.
BROKER_BIN = "/usr/libexec/customs/customs-broker"


# --- The credential table, and the blocks that name one ---
#
# The type and its parse live here rather than beside the rest of `[vm.network]`
# because a credential is a property of the broker instance and of nothing else:
# every field on it decides what material that instance loads, what the guest is
# seeded with instead, and how the header is spelled. `validate_vm_network`
# reads them from a rung above, which is the right direction; the renderer
# reading them from a rung above would have been the cycle.

class VmCredential(NamedTuple):
    """One [[vm.network.credential]] block, normalised.

    `placeholder` and `env` are properties OF THE CREDENTIAL, not of the policy
    entry that selects it, and that is the whole reason this table exists rather
    than two more keys on the entry. Stated on the entry, each would need an
    "entries naming the same credential must agree" rule, and there would be two
    of them; stated here, each is stated once and the rule is unwritable.

    `name` is the credstore name, and `env` is the guest variable the placeholder
    is seeded into. They are separate keys on purpose: collapsing them would bind
    the sealed material's path to a provider-owned string, so a provider renaming
    its variable would force a re-seal.

    `auth_header` and `auth_format` are the provider's HTTP convention, and they
    are here rather than on the policy entry for the same reason: a credential
    is minted for one provider, and docs/agent-broker.md §10 documents them
    per provider beside the key. Both are OPTIONAL and default to
    the broker's own (`x-api-key`, `{secret}`), which is the Anthropic
    convention -- so a workload that says nothing gets exactly what it got
    before these keys existed.

    THEY EXIST BECAUSE THE GENERATOR DROPPED THEM. ADR 007 names the profile as
    `(upstream, credential, auth_header, auth_format)` and lists "one profile
    per sandbox" as the limit this rung removes; the first render emitted the
    first two and defaulted the rest, so every workload got `x-api-key` and any
    provider wanting `Authorization: Bearer` answered 401 on a request this
    layer considered fully authorised. The hand-written host-wide config could
    express it and the generated one could not, which made the new shape a
    regression for a whole class of provider with no key to fix it with.

    NOTHING HERE TRAVELS ON THE WIRE AS A SELECTOR. The inspector sends no name
    and no credential hint; the broker's whole dispatch key is (uid, Host), per
    ADR 007 decision 9. These fields decide which material a generated broker
    instance loads, what the guest is seeded with, and how the broker spells the
    header it attaches -- and nothing else.
    """

    name: str
    placeholder: str
    env: str
    auth_header: str | None = None
    auth_format: str | None = None


def vm_credential_entries(net: dict) -> list[VmCredential]:
    """The [[vm.network.credential]] blocks, normalised, in file order.

    Shape-tolerant for the reason vm_policy_entries is: validate_vm_network owns
    the shape and the boot generator skips a workload that does not validate.
    """
    return parse_credential_entries(net, VmCredential)


def vm_uses_credentials(config: dict) -> bool:
    """Whether this workload gets a broker instance of its own.

    Inspection AND at least one declared credential. The first half is not
    redundant: the inspector is the ONLY thing that dials the broker now (the
    advertised endpoint is gone), so an instance for a bridged or unfiltered VM
    would hold decrypted provider keys for a path that does not exist.
    validate_vm_network refuses that combination, and this predicate is what
    keeps the boot generator -- which renders whatever validates -- from
    rendering the unit anyway.

    It is also the `present=` of the run-file, so it decides what `remove`
    unlinks and what `drift` compares. A workload that drops its last
    credential therefore has its instance unlinked rather than left behind
    holding material nothing selects.
    """
    # The VM half. container_uses_credentials below is the container one, and
    # the two are deliberately identical: one mechanism on both substrates.
    if not vm_uses_inspect(config):
        return False
    net = (config.get("vm", {}) or {}).get("network", {}) or {}
    if not isinstance(net, dict):
        return False
    return bool(vm_credential_entries(net))


def broker_credential(name: str, credential: str) -> tuple[Path, str]:
    """(ciphertext path, systemd credential id) for one workload's material.

    Asked of secrets_template rather than spelled here, because the id is the
    SEAL NAME and the seal name is not decorative: systemd-creds binds it into the
    blob and verifies it on decrypt, so a generated unit that loaded another
    workload's file -- given the path, which is guessable -- gets a decryption
    failure at start instead of that workload's key. Two implementations of the
    rule would be one refactor away from a unit that loads nothing, or worse,
    one that loads the wrong thing under a name the config still matches.

    The id is also what the broker looks the credential up by: systemd writes
    each into $CREDENTIALS_DIRECTORY under exactly this name, and
    broker_command writes the same string after the `=` of each `--host`.
    """
    path, seal = credential_path(Path(CREDSTORE_DIR), f"broker/{name}/{credential}")
    return path, seal


def vm_credential_env(config: dict) -> dict[str, str]:
    """{guest variable: placeholder} for every credential this workload declares.

    What the guest is given INSTEAD of a key. The broker discards whatever
    arrives in the auth header and sets the real one, so the placeholder never
    has to be plausible to anything but the guest's own client library -- which
    is exactly why it must be present: an SDK that refuses to send a request
    without a key fails inside the guest, before a packet, which looks nothing
    like a policy failure.

    Seeded ONCE per instance, by cloud-init, like every other guest env var
    here. Changing a `placeholder` in the TOML therefore does not reach a
    running guest; `diagnose` says so.
    """
    net = (config.get("vm", {}) or {}).get("network", {}) or {}
    if not isinstance(net, dict):
        return {}
    return {c.env: c.placeholder for c in vm_credential_entries(net)}


def vm_broker_hosts(config: dict) -> list[tuple[str, str]]:
    """(Host, credential name) for every credential-backed policy entry.

    In file order, and only the entries that select a credential: an entry
    without one is a host the guest reaches carrying whatever it holds, which
    is not the broker's business and must not appear in its table.
    """
    net = (config.get("vm", {}) or {}).get("network", {}) or {}
    if not isinstance(net, dict):
        return []
    return [(e.host, e.credential) for e in vm_policy_entries(net) if e.credential]


def container_broker_hosts(config: dict) -> list[tuple[str, str]]:
    """vm_broker_hosts for the container substrate. Same contract, one table
    up: a container workload's egress policy is workload-level ([network]),
    not per-container, which is what makes one broker instance per workload
    the right shape here too."""
    net = config.get("network", {}) or {}
    if not isinstance(net, dict):
        return []
    return [(e.host, e.credential)
            for e in container_policy_entries(net) if e.credential]


def container_uses_credentials(config: dict) -> bool:
    """vm_uses_credentials for containers, and identical in both halves.

    Inspection AND at least one declared credential -- the inspector is the
    only thing that dials the broker on either substrate, so an instance for
    an uninspected container would hold decrypted provider keys for a path
    that does not exist.

    Also the run-file `present=`, so a workload that drops its last
    credential has the unit unlinked rather than left behind.
    """
    if not container_uses_inspect(config):
        return False
    net = config.get("network", {}) or {}
    if not isinstance(net, dict):
        return False
    return bool(container_credential_entries(net))


def vm_broker_command(config: dict, uid: int) -> list[str]:
    """The argv for one VM workload's instance. See broker_command."""
    net = (config.get("vm", {}) or {}).get("network", {}) or {}
    return broker_command(
        config["workload"]["name"], uid, vm_broker_hosts(config),
        vm_credential_entries(net if isinstance(net, dict) else {}))


def container_broker_command(config: dict, uid: int) -> list[str]:
    """The argv for one container workload's instance.

    A call site, not a second builder. ContainerCredential and VmCredential
    are field-identical by construction, and both of the defects the VM
    render was fixed for -- the per-entry duplicate table that TOML refused,
    and the dropped auth_header/auth_format that 401s a fully authorised
    request -- would have been reproduced verbatim by a container twin,
    which is why there is not one.
    """
    net = config.get("network", {}) or {}
    return broker_command(
        config["workload"]["name"], uid, container_broker_hosts(config),
        container_credential_entries(net if isinstance(net, dict) else {}))


def broker_command(name: str, uid: int, hosts, credentials) -> list[str]:
    """The argv of one workload's instance, either substrate: the binary and
    every flag it takes, unquoted. The unit writes it with dq per value.

    Takes the (host, credential-name) pairs and the declared credential
    blocks rather than the config, so nothing here reads a [vm.] or
    [network.] key -- that is the whole of what makes it shared.

    A pure function of the workload TOML and the uid: there is nothing here
    to reconcile at start, and nothing on the line the broker could derive
    for itself. The uid is written twice, as the address it makes and as the
    caller it is, because the broker is told both and computes neither.

    The listen address is generated and never defaulted (ADR 007 decision
    6): the broker's own default was 127.0.0.1, which is where every OTHER
    workload's inspector is dialling, so an instance that fell back to it
    would serve callers it holds no material for and hand them refusals --
    or, once two instances raced for the same socket, one workload's key to
    another's request. The broker's parser requires the flag for the same
    reason.
    """
    cmd = [
        BROKER_BIN,
        "--name", name,
        "--listen", f"{broker_listen_address(uid)}:{BROKER_INSTANCE_PORT}",
        "--caller-uid", str(uid),
    ]
    # ONE FLAG PER HOST, not per policy entry. Splitting a host's rules
    # across entries -- `/v1/*` for GET, `/v2/*` for POST, one credential --
    # is the ordinary way to write §3, and it validates: the only per-host
    # credential rule refuses entries that disagree about WHICH credential.
    # Rendered per entry, the old document held one host's table twice,
    # which TOML refused outright, so the broker exited at start and every
    # brokered request 502'd on a workload whose config `validate` had just
    # called clean. The broker refuses a repeated host for the same reason
    # (the two spellings rule), so this collapse is what keeps it starting.
    #
    # Collapsing on the host is sound because a credentialed host is always a
    # literal (a wildcard selecting a credential is a validation error) and
    # two entries for one host cannot name different credentials (also one).
    seen_hosts: list[str] = []
    selected: list[str] = []
    for host, credential in hosts:
        if host in seen_hosts:
            continue
        seen_hosts.append(host)
        _path, cred_id = broker_credential(name, credential)
        # https://<host> and no path, on the broker's side: the upstream is
        # the host the policy authorised and nothing else, so the flag
        # names the host and the broker supplies the scheme and the port.
        cmd += ["--host", f"{host}={cred_id}"]
        if credential not in selected:
            selected.append(credential)
    # The per-credential facts, once per SELECTED credential rather than
    # per host: two hosts may share one, and the broker refuses a
    # credential described twice. Each is emitted ONLY when the block
    # states one. An absent flag leaves the broker's own default in force,
    # which keeps the default in one place -- writing it out here would
    # mean two copies to disagree later. A credential no host selects is
    # not described at all; the broker refuses a description with no
    # selector, and validate refuses the block.
    for credential in selected:
        cred = _credential_named(credentials, credential)
        if cred is None:
            continue
        _path, cred_id = broker_credential(name, credential)
        if cred.placeholder is not None:
            cmd += ["--placeholder", f"{cred_id}={cred.placeholder}"]
        if cred.auth_header:
            cmd += ["--auth-header", f"{cred_id}={cred.auth_header}"]
        if cred.auth_format:
            cmd += ["--auth-format", f"{cred_id}={cred.auth_format}"]
    return cmd


def _credential_named(credentials, credential: str):
    """The declared block a policy entry's `credential` selects, or None.

    Returns the whole block rather than one field: the command needs three
    of them, and three lookups walking the same list is how one of them
    comes to be looked up under a name the other two do not use.

    Takes the list, not a config, so it serves VmCredential and
    ContainerCredential alike -- the two are field-identical.
    """
    for cred in credentials:
        if cred.name == credential:
            return cred
    return None


def vm_broker_upstream_addresses(config: dict) -> list[str]:
    """vm_broker_hosts' addresses. See broker_upstream_addresses."""
    return broker_upstream_addresses(vm_broker_hosts(config))


def container_broker_upstream_addresses(config: dict) -> list[str]:
    """container_broker_hosts' addresses. See broker_upstream_addresses."""
    return broker_upstream_addresses(container_broker_hosts(config))


def broker_upstream_addresses(hosts) -> list[str]:
    """Every address the credential-backed hosts resolve to, for IPAddressAllow=.

    Resolved HERE, at generation time, because IPAddressAllow= takes addresses
    and systemd will not resolve a name in it. That makes the list stale on a
    moved record exactly as every other resolve-at-start element in this design
    is, and fixed by the same restart.

    A name that does not resolve contributes nothing and is not an error. The
    failure it produces is the safe one: with IPAddressDeny=any under the list,
    an unresolvable upstream is a broker that cannot reach that provider and
    says so per request, rather than a broker that reaches everything. This
    matters more here than anywhere else in the design -- the broker's uid is
    NOT in wl_filtered, so workload-filter.nft's default-deny never applies to
    this leg and these two directives are its SOLE egress bound. A dropped
    IPAddressAllow= line is not a degraded bound, it is no bound at all.
    """
    seen: list[str] = []
    for host, _credential in hosts:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError:
            continue
        for info in infos:
            addr = str(ipaddress.ip_address(info[4][0]))
            if addr not in seen:
                seen.append(addr)
    return seen


def host_resolver_addresses(resolv_conf: str = "/etc/resolv.conf") -> list[str]:
    """The host's nameservers, for IPAddressAllow=.

    NOT optional, and not an optimisation: the broker resolves its own upstream
    names, so a list without the resolver in it is a broker whose every lookup
    is denied -- the same shape as a guest that can reach its allowlisted hosts
    and cannot resolve them, reached from a third direction, and one that
    presents as the provider being down rather than as a policy fault.

    Loopback is added by the caller rather than found here: on a
    systemd-resolved host the only nameserver in this file is 127.0.0.53, and
    the instance needs the loopback range anyway for the address it binds.
    """
    found: list[str] = []
    try:
        text = Path(resolv_conf).read_text()
    except OSError:
        return found
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                addr = str(ipaddress.ip_address(parts[1].split("%")[0]))
            except ValueError:
                continue
            if addr not in found:
                found.append(addr)
    return found


def inspect_link_address_commands(uid: int) -> tuple[list[str], list[str]]:
    """The `ip addr` argvs putting this workload's inspector addresses on the
    shared dummy link, (v4, v6).

    Both families or neither: the redirect is dual-stack from the first rung,
    and the address is on a dummy link and therefore local, so neither add
    touches a route or a sysctl.

    The v6 add carries `nodad`. A dummy link runs no DAD at all, so the flag
    changes
    nothing today; it states the intent and stays correct if the address ever
    moves to a link type that does run DAD, where it would otherwise sit
    tentative through the router-solicitation window and the inspector's first
    connection on that family would time out.
    """
    addr = inspect_address(uid)
    v4 = [IP_BIN, "addr", "add", f"{addr.v4}/32", "dev", ADVERTISED_IFACE]
    v6 = [IP_BIN, "addr", "add", f"{addr.v6}/128", "dev", ADVERTISED_IFACE,
          "nodad"]
    return v4, v6


def inspect_link_delete_commands(uid: int) -> tuple[list[str], list[str]]:
    """The `ip addr del` argvs removing them again, (v4, v6).

    The per-workload addresses are removed on stop (unlike the shared link and
    the advertised address, which are never): an address on the link means an
    inspector that is supposed to be running, and a stopped workload leaving
    its listener address behind is exactly what `diagnose` cannot explain.
    """
    addr = inspect_address(uid)
    v4 = [IP_BIN, "addr", "del", f"{addr.v4}/32", "dev", ADVERTISED_IFACE]
    v6 = [IP_BIN, "addr", "del", f"{addr.v6}/128", "dev", ADVERTISED_IFACE]
    return v4, v6
