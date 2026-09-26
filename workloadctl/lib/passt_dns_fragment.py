"""The passt netdev DNS fragment: what a guest is told, per address family.

Two pure builders, one per kind of workload. `build_dns_fragment` is for a
guest that really is handed the host's own nameservers; `build_synthesis_fragment`
for one whose queries are answered by its own synthesising responder. Each
returns the comma-separated netdev property fragment and the notes to log
about it. Nothing here reads the host; the inputs come from
lib/passt_dns_host.py.

THE PER-FAMILY RULE (design "DNS", ADR 006)

passt's DNS handling is per address family, and half-configuring a family fails
*open*. `get_dns()` (conf.c:206) computes `dns4_set`/`dns6_set` independently;
supplying `--dns` for one family suppresses only that family's branch of the
resolv.conf scan, leaving the other free to advertise the host's real
nameservers over NDP RDNSS / DHCPv6. So the invariant is:

    for each address family, emit all three of dns-forward, dns and dns-host,
    or none of them.

Never one or two. A family the host has no resolver for gets nothing at all,
which is safe: the scan runs, finds nothing, and advertises nothing.

That rule governs a workload WITHOUT a synthesising responder — an unfiltered
or bridged VM, whose guest really is being handed the host's own nameservers.
It is not the rule for a filtered one; see the next section, which is where
the loop stops being symmetric.

`--search none` suppresses the resolv.conf search list, which is otherwise
advertised over both DHCP and NDP and leaks internal domain names. It covers
both families by itself and is emitted by the generator, not here, because it
depends on nothing about the host.

AND WHAT THAT RULE BECOMES ONCE THE WORKLOAD HAS A RESPONDER

A workload matching `vm_uses_resolve` (filtered, not bridged, `resolver` not
"none") has its own synthesising responder on 127.130.x.y:53, and `--dns-host`
points there instead of at a nameserver from /etc/resolv.conf. Three things
change, and the middle one is the one that looks unchanged and is not.

  - **/etc/resolv.conf stops being read at all.** Not an optimisation: it is
    the headline property. A filtered guest's DNS must not depend on what the
    host's resolver configuration said that morning, and a code path that still
    consults it is one `resolv.conf` edit away from handing that guest nothing
    while a responder sits ready to answer every query.
  - **The all-three-or-none invariant becomes IPv4's.** IPv6 leaves the loop
    entirely and emits exactly one of the three (`--dns ::1`), which is neither
    all nor none. Stated this way deliberately: "the invariant stays exactly as
    it is" reads as licence to keep the loop symmetric, and a symmetric loop is
    what reopens the v6 resolver.
  - **The gate loses its resolver half.** Today a family is dropped unless the
    host has both a default-route gateway and a nameserver of its own for it.
    `--dns-host` is now an address that always exists, so the resolver half is
    obsolete. The gateway half is NOT: `--dns` advertises it over DHCP and
    `--dns-forward` is the address passt intercepts, and neither can be
    127.130.x.y — that is the *guest's* own loopback and unreachable from it by
    construction. So the gate becomes `gateway` alone, for IPv4.

The three fragments that produces, since the shape is what a reviewer checks
and only one of the three carries the v6 flag:

    | host                     | fragment                                    |
    |--------------------------|---------------------------------------------|
    | v4 default route present | dns-forward=<gw4>,dns=<gw4>,dns-host=<resp> |
    |                          |   plus param=--dns param=::1                |
    | no v4 default route      | dhcp-dns=off                                |
    | resolver = "none"        | dhcp-dns=off                                |

WHY `--dns ::1`, ARGUED AS WHAT IT IS

A failure-shape fix, not a leak fix. Overstating it is how the requirement gets
dropped by the first person who checks the claim.

With no v6 `--dns-forward`, `ip6.dns_match` stays unset, so passt intercepts
nothing on v6 and `ip6.dns_host` is inert (fwd.c:906-914, via is_dns_flow()).
The guest's v6 query to an advertised nameserver is then *ordinary egress
meeting the default deny* — not in any allow set, not `oif lo`, not in the
proxy cgroup — so it is dropped. Fail-closed. What it costs is a full retry
schedule per lookup on the family clients try first, which presents as broken
DNS rather than as policy.

`--dns ::1` sets ip6.dns[0], which makes `dns6_set` true and stops the
resolv.conf scan before it reaches the v6 branch; neither RDNSS nor DHCPv6
filters loopback (ndp.c:284-300, dhcpv6.c:427-443), so `::1` reaches the guest
verbatim — where it is the guest's *own* loopback with nothing listening. The
v6 query fails locally with ECONNREFUSED, immediately, never leaving the guest.

Do not reach for the alternatives: `--no-dhcp-dns` is global (dhcp.c:437,
dhcpv6.c:427, ndp.c:284) and `--dns none` is global, destructive of
dns/dns_match/dns_host on both families (conf.c:1785-1797), and order-sensitive
in the option parse (conf.c:1801).

That globality is also why `--dns ::1` belongs to the first row only: under
`dhcp-dns=off` nothing is advertised on either family, so a dead `::1` there
would be a guest-visible artifact of a mechanism that is switched off.

RESIDUAL, STATED RATHER THAN SOLVED

A host with no default route on a family still cannot offer the guest DNS on
it — there is no address to advertise that passt would then intercept. A limit
of the mechanism, unchanged from before synthesis.
"""

# What a guest is told when it gets no resolver: passt advertises nothing on
# either family. Also the helper's fallback, so ExecStart always has a defined
# expansion.
NO_RESOLVER = "dhcp-dns=off"


def build_synthesis_fragment(gateways: dict[int, str],
                             responder: str) -> tuple[str, list[str]]:
    """The fragment for a workload whose queries are answered by its responder.

    IPv4 only, gated on the default-route gateway alone, with `--dns-host`
    pointing at 127.130.x.y instead of at anything from /etc/resolv.conf —
    which is not read on this path at all. IPv6 is handled outside any loop:
    exactly one option, `--dns ::1`, and only when v4 was configured. The
    module docstring carries the reasoning for all three of those; this is the
    transcription of its table.
    """
    gateway = gateways.get(4)
    if not gateway:
        # No address to advertise that passt would then intercept. The stated
        # residual, and the reason this row carries no `--dns ::1`: dhcp-dns=off
        # suppresses the advertisement on BOTH families, so a dead ::1 here
        # would be a guest-visible artifact of a switched-off mechanism.
        return (NO_RESOLVER,
                ["host has no IPv4 default route, so there is no address to "
                 "advertise and intercept; the guest gets no resolver"])

    props = [f"dns-forward={gateway}", f"dns={gateway}",
             f"dns-host={responder}"]
    # The v6 black hole. `param=` is QEMU's repeatable escape hatch, appended to
    # passt's command line verbatim; `--dns ::1` sets ip6.dns[0], which makes
    # dns6_set true and stops the resolv.conf scan before it reaches the v6
    # branch. Not a leak fix -- see the module docstring.
    params = ["param=--dns", "param=::1"]
    notes = [
        f"IPv4: guest is told {gateway}, intercepted to this workload's "
        f"responder at {responder}; nothing is forwarded",
        "IPv6: guest is told ::1, its own loopback with nothing listening, so "
        "a v6 lookup fails immediately instead of timing out",
    ]
    return (",".join(props + params), notes)


def build_dns_fragment(gateways: dict[int, str],
                       resolvers: dict[int, str]) -> tuple[str, list[str]]:
    """Build the netdev fragment for a workload with NO responder.

    An unfiltered or bridged VM: its guest really is being handed the host's own
    nameservers, so the symmetric all-three-or-none loop still governs it. A
    filtered one goes through build_synthesis_fragment instead.

    The QEMU netdev's dns-forward/dns/dns-host properties are single-valued
    (qapi/net.json:203-216), so only one family can use them; the second goes
    through the repeatable `param=` escape hatch, which net/passt.c appends to
    passt's command line verbatim. passt itself accepts each option once per
    family — conf.c's case 9 tries inet_pton(AF_INET6) then AF_INET and sets
    the matching dns_match — so the two spellings compose.
    """
    notes: list[str] = []
    props: list[str] = []
    params: list[str] = []
    native_used = False

    for family in (4, 6):
        gateway = gateways.get(family)
        resolver = resolvers.get(family)
        if not gateway or not resolver:
            # All three or none. Omitting the family entirely is the safe half:
            # passt's scan finds no nameserver for it and advertises nothing.
            if resolver and not gateway:
                notes.append(
                    f"IPv{family}: host has a resolver but no default route, "
                    f"so no IPv{family} DNS is offered to the guest")
            continue
        if not native_used:
            props += [f"dns-forward={gateway}",
                      f"dns={gateway}",
                      f"dns-host={resolver}"]
            native_used = True
        else:
            params += ["param=--dns-forward", f"param={gateway}",
                       "param=--dns", f"param={gateway}",
                       "param=--dns-host", f"param={resolver}"]
        notes.append(
            f"IPv{family}: guest is told {gateway}, queries go to {resolver}")

    if not props:
        # No family is fully configured. Say so explicitly rather than leaving
        # the fragment empty: an empty expansion would leave a dangling comma
        # in the netdev argument and QEMU would refuse to start.
        notes.append("no usable resolver on any family; the guest gets none")
        return (NO_RESOLVER, notes)

    return (",".join(props + params), notes)
