#!/usr/bin/env python3
"""The names of the nftables objects this design owns, and the pair type they
are spelled through.

Every one of these is a name two programs must spell identically -- the helper
that arms a set and the reporting code that reads it back, or the skeleton and
`cmd_rules`. A disagreement matches nothing, and a set that never matches looks
exactly like a set nothing dialled: no error, no counter, no symptom. That is
the whole reason this file exists rather than a literal at each site.

Names only, plus FamilyPair and the two helpers that fill both halves of one.
The type belongs with the names because a name here is HALF a name -- the v4
and v6 sets are one logical object -- and separating them is how an element
lands in the family that matches nothing. Nothing here builds an argv or runs
nft; that is lib/nft.py.

Imports nothing of ours.

Installed to /usr/libexec/workloadctl/nft_constants.py.
"""

from typing import NamedTuple


# The uid-keyed egress layer (ADR 006 §4). One table shared by every VM;
# units manage set *elements* only, never rules.
NFT_BIN = "/usr/sbin/nft"
NFT_TABLE = "inet workload_filter"
NFT_SKELETON = "/usr/share/workloadctl/workload-filter.nft"
NFT_SET_FILTERED = "wl_filtered"
NFT_SET_ALLOW4 = "wl_allow4"
NFT_SET_ALLOW6 = "wl_allow6"

# The sets a workload's own filter helper arms and purges. Not every set in the
# table: the interval sets are the skeleton's and the inspect sets are armed by
# the redirect's installer, so a helper that walked all of them would delete
# state it does not own.
NFT_SETS = (NFT_SET_FILTERED, NFT_SET_ALLOW4, NFT_SET_ALLOW6)

# --- One object, two families ---
#
# In the inet family `ip daddr` matches v4 only and `ip6 daddr` v6 only, so
# every address-bearing object here is two nftables objects. The RULES have to
# be written twice; the Python does not, and writing it twice is how the v6
# half goes missing. It has: the reserved-range check was v4 by construction
# and 2001:2::/48 went unchecked for a whole rung (TestReservedRanges), and an
# element in the wrong family's set matches nothing at all -- a silent failure,
# because a set that never matches looks exactly like a set nothing dialled.
#
# So the two names are ONE value, and the builders below take a FamilyPair and
# fill both halves rather than naming either. A builder cannot emit one family:
# there is no line in it that says `.v4`.

class FamilyPair(NamedTuple):
    """The v4 and v6 names of one logical nftables set or map."""
    v4: str
    v6: str

    def of(self, version: int) -> str:
        return self.v6 if version == 6 else self.v4


def both_families(pair: FamilyPair, addr: "VmInspectAddress",
                   build) -> dict[str, list[str]]:
    """Both halves of one object, built from this workload's address in each.

    BOTH, unconditionally: these objects are derived from a uid rather than
    from operator input, so there is no such thing as a workload with a v4
    inspector and no v6 one, and an empty half would mean the derivation
    broke.
    """
    return {pair.v4: build(addr.v4), pair.v6: build(addr.v6)}


def split_by_family(pair: FamilyPair, elements) -> dict[str, list[str]]:
    """Bucket (address, element-expression) pairs into their family's half.

    Empty halves are dropped rather than emitted, because these objects come
    from operator input -- an allowlist naming only v4 names is ordinary --
    and `nft add element ... { }` is an error, not a no-op.
    """
    buckets: dict[str, list[str]] = {pair.v4: [], pair.v6: []}
    for addr, element in elements:
        buckets[pair.of(addr.version)].append(element)
    return {name: entries for name, entries in buckets.items() if entries}


NFT_PAIR_ALLOW = FamilyPair(NFT_SET_ALLOW4, NFT_SET_ALLOW6)
# Internal destination prefixes the egress inspector may not connect OUT to. The
# elements are constant and live in the skeleton, not here -- nothing in Python
# manages them. The names exist so tests can name the sets and so
# `vm_egress_check` can tell a loaded guard from a table that predates it,
# which it cannot infer from wl_filtered membership: nft state is kernel state
# until reboot, so a VM started before an upgrade keeps the older chain.
NFT_SET_INTERNAL4 = "wl_internal4"
NFT_SET_INTERNAL6 = "wl_internal6"
NFT_PAIR_INTERNAL = FamilyPair(NFT_SET_INTERNAL4, NFT_SET_INTERNAL6)
# The per-workload exceptions to those drops -- [[vm.network.internal]]. Per
# workload, so unlike the interval sets above these ARE managed from Python and
# are never flushed by the skeleton.
NFT_SET_INTERNAL_OK4 = "wl_internal_ok4"
NFT_SET_INTERNAL_OK6 = "wl_internal_ok6"
NFT_PAIR_INTERNAL_OK = FamilyPair(NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6)

# per workload and are armed by the same script that arms the DNAT maps, not
# by the filter helper: the dst sets hold the TRANSLATED tuple, which only the
# redirect's installer knows. The self sets carry a per-element counter —
# the load-bearing half, since it is what attributes a wrong-port self-dial to
# its workload instead of the cross-workload guard's shared number. None of
# these is flushed in the skeleton; the ones that hold per-workload state are
# never emptied by it.
NFT_SET_INSPECT_DST = "wl_inspect_dst"
NFT_SET_INSPECT_DST6 = "wl_inspect_dst6"
NFT_PAIR_INSPECT_DST = FamilyPair(NFT_SET_INSPECT_DST, NFT_SET_INSPECT_DST6)
NFT_SET_INSPECT_SELF = "wl_inspect_self"
NFT_SET_INSPECT_SELF6 = "wl_inspect_self6"
NFT_PAIR_INSPECT_SELF = FamilyPair(NFT_SET_INSPECT_SELF, NFT_SET_INSPECT_SELF6)
# The cross-workload guard's destination sets: every LIVE inspector address on
# the host, one plain address per armed workload and no uid. Armed alongside
# the four above, by the same helper, for the same reason.
#
# WHY A SET AND NOT THE /16. Naming 198.18.0.0/16 outright would make a
# workload-scoped tool drop every non-root packet on the host bound for a /16
# workloadctl does not own -- an operator using that range for anything of
# their own would lose it whether or not they run workloads. Bounded to the
# addresses workloadctl ITSELF allocated, the guard reaches exactly as far as
# workloadctl's own listeners, and the drop stays guarded on set membership:
# an abandoned table holds an empty set and is inert.
NFT_SET_INSPECT_LIVE = "wl_inspect_live"
NFT_SET_INSPECT_LIVE6 = "wl_inspect_live6"
NFT_PAIR_INSPECT_LIVE = FamilyPair(NFT_SET_INSPECT_LIVE, NFT_SET_INSPECT_LIVE6)


# The inspector's plumbing, named here for the same reason: these are the

# The host-side process that re-originates a workload's egress — the egress
# inspector, and it alone; the synthesising responder re-originates nothing,
# see below — runs as the workload's own user, so `meta skuid` cannot separate
# its traffic from the guest's, and under default-deny the drop catches it too,
# leaving the workload's own enforcement path unable to reach anything. The control group is the discriminator that
# survives the shared uid: systemd assigns it, a guest can neither enter nor
# forge it, and it widens no destination or port, so a guest that dials 443
# past the inspector is still dropped.
#
# ONE MEMBER: the egress inspector. The synthesising responder is not a second
# one -- it answers from memory and opens no socket, so there is no
# vm_resolve_cgroup and nothing arms one. Its twin in the nat table,
# wl_inspect_cg, exempts the
# same process from the REDIRECT; this one exempts it from the DROP. A process
# needs both or it either reaches nothing or loops into the listener it is
# dialling past.
#
# The slice is pinned rather than taken from [resources].slice so the cgroup
# path is always exactly two components and the rule's `level 2` is exact.
# These sidecars are not the payload; resource control belongs on the VM.
NFT_SET_EGRESS_CG = "wl_egress_cg"
NFT_PROXY_SKELETON = "/usr/share/workloadctl/workload-proxy.nft"
NFT_PROXY_TABLE = "inet workload_proxy"

# The transparent redirect's objects (§7.1). The two maps carry one element per
# workload per redirected port, keyed uid . original port -> (listener address,
# listener port), one map per family because `dnat ip` and `dnat ip6` are
# different translations in the inet family; the set exempts the ONE process
# that re-originates workload-uid traffic -- the inspector, on the same terms
# and for the same reason as wl_egress_cg above -- so its own dials are not
# translated into the listener it is dialing past. All three live in table
# inet workload_proxy and are declared in workload-proxy.nft.
NFT_MAP_INSPECT4 = "wl_inspect4"
NFT_MAP_INSPECT6 = "wl_inspect6"
NFT_PAIR_INSPECT_MAP = FamilyPair(NFT_MAP_INSPECT4, NFT_MAP_INSPECT6)
NFT_SET_INSPECT_CG = "wl_inspect_cg"
