"""One workload's answer document, as the synthesising responder reads it.

The writer is vm_network_config.vm_resolve_policy; this is the reader, and
Policy.DOCUMENT_KEYS is the seam the two are tested against each other on.
"""
import json

from config_parser import normalise_hostname
from dns_wire import TYPE_AAAA
from egress_policy import hostname_match
from workload_addr import RESOLVE_TTL


class Policy:
    """One workload's answers, as read at start.

    Read once. The recovery contract is the inspector's: an edited config
    applies on a RESTART, and the unit is PartOf= the VM, so a VM restart is
    what re-reads it. Re-reading per query would make the guest's view of policy
    depend on when it asked.
    """

    # Every key this reader takes from vm_resolve_policy's document, named so
    # the two halves can be tested against each other rather than each against
    # a literal. The failure it exists to catch is silent and crosses two
    # processes: __init__ reads by document.get(), so a key added to the writer
    # and never wired in here loads clean and changes nothing -- which for
    # `policy` meant every legitimate lookup on a policy-only workload counting
    # as the tunnelling signature, with no traffic broken to point at it.
    DOCUMENT_KEYS = ("address", "address6", "ttl", "static", "hosts", "policy")

    def __init__(self, document):
        self.address = document["address"]
        self.address6 = document["address6"]
        self.ttl = int(document.get("ttl", RESOLVE_TTL))
        static = document.get("static") or {}
        # Normalised on the way in as well as on the way out. The writer already
        # normalises, and doing it here too means a hand-edited policy file
        # cannot introduce a name that never matches anything.
        self.static = {
            normalise_hostname(name): tuple(addrs)
            for name, addrs in static.items()
        }
        # Read to COUNT, never to answer. See vm_resolve_policy: synthesis is
        # unconditional, and a responder that refused an unlisted name would be
        # a different design. Tolerated absent so a policy document written
        # before this key existed still loads.
        self.hosts = tuple(document.get("hosts") or ())
        # The [[vm.network.policy]] host patterns, read for the same counting
        # reason and tolerated absent for the same compatibility one. See
        # on_a_list for why a responder that knew only `hosts` is wrong.
        self.policy = tuple(document.get("policy") or ())

    def on_a_list(self, name: str) -> bool:
        """Whether any list in this workload would authorise the name.

        ANY list, and the word is load-bearing -- this predicate decides
        nothing except whether a query is the tunnelling signature, so every
        list that authorises a name has to be in it or a working config
        reports an attack.

        `static` counts as a list: an `allow` entry is an authorisation, and a
        query for one is not the tunnelling signature even though `hosts` does
        not match it.

        So does `policy`. §3 lets a [[vm.network.policy]] entry allowlist its
        own host, so `hosts` can legitimately be EMPTY on a workload that
        reaches several names -- and the listener's Policy.admits already
        knows it. Leaving this half behind does not break any traffic, which
        is exactly why it would have survived: the workload works, and the one
        figure built to notice exfiltration sits pinned at every query the
        guest makes.
        """
        return (name in self.static
                or hostname_match(name, self.hosts)
                or hostname_match(name, self.policy))

    def answers(self, name, qtype):
        """The addresses to answer `name`/`qtype` with, and where they came from.

        Returns (addresses, source). An empty tuple means NODATA.

        The static map WINS over synthesis, and it wins completely: a name in
        the map is answered only from the map, so a map entry with v4 addresses
        and no v6 gets NODATA for AAAA rather than the synthesised inspector
        address. Falling back to synthesis there would send the guest to a
        listener that does not serve the port it wanted, which is a hang and not
        a refusal -- the exact failure the map exists to prevent.
        """
        want6 = qtype == TYPE_AAAA
        entry = self.static.get(name)
        if entry is not None:
            picked = tuple(a for a in entry if (":" in a) == want6)
            return picked, "static"
        return (self.address6 if want6 else self.address,), "synthesised"


def load_policy(path):
    with open(path) as f:
        return Policy(json.load(f))
