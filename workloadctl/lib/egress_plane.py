"""egress_plane: the two ports the egress redirect catches, and what each is.

A plane is which port the guest dialled. The `workload-filter` output chain
redirects a filtered workload's dials to 80 and 443 onto its own inspector and
nothing else, so there are exactly two, fixed before the inspector does
anything and unchanged by what it does next (terminate, splice, h2, forward).
Each carries three facts that are spelled at both ends of the redirect: the
port the guest dialled, which the nft map keys on; the port the redirect lands
it on, which the socket unit binds and the inspector recognises by
getsockname(); and the label a record and `workloadctl egress --plane` name it
by. One row per plane, so the three cannot drift apart.

Below everything: the parser refuses `[vm.network].ports` on a guest port, the
generator binds the inspect ports, the element builder writes both into the
map, and the listener labels a connection from the port that accepted it.

Installed to /usr/libexec/workloadctl/egress_plane.py.
"""

from typing import NamedTuple


class Plane(NamedTuple):
    label: str
    """What a record and `--plane` call it."""
    guest_port: int
    """What the guest dialled; the port the redirect matches."""
    inspect_port: int
    """Where the redirect lands it; the port the socket unit binds."""


CLEARTEXT = Plane("cleartext", 80, 8080)
TLS = Plane("tls", 443, 8443)

# In port order, which is the order the socket unit binds them and the map
# lists them.
PLANES = (CLEARTEXT, TLS)


def plane_for_port(port: int) -> Plane | None:
    """The plane a listener accepting on `port` carries, or None.

    The port is getsockname() on the inherited fd, because under `Accept=no`
    every activated fd carries the same LISTEN_FDNAMES entry and the name
    cannot tell the two apart; the local port can, and the socket that
    accepted the connection knows it. Only the two ports the socket unit binds
    are recognisable: anything else is not one of our listeners, and naming it
    a plane would be a guess.
    """
    for plane in PLANES:
        if port == plane.inspect_port:
            return plane
    return None
