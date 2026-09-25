"""Who owns the far end of an accepted TCP connection?

Shared by `libexec/agent-broker` and `libexec/workload-inspect-listener`,
which both need to answer the same question about a caller and had no business
answering it two ways. The userns helpers at the end are the precondition for
the answer being truthful: /proc/net translates the uid column through the
reader's namespace, so a process that cannot map a workload's uid sees the
overflow uid instead and every such caller collapses into one identity.

WHY NOT SO_PEERCRED. It is AF_UNIX-only. On a TCP socket it yields nothing
usable, so a peer-credential check on a listener bound to an address has to go
to the kernel's socket table instead. That is still not a handshake: the owner
is recorded by the kernel and read out of /proc/net, so there is nothing for a
caller to participate in or lie about.

WHY THE UID AND NOT THE ADDRESS. The host's networking re-originates every
workload flow -- passt for a VM, pasta for a container -- as a host socket owned
by that workload's own user. The source address is therefore identical for all
of them and carries no information; the uid is assigned by the host, is
unreachable from inside the workload, and is the same primitive the host's
egress rules already match on.
"""

import ipaddress
import socket
import struct
from pathlib import Path

PROC_NET_TCP = ("/proc/net/tcp", "/proc/net/tcp6")

# Recovers what a connection was aimed at before the host translated it.
# Two of them, one per family, and they are NOT interchangeable: the v4 option
# lives under SOL_IP and returns a sockaddr_in, the v6 one under SOL_IPV6 and
# returns a sockaddr_in6. Asking for the v4 one on a v6 socket does not fall
# back, it fails -- which is how the v6 half of this lookup was silently inert.
SO_ORIGINAL_DST = 80
IPV6_ORIGINAL_DST = 80
# Asked for as socket.IPPROTO_IPV6, never socket.SOL_IPV6: Python defines no
# such name, so writing it raises AttributeError -- which, swallowed by the
# tolerant except around the lookup, would leave the v6 branch inert in exactly
# the way it exists to prevent -- and reads as correct.


def _norm(addr):
    """Canonical address, with v4-mapped v6 collapsed to plain v4.

    A dual-stack listener reports peers as ::ffff:a.b.c.d while the row for the
    same socket may sit in either table, so both sides of a comparison have to
    be flattened or an exact match never happens.
    """
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _proc_addr(text):
    """Decode a /proc/net address: 32-bit words, each little-endian, in hex."""
    raw = bytes.fromhex(text)
    return _norm(b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4)))


def local_endpoints(sock):
    """Every endpoint this connection's local end may be recorded under.

    Both callers sit behind a destination rewrite, and the *client* socket keeps
    recording the address it dialled rather than the one we ended up bound to.
    Matching only getsockname() therefore misses precisely the traffic the
    redirect creates -- and misses it as a refusal, which looks like a config
    error rather than a lookup that cannot match. SO_ORIGINAL_DST recovers what
    the caller aimed at; both are accepted so the untranslated path (local
    testing) keeps working.
    """
    endpoints = [tuple(sock.getsockname()[:2])]
    try:
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, packed = struct.unpack("!2xH4s8x", raw)
        endpoints.append((socket.inet_ntoa(packed), port))
    except (OSError, struct.error):
        pass  # no conntrack entry, or this is a v6 socket: try v6 below
    # BOTH FAMILIES, and the v6 half is not symmetry for its own sake. The
    # redirect that puts traffic here has a v6 rule of its own (`dnat ip6 to
    # ... map @wl_inspect6`), so a v6 dial arrives translated exactly as a v4
    # one does -- but SO_ORIGINAL_DST under SOL_IP raises on that socket, which
    # left this list holding only getsockname(). The peer's row in
    # /proc/net/tcp6 records the address it DIALLED, so nothing matched, the
    # lookup returned None, and the caller was admitted and counted as
    # unresolved. The nft guard still covered it, so the only symptom was a
    # counter climbing: a hardening layer degrading to inert with nothing
    # saying so, which is the shape this whole module exists to refuse.
    #
    # sockaddr_in6 is 28 bytes -- family, port, flowinfo, 16-byte address,
    # scope id -- and the scope id is dropped deliberately: it qualifies a
    # link-local address for a sender, and both sides of the comparison here
    # come from /proc, which records none.
    try:
        raw = sock.getsockopt(socket.IPPROTO_IPV6, IPV6_ORIGINAL_DST, 28)
        port, packed = struct.unpack("!2xH4x16s4x", raw)
        endpoints.append((socket.inet_ntop(socket.AF_INET6, packed), port))
    except (OSError, struct.error):
        pass  # no conntrack entry: nothing translated this
    return endpoints


def _peer_rows(rows, locals_, peer):
    """(uid, inode) of every row that is `peer`'s end of this connection.

    The peer's row is this connection mirrored: its local address is our
    remote and its remote is our local. `locals_` is every endpoint that
    "our local" may be recorded as -- see local_endpoints, which explains
    why there is more than one.

    The port test before the split is a filter, not a shortcut: the row we
    want carries the peer's port in its local column, so a line without
    that hex anywhere cannot be it. The peer's port is ephemeral and
    therefore nearly unique, so `in` -- which runs in C -- rejects almost
    every row before Python touches it. Measured over a 1638-row table:
    1.188ms to split and hex-decode every row, 0.034ms with the filter,
    same uid. 34x, and it scales with the host's socket count, which is
    not something a caller should be able to make a listener pay per
    connection.

    The survivors are checked in full. This narrows the work without
    widening the match.
    """
    want_local = (_norm(peer[0]), peer[1])
    want_remotes = {(_norm(host), port) for host, port in locals_}
    needle = f":{peer[1]:04X}"
    for line in rows:
        if needle not in line:
            continue
        f = line.split()
        if len(f) < 10:
            continue
        try:
            local_host, local_port = f[1].split(":")
            if (_proc_addr(local_host), int(local_port, 16)) != want_local:
                continue
            remote_host, remote_port = f[2].split(":")
            remote = (_proc_addr(remote_host), int(remote_port, 16))
            if remote not in want_remotes:
                continue
            yield int(f[7]), int(f[9])
        except ValueError:
            continue


def peer_uid_from(rows, locals_, peer):
    """uid owning `peer`'s socket, given /proc/net/tcp data lines, or None.

    inode 0 is a socket with no owning process -- a TIME_WAIT remnant,
    which the kernel reports with uid 0, or a socket its owner has closed.
    Reading that as identity would silently attribute the request to root,
    so such a row names nobody.
    """
    for uid, inode in _peer_rows(rows, locals_, peer):
        if inode != 0:
            return uid
    return None


def peer_orphaned_from(rows, locals_, peer):
    """Whether `peer`'s row is there and owned by no socket.

    A peer that wrote its request and closed before we looked leaves its
    end as an orphan: the kernel keeps the row, with inode 0, until the
    close completes. Its data is still ours to read, and nothing says who
    sent it -- a state a caller can put itself in on purpose, so it is
    told apart from a row that is merely absent.
    """
    found = list(_peer_rows(rows, locals_, peer))
    return bool(found) and all(inode == 0 for _uid, inode in found)


def _proc_tables():
    """The data lines of each /proc/net table that can be read."""
    for path in PROC_NET_TCP:
        try:
            with open(path) as fh:
                yield fh.readlines()[1:]
        except OSError:
            continue


def peer_uid(locals_, peer):
    """uid owning the far end of an accepted connection, or None."""
    for rows in _proc_tables():
        uid = peer_uid_from(rows, locals_, peer)
        if uid is not None:
            return uid
    return None


def peer_caller(locals_, peer):
    """(uid or None, orphaned) for the far end of an accepted connection.

    One read of each table for both answers. `orphaned` is True when the
    peer's row is there and no socket owns it: the caller closed before it
    could be identified. See peer_orphaned_from for why that is not the
    same as a row that could not be found.
    """
    orphaned = False
    for rows in _proc_tables():
        uid = peer_uid_from(rows, locals_, peer)
        if uid is not None:
            return uid, False
        orphaned = orphaned or peer_orphaned_from(rows, locals_, peer)
    return None, orphaned


# The first byte of the kernel's struct tcp_info: the connection's state.
TCP_ESTABLISHED = 1


def peer_closed(sock):
    """Whether the far end of an accepted TCP connection has already closed
    or reset it. A reset leaves no row in the table at all, so a caller the
    lookup could not name is only innocent while its connection is up.
    """
    info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 1)
    return info[0] != TCP_ESTABLISHED


def userns_ranges(uid_map):
    """The uid ranges this namespace can represent, as (start, count), in
    the namespace's OWN numbering.

    /proc/net translates the uid column through the *reader's* namespace,
    so an owner outside these ranges reads as the overflow uid instead.
    Enough of those and every caller collapses into one identity, with the
    broker still serving traffic and no error anywhere.

    The first column of uid_map, not the second. A line reads
    `inside outside count`, and the uid a program is told and the uids the
    kernel reports to it are both inside values; the outside column is the
    parent's numbering, which nothing here ever sees. The two coincide in
    the initial namespace and under PrivateUsers=, and differ in a rootless
    container, where reading the outside column refuses every uid the
    container has.
    """
    ranges = []
    for line in uid_map.splitlines():
        f = line.split()
        if len(f) != 3:
            continue
        try:
            ranges.append((int(f[0]), int(f[2])))
        except ValueError:
            continue
    return ranges


def userns_maps_everything(uid_map):
    """Whether this is an unrestricted namespace -- the initial one, in practice."""
    return any(start == 0 and count >= 0xFFFFFFFF
               for start, count in userns_ranges(uid_map))


def unmappable_uids(uids, uid_map):
    """The uids among `uids` this namespace cannot represent.

    Checked against the uids that actually matter rather than against the shape
    of the map, because a namespace can be restricted and still map the whole
    workload range -- refusing that would be a false alarm, and an operator who
    hits one learns to route around the check.

    Uids, not names: the broker is told the uid of its one caller on its
    command line and never looks a workload user up, so this answers about
    the number it was given. (It answered about workload USERS while the
    broker read a document keyed by workload name, and the passwd lookup that
    turned a name into a uid -- with the user-name prefix it had to know to
    do so -- was the last workload-side fact in either daemon's process.)
    """
    ranges = userns_ranges(uid_map)
    return [uid for uid in uids
            if not any(start <= uid < start + count for start, count in ranges)]


def overflow_uid():
    """The uid the kernel substitutes for one it cannot map."""
    try:
        return int(Path("/proc/sys/kernel/overflowuid").read_text().strip())
    except (OSError, ValueError):
        return 65534
