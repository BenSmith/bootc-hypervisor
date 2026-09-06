"""Who owns the far end of an accepted TCP connection?

Shared by `libexec/agent-broker` and `libexec/workload-vm-inspect-listener`,
which both need to answer the same question about a caller and had no business
answering it two ways. Extracted from the broker, where it was first written
and where its edge cases were paid for.

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
import pwd
import socket
import struct

WORKLOAD_USER_PREFIX = "_wl-"
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
# the way it was written to fix. Caught by a test, not by reading it.


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


def peer_uid_from(rows, locals_, peer):
    """uid owning `peer`'s socket, given /proc/net/tcp data lines, or None.

    The peer's row is this connection mirrored: its local address is our remote
    and its remote is our local. `locals_` is every endpoint that "our local"
    may be recorded as -- see local_endpoints, which explains why there is more
    than one.

    The port test before the split is a filter, not a shortcut: the row we want
    carries the peer's port in its local column, so a line without that hex
    anywhere cannot be it. The peer's port is ephemeral and therefore nearly
    unique, so `in` -- which runs in C -- rejects almost every row before Python
    touches it. Measured over a 1638-row table: 1.188ms to split and hex-decode
    every row, 0.034ms with the filter, same uid. 34x, and it scales with the
    host's socket count, which is not something a caller should be able to make
    a listener pay per connection.

    The survivors are checked exactly as before. This narrows the work without
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
            if (_proc_addr(remote_host), int(remote_port, 16)) not in want_remotes:
                continue
            # inode 0 is a socket with no owning process -- a TIME_WAIT remnant,
            # which the kernel reports with uid 0. Reading that as identity
            # would silently attribute the request to root.
            if int(f[9]) == 0:
                continue
            return int(f[7])
        except ValueError:
            continue
    return None


def peer_uid(locals_, peer):
    """uid owning the far end of an accepted connection, or None."""
    for path in PROC_NET_TCP:
        try:
            with open(path) as fh:
                rows = fh.readlines()[1:]
        except OSError:
            continue
        uid = peer_uid_from(rows, locals_, peer)
        if uid is not None:
            return uid
    return None


def workload_name(uid):
    """Workload name behind a uid, or None if it is not a workload user."""
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        return None
    if not user.startswith(WORKLOAD_USER_PREFIX):
        return None
    return user[len(WORKLOAD_USER_PREFIX):]
