"""egress_relay: the byte splice, and the two timeouts every plane spends.

Once the inspector has decided a connection -- spliced it to the name in its
ClientHello, or authorised a request on it -- what remains is moving bytes
both ways until one side closes or goes idle. `relay` is that loop. It is
the same loop for a spliced TLS connection, a terminated one whose guest leg
and origin leg are both TLS engines, an upgraded connection handed over
after a 101, and an h2 session checked frame by frame on the way through.

TWO TIMEOUTS, NOT ONE

Every accepted socket carries an explicit timeout before it is touched, none
of them the stdlib default. CONNECTION_TIMEOUT bounds every wait up to and
including a decision, and RELAY_IDLE_TIMEOUT bounds every wait after one.
They cannot be the same number: a peek that waited as long as a long-lived
tunnel is idle gives a guest a cheap way to pin every connection slot, and a
tunnel held to the peek's timeout is cut mid-download every time the far end
pauses.

Both planes spend both numbers, and the cleartext one is where the boundary
is easy to get wrong. There, the decision is per REQUEST, so the socket
returns to CONNECTION_TIMEOUT at the top of each one and moves to
RELAY_IDLE_TIMEOUT the moment a request is authorised. The wait BETWEEN
requests on a kept-alive connection is the third case and takes the idle
number: a guest holding a connection open to use again is not a guest failing
to say what it wants, and bounding that wait at the decision timeout would
both break keep-alive and report each break as a request that could not be
read.

The upstream dials (`egress_upstream`) and the listener read both numbers
through this module by attribute, so a test that shortens a wait has one
place to patch.

Installed to /usr/libexec/workloadctl/egress_relay.py.
"""

import selectors

from http_framing import RELAY_CHUNK


# The timeout on an accepted socket up to and including the decision, in
# seconds. It bounds the ClientHello peek and the upstream connect, which are
# the only reads made before a connection is either spliced or closed. Short on
# purpose: a connection that has not said what it wants is holding one of
# MAX_CONNECTIONS slots for nothing.
CONNECTION_TIMEOUT = 5.0

# The timeout both sockets carry once a connection is spliced, in seconds. It is
# an IDLE bound, not a lifetime: the relay loop rearms it on every direction of
# traffic, so a long download is fine and a tunnel nobody is using is not. It
# must be larger than CONNECTION_TIMEOUT — the module docstring says why the
# two cannot be one number.
RELAY_IDLE_TIMEOUT = 120.0


def relay(client, upstream, on_client_bytes=None):
    """Move bytes both ways until either side closes or goes idle.

    Both sockets are moved off the handshake timeout onto the idle one
    first: up to here the numbers bounded a decision, and from here they
    bound a tunnel.

    `on_client_bytes`, when given, sees every byte read from `client`
    BEFORE it is forwarded, and may raise to end the relay. That ordering
    is what lets a check refuse a chunk without the origin seeing it; note
    that the h2 framing check can only make use of it for what it can spot
    WITHIN a chunk, which is less than it looks (see H2Framing). Only the
    guest's
    direction is offered, and that is a decision rather than an omission:
    the origin is a name this workload allowlisted, reached over a fully
    verified session, so checking its framing could only break a working
    host on our own parser's opinion.
    """
    for s in (client, upstream):
        s.settimeout(RELAY_IDLE_TIMEOUT)
    peer = {client: upstream, upstream: client}
    sel = selectors.DefaultSelector()
    sel.register(client, selectors.EVENT_READ)
    sel.register(upstream, selectors.EVENT_READ)
    try:
        while True:
            # BYTES INSIDE A TLS ENGINE ARE INVISIBLE TO select(). A record
            # that has been read off the kernel and decrypted leaves nothing
            # for the kernel to report, so a relay that only ever selected
            # would sit idle holding a complete frame until the idle timeout
            # cut it. Reachable on the terminated plane in two ways: a
            # `101` handing an upgraded TLS connection to this loop, and an
            # [[vm.network.http2]] host, where BOTH legs are TLS and every
            # frame arrives through an engine.
            buffered = [s for s in (client, upstream)
                        if getattr(s, "pending", None) and s.pending()]
            if buffered:
                ready = buffered
            else:
                events = sel.select(timeout=RELAY_IDLE_TIMEOUT)
                if not events:
                    return                  # idle: nothing either way
                ready = [key.fileobj for key, _ in events]
            for sock in ready:
                data = sock.recv(RELAY_CHUNK)
                if data and on_client_bytes is not None and sock is client:
                    # Before the forward, so a stream this refuses does not
                    # reach the origin at all.
                    on_client_bytes(data)
                if not data:
                    # A close in either direction ends the whole splice.
                    # Half-close forwarding would be more faithful to TCP,
                    # but it also keeps a slot and a thread alive on a
                    # direction the guest has already abandoned; the
                    # ceiling is the reason to prefer the simpler end.
                    return
                peer[sock].sendall(data)
    finally:
        sel.close()
