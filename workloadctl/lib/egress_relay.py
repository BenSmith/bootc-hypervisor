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
import ssl
import time

from http_framing import RELAY_CHUNK

# The timeout on an accepted socket up to and including the decision, in
# seconds. It bounds the ClientHello peek and the upstream connect, which are
# the only reads made before a connection is either spliced or closed. Short on
# purpose: a connection that has not said what it wants is holding one of
# MAX_CONNECTIONS slots for nothing.
CONNECTION_TIMEOUT = 5.0

# The idle bound once a connection is spliced, in seconds, and the timeout both
# sockets carry after it. It is an IDLE bound, not a lifetime: the relay loop
# rearms it on every byte moved either way, so a long download is fine and a
# tunnel nobody is using is not. It
# must be larger than CONNECTION_TIMEOUT — the module docstring says why the
# two cannot be one number.
RELAY_IDLE_TIMEOUT = 120.0

# What one direction may hold that its far side has not taken. Past it that
# direction's sender is not read, so a peer that stops reading slows the
# other rather than growing this process.
RELAY_BUFFER = 4 * RELAY_CHUNK


class _Direction:
    """Bytes read from `src` and not yet written to `dst`, and which event
    each side's last attempt was left waiting on.

    A TLS read can need the socket writable and a TLS write can need it
    readable, so the event is the one the engine asked for, not the one the
    direction suggests.
    """

    def __init__(self, src, dst, check=None):
        self.src, self.dst, self.check = src, dst, check
        self.buf = bytearray()
        # The chunk a TLS write was refused on: OpenSSL requires the retry
        # to carry the same bytes.
        self.inflight = None
        self.read_on = selectors.EVENT_READ
        self.write_on = selectors.EVENT_WRITE

    def holding(self):
        return bool(self.buf) or self.inflight is not None

    def room(self):
        return len(self.buf) < RELAY_BUFFER

    def read(self):
        """One read into the buffer: the bytes, b"" at the end of the
        stream, or None when there was nothing to take yet."""
        try:
            data = self.src.recv(RELAY_CHUNK)
        except ssl.SSLWantWriteError:
            self.read_on = selectors.EVENT_WRITE
            return None
        except (ssl.SSLWantReadError, BlockingIOError):
            self.read_on = selectors.EVENT_READ
            return None
        self.read_on = selectors.EVENT_READ
        if data:
            if self.check is not None:
                # Before the buffer, so a stream this refuses does not
                # reach the origin at all.
                self.check(data)
            self.buf += data
        return data

    def write(self):
        """One write from the buffer. Whether any bytes moved."""
        chunk = self.inflight or bytes(self.buf[:RELAY_CHUNK])
        try:
            sent = self.dst.send(chunk)
        except ssl.SSLWantReadError:
            self.inflight, self.write_on = chunk, selectors.EVENT_READ
            return False
        except (ssl.SSLWantWriteError, BlockingIOError):
            self.inflight, self.write_on = chunk, selectors.EVENT_WRITE
            return False
        self.inflight, self.write_on = None, selectors.EVENT_WRITE
        del self.buf[:sent]
        return sent > 0


def relay(client, upstream, on_client_bytes=None):
    """Move bytes both ways until either side closes or goes idle.

    Neither direction waits on the other. Each is read while its buffer has
    room and written while it holds anything, so a peer that writes before
    it reads -- an origin answering 401 or 413 to a large upload, a
    WebSocket, a bidirectional h2 stream -- is read while it writes. A
    relay that blocked in one direction's write never read the other, and
    both peers and the relay waited out the idle timeout together. Two
    threads are not the way out: a terminated connection's legs are TLS
    engines, and one SSLSocket carries both directions of its leg.

    A close in either direction ends the whole splice once what was already
    read has been written, or the side it is for refuses it or goes idle.
    Half-close forwarding would be more faithful to TCP, but it also keeps
    a slot and a thread alive on a direction the guest has already
    abandoned; the ceiling is the reason to prefer the simpler end. Idle
    means no byte moved either way for RELAY_IDLE_TIMEOUT, and before a
    close it raises TimeoutError if bytes were still waiting for a side
    that stopped reading.

    `on_client_bytes`, when given, sees every byte read from `client`
    BEFORE it is forwarded, and may raise to end the relay. That ordering
    is what lets a check refuse a chunk without the origin seeing it; note
    that the h2 framing check can only make use of it for what it can spot
    WITHIN a chunk, which is less than it looks (see H2Framing). Only the
    guest's direction is offered, and that is a decision rather than an
    omission: the origin is a name this workload allowlisted, reached over
    a fully verified session, so checking its framing could only break a
    working host on our own parser's opinion.
    """
    directions = (_Direction(client, upstream, on_client_bytes),
                  _Direction(upstream, client))
    sel = selectors.DefaultSelector()
    watching = {}
    closing = False
    moved_at = time.monotonic()
    try:
        for s in (client, upstream):
            s.setblocking(False)
        while True:
            holding = any(d.holding() for d in directions)
            if closing and not holding:
                return
            idle = time.monotonic() - moved_at
            if idle >= RELAY_IDLE_TIMEOUT:
                if holding and not closing:
                    raise TimeoutError(
                        f"no byte moved for {RELAY_IDLE_TIMEOUT:.0f}s with "
                        f"bytes still to write")
                return
            reading = [d for d in directions if not closing and d.room()]
            events = {client: 0, upstream: 0}
            for d in reading:
                events[d.src] |= d.read_on
            for d in directions:
                if d.holding():
                    events[d.dst] |= d.write_on
            _watch(sel, watching, events)
            # BYTES INSIDE A TLS ENGINE ARE INVISIBLE TO select(). A record
            # that has been read off the kernel and decrypted leaves nothing
            # for the kernel to report, so a side holding some is ready
            # without it. Reachable on the terminated plane in two ways: a
            # `101` handing an upgraded TLS connection to this loop, and an
            # [[vm.network.http2]] host, where BOTH legs are TLS and every
            # frame arrives through an engine.
            ready = {d.src for d in reading
                     if getattr(d.src, "pending", None) and d.src.pending()}
            timeout = 0 if ready else RELAY_IDLE_TIMEOUT - idle
            ready |= {key.fileobj for key, _ in sel.select(timeout)}
            for d in directions:
                moved = False
                if d.src in ready and d in reading and not closing:
                    data = d.read()
                    if data == b"":
                        closing = True
                    elif data:
                        moved = True
                if d.holding() and (d.dst in ready or moved):
                    try:
                        moved = d.write() or moved
                    except OSError:
                        if not closing:
                            raise
                        # The side that closed will take nothing more.
                        return
                if moved:
                    moved_at = time.monotonic()
    finally:
        sel.close()
        for s in (client, upstream):
            try:
                s.settimeout(RELAY_IDLE_TIMEOUT)
            except OSError:
                pass


def _watch(sel, watching, events):
    """Bring the selector's registrations to `events`, a mask per socket;
    a socket with none is unregistered."""
    for sock, mask in events.items():
        now = watching.get(sock, 0)
        if mask == now:
            continue
        if not mask:
            sel.unregister(sock)
        elif not now:
            sel.register(sock, mask)
        else:
            sel.modify(sock, mask)
        watching[sock] = mask
