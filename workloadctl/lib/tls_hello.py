"""
Reading a server name out of a TLS ClientHello, and no more.

Enough of RFC 8446 §4.1.2 to read the server name and see which extensions are
present. It is not a TLS implementation and must not become one: every field
it does not need is skipped by its length, so an extension shape it has never
seen costs it nothing. The egress inspector runs this at the front of every
connection on its TLS plane, and the ECH tripwire reads the extension list it
returns; nothing else consults a parse. The raw bytes are returned alongside
because under `tls = "splice"` they are what travels upstream -- a ClientHello
re-serialised from a parse is a different ClientHello (different extension
order, different GREASE, a different JA3), so the parse is only ever consulted
for a decision.

WHY THE INSPECT PEEK USES MSG_PEEK AND THE SPLICE PEEK DOES NOT

A terminated connection's ClientHello must still be there for the TLS engine to
consume — Python's ssl wraps a SOCKET and cannot be handed bytes already read
off one. So the inspect path peeks: the same reader, with MSG_PEEK|MSG_WAITALL,
leaving every byte in the kernel receive buffer for wrap_socket to find. That
bounds a hello at what the receive buffer holds rather than at what we are
willing to read, which is why CLIENTHELLO_MAX (16 KiB) matters twice over — it
is comfortably inside a default rmem, and a hello larger than the buffer would
peek forever without progressing. The no-progress guard in `_recv_at_least` is
what turns that into a refusal instead of a spin.
"""

import socket
from typing import NamedTuple

from inspect_document import hostname_control_character

# The ceiling on how much is read looking for a complete ClientHello, in bytes.
# A real one is a few hundred bytes; post-quantum key shares push it over a
# single TCP segment but nowhere near this. The bound exists because the read
# loop is otherwise driven by lengths the GUEST writes: without it, a peer that
# opens a record and dribbles it holds a slot and grows a buffer for as long as
# the idle timeout allows.
CLIENTHELLO_MAX = 16384

# How many MSG_PEEK attempts a single ClientHello read may make before it is
# refused. MSG_WAITALL is advisory under a socket timeout -- Linux returns a
# short read rather than raising -- so a peer dribbling one byte per timeout
# would otherwise hold a ceiling slot for attempts * CONNECTION_TIMEOUT. An
# honest hello needs one attempt, occasionally two.
PEEK_ATTEMPTS_MAX = 16

# How much a consuming (non-peek) read asks for at a time. Only the splice path
# consumes, and whatever lands past the end of the hello is the guest's own next
# bytes in order, replayed upstream unchanged -- so the size only sets how much
# of that surplus one read may pull in.
READ_CHUNK = 65536

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_EXT_SERVER_NAME = 0x0000
TLS_SNI_HOST_NAME = 0x00

# RFC 9460 / draft-ietf-tls-esni: encrypted_client_hello. Read by the tripwire
# only -- the parser skips it by its length like every other extension, and
# must keep doing so. Nothing here decrypts it and nothing here can: the point
# of the tripwire is that an ECH hello is UNREADABLE, and what is observable is
# that one was attempted.
TLS_EXT_ECH = 0xfe0d


class HelloUnreadable(Exception):
    """The first bytes are not a ClientHello this can read a name out of.

    A DISTINCT condition from "the name is not allowlisted", and the two must
    stay distinguishable in the log and in the counters. They fail the
    connection identically, so an operator with one bucket for both cannot tell
    a guest reaching for a host it may not have from a guest speaking something
    that is not TLS on the TLS port — which is the tunnelling signature.
    """


class ClientHello(NamedTuple):
    """What the peek extracts. `server_name` is None when the hello carries no
    SNI extension at all, which is legal TLS and simply unallowlistable here.

    `extensions` is every extension type in wire order, GREASE values included.
    Nothing in this unit reads it; the ECH tripwire does, and recording it in
    the parse rather than re-walking the buffer later is what keeps there being
    one parser.
    """

    server_name: str
    extensions: tuple


class _Reader:
    """A length-checked cursor over a byte string.

    Every field in a ClientHello is preceded by a length the PEER wrote, so
    every read here is bounds-checked and a short one raises HelloUnreadable
    rather than returning a truncated field. Slicing past the end of a bytes
    object in Python returns a short result silently, which for a parser driven
    by attacker-supplied lengths is the whole bug class.
    """

    def __init__(self, buf):
        self._buf = buf
        self._pos = 0

    def remaining(self) -> int:
        return len(self._buf) - self._pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.remaining() < n:
            raise HelloUnreadable(
                f"a length field claims {n} bytes with {self.remaining()} left")
        out = self._buf[self._pos:self._pos + n]
        self._pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")


def _parse_server_name(data: bytes):
    """The first host_name in a server_name extension, or None.

    Non-ASCII is refused rather than decoded: a name on the wire is punycode by
    RFC 6066, so bytes that are not ASCII are either a different encoding of a
    name — which would match a pattern differently from the way it was written
    — or not a name at all.

    A control character is refused for the second reason, which ASCII-ness does
    not cover: this name is logged and written into the status document, and a
    bare LF inside it forges a journal record. See
    `hostname_control_character`.
    """
    r = _Reader(data)
    entries = _Reader(r.take(r.u16()))
    while entries.remaining():
        kind = entries.u8()
        value = entries.take(entries.u16())
        if kind == TLS_SNI_HOST_NAME:
            try:
                name = value.decode("ascii")
            except UnicodeDecodeError:
                raise HelloUnreadable(
                    "the server_name is not ASCII, so it is not a name as "
                    "RFC 6066 puts one on the wire") from None
            ch = hostname_control_character(name)
            if ch is not None:
                # The character is named with !r and nothing else of the name
                # is: quoting the whole thing would put the injected bytes in
                # the record this refusal exists to keep clean.
                raise HelloUnreadable(
                    f"the server_name carries the control character {ch!r}, "
                    "which no name has and which forges a line in this log")
            return name
    return None


def parse_client_hello(msg: bytes) -> ClientHello:
    """Parse a ClientHello handshake body (the 4-byte header already stripped).

    GREASE (RFC 8701) needs no handling of its own and gets none: a GREASE
    extension is a well-formed extension with a reserved type, so it is skipped
    by its length like any other. Code that special-cased it would be code that
    could get the list of reserved values wrong.

    An ECH ClientHello parses like any other and yields the name it carries —
    the cover name from the ECHConfig. That name is matched against the lists
    exactly like a cleartext one; the tripwire keys on the ECH EXTENSION being
    present, never on an absent or unexpected name, because an ECH hello has a
    perfectly ordinary-looking one.
    """
    r = _Reader(msg)
    r.take(2)              # legacy_version
    r.take(32)             # random
    r.take(r.u8())         # legacy_session_id
    r.take(r.u16())        # cipher_suites
    r.take(r.u8())         # legacy_compression_methods
    if r.remaining() == 0:
        # Legal, and pre-TLS1.3 only: a hello with no extension block has no
        # SNI and so no name to match. Not an error — it is a readable hello
        # that names nothing, which the caller reports as such.
        return ClientHello(None, ())
    exts = _Reader(r.take(r.u16()))
    name = None
    seen = []
    while exts.remaining():
        etype = exts.u16()
        data = exts.take(exts.u16())
        seen.append(etype)
        if etype == TLS_EXT_SERVER_NAME and name is None:
            name = _parse_server_name(data)
    return ClientHello(name, tuple(seen))


def read_client_hello(conn, max_bytes=CLIENTHELLO_MAX, *, peek=False):
    """Read until a whole ClientHello is in hand. Returns (raw, hello).

    `peek` leaves every byte where it was. The splice path consumes the hello
    because it replays it upstream itself; the inspect path must not, because
    the bytes have to still be in the kernel receive buffer when ssl's
    wrap_socket runs the handshake. See the module docstring on the bound that
    imposes.

    `raw` is every byte read off the socket, record headers included and
    unmodified — that is what gets replayed upstream, and it is returned rather
    than rebuilt because a re-serialised hello is a different hello. It may run
    slightly past the end of the ClientHello if the peer coalesced more into the
    same segment; replaying the surplus is correct, since it is the guest's own
    next bytes in order.

    The handshake message is reassembled across records: a large hello (a
    post-quantum key share, say) legitimately spans more than one TLS record,
    and a parser that read only the first record would fail exactly the clients
    that are becoming the common case.
    """
    raw = b""
    pos = 0          # how much of `raw` has been consumed as complete records
    body = b""       # handshake bytes, record framing stripped
    want = None      # the handshake message length, once its header is in hand
    while True:
        raw = _recv_at_least(conn, raw, pos + 5, max_bytes, peek=peek)
        if raw[pos] != TLS_HANDSHAKE:
            raise HelloUnreadable(
                f"record type 0x{raw[pos]:02x} is not a TLS handshake record")
        length = int.from_bytes(raw[pos + 3:pos + 5], "big")
        raw = _recv_at_least(conn, raw, pos + 5 + length, max_bytes,
                             peek=peek)
        body += raw[pos + 5:pos + 5 + length]
        pos += 5 + length
        if want is None and len(body) >= 4:
            if body[0] != TLS_CLIENT_HELLO:
                raise HelloUnreadable(
                    f"handshake type 0x{body[0]:02x} is not a ClientHello")
            want = int.from_bytes(body[1:4], "big")
        if want is not None and len(body) >= 4 + want:
            return raw, parse_client_hello(body[4:4 + want])


def _recv_at_least(conn, raw, n, max_bytes, *, peek=False):
    """Read until `raw` holds at least n bytes, or fail closed.

    In `peek` mode every call re-reads the queue from its start with
    MSG_PEEK|MSG_WAITALL, so `raw` is REPLACED rather than appended to and the
    socket is left exactly as it was found. A peek that comes back no longer
    than what we already had is refused rather than retried forever: it means
    the hello is larger than the receive buffer can hold, and no number of
    further attempts changes that.
    """
    attempts = 0
    while len(raw) < n:
        if n > max_bytes:
            raise HelloUnreadable(
                f"a ClientHello over {max_bytes} bytes is not one we read")
        try:
            if peek:
                chunk = conn.recv(n, socket.MSG_PEEK | socket.MSG_WAITALL)
            else:
                chunk = conn.recv(READ_CHUNK)
        except OSError as exc:
            raise HelloUnreadable(f"read failed: {exc}") from None
        if not chunk:
            raise HelloUnreadable("the connection closed mid-ClientHello")
        if peek:
            attempts += 1
            if len(chunk) <= len(raw) or attempts > PEEK_ATTEMPTS_MAX:
                raise HelloUnreadable(
                    "the ClientHello did not arrive whole in the receive "
                    "buffer")
            raw = chunk
        else:
            raw += chunk
    return raw
