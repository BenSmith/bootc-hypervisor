"""
Reading a server name out of a TLS ClientHello, and no more.

Enough of RFC 8446 §4.1.2 to read the server name and see which extensions are
present. It is not a TLS implementation and must not become one: every field
it does not need is skipped by its length, so an extension shape it has never
seen costs it nothing.

The hello is PEEKED, never consumed. A terminated connection's hello must
still be on the socket for ssl's wrap_socket, and a spliced one is relayed
from the socket unchanged, so neither path wants the bytes taken off it. A
peek is bounded by the receive buffer, which CLIENTHELLO_MAX sits well
inside.
"""

import socket
import time
from typing import NamedTuple

from inspect_document import (
    hostname_bad_character, hostname_control_character, normalise_hostname,
)

# The ceiling on how much is read looking for a complete ClientHello, in bytes.
# A real one is a few hundred bytes; post-quantum key shares push it over a
# single TCP segment but nowhere near this. The bound exists because the read
# loop is otherwise driven by lengths the GUEST writes: without it, a peer that
# opens a record and dribbles it holds a slot and grows a buffer for as long as
# the idle timeout allows.
CLIENTHELLO_MAX = 16384

# How long a peek that found nothing new waits before asking again, in
# seconds. A socket with a timeout is non-blocking underneath, so MSG_WAITALL
# does not wait: while part of the hello is already buffered, poll() reports
# the socket readable and the peek returns that same part at once. A hello
# larger than one segment -- the default post-quantum hello is, at 1500 MTU
# -- is routinely caught between its segments, so no progress means "wait",
# not "refuse". The whole read is bounded by the socket's own timeout, taken
# once for the hello rather than per read, so a dribbling peer holds its
# slot for one timeout and no longer.
PEEK_POLL = 0.01

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
    `hostname_control_character`. So is anything else no host name is spelled
    with, which forges a field inside one; see `hostname_bad_character`.
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
            ch = hostname_bad_character(normalise_hostname(name))
            if ch is not None:
                # Named with !r alone, for the reason above.
                raise HelloUnreadable(
                    f"the server_name carries {ch!r}, which no host name is "
                    "spelled with")
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


def read_client_hello(conn, max_bytes=CLIENTHELLO_MAX):
    """Peek until a whole ClientHello is on the socket, and parse it.

    The handshake message is reassembled across records: a large hello (a
    post-quantum key share, say) legitimately spans more than one TLS
    record. The socket's timeout bounds the whole read, not each peek.
    """
    timeout = conn.gettimeout()
    deadline = None if timeout is None else time.monotonic() + timeout
    raw = b""
    pos = 0          # how much of `raw` has been consumed as complete records
    body = b""       # handshake bytes, record framing stripped
    want = None      # the handshake message length, once its header is in hand
    while True:
        raw = _peek_at_least(conn, raw, pos + 5, max_bytes, deadline)
        if raw[pos] != TLS_HANDSHAKE:
            raise HelloUnreadable(
                f"record type 0x{raw[pos]:02x} is not a TLS handshake record")
        length = int.from_bytes(raw[pos + 3:pos + 5], "big")
        raw = _peek_at_least(conn, raw, pos + 5 + length, max_bytes, deadline)
        body += raw[pos + 5:pos + 5 + length]
        pos += 5 + length
        if want is None and len(body) >= 4:
            if body[0] != TLS_CLIENT_HELLO:
                raise HelloUnreadable(
                    f"handshake type 0x{body[0]:02x} is not a ClientHello")
            want = int.from_bytes(body[1:4], "big")
        if want is not None and len(body) >= 4 + want:
            return parse_client_hello(body[4:4 + want])


def _peek_at_least(conn, raw, n, max_bytes, deadline):
    """The socket's queue from its start, once it holds at least n bytes.

    A peek that comes back no longer than `raw` is the rest of the hello not
    having arrived yet (see PEEK_POLL), and is asked again until `deadline`.
    A peer that closed mid-hello looks the same and ends the same way.
    """
    while len(raw) < n:
        if n > max_bytes:
            raise HelloUnreadable(
                f"a ClientHello over {max_bytes} bytes is not one we read")
        try:
            chunk = conn.recv(n, socket.MSG_PEEK | socket.MSG_WAITALL)
        except OSError as exc:
            raise HelloUnreadable(f"read failed: {exc}") from None
        if not chunk:
            raise HelloUnreadable("the connection closed mid-ClientHello")
        if len(chunk) <= len(raw):
            if deadline is not None and time.monotonic() >= deadline:
                raise HelloUnreadable(
                    "the ClientHello did not arrive whole in time")
            time.sleep(PEEK_POLL)
            continue
        raw = chunk
    return raw
