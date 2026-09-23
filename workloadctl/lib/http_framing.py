"""
http_framing: where one HTTP/1.1 message ends and the next begins, by refusal.

Everything here answers one question for the inspect listener's cleartext and
terminated planes: given bytes a GUEST wrote, where does this message end, so
the next one can be authorised on its own. The framing that says where a
request ends is written by the guest, and every refusal here exists because
the alternative is a request smuggled past the authorisation of the one in
front of it. Where two parsers could read a message two ways, nothing here
picks one: it raises RequestUnreadable and the listener declines the message.

The request parser (`_split_head`) is strict for that reason. The response
parser (`_split_response_head`) is lenient for the opposite one: that head was
written by an origin the policy authorised and is relayed verbatim, so the
only thing to learn from it is where the body ends.

Not here: what the request target means (`http_target`), what a whole
request looks like once parsed (`http_request`), and the HTTP/2 check
(`h2_framing`), which is framing too, of the shallowest kind.
"""

import email.utils
from typing import NamedTuple

# The buffer size the relay moves in each direction, in bytes.
RELAY_CHUNK = 65536


# The ceiling on a request or response head (request line plus headers), in
# bytes. Like tls_hello.CLIENTHELLO_MAX it exists because the read is otherwise
# driven by a peer that can simply never send the blank line.
MESSAGE_HEAD_MAX = 32768


# The ceiling on one chunk-size line, in bytes. A chunk header is a handful of
# hex digits; anything approaching this is a peer dribbling a line to hold a
# slot.
CHUNK_LINE_MAX = 4096


# The longest method spelling worth waiting for before deciding that what is
# being read is not an HTTP request at all, plus the space that ends it.
# Sixteen covers every method anyone has registered (BASELINE-CONTROL, RFC
# 3253, is the long one). Nothing rejects a longer method on the strength of
# this number alone: it only bounds how many bytes the check below waits for
# before it stops being undecided, and the parser -- which has the whole
# request line -- is what actually refuses.
HTTP_METHOD_MAX = 16
HTTP_START_MAX = HTTP_METHOD_MAX + 1


# How much of a refused request's body is read and discarded before the 403, in
# bytes. Past it the connection is closed instead: draining exists so the NEXT
# request is read from where a request starts, and a guest that answers a
# refusal with a gigabyte gets the connection closed rather than the service of
# having it read. See _drain_or_close.
DRAIN_MAX = 1 << 20


# The methods whose responses carry no body whatever the headers say. HEAD is
# the one that matters: a HEAD response legitimately carries Content-Length
# describing a body it does not send, and a relay that believed it would block
# forever on bytes that are not coming.
_BODYLESS_STATUSES = frozenset((204, 304))


# The ceiling on trailer lines after a zero chunk. Trailers are read and
# discarded, and "read until a blank line" is a loop a guest drives: without a
# bound it can hold a slot writing well-formed lines forever.
MAX_TRAILER_LINES = 64


# RFC 9110 §5.6.2 tchar. A header name outside this set is refused rather than
# sanitised: every byte in it is a byte some other parser might treat as a
# delimiter.
_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class RequestUnreadable(Exception):
    """The guest's bytes are not a request we will act on.

    Every raise is a REFUSAL and not a repair. Where two readings of a message
    are possible, this design does not pick one: it declines the message. A
    proxy that resolves an ambiguity guesses, the origin behind it guesses too,
    and a request smuggles through the gap between the two guesses.
    """


class ReadTimedOut(RequestUnreadable):
    """A read that reached its timeout with nothing to show for it.

    A subclass, so every existing handler still catches it: a peer that stalls
    mid-message HAS failed to give us a request we can act on. It is separate
    because one of the waits is not a failure at all -- a kept-alive connection
    with no next request on it is a connection doing exactly what keep-alive is
    for, and counting that as `unreadable request` would inflate the one bucket
    whose job is to stay distinguishable from a guest speaking something that
    is not HTTP at all.

    `idle` is True when the timeout that fired was the wait for the FIRST byte,
    which is the wait that means "nothing was said" rather than "something was
    started and abandoned".
    """

    def __init__(self, message, *, idle=False):
        super().__init__(message)
        self.idle = idle


class Framing(NamedTuple):
    """Where a message body ends. `length` is meaningful only for "length"."""

    kind: str          # "none" | "length" | "chunked" | "close"
    length: int = 0


class _Stream:
    """A socket plus the bytes already read past the end of the last message.

    Pipelining is the reason this exists rather than a bare socket: the read
    that finishes one request's head routinely carries the beginning of the
    next, and a reader that dropped that surplus would lose the very request
    whose independent authorisation is the point of this unit.
    """

    def __init__(self, sock, prefill=b""):
        self.sock = sock
        # `prefill` is bytes already taken off this socket before the stream
        # existed -- the one non-blocking read the terminated plane makes after
        # an upstream handshake, looking for a TLS 1.3 alert. On the ordinary
        # path it comes back empty; when it does not, the bytes are the origin's
        # and must be read in order, not dropped.
        self._buf = prefill
        self.eof = False

    def take_buffered(self):
        """Everything read past the last message, removed from this stream.

        Used where a connection stops being a sequence of messages -- after a
        101 -- so the bytes already pulled off the socket join the byte stream
        rather than being stranded in a buffer nothing will read again.
        """
        out, self._buf = self._buf, b""
        return out

    def _fill(self, timeout=None):
        """One recv, appended to the buffer. False at a clean EOF.

        `timeout` overrides the socket's own for this ONE read and is restored
        afterwards, which is how the wait for the first byte of a head can be
        bounded differently from the wait for the rest of it. A read that
        reaches its timeout raises ReadTimedOut rather than the generic
        RequestUnreadable, and the flag says which of the two waits it was --
        the caller's disposition differs, and the socket cannot be asked after
        the fact.
        """
        if timeout is not None:
            previous = self.sock.gettimeout()
            self.sock.settimeout(timeout)
        try:
            chunk = self.sock.recv(RELAY_CHUNK)
        except TimeoutError:
            # BEFORE the OSError arm: socket.timeout is TimeoutError and
            # TimeoutError is an OSError, so a generic arm first would swallow
            # every timeout into `read failed`.
            raise ReadTimedOut(
                f"nothing was readable within "
                f"{timeout if timeout is not None else self.sock.gettimeout()}s",
                idle=timeout is not None) from None
        except OSError as exc:
            raise RequestUnreadable(f"read failed: {exc}") from None
        finally:
            if timeout is not None:
                self.sock.settimeout(previous)
        if not chunk:
            self.eof = True
            return False
        self._buf += chunk
        return True

    def read_head(self, max_bytes=MESSAGE_HEAD_MAX, idle_timeout=None):
        """A whole message head, or b"" if the peer closed cleanly first.

        The terminator is CRLFCRLF and only that. A bare-LF head is refused by
        never being found, because bare-LF line endings are precisely what two
        parsers disagree about: accept them here and a request the origin reads
        as one message can be read as two.

        `idle_timeout`, when given, bounds the wait for the FIRST byte only --
        the socket's own timeout still bounds the rest. That is what lets a
        kept-alive connection sit idle between requests for as long as a tunnel
        may while a guest that has started a head still has to finish it inside
        the decision timeout. One number for both would either cut keep-alive
        at five seconds or hand a dribbling peer a 128th of the ceiling for two
        minutes.
        """
        while True:
            idx = self._buf.find(b"\r\n\r\n")
            if idx != -1:
                head, self._buf = self._buf[:idx + 4], self._buf[idx + 4:]
                return head
            if len(self._buf) > max_bytes:
                raise RequestUnreadable(
                    f"a message head over {max_bytes} bytes is not one we read")
            if not self._fill(idle_timeout if not self._buf else None):
                if not self._buf:
                    return b""
                raise RequestUnreadable("the connection closed mid-head")

    def read_exactly(self, n):
        while len(self._buf) < n:
            if not self._fill():
                raise RequestUnreadable("the connection closed mid-body")
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def read_line(self, max_bytes=CHUNK_LINE_MAX):
        """One CRLF-terminated line, returned without its CRLF."""
        while True:
            idx = self._buf.find(b"\r\n")
            if idx != -1:
                line, self._buf = self._buf[:idx], self._buf[idx + 2:]
                return line
            if len(self._buf) > max_bytes:
                raise RequestUnreadable(
                    f"a line over {max_bytes} bytes is not one we read")
            if not self._fill():
                raise RequestUnreadable("the connection closed mid-line")

    def read_some(self):
        if self._buf:
            out, self._buf = self._buf, b""
            return out
        if not self._fill():
            return b""
        out, self._buf = self._buf, b""
        return out

    def peek_start(self, n=HTTP_START_MAX, until=None):
        """Up to n bytes from the front of the stream, LEFT where they are.

        Unlike every other read here this one does not consume: the caller is
        deciding whether the connection is worth handing to the parser, and the
        parser needs the bytes. They stay in this buffer, so the read_head that
        follows finds them without a second syscall -- there is no MSG_PEEK
        here and there does not need to be, because the buffer IS the peek.

        `until` is asked, after each read that added something, whether the
        bytes so far already settle whatever the caller is deciding; the first
        True ends the wait. Without it a peer that sends four bytes and then
        waits for us holds its slot for the whole decision timeout to answer a
        question that was answerable at byte four.

        A short read is not an error. This returns whatever arrived within the
        socket's own timeout, including b"", and swallows the two exceptions a
        fill raises rather than reporting them: everything it can go wrong on
        goes wrong again in the read_head immediately after, where the
        disposition for it already exists and is already counted. THE COST of
        that is one extra decision-timeout wait for a peer that completes a
        handshake and then says nothing at all -- five seconds of one of
        MAX_CONNECTIONS slots, not a leak, and the alternative is duplicating
        the loop's timeout and EOF arms here to save it.
        """
        while len(self._buf) < n:
            if until is not None and self._buf and until(self._buf):
                break
            try:
                if not self._fill():
                    break
            except RequestUnreadable:
                break
        return self._buf[:n]


def _reject_controls(text, what, *, tab_ok):
    """Refuse a control character in a field we will re-emit.

    THE BARE LF IS THE ONE THAT MATTERS. This head was framed on CRLF, so a
    lone \\n inside a header value or a request target survives the split and
    travels upstream inside the field it was written in -- and an origin that
    accepts bare-LF line endings, which many do, reads it as the start of a
    line. That is a whole second request line, smuggled past the per-request
    authorisation this plane exists to apply, with our own Host header standing
    in front of it.

    So it is refused, not stripped: a field with a line ending inside it has no
    reading both ends are guaranteed to share, and rewriting one into something
    harmless would be picking a reading. NUL, CR and the rest go with it for
    the same reason.
    """
    for ch in text:
        if ch == "\t" and tab_ok:
            continue
        if ch < " " or ch == "\x7f":
            raise RequestUnreadable(
                f"{what} carries the control character {ch!r}: a field with a "
                "line ending inside it is read as one field here and as two by "
                "anything that accepts bare LF")


def _split_head(head):
    """(start line, [(name, value)]) from a message head, or raise.

    Refusals, in order of how they are used against a proxy: non-ASCII, which
    is a second encoding of a name or a header; a control character in any
    field, which is a line ending that only one end of the path will see;
    obs-fold continuation lines, which let a header hide inside another's
    value; and whitespace before the colon, which some parsers accept as part
    of the name and others as the end of it.
    """
    try:
        text = head[:-4].decode("ascii")
    except UnicodeDecodeError:
        raise RequestUnreadable(
            "the head is not ASCII, so it is not one every parser on this "
            "path would read the same way") from None
    lines = text.split("\r\n")
    _reject_controls(lines[0], "the start line", tab_ok=False)
    headers = []
    for line in lines[1:]:
        _reject_controls(line, "a header line", tab_ok=True)
        if line[:1] in (" ", "\t"):
            raise RequestUnreadable(
                "an obs-fold continuation line lets a header hide inside "
                "another header's value")
        name, sep, value = line.partition(":")
        if not sep:
            raise RequestUnreadable(f"header line {line!r} has no colon")
        if not name or any(c not in _TOKEN_CHARS for c in name):
            raise RequestUnreadable(
                f"header name {name!r} is not a token")
        headers.append((name.lower(), value.strip(" \t")))
    return lines[0], tuple(headers)


def _split_response_head(head):
    """(status line, [(name, value)]) from a RESPONSE head. Lenient by design.

    The strict parser above is a defence against the GUEST's framing: every
    refusal in it names a way one message can be read as two by two parsers on
    the path. This head was written by an origin the workload's own policy
    authorised, and it is relayed to the guest VERBATIM -- so the reason to
    parse it at all is narrow: to learn where the body ends, which is what says
    whether the next request can be read from this connection.

    The request parser here would make the listener stricter than the web.
    A raw UTF-8 byte in a filename (`Content-Disposition: attachment;
    filename="cafe\u0301.pdf"`), a folded header, a header name with a byte
    outside tchar: each is something real servers emit, none of them changes
    where the body ends, and each would abort an authorised exchange as
    `relay failed` -- a dead connection on a request the policy allowed.

    So: latin-1, which cannot fail and preserves every byte's identity for the
    lowercase framing-name comparison; obs-fold joined into the value it
    continues, as RFC 7230 §3.2.4 says to treat it; and a line whose name is
    not a token dropped rather than raised on, since no framing header has a
    name like that and the line is relayed regardless. Control characters are
    still refused: a bare CR or LF inside a head is the one defect here that
    changes where a MESSAGE ends rather than where a field does.
    """
    text = head[:-4].decode("latin-1")
    lines = text.split("\r\n")
    _reject_controls(lines[0], "the status line", tab_ok=False)
    headers = []
    for line in lines[1:]:
        _reject_controls(line, "a response header line", tab_ok=True)
        if line[:1] in (" ", "\t"):
            if headers:
                name, value = headers[-1]
                headers[-1] = (name, (value + " " + line.strip(" \t")).strip())
            continue
        name, sep, value = line.partition(":")
        if not sep or not name or any(c not in _TOKEN_CHARS for c in name):
            continue
        headers.append((name.lower(), value.strip(" \t")))
    return lines[0], tuple(headers)


def _get_all(headers, name):
    return [v for n, v in headers if n == name]


def _is_count(text):
    """Whether `text` is a plain ASCII decimal `int()` will accept.

    NOT `str.isdigit()`, which is the obvious spelling and is wrong on the
    response path. That head is decoded latin-1 -- deliberately, so a raw byte
    in a filename cannot kill an authorised exchange -- and latin-1 carries the
    superscripts. `"\u00b2".isdigit()` is True and `int("\u00b2")` raises, so
    under isdigit a `Content-Length: \u00b2` or a status line of `\u00b200`
    would pass the guard and then raise ValueError out of a call site that
    catches RequestUnreadable and OSError: the connection thread dying with a
    traceback and no counter moving, in a file whose whole discipline is that
    every disposition is counted.

    The request side cannot reach that -- its head is decoded ASCII, so a
    non-ASCII byte is refused several steps earlier -- and uses this anyway.
    The guarantee that makes it safe lives two functions away, and a check
    written to depend on it is one refactor from being wrong.
    """
    return text.isascii() and text.isdigit()


def request_framing(headers):
    """Where the request body ends, by refusal rather than by preference.

    Every branch here is a smuggling class. Both headers present is the classic
    one -- one parser reads the length, the next reads the chunks, and the
    bytes between the two readings are a second request. This does not resolve
    it in favour of either; it declines the message.
    """
    lengths = _get_all(headers, "content-length")
    encodings = _get_all(headers, "transfer-encoding")
    if lengths and encodings:
        raise RequestUnreadable(
            "both Content-Length and Transfer-Encoding: which of the two says "
            "where the body ends is exactly what a smuggled request lives in")
    if encodings:
        if len(encodings) > 1 or encodings[0].strip().lower() != "chunked":
            raise RequestUnreadable(
                f"Transfer-Encoding {', '.join(encodings)!r} is not a single "
                "'chunked', and this relay implements no other coding")
        return Framing("chunked")
    if lengths:
        if len(lengths) > 1:
            raise RequestUnreadable(
                f"{len(lengths)} Content-Length headers: duplicates are "
                "refused whether or not they agree, because agreeing today "
                "makes the disagreeing case the untested path")
        value = lengths[0]
        if not _is_count(value):
            raise RequestUnreadable(
                f"Content-Length {value!r} is not a plain decimal count")
        return Framing("length", int(value))
    return Framing("none")


def is_http_request_start(start):
    """Whether these first bytes begin an HTTP/1.1 request line: True, False,
    or None for not enough bytes to say yet.

    Deliberately liberal, and deliberately not a second parser. It answers one
    question -- is this connection speaking HTTP at all -- and every reading
    that is still open stays open: a prefix that has not yet reached a space is
    undecided, and undecided is HTTP here, because the parser downstream has
    the whole request line and a 400 to say so with. Only a byte that no method
    is spelled with, or a run of them longer than any method is, is a no.

    WHY THIS EXISTS AT ALL. A spliced connection that is not HTTP is
    relayed and neither end notices. A terminated one has had its handshake
    completed by the listener, which is then the one reading, so a guest
    speaking anything else over 443 -- a database wire protocol, a tunnel,
    gRPC that ignored the ALPN it was offered -- is read as a request that
    will never arrive, and it holds a slot until the head ceiling or the
    clock ends it.
    Answering it 400 is worse than closing: those bytes are an HTTP response
    written into a protocol that is not HTTP, and what the peer makes of them
    is anyone's guess.

    THE METHOD ALPHABET is A-Z and the hyphen, which is what every registered
    method is spelled with. It is narrower than the token grammar a method is
    allowed to use, and that is the point: this is a heuristic that has to be
    wrong in the harmless direction, and its whole job is telling an ASCII
    request line from a binary first byte. An extension method in lowercase
    would be closed here rather than 400'd -- named, accepted, and cheap to
    widen if one ever turns up.
    """
    for i, ch in enumerate(start):
        if ch == 0x20:
            return i > 0            # a method, then the space that ends it
        if not (0x41 <= ch <= 0x5A or ch == 0x2D):
            return False
    # Ran out of bytes without a space. Undecided -- unless there were already
    # more of them than any method is long, in which case whatever is being
    # spelled is not one.
    return None if len(start) < HTTP_METHOD_MAX else False


def response_framing(status, method, headers):
    """Where a response body ends.

    The status and the request method come first and the headers second, in
    that order, because a HEAD response and a 304 both carry a Content-Length
    describing a body they do not send -- a relay that read the header before
    the status blocks forever on bytes that are never coming.
    """
    if method == "HEAD" or status in _BODYLESS_STATUSES or 100 <= status < 200:
        return Framing("none")
    encodings = _get_all(headers, "transfer-encoding")
    lengths = _get_all(headers, "content-length")
    if encodings and lengths:
        raise RequestUnreadable(
            "the origin framed its response both ways at once")
    if encodings:
        if len(encodings) > 1 or encodings[0].strip().lower() != "chunked":
            raise RequestUnreadable(
                f"response Transfer-Encoding {', '.join(encodings)!r} is not a "
                "single 'chunked'")
        return Framing("chunked")
    if lengths:
        if len(lengths) > 1 or not _is_count(lengths[0]):
            raise RequestUnreadable(
                "the origin's Content-Length is duplicated or not a count")
        return Framing("length", int(lengths[0]))
    # No framing header at all: the body ends when the connection does, and
    # this connection is therefore not reusable.
    return Framing("close")


def copy_chunked(src, dst):
    """Relay a chunked body, re-emitting each chunk header ourselves.

    Chunk extensions are dropped and trailers are dropped rather than
    forwarded: both are fields the guest writes after the head has been
    authorised, and neither is worth a second parser on this path.
    """
    while True:
        line = src.read_line()
        size_field = line.split(b";", 1)[0].strip()
        if not size_field or any(c not in b"0123456789abcdefABCDEF"
                                 for c in size_field):
            raise RequestUnreadable(
                f"chunk size {size_field!r} is not plain hex")
        size = int(size_field, 16)
        if size == 0:
            for _ in range(MAX_TRAILER_LINES):
                if not src.read_line():
                    break
            else:
                raise RequestUnreadable(
                    f"more than {MAX_TRAILER_LINES} trailer lines")
            dst.sendall(b"0\r\n\r\n")
            return
        # Streamed, never `read_exactly(size)`. The size is a hex number the
        # PEER writes, so reading a whole chunk into memory before forwarding
        # any of it lets one declared chunk set this process's footprint -- and
        # this process runs beside the workloads on the same host. The chunk
        # header goes out first and the bytes follow it in bounded pieces.
        dst.sendall(b"%x\r\n" % size)
        left = size
        while left:
            piece = src.read_exactly(min(left, RELAY_CHUNK))
            dst.sendall(piece)
            left -= len(piece)
        if src.read_exactly(2) != b"\r\n":
            raise RequestUnreadable("a chunk is not CRLF-terminated")
        dst.sendall(b"\r\n")


def copy_body(src, dst, framing):
    """Relay a body of the given framing. `dst` may be None to discard it."""
    if framing.kind == "none":
        return
    if framing.kind == "chunked":
        copy_chunked(src, _Discard() if dst is None else dst)
        return
    if framing.kind == "close":
        while True:
            data = src.read_some()
            if not data:
                return
            if dst is not None:
                dst.sendall(data)
        return
    left = framing.length
    while left:
        data = src.read_exactly(min(left, RELAY_CHUNK))
        left -= len(data)
        if dst is not None:
            dst.sendall(data)


class _Discard:
    """A bounded sink for a body being drained rather than relayed.

    Bounded because a chunked body has no length to check in advance: the
    ceiling has to be spent as the bytes arrive, or a guest answers a refusal
    with an endless body and the drain becomes the denial of service.
    """

    def __init__(self, limit=DRAIN_MAX):
        self._left = limit

    def sendall(self, data):
        self._left -= len(data)
        if self._left < 0:
            raise RequestUnreadable(
                f"a refused body over the {DRAIN_MAX}-byte drain ceiling")


def http_response(status, reason, *, close):
    """One refusal of ours, as an origin would write it: the status line,
    a `Date`, and the reason phrase as the whole body."""
    body = f"{reason}\n".encode()
    head = (f"HTTP/1.1 {status} {reason}\r\n"
            f"Date: {email.utils.formatdate(usegmt=True)}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: {'close' if close else 'keep-alive'}\r\n"
            "\r\n")
    return head.encode("ascii") + body


def drain(client, framing):
    """Read a refused request's body to its end. False if it was too much.

    Draining is a service to the connection, not an obligation: a guest
    that answers a refusal with a gigabyte gets the connection closed
    rather than the courtesy of having it all read.
    """
    if framing.kind == "none":
        return True
    if framing.kind == "length" and framing.length > DRAIN_MAX:
        return False
    try:
        copy_body(client, None, framing)
    except (RequestUnreadable, OSError):
        return False
    return True


def send_response(conn, status, reason, *, close):
    """Write one refusal to the guest, and nothing about why.

    The body is the status's own phrase. This process's responses reach
    the guest where an origin's would, so a sentence of ours in one -- a
    parser's refusal, a session bound to another name, a tool name -- is
    a guest learning in one request that its egress is mediated, and by
    what, before it has looked at a single certificate. The reason is in
    the journal line and the per-request record the caller writes, which
    the guest cannot read. `Date` is there because every origin sends one,
    and its absence would say the same thing.
    """
    try:
        conn.sendall(http_response(status, reason, close=close))
    except OSError:
        pass
