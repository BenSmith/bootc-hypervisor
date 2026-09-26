"""The DNS wire format the synthesising responder speaks.

Pure bytes -> bytes: build_answer takes a query and a Policy and returns the
response with no I/O behind it, which is what lets TestFuzz feed it garbage
in bulk. The one line it prints per answer goes through `log`, which the serve
loop shares.

This module, like the responder it serves, contains no call that could reach a
nameserver: pack_address is inet_pton, never getaddrinfo, and
tests/test_vm_resolve.py TestNoUpstream parses this file to keep it that way.
"""
import socket
import struct

from customs.inspect_document import hostname_control_character, normalise_hostname

FLAG_QR = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200
FLAG_RD = 0x0100
FLAG_RA = 0x0080
OPCODE_MASK = 0x7800
OPCODE_QUERY = 0

RCODE_NOERROR = 0
RCODE_FORMERR = 1
# "the query was fine, we were not" -- see serve_datagram's catch-all.
RCODE_SERVFAIL = 2
RCODE_NOTIMP = 4

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1

HEADER = struct.Struct("!HHHHHH")
HEADER_LEN = HEADER.size

# The classic UDP answer budget. Nothing we emit approaches it -- a synthesised
# answer is one record -- but a static map entry for a name with many addresses
# could, and silently dropping records is the failure this bound exists to turn
# into a visible one. See build_answer: what does not fit is dropped WITH the
# truncate bit set, which sends the client to the TCP listener we also serve.
UDP_BUDGET = 512

# Bound on one TCP message, which carries its own 16-bit length prefix. A query
# is a question and an optional OPT; anything near the maximum is not one.
TCP_MAX = 4096


class Malformed(Exception):
    """The query could not be parsed far enough to answer it."""


class NotAQuery(Exception):
    """The message is a response. It gets no reply, not even an error: a
    responder that answers responses talks forever with another one, or
    with itself given its own address as the source.
    """


def log(msg):
    print(msg, flush=True)


def read_name(msg, offset):
    """Read a QNAME. Returns (name, next_offset).

    Compression pointers are refused rather than followed. A pointer in a
    QUESTION section is malformed -- there is nothing earlier in the message for
    it to point at -- and following one is how a parser is walked into a loop by
    a peer that controls every byte.
    """
    labels = []
    while True:
        if offset >= len(msg):
            raise Malformed("name runs past the end of the message")
        length = msg[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise Malformed("compression pointer in the question section")
        end = offset + length
        if end > len(msg):
            raise Malformed("label runs past the end of the message")
        labels.append(msg[offset:end])
        offset = end
    try:
        name = ".".join(l.decode("ascii") for l in labels)
    except UnicodeDecodeError:
        raise Malformed("non-ASCII label") from None
    # A label may legally carry any byte, including a bare LF -- and this name
    # is logged and written into the status document, where an LF ends the
    # record and makes the rest of it a second, fabricated entry. Refused at
    # the parse, so no log site has to remember; see
    # hostname_control_character. The character is named and the name is
    # not, so the refusal does not print what it is refusing.
    ch = hostname_control_character(name)
    if ch is not None:
        raise Malformed(
            f"label carries the control character {ch!r}, which forges a "
            f"line in this log")
    return normalise_hostname(name), offset


def encode_name(name):
    """Encode a name as length-prefixed labels. Empty name is the root."""
    out = bytearray()
    for label in name.split(".") if name else []:
        raw = label.encode("ascii")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def pack_address(text):
    """Wire form of an address literal, without a name-resolution call.

    inet_pton, never getaddrinfo: this program must contain no call that could
    consult a resolver, and getaddrinfo on a literal is still that call.
    """
    if ":" in text:
        return socket.inet_pton(socket.AF_INET6, text)
    return socket.inet_pton(socket.AF_INET, text)


# The tick on which the status file is replaced while the responder is idle.


def build_answer(query, policy, budget=None, counters=None):
    """Build the response to one query. Returns the full message bytes.

    `budget` bounds the message for UDP; None means unbounded (TCP).

    `counters` is optional so that every existing caller and test that only
    wants the bytes still gets them. A response is never shaped by whether
    anyone is counting.
    """
    if len(query) < HEADER_LEN:
        raise Malformed("shorter than a DNS header")
    ident, flags, qdcount, _an, _ns, _ar = HEADER.unpack(query[:HEADER_LEN])
    if flags & FLAG_QR:
        raise NotAQuery()

    # Echo the opcode back, and preserve RD. RA is set because from the client's
    # point of view recursion IS available -- every name is answered here, with
    # no referral and no "ask someone else" -- and a stub that sees RD honoured
    # with RA clear can decide the server is not usable for recursion and stop
    # asking it, which with a one-entry resolver list is the whole of DNS.
    opcode = flags & OPCODE_MASK
    base = FLAG_QR | opcode | FLAG_AA | FLAG_RA | (flags & FLAG_RD)

    if opcode != (OPCODE_QUERY << 11):
        # NOTIMP, not NODATA: an UPDATE or a NOTIFY is not a question about a
        # name, so there is no empty answer that means anything. No stub sends
        # one; this is here so an odd one gets a defined reply.
        return HEADER.pack(ident, base | RCODE_NOTIMP, 0, 0, 0, 0)
    if qdcount != 1:
        return HEADER.pack(ident, base | RCODE_FORMERR, 0, 0, 0, 0)

    name, offset = read_name(query, HEADER_LEN)
    if offset + 4 > len(query):
        raise Malformed("question is missing its type and class")
    qtype, qclass = struct.unpack("!HH", query[offset:offset + 4])
    question = query[HEADER_LEN:offset + 4]

    # No OPT of our own is emitted, for the reason workload-vm-resolve's docstring gives.
    # The query's OPT is simply not read: everything past the question is
    # ignored, which is well-formed behaviour for a server with no EDNS0
    # options to honour, and is the shape that cannot echo a malformed one.

    if qclass != CLASS_IN or qtype not in (TYPE_A, TYPE_AAAA):
        # NODATA: NOERROR, this question echoed, no records. Every type that is
        # not an address -- HTTPS, SVCB, TXT, PTR, MX, SRV, and a CHAOS-class
        # version.bind -- lands here.
        if counters is not None:
            counters.record_nodata()
        return HEADER.pack(ident, base | RCODE_NOERROR, 1, 0, 0, 0) + question

    addresses, source = policy.answers(name, qtype)

    records = bytearray()
    count = 0
    truncated = False
    header_and_question = HEADER_LEN + len(question)
    for text in addresses:
        rdata = pack_address(text)
        # 0xC00C: the answer's NAME as a pointer to the question's, which is at
        # offset 12 in every message we build. Standard, and it keeps a
        # multi-address answer inside the UDP budget that a repeated name would
        # not.
        record = struct.pack("!HHHIH", 0xC00C, qtype, CLASS_IN,
                             policy.ttl, len(rdata)) + rdata
        if budget is not None and \
                header_and_question + len(records) + len(record) > budget:
            truncated = True
            break
        records += record
        count += 1

    if counters is not None:
        counters.record_answer(name, source, count, policy.on_a_list(name))
    flags_out = base | RCODE_NOERROR | (FLAG_TC if truncated else 0)
    log(f"  {name or '.'} {'AAAA' if qtype == TYPE_AAAA else 'A'} -> "
        f"{source}: {count} record(s)"
        + (" (truncated; retry over TCP)" if truncated else ""))
    return (HEADER.pack(ident, flags_out, 1, count, 0, 0) + question
            + bytes(records))


def error_response(query, rcode):
    """A minimal header-only reply, for a query too malformed to echo.

    Best-effort on the id: if there are not even two bytes, there is nothing to
    reply to and the caller drops it instead.
    """
    ident = struct.unpack("!H", query[:2])[0]
    return HEADER.pack(ident, FLAG_QR | rcode, 0, 0, 0, 0)
