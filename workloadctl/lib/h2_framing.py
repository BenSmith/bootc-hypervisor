"""h2_framing: HTTP/2, as far as a relay that decodes nothing can check it.

The shallowest framing there is. A guest reaching a host that policy marks
`http2` is relayed as opaque bytes, so what can be checked is only that the
stream keeps the shape h2 requires: the 24-byte connection preface, a
SETTINGS frame first on stream 0, and thereafter that every byte falls
inside a frame whose header was well-formed. `H2Framing` accounts for that
and raises NotH2 the moment the stream stops looking like h2; the listener
declines the connection. Nothing here decodes a frame's payload.

The HTTP/1.1 half -- where a message ends, by refusal -- is http_framing.
"""

# The HTTP/2 connection preface (RFC 9113 §3.4): the exact 24 bytes every h2
# client sends before its first frame, chosen by the RFC to be something an
# HTTP/1.1 server cannot mistake for a request.
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# A frame header is 9 bytes: 24-bit length, 8-bit type, 8-bit flags, 32-bit
# stream id.
H2_FRAME_HEADER = 9


# The frame type every connection must open with after the preface, on stream
# 0 (RFC 9113 §3.4: "The server connection preface consists of a potentially
# empty SETTINGS frame ... the client sends ... a SETTINGS frame").
H2_FRAME_SETTINGS = 0x4


class NotH2(Exception):
    """A connection on an [[vm.network.http2]] host is not speaking h2."""


class H2Framing:
    """Whether a guest's byte stream continues to look like HTTP/2 framing.

    WHAT THIS IS FOR, and it is one thing. `[[vm.network.http2]]` names a host
    whose stream is relayed without being decoded, so without this the key
    means EXEMPT rather than SPEAKS H2: a guest reaches a full policy opt-out
    on any host an operator listed for performance, by writing different first
    bytes. That is the same shape as the non-HTTP fallback HLD §8 removed, and
    it was missed the first time for the same reason -- the entry reads as
    naming a protocol when what it names is a hole.

    WHAT ACTUALLY BINDS, stated plainly because the ratio is not obvious and a
    later reader will otherwise trust this further than it goes:

    - The PREFACE does nearly all of the work. Twenty-four fixed bytes, checked
      before this class is fed anything, and every protocol that is not h2 --
      HTTP/1.1, a database wire protocol, a raw tunnel -- fails on byte one.
    - The FIRST FRAME must be SETTINGS on stream 0, which RFC 9113 §3.4
      requires and which no non-h2 sender produces by accident.
    - Continuous framing catches very little on its own, and pretending
      otherwise would be the mistake. The length field is 24 arbitrary bits, so
      almost ANY byte string parses as a sequence of frames: `GET /secr` reads
      as a frame announcing a 4.6MB payload, and there is nothing to object to
      until the connection ends short of it. So mid-session the guarantee is
      ALIGNMENT AT CLOSE, not refusal in flight -- the connection is counted
      and named, and the bytes have already been relayed. This is not a
      conformance checker and must not be described as one; closing that
      residual means decoding frames properly, which is §16's work.

    Nothing is decoded, nothing is rewritten, stream ids are untouched and the
    dynamic table stays end-to-end -- so §16's HPACK decoder lands on top of
    this rather than replacing it, and the relay stays exactly what §8 says it
    is.
    """

    def __init__(self):
        self._header = bytearray()
        self._payload = 0
        self._first = True

    def feed(self, data: bytes) -> None:
        """Account for bytes going guest -> origin. Raises NotH2."""
        i, n = 0, len(data)
        while i < n:
            if self._payload:
                take = min(self._payload, n - i)
                self._payload -= take
                i += take
                continue
            take = min(H2_FRAME_HEADER - len(self._header), n - i)
            self._header += data[i:i + take]
            i += take
            if len(self._header) < H2_FRAME_HEADER:
                return                  # a header split across two reads
            length = int.from_bytes(self._header[:3], "big")
            kind = self._header[3]
            # The top bit is reserved and receivers must ignore it, so it is
            # masked off rather than refused -- a sender setting it is not
            # something this may fail a connection over.
            stream = int.from_bytes(self._header[5:9], "big") & 0x7FFFFFFF
            self._header.clear()
            if self._first:
                self._first = False
                if kind != H2_FRAME_SETTINGS or stream != 0:
                    raise NotH2(
                        f"the first frame after the preface is type {kind:#04x} "
                        f"on stream {stream}, and RFC 9113 requires SETTINGS on "
                        f"stream 0")
                if length % 6:
                    raise NotH2(
                        f"the opening SETTINGS frame is {length} bytes, which "
                        f"is not a whole number of 6-byte settings")
            self._payload = length

    @property
    def aligned(self) -> bool:
        """Whether the stream ended on a frame boundary.

        A peer that stops mid-frame was either not framing at all or was cut
        off; either way the connection did not end where h2 says it should, and
        a relay that only ever checked the first frame would carry anything at
        all after it.
        """
        return not self._payload and not self._header
