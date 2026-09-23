"""What leaves this host carrying a credential, decided without a socket.

The broker's request path as free functions: which of a caller's headers go
upstream and which are replaced, how a request is framed before any of it is
forwarded, and how an upstream response is re-framed on the way back. None
of it needs a connection to be decided, and as methods on the handler it was
reachable only by standing up a server with a TLS upstream -- which is how
the whole request path goes untested while config and identity are covered
three ways.

Used by `libexec/agent-broker`. Installed to /usr/libexec/workloadctl/broker_request.py.
"""

# Headers that are meaningful only for a single transport hop and must never be
# copied across one (RFC 9110 §7.6.1).
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
})

# Anything the guest sends that looks like a credential is dropped rather than
# forwarded. The guest has no legitimate reason to set these: we supply the
# credential, and letting a caller pass its own through would turn the broker
# into an open relay for whatever key a compromised sandbox happened to find.
#
# This list is not the whole story, and must not be treated as it: the
# configured `auth_header` is stripped too, by name, in forwarded_headers().
# These four are the ones worth dropping even when they are not the header this
# broker uses.
STRIP_FROM_REQUEST = frozenset({
    "authorization", "x-api-key", "api-key", "x-goog-api-key",
    "cookie", "host", "content-length",
})

# Dropped from a relayed response. Beyond the hop-by-hop set:
#
# `content-length` because this hop re-frames the body and declares its own --
# a streamed response goes back chunked, so the upstream's number would be a
# lie about a message it no longer describes.
#
# `date` and `server` are NOT here, and the handler stamps neither: they go
# back as the provider sent them. The inspector relays every other host's
# response head verbatim, so a brokered host that answered with a Server of
# its own would be the one host whose responses say something else stands
# in front of it -- the sandbox told it is one, on every brokered request.
DROP_FROM_RESPONSE = HOP_BY_HOP | {"content-length"}

# Read at most this much request body. Generous enough for a large context
# window, small enough that a runaway sandbox can't exhaust host memory.
MAX_REQUEST_BYTES = 64 * 1024 * 1024


def forwarded_headers(incoming, profile):
    """The headers to send upstream, given the ones the caller sent.

    The configured auth header is stripped by name as well as by the fixed
    list, and both are compared lowercased. The outgoing dict is keyed by
    whatever case the *caller* used, so a caller's `x-custom-key` and the
    broker's `X-Custom-Key` would otherwise be two keys, and the caller's
    value would go upstream beside the real credential.
    """
    strip = STRIP_FROM_REQUEST | HOP_BY_HOP | {profile.auth_header.lower()}
    headers = {k: v for k, v in incoming.items() if k.lower() not in strip}
    headers[profile.auth_header] = profile.auth_value
    headers["Host"] = profile.host
    return headers


def request_framing(path, headers):
    """(body length, rejection) for a request, before any of it is forwarded.

    A rejection is (status, log reason, client message); None means proceed.
    Every one of these closes the connection rather than reading on, because
    each means the body is either unread or unreadable and the stream can no
    longer be framed -- see _fail.

    The chunked case is the reason this exists. Transfer-Encoding is hop-by-hop
    and was stripped, and no Content-Length meant length 0, so a chunked request
    body was silently dropped and forwarded as empty: 200 OK, nothing logged,
    the provider seeing a request the caller did not send. Measured.
    """
    if not path.startswith("/"):
        # Absolute-form targets ("GET https://elsewhere/...") are how a client
        # asks a *proxy* to choose the destination. We are not a proxy.
        return 0, (400, "absolute-target",
                   "absolute request targets are not accepted\n")

    if headers.get("Transfer-Encoding"):
        return 0, (411, "chunked-request",
                   "chunked request bodies are not accepted; send "
                   "Content-Length\n")

    declared = headers.get_all("Content-Length") or []
    if len(declared) > 1:
        # Two lengths frame two different messages. Picking one (get() takes the
        # first) leaves the rest of the other in the socket, to be read as the
        # next request line -- the same desynchronisation the chunked case
        # produced, arrived at from the other direction. RFC 9112 §6.3 says
        # reject, and there is no legitimate sender to accommodate.
        return 0, (400, "duplicate-content-length",
                   "Content-Length appears more than once\n")

    raw = declared[0] if declared else None
    if raw is None or raw.strip() == "":
        return 0, None
    try:
        length = int(raw)
    except ValueError:
        return 0, (400, "bad-content-length",
                   "Content-Length is not a number\n")
    if length < 0:
        # int("-1") is not a size. Left unchecked it reached rfile.read(-1),
        # which reads to EOF -- so the handler blocked until the caller chose to
        # close, holding a slot for as long as it liked.
        return 0, (400, "bad-content-length",
                   "Content-Length is negative\n")
    if length > MAX_REQUEST_BYTES:
        return length, (413, "body-too-large", "request body too large\n")
    return length, None


def response_framing(status, headers, method="GET"):
    """(headers to pass back, declared length, whether a body is forbidden).

    A response to HEAD carries the headers a GET would have had and no
    body, so its Content-Length describes bytes that never follow. Framing
    it as a body -- or, with no length, as chunked with a terminator -- puts
    bytes on the wire the client reads as the start of the next response.
    """
    passthrough = [(k, v) for k, v in headers
                   if k.lower() not in DROP_FROM_RESPONSE]
    declared = next((v for k, v in headers if k.lower() == "content-length"), None)
    # 204 and 304 must not carry a body; framing them as chunked (even as a bare
    # terminator) is a protocol violation that strict clients reject.
    return passthrough, declared, (status in (204, 304)
                                   or method == "HEAD")
