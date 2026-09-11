"""
http_request: one request head, parsed to the form the inspect listener emits.

`parse_request` is where the pieces meet: the head is split by
`http_framing`, the target and authority are reduced by `http_target` to the
one name policy is matched against, the body's framing is decided, and the
result is a `Request` the listener authorises and -- if it passes --
`rebuild_request` turns back into bytes. Those bytes are OUR framing and the
name we authorised, never the guest's head forwarded verbatim: two parsers
cannot disagree about a length one of them wrote.

The one place the strip-and-recompute rule reaches past framing is an
`Upgrade` offer, which is re-emitted from the value `_upgrade_offer`
recognised -- and never for `h2c`, which would move the rest of the
connection onto frames this relay cannot read.
"""

from typing import NamedTuple

from http_framing import (
    _TOKEN_CHARS, Framing, RequestUnreadable, _get_all, _split_head,
    request_framing,
)
from http_target import SCHEME_HTTP, host_from_authority, normalise_target

class Request(NamedTuple):
    """One request head, parsed and normalised to the form we will emit."""

    method: str
    target: str        # always origin-form by the time this exists
    version: str
    authority: str     # what our Host header will say, port included
    host: str          # the normalised name the policy is matched against
    headers: tuple     # (name, value) as the guest wrote them
    framing: Framing
    expects_continue: bool
    wants_close: bool
    upgrade: str = ""   # the Upgrade value to re-emit, "" for an ordinary request

    @property
    def path(self) -> str:
        """The target's path ALONE, which is what `paths` is matched against.

        The query is deliberately not part of it (§3, and normalise_path says
        so at length): matching the full target makes `paths = ["/v1/messages"]`
        fail on `/v1/messages?stream=true`, a legitimate request denied for a
        reason the operator cannot see anywhere in their config.
        """
        return self.target.partition("?")[0]


# Headers we never forward: the hop-by-hop names, plus the two framing headers,
# which are re-emitted from what we computed, plus Host, which is re-emitted as
# the name we authorised.
#
# A FIXED LIST, NOT RFC 9110 §7.6.1's. That section says the names to drop are
# the ones the message's own `Connection` header lists, which is a set the GUEST
# writes; this is the standing set those names are drawn from in practice. The
# difference is real and is accepted: a guest sending `Connection: x-custom`
# has `x-custom` forwarded rather than stripped. It buys nothing here -- every
# framing decision on this path is recomputed by request_framing and re-emitted
# by rebuild_request, so a header the origin does not recognise is a header the
# origin ignores -- and honouring the dynamic list would mean letting guest
# input decide which of OUR headers survive. Named so the citation cannot be
# read as a claim this implements it.
_NOT_FORWARDED = frozenset((
    "host", "content-length", "transfer-encoding", "connection",
    "proxy-connection", "keep-alive", "te", "trailer", "upgrade", "expect",
))


# Protocol names we will not carry an upgrade to. An `h2c` upgrade moves the
# rest of the connection onto HTTP/2, whose requests are HPACK-compressed
# frames this relay cannot read -- so forwarding one would hand the guest a
# way to opt out of per-request authorisation entirely, which is the property
# the terminating plane exists to provide. ADR 008 leaves HTTP/2 open as a
# capability to buy deliberately, and this is the line that keeps it from
# arriving by accident in the meantime.
_UPGRADE_REFUSED = frozenset(("h2", "h2c"))


def _upgrade_offer(headers, tokens, version):
    """The Upgrade value to forward, or "" for a request that is not one.

    "" covers three different things and deliberately does not distinguish
    them, because they all mean the same to the origin: not an upgrade at all,
    an upgrade this relay will not carry, and an upgrade on HTTP/1.0 (where the
    mechanism does not exist). In each case the request goes upstream as the
    ordinary HTTP/1.1 request it also is, the origin does not switch protocols,
    and the exchange completes normally -- which is the behaviour RFC 9110
    already defines for a server that declines an offer, not a silent breakage.
    """
    if version != "HTTP/1.1" or "upgrade" not in tokens:
        return ""
    offered = [v.strip() for v in _get_all(headers, "upgrade") if v.strip()]
    joined = ", ".join(offered)
    for entry in joined.split(","):
        name = entry.strip().split("/", 1)[0].strip().lower()
        if name in _UPGRADE_REFUSED:
            return ""
    return joined


def parse_request(head, scheme=SCHEME_HTTP):
    """A Request from a request head, normalised and framed, or raise."""
    start, headers = _split_head(head)
    parts = start.split(" ")
    if len(parts) != 3:
        raise RequestUnreadable(
            f"request line {start!r} is not three space-separated fields")
    method, target, version = parts
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        raise RequestUnreadable(f"{version!r} is not a version we relay")
    if not method or any(c not in _TOKEN_CHARS for c in method):
        raise RequestUnreadable(f"method {method!r} is not a token")
    target, authority = normalise_target(method, target, scheme)
    if authority is None:
        hosts = _get_all(headers, "host")
        if len(hosts) != 1:
            raise RequestUnreadable(
                f"{len(hosts)} Host headers: with no absolute-form authority "
                "there is exactly one name that could authorise this request")
        authority = hosts[0]
    # The port is dropped from what we emit: it is either absent or the port we
    # are on, so the canonical spelling is the bare name -- and the name is
    # what was authorised.
    host = host_from_authority(authority.strip().lower(), scheme).host
    connection = ",".join(_get_all(headers, "connection")).lower()
    tokens = {t.strip() for t in connection.split(",")}
    wants_close = "close" in tokens or (
        version == "HTTP/1.0" and "keep-alive" not in tokens)
    expects = [v.strip().lower() for v in _get_all(headers, "expect")]
    if expects and expects != ["100-continue"]:
        raise RequestUnreadable(
            f"Expect {', '.join(expects)!r} is an expectation this relay "
            "cannot honour")
    return Request(
        method=method, target=target, version=version, authority=host,
        host=host, headers=headers, framing=request_framing(headers),
        expects_continue=bool(expects) and version == "HTTP/1.1",
        wants_close=wants_close,
        upgrade=_upgrade_offer(headers, tokens, version))


def rebuild_request(req):
    """The bytes we send upstream: OUR framing, and the name we authorised.

    Not the guest's head forwarded verbatim. Two parsers cannot disagree about
    a length one of them wrote, so the framing headers are dropped and re-
    emitted from the Framing we computed, and Host is re-emitted as the
    authority that was actually matched -- which for an absolute-form request
    is not what the guest's Host header said.

    THE NAMES GO UPSTREAM LOWERCASED, as a consequence of _split_head folding
    them for its own comparisons. Field names are case-insensitive, so this is
    legal and nothing that reads HTTP properly can tell -- but an origin with a
    hand-rolled parser that string-matches `Content-Type` can, and the symptom
    is a request that works direct and fails inspected. Named here and in
    docs/vm-egress-walkthrough.md rather than repaired: preserving the guest's
    spelling would mean carrying a second copy of every name purely to write it
    back, and the case where that matters is an origin already outside the spec.
    """
    lines = [f"{req.method} {req.target} {req.version}",
             f"Host: {req.authority}"]
    lines += [f"{name}: {value}" for name, value in req.headers
              if name not in _NOT_FORWARDED]
    if req.framing.kind == "length":
        lines.append(f"Content-Length: {req.framing.length}")
    elif req.framing.kind == "chunked":
        lines.append("Transfer-Encoding: chunked")
    # AN UPGRADE OFFER IS RE-EMITTED, NOT DROPPED, and this is the one place the
    # strip-and-recompute rule reaches past framing. `Upgrade` and `Connection`
    # are both in _NOT_FORWARDED -- correctly, since a guest must not choose
    # which of our headers survive -- and for one rung that meant every upgrade
    # request reached the origin with the offer removed, so no origin could
    # ever answer 101 and the whole relay-after-101 path below it was
    # unreachable. ADR 008 records upgrades as SUPPORTED behaviour (police the
    # request as ordinary HTTP, relay opaquely afterwards), so the offer is put
    # back here -- from the value _upgrade_offer recognised, never from the
    # guest's own bytes, which is what keeps this a recompute rather than a
    # forward.
    if req.upgrade:
        lines.append(f"Upgrade: {req.upgrade}")
        lines.append("Connection: upgrade")
    else:
        # The guest's own version goes upstream, and an HTTP/1.0 request is not
        # offered keep-alive. Speaking 1.1 upstream on a 1.0 guest's behalf
        # invites a `Transfer-Encoding: chunked` response, and the head is
        # relayed verbatim -- so a client that has never heard of chunked would
        # be handed a chunked body. The version is the one field that decides
        # that, so it is the guest's.
        lines.append("Connection: close" if req.version == "HTTP/1.0"
                     else "Connection: keep-alive")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
