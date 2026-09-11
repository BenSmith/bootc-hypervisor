"""
http_target: what a request target and an authority NAME, in one canonical form.

The request target the inspect listener acts on IS normalised here --
percent-decoding, dot-segment resolution, duplicate-slash collapsing -- and
the normalised form is what goes upstream. Rung 2 deferred this to rung 4 on
the reasoning that there was no `paths` rule for it to matter to yet, and that
was the wrong half of the problem to look at. Normalisation is not a service
to a matcher; it is the claim that the string the listener acts on and the
string the origin acts on are the same string. That claim has to be TRUE
BEFORE a matcher exists, or the matcher arrives already reading a different
path from the one being fetched -- and the day it arrives is the worst
possible day to find out. See normalise_path for what is normalised, what is
deliberately not (the query, `;params`, a trailing `/`), and why each.

The same applies to the two other places a guest names a destination: the
authority (`Host`, or an absolute-form target) and a redirect's `Location`.
Each is reduced to the one name the policy is matched against, for the plane
the request arrived on -- `Scheme` says which port that plane is, so that
`Host: example.com:443` is the ordinary spelling on one and misdirected on
the other.
"""

from typing import NamedTuple

from config_parser import normalise_hostname
from egress_plane import CLEARTEXT, TLS
from http_framing import RequestUnreadable

class Scheme(NamedTuple):
    """Which plane a request is being read on, for the two parsers that care.

    The request parser is shared by the cleartext plane and the terminated TLS
    one, and two of its refusals are plane-specific: the absolute-form scheme it
    accepts, and the port an authority may name. Both are refusals about
    reaching a destination neither end is on, so both have to know which port
    this end IS -- hard-coding 80 in a parser the terminated plane also uses
    would refuse `Host: example.com:443` as a misdirected request when it is the
    ordinary spelling there.
    """

    name: str
    port: int


SCHEME_HTTP = Scheme("http", CLEARTEXT.guest_port)
SCHEME_HTTPS = Scheme("https", TLS.guest_port)


# The characters RFC 3986 says a percent-encoding of is equivalent to the
# character itself, so decoding one changes nothing and NOT decoding one leaves
# two spellings of the same path for a matcher to disagree about.
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

_HEX = frozenset("0123456789abcdefABCDEF")


def _decode_unreserved(path):
    """A path with unreserved percent-encodings decoded and the rest kept.

    THE ENCODED SLASH IS REFUSED, and that is the whole reason this function is
    not three lines of urllib. `%2f` has two readings -- an opaque byte inside a
    segment, or a separator -- and real origins are split between them. Decode
    it and `..%2f..%2f` becomes a traversal we then resolve on the guest's
    behalf; keep it opaque and we match a pattern against a path the origin will
    read as one segment deeper. Neither is a reading this listener is entitled
    to pick, so the request is declined, in the same voice as the framing
    refusals above: a message two parsers on the path read differently is not
    one we relay.

    `%2e` is a different case and IS decoded: `.` is unreserved, the decoding is
    equivalence rather than a choice, and the dot-segment resolution downstream
    is then applied to the same path the origin will resolve. That is the
    `%2e%2e%2f` case closed, from the other end -- the dots become dots, and the
    slash that would have joined them is gone before them.

    Everything else percent-encoded stays encoded, spelled in UPPERCASE hex so
    one path has one form. Non-ASCII travels as the bytes it was written as.
    """
    out = []
    i = 0
    while i < len(path):
        ch = path[i]
        if ch != "%":
            out.append(ch)
            i += 1
            continue
        digits = path[i + 1:i + 3]
        if len(digits) != 2 or digits[0] not in _HEX or digits[1] not in _HEX:
            raise RequestUnreadable(
                f"{path[i:i + 3]!r} in the request target is not a percent "
                "escape, and a target with a stray % in it is read one way "
                "here and another by anything that repairs it")
        value = int(digits, 16)
        decoded = chr(value)
        if decoded == "/":
            raise RequestUnreadable(
                "an encoded slash in the request target: whether it separates "
                "two segments or sits inside one is a question origins answer "
                "differently, so it is not a path this can authorise")
        if decoded in _UNRESERVED:
            out.append(decoded)
        else:
            out.append("%" + digits.upper())
        i += 3
    return "".join(out)


def _resolve_dot_segments(path):
    """A path with `.` and `..` resolved and empty segments collapsed.

    The motivating case is a matcher that does not exist yet:
    `/repos/myorg/../../secret` matches `paths = ["/repos/myorg/*"]` and arrives
    at the origin as `/secret`. Resolving BEFORE the match, and sending what was
    resolved, is what makes the string a policy is written against the string
    the origin acts on.

    A `..` at the root is discarded rather than refused, which is what RFC 3986
    prescribes and what every origin does. TRAILING SLASH IS SIGNIFICANT and is
    preserved: `/a` and `/a/` are different resources to most origins, so
    normalising one into the other would change which one is fetched. A
    trailing `.` or `..` produces one, again per RFC 3986.
    """
    segments = path.split("/")
    trailing = segments[-1] in ("", ".", "..")
    out = []
    for segment in segments:
        if segment in ("", "."):
            continue                    # collapses `//` in the same pass
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    return "/" + "/".join(out) + ("/" if trailing and out else "")


def normalise_path(path):
    """The canonical form of an origin-form path, or raise.

    ONE PLACE, on purpose. A path that is decoded here, resolved there and
    matched somewhere else is a path with three forms, and the gap between any
    two of them is where a traversal lives. Everything that has an opinion about
    what this request addresses -- the `paths` matcher arriving at rung 4, the
    log line, and the bytes sent upstream -- reads the string this returns.

    THE QUERY IS NOT PART OF IT and is carried through untouched. Both readings
    are defensible and silence picks the worse one: matching the full target
    makes `paths = ["/v1/messages"]` fail on `/v1/messages?stream=true`, a
    legitimate request denied for a reason an operator cannot see in their
    config. Nor is the query normalised -- `%26` and `&` are different
    parameters, so decoding there is not equivalence. A policy that needs to
    constrain a query wants a key of its own.

    `;params` are left inside their segment for the same reason: stripping them
    is a legacy reading, and this listener does not get to decide that the
    origin shares it.
    """
    if "#" in path:
        raise RequestUnreadable(
            "a fragment in the request target: it is not part of what is sent "
            "to an origin, and a parser that keeps it addresses a different "
            "resource from one that drops it")
    path, sep, query = path.partition("?")
    return _resolve_dot_segments(_decode_unreserved(path)) + sep + query


def normalise_target(method, target, scheme=SCHEME_HTTP):
    """(origin-form target, authority or None) for a request target, or raise.

    Absolute-form is legal HTTP/1.1 and moves the authorising name OUT of the
    Host header, which RFC 9110 §7.2 then says to ignore. Left alone, that one
    line of guest input defeats both the Host read that authorises here and the
    `paths` match arriving at rung 4. So it is normalised to origin-form and
    its authority becomes the name we authorise -- or the request is refused.
    """
    if method == "CONNECT":
        raise RequestUnreadable(
            "CONNECT on the cleartext plane: this listener is transparent, so "
            "a guest reaching it believes it is talking to an origin and has "
            "no proxy to tunnel through")
    if target.startswith("/"):
        return normalise_path(target), None
    if target == "*":
        raise RequestUnreadable(
            "an asterisk-form target names no resource to authorise")
    got, sep, rest = target.partition("://")
    if not sep or got.lower() != scheme.name:
        raise RequestUnreadable(
            f"request target {target!r} is neither origin-form nor an "
            f"{scheme.name} absolute-form URI")
    # The authority ends at the FIRST of these three, not at the first slash: a
    # query or a fragment can carry a slash of its own, and splitting on that
    # one puts half the query into the name we are about to authorise.
    cut = min((i for i in (rest.find("/"), rest.find("?"), rest.find("#"))
               if i != -1), default=-1)
    if cut == -1:
        authority, path = rest, "/"
    elif rest[cut] == "/":
        authority, path = rest[:cut], rest[cut:]
    else:
        authority, path = rest[:cut], "/" + rest[cut:]
    if "@" in authority:
        raise RequestUnreadable(
            "userinfo in the request target: parsers disagree about where the "
            "host in it begins, which is the whole of its use here")
    if not authority:
        raise RequestUnreadable("an absolute-form target with no authority")
    return normalise_path(path), authority


class Authority(NamedTuple):
    """An authority split into the name policy matches and the port it named."""

    host: str
    port: str          # "" when the authority carried none


def host_from_authority(authority, scheme=SCHEME_HTTP):
    """The name and port in an authority, or raise."""
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise RequestUnreadable(
                f"authority {authority!r} opens a bracketed literal and never "
                "closes it")
        host, rest = authority[:end + 1], authority[end + 1:]
        if rest and not rest.startswith(":"):
            raise RequestUnreadable(
                f"authority {authority!r} has trailing bytes after its "
                "bracketed literal")
        port = rest[1:]
    elif authority.count(":") > 1:
        raise RequestUnreadable(
            f"authority {authority!r} has several colons and no brackets, so "
            "where its port begins is a guess")
    else:
        host, _, port = authority.partition(":")
    host = normalise_hostname(host)
    if not host:
        raise RequestUnreadable(f"authority {authority!r} names no host")
    # A plane is reached by a redirect keyed on one dport and it dials that
    # same port, so an authority naming any other port describes a destination
    # that is not the one either end is on. Refused rather than ignored: the
    # alternative is authorising and dialling one thing while telling the
    # origin another, which is how a vhost decision gets made on a port nobody
    # connected to.
    if port not in ("", str(scheme.port)):
        raise RequestUnreadable(
            f"authority {authority!r} names port {port!r}, but this plane "
            f"only ever reaches port {scheme.port}")
    return Authority(host, port)


def redirect_target(location, scheme=SCHEME_HTTP):
    """(host, path) a Location header names, or (None, None) for neither.

    A relative Location -- the common case -- names no host and is not a
    redirect off this origin, so it is None rather than a refusal. So is
    anything this cannot read: the only thing built on the answer is a log line,
    and a parse failure there must never become a failed response.

    Any scheme is read, not just this plane's: a redirect from http to https is
    ordinary, and the name is the question, not the scheme it is reached over.

    The path comes back NORMALISED BY THE REQUEST PARSER'S OWN FUNCTION, and
    that is the point of returning it at all. What is built on it is a
    prediction of the verdict the guest's next connection will get, so it has
    to be the same string that connection will be judged on; a path normalised
    differently here would produce a note that disagrees with the 403 it is
    meant to explain. A path this cannot normalise comes back None -- there is
    then no prediction to make, which is not the same as predicting no refusal.
    """
    text = location.strip()
    got, sep, rest = text.partition("://")
    if not sep or not got or "/" in got:
        return None, None
    # The authority ends at the FIRST of these three, not at the first slash --
    # the same cut `normalise_target` makes and for the same reason: a query or
    # a fragment can carry a slash, and splitting on that one puts half the
    # query into the name.
    cut = min((i for i in (rest.find("/"), rest.find("?"), rest.find("#"))
               if i != -1), default=-1)
    if cut == -1:
        authority, path = rest, "/"
    elif rest[cut] == "/":
        authority, path = rest[:cut], rest[cut:]
    else:
        # A query or fragment with no path before it: the resource is the root.
        # The query is dropped either way, because `paths` matches the path
        # alone -- the same rule the request side applies.
        authority, path = rest[:cut], "/"
    if not authority:
        return None, None
    # Port-agnostic on purpose: `host_from_authority` refuses a port this plane
    # does not reach, which is right for a request being authorised and wrong
    # for a name being reported. Strip it first.
    try:
        host = host_from_authority(authority, Scheme(got.lower(), 0)).host
    except RequestUnreadable:
        head = authority.rsplit(":", 1)[0]
        try:
            host = host_from_authority(head, Scheme(got.lower(), 0)).host
        except RequestUnreadable:
            return None, None
    path = path.split("#", 1)[0].split("?", 1)[0]
    try:
        return host, normalise_path(path)
    except RequestUnreadable:
        return host, None


def redirect_host(location, scheme=SCHEME_HTTP):
    """The host a Location header names, or None when it names none."""
    return redirect_target(location, scheme)[0]
