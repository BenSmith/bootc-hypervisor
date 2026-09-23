"""The inspector's policy document, as the listener holds it.

`load_policy` reads the JSON document and returns a `Policy`: one
workload's inspection lists, read once at start and never edited after, so
that an edited document applies on a restart and the running policy is
always the file's. The questions the listener asks of it -- does this host
get through, is it spliced, is it h2, which policy entry governs it -- are
answered with the same hostname rule and the same entry matcher the render
side uses, both imported from inspect_document so the two cannot diverge.

The renderer is egress_policy, and this module does not import it: the
document is the whole interface, and a reader that imported its writer
would drag the config grammar into the listener's closure. What is shared
lives one rung below both, in inspect_document.

Installed to /usr/libexec/workloadctl/inspect_policy.py.
"""

import json
from typing import NamedTuple

from inspect_document import (
    TLS_DEFAULT,
    TLS_MODES,
    hostname_match,
    inspect_policy_digest,
    normalise_hostname,
    patterns_overlap,
    policy_governs,
    VmPolicyEntry,
)


class Policy(NamedTuple):
    """One workload's inspection lists, as read at start.

    `hosts` is a tuple, not a list, because nothing may edit it after load: the
    recovery contract is that an edited list applies on a RESTART, and a
    listener that could mutate its own policy would make the restart optional
    and the running policy unknowable from the file.

    `internal` is the [[vm.network.internal]] host names, and it admits
    nothing. The kernel's wl_internal_ok4/6 elements are the one enforcement
    point; this copy exists so a failed dial into private space can be
    attributed to the wildcard trap rather than to a host that is down. See
    vm_inspect_policy.
    """

    tls: str
    hosts: tuple
    internal: tuple = ()
    splice: tuple = ()
    http2: tuple = ()
    policy: tuple = ()
    # The digest of the document text this was parsed from, echoed into the
    # status file so `diagnose` can tell a listener enforcing the file on disk
    # from one enforcing an older one it still holds in memory. Defaulted so
    # every Policy() a test constructs by hand keeps working; the empty string
    # reads downstream as "this listener does not report a digest", which is a
    # state the check is required to pass over in silence anyway.
    digest: str = ""

    @property
    def summary(self) -> str:
        return (f"tls={self.tls} hosts={len(self.hosts)} "
                f"internal={len(self.internal)} splice={len(self.splice)} "
                f"http2={len(self.http2)} policy={len(self.policy)}")

    def admits(self, host: str) -> bool:
        """Whether this name is on a list at all -- the CONNECTION question.

        Asked at the front of a TLS connection, where there is no request yet
        and the only thing known is the name in the ClientHello. A `policy`
        entry allowlists its own host (§3: a name in `policy` need not also
        appear in `hosts`), so a workload whose entire allowlist is written as
        policy entries has to be admitted here -- otherwise the connection dies
        before the request the rules were written about ever exists, and the
        operator sees `not allowlisted` for a host their file plainly names.
        """
        return (hostname_match(host, self.hosts)
                or bool(policy_governs(host, self.policy)))

    def permits(self, host: str, method: str, path: str) -> bool:
        """Whether one request is authorised -- §3's composition rule.

        A host ANY policy entry matches is governed by those entries alone and
        `hosts` is not consulted for it; a host no entry matches is allowed by
        `hosts` with no method or path constraint. The rule is not "union the
        two lists", and the difference is the whole feature: under the union
        reading one wildcard in `hosts` written for an unrelated reason
        contributes "any method, any path" to every host it covers, silently
        removing the restriction somebody wrote a policy entry for.

        Among the governing entries it is union, not precedence: every entry
        permits something or does nothing, so REORDERING THE FILE CANNOT
        CHANGE WHAT IS ALLOWED. Two consequences follow and both look like
        bugs: a narrower entry cannot carve an exception out of a wider one,
        and a specific entry does not override a general one.
        """
        governing = policy_governs(host, self.policy)
        if governing:
            return any(e.permits(method, path) for e in governing)
        return hostname_match(host, self.hosts)

    def governs(self, host: str) -> bool:
        """Whether ANY policy entry names this host.

        Not "whether the request was permitted" -- this is asked where there is
        no request to permit, about a connection that turned out not to carry
        HTTP at all. It answers the operator's question instead: are there
        `methods` and `paths` here that never got to run?
        """
        return bool(policy_governs(host, self.policy))

    def splices(self, host: str) -> bool:
        """Whether this host is exempt from termination.

        True on the whole-workload mode as well as the per-host list, so that
        every caller asks one question. Splitting it -- `tls == "splice"` in
        one place and a list check in another -- is how a path gets one of the
        two and reads correct: the connection is spliced by the mode and
        terminated by the list, or the reverse, depending on which branch it
        took.

        NEVER A HOST A POLICY ENTRY GOVERNS. A spliced connection is never
        decrypted, so its entry's `methods` and `paths` would never run, and
        a restriction that is silently not applied is the one failure this
        reader exists to rule out. load_policy refuses a document whose
        `splice` and `policy` overlap; this is the half of that rule that
        holds for the names the overlap test cannot see (two wildcards), and
        it settles them by inspecting.
        """
        if self.tls == "splice":
            return True
        return (hostname_match(host, self.splice)
                and not self.governs(host))

    def speaks_h2(self, host: str) -> bool:
        """Whether this host is offered h2 and relayed at the frame level.

        Asked only of a host that is being TERMINATED, and it does not ask
        about the mode: under `tls = "splice"` no ALPN of ours is offered on
        any connection, so a listener that consulted this there would be
        answering a question nothing had asked. load_policy accepts `http2`
        entries under that mode for the same reason it accepts `splice` ones
        -- they ask for something already true -- so this list is populated
        and inert, and the one caller reaches it only past a `splices()`
        check.

        Never a host a policy entry governs, for the reason `splices` gives:
        an h2 session is relayed with its headers HPACK-compressed, so there
        is no request line for `methods` and `paths` to match.
        """
        return hostname_match(host, self.http2) and not self.governs(host)

    def credential_for(self, host: str):
        """The credstore NAME this host's requests are brokered with, or None.

        Asked once per authorised request, and it decides only WHERE the
        request is sent -- to this workload's broker instance instead of to the
        origin. Nothing about the credential itself is known here and nothing
        needs to be: ADR 007 decision 9 keys the broker's table by `(uid,
        Host)`, so the name travels on no wire and exists in this process for
        one purpose, which is naming the credential in the record and the
        figures.

        THE FIRST governing entry that carries one, not a merge. `validate`
        already refuses two entries that match the same host and disagree about
        `credential`, so on a document written by the generator there is at most
        one answer -- but this reads a FILE, which an operator can edit, and a
        reader that raised or picked arbitrarily on a hand-edited document would
        turn an editing mistake into a dead workload. First-match is
        deterministic and matches the order the file states.
        """
        for entry in policy_governs(host, self.policy):
            if entry.credential:
                return entry.credential
        return None


def load_policy(path):
    """Read the policy document, or raise.

    Deliberately without a default: a missing or unreadable document must fail
    the start. The tempting fallback — an empty policy — is the worst of the
    options, because an empty `hosts` list is a valid configuration (a workload
    reachable only through `allow`), so the listener could not tell "the
    operator allowed nothing" from "the file was not there" and would enforce
    the strictest reading of a policy it never read.
    """
    with open(path) as f:
        text = f.read()
    # Digested from the TEXT THIS PARSED, never from a re-read of the path.
    # The whole value of the figure is that it says what this process is
    # enforcing; a second open() would report the file as it is now, so a
    # rewrite landing between the two would give a listener that advertises the
    # new document's digest while enforcing the old one -- green on the one
    # case the comparison exists for.
    digest = inspect_policy_digest(text)
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: expected a JSON object, got {type(doc).__name__}")
    # THE MODE IS ONE OF TWO WORDS, and anything else is refused rather
    # than read. Every branch on it asks `== "inspect"` or `== "splice"`, so
    # an unknown value is neither: it skips the CA check that refuses a start
    # with no CA, and then splices every connection -- a document asking for
    # termination loads clean and inspects nothing, with the status file
    # echoing the misspelling back as though it were a mode.
    tls = doc.get("tls")
    if tls is None:
        tls = TLS_DEFAULT
    if tls not in TLS_MODES:
        raise ValueError(
            f"{path}: 'tls' is {tls!r}; it is one of "
            + ", ".join(repr(m) for m in TLS_MODES))
    hosts = _names(doc, "hosts", path)
    internal = _names(doc, "internal", path)
    # Tolerated absent, unlike `hosts`: a policy document written before this
    # key existed is a policy with no internal entries, which is the common
    # case and not an error. `hosts` gets no such tolerance because there the
    # empty reading and the missing reading are different configurations.
    splice = _names(doc, "splice", path)
    # NOT normalised here, unlike `internal`: these are fnmatch PATTERNS and
    # hostname_match normalises both sides at the point of comparison.
    # Normalising a pattern early is harmless today and would silently stop
    # being so the moment a pattern could carry something a hostname cannot.
    http2 = _names(doc, "http2", path)
    # Unnormalised, like `splice` and for the same reason: these are fnmatch
    # PATTERNS, and hostname_match normalises both sides where they are
    # compared.
    entries = doc.get("policy")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'policy' is not a list")
    policy = []
    for item in entries:
        if (not isinstance(item, dict)
                or not isinstance(item.get("host"), str)
                or not item["host"].strip()):
            raise ValueError(f"{path}: a 'policy' entry is not a table with a "
                             f"host: {item!r}")
        # None and [] are DIFFERENT and the document distinguishes them, so
        # this must too: absent means any, empty would mean none. A `or ()`
        # here would turn every unconstrained entry into one permitting
        # nothing, which fails closed and therefore quietly -- the workload
        # reaches nothing and every unit test still passes.
        #
        # Uppercased and string-filtered HERE as well as in
        # vm_policy_entries, which is the convention this file already holds
        # for `internal` and the responder holds for its static map: the
        # writer normalises, and the reader normalises again so that a
        # hand-edited document cannot introduce a rule that never matches.
        # `methods` is the one that needs it -- VmPolicyEntry.permits compares
        # `method.upper()` against these, so a document carrying `["get"]`
        # would deny every GET on that host while the file reads as
        # permitting it. Fails closed, and therefore in silence.
        methods = item.get("methods")
        paths = item.get("paths")
        for key, value in (("methods", methods), ("paths", paths)):
            # A string is refused rather than iterated: `"GET"` read as a
            # list is the three one-letter methods, a rule that never
            # matches and says nothing about why.
            if value is not None and not isinstance(value, list):
                raise ValueError(
                    f"{path}: policy entry {item['host']!r}: {key!r} is not "
                    f"a list or null")
            # Each member a non-empty string, or the entry is refused: a
            # member dropped in silence narrows the entry to something the
            # file does not say.
            for member in value or ():
                if not isinstance(member, str) or not member.strip():
                    raise ValueError(
                        f"{path}: policy entry {item['host']!r}: {key!r} "
                        f"holds {member!r}, which is not a "
                        f"{'method' if key == 'methods' else 'path pattern'}")
        # `.get`, not `[...]`: the document emits the key only on the entries
        # that carry one (vm_inspect_policy explains why the sparseness is
        # load-bearing there), so absent and null mean the same thing here and
        # the reader is the side that pays for it. A non-string is dropped to
        # None rather than refused -- the value's only use is as a name, and a
        # document that named a number would otherwise fail the listener's
        # START, which is a worse outcome than one brokered host reaching the
        # origin unbrokered and saying so in the record.
        credential = item.get("credential")
        if not isinstance(credential, str) or not credential.strip():
            credential = None
        else:
            credential = credential.strip()
        policy.append(VmPolicyEntry(
            host=item["host"],
            methods=None if methods is None else tuple(
                m.upper() for m in methods),
            paths=None if paths is None else tuple(paths),
            credential=credential))
    _refuse_inert_entries(path, tls, policy, splice, http2)
    return Policy(tls=tls, hosts=tuple(hosts),
                  internal=tuple(normalise_hostname(h) for h in internal),
                  splice=tuple(splice), http2=tuple(http2),
                  policy=tuple(policy), digest=digest)


def _names(doc, key, path):
    """One of the document's name lists: absent is empty, and every entry
    is a non-empty string.

    Checked here, at start, because the first use of an entry is a
    hostname comparison on a connection thread: a number in `hosts` loads
    clean and then kills every connection that reaches the matcher, with
    the listener reporting itself up throughout.
    """
    value = doc.get(key)
    if value is None:
        return []
    # Checked before any falsiness: `{}` or `""` is a key of the wrong type,
    # not an empty list, and reading it as one is a document that loads and
    # says something other than it was written to.
    if not isinstance(value, list):
        raise ValueError(f"{path}: {key!r} is not a list")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"{path}: {key!r} holds {item!r}, which is not a host name "
                f"or pattern")
    return value


def _refuse_inert_entries(path, tls, entries, splice, http2):
    """Refuse a document whose policy entries could never run.

    `methods` and `paths` are matched against a decrypted HTTP/1.1 request
    line, and three things in the document leave a host with none: the
    whole-workload splice, a per-host splice, and h2, whose headers are
    relayed HPACK-compressed. An entry for such a host is a restriction the
    file states and the listener would not apply, and a credential on one
    is never attached. Two intentions that cannot both hold are refused at
    start, naming both, rather than one of them being picked in silence.
    """
    if not entries:
        return
    if tls == "splice":
        raise ValueError(
            f"{path}: 'policy' entries with tls 'splice': a spliced "
            f"connection is never decrypted, so no entry's methods, paths "
            f"or credential could apply. Use tls 'inspect' and splice only "
            f"the hosts that cannot take the CA, or drop the entries")
    for key, patterns in (("splice", splice), ("http2", http2)):
        for entry in entries:
            for pattern in patterns:
                if patterns_overlap(entry.host, pattern):
                    raise ValueError(
                        f"{path}: policy entry {entry.host!r} overlaps "
                        f"{key!r} entry {pattern!r}: that host is never "
                        f"read as an HTTP/1.1 request, so the entry could "
                        f"never run. Keep one of the two")
