"""What the shipped broker makes of broker.toml at startup.

The key vocabulary, the refusals, and the (workload, Host) profile table:
`load_config` reads the document and refuses any key it does not know,
`build_profiles` resolves each host entry against the credential it names,
and `normalise_host` is the one spelling of a `Host` the table is keyed by
and the server looks up. The render side -- how broker_config writes the
document this reads -- spells the same keys, and tests/test_broker.py pins
the two against each other, because a key rendered at one level and
accepted at another is a broker that refuses to start, which for a
generated unit is a restart loop.

Installed to /usr/libexec/workloadctl/broker_profiles.py.
"""

import dataclasses
import difflib
import os
import urllib.parse
from pathlib import Path

import tomllib
from credential_entries import BROKER_DEFAULT_AUTH_FORMAT, BROKER_DEFAULT_AUTH_HEADER


class BrokerConfigError(ValueError):
    """The document, or the credential it names, cannot be used. Raised by the
    reader and turned into an exit by the program: the library raises, the
    leaf ends the process (tests/test_layering.py)."""



@dataclasses.dataclass(frozen=True)
class Profile:
    """Everything a request needs, resolved per caller.

    `auth_value` is the finished header value, rendered once at startup rather
    than per request. auth_format is operator-written and `str.format` raises on
    a typo like "Bearer {token}"; rendering it here makes that a refusal to
    start, which is how every other config error here behaves, instead of a
    500 on every request from a broker that came up clean.
    """
    name: str
    host: str
    port: int
    auth_header: str
    auth_format: str
    secret: str
    auth_value: str


def normalise_host(value):
    """One `Host` header or config key as the string the table is keyed by.

    Lowercased, port stripped, trailing root dot stripped. All three arrive in
    practice -- `API.GitHub.com`, `api.github.com:443` and `api.github.com.` are
    the same host to every resolver and to the inspector's own allowlist, and a
    table keyed by the raw string would refuse two of the three while the
    config looked right.

    Returns None for anything that is not a usable host, which is a REFUSAL and
    never a fallback: the profile is selected by this value.
    """
    if not isinstance(value, str):
        return None
    host = value.strip().lower()
    if host.startswith("["):
        # An IPv6 literal in brackets, possibly with a port. Not something a
        # credential-backed host is ever spelled as -- the inspector binds the
        # NAME that authorised the connection -- but it must not be mangled
        # into something that accidentally matches an entry.
        end = host.find("]")
        if end == -1:
            return None
        host = host[:end + 1]
    elif ":" in host:
        host = host.split(":", 1)[0]
    host = host.rstrip(".")
    return host or None


def _split_upstream(url, where):
    """(host, port) for one configured upstream.

    A base path is REFUSED rather than carried. Prepending one to every
    forwarded path would rewrite the very path `[[vm.network.policy]].paths`
    authorised at the inspector in front: a guest's `/repos/myorg/x`, admitted
    against that pattern, would leave here as `/v1/repos/myorg/x`. The two
    layers would disagree about what request was made, and the one holding
    the credential would win.
    """
    up = urllib.parse.urlsplit(url)
    if up.scheme != "https" or not up.hostname:
        raise BrokerConfigError(f"{where}: 'upstream' must be an https:// URL with a hostname")
    if up.query or up.fragment:
        raise BrokerConfigError(f"{where}: 'upstream' must not carry a query or fragment")
    if up.path.rstrip("/"):
        raise BrokerConfigError(f"{where}: 'upstream' must not carry a path ({up.path!r}). A "
                                f"base path would be prepended to every forwarded request, "
                                f"rewriting the path the inspector's policy admitted -- put "
                                f"the full path in the request instead")
    return up.hostname, up.port or 443


# Every key the broker reads, at each level. Anything else is a typo or a key
# from a version that did not survive, and both are refused rather than
# defaulted: an operator who writes `listen_addr` or `tls_certificate`
# gets a broker that starts, reports itself healthy, and applies a policy they
# did not choose. Unknown keys are cheap to catch and silent to miss, and every
# one of these decides who gets a credential.
CONFIG_KEYS = frozenset({
    "upstream", "credential", "listen_address", "listen_port", "auth_header",
    "auth_format", "sandboxes", "connect_timeout",
    "read_timeout", "relax_x509_strict", "tls_cert", "tls_key",
})

# What a [sandboxes.<name>] table holds: a container and nothing else. Every
# credential-bearing key lives one level down, in [sandboxes.<name>
# .hosts."<Host>"], because ADR 007 decision 3 keys the profile table by
# (workload, Host) rather than by workload alone.
SANDBOX_KEYS = frozenset({"hosts"})

# What one [sandboxes.<name>.hosts."<Host>"] table may override. `upstream` and
# `credential` are required here or inherited from the top level; the rest are
# defaults.
#
# `placeholder` is the odd one, because the broker never USES it -- it discards
# whatever credential arrived and sets its own header, so substitution works
# whether the guest sent a plausible fiction or nothing at all. It is here for
# one startup check: a `placeholder` that equals the decrypted material means a
# real provider key was pasted into a world-readable workload.toml, and that is
# worth refusing to start over.
HOST_KEYS = frozenset({"upstream", "credential", "placeholder", "auth_header",
                       "auth_format"})


def reject_unknown_keys(present, known, where):
    """Refuse anything outside `known`, naming the nearest real key if there
    is one -- most of these are a plural or an underscore away from correct."""
    unknown = sorted(set(present) - known)
    if not unknown:
        return
    described = []
    for key in unknown:
        near = difflib.get_close_matches(key, sorted(known), n=1)
        described.append(f"'{key}'" + (f" (did you mean '{near[0]}'?)" if near else ""))
    plural = "s" if len(unknown) > 1 else ""
    raise BrokerConfigError(f"{where}: unknown key{plural}: " + ", ".join(described))


def load_config(path):
    with open(path, "rb") as fh:
        cfg = tomllib.load(fh)

    # Address-keyed config predates uid identity and cannot work: every guest
    # now arrives from the same address, so these entries would match nothing
    # and 403 everything. Refuse it rather than let a stale file look applied.
    if "allow_unknown_sources" in cfg:
        raise BrokerConfigError("broker.toml: 'allow_unknown_sources' identified callers by "
                                "address, which stopped working when every guest began "
                                "arriving from the same one. Its successor "
                                "'allow_unknown_callers' is gone too -- see below "
                                "(docs/agent-broker.md §5)")
    if "allow_unknown_callers" in cfg:
        # Deleted rather than defaulted, because there is nothing left for it to
        # mean. It named a default profile for a caller the config did not
        # enumerate, which made sense for ONE host-wide broker fronting guests an
        # operator had not finished listing. An instance is per workload now
        # (ADR 007 decision 6) and its config is generated from that workload's
        # own TOML, so an unenumerated caller is a caller that should not be
        # here. Keeping the key would ship the one switch that turns the uid
        # check off, on the component whose whole job is the uid check.
        raise BrokerConfigError("broker.toml: 'allow_unknown_callers' is gone -- a broker "
                                "instance serves one workload and its config is generated "
                                "from that workload's [[vm.network.credential]] blocks, so "
                                "there is no caller it could apply to (docs/agent-broker.md)")
    for key, value in cfg.get("sandboxes", {}).items():
        if not isinstance(value, dict):
            raise BrokerConfigError(f"broker.toml: [sandboxes] maps a workload NAME to a "
                                    f"table now, not {key!r} to a string -- callers are "
                                    f"identified by uid, not by address (docs/agent-broker.md §5)")
        if set(value) & (HOST_KEYS - SANDBOX_KEYS):
            # The pre-rung-6 shape: one profile per sandbox, with `upstream` and
            # `credential` on the sandbox table itself. Named rather than
            # reported as unknown keys, because a file in that shape is not a
            # typo -- it is a working config for a broker that fronted one
            # upstream per caller, and the operator needs to know the dimension
            # that was added rather than which four keys moved.
            raise BrokerConfigError(f"broker.toml: [sandboxes.{key}] holds one profile for "
                                    f"the whole sandbox, which is the shape before credentials "
                                    f"were selected per host. The table is keyed by (workload, "
                                    f"Host) now: move `upstream`, `credential` and the auth "
                                    f"keys into [sandboxes.{key}.hosts.\"<the Host>\"] "
                                    f"(docs/agent-broker.md §3)")
        reject_unknown_keys(value, SANDBOX_KEYS, f"broker.toml: [sandboxes.{key}]")
        hosts = value.get("hosts", {})
        if not isinstance(hosts, dict):
            raise BrokerConfigError(f"broker.toml: [sandboxes.{key}].hosts maps a Host to a "
                                    f"table, got {type(hosts).__name__}")
        for host, entry in hosts.items():
            where = f"broker.toml: [sandboxes.{key}.hosts.\"{host}\"]"
            if not isinstance(entry, dict):
                raise BrokerConfigError(f"{where} must be a table")
            if normalise_host(host) is None:
                raise BrokerConfigError(f"{where}: {host!r} is not a usable Host")
            reject_unknown_keys(entry, HOST_KEYS, where)

    # After the two migration checks above, so a stale file gets the message
    # that explains it rather than a bare "unknown key".
    reject_unknown_keys(cfg, CONFIG_KEYS, "broker.toml")

    # `upstream` and `credential` are top-level DEFAULTS now, not requirements:
    # a host entry supplies its own or inherits one, and build_profiles refuses
    # an entry that ends up with neither. Requiring them here would force the
    # generator to pick one of a workload's credentials arbitrarily and write it
    # where nothing reads it.
    if not cfg.get("sandboxes"):
        raise BrokerConfigError("broker.toml: no [sandboxes.<workload>.hosts.\"<Host>\"] "
                                "tables, so this broker holds credentials for nothing and "
                                "would refuse every request it received")

    # NOT defaulted, unlike everything below it. An instance must bind the
    # address derived for ITS workload (ADR 007's second detail that will bite):
    # a default of 127.0.0.1 puts one workload's broker at an address every
    # other workload's inspector also dials, which grows the hole decision 6
    # closes. So a missing value is a refusal to start, and 0.0.0.0 -- which is
    # worse, since it binds the derived address AND every other one -- is
    # refused by name.
    listen = cfg.get("listen_address")
    if not listen:
        raise BrokerConfigError("broker.toml: 'listen_address' is required -- an instance "
                                "binds the loopback address derived from its own workload's "
                                "uid, and there is no safe default (ADR 007 decision 6)")
    if listen in ("0.0.0.0", "::", "*"):
        raise BrokerConfigError(f"broker.toml: 'listen_address' = {listen!r} binds every "
                                f"address on the host, including the ones other workloads' "
                                f"brokers listen on. Bind this workload's derived address "
                                f"alone.")

    cfg.setdefault("listen_port", 8081)
    cfg.setdefault("auth_header", BROKER_DEFAULT_AUTH_HEADER)
    cfg.setdefault("auth_format", BROKER_DEFAULT_AUTH_FORMAT)
    cfg.setdefault("connect_timeout", 15.0)
    cfg.setdefault("read_timeout", 900.0)  # long: streamed completions idle
    return cfg


def build_profiles(cfg, load=None):
    """Resolve the (workload, Host) profile table. ADR 007 decision 3.

    Keyed by both, and there is NO default entry in either dimension: a caller
    whose workload is not a sandbox gets nothing, and a `Host` with no entry
    under its sandbox gets nothing. That is a threat-model property, not a
    schema detail: a table keyed by workload alone gives every caller that
    reaches the broker ONE upstream with ONE credential, so a workload holding
    several keys can only say which request gets which through something the
    request carries.

    Nothing it carries decides that. The `Host` is a lookup key into this
    table and never a source of anything: an unrecognised value selects no profile and the request
    is refused, and a recognised one selects an upstream, a port and a
    credential that were all written here at start. Nothing the caller sends
    reaches the wire unexamined -- forwarded_headers rewrites `Host` from the
    resolved profile, so a request whose body claims a different destination
    than its header goes to the header's.

    Returns {(workload, host): Profile}. Both key halves are normalised: the
    workload as written, the host through normalise_host.
    """
    load = load or load_credential
    secrets = {}

    def resolve(sandbox, host_key, spec, where):
        credential = spec.get("credential", cfg.get("credential"))
        if not credential:
            raise BrokerConfigError(f"{where}: no 'credential', and none at the top level to "
                                    f"inherit. A host entry with no credential is a host the "
                                    f"broker would forward for while attaching nothing")
        if credential not in secrets:
            secrets[credential] = load(credential)
        upstream = spec.get("upstream", cfg.get("upstream"))
        if not upstream:
            raise BrokerConfigError(f"{where}: no 'upstream', and none at the top level to "
                                    f"inherit")
        host, port = _split_upstream(upstream, where)
        placeholder = spec.get("placeholder")
        if placeholder and placeholder == secrets[credential]:
            # The one check that survives generation (the other two §7.8 asked
            # for cannot fail on a config that is a pure function of the TOML).
            # It is worth its lines because it fires on the mistake generation
            # cannot prevent: a real provider key pasted into a workload.toml,
            # which is world-readable and, for a bundle, very likely committed.
            #
            # Compared against the DECRYPTED material, so it catches the key
            # itself rather than a coincidental match with a sealed blob. The
            # message names neither value.
            raise BrokerConfigError(f"{where}: 'placeholder' is byte-identical to the "
                                    f"decrypted credential {credential!r}. The placeholder is "
                                    f"the fiction the guest holds and lives in a plain-text "
                                    f"workload.toml; if it equals the real key then the real "
                                    f"key is in that file. Rotate the credential, then put a "
                                    f"plausible fake of the same shape here")
        auth_format = spec.get("auth_format", cfg["auth_format"])
        try:
            auth_value = auth_format.format(secret=secrets[credential])
        except (KeyError, IndexError, ValueError) as exc:
            # The message deliberately does not echo auth_format: the whole
            # point of the string is that a secret is substituted into it, and a
            # sufficiently wrong one could already hold part of it.
            raise BrokerConfigError(f"{where}: 'auth_format' is not a usable format string "
                                    f"({type(exc).__name__}); it takes exactly {{secret}}")
        return Profile(
            name=f"{sandbox}/{host_key}",
            host=host,
            port=port,
            auth_header=spec.get("auth_header", cfg["auth_header"]),
            auth_format=auth_format,
            secret=secrets[credential],
            auth_value=auth_value,
        )

    profiles = {}
    for sandbox, spec in cfg["sandboxes"].items():
        for raw, entry in spec.get("hosts", {}).items():
            key = normalise_host(raw)
            where = f"[sandboxes.{sandbox}.hosts.\"{raw}\"]"
            if (sandbox, key) in profiles:
                # Two spellings of one host under one sandbox -- "API.Example"
                # and "api.example:443" normalise together. Refused rather than
                # last-wins, because which credential a request gets would then
                # depend on table order.
                raise BrokerConfigError(f"{where}: {key!r} is already configured for sandbox "
                                        f"{sandbox!r} under a different spelling; hosts are "
                                        f"compared lowercased and without a port")
            profiles[(sandbox, key)] = resolve(sandbox, key, entry, where)
    return profiles


def load_credential(name):
    """Read the secret from the systemd credentials directory.

    systemd puts LoadCredentialEncrypted= material on a tmpfs at 0400 owned by
    the service user, which is why the broker never needs to read a file the
    rest of the host can see. Falls back to an env var only to keep local
    development possible.
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds_dir:
        secret = Path(creds_dir, name).read_text().strip()
        if not secret:
            raise BrokerConfigError(f"credential '{name}' is empty")
        return secret
    env = os.environ.get("AGENT_BROKER_SECRET")
    if env:
        return env.strip()
    raise BrokerConfigError("no credential: run under systemd with LoadCredentialEncrypted=, "
                            "or set AGENT_BROKER_SECRET for local testing")
