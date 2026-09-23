"""What the shipped broker makes of its command line at startup.

The refusals and the per-Host profile table: `build_profiles` resolves each
`--host HOST=CREDENTIAL` against the material that credential id names and
the `--placeholder`/`--auth-header`/`--auth-format` flags that describe it,
and `normalise_host` is the one spelling of a `Host` the table is keyed by
and the server looks up. The generator side -- how broker_config spells the
flags this reads -- and this reader are pinned against each other by
tests/test_broker_closure.py, because a flag emitted at one end and not
taken at the other is a broker that refuses to start, which for a generated
unit is a restart loop.

THERE IS NO DOCUMENT. The broker took a broker.toml until the flags: a file
workload-broker-config rendered into the unit's RuntimeDirectory at every
start, from the workload TOML, as the unit's DynamicUser. Every value in it
was a pure function of the workload TOML and the uid -- which is exactly
what the generator holds when it writes the unit -- so the file was a second
rendering of facts the ExecStart= line could carry itself, plus a TOML
reader, a key vocabulary, a writer, an ExecStartPre and a RuntimeDirectory=
to keep the two in step. The property the file was chosen for (never serving
a previous boot's credential set) was never the file's: it holds no
material, and LoadCredentialEncrypted= decrypts the material afresh at every
start with or without it.

Installed to /usr/libexec/workloadctl/broker_profiles.py.
"""

import dataclasses
import os
from pathlib import Path

# The auth convention a credential gets when its block states none: the
# Anthropic one. Defined HERE, in the reader that applies them, and quoted
# by credential_entries at an operator -- the generator emits no flag for
# an absent key, so the broker is the one place the default is in force.
BROKER_DEFAULT_AUTH_HEADER = "x-api-key"
BROKER_DEFAULT_AUTH_FORMAT = "{secret}"


class BrokerConfigError(ValueError):
    """The command line, or the credential it names, cannot be used. Raised
    by the reader and turned into an exit by the program: the library raises,
    the leaf ends the process (tests/test_layering.py)."""


# The port an upstream is dialled on. Not a flag: `--host` names a host and
# the upstream is https://<host>, on the reasoning broker_config gives -- the
# upstream is the host the policy authorised and nothing else, so there is
# no scheme, no port and no path for a flag to vary.
UPSTREAM_PORT = 443


@dataclasses.dataclass(frozen=True)
class Profile:
    """Everything a request needs, resolved per Host.

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
    """One `Host` header or flag key as the string the table is keyed by.

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


def split_pair(value, flag):
    """(key, value) of one `KEY=VALUE` flag argument.

    Split on the FIRST `=`, so a value may carry one: a placeholder is
    operator prose and `Bearer {secret}` is not the only shape an auth
    format takes. A key cannot carry one -- a host is a DNS name and a
    credential id is a seal name, both with character classes that exclude
    it. No `=` at all is refused rather than read as an empty value, because
    an empty placeholder is not what an operator who wrote `--placeholder x`
    meant.
    """
    key, sep, val = value.partition("=")
    if not sep or not key:
        raise BrokerConfigError(f"{flag} takes KEY=VALUE, got {value!r}")
    return key, val


def listen_endpoint(value):
    """(address, port) of the `--listen` flag.

    NOT defaulted, unlike the timeouts. An instance must bind the address
    derived for ITS workload (ADR 007's first detail that will bite): a
    default of 127.0.0.1 puts one workload's broker at an address every other
    workload's inspector also dials, which grows the hole decision 6 closes.
    So the flag is required by the parser, and 0.0.0.0 -- which is worse,
    since it binds the derived address AND every other one -- is refused by
    name here.
    """
    address, sep, port = value.rpartition(":")
    if not sep or not address:
        raise BrokerConfigError(f"--listen takes ADDRESS:PORT, got {value!r}")
    if address in ("0.0.0.0", "::", "*", "[::]"):
        raise BrokerConfigError(
            f"--listen {value!r} binds every address on the host, including "
            f"the ones other workloads' brokers listen on. Bind this "
            f"workload's derived address alone (ADR 007 decision 6)")
    try:
        port = int(port)
    except ValueError:
        raise BrokerConfigError(f"--listen {value!r}: the port is not a number")
    if not 0 <= port <= 65535:
        raise BrokerConfigError(f"--listen {value!r}: the port is out of range")
    return address, port


def _by_credential(values, flag):
    """{credential id: value} for one repeatable CREDENTIAL=VALUE flag.

    A credential stated twice is refused rather than last-wins, because
    which fiction the guest is checked against would then depend on flag
    order, which nothing states.
    """
    table = {}
    for raw in values:
        cred_id, value = split_pair(raw, flag)
        if cred_id in table:
            raise BrokerConfigError(f"{flag} {cred_id}=... is given twice")
        table[cred_id] = value
    return table


def build_profiles(name, hosts, placeholders=(), auth_headers=(),
                   auth_formats=(), load=None):
    """Resolve the per-Host profile table from the flags, as given.

    `hosts` is every `--host HOST=CREDENTIAL` argument, in order; the other
    three are the repeatable `CREDENTIAL=VALUE` flags. `name` is the label
    the profiles and the log lines carry -- the workload's name, which the
    broker is TOLD and never derives.

    Keyed by Host, and there is NO default entry: a `Host` with no flag gets
    nothing. That is a threat-model property, not a schema detail: a table
    with a default gives every request that reaches the broker ONE upstream
    with ONE credential, so a workload holding several keys can only say
    which request gets which through something the request carries.

    Nothing it carries decides that. The `Host` is a lookup key into this
    table and never a source of anything: an unrecognised value selects no
    profile and the request is refused, and a recognised one selects an
    upstream, a port and a credential that were all written here at start.
    Nothing the caller sends reaches the wire unexamined -- forwarded_headers
    rewrites `Host` from the resolved profile, so a request whose body claims
    a different destination than its header goes to the header's.

    The other dimension the table used to have -- the workload -- is gone
    with the document. An instance serves one caller (ADR 007 decision 6),
    identified by the uid on the ExecStart= line, so the caller half of the
    key is an assertion the server makes before this table is consulted.

    Returns {host: Profile}, the host through normalise_host.
    """
    from_env = load is None and not os.environ.get("CREDENTIALS_DIRECTORY")
    load = load or load_credential
    if not hosts:
        raise BrokerConfigError(
            "no --host HOST=CREDENTIAL flags, so this broker holds "
            "credentials for nothing and would refuse every request it "
            "received")
    placeholders = _by_credential(placeholders, "--placeholder")
    auth_headers = _by_credential(auth_headers, "--auth-header")
    auth_formats = _by_credential(auth_formats, "--auth-format")

    secrets = {}
    profiles = {}
    for raw in hosts:
        raw_host, cred_id = split_pair(raw, "--host")
        where = f"--host {raw}"
        host = normalise_host(raw_host)
        if host is None:
            raise BrokerConfigError(f"{where}: {raw_host!r} is not a usable Host")
        if host in profiles:
            # Two spellings of one host -- "API.Example" and "api.example:443"
            # normalise together. Refused rather than last-wins, because
            # which credential a request gets would then depend on flag
            # order.
            raise BrokerConfigError(
                f"{where}: {host!r} is already configured under a different "
                f"spelling; hosts are compared lowercased and without a port")
        if not cred_id:
            raise BrokerConfigError(
                f"{where}: no credential. A host with no credential is a "
                f"host the broker would forward for while attaching nothing")
        if cred_id not in secrets:
            secrets[cred_id] = load(cred_id)
        placeholder = placeholders.get(cred_id)
        if placeholder and placeholder == secrets[cred_id]:
            # The one startup check that survives generation: it fires on
            # the mistake generation cannot prevent, a real provider key
            # pasted into a workload.toml, which is world-readable and, for
            # a bundle, very likely committed.
            #
            # Compared against the DECRYPTED material, so it catches the key
            # itself rather than a coincidental match with a sealed blob. The
            # message names neither value.
            raise BrokerConfigError(
                f"{where}: the placeholder for {cred_id!r} is byte-identical "
                f"to the decrypted credential. The placeholder is the fiction "
                f"the guest holds and lives in a plain-text workload.toml; if "
                f"it equals the real key then the real key is in that file. "
                f"Rotate the credential, then put a plausible fake of the "
                f"same shape here")
        auth_format = auth_formats.get(cred_id, BROKER_DEFAULT_AUTH_FORMAT)
        try:
            auth_value = auth_format.format(secret=secrets[cred_id])
        except (KeyError, IndexError, ValueError) as exc:
            # The message deliberately does not echo auth_format: the whole
            # point of the string is that a secret is substituted into it, and
            # a sufficiently wrong one could already hold part of it.
            raise BrokerConfigError(
                f"--auth-format {cred_id}=... is not a usable format string "
                f"({type(exc).__name__}); it takes exactly {{secret}}")
        profiles[host] = Profile(
            name=f"{name}/{host}",
            host=host,
            port=UPSTREAM_PORT,
            auth_header=auth_headers.get(cred_id, BROKER_DEFAULT_AUTH_HEADER),
            auth_format=auth_format,
            secret=secrets[cred_id],
            auth_value=auth_value,
        )

    # ONE VARIABLE IS ONE KEY. AGENT_BROKER_SECRET answers every
    # credential id with the same value, so two ids under it would send
    # one provider's key to the other provider's host -- attached by this
    # broker, over verified TLS, to a party that was never meant to hold
    # it. The fallback is for one credential or none.
    if from_env and len(secrets) > 1:
        raise BrokerConfigError(
            f"--host names {len(secrets)} credentials "
            f"({', '.join(sorted(secrets))}) and $CREDENTIALS_DIRECTORY is "
            f"not set: AGENT_BROKER_SECRET is one value, and every one of "
            f"them would be sent that value. Run under systemd with "
            f"LoadCredentialEncrypted=, or name one credential")

    # A credential described but never selected is a flag the generator does
    # not emit, so its presence means a hand-edited unit -- refused rather
    # than ignored, because the description that went unapplied may have
    # been meant for a host spelled wrong on another flag.
    for flag, table in (("--placeholder", placeholders),
                        ("--auth-header", auth_headers),
                        ("--auth-format", auth_formats)):
        unselected = sorted(set(table) - set(secrets))
        if unselected:
            raise BrokerConfigError(
                f"{flag} names {', '.join(unselected)}, which no --host "
                f"selects")
    return profiles


def load_credential(name):
    """Read the secret from the systemd credentials directory.

    systemd puts LoadCredentialEncrypted= material on a tmpfs at 0400 owned by
    the service user, which is why the broker never needs to read a file the
    rest of the host can see. Falls back to an env var only to keep local
    development possible, and then for one credential id: build_profiles
    refuses a second, which would be sent the same value.
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds_dir:
        try:
            secret = Path(creds_dir, name).read_text().strip()
        except OSError as exc:
            raise BrokerConfigError(
                f"credential {name!r} is not in $CREDENTIALS_DIRECTORY "
                f"({exc.strerror}); the unit's LoadCredentialEncrypted= "
                f"lines and its --host flags disagree")
        if not secret:
            raise BrokerConfigError(f"credential '{name}' is empty")
        return secret
    env = os.environ.get("AGENT_BROKER_SECRET")
    if env:
        return env.strip()
    raise BrokerConfigError("no credential: run under systemd with LoadCredentialEncrypted=, "
                            "or set AGENT_BROKER_SECRET for local testing")
