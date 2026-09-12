"""
The credential block: [[network.credential]] and [[vm.network.credential]],
parsed and validated once for both substrates.

A container's block and a VM's block are the same five keys, rendered into
the same broker.toml by the same generator and read by the same broker
binary, so one parse loop and one rule set serve both; the NamedTuple to
build and the reserved-variable set to refuse are the substrate's
contribution. parse_credential_entries is shape-tolerant and is what the
broker's config render reads; validate_credential_entries is what the two
egress validators apply.

Installed to /usr/libexec/workloadctl/credential_entries.py.
"""

import re
import string


def parse_credential_entries(net: dict, credential_cls) -> list:
    """The `credential` blocks of one network table, normalised, in file order.

    `credential_cls` is VmCredential or ContainerCredential; see VmCredential's
    docstring for what each field is for and why the optional pair is optional.
    """
    creds = []
    raw = net.get("credential", [])
    if not isinstance(raw, list):
        return creds
    for item in raw:
        if not isinstance(item, dict):
            continue
        values = []
        for key in ("name", "placeholder", "env"):
            value = item.get(key)
            if not isinstance(value, str) or not value.strip():
                values = []
                break
            values.append(value.strip())
        if not values:
            continue
        # Optional, and absent stays None rather than becoming the default
        # here: the render emits nothing for an absent key and lets the broker
        # apply its own, so there is one place the default lives. Writing it in
        # twice is how the two come to disagree after one of them changes.
        optional = []
        for key in ("auth_header", "auth_format"):
            value = item.get(key)
            optional.append(value.strip()
                            if isinstance(value, str) and value.strip()
                            else None)
        creds.append(credential_cls(*values, *optional))
    return creds


# --- Shared credential-block validation ---
#
# One implementation for both substrates, because a [[network.credential]] and
# a [[vm.network.credential]] are the same block: the same five keys, rendered
# into the same broker.toml by the same generator and read by the same broker
# binary. Every rule here fails the same way when it is absent: the broker
# attaches the wrong header or none at all, the provider answers 401, and every
# layer on this host considers the request fully authorised -- so a rule that
# goes missing has no symptom this side of the provider.
#
# `table` is "vm.network" or "network" and spells both `[{table}].credential`
# and `[[{table}.credential]]`; `noun` is what the material is seeded into,
# "guest" or "container". Those two, plus the NamedTuple to build and the
# reserved-variable set to refuse, are the whole of the difference.

# What a credential `name` may be. The same character class cmd_secret enforces,
# because the name IS the credstore filename -- the material lands at
# /etc/credstore.encrypted/broker/<workload>/<name>. The absence of `/` from this
# class is load-bearing twice over: it keeps a name from escaping the workload's
# own subtree, and it is the same absence that makes the scoped path unnameable
# from ${SECRET:...} in workload env (secrets_template.SECRET_PATTERN has no `/`
# either), so broker material cannot be pulled into a container's environment by
# spelling its path.
_CREDENTIAL_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


# What a credential `env` may be. POSIX shell name, because it is written into an
# EnvironmentFile the seed reads: a name with `=` or a space in it would produce
# a line the reader silently drops or, worse, mis-splits.
_CREDENTIAL_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# RFC 9110 §5.1: a field name is one or more tchar. Spelled out rather than
# approximated with \w, because the characters that are NOT here are the whole
# point -- a colon, a space or a newline in this string writes a header the
# provider reads as something else, or splits one into two.
_AUTH_HEADER_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


# Header names the broker must be the only writer of, or that decide how the
# message is framed. Refused rather than allowed to produce a broken request:
# `content-length` would be overwritten by a number describing a different
# body, `host` is set from the upstream and would silently not take, and the
# hop-by-hop names are stripped on the way out so the credential would simply
# vanish -- a 401 whose cause is invisible from every layer of ours.
_AUTH_HEADER_REFUSED = {
    "content-length": "it frames the message, and the broker sets its own",
    "transfer-encoding": "it frames the message, and it is hop-by-hop",
    "host": "the broker sets it from the upstream, so this would not take",
    "connection": "it is hop-by-hop and is stripped before the request leaves",
    "upgrade": "it is hop-by-hop and is stripped before the request leaves",
    "te": "it is hop-by-hop and is stripped before the request leaves",
    "trailer": "it is hop-by-hop and is stripped before the request leaves",
    "keep-alive": "it is hop-by-hop and is stripped before the request leaves",
    "proxy-authorization":
        "it is hop-by-hop and is stripped before the request leaves",
    "proxy-authenticate":
        "it is hop-by-hop and is stripped before the request leaves",
}


# The broker's defaults. Applied by broker_config.load_config, which the
# shipped program runs; here they are only quoted at an operator, because the
# render emits nothing for an absent key.
BROKER_DEFAULT_AUTH_HEADER = "x-api-key"
BROKER_DEFAULT_AUTH_FORMAT = "{secret}"


def _validate_auth_header(table: str, name: str, header: str) -> list[str]:
    if not _AUTH_HEADER_RE.match(header):
        return [f"[{table}].credential: {name!r} has `auth_header` = "
                f"{header!r}, which is not an HTTP field name (RFC 9110 §5.1 "
                f"tchar). A colon, a space or a newline here does not produce "
                f"a header the provider ignores -- it produces a different "
                f"header, or two"]
    why = _AUTH_HEADER_REFUSED.get(header.lower())
    if why:
        return [f"[{table}].credential: {name!r} has `auth_header` = "
                f"{header!r}, which cannot carry a credential: {why}. The "
                f"request would go upstream with no material on it and the "
                f"provider would answer 401, on a request every layer here "
                f"considers fully authorised"]
    return []


def _validate_auth_format(table: str, name: str, fmt: str) -> list[str]:
    """`auth_format` must substitute the material exactly once and name nothing
    else.

    Checked HERE because the broker renders it at startup with `str.format` and
    exits on a bad one -- which, for a generated unit, is a workload whose
    broker will not start and whose only symptom is a restart loop. An operator
    writing `Bearer {token}` gets the reason at `validate` instead.
    """
    fields = []
    try:
        for _literal, field, _spec, _conv in string.Formatter().parse(fmt):
            if field is not None:
                fields.append(field)
    except ValueError as exc:
        return [f"[{table}].credential: {name!r} has `auth_format` = "
                f"{fmt!r}, which is not a usable format string ({exc})"]
    if fields != ["secret"]:
        return [f"[{table}].credential: {name!r} has `auth_format` = "
                f"{fmt!r}, which substitutes {fields or 'nothing'} -- it must "
                f"name `{{secret}}` exactly once and nothing else. The broker "
                f"renders this once at startup and exits on anything it cannot "
                f"format, so a generated instance would not start at all"]
    return []


def validate_credential_entries(net: dict, *, table: str, noun: str,
                                credential_cls,
                                reserved_env) -> tuple[list, list[str]]:
    """Validate one network table's credential blocks. Returns (creds, errors).

    Shape only, plus uniqueness. Whether a block is USED, and whether a policy
    entry names one that exists, are relations between the two tables and live
    with the policy validation, which is the one place that has both.

    Whether the credstore actually HOLDS the named material is not checked here
    and deliberately: this runs from the boot generator, where /etc is not the
    authority it is at config time, and a rule that read the credstore would
    make a validation result depend on host state. `workloadctl validate`
    performs that check, beside the one it already performs for ${SECRET:}
    names.
    """
    errors: list[str] = []
    raw = net.get("credential", [])
    if not isinstance(raw, list):
        return [], [f"[{table}].credential must be an array of "
                    f"[[{table}.credential]] tables, got "
                    f"{type(raw).__name__}"]

    known = {"name", "placeholder", "env", "auth_header", "auth_format"}
    creds: list = []
    seen: set[str] = set()
    seen_envs: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            errors.append(
                f"[{table}].credential entries are tables with `name`, "
                f"`placeholder` and `env`, got {item!r}")
            continue
        unknown = sorted(set(item) - known)
        if unknown:
            errors.append(
                f"[{table}].credential: unknown key(s) "
                f"{', '.join(unknown)}; a credential block carries `name`, "
                f"`placeholder` and `env`, and optionally `auth_header` and "
                f"`auth_format`")
        values = {}
        for key in ("name", "placeholder", "env"):
            value = item.get(key)
            if not isinstance(value, str) or not value.strip():
                # All three are required, and `placeholder` is the one whose
                # absence would otherwise fail invisibly: with no placeholder
                # the workload is seeded with nothing, its client sends no
                # Authorization header at all, and the broker's substitution
                # has nothing to replace -- which surfaces as the provider
                # returning 401 on a request the inspector considers fully
                # authorised. The seed is where the fiction is maintained, so
                # a credential with no fiction is not a credential.
                errors.append(
                    f"[{table}].credential: entry {item!r} has no `{key}`; "
                    f"a block carries all three -- `name` selects the sealed "
                    f"material, `placeholder` is the fiction the {noun} holds "
                    f"in its place, and `env` is the variable it is seeded "
                    f"into")
                values = {}
                break
            values[key] = value.strip()
        if not values:
            continue
        name, placeholder, env = (values["name"], values["placeholder"],
                                  values["env"])
        if not _CREDENTIAL_NAME_RE.match(name):
            errors.append(
                f"[{table}].credential: {name!r} is not a usable credstore "
                f"name -- letters, numbers, underscore and hyphen only. The "
                f"name is the filename the sealed material lands under, and a "
                f"`/` in it would put one workload's credential outside its "
                f"own subtree")
            continue
        if not _CREDENTIAL_ENV_RE.match(env):
            errors.append(
                f"[{table}].credential: {name!r} has `env` = {env!r}, "
                f"which is not a shell variable name. It is written into the "
                f"{noun}'s environment as `{env}=...`, so a name with a space "
                f"or an `=` in it produces a line the {noun} silently drops")
            continue
        if env in reserved_env:
            # The seed merges this block over workloadctl's own variables, so a
            # collision resolves silently whichever way the merge happens to
            # go: either the workload loses the placeholder (its client sends
            # no key and the provider answers 401 on a request this layer fully
            # authorised) or it loses its CA path (every HTTPS request fails
            # validation inside the workload, where no line on the host can see
            # it). Both are invisible from here, so the collision is refused
            # where it is still visible.
            errors.append(
                f"[{table}].credential: {name!r} has `env` = {env!r}, which "
                f"is one of the CA trust-store variables workloadctl already "
                f"seeds this {noun} with. Choose another name -- the {noun} "
                f"maps it to whatever its client reads, so it is yours to pick")
            continue
        if env in seen_envs:
            errors.append(
                f"[{table}].credential: `env` = {env!r} is used by two "
                f"credential blocks, so one placeholder overwrites the other "
                f"in the {noun} and one credential's host answers 401 for a "
                f"reason nothing on this host reports")
            continue
        seen_envs.add(env)
        if name in seen:
            errors.append(
                f"[{table}].credential: {name!r} is declared twice. A "
                f"policy entry selects a credential by name, so two blocks "
                f"sharing one make the selector ambiguous -- and the file "
                f"states two placeholders for material that has one")
            continue
        seen.add(name)
        auth_header, auth_format = None, None
        raw_header = item.get("auth_header")
        if raw_header is not None:
            if not isinstance(raw_header, str) or not raw_header.strip():
                errors.append(
                    f"[{table}].credential: {name!r} has `auth_header` = "
                    f"{raw_header!r}; it is the HTTP header the broker attaches "
                    f"the material in, and omitting the key means the broker's "
                    f"own default, {BROKER_DEFAULT_AUTH_HEADER!r}")
                continue
            auth_header = raw_header.strip()
            errors.extend(_validate_auth_header(table, name, auth_header))
        raw_format = item.get("auth_format")
        if raw_format is not None:
            if not isinstance(raw_format, str) or not raw_format.strip():
                errors.append(
                    f"[{table}].credential: {name!r} has `auth_format` = "
                    f"{raw_format!r}; it is the value template the material is "
                    f"substituted into, and omitting the key means the "
                    f"broker's own default, {BROKER_DEFAULT_AUTH_FORMAT!r}")
                continue
            auth_format = raw_format.strip()
            errors.extend(_validate_auth_format(table, name, auth_format))
        creds.append(credential_cls(name=name, placeholder=placeholder,
                                    env=env, auth_header=auth_header,
                                    auth_format=auth_format))
    return creds, errors
