"""
Template substitution and secret resolution for workload configs.

The security-sensitive text pass: it resolves ${VAR}/${SECRET:name}/${SECRET?name}
placeholders in cloud-init user-data and container env values, and detects which
credentials a config demands. The single-pass, never-re-scan property and the
`$$` escaping are load-bearing security invariants — read the pattern comments
before touching them.

Installed to /usr/libexec/workloadctl/secrets_template.py.
"""

import re
from pathlib import Path


# --- Environment variables ---

# POSIX env var key: starts with letter or underscore, then alphanumeric/underscore
ENV_KEY_PATTERN = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def validate_env_key(key: str) -> bool:
    """Check that an environment variable key is a valid POSIX name."""
    return bool(ENV_KEY_PATTERN.match(key))


# --- Secrets ---

# Pattern matching ${SECRET:name} references in env var values
SECRET_PATTERN = re.compile(r'\$\{SECRET:([a-zA-Z0-9_-]+)}')

# Single combined pattern for substitute_template. Folding every form — the three
# placeholders AND the `$$` literal-dollar escape — into one left-to-right pass is
# a security property, not just an optimization: re.sub never re-scans the text it
# inserts, so a resolved value — e.g. a decrypted secret whose plaintext happens to
# contain "${PATH}", "${SECRET:other}", or "$$" — is emitted verbatim instead of
# being re-expanded or collapsed by a later pass (which would leak host env/other
# secrets, or corrupt a secret containing `$$`, in the rendered guest user-data).
# The SECRET? / SECRET: alternatives precede VAR so a secret ref is never captured
# as a plain var. The placeholder branches carry the (?<!\$) lookbehind and the
# `esc` branch (`\$\$` -> `$`) comes last, so `$$` escaping is uniform: `$${VAR}`,
# `$${SECRET:name}` and `$${SECRET?name}` each have their leading `$$` consumed as
# the escape token and leave a literal `${...}` — the placeholder never resolves.
# Because the collapse rides in this same pass, `$$` in an inserted value survives.
# (A missing lookbehind on the SECRET branches silently broke the escape:
# `$${SECRET:name}` still matched and tried to resolve a secret named "name",
# aborting substitution — see the substitute_template tests in test_workload_lib.)
_SUBSTITUTION_PATTERN = re.compile(
    r'(?<!\$)\$\{SECRET\?(?P<optsecret>[a-zA-Z0-9_-]+)}'
    r'|(?<!\$)\$\{SECRET:(?P<secret>[a-zA-Z0-9_-]+)}'
    r'|(?<!\$)\$\{(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)}'
    r'|(?P<esc>\$\$)'
)

# Container-env secret reference, escape-aware. The escape is meaningful ONLY
# immediately before `{SECRET:`: `(\$)?` captures an optional leading `$`, so
# `$${SECRET:name}` (group 1 set) is a literal that collapses to `${SECRET:name}`
# — the credential is neither read nor demanded — while a bare `${SECRET:name}`
# (group 1 empty) resolves. group 2 is the credential name. Deliberately narrow:
# unlike the cloud-init template path we do NOT globally collapse `$$` in env
# values (they are opaque — a password may legitimately contain `$$`); only the
# exact `$${SECRET:...}` sequence is neutralized. This still matches
# substitute_template's resolve-vs-literal decision for any run of `$` (both
# resolve iff exactly one `$` precedes `{SECRET:`), so a ref the cloud-init path
# treats as inert is never resolved here. re.sub never re-scans inserted text, so
# decrypted secret plaintext is emitted verbatim. Shared by resolve_secret_env_vars
# (resolve) and auto_detect_credentials (demand) so the two agree exactly.
_ENV_SECRET_REF = re.compile(r'(\$)?\$\{SECRET:([a-zA-Z0-9_-]+)}')


def substitute_template(
    text: str,
    template_vars: dict | None = None,
    env: dict | None = None,
    secret_resolver=None,
) -> str:
    """Resolve ${VAR}, ${SECRET:name}, and ${SECRET?name} placeholders.

    Resolution order for ${VAR}: template_vars first, then env. Unresolved
    placeholders raise KeyError so a missing var fails loudly at ISO build
    time rather than producing a broken guest.

    ${SECRET:name} is delegated to secret_resolver(name) -> str so callers
    decide where secrets come from (encrypted credstore, raw file, mock for
    tests). If secret_resolver is None, ${SECRET:...} refs raise KeyError.

    ${SECRET?name} is the *optional* variant: missing credentials (resolver
    raises FileNotFoundError or KeyError) substitute to the empty string
    instead of failing. This lets user-data reference a credential that the
    operator may or may not pre-seed — the rendered shell can check whether
    the resulting value is non-empty before using it.

    ``$$`` collapses to a literal ``$`` in the same pass, matching the
    convention used by Python's string.Template and shell here-docs. Because the
    collapse is part of the single substitution pass (not a later step), a ``$$``
    inside a resolved secret/var value is emitted verbatim, never re-collapsed.
    """
    template_vars = template_vars or {}
    env = env or {}

    def _resolve(match):
        if match.group("esc") is not None:  # `$$` literal-dollar escape
            return "$"
        opt = match.group("optsecret")
        if opt is not None:
            if secret_resolver is None:
                return ""
            try:
                return secret_resolver(opt)
            except (FileNotFoundError, KeyError):
                return ""
        secret = match.group("secret")
        if secret is not None:
            if secret_resolver is None:
                raise KeyError(f"${{SECRET:{secret}}} present but no resolver provided")
            return secret_resolver(secret)
        name = match.group("var")
        if name in template_vars:
            return str(template_vars[name])
        if name in env:
            return env[name]
        raise KeyError(f"unresolved ${{{name}}} in cloud-init template")

    # One left-to-right pass: replacements are not re-scanned, so a resolved
    # secret/var value can't be re-expanded — or have its own `$$` collapsed — by
    # a "later" pass. The `$$`→`$` escape is folded in as the pattern's `esc`
    # branch (see the pattern's comment), so `$${VAR}` still escapes.
    return _SUBSTITUTION_PATTERN.sub(_resolve, text)


def auto_detect_credentials(config: dict) -> set[str]:
    """Auto-detect which credentials are needed by scanning a TOML config.

    Scans:
    - Top-level [container.environment] (single-container TOMLs and the
      per-container slices the generator passes in).
    - [[containers]] entries, both sibling [containers.environment] and
      nested [containers.container.environment], plus per-container
      [containers.secrets].files.
    - Top-level [secrets].files.

    Returns a set of credential names.
    """
    needed = set()

    def _scan_env(env: dict):
        for value in env.values():
            for match in _ENV_SECRET_REF.finditer(str(value)):
                if not match.group(1):  # group 1 set == escaped `$$`, not demanded
                    needed.add(match.group(2))

    _scan_env(config.get("container", {}).get("environment", {}))

    for entry in config.get("containers", []):
        # Multi-container TOMLs may write env at either nesting depth;
        # normalize_containers lifts the sibling form, but this helper is
        # called on the raw config too (CLI commands, backup bundling), so
        # check both.
        _scan_env(entry.get("environment", {}))
        _scan_env(entry.get("container", {}).get("environment", {}))
        for file_spec in entry.get("secrets", {}).get("files", []):
            if "credential" in file_spec:
                needed.add(file_spec["credential"])

    for file_spec in config.get("secrets", {}).get("files", []):
        if "credential" in file_spec:
            needed.add(file_spec["credential"])

    return needed


def resolve_secret_env_vars(config: dict, creds_dir: str) -> dict[str, str]:
    """Resolve environment variables that contain ${SECRET:name} references.

    Reads credential files from creds_dir and substitutes their contents
    into the env var values. `$${SECRET:name}` is the literal escape: it
    collapses to a literal `${SECRET:name}` and the credential is never read.

    Args:
        config: Parsed TOML workload config.
        creds_dir: Path to the credentials directory (e.g., /run/credentials/unit/).

    Returns:
        Dict of {KEY: resolved_value} for env vars that contained secrets.

    Raises:
        FileNotFoundError: If a referenced credential file is missing.
    """
    env_vars = config.get("container", {}).get("environment", {})
    resolved = {}

    for key, value in env_vars.items():
        value_str = str(value)
        if not SECRET_PATTERN.search(value_str):
            continue

        def _sub(match):
            cred_name = match.group(2)
            if match.group(1):  # `$${SECRET:name}` -> literal, no read, no demand
                return "${SECRET:" + cred_name + "}"
            cred_path = Path(creds_dir) / cred_name
            if not cred_path.exists():
                raise FileNotFoundError(
                    f"Credential '{cred_name}' not found at {cred_path}"
                )
            return cred_path.read_text()

        resolved[key] = _ENV_SECRET_REF.sub(_sub, value_str)

    return resolved
