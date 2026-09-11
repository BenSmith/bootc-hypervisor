"""One container's decrypted-secret EnvironmentFile, written for --env-file.

Runs as ExecStartPre=+ (root) on a per-container service after
workload-ensure-user. Reads ${SECRET:name} references out of the container's
environment, resolves them from the unit's CREDENTIALS_DIRECTORY, and writes
KEY=value lines to a file readable only by the workload user:

    /run/workload-env/workload-<workload>.secrets               (single)
    /run/workload-env/workload-<workload>-<container>.secrets   (multi)

Each per-container service has its own CREDENTIALS_DIRECTORY
(LoadCredentialEncrypted attaches to the unit that lists it), so a
multi-container workload writes one file per container rather than letting
concurrent services clobber each other's secrets.

Every refusal is an EnvFileError carrying the operator-facing message; the
entrypoint prints it and exits 1. Warnings are printed here, to stderr, and
never fail the start.
"""
import os
import pwd
import sys
from pathlib import Path

from secrets_template import (
    SECRET_PATTERN,
    auto_detect_credentials,
    resolve_secret_env_vars,
    validate_env_key,
)
from workload_lib import (
    load_workload_config,
    normalize_containers,
    workload_username,
)

ENV_DIR = Path(os.environ.get("WORKLOAD_ENV_DIR", "/run/workload-env"))


class EnvFileError(Exception):
    """Why the file was not written; the message is the whole of the report."""


def env_file_name(name: str, container: str | None) -> str:
    if container is None:
        return f"workload-{name}.secrets"
    return f"workload-{name}-{container}.secrets"


def select_container(config: dict, name: str, container: str | None) -> dict:
    """The normalized entry whose environment is written.

    normalize_containers gives single and multi the same shape (env lives
    under entry["container"]["environment"]), so everything after this is
    uniform. Without a container name there has to be exactly one.
    """
    containers = normalize_containers(config)
    if container is None:
        if len(containers) != 1:
            raise EnvFileError(
                f"workload '{name}' has multiple containers; "
                f"call with <workload-name> <container-name>")
        return containers[0]
    match = [c for c in containers if c.get("name") == container]
    if not match:
        raise EnvFileError(f"container '{container}' not in workload '{name}'")
    return match[0]


def declares_secrets(entry: dict) -> bool:
    env_vars = entry.get("container", {}).get("environment", {})
    return any(SECRET_PATTERN.search(str(v)) for v in env_vars.values())


def remove_stale(path: Path) -> None:
    """A .secrets file from when this container *did* declare secrets must
    not survive. Retiring a ${SECRET:...} reference and restarting is the
    normal way to un-secret a live workload, and nothing else on that path
    removes the decrypted value: the generator just stops emitting the
    EnvironmentFile= line, `recreate` never touches /run, and cmd_disable
    skips kind == "env-file" (removal is --purge only, which is teardown, not
    what you run to drop one secret). Without this the plaintext outlives the
    config change, the credential, and every restart, until the tmpfs is
    cleared by a reboot."""
    try:
        path.unlink(missing_ok=True)
    except OSError as e:
        # Best-effort: never fail the ExecStartPre and block the workload
        # from starting over a leftover file.
        print(f"WARNING: could not remove stale {path}: {e}", file=sys.stderr)


def secret_lines(entry: dict, creds_dir: str | None) -> list[str]:
    """The KEY=VALUE lines, resolved and checked."""
    # A purely-escaped value (`$${SECRET:name}`) is delivered as a literal and
    # reads no credential; only an *unescaped* ref actually needs the decrypted
    # credstore. auto_detect_credentials is escape-aware and is the exact scan
    # the generator used to decide whether to emit LoadCredentialEncrypted --
    # so `demanded` is non-empty iff the unit has a CREDENTIALS_DIRECTORY.
    # Require it only then, so an escaped-only workload (no
    # LoadCredentialEncrypted, hence no CREDENTIALS_DIRECTORY) still writes
    # its literal env-file and boots instead of failing this ExecStartPre.
    demanded = auto_detect_credentials({
        "container": entry.get("container", {}),
        "secrets":   entry.get("secrets", {}),
    })
    if demanded and not creds_dir:
        raise EnvFileError("CREDENTIALS_DIRECTORY not set")

    # resolve_secret_env_vars expects config["container"]["environment"];
    # entry["container"] already has that shape after normalization. With no
    # real ref, creds_dir is never dereferenced (escaped refs resolve to
    # literals), so an empty string is a safe placeholder.
    try:
        resolved = resolve_secret_env_vars({"container": entry["container"]},
                                           creds_dir or "")
    except FileNotFoundError as e:
        raise EnvFileError(str(e)) from e

    lines = []
    for key, value in resolved.items():
        if not validate_env_key(key):
            raise EnvFileError(f"Invalid env var key: {key!r}")
        # Env-file format: KEY=VALUE (one per line, no quoting needed).
        # Newlines in values would inject extra env vars -- reject them.
        if "\n" in value:
            raise EnvFileError(
                f"Secret value for {key} contains newlines; "
                f"use secrets.files[] instead of env var injection")
        lines.append(f"{key}={value}")
    return lines


def write_env_file(path: Path, lines: list[str], name: str) -> None:
    """0600 from the first byte, then owned by the workload user."""
    content = "\n".join(lines) + "\n" if lines else ""
    username = workload_username(name)
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        print(f"WARNING: User {username} not found, env file owned by root",
              file=sys.stderr)
        pw = None

    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode())
    finally:
        os.close(fd)
    if pw:
        os.chown(path, pw.pw_uid, pw.pw_gid)


def write_secrets_env(name: str, container: str | None) -> None:
    """The whole helper for one container: select, resolve, write -- or
    remove what a previous config wrote."""
    config = load_workload_config(name)
    entry = select_container(config, name, container)
    path = ENV_DIR / env_file_name(name, container)
    if not declares_secrets(entry):
        remove_stale(path)
        return
    lines = secret_lines(entry, os.environ.get("CREDENTIALS_DIRECTORY"))
    write_env_file(path, lines, name)
