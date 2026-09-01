"""
cmd_secret — secret management commands (systemd credentials).
"""

import datetime
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

from workload_lib import (
    CREDSTORE_DIR,
    iter_workloads,
)
from secrets_template import auto_detect_credentials
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
)
from service_runtime import restart_workload_service


# --- Portable secret export format (ADR 004) ---
#
# v1 was `openssl enc -aes-256-cbc -pbkdf2` with no explicit iteration count and
# no integrity — a stored, off-host blob with a weak KDF and no tamper
# detection. v2 adds a modern KDF (pbkdf2, 600k iters) AND integrity via
# encrypt-then-HMAC-SHA256: `openssl enc` cannot safely do AEAD/GCM (the CLI
# doesn't handle the auth tag), so we authenticate the ciphertext explicitly.
# `import` detects the version by header, so existing v1 blobs stay restorable.
SECRET_EXPORT_V2_MAGIC = b"WLCTLsecret-v2\n"
_SECRET_PBKDF2_ITERS = 600000
_SECRET_MAC_SALT_LEN = 16
_SECRET_MAC_LEN = 32  # HMAC-SHA256 digest size


def _openssl_pass_enc(openssl_args: list, data: bytes, passphrase: str) -> bytes:
    """Run `openssl enc` with the passphrase supplied via a 0600 temp file
    (never argv, so it can't leak through /proc/*/cmdline)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pass") as pf:
        pf.write(passphrase)
        pf.flush()
        os.chmod(pf.name, 0o600)
        return subprocess.run(
            ["openssl", "enc", *openssl_args, "-pass", f"file:{pf.name}"],
            input=data, capture_output=True, check=True,
        ).stdout


def _secret_export_encrypt_v2(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt-then-MAC: AES-256-CBC (pbkdf2, 600k iters) + HMAC-SHA256 over the
    ciphertext, keyed by a separately-salted passphrase-derived key."""
    ciphertext = _openssl_pass_enc(
        ["-aes-256-cbc", "-pbkdf2", "-iter", str(_SECRET_PBKDF2_ITERS), "-salt"],
        plaintext, passphrase)
    mac_salt = os.urandom(_SECRET_MAC_SALT_LEN)
    mac_key = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode(), mac_salt, _SECRET_PBKDF2_ITERS, dklen=32)
    tag = hmac.new(
        mac_key, SECRET_EXPORT_V2_MAGIC + mac_salt + ciphertext, hashlib.sha256
    ).digest()
    return SECRET_EXPORT_V2_MAGIC + mac_salt + tag + ciphertext


def _secret_export_decrypt(blob: bytes, passphrase: str) -> bytes:
    """Decrypt a v1 or v2 exported blob, detected by header.

    Raises ValueError on v2 integrity failure (a tampered blob or a wrong
    passphrase — the MAC key is passphrase-derived, so both fail here before any
    decryption is attempted). Propagates subprocess.CalledProcessError on an
    openssl decrypt failure (v1 wrong passphrase).
    """
    if blob.startswith(SECRET_EXPORT_V2_MAGIC):
        body = blob[len(SECRET_EXPORT_V2_MAGIC):]
        mac_salt = body[:_SECRET_MAC_SALT_LEN]
        tag = body[_SECRET_MAC_SALT_LEN:_SECRET_MAC_SALT_LEN + _SECRET_MAC_LEN]
        ciphertext = body[_SECRET_MAC_SALT_LEN + _SECRET_MAC_LEN:]
        mac_key = hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode(), mac_salt, _SECRET_PBKDF2_ITERS, dklen=32)
        expected = hmac.new(
            mac_key, SECRET_EXPORT_V2_MAGIC + mac_salt + ciphertext, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, tag):
            raise ValueError(
                "integrity check failed — tampered export or wrong passphrase")
        return _openssl_pass_enc(
            ["-d", "-aes-256-cbc", "-pbkdf2", "-iter", str(_SECRET_PBKDF2_ITERS)],
            ciphertext, passphrase)
    # Legacy v1: openssl enc -aes-256-cbc -pbkdf2 (default iters), no integrity.
    return _openssl_pass_enc(["-d", "-aes-256-cbc", "-pbkdf2"], blob, passphrase)


def _read_passphrase(args, *, prompt: str, confirm: bool) -> str:
    """Resolve a passphrase from a non-interactive source or interactive prompt.

    Precedence: --passphrase-stdin / --passphrase-file ('-' == stdin) over the
    prompt. For file/stdin sources a single trailing newline is stripped so the
    common `echo pw > file` / `... | workloadctl ...` idioms work, but an
    *embedded* newline is rejected: a multi-line passphrase file is almost
    always an accident (extra line, pasted blob) that would otherwise encrypt
    with bytes the operator didn't intend and fail to decrypt later. The
    passphrase must be non-empty. `confirm` adds a second interactive prompt
    (export); import uses a single prompt.
    """
    from_stdin = getattr(args, "passphrase_stdin", False)
    pass_file = getattr(args, "passphrase_file", None)

    if from_stdin or pass_file == "-":
        passphrase = _strip_trailing_newline(sys.stdin.buffer.read().decode())
    elif pass_file:
        try:
            passphrase = _strip_trailing_newline(Path(pass_file).read_text())
        except OSError as e:
            print(f"Error: Cannot read passphrase file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # getpass already strips the trailing newline of interactive input.
        passphrase = getpass.getpass(prompt)
        if confirm and passphrase != getpass.getpass("Confirm passphrase: "):
            print("Error: Passphrases do not match", file=sys.stderr)
            sys.exit(1)

    if not passphrase:
        print("Error: Passphrase cannot be empty", file=sys.stderr)
        sys.exit(1)
    if "\n" in passphrase or "\r" in passphrase:
        print("Error: Passphrase must be a single line (no embedded newlines)",
              file=sys.stderr)
        sys.exit(1)
    return passphrase


def _read_secret_value(name: str, *, action: str) -> bytes:
    """Read a secret value to hand to `systemd-creds encrypt` on stdin.

    Piped/redirected stdin is passed through VERBATIM — no strip, no decode —
    so `echo -n pw | workloadctl secret create ...` and binary payloads keep
    working byte-for-byte.

    On a TTY we prompt with echo OFF (getpass) and confirm. The old path just
    printed "press Ctrl+D when done" and let systemd-creds read the inherited
    terminal, which displayed every character of the credential as it was
    typed — it stayed in scrollback and in anyone's line of sight. It also made
    a trailing newline nearly unavoidable (Enter, then Ctrl+D), and a secret
    with a newline in it fails later at a much less obvious place: the unit
    generator rejects newlines in env-injected values, so three services fail
    to start with no hint that the password is the problem. getpass returns the
    typed line with no terminator, so both go away together.
    """
    if sys.stdin is None:
        # `workloadctl secret create x 0<&-`. Nothing to read and no terminal to
        # prompt on; say so instead of an AttributeError traceback.
        print("Error: No stdin to read the secret value from — pipe a value, "
              "use --file, or run from a terminal", file=sys.stderr)
        sys.exit(1)

    if not sys.stdin.isatty():
        value = sys.stdin.buffer.read()
        # A trailing newline is almost always `echo` without -n, and it is the
        # same defect the interactive path used to produce: it survives into the
        # credential and only fails later, at unit start, where the error names
        # newlines but not the command that introduced them. Warn rather than
        # strip — a binary payload or a value that deliberately ends in \n is
        # legitimate, and silently altering a credential is worse than a noisy
        # one. stderr so it can't land in a value being captured downstream.
        if value.endswith(b"\n"):
            print("Warning: secret value ends with a newline — if that wasn't "
                  "intended use `printf` or `echo -n`, and re-create with "
                  "--force. Workloads that inject this as an env var will fail "
                  "to start.", file=sys.stderr)
        return value

    value = getpass.getpass(f"{action} secret value for '{name}': ")
    if value != getpass.getpass("Confirm: "):
        print("Error: Values do not match", file=sys.stderr)
        sys.exit(1)
    if not value:
        print("Error: Secret value cannot be empty", file=sys.stderr)
        sys.exit(1)
    return value.encode()


def _strip_trailing_newline(text: str) -> str:
    """Strip exactly one trailing newline (LF or CRLF), nothing more."""
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


# The one scope below the credstore root, and the only one. Broker material
# (ADR 007) lives at <credstore>/broker/<workload>/<name>: it is operator-
# created, encrypted, and has to survive a reboot like everything else here,
# but it must never be reachable from a workload's environment.
#
# THAT UNREACHABILITY IS STRUCTURAL AND COMES FROM ONE CHARACTER, TWICE. `/` is
# what makes the credential nameable on this CLI, and it is what makes it
# unnameable from workload env: secrets_template.SECRET_PATTERN is
# `\$\{SECRET:([a-zA-Z0-9_-]+)}` and has no `/`, so `${SECRET:broker/x/y}`
# does not match the pattern at all -- it is not refused by a rule that could
# be relaxed, it is unrepresentable. A future pass that "tidied" the pattern by
# adding `/` to that class would open this silently, which is why the test for
# it asserts against SECRET_PATTERN and the resolver rather than against a
# validation message.
CREDENTIAL_SCOPES = ("broker",)

# One path segment. The same class the unscoped form has always enforced, and
# it is what keeps a scoped name inside its own workload's subtree: no `/`, so
# no traversal, and no `..`, so nothing to normalise away.
_SEGMENT_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def credential_path(cred_dir: Path, name: str):
    """(file, seal_name) for one credential name, scoped or not.

    Two forms:

      `<name>`                     -> <credstore>/<name>, sealed --name=<name>
      `broker/<workload>/<name>`   -> <credstore>/broker/<workload>/<name>,
                                      sealed --name=broker-<workload>-<name>

    The seal name matters as much as the path. systemd-creds binds the
    plaintext to the name it was sealed under, so a generated unit that
    LoadCredentialEncrypted='s another workload's file gets a decryption
    failure rather than the material -- the path is not the boundary, the seal
    name is, and it carries the workload.

    Scoping is a NAME FORM and not a flag, deliberately: every verb takes a
    name already, so this reaches all seven at once with no new argparse
    option, no completions change, no docs/cli.md matrix row, and nothing for
    tests/test_completions.py's one-way blindness (it catches offered-but-unreal
    flags, never unoffered-but-real ones) to miss.

    Raises ValueError with an operator-readable message.
    """
    parts = name.split("/")
    if len(parts) == 1:
        if not _SEGMENT_RE.match(name):
            raise ValueError(
                "Secret name must contain only letters, numbers, underscore "
                "and hyphen — or be a scoped name like "
                "'broker/<workload>/<credential>'")
        return cred_dir / name, name
    if parts[0] not in CREDENTIAL_SCOPES:
        raise ValueError(
            f"Unknown credential scope {parts[0]!r}; the scoped form is "
            f"'{CREDENTIAL_SCOPES[0]}/<workload>/<credential>'")
    if len(parts) != 3:
        raise ValueError(
            f"A {parts[0]!r} credential is named "
            f"'{parts[0]}/<workload>/<credential>' — three segments, got "
            f"{len(parts)}")
    if not all(_SEGMENT_RE.match(part) for part in parts):
        raise ValueError(
            "Each segment of a scoped name must contain only letters, "
            "numbers, underscore and hyphen")
    scope, workload, leaf = parts
    return cred_dir / scope / workload / leaf, f"{scope}-{workload}-{leaf}"


def iter_credentials(cred_dir: Path):
    """(display name, path) for every credential, scoped ones included.

    Scoped material used to be invisible here, because `list` read one
    directory and kept only files -- so a subtree looked like nothing at all,
    and an operator checking whether a workload's key was present got "no
    credentials found" for a key that was sitting right there. Sorted by
    display name so the scoped entries group under their scope.
    """
    if not cred_dir.exists():
        return []
    found = []
    for path in cred_dir.iterdir():
        if path.is_file():
            found.append((path.name, path))
        elif path.is_dir() and path.name in CREDENTIAL_SCOPES:
            for workload_dir in path.iterdir():
                if not workload_dir.is_dir():
                    continue
                for leaf in workload_dir.iterdir():
                    if leaf.is_file():
                        found.append(
                            (f"{path.name}/{workload_dir.name}/{leaf.name}",
                             leaf))
    return sorted(found)


# ---------------------------------------------------------------------------
# cmd_secret
# ---------------------------------------------------------------------------

def cmd_secret(args, manager: WorkloadManager):
    """Manage secrets (systemd credentials)"""
    cred_dir = Path(CREDSTORE_DIR)

    # Resolved once for every verb that takes a name, so the scoped form works
    # on all of them rather than on the three somebody remembered.
    cred_file = seal_name = None
    if getattr(args, "name", None) is not None:
        try:
            cred_file, seal_name = credential_path(cred_dir, args.name)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    if args.subcommand == "create":
        require_root()
        name = args.name

        if cred_file.exists() and not args.force:
            print(f"Error: Credential '{name}' already exists. Use --force to overwrite.", file=sys.stderr)
            sys.exit(1)

        # Create the credstore directory, and the scope subtree with it, if
        # they do not exist (0o700: only root can list).
        cred_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Determine encryption key type
        key_type = args.key_type or "tpm2"

        # Read secret from stdin or file
        secret_value = None
        if args.file:
            # Encrypt from file
            cmd = [
                "systemd-creds", "encrypt",
                f"--with-key={key_type}",
                f"--name={seal_name}",
                str(Path(args.file).expanduser()),
                str(cred_file)
            ]
        else:
            # Encrypt from stdin — read it ourselves so an interactive value is
            # never echoed to the terminal (see _read_secret_value).
            secret_value = _read_secret_value(name, action="Enter")
            cmd = [
                "systemd-creds", "encrypt",
                f"--with-key={key_type}",
                f"--name={seal_name}",
                "-", str(cred_file)
            ]

        try:
            subprocess.run(cmd, input=secret_value, check=True)
            os.chmod(cred_file, 0o600)
            print(f"✓ Created encrypted credential: {cred_file}")
            print(f"  Encryption: {key_type}")
            print(f"  Size: {cred_file.stat().st_size} bytes")
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to create credential: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "list":
        if not cred_dir.exists():
            if args.json:
                print(json.dumps({"credentials": []}, indent=2))
            else:
                print("No credentials found (directory does not exist)")
            return

        # Scoped material included, under its full name. This used to read one
        # directory and keep only files, so a whole subtree was invisible: an
        # operator checking whether a workload's broker key was present got "no
        # credentials found" for material sitting right there, and the natural
        # next step is to seal it again.
        creds = iter_credentials(cred_dir)

        if args.json:
            print(json.dumps({
                "credentials": [
                    {"name": name, "size": p.stat().st_size, "modified": int(p.stat().st_mtime)}
                    for name, p in creds
                ]
            }, indent=2))
            return

        if not creds:
            print("No credentials found")
            return

        # Wide enough for `broker/<workload>/<credential>`, which is the whole
        # point of showing the scope rather than the leaf.
        print(f"{'NAME':<44} {'SIZE':<10} {'MODIFIED':<20}")
        print("-" * 74)
        for name, cred in creds:
            size = cred.stat().st_size
            mtime = cred.stat().st_mtime
            mod_time = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            print(f"{name:<44} {size:<10} {mod_time:<20}")

        print(f"\nTotal: {len(creds)} credential(s)")
        print(f"Location: {cred_dir}")

    elif args.subcommand == "delete":
        require_root()
        name = args.name

        if not cred_file.exists():
            print(f"Error: Credential '{name}' not found", file=sys.stderr)
            sys.exit(1)

        if not args.force:
            response = input(f"Delete credential '{name}'? [y/N]: ")
            if response.lower() != 'y':
                print("Cancelled")
                return

        cred_file.unlink()
        print(f"✓ Deleted credential: {name}")

    elif args.subcommand == "show":
        require_root()
        name = args.name

        if not cred_file.exists():
            print(f"Error: Credential '{name}' not found", file=sys.stderr)
            sys.exit(1)

        # Decrypt and show
        try:
            decrypted = subprocess.run(
                ["systemd-creds", "decrypt", str(cred_file), "-"],
                capture_output=True,
                check=True,
                text=True
            )
            print(f"Credential: {name}")
            print(f"Value: {decrypted.stdout}", end="")
            if not decrypted.stdout.endswith("\n"):
                print()  # Add newline if value doesn't have one
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to decrypt credential: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "rotate":
        require_root()
        name = args.name

        if not cred_file.exists():
            print(f"Error: Credential '{name}' not found", file=sys.stderr)
            sys.exit(1)

        # Find workloads using this credential (via secrets.files or ${SECRET:name}
        # env refs, in any of single/pod/bridge shape) — same scan `import` uses.
        affected_workloads = []
        for _, workload_file in iter_workloads():
            try:
                with open(workload_file, "rb") as f:
                    wl_config = tomllib.load(f)
                if name in auto_detect_credentials(wl_config):
                    affected_workloads.append(wl_config["workload"]["name"])
            except Exception:
                pass

        if affected_workloads:
            print(f"The following workloads use credential '{name}':")
            for wl in affected_workloads:
                print(f"  - {wl}")
            print()

        # Prompt for the new value (echo off on a TTY — see _read_secret_value)
        secret_value = _read_secret_value(name, action="Enter new")
        key_type = args.key_type or "tpm2"

        cmd = [
            "systemd-creds", "encrypt",
            f"--with-key={key_type}",
            f"--name={seal_name}",
            "-", str(cred_file)
        ]

        try:
            subprocess.run(cmd, input=secret_value, check=True)
            os.chmod(cred_file, 0o600)
            print(f"✓ Rotated credential: {name}")

            # Restart affected workloads
            if affected_workloads:
                print("\nRestarting affected workloads...")
                for wl_name in affected_workloads:
                    try:
                        wl = WorkloadConfig(wl_name)
                        # Containers go through the self-healing restart (re-pin
                        # runtime dir + clear start-limit thrash); VMs have no
                        # /run/user/<uid>, so restart them plainly.
                        if wl.is_vm:
                            subprocess.run(["systemctl", "restart", wl.service_name], check=True)
                        else:
                            restart_workload_service(wl.uid, wl.service_name)
                        print(f"  ✓ Restarted {wl_name}")
                    except Exception as e:
                        print(f"  ✗ Failed to restart {wl_name}: {e}", file=sys.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to rotate credential: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "export":
        require_root()
        name = args.name

        if not cred_file.exists():
            print(f"Error: Credential '{name}' not found", file=sys.stderr)
            sys.exit(1)

        # Decrypt the credential
        try:
            result = subprocess.run(
                ["systemd-creds", "decrypt", str(cred_file), "-"],
                capture_output=True, check=True,
            )
            plaintext = result.stdout
        except subprocess.CalledProcessError:
            print("Error: Failed to decrypt credential (TPM unavailable?)", file=sys.stderr)
            sys.exit(1)

        # Read passphrase (non-interactive source or interactive double-prompt)
        passphrase = _read_passphrase(args, prompt="Passphrase for export: ",
                                      confirm=True)

        # Encrypt with the versioned, integrity-protected v2 format (ADR 004).
        output = Path(args.output) if args.output else Path(f"{name}.secret")
        try:
            blob = _secret_export_encrypt_v2(plaintext, passphrase)
        except subprocess.CalledProcessError:
            print("Error: Failed to encrypt with passphrase", file=sys.stderr)
            sys.exit(1)
        output.write_bytes(blob)

        print(f"✓ Exported credential '{name}' to {output}")
        print("  Transfer this file to the target machine, then import with:")
        print(f"  sudo workloadctl secret import {name} {output}")

    elif args.subcommand == "import":
        require_root()
        name = args.name
        input_file = Path(args.file)

        if not input_file.exists():
            print(f"Error: File not found: {input_file}", file=sys.stderr)
            sys.exit(1)

        if cred_file.exists() and not args.force:
            print(f"Error: Credential '{name}' already exists. Use --force to overwrite.", file=sys.stderr)
            sys.exit(1)

        # Read passphrase (non-interactive source or interactive prompt)
        passphrase = _read_passphrase(args, prompt="Passphrase: ", confirm=False)

        # Decrypt — detects v2 (integrity-checked) vs legacy v1 by header.
        try:
            plaintext = _secret_export_decrypt(input_file.read_bytes(), passphrase)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        except subprocess.CalledProcessError:
            print("Error: Failed to decrypt (wrong passphrase?)", file=sys.stderr)
            sys.exit(1)

        # Re-encrypt with systemd-creds (TPM-bound)
        key_type = args.key_type or "tpm2"
        cred_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            subprocess.run(
                ["systemd-creds", "encrypt", f"--with-key={key_type}",
                 f"--name={seal_name}", "-", str(cred_file)],
                input=plaintext, check=True,
            )
            os.chmod(cred_file, 0o600)
        except subprocess.CalledProcessError:
            print("Error: Failed to encrypt with systemd-creds", file=sys.stderr)
            sys.exit(1)

        print(f"✓ Imported credential '{name}' → {cred_file}")
        print(f"  Encryption: {key_type}")

        # Suggest restart if workloads use this credential
        affected = []
        for _, wl_file in iter_workloads():
            try:
                with open(wl_file, "rb") as f:
                    wl_config = tomllib.load(f)
                wl_creds = auto_detect_credentials(wl_config)
                if name in wl_creds:
                    affected.append(wl_config["workload"]["name"])
            except Exception:
                pass
        if affected:
            print("\n  Restart affected workloads:")
            for wl_name in affected:
                print(f"    sudo workloadctl recreate {wl_name}")
