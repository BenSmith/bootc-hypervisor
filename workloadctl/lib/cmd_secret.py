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


# ---------------------------------------------------------------------------
# cmd_secret
# ---------------------------------------------------------------------------

def cmd_secret(args, manager: WorkloadManager):
    """Manage secrets (systemd credentials)"""
    cred_dir = Path(CREDSTORE_DIR)

    if args.subcommand == "create":
        require_root()
        name = args.name

        # Validate secret name
        if not re.match(r'^[a-zA-Z0-9_-]+$', name):
            print("Error: Secret name must contain only letters, numbers, underscore, and hyphen", file=sys.stderr)
            sys.exit(1)

        cred_file = cred_dir / name

        if cred_file.exists() and not args.force:
            print(f"Error: Credential '{name}' already exists. Use --force to overwrite.", file=sys.stderr)
            sys.exit(1)

        # Create credstore directory if it doesn't exist (0o700: only root can list)
        cred_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Determine encryption key type
        key_type = args.key_type or "tpm2"

        # Read secret from stdin or file
        secret_value = None
        if args.file:
            # Encrypt from file
            cmd = [
                "systemd-creds", "encrypt",
                f"--with-key={key_type}",
                f"--name={name}",
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
                f"--name={name}",
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

        creds = sorted(p for p in cred_dir.iterdir() if p.is_file())

        if args.json:
            print(json.dumps({
                "credentials": [
                    {"name": p.name, "size": p.stat().st_size, "modified": int(p.stat().st_mtime)}
                    for p in creds
                ]
            }, indent=2))
            return

        if not creds:
            print("No credentials found")
            return

        print(f"{'NAME':<30} {'SIZE':<10} {'MODIFIED':<20}")
        print("-" * 60)
        for cred in creds:
            name = cred.name
            size = cred.stat().st_size
            mtime = cred.stat().st_mtime
            mod_time = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            print(f"{name:<30} {size:<10} {mod_time:<20}")

        print(f"\nTotal: {len(creds)} credential(s)")
        print(f"Location: {cred_dir}")

    elif args.subcommand == "delete":
        require_root()
        name = args.name
        cred_file = cred_dir / name

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
        cred_file = cred_dir / name

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
        cred_file = cred_dir / name

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
            f"--name={name}",
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

        cred_file = cred_dir / name
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

        cred_file = cred_dir / name
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
        cred_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            subprocess.run(
                ["systemd-creds", "encrypt", f"--with-key={key_type}",
                 f"--name={name}", "-", str(cred_file)],
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
