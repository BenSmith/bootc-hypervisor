"""
cmd_secret — secret management commands (systemd credentials).
"""

import datetime
import getpass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

from workload_lib import (
    auto_detect_credentials,
)
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    restart_workload_service,
    require_root,
    WORKLOAD_DIR,
)


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
    cred_dir = Path("/etc/credstore.encrypted")

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
        if args.file:
            # Encrypt from file
            cmd = [
                "systemd-creds", "encrypt",
                f"--with-key={key_type}",
                str(Path(args.file).expanduser()),
                str(cred_file)
            ]
        else:
            # Encrypt from stdin
            print(f"Enter secret value for '{name}' (press Ctrl+D when done):")
            cmd = [
                "systemd-creds", "encrypt",
                f"--with-key={key_type}",
                f"--name={name}",
                "-", str(cred_file)
            ]

        try:
            result = subprocess.run(cmd, check=True)
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
            result = subprocess.run(
                ["systemd-creds", "decrypt", str(cred_file), "-"],
                capture_output=True,
                check=True,
                text=True
            )
            print(f"Credential: {name}")
            print(f"Value: {result.stdout}", end="")
            if not result.stdout.endswith("\n"):
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

        # Find workloads using this credential (via secrets.files or ${SECRET:name} env refs)
        affected_workloads = []
        cred_env_pattern = re.compile(r'\$\{SECRET:([a-zA-Z0-9_-]+)\}')
        for workload_file in WORKLOAD_DIR.glob("*.toml"):
            try:
                with open(workload_file, "rb") as f:
                    wl_config = tomllib.load(f)
                uses_cred = False
                for file_spec in wl_config.get("secrets", {}).get("files", []):
                    if file_spec.get("credential") == name:
                        uses_cred = True
                        break
                if not uses_cred:
                    for val in wl_config.get("container", {}).get("environment", {}).values():
                        if any(m.group(1) == name for m in cred_env_pattern.finditer(str(val))):
                            uses_cred = True
                            break
                if uses_cred:
                    affected_workloads.append(wl_config["workload"]["name"])
            except Exception:
                pass

        if affected_workloads:
            print(f"The following workloads use credential '{name}':")
            for wl in affected_workloads:
                print(f"  - {wl}")
            print()

        # Prompt for new value
        print(f"Enter new secret value for '{name}' (press Ctrl+D when done):")
        key_type = args.key_type or "tpm2"

        cmd = [
            "systemd-creds", "encrypt",
            f"--with-key={key_type}",
            f"--name={name}",
            "-", str(cred_file)
        ]

        try:
            subprocess.run(cmd, check=True)
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

        # Encrypt with openssl (passphrase-based, portable)
        # Use a temp file for the passphrase to avoid leaking it in /proc/*/cmdline
        output = Path(args.output) if args.output else Path(f"{name}.secret")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pass') as pf:
            pf.write(passphrase)
            pf.flush()
            os.chmod(pf.name, 0o600)
            try:
                subprocess.run(
                    ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
                     "-pass", f"file:{pf.name}", "-out", str(output)],
                    input=plaintext, check=True,
                )
            except subprocess.CalledProcessError:
                print("Error: Failed to encrypt with passphrase", file=sys.stderr)
                sys.exit(1)

        print(f"✓ Exported credential '{name}' to {output}")
        print(f"  Transfer this file to the target machine, then import with:")
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

        # Decrypt with openssl
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pass') as pf:
            pf.write(passphrase)
            pf.flush()
            os.chmod(pf.name, 0o600)
            try:
                result = subprocess.run(
                    ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
                     "-pass", f"file:{pf.name}", "-in", str(input_file)],
                    capture_output=True, check=True,
                )
                plaintext = result.stdout
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
        for wl_file in WORKLOAD_DIR.glob("*.toml"):
            try:
                with open(wl_file, "rb") as f:
                    wl_config = tomllib.load(f)
                creds = auto_detect_credentials(wl_config)
                if name in creds:
                    affected.append(wl_config["workload"]["name"])
            except Exception:
                pass
        if affected:
            print(f"\n  Restart affected workloads:")
            for wl_name in affected:
                print(f"    sudo workloadctl recreate {wl_name}")
