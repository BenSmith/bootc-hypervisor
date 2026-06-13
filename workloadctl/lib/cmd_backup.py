"""
cmd_backup — backup and restore commands.
"""

import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib

from workload_lib import (
    auto_detect_credentials,
    WORKLOADS_BASE,
    workload_home_dir,
    workload_service_name,
)
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
    WORKLOAD_DIR,
)
from substrate import get_substrate

CREDSTORE_DIR = Path("/etc/credstore.encrypted")
BACKUP_DIR = WORKLOADS_BASE / "backups"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _backup_one(config: WorkloadConfig, output: Path, no_stop: bool, quiet: bool = False) -> int:
    """Create a backup archive for a single workload. Returns size in bytes.

    Routes through the Substrate port so VM backups are safe (excludes
    rebuild artifacts; refuses --no-stop which risks a corrupt live disk).

    Archive layout:
        workload.toml           — the config file
        credentials/            — referenced encrypted credentials (TPM-bound)
        home/                   — home directory (.local/share/containers and
                                  VM rebuild artifacts excluded)
    """
    substrate = get_substrate(config, None)
    return substrate.capture(output, no_stop=no_stop, quiet=quiet)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_backup(args, manager: WorkloadManager):
    """Backup workload configs, credentials, and data"""
    require_root()

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    if args.all:
        configs = manager.get_all_configs()
        if not configs:
            print("No workloads found")
            return
    else:
        if not args.workload:
            print("Error: Specify a workload name or use --all", file=sys.stderr)
            sys.exit(1)
        configs = [WorkloadConfig(args.workload)]

    backups = []
    skipped = []
    for config in configs:
        name = config.name

        # VM live-backup guard: tarring a running qcow2 without guest-agent
        # fsfreeze + QMP quiesce can capture a torn, unbootable image. Until that
        # quiesce path exists, refuse --no-stop for VMs rather than silently risk a
        # corrupt backup. (Containers back up a stopped rootfs/volumes and are unaffected.)
        if args.no_stop and config.is_vm:
            msg = (f"--no-stop is unsafe for VM workload '{name}': backing up a live "
                   f"qcow2 without guest quiesce can produce a corrupt image. "
                   f"Re-run without --no-stop for a consistent (stopped) backup.")
            if args.all:
                if not args.json:
                    print(f"  Skipping {name}: {msg}", file=sys.stderr)
                skipped.append(name)
                continue
            print(f"Error: {msg}", file=sys.stderr)
            sys.exit(1)

        if args.output:
            output = Path(args.output)
            if output.is_dir():
                output = output / f"{name}-{timestamp}.tar.zst"
        else:
            output = BACKUP_DIR / f"{name}-{timestamp}.tar.zst"

        if not args.json:
            print(f"Backing up: {name}")
        size_bytes = _backup_one(config, output, args.no_stop, quiet=args.json)
        backups.append({"workload": name, "archive": str(output), "size_bytes": size_bytes})

    if args.json:
        result = {"backups": backups}
        if skipped:
            result["skipped"] = skipped
        print(json.dumps(result, indent=2))
    elif args.all:
        print(f"\nBacked up {len(backups)} workload(s)")
        if skipped:
            print(f"Skipped {len(skipped)} VM workload(s) (--no-stop unsafe): "
                  f"{', '.join(skipped)}")


def cmd_restore(args, manager: WorkloadManager):
    """Restore a workload from a backup archive"""
    require_root()

    archive = Path(args.archive)
    if not archive.exists():
        print(f"Error: Archive not found: {archive}", file=sys.stderr)
        sys.exit(1)

    # Extract to temp dir to inspect contents
    with tempfile.TemporaryDirectory() as staging:
        staging = Path(staging)
        subprocess.run(
            ["tar", "-C", str(staging), "-xf", str(archive), "--zstd"],
            check=True,
        )

        # Read the config to get the workload name
        config_path = staging / "workload.toml"
        if not config_path.exists():
            print("Error: Archive does not contain workload.toml", file=sys.stderr)
            sys.exit(1)

        with open(config_path, "rb") as f:
            config_data = tomllib.load(f)

        name = config_data.get("workload", {}).get("name", "")
        if not name:
            print("Error: workload.toml has no workload name", file=sys.stderr)
            sys.exit(1)

        print(f"Restoring workload: {name}")

        # Check if workload already exists
        dest_config = WORKLOAD_DIR / f"{name}.toml"
        dest_home = workload_home_dir(name)
        if dest_config.exists() and not args.force:
            print(f"Error: Config already exists: {dest_config}", file=sys.stderr)
            print("Use --force to overwrite", file=sys.stderr)
            sys.exit(1)

        # Stop existing service if running
        service_name = workload_service_name(name)
        subprocess.run(["systemctl", "stop", service_name],
                        capture_output=True)

        # 1. Restore config
        print(f"  Config → {dest_config}")
        shutil.copy2(config_path, dest_config)

        # 2. Restore credentials
        cred_staging = staging / "credentials"
        restored_creds = []
        tpm_warning = False
        if cred_staging.is_dir():
            CREDSTORE_DIR.mkdir(parents=True, exist_ok=True)
            for cred_file in sorted(cred_staging.iterdir()):
                dest_cred = CREDSTORE_DIR / cred_file.name
                if dest_cred.exists() and not args.force:
                    print(f"  Credential '{cred_file.name}' already exists, skipping")
                else:
                    shutil.copy2(cred_file, dest_cred)
                    restored_creds.append(cred_file.name)
                    print(f"  Credential → {dest_cred}")
                    tpm_warning = True

        # 3. Restore home directory
        home_staging = staging / "home"
        if home_staging.is_dir():
            if dest_home.exists():
                if args.force:
                    shutil.rmtree(dest_home)
                else:
                    print(f"  Warning: Home dir exists, merging (use --force to replace)")
            shutil.copytree(home_staging, dest_home,
                            symlinks=True, dirs_exist_ok=True)
            print(f"  Home dir → {dest_home}")

        print()

        # 4. Note about excluded image storage
        print("Note: container images are not included in backups.")
        print(f"Run `workloadctl update {name}` to re-pull images after starting.")
        print()

        # 5. TPM warning for cross-machine restores
        if tpm_warning:
            print("Note: Credentials are TPM-bound to the original machine.")
            print("If restoring on a different machine, re-encrypt each credential:")
            for cred_name in restored_creds:
                print(f"  sudo workloadctl secret rotate {cred_name}")
            print()

        # 6. Enable the workload
        if args.enable:
            print(f"Enabling {name}...")
            subprocess.run(
                ["workloadctl", "enable", name],
            )
        else:
            print(f"To start the workload, run:")
            print(f"  sudo workloadctl enable {name}")
