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
    validate_workload_name,
    workload_config_path,
    WORKLOADS_BASE,
    workload_data_dir,
    workload_service_name,
)
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    require_root,
)
from substrate import get_substrate, BackupError

CREDSTORE_DIR = Path("/etc/credstore.encrypted")
BACKUP_DIR = WORKLOADS_BASE / "backups"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _backup_one(config: WorkloadConfig, output: Path, consistency: str, quiet: bool = False) -> int:
    """Create a backup archive for a single workload. Returns size in bytes.

    Routes through the Substrate port so VM backups are safe (excludes
    rebuild artifacts; uses QMP-paused copy for crash-consistent VM backups).

    Archive layout:
        workload.toml           — the config file
        credentials/            — referenced encrypted credentials (TPM-bound)
        data/                   — the precious data/ subtree (the only captured
                                  state; reconstructible state/ is never backed up)
    """
    substrate = get_substrate(config, None)
    try:
        return substrate.capture(output, consistency=consistency, quiet=quiet)
    except BackupError:
        # Already a clean per-workload failure (e.g. QMP unreachable on a VM);
        # the substrate printed its diagnostic. Let the caller isolate it.
        raise
    except (subprocess.CalledProcessError, OSError, shutil.Error) as e:
        # Normalize copy/IO faults (tar exited nonzero, disk full, a permission
        # error, a missing path) into BackupError so a single bad workload can't
        # abort a whole --all run with a traceback — same isolation the crash
        # path already gets. The underlying tool's stderr is already on the
        # terminal; this just adds the workload context.
        raise BackupError(f"backup of '{config.name}' failed: {e}") from e


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

    # In --all mode every workload gets its own archive, so --output names a
    # directory; a single file path would clobber every archive into one.
    if args.all and args.output:
        out_dir = Path(args.output)
        if out_dir.exists() and not out_dir.is_dir():
            print(f"Error: --output must be a directory when using --all "
                  f"(got a file: {out_dir})", file=sys.stderr)
            sys.exit(1)

    backups = []
    failed = []
    for config in configs:
        name = config.name

        if args.all:
            out_dir = Path(args.output) if args.output else BACKUP_DIR
            output = out_dir / f"{name}-{timestamp}.tar.zst"
        elif args.output:
            output = Path(args.output)
            if output.is_dir():
                output = output / f"{name}-{timestamp}.tar.zst"
        else:
            output = BACKUP_DIR / f"{name}-{timestamp}.tar.zst"

        if not args.json:
            print(f"Backing up: {name}")
        try:
            size_bytes = _backup_one(config, output, args.consistency, quiet=args.json)
        except BackupError as e:
            # Isolate per-workload backup faults (a VM whose QMP monitor is
            # unreachable, or a copy that failed) so one bad workload can't abort
            # a whole --all run. A diagnostic was already printed to stderr — by
            # the substrate for QMP faults, or by the underlying tool (tar, etc.)
            # for copy faults — and the message is also recorded under 'failed'.
            failed.append({"workload": name, "error": str(e)})
            continue
        backups.append({"workload": name, "archive": str(output), "size_bytes": size_bytes})

    if args.json:
        result: dict[str, list] = {"backups": backups}
        if failed:
            result["failed"] = failed
        print(json.dumps(result, indent=2))
    elif args.all:
        print(f"\nBacked up {len(backups)} workload(s)")
        if failed:
            print(f"Failed to back up {len(failed)} workload(s): "
                  f"{', '.join(f['workload'] for f in failed)}", file=sys.stderr)

    # Surface partial/total failure with a nonzero exit (covers both the
    # single-workload path and --all).
    if failed:
        sys.exit(1)


def _assert_no_escaping_symlinks(root: Path) -> None:
    """Reject any symlink under `root` whose target resolves outside `root`.

    Restore lays the archive's data/ tree down verbatim (copytree symlinks=True)
    and the archive may have been authored on another, untrusted host. A member
    symlink like `data/x -> /etc` or `data/x -> ../../etc` would otherwise be
    restored pointing out of the workload's own tree (and a later write through
    it could land on host paths). Self-contained relative symlinks that stay
    within the tree are allowed. We enforce this here rather than leaning on
    tar's version-dependent traversal heuristics.
    """
    root_resolved = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for entry in dirnames + filenames:
            p = Path(dirpath) / entry
            if not p.is_symlink():
                continue
            target = (p.parent / os.readlink(p)).resolve()
            if target != root_resolved and not target.is_relative_to(root_resolved):
                raise ValueError(
                    f"archive symlink escapes the data tree: "
                    f"{p.relative_to(root)} -> {os.readlink(p)}"
                )


def cmd_restore(args, manager: WorkloadManager):
    """Restore a workload from a backup archive"""
    require_root()

    archive = Path(args.archive)
    if not archive.exists():
        print(f"Error: Archive not found: {archive}", file=sys.stderr)
        sys.exit(1)

    # Extract to temp dir to inspect contents
    with tempfile.TemporaryDirectory() as staging_name:
        staging = Path(staging_name)
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

        # The name comes from a portable archive that may have been authored on
        # another host — the one restore input that crosses a trust boundary. It
        # flows straight into root-owned destination paths (dest_config/dest_data
        # below, plus copy2/rmtree/copytree as root), so a crafted name like
        # "../../etc/cron.d/x" would write/delete outside the workloads tree.
        # WorkloadConfig enforces this on the backup side; restore reads raw
        # tomllib, so validate here before any path is built.
        try:
            validate_workload_name(name)
        except ValueError as e:
            print(f"Error: archive has an invalid workload name {name!r}: {e}",
                  file=sys.stderr)
            sys.exit(1)

        print(f"Restoring workload: {name}")

        # Check if workload already exists
        dest_config = workload_config_path(name)
        dest_data = workload_data_dir(name)
        if dest_config.parent.exists() and not args.force:
            print(f"Error: Config already exists: {dest_config}", file=sys.stderr)
            print("Use --force to overwrite", file=sys.stderr)
            sys.exit(1)

        # Stop existing service if running
        service_name = workload_service_name(name)
        subprocess.run(["systemctl", "stop", service_name],
                        capture_output=True)

        # 1. Restore config
        print(f"  Config → {dest_config}")
        dest_config.parent.mkdir(exist_ok=True)
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

        # 3. Restore the precious data/ subtree (the only captured state;
        #    reconstructible state/ is rebuilt by `update`, not restored).
        data_staging = staging / "data"
        if data_staging.is_dir():
            # Guard against an escaping symlink in an untrusted archive before
            # copying the tree down verbatim.
            try:
                _assert_no_escaping_symlinks(data_staging)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            if dest_data.exists():
                if args.force:
                    shutil.rmtree(dest_data)
                else:
                    print("  Warning: data/ exists, merging (use --force to replace)")
            shutil.copytree(data_staging, dest_data,
                            symlinks=True, dirs_exist_ok=True)
            print(f"  Data dir → {dest_data}")

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
            print("Only the precious data/ subtree was restored; the "
                  "reconstructible state/ (images, graphroot, VM system disk) is "
                  "rebuilt on enable. To start the workload, run:")
            print(f"  sudo workloadctl enable {name}")
