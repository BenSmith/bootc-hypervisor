"""
cmd_cleanup — sweep orphaned workload users, directories and SELinux modules.

An orphan is state whose workload no longer has a config at all: a _wl-* user, a
/var/lib/workloads/<name> dir, or a loaded wl_* SELinux module that no TOML
declares. Keyed on declaration rather than enabled state, so a merely-disabled
workload is never swept. Defaults to a dry run; --apply removes.

"No config at all" is a per-deployment statement on an ostree host, where /etc is
per-deployment and /var is shared — so a `bootc rollback` manufactures orphans
out of state that another deployment still owns. State carrying a provenance
marker for a deployment that exists but isn't booted is reported separately and
never swept; see lib/deployment.py for the full rule.
"""

import json
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tomllib

import deployment
from workload_lib import (
    iter_workloads,
    remove_subid_entries,
    selinux_module_name,
    subid_files_with_entries,
    USERNAME_PREFIX,
    WORKLOADS_BASE,
    workload_username,
)
from workloadctl_core import WorkloadManager, require_root
from cmd_backup import BACKUP_DIR


def cmd_cleanup(args, manager: WorkloadManager):
    """Find and remove orphaned workload users and directories"""
    require_root()

    apply = args.apply

    # Collect names of ALL configured workloads (enabled or not)
    # A user with a config (even disabled) is not orphaned
    configured_names = set()
    # Per-workload SELinux modules a config still expects (selinux_policy = true).
    # Keyed on declaration, not enabled state — same as users above.
    expected_modules = set()
    for _name, config_file in iter_workloads():
        try:
            with open(config_file, "rb") as f:
                cfg = tomllib.load(f)
            name = cfg.get("workload", {}).get("name")
            if name:
                configured_names.add(name)
                if cfg.get("security", {}).get("selinux_policy"):
                    expected_modules.add(selinux_module_name(name))
        except Exception:
            pass

    # Orphaned per-workload SELinux modules: loaded wl_* modules that no config
    # still declares. semodule loads are persistent (a reboot reloads the same
    # policy), so a hand-deleted TOML or a dropped selinux_policy leaves the
    # module loaded with nothing behind it. The wl_ prefix scopes this to
    # per-workload modules — udica base templates and seatd_container are untouched.
    orphaned_modules = []
    if shutil.which("semodule"):
        r = subprocess.run(["semodule", "-l"], capture_output=True, text=True)
        if r.returncode == 0:
            loaded = {ln.strip() for ln in r.stdout.splitlines()
                      if ln.strip().startswith("wl_")}
            orphaned_modules = sorted(loaded - expected_modules)

    workloads_base = WORKLOADS_BASE

    # Rollback guard. Everything below decides "orphan" from the booted
    # deployment's /etc, which a `bootc rollback` rewrites wholesale while /var
    # stays put. Ask the state itself who it belongs to first: a marker naming a
    # deployment that still exists but isn't booted means these were never
    # orphans, only invisible from here. Memoized per workload name — a rolled
    # back workload reaches this from both the user scan and the dir scan, and
    # the report should name it once.
    #
    # Derived from `workloads_base`, not workload_root_dir(), for the same
    # reason the root-claiming loop below is: one base path for the whole sweep.
    skipped_other_deployment = {}   # name -> deployment id
    _judged = {}

    def _belongs_elsewhere(name):
        if name not in _judged:
            dep = deployment.other_deployments_state(workloads_base / name, name)
            _judged[name] = dep
            if dep:
                skipped_other_deployment[name] = dep
        return _judged[name]

    # Find all _wl-* system users
    all_users = pwd.getpwall()
    orphaned_users = []
    for entry in all_users:
        if not entry.pw_name.startswith(USERNAME_PREFIX):
            continue
        name = entry.pw_name[len(USERNAME_PREFIX):]
        if name not in configured_names and not _belongs_elsewhere(name):
            orphaned_users.append(entry)

    # Find workload dirs with no corresponding system user
    orphaned_dirs = []
    if workloads_base.exists():
        existing_users = {e.pw_name for e in all_users}
        for d in workloads_base.iterdir():
            if not d.is_dir() or d.name.startswith("."):
                continue
            # The shared backup output dir has no _wl- user; it is not an
            # orphaned workload dir (`workloadctl backup` writes here).
            if d == workloads_base / BACKUP_DIR.name:
                continue
            # A dir with a live config but no user yet is NOT an orphan: the
            # documented recovery flow (pre-flight failed -> stage required
            # files in the dir -> re-run enable) leaves exactly that state, and
            # rmtree'ing it would destroy operator-staged data. Mirror the
            # configured_names guard used for orphan users above.
            expected_user = workload_username(d.name)
            if (expected_user not in existing_users
                    and d.name not in configured_names
                    and not _belongs_elsewhere(d.name)):
                orphaned_dirs.append(d)

    # The scan above skips a dir whose user still exists — which is every dir
    # belonging to a user in orphaned_users, since those users are removed below.
    # `userdel -r` only clears pw_dir (= <root>/state), so data/ and
    # operations.log would survive and be swept on a *later* run. Claim the whole
    # root here instead, so one --apply is enough and the plan says what happens.
    # Derived from the same workloads_base the scan above uses, not from
    # workload_root_dir(), so there is one base path in play for the whole sweep.
    for entry in orphaned_users:
        root = workloads_base / entry.pw_name[len(USERNAME_PREFIX):]
        if root.exists() and root not in orphaned_dirs:
            orphaned_dirs.append(root)

    # Reported in every JSON document, dry-run or not, and always empty off
    # ostree. A consumer that never sees a non-empty list still knows the key.
    skipped_json = [
        {"name": n, "path": str(workloads_base / n), "deployment": dep}
        for n, dep in sorted(skipped_other_deployment.items())
    ]

    def _print_skipped():
        """Name what was spared and why.

        Not optional: an operator staring at unexplained _wl-* state after a
        rollback, told only that there is "nothing to clean up", is left with
        the same silence that made the original failure mode a trap.
        """
        if not skipped_other_deployment:
            return
        print(f"\nState from another deployment ({len(skipped_other_deployment)}) "
              f"— not swept:")
        for n, dep in sorted(skipped_other_deployment.items()):
            print(f"  {workloads_base / n}  (last provisioned under "
                  f"deployment {dep[:12]}…)")
        print("  These have no config on the *booted* deployment, which is what a")
        print("  `bootc rollback` looks like — the deployment that owns them still")
        print("  exists. Boot it and run 'workloadctl disable --purge <name>' there")
        print("  to remove them for good.")

    if args.json and not apply:
        print(json.dumps({
            "dry_run": True,
            "orphan_users": [e.pw_name for e in orphaned_users],
            "orphan_dirs": [str(d) for d in orphaned_dirs],
            "orphan_modules": orphaned_modules,
            "skipped_other_deployment": skipped_json,
            "removed_users": [],
            "removed_dirs": [],
            "removed_modules": []
        }, indent=2))
        return

    if not orphaned_users and not orphaned_dirs and not orphaned_modules:
        if args.json:
            print(json.dumps({
                "dry_run": not apply,
                "orphan_users": [],
                "orphan_dirs": [],
                "orphan_modules": [],
                "skipped_other_deployment": skipped_json,
                "removed_users": [],
                "removed_dirs": [],
                "removed_modules": []
            }, indent=2))
        else:
            print("Nothing to clean up.")
            _print_skipped()
        return

    if not args.json:
        # Report what was found
        if orphaned_users:
            print(f"Orphaned users ({len(orphaned_users)}):")
            for entry in orphaned_users:
                has_subid_entries = bool(subid_files_with_entries(entry.pw_name))
                extras = []
                if Path(entry.pw_dir).exists():
                    extras.append("has home dir")
                if has_subid_entries:
                    extras.append("has subuid/subgid")
                extra_str = f"  ({', '.join(extras)})" if extras else ""
                print(f"  {entry.pw_name} (UID {entry.pw_uid}){extra_str}")

        if orphaned_dirs:
            print(f"\nOrphaned directories ({len(orphaned_dirs)}):")
            for d in orphaned_dirs:
                print(f"  {d}")

        if orphaned_modules:
            print(f"\nOrphaned SELinux modules ({len(orphaned_modules)}):")
            for m in orphaned_modules:
                print(f"  {m}  (no workload declares selinux_policy)")

        # After the --apply hint, never between the orphan lists and it: "the
        # above" has to mean the orphans, not the state deliberately spared.
        if not apply:
            print("\nRun with --apply to remove the above.")
            _print_skipped()
            return

        _print_skipped()

    removed_users = []
    removed_dirs = []

    # Remove orphaned users
    if not args.json:
        print()
    for entry in orphaned_users:
        username = entry.pw_name
        uid = entry.pw_uid
        if not args.json:
            print(f"Removing {username}...")

        subprocess.run(["loginctl", "terminate-user", str(uid)], check=False,
                       capture_output=True)
        subprocess.run(["loginctl", "disable-linger", str(uid)], check=False,
                       capture_output=True)

        remove_subid_entries(username)

        subprocess.run(["userdel", "-r", username], check=False, capture_output=True)
        removed_users.append(username)
        if not args.json:
            print(f"  ✓ Removed {username}")

    # Remove orphaned directories
    for d in orphaned_dirs:
        if not args.json:
            print(f"Removing directory {d}...")
        shutil.rmtree(d, ignore_errors=True)
        removed_dirs.append(str(d))
        if not args.json:
            print(f"  ✓ Removed {d}")

    # Remove orphaned SELinux modules
    removed_modules = []
    for m in orphaned_modules:
        if not args.json:
            print(f"Removing SELinux module {m}...")
        rc = subprocess.run(["semodule", "-r", m], check=False,
                            capture_output=True, text=True)
        if rc.returncode == 0:
            removed_modules.append(m)
            if not args.json:
                print(f"  ✓ Removed {m}")
        elif not args.json:
            print(f"  ✗ Failed to remove {m}: {rc.stderr.strip()}", file=sys.stderr)

    if args.json:
        print(json.dumps({
            "dry_run": False,
            "orphan_users": [e.pw_name for e in orphaned_users],
            "orphan_dirs": [str(d) for d in orphaned_dirs],
            "orphan_modules": orphaned_modules,
            "skipped_other_deployment": skipped_json,
            "removed_users": removed_users,
            "removed_dirs": removed_dirs,
            "removed_modules": removed_modules
        }, indent=2))
    else:
        print("\nCleanup complete.")
