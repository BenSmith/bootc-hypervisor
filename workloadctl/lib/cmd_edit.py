"""
cmd_edit — edit a workload's TOML or one of its control files in $EDITOR.

Edits land in the /etc override tree, never in the shipped bundle, and are
validated before they are kept: a config that no longer validates is restored
from the pre-edit copy. Control-file names are checked against traversal and
symlink escape before anything is opened.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

from cli_log import emit_result
from workload_lib import workload_config_path, workload_service_units
from workloadctl_core import WorkloadConfig, WorkloadManager, require_root
from service_runtime import restart_workload_service
from cmd_validate import validate_single


def _ask_yes_no(prompt: str) -> bool:
    """Prompt for y/N. Treat EOF (non-interactive stdin) as 'no' rather than
    crashing with `EOFError: EOF when reading a line`."""
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        print()
        return False


def _validate_control_file_name(rel: str) -> None:
    """Reject anything that isn't a safe relative path under the override dir.

    Blocks absolute paths and `..` traversal so `edit <name> <file>` can never
    write outside `/etc/workloads.d/<name>/`. Nested names (e.g. `rootfs/x`) are
    allowed — the build context may have subdirectories.
    """
    if not rel or not rel.strip():
        raise ValueError("empty control-file name")
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("must be a relative path with no '..' components")


def _assert_no_symlink_escape(base: Path, target: Path) -> None:
    """Reject if any component from `base` down to `target` is a symlink.

    `..`/absolute are already blocked, but a relpath like `sub/file` could still
    escape `/etc/workloads.d/<name>/` if a component (`sub`, or the file itself)
    was pre-planted as a symlink. Walk the chain and refuse any symlinked
    component so a write can never follow a link out of the override tree.
    """
    if base.is_symlink():
        raise ValueError(f"override dir is a symlink: {base}")
    cur = base
    for part in target.relative_to(base).parts:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError(f"refusing to write through symlink: {cur}")


def _cleanup_override_dir(config: WorkloadConfig, override: Path) -> None:
    """Remove now-empty override dirs from `override` up to override_dir.

    Keeps the override tree free of empty `<name>/` (and any seeded subdirs)
    after a lazy-cleanup removal, so the dir's existence stays meaningful.
    """
    base = config.override_dir
    d = override.parent
    while True:
        try:
            d.rmdir()
        except OSError:
            break
        if d == base:
            break
        d = d.parent


def _print_control_file_next_steps(config: WorkloadConfig, rel: str) -> None:
    """Print how to apply a just-edited control file (it isn't auto-applied)."""
    base = Path(rel).name
    setup = config.config.get("host", {}).get("setup", "")
    # Files that drive an image build: the conventional names plus whatever this
    # workload actually declares ([build].containerfile / [build].script), so a
    # `Containerfile.gpu` edit still gets the rebuild hint, not the generic one.
    build_files = {"build.sh", "Containerfile",
                   Path(config.build_containerfile).name}
    if config.build_script:
        build_files.add(Path(config.build_script).name)
    print()
    print("  Next steps:")
    if base == "policy.cil":
        print(f"    Reload SELinux policy:  sudo workloadctl enable {config.name}")
    elif base in build_files:
        print(f"    Rebuild image:          sudo workloadctl build {config.name}")
        print(f"    Apply to running:       sudo workloadctl recreate {config.name}")
    elif rel == setup:
        print(f"    Re-runs on next enable: sudo workloadctl enable {config.name}")
    else:
        print(f"    Apply changes:          sudo workloadctl recreate {config.name}")
    print(f"    Revert to shipped:      sudo rm {config.override_dir / rel}")


def _editor_argv() -> list:
    """Return the argv for the user's $EDITOR.

    Split so a value carrying flags (e.g. "code --wait", "emacs -nw") is honored
    instead of being treated as one impossible argv[0]. Falls back to nano if
    $EDITOR is unset/empty, or malformed (unbalanced quotes make shlex.split
    raise ValueError) rather than crashing `workloadctl edit`.
    """
    try:
        return shlex.split(os.environ.get("EDITOR", "") or "nano") or ["nano"]
    except ValueError:
        print("Warning: $EDITOR is malformed; falling back to nano", file=sys.stderr)
        return ["nano"]


def _edit_control_file(args, manager: WorkloadManager):
    """Edit a bundle control file, seeding an /etc override copy-on-write.

    The lazy-override ergonomic (systemd `systemctl edit`): on first edit, seed
    `/etc/workloads.d/<name>/<file>` from the resolved `/usr` default (or an
    empty file if the bundle ships none), then open `$EDITOR`. If the result is
    byte-identical to the shipped default — or an untouched empty new file — the
    override is dropped so it never freezes upgrade-tracking.
    """
    name = args.workload
    rel = args.file

    config_path = workload_config_path(name)
    if not config_path.exists():
        print(f"Error: Workload config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    try:
        _validate_control_file_name(rel)
    except ValueError as e:
        print(f"Error: invalid control-file name {rel!r}: {e}", file=sys.stderr)
        sys.exit(1)

    config = WorkloadConfig(name)
    override = config.override_dir / rel
    default = config.bundle_dir / rel

    # Containment: even with `..` blocked, a pre-planted symlink component could
    # redirect the write outside the override tree. Check before creating dirs.
    try:
        _assert_no_symlink_escape(config.override_dir, override)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    seeded = False
    if not override.exists():
        override.parent.mkdir(parents=True, exist_ok=True)
        if default.exists():
            shutil.copy2(default, override)
            print(f"  Seeded override from shipped default: {default}")
        else:
            override.touch()
            if rel.endswith(".sh"):
                override.chmod(0o755)
            print(f"  No shipped default — created a new control file: {override}")
        seeded = True

    editor_argv = _editor_argv()
    result = subprocess.run([*editor_argv, str(override)])
    if result.returncode != 0:
        print(f"Editor exited with error code {result.returncode}", file=sys.stderr)
        # Don't leave a half-seeded override behind on editor failure.
        if seeded:
            override.unlink(missing_ok=True)
            _cleanup_override_dir(config, override)
        sys.exit(1)

    # Lazy-override cleanup. An override byte-identical to the shipped default is
    # redundant and would freeze upgrade-tracking, so drop it; likewise an
    # untouched empty new file. Mirrors `systemctl edit` discarding a no-op.
    if default.exists() and override.read_bytes() == default.read_bytes():
        override.unlink()
        _cleanup_override_dir(config, override)
        print(f"  No change from the shipped default — no override kept "
              f"(still tracks {default}).")
        return
    if not default.exists() and override.stat().st_size == 0:
        override.unlink()
        _cleanup_override_dir(config, override)
        print("  Empty file — nothing created.")
        return

    # A freshly authored control file with a shebang should be executable even
    # when it isn't named *.sh (a hook with no extension). copy2 already
    # preserves a shipped default's mode, so only touch newly seeded files.
    if seeded and not default.exists():
        try:
            with open(override, "rb") as fh:
                if fh.read(2) == b"#!":
                    override.chmod(override.stat().st_mode | 0o111)
        except OSError:
            pass

    print(f"✓ Override saved: {override}")
    # Both no-op paths above return without an override, so a line here means one
    # was really kept. `applied` is false by construction: this verb only writes
    # the file — _print_control_file_next_steps tells the operator which verb
    # actually pushes it into the running workload.
    emit_result([{"workload": name, "result": "edited",
                  "file": rel, "applied": False}])
    _print_control_file_next_steps(config, rel)


def cmd_edit(args, manager: WorkloadManager):
    """Edit config and apply changes"""
    require_root()

    if getattr(args, "file", None):
        _edit_control_file(args, manager)
        return

    config_path = workload_config_path(args.workload)
    if not config_path.exists():
        print(f"Error: Workload config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # Create backup using mkstemp to avoid TOCTOU race
    backup_fd, backup_str = tempfile.mkstemp(prefix=f"workload-{args.workload}-", suffix=".toml")
    os.close(backup_fd)
    backup_path = Path(backup_str)
    shutil.copy2(config_path, backup_path)

    # Open editor
    editor_argv = _editor_argv()
    result = subprocess.run(editor_argv + [str(config_path)])
    if result.returncode != 0:
        print(f"Editor exited with error code {result.returncode}", file=sys.stderr)
        backup_path.unlink()
        sys.exit(1)

    # Check if file changed
    if config_path.read_text() == backup_path.read_text():
        print("No changes made")
        backup_path.unlink()
        return

    print()
    print("Config changed. Validating...")
    print()

    try:
        config = WorkloadConfig(args.workload)
        validation = validate_single(config, manager, json_mode=False)
        if not validation["passed"]:
            print()
            if _ask_yes_no("Validation failed. Restore backup? [y/N] "):
                shutil.copy2(backup_path, config_path)
                print("Backup restored")
            else:
                print("Config saved with errors - fix before enabling")
            backup_path.unlink()
            sys.exit(1)
    except Exception as e:
        print(f"Error loading config: {e}", file=sys.stderr)
        if _ask_yes_no("Restore backup? [y/N] "):
            shutil.copy2(backup_path, config_path)
            print("Backup restored")
        backup_path.unlink()
        sys.exit(1)

    print()
    print("Validation passed. Changes:")
    print()
    subprocess.run(["diff", "-u", str(backup_path), str(config_path)])
    print()

    applied = False
    if config.enabled:
        if getattr(args, "yes", False):
            print("Apply changes and restart workload? [y/N] y")
            apply = True
        else:
            apply = _ask_yes_no("Apply changes and restart workload? [y/N] ")
        if apply:
            applied = True
            # daemon-reload alone won't regenerate per-workload unit files —
            # only the systemd shell-generator re-runs, and it just emits a
            # oneshot that doesn't fire until next boot. Run workload-generate
            # explicitly so [container.environment] and other inlined values
            # actually take effect. --workload keeps the run to the workload
            # being edited: an unfiltered run rewrites every enabled workload's
            # units and starts each one.
            subprocess.run(
                ["/usr/libexec/workloadctl/workload-generate", "/run/systemd/system",
                 "--workload", config.name],
                check=True,
            )
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            if config.is_vm:
                # VM cloud-init/nvram are built by the setup oneshot
                # (RemainAfterExit=yes); restart it so edits to [vm.cloud_init]
                # / template_vars are re-rendered into a fresh seed before the
                # main service reboots QEMU onto it.
                subprocess.run(
                    ["systemctl", "restart",
                     workload_service_units(config, roles={"setup"})[0]],
                    check=True,
                )
                subprocess.run(["systemctl", "restart", config.service_name], check=True)
            elif manager.user_exists(config):
                # Container: self-healing restart (re-pin runtime dir + clear
                # start-limit thrash) rather than a bare systemctl restart.
                restart_workload_service(config.uid, config.service_name)
            else:
                subprocess.run(["systemctl", "restart", config.service_name], check=True)
            print("✓ Changes applied and service restarted")
        else:
            print(f"Changes saved but not applied. Run 'sudo workloadctl recreate {args.workload}' to apply.")
    else:
        print("✓ Changes saved (workload is disabled)")

    # Only reached once the edit is validated and kept — an editor that exited
    # nonzero, an unchanged file, and a rolled-back validation failure all
    # return above, so a line here means the config on disk really did change.
    # `applied` is the load-bearing part: a saved-but-not-applied edit is why a
    # workload's running units can disagree with its TOML, and that is exactly
    # what someone reads this log to explain.
    emit_result([{"workload": args.workload, "result": "edited",
                  "applied": applied}])

    backup_path.unlink()


