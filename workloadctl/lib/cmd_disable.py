"""
cmd_disable — disable a workload, optionally purging its user and data.

Teardown is best-effort by construction: every step is attempted independently
through attempt(), so a half-provisioned or partly-wedged workload still comes
apart as far as it can, and the failures are reported together with a non-zero
exit at the end. --purge additionally removes the user, its subuid/subgid
ranges, the runtime env/secret files and the data directory.
"""

from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

from workload_lib import (
    RUN_SYSTEMD_SYSTEM,
    subid_lock,
    workload_enabled_marker,
    workload_root_dir,
    workload_run_files,
)
from vm import VM_BRIDGE_NAME, VM_SOCKET_DIR
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    WorkloadUserNotFound,
    format_size,
    require_root,
)
from cmd_provision import apply_selinux_policy, run_host_setup


def _remove_runtime_env_files(config: WorkloadConfig) -> list[str]:
    """Delete a workload's /run/workload-env files on purge. Returns names removed.

    These are tmpfs + root-owned, written by workload-write-env (decrypted
    ${SECRET:…} values → .secrets) and workload-ensure-user
    (XDG_RUNTIME_DIR/HOST_IP → .env). Nothing rewrites them once the workload is
    gone, so without this a purge leaves decrypted secrets readable in /run
    until the next reboot. The env-tree entries of workload_run_files() name
    them by exact basename (not a glob), so purging 'git' never touches
    'github's files, and honor WORKLOAD_ENV_DIR for tests.
    """
    removed = []
    for rf in workload_run_files(config):
        if rf.kind != "env-file":
            continue
        if rf.path.exists():
            rf.path.unlink()
            removed.append(rf.path.name)
    return removed


def _stop_user_manager(username: str) -> bool:
    """Tear down a workload user's lingering systemd manager on disable.

    Terminates the user's session/manager and removes the linger marker so a
    *disabled* workload doesn't keep a live user@<uid>.service with a pinned
    /run/user/<uid>. Idempotent and safe: the user, home, and subuid ranges are
    left intact, and workload-ensure-user re-enables linger on the next start.
    Returns True if the user existed (and we acted), False otherwise.
    """
    try:
        uid = pwd.getpwnam(username).pw_uid
    except KeyError:
        return False
    subprocess.run(["loginctl", "terminate-user", str(uid)],
                   check=False, capture_output=True)
    subprocess.run(["loginctl", "disable-linger", str(uid)],
                   check=False, capture_output=True)
    return True

def _stop_bridge_if_last_vm(config: WorkloadConfig, manager: WorkloadManager):
    """Stop the shared VM bridge service when no managed-bridge VMs remain enabled.

    Called at the end of cmd_disable (purge and non-purge alike).  If the
    disabled workload was not itself a managed-bridge VM, returns immediately
    without consulting the workload list.  When it *was* the last such workload,
    stops workload-bridge.service so the _workload-br interface, dnsmasq, and
    nftables NAT table are torn down without waiting for a reboot.
    """
    if not (config.is_vm and config.vm_bridge == VM_BRIDGE_NAME):
        return

    still_needed = any(
        c.is_vm and c.vm_bridge == VM_BRIDGE_NAME and c.name != config.name
        for c in manager.get_all_configs(enabled_only=True)
    )
    if still_needed:
        return

    subprocess.run(
        ["systemctl", "stop", "workload-bridge.service"],
        check=False,
        capture_output=True,
    )
    print("  Stopped shared VM bridge (no managed-bridge VMs remain)")


def _dir_size(path: Path) -> str:
    """Human size of a directory tree, or 'unknown' if it can't be measured."""
    result = subprocess.run(["du", "-sb", str(path)],
                            check=False, capture_output=True, text=True)
    if result.returncode != 0:
        return "unknown"
    try:
        return format_size(int(result.stdout.split()[0]))
    except (ValueError, IndexError):
        return "unknown"


def _disable_plan(config: WorkloadConfig, manager: WorkloadManager, purge: bool) -> list[str]:
    """The teardown cmd_disable would perform, as printable lines.

    Enumerated from the same sources the real path acts on — workload_run_files,
    the passwd db, /etc/subuid, the data dir — and reports only what is actually
    there, so an operator can trust that what this doesn't list, disable won't
    touch. Purely read-only: it is computed before any mutation, not by walking
    the teardown with the writes switched off, because a plan that shares the
    mutating path can only be as trustworthy as the last guard someone
    remembered to add.
    """
    lines = []

    units = [config.service_name] + [
        rf.path.name for rf in workload_run_files(config)
        if rf.kind == "unit" and rf.path.name != config.service_name
    ]
    lines.append(f"stop units: {', '.join(units)}")

    run_files = [rf.path for rf in workload_run_files(config)
                 if rf.kind != "env-file" and rf.path.exists()]
    if run_files:
        lines.append("remove generated unit files:")
        lines.extend(f"    {p}" for p in run_files)

    setup_script = config.config.get("host", {}).get("setup", "")
    if setup_script:
        lines.append(f"run host teardown hook: {setup_script} disable")

    lines.append(f"remove SELinux module: wl_{config.name}")
    lines.append(f"unlink enabled marker: {workload_enabled_marker(config.name)}")

    try:
        pwd.getpwnam(config.username)
        user_present = True
    except KeyError:
        user_present = False

    if purge:
        env_files = [rf.path for rf in workload_run_files(config)
                     if rf.kind == "env-file" and rf.path.exists()]
        if env_files:
            lines.append("remove runtime env/secret files:")
            lines.extend(f"    {p}" for p in env_files)

        if config.is_vm:
            sock_dir = VM_SOCKET_DIR / config.name
            if sock_dir.exists():
                lines.append(f"remove VM socket dir: {sock_dir}")
        else:
            subid = [f for f in ("/etc/subuid", "/etc/subgid")
                     if Path(f).exists()
                     and any(line.startswith(f"{config.username}:")
                             for line in Path(f).read_text().splitlines())]
            if subid:
                lines.append(f"remove subuid/subgid entries from: {', '.join(subid)}")

        if user_present:
            lines.append(f"kill user sessions and delete user: {config.username}")
        else:
            lines.append(f"user {config.username} not present (nothing to remove)")

        workload_dir = workload_root_dir(config.name)
        if workload_dir.exists():
            lines.append(f"DESTROY data directory: {workload_dir} ({_dir_size(workload_dir)})")
    else:
        if user_present:
            lines.append(f"stop lingering user manager for {config.username}")
        lines.append(f"keep user, home and subuid ranges for {config.username}")

    if config.is_vm and config.vm_bridge == VM_BRIDGE_NAME:
        still_needed = any(
            c.is_vm and c.vm_bridge == VM_BRIDGE_NAME and c.name != config.name
            for c in manager.get_all_configs(enabled_only=True)
        )
        if not still_needed:
            lines.append("stop shared VM bridge (last bridged VM)")

    return lines


def cmd_disable(args, manager: WorkloadManager):
    """Disable and stop a workload"""
    require_root()

    config = WorkloadConfig(args.workload)
    purge = args.purge

    if getattr(args, "dry_run", False):
        verb = "disable and purge" if purge else "disable"
        print(f"Dry run — would {verb} workload '{args.workload}':")
        for line in _disable_plan(config, manager, purge):
            print(f"  {line}")
        print("\nNothing was changed. Re-run without --dry-run to apply.")
        return

    if purge:
        print(f"Disabling and purging workload: {args.workload}")
    else:
        print(f"Disabling workload: {args.workload}")

    # Every teardown/removal step below is attempted independently and
    # best-effort: a failure in one never skips the rest, so a half-provisioned
    # or partly-wedged workload still gets torn down as far as possible. Failures
    # are collected and reported together with a non-zero exit at the end.
    failures: list[str] = []

    def attempt(label, fn):
        try:
            fn()
        except Exception as e:
            failures.append(f"{label}: {e}")

    print(f"  Stopping {config.service_name}...")
    attempt(f"stop {config.service_name}",
            lambda: subprocess.run(["systemctl", "stop", config.service_name], check=False))

    # Stop and reset the workload's RemainAfterExit=yes oneshot helpers so they
    # re-run on the next enable. They stay "active (exited)" after the umbrella
    # service stops (Requires= does not propagate stop), so a same-name re-enable
    # within one boot finds the Requires=d helper already satisfied and systemd
    # SILENTLY SKIPS re-running it. For the setup service that means
    # workload-ensure-user (linger, subuid/subgid, volume dirs, EnvironmentFile)
    # never re-runs: the workload comes up with no lingering user manager, so
    # /run/user/<uid> only exists for the lifetime of each transient
    # `sudo -u … podman` session and is GC'd in between — making every CLI podman
    # call (health/images/status/logs/exec/cp) intermittently fail with
    # "lstat /run/user/<uid>: no such file or directory".
    # Every service unit the workload owns except the umbrella (stopped above):
    # the setup/build oneshots, BOTH the pod and net helpers, per-container
    # sub-services, and a VM's virtiofs mounts. They share the RemainAfterExit
    # staleness, so all must be stopped + reset for a same-name re-enable to
    # re-run them; stopping an absent unit is a harmless no-op.
    #
    # Sourced from the run-file SUPERSET (workload_run_files), NOT the emitted
    # subset — this MUST match _remove_run_files below, which unlinks both the
    # -pod and -net fragments regardless of the current mode. If the TOML's mode
    # is changed (e.g. pod -> bridge) between enable and disable, the old mode's
    # still-active helper would otherwise have its fragment removed but never be
    # stopped, stranding a loaded unit (and its pod) until the next reboot.
    helper_services = [
        rf.path.name
        for rf in workload_run_files(config)
        if rf.kind == "unit" and rf.path.name != config.service_name
    ]
    for svc in helper_services:
        attempt(f"stop {svc}",
                lambda svc=svc: subprocess.run(["systemctl", "stop", svc], check=False, capture_output=True))
        attempt(f"reset-failed {svc}",
                lambda svc=svc: subprocess.run(["systemctl", "reset-failed", svc], check=False, capture_output=True))

    # Run host setup teardown if configured
    attempt("host setup teardown", lambda: run_host_setup(config, "disable"))

    # Remove the per-workload SELinux module (1:1 with the workload, so this is
    # an unambiguous teardown — nothing else depends on wl_<name>).
    attempt("remove SELinux module", lambda: apply_selinux_policy(config, "disable"))

    # Mark disabled so a future generation (next enable of anything, or boot)
    # won't re-emit this workload.
    attempt("mark disabled (unlink marker)",
            lambda: workload_enabled_marker(args.workload).unlink(missing_ok=True))

    # Remove this workload's generated unit files from /run/systemd/system. The
    # generator only ever writes (idempotent emit from the enabled set), so unless
    # we delete them here they linger as dead units — including the user@<uid>
    # drop-in that pins the user manager into workloads.slice — until the next
    # reboot wipes the tmpfs. Each unlink is independent (one failure never skips
    # the rest), then daemon-reload drops them from systemd's view.
    def _remove_run_files():
        # Removable (superset) view: every systemd-side file the workload owns,
        # -pod and -net listed for the whole topology so missing_ok covers the
        # mode we didn't emit. The env-tree files are removed separately, on
        # --purge only, by _remove_runtime_env_files.
        for rf in workload_run_files(config):
            if rf.kind == "env-file":
                continue
            try:
                rf.path.unlink(missing_ok=True)
            except OSError as e:
                failures.append(f"remove {rf.path}: {e}")
        if not config.is_vm:
            # Prune the now-empty user@<uid>.service.d drop-in dir. The UID lookup
            # raises once the user is gone; nothing to prune in that case.
            try:
                (RUN_SYSTEMD_SYSTEM / f"user@{config.uid}.service.d").rmdir()
            except (OSError, WorkloadUserNotFound):
                pass
    attempt("remove /run unit files", _remove_run_files)
    attempt("reload systemd",
            lambda: subprocess.run(["systemctl", "daemon-reload"], check=False))

    if purge:
        # Look up the user up front (may be absent if the workload was enabled
        # but never fully provisioned — /var setup is deferred to first start).
        # An absent user is "already clean", not an error.
        uid = None
        try:
            uid = pwd.getpwnam(config.username).pw_uid
        except KeyError:
            print(f"  User {config.username} not present (nothing to remove)")

        if uid is not None:
            try:
                print(f"  Terminating user sessions for {config.username}...")
                _stop_user_manager(config.username)
                time.sleep(1)
                # Kill any straggler processes (rootless podman, conmon, etc.)
                # so userdel doesn't print "user is currently used by process N".
                subprocess.run(["pkill", "-KILL", "-u", str(uid)],
                               check=False, capture_output=True)
                time.sleep(0.5)
            except Exception as e:
                failures.append(f"terminate user sessions: {e}")

        # Remove per-workload runtime files in /run/workload-env (decrypted
        # secrets + the env file) so a purge doesn't leave them readable in
        # /run until the next reboot.
        try:
            _remove_runtime_env_files(config)
        except Exception as e:
            failures.append(f"remove runtime env files: {e}")

        if config.is_vm:
            try:
                # Clean up the runtime socket directory
                vm_sock_dir = VM_SOCKET_DIR / config.name
                if vm_sock_dir.exists():
                    shutil.rmtree(vm_sock_dir, ignore_errors=True)
            except Exception as e:
                failures.append(f"remove VM socket dir: {e}")
        else:
            try:
                print("  Removing subuid/subgid entries...")
                with subid_lock():
                    for file in ["/etc/subuid", "/etc/subgid"]:
                        p = Path(file)
                        if p.exists():
                            lines = [line for line in p.read_text().splitlines()
                                     if not line.startswith(f"{config.username}:")]
                            p.write_text("\n".join(lines) + ("\n" if lines else ""))
            except Exception as e:
                failures.append(f"remove subuid/subgid entries: {e}")

        if uid is not None:
            try:
                print(f"  Removing user {config.username}...")
                userdel = subprocess.run(["userdel", "-f", config.username],
                                         check=False, capture_output=True, text=True)
                # userdel -f exits 0 even when it prints a warning about a
                # process still using the account — check whether the user
                # actually got removed rather than trusting the exit code.
                try:
                    pwd.getpwnam(config.username)
                    msg = f"userdel: user {config.username} still exists"
                    if userdel.stderr.strip():
                        msg += f" ({userdel.stderr.strip()})"
                    msg += " — fix the underlying issue (e.g. 'sudo grpck') then re-run disable --purge"
                    failures.append(msg)
                except KeyError:
                    pass
            except Exception as e:
                failures.append(f"remove user {config.username}: {e}")

        # Remove the data dir regardless of whether the user still existed — an
        # orphaned /var/lib/workloads/<name> should still be swept.
        workload_dir = workload_root_dir(config.name)
        if workload_dir.exists():
            try:
                print(f"  Removing workload directory {workload_dir}...")
                shutil.rmtree(workload_dir)
            except OSError as e:
                failures.append(f"remove {workload_dir}: {e} "
                                "(data may still be present — remove manually before re-enabling)")

        if uid is None:
            success_msg = (f"✓ Workload '{args.workload}' disabled and purged "
                           "(user was not provisioned)")
        else:
            success_msg = f"✓ Workload '{args.workload}' disabled and purged"
    else:
        # A disabled (non-purged) workload keeps its user, home, and subuid
        # ranges, but should not keep a live lingering user manager. Stop it so
        # /run/user/<uid> and user@<uid>.service don't idle on; re-enable
        # re-establishes linger via workload-ensure-user.
        def _stop_lingering_user_manager():
            if _stop_user_manager(config.username):
                print(f"  Stopped lingering user manager for {config.username}")
        attempt("stop lingering user manager", _stop_lingering_user_manager)
        success_msg = f"✓ Workload '{args.workload}' disabled and stopped (use --purge to fully remove)"

    attempt("stop shared VM bridge", lambda: _stop_bridge_if_last_vm(config, manager))

    if failures:
        sys.stderr.write(f"  ! Disable of '{args.workload}' completed with errors:\n")
        for f in failures:
            sys.stderr.write(f"    - {f}\n")
        sys.exit(1)

    print(success_msg)
