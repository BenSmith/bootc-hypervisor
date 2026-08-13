"""
backup — archive capture shared by both substrates.

Implements the ``Substrate.capture`` primitive: stage the workload's TOML,
its credential blobs and its precious ``data/`` tree into a temp directory,
then tar it. The container and VM substrates differ only in how they quiesce
the workload first (systemd stop vs QMP vCPU pause), so that difference lives
in the callers and everything below it lives here.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from cli_log import error, info, warn
from qmp import QMPClient
from secrets_template import auto_detect_credentials
from service_runtime import restart_workload_service
from substrate import BackupError
from vm import VM_SOCKET_DIR
from workload_lib import CREDSTORE_DIR, workload_config_path


def backup_vm(config, output: Path, *, quiet: bool) -> int:
    """Backup a VM workload (always stopped).  Returns archive size in bytes."""
    backup_impl(config, output, no_stop=False, quiet=quiet, vm=True)
    size = output.stat().st_size
    if not quiet:
        print_backup_size(output, size)
    return size


def backup_vm_crash(config, output: Path, *, quiet: bool) -> int:
    """Crash-consistent VM backup: pause vCPUs via QMP, copy, resume.

    If the VM service is not active, falls back to the cold copy (nothing to
    pause).  If QMP is unreachable, errors clearly rather than copying an
    unpaused live disk — a copy of an unpaused qcow2 is torn and not safe.

    The vCPUs are paused for the entire copy duration (simple first cut).
    A future improvement would use QMP 'drive-backup' / 'blockdev-backup' to
    issue a copy-on-write snapshot job so the pause window is just the initial
    COW setup, not the full copy — see docs/ideas.md for the drive-backup
    follow-up.

    RESUME SAFETY: the QMP 'cont' command is issued in a finally block so
    a failed or interrupted copy never leaves the guest permanently paused.
    """
    service_name = config.service_name
    service_was_active = subprocess.run(
        ["systemctl", "is-active", "--quiet", service_name],
    ).returncode == 0

    if not service_was_active:
        # Nothing running — fall back to cold copy (identical result, no QMP
        # needed).
        if not quiet:
            info(f"  VM '{config.name}' is not active; using cold backup path.")
        return backup_vm(config, output, quiet=quiet)

    # VM is running — pause vCPUs, copy durable disk + home, then resume.
    sock_path = VM_SOCKET_DIR / config.name / "qmp.sock"
    if not sock_path.exists():
        error(
            f"Error: QMP socket not found at {sock_path}. "
            f"Cannot safely copy a live qcow2 without pausing vCPUs. "
            f"Use --consistency cold to stop the VM first.",
        )
        raise BackupError(f"QMP socket not found for VM '{config.name}'")

    qmp = QMPClient()
    # The outer finally guarantees qmp.close() on every exit path — including a
    # failure in negotiate() after connect() already opened the socket — so an
    # error here can't leak the descriptor.
    try:
        try:
            qmp.connect(str(sock_path))
            qmp.negotiate()
        except (OSError, ValueError) as exc:
            # TimeoutError/ConnectionError are OSError subclasses; ValueError
            # covers a malformed JSON greeting from the monitor.
            error(
                f"Error: Could not connect to QMP for VM '{config.name}': {exc}. "
                f"Cannot safely copy a live qcow2 without pausing vCPUs. "
                f"Use --consistency cold to stop the VM first.",
            )
            raise BackupError(f"QMP unreachable for VM '{config.name}': {exc}")

        if not quiet:
            info(f"  Pausing vCPUs for '{config.name}'...")
        try:
            stop_reply = qmp.execute("stop")
        except (OSError, ValueError) as exc:
            # A protocol/socket fault here means the vCPUs were never paused, so
            # there is nothing to resume — fail the backup cleanly.
            error(
                f"Error: QMP 'stop' failed for VM '{config.name}': {exc}. "
                f"Use --consistency cold to stop the VM first.",
            )
            raise BackupError(f"QMP 'stop' failed for VM '{config.name}': {exc}")
        if "error" in stop_reply:
            error(
                f"Error: QMP 'stop' failed for VM '{config.name}': {stop_reply['error']}. "
                f"Use --consistency cold to stop the VM first.",
            )
            raise BackupError(
                f"QMP 'stop' failed for VM '{config.name}': {stop_reply['error']}"
            )

        try:
            # no_stop=True: copy durable disk + home WITHOUT stopping the
            # systemd service (vCPUs are already paused by QMP above).
            backup_impl(config, output, no_stop=True, quiet=quiet, vm=True)
        finally:
            # CRITICAL: always resume vCPUs, even if the copy raised.
            if not quiet:
                info(f"  Resuming vCPUs for '{config.name}'...")
            try:
                cont_reply = qmp.execute("cont")
                if "error" in cont_reply:
                    error(
                        f"Warning: QMP 'cont' failed for '{config.name}': {cont_reply['error']}. "
                        f"The VM may remain paused — check with 'workloadctl status {config.name}'.",
                    )
            except (OSError, ValueError) as exc:
                # OSError covers ConnectionError; ValueError covers a malformed
                # reply. Resume is best-effort — warn, never mask the backup or
                # escape un-isolated.
                error(
                    f"Warning: Failed to resume vCPUs for '{config.name}': {exc}. "
                    f"The VM may remain paused — check with 'workloadctl status {config.name}'.",
                )
    finally:
        qmp.close()

    size = output.stat().st_size
    if not quiet:
        print_backup_size(output, size)
    return size


def _ignore_other_filesystems(root: Path, *, quiet: bool):
    """Build a `shutil.copytree` ignore callback that stops at mount points.

    Returns the names in each visited directory that sit on a different
    filesystem than `root` -- `--one-file-system` semantics, applied at every
    level rather than only the top, so a mount nested deep in the tree is
    skipped too.

    lstat, not stat: a symlink is judged by the filesystem holding the *link*,
    which is what `symlinks=True` copies. Resolving it would skip ordinary
    in-tree symlinks merely because they point at another filesystem.

    Skips are warned about, never silent. An archive quietly missing a subtree
    is a problem discovered at restore time, which is the worst time.
    """
    root_dev = root.stat().st_dev

    def ignore(src, names):
        skipped = set()
        for name in names:
            try:
                if os.lstat(os.path.join(src, name)).st_dev != root_dev:
                    skipped.add(name)
            except OSError:
                # Vanished between scandir and lstat -- leave it to copytree,
                # which reports per-entry errors properly.
                continue
        if skipped and not quiet:
            for name in sorted(skipped):
                warn(f"  Warning: skipping '{os.path.join(src, name)}' — separate "
                     f"filesystem, not captured in this archive")
        return skipped

    return ignore


def backup_impl(config, output: Path, *, no_stop: bool, quiet: bool, vm: bool) -> None:
    """Internal backup implementation shared by container and VM paths."""
    name = config.name
    config_path = workload_config_path(name)
    service_name = config.service_name

    service_was_active = subprocess.run(
        ["systemctl", "is-active", "--quiet", service_name],
    ).returncode == 0

    if service_was_active and not no_stop:
        if not quiet:
            info(f"  Stopping {service_name}...")
        subprocess.run(["systemctl", "stop", service_name], check=True)

    try:
        with tempfile.TemporaryDirectory() as staging_name:
            staging = Path(staging_name)

            shutil.copy2(config_path, staging / "workload.toml")

            creds = auto_detect_credentials(config.config)
            if creds:
                cred_dir = staging / "credentials"
                cred_dir.mkdir()
                for cred_name in sorted(creds):
                    cred_path = CREDSTORE_DIR / cred_name
                    if cred_path.exists():
                        shutil.copy2(cred_path, cred_dir / cred_path.name)
                    elif not quiet:
                        warn(f"  Warning: Credential '{cred_name}' not found, skipping")

            # Capture only the precious data/ subtree — for every substrate.
            # state/ (podman graphroot, VM system.qcow2 + gen snapshots,
            # .image-cache) is reconstructible from registries/Containerfiles
            # and is deliberately never in backup scope, so no exclude filtering
            # is needed on that axis: the archive is a copy of data/.
            #
            # It stops at filesystem boundaries, though. data/ is a plain local
            # directory in the normal case, which is what made a straight copy
            # the whole story — but an operator can mount something under it (a
            # network share behind a VM's virtiofs volume, a second disk, a bind
            # mount), and copytree does not stop at mount points. It would pull
            # that entire filesystem across into the archive, over whatever
            # transport backs it, with the workload STOPPED — cold consistency
            # is the default. Data on a mount under data/ is backed up by
            # whatever owns that mount, so skip it and say so.
            data_dir = config.data_dir
            if data_dir.is_dir():
                shutil.copytree(
                    data_dir, staging / "data",
                    symlinks=True, dirs_exist_ok=False,
                    ignore=_ignore_other_filesystems(data_dir, quiet=quiet),
                )
            else:
                (staging / "data").mkdir()

            # Backups hold the precious data/ tree and credential blobs, so keep
            # the archive root-only. Pre-create it as 0600 *before* tar writes so
            # it is never traversable by non-root during the write window (tar
            # truncates but leaves an existing file's mode intact), then re-pin to
            # 0600 after. We deliberately do NOT touch output.parent's mode: it's
            # the operator-chosen --output location (e.g. /tmp or a shared mount),
            # and chmodding it to 0700 as root would clobber a directory the
            # operator meant to share.
            output.parent.mkdir(parents=True, exist_ok=True)
            os.close(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
            subprocess.run(
                ["tar", "-C", str(staging), "-cf", str(output), "--zstd", "."],
                check=True,
            )
            os.chmod(output, 0o600)
    finally:
        if service_was_active and not no_stop:
            if not quiet:
                info(f"  Starting {service_name}...")
            # Containers: re-pin the runtime dir and tolerate start-limit thrash
            # when bringing the workload back up after the cold-backup stop.
            # VMs have no /run/user/<uid>, so start them plainly.
            if vm:
                subprocess.run(["systemctl", "start", service_name])
            else:
                try:
                    restart_workload_service(config.uid, service_name, action="start")
                except subprocess.CalledProcessError:
                    pass


def print_backup_size(output: Path, size: int) -> None:
    if size >= 1_000_000_000:
        size_str = f"{size / 1_000_000_000:.1f}G"
    elif size >= 1_000_000:
        size_str = f"{size / 1_000_000:.1f}M"
    elif size >= 1_000:
        size_str = f"{size / 1_000:.1f}K"
    else:
        size_str = f"{size}B"
    info(f"  Backup: {output} ({size_str})")
