"""
cmd_interact — interactive/exec commands: shell, exec, logs, cp, incant.
"""

import contextlib
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

from cli_log import emit_result
from workload_lib import workload_service_units
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    WorkloadUserNotFound,
    parse_workload_ref,
    resolve_container_target,
)
from substrate import get_substrate


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_shell(args, manager: WorkloadManager):
    """Open interactive shell in workload container or VM console"""
    workload, container = parse_workload_ref(args.workload)
    config = WorkloadConfig(workload)

    if not manager.user_exists(config):
        print(f"Error: Workload user '{config.username}' does not exist", file=sys.stderr)
        print("Is the workload enabled and running?", file=sys.stderr)
        sys.exit(1)

    substrate = get_substrate(config, manager)
    substrate.open_shell(container=container, console=getattr(args, 'console', False))


def cmd_exec(args, manager: WorkloadManager):
    """Execute command in workload container or VM (via SSH)"""
    workload, container = parse_workload_ref(args.workload)
    config = WorkloadConfig(workload)

    if not manager.user_exists(config):
        print(f"Error: Workload user '{config.username}' does not exist", file=sys.stderr)
        print("Is the workload enabled and running?", file=sys.stderr)
        sys.exit(1)

    # argparse.REMAINDER keeps a literal `--` separator if the user passed one
    # (`workloadctl exec web -- cmd`); drop it so it isn't run as the command.
    exec_args = args.exec_args
    if exec_args and exec_args[0] == "--":
        exec_args = exec_args[1:]
    if not exec_args:
        print("Error: no command given to exec", file=sys.stderr)
        sys.exit(2)

    substrate = get_substrate(config, manager)
    sys.exit(substrate.exec(exec_args, container=container))


def _journal_selection(config, container):
    """journalctl match args selecting a workload's (or one container's) logs.

    Container workloads run ``--log-driver=passthrough``, so a container's own
    output is attributed by journald to the rootless user manager's cgroup
    (``user@<uid>.service``), NOT the workload ``.service`` unit — ``-u <unit>``
    alone catches only the systemd lifecycle lines, none of the app output. The
    output IS in the journal, tagged with the container's ``SyslogIdentifier``
    (its podman ``--name``), so we OR that identifier in alongside the unit.
    Three fields cover the three line sources, all time-merged by journald:
    ``_SYSTEMD_UNIT=`` the ``podman run`` supervisor's own messages, ``UNIT=``
    the PID1 Started/Stopped lines, ``SYSLOG_IDENTIFIER=`` the passthrough app
    output. A whole multi-container workload ORs every member so its containers
    interleave into one chronological stream; ``<workload>/<container>`` narrows
    to one.

    A fourth field, ``_UID=``, catches what the other three structurally cannot:
    bundles that run systemd as PID 1 give every service's output to their *own*
    in-container journald, and bridge it to the host with journald's
    ``ForwardToSocket=`` aimed at the bind-mounted host journal socket. Those
    entries keep their in-container ``SYSLOG_IDENTIFIER`` (``sunshine``,
    ``sway``, ``systemd``) and are stamped ``_SYSTEMD_UNIT=user@<uid>.service``
    from the sender's cgroup, so none of the three terms above match them. Each
    workload owns a dedicated user, which makes ``_UID`` an exact per-workload
    selector — and a trustworthy one: journald stamps it from ``SO_PEERCRED``
    and clients cannot forge ``_``-prefixed fields, so a workload can spoof its
    display identifier but not its provenance. It is workload-wide by
    construction, so ``<workload>/<container>`` omits it rather than silently
    widening back to every container.

    VMs log to a real QEMU *system* unit where ``-u`` works, so they keep it.
    """
    if config.is_vm:
        return ["-u", config.service_name]

    uids = []
    if container is not None:
        # container_names() and sub_service_names() are index-aligned; for a
        # single-container workload NAME/NAME this maps to the main unit.
        units = [dict(zip(config.container_names(),
                          config.sub_service_names()))[container]]
        idents = [config.podman_container_name(container)]
    else:
        units = workload_service_units(config) if config.is_multi \
            else [config.service_name]
        idents = config.podman_targets()
        # No user yet (never enabled) just means there are no forwarded entries
        # to select — the unit/identifier terms still work, so don't fail.
        with contextlib.suppress(WorkloadUserNotFound):
            uids = [config.uid]

    terms = ([f"_SYSTEMD_UNIT={u}" for u in units]
             + [f"UNIT={u}" for u in units]
             + [f"SYSLOG_IDENTIFIER={i}" for i in idents]
             + [f"_UID={u}" for u in uids])
    # '+' between every term forces a disjunction even across different fields
    # (same-field matches OR implicitly; different fields would otherwise AND).
    # journalctl rejects '+' next to the -u/-t convenience flags, so these are
    # raw FIELD=value matches.
    selection = []
    for i, term in enumerate(terms):
        if i:
            selection.append("+")
        selection.append(term)
    return selection


def cmd_logs(args, manager: WorkloadManager):
    """View workload logs"""
    workload, container = parse_workload_ref(args.workload)
    config = WorkloadConfig(workload)

    if container is not None and container not in config.container_names():
        print(f"Error: container '{container}' not in workload '{workload}'. "
              f"Available: {', '.join(config.container_names())}", file=sys.stderr)
        sys.exit(2)

    # Build the journalctl command (substrate-agnostic: the substrate's logs()
    # primitive handles any substrate-specific wrapping around this argv).
    cmd = ["journalctl"] + _journal_selection(config, container)

    # Add options
    if args.follow:
        cmd.append("-f")
    if args.lines:
        cmd.extend(["-n", str(args.lines)])
    elif not args.follow and not args.since and not args.extra_args:
        cmd.extend(["-n", "50"])
    if args.since:
        cmd.extend(["--since", args.since])

    if args.extra_args:
        cmd.extend(args.extra_args)

    substrate = get_substrate(config, manager)
    substrate.logs(cmd)


def cmd_cp(args, manager: WorkloadManager):
    """Copy files to/from container"""
    src = args.source
    dest = args.destination

    # Parse workload[/container]:path syntax
    workload_pattern = re.compile(r'^([^:]+):(.+)$')

    src_match = workload_pattern.match(src)
    dest_match = workload_pattern.match(dest)

    if src_match and not dest_match:
        # Copy from container
        workload_ref = src_match.group(1)
        container_path = src_match.group(2)
        host_path = dest
        direction = "from"
    elif dest_match and not src_match:
        # Copy to container
        workload_ref = dest_match.group(1)
        container_path = dest_match.group(2)
        host_path = src
        direction = "to"
    else:
        print("Error: One argument must be in workload:path format", file=sys.stderr)
        print("Examples:", file=sys.stderr)
        print("  workloadctl cp webserver:/etc/config ./config", file=sys.stderr)
        print("  workloadctl cp ./file.txt webserver:/data/file.txt", file=sys.stderr)
        print("  workloadctl cp proxy/web:/etc/config ./config", file=sys.stderr)
        sys.exit(1)

    workload, container = parse_workload_ref(workload_ref)
    config = WorkloadConfig(workload)

    if not manager.user_exists(config):
        print(f"Error: Workload user '{config.username}' does not exist", file=sys.stderr)
        print("Is the workload enabled and running?", file=sys.stderr)
        sys.exit(1)

    target = resolve_container_target(config, container, workload)
    pod = manager.podman(config)

    # The host side of the copy must run in the root context (workloadctl runs
    # as root): the rootless `_wl` user generally cannot read root-owned/0600
    # host sources (host->container "not found") and cannot write the host
    # destination — and because podman runs with cwd=/tmp, relative host
    # destinations silently land in /tmp instead of the caller's directory
    # (container->host data loss). We bridge through a staging dir owned by the
    # workload user: root does all host I/O, podman does all container-side path
    # semantics natively against the staged copy.
    if direction == "from":
        _cp_from_container(pod, config, target, container_path, host_path)
    else:
        _cp_to_container(pod, config, target, container_path, host_path)

    print("✓ Copied successfully")

    # Only a copy *into* the workload is an operation on it; copying out reads it
    # and changes nothing, and recording that would be the same no-op noise the
    # allowlist in oplog exists to keep out.
    if direction == "to":
        emit_result([{"workload": workload, "result": "copied",
                      "container": target, "path": container_path,
                      "source": host_path}])


@contextlib.contextmanager
def _cp_staging(config: "WorkloadConfig"):
    """A temp dir under the workload's home (0700) for staging cp transfers.

    Must live inside the workload user's home, not /var/tmp or /tmp: the
    rootless podman runs in a mount namespace with a private tmp (PrivateTmp),
    so a host-side dir created under /var/tmp is invisible to it ("could not be
    found on the host"). The home dir is on podman's own storage path and is
    always visible inside that namespace. Owned by `_wl-<name>` so its podman
    can read/write inside it; root keeps access regardless, and 0700 keeps other
    workload users out. Always removed on exit.
    """
    home = config.home_dir
    if not home.is_dir():
        print(f"Error: Workload home '{home}' does not exist (is it enabled?)",
              file=sys.stderr)
        sys.exit(1)
    d = Path(tempfile.mkdtemp(prefix=".workloadctl-cp-", dir=str(home)))
    try:
        # follow_symlinks=False for parity with _chown_tree: d is a real dir
        # root just minted, but never chown through a symlink from a home the
        # workload user owns (B1).
        os.chown(d, config.uid, config.gid, follow_symlinks=False)
        os.chmod(d, 0o700)
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _chown_tree(path: Path, uid: int, gid: int) -> None:
    """Recursively chown path (not following symlinks)."""
    os.chown(path, uid, gid, follow_symlinks=False)
    if path.is_dir() and not path.is_symlink():
        for root, dirs, files in os.walk(path):
            for name in dirs + files:
                try:
                    os.chown(os.path.join(root, name), uid, gid,
                             follow_symlinks=False)
                except OSError:
                    pass


def _cp_to_container(pod, config, target, container_path, host_path):
    """Copy a host path into a container (host read happens as root)."""
    src = Path(host_path)
    if not src.exists() and not src.is_symlink():
        print(f"Error: Source path '{host_path}' does not exist", file=sys.stderr)
        sys.exit(1)

    with _cp_staging(config) as stage:
        staged = stage / src.name
        # Copy as root so root-owned / 0600 sources are readable.
        if src.is_dir() and not src.is_symlink():
            shutil.copytree(src, staged, symlinks=True)
        else:
            shutil.copy2(src, staged, follow_symlinks=False)
        # Hand ownership to the workload user so its rootless podman can read it.
        _chown_tree(staged, config.uid, config.gid)

        # podman handles all container-side semantics (dir vs file, overwrite).
        proc = pod.run("cp", str(staged), f"{target}:{container_path}",
                       capture_output=True)
        if proc.returncode != 0:
            print(f"Error: copy into container failed:\n{proc.stderr.strip()}",
                  file=sys.stderr)
            sys.exit(1)


def _cp_from_container(pod, config, target, container_path, host_path):
    """Copy a container path to the host (host write happens as root)."""
    dest = Path(host_path)
    if not dest.is_dir() and not dest.parent.is_dir():
        print(f"Error: Destination directory '{dest.parent}' does not exist",
              file=sys.stderr)
        sys.exit(1)

    with _cp_staging(config) as stage:
        # podman copies the source into the staging dir using its basename, as
        # the workload user (only it can read its rootless container's fs).
        proc = pod.run("cp", f"{target}:{container_path}", f"{stage}/",
                       capture_output=True)
        if proc.returncode != 0:
            print(f"Error: copy from container failed:\n{proc.stderr.strip()}",
                  file=sys.stderr)
            sys.exit(1)

        entries = list(stage.iterdir())
        if not entries:
            print("Error: nothing was copied from the container", file=sys.stderr)
            sys.exit(1)
        produced = entries[0]

        # Move into place as root with docker-cp destination semantics:
        # existing dir -> copy in under the source basename; otherwise the
        # destination names the result (overwriting any existing file/dir).
        final = dest / produced.name if dest.is_dir() else dest
        if final.is_symlink() or final.exists():
            if final.is_dir() and not final.is_symlink():
                shutil.rmtree(final)
            else:
                final.unlink()
        shutil.move(str(produced), str(final))
        # Owned by the workload user after the move on same-fs renames; normalize
        # to root so the host result isn't left owned by `_wl-<name>`.
        _chown_tree(final, 0, 0)


def cmd_incant(args, manager: WorkloadManager):
    """Run a raw control-plane command against a workload (escape hatch).

    For container workloads this runs ``podman <argv>`` as the owning
    ``_wl-<name>`` user with the correct rootless environment — you never
    have to hand-build the sudo/XDG_RUNTIME_DIR invocation yourself.

    For VM workloads this sends a QMP command to the QEMU monitor (qmp.sock).
    The first token after ``--`` is the QMP command name; additional
    ``key=value`` tokens become the arguments dict.

    This verb bypasses the declarative TOML → units model.  Prefer the
    purpose-built verbs (update, rollback, shell, exec, …) when they cover your
    use case; use incant only when they do not.

    Examples::

        workloadctl incant webproxy -- network create mynet
        workloadctl incant webproxy -- volume ls
        workloadctl incant git -- system_powerdown
        workloadctl incant git -- query-status
    """
    workload, container = parse_workload_ref(args.workload)
    config = WorkloadConfig(workload)

    if not manager.user_exists(config):
        print(f"Error: Workload user '{config.username}' does not exist", file=sys.stderr)
        print("Is the workload enabled and running?", file=sys.stderr)
        sys.exit(1)

    # argparse.REMAINDER keeps a literal `--` separator; drop it.
    argv = args.argv
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("Error: no command given to incant", file=sys.stderr)
        sys.exit(2)

    substrate = get_substrate(config, manager)
    sys.exit(substrate.control(argv))
