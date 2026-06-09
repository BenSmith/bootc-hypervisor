"""Run podman against a --cgroups=split workload container from the right cgroup.

Containers started with --cgroups=split (single/bridge mode) run under the
*system* manager's workloads.slice, e.g.

    0::/workloads.slice/workload-bigdevfire.service/libpod-payload-<id>

The `workload-<name>.service` directory is the cgroup systemd delegated to the
workload user (Delegate=yes + User=). crun runs an `exec`/`healthcheck` probe by
*migrating* the new process into that payload cgroup. cgroup v2 only permits
that move when the originating process already sits inside the delegated
subtree — so a plain `sudo -u` (which pam_systemd re-homes into a user
login-session scope under user.slice) or podman's own user-manager healthcheck
timer (under user@<uid>.service) crosses the root cgroup boundary and fails:

    crun: write to .../cgroup.procs: Permission denied

The fix: as root, park podman in a leaf of the container's *delegated* unit
cgroup, then drop privileges without PAM. The leaf must be *owned* by the
workload uid (chowning cgroup.procs alone is not enough — directory ownership is
what authorizes the cross-cgroup move). Both `workloadctl exec/shell` and the
split-workload healthcheck timer use this. See the project memory note
`cgroups-split-breaks-podman-exec`.
"""

import os
import subprocess
from pathlib import Path


def delegated_unit_cgroup(proc_cgroup_text: str) -> str | None:
    """Relative cgroup path of a container's *delegated* systemd unit, parsed
    from the contents of its /proc/<pid>/cgroup; None when there isn't one.

    Returns e.g. "/workloads.slice/workload-bigdevfire.service" (single) or
    "/workloads.slice/workload-foo-web.service" (bridge). When the container
    lives in the user manager instead (pod mode, or migrated to user@<uid>
    without split) there is no `workload-*.service` ancestor, so this returns
    None and callers fall back to the plain `sudo -u` path (which works there).
    """
    rel = ""
    for line in proc_cgroup_text.splitlines():
        if line.startswith("0::"):  # cgroup v2 unified line
            rel = line[3:]
            break
    parts = [p for p in rel.split("/") if p]
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].startswith("workload-") and parts[i].endswith(".service"):
            return "/" + "/".join(parts[: i + 1])
    return None


def cgroup_for_pid(pid: str) -> str | None:
    """Return the delegated unit cgroup for a running container PID, or None.

    Wraps delegated_unit_cgroup() + the /proc read so callers don't each need
    a bare try/except around Path(...).read_text().
    """
    try:
        return delegated_unit_cgroup(Path(f"/proc/{pid}/cgroup").read_text())
    except OSError:
        return None


def cgroup_placed_podman(unit_rel: str, uid: int, gid: int, username: str,
                         home_dir, podman_args, *, leaf_name: str,
                         check=False, capture_output=False, extra_env=None,
                         timeout=None):
    """Run `podman <podman_args>` parked in a uid-owned leaf of a split
    container's delegated unit cgroup, dropping privileges without PAM.

    `unit_rel` is the delegated unit cgroup (from delegated_unit_cgroup());
    `leaf_name` is the sub-cgroup we create under it (e.g. "wlctl-exec" or
    "wlctl-hc"). Must be called as root. Raises OSError if the leaf cannot be
    created/chowned (the caller decides whether to fall back); otherwise returns
    the CompletedProcess from `podman` (and honours check= like subprocess.run).
    """
    leaf = Path("/sys/fs/cgroup") / unit_rel.lstrip("/") / leaf_name
    # The leaf must be *owned* by the workload uid, not merely writable: cgroup
    # v2 grants the migration's cross-cgroup move on the basis of source-cgroup
    # *directory* ownership. A root-owned leaf EPERMs even though the placement
    # write below is done as root.
    leaf.mkdir(exist_ok=True)
    os.chown(leaf, uid, gid)

    procs_file = str(leaf / "cgroup.procs")
    env = {
        "XDG_RUNTIME_DIR": f"/run/user/{uid}",
        "HOME": str(home_dir),
        "PATH": "/usr/bin:/bin",
    }
    if extra_env:
        env.update(extra_env)

    def _enter_cgroup_and_drop_privs():
        # Forked child, still root, pre-execve: join the delegated leaf, then
        # drop to the workload user without PAM (no session-scope re-homing).
        with open(procs_file, "w") as f:
            f.write(str(os.getpid()))
        os.initgroups(username, gid)
        os.setgid(gid)
        os.setuid(uid)

    try:
        return subprocess.run(
            ["/usr/bin/podman", *podman_args],
            preexec_fn=_enter_cgroup_and_drop_privs,
            env=env, check=check, capture_output=capture_output,
            text=True, cwd="/tmp", timeout=timeout,
        )
    finally:
        try:
            leaf.rmdir()  # best-effort; fails (ignored) if another run is live
        except OSError:
            pass
