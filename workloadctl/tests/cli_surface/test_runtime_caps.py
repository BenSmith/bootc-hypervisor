"""
test_runtime_caps.py — C1 GAP check: per-container resource caps land as real
cgroup limit values on a live kernel.

`[container.resources]` limits are emitted as podman flags (`--memory`,
`--pids-limit`, …) rather than systemd slice directives (generators/workload-
generate): crun writes them straight onto the container payload's own cgroup. The
claim that they *bind* — that a `--memory=128M` actually becomes `memory.max =
134217728` on the running container — is only observable on a real kernel. This
test enables a capped workload, resolves the live payload PID, and reads the
enforced limit values from that PID's cgroup.

Core assertions are the cgroup limit *values* (deterministic, reliable). The
OOM-kill-on-limit path is deliberately out of scope here (the fiddly optional
extra called out in the C1 build order).

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import pytest

from fixtures import _enable_workload, _install_toml, _purge_workload

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-caps"
USER = "_wl-rt-caps"
CONTAINER = "workload-rt-caps"       # single-mode container name (generator convention)

# Expected enforced values (see rt-caps.toml).
EXPECT_MEMORY_MAX = str(128 * 1024 * 1024)   # "128M" -> bytes
EXPECT_PIDS_MAX = "100"                        # tasks_max


def _dump_journal(target, name):
    r = target.run(
        ["journalctl", "--no-pager", "-n", "80", "-u", f"workload-{name}.service"],
        sudo=True, check=False,
    )
    print(f"\n----- journalctl -u workload-{name}.service (tail) -----\n"
          f"{r.stdout}\n{r.stderr}\n--------------------------------------------------------")


def _cgroup_chain(cgroup_path):
    """Yield the payload's cgroup and its ancestors, stopping *below* the user
    manager (user@<uid>.service).

    A cgroup-v2 memory/pids limit is written on whichever cgroup crun/podman
    manages for the container — that can be the leaf the payload PID sits in or
    the enclosing `libpod-*.scope`. Walking the container's own subtree (but not
    up into the user@<uid>.service manager or the workload slice) finds the limit
    wherever it landed, without ever reading a slice-level cap.
    """
    parts = cgroup_path.strip("/").split("/")
    # Trim everything up to and including the user@<uid>.service manager, so the
    # chain we scan is strictly the container's subtree.
    for i, seg in enumerate(parts):
        if seg.startswith("user@") and seg.endswith(".service"):
            parts = parts[i + 1:]
            break
    while parts:
        yield "/" + "/".join(parts)
        parts = parts[:-1]


def _limit_in_chain(target, cgroup_path, filename):
    """Return (matched_value_map) of cgroup file -> value across the container
    subtree, so the caller can assert the expected limit appears somewhere."""
    seen = {}
    for cg in _cgroup_chain(cgroup_path):
        full = f"/sys/fs/cgroup{cg}/{filename}"
        r = target.run(["cat", full], sudo=True, check=False)
        if r.rc == 0:
            seen[full] = r.stdout.strip()
    return seen


def test_container_cgroup_limits_enforced(target):
    """--memory / --pids-limit land as memory.max / pids.max on the payload cgroup."""
    _install_toml(target, "rt-caps.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            _dump_journal(target, WORKLOAD)
            raise

        # Resolve the workload uid at runtime (get_next_uid scans the live passwd
        # DB, so the slot shifts across hosts — never hardcode 10000).
        uid = target.run(["id", "-u", USER], sudo=False, check=True).stdout.strip()
        assert uid.isdigit(), f"could not resolve uid for {USER}"

        # Live payload PID via the workload user's own rootless podman. Run from
        # `/` so runuser can chdir somewhere world-accessible before dropping
        # privileges (the deploy user's home isn't traversable by _wl-*).
        pid_fmt = "{{.State.Pid}}"
        r = target.run(
            ["sh", "-c",
             f"cd / && runuser -u {USER} -- "
             f"env XDG_RUNTIME_DIR=/run/user/{uid} "
             f"podman inspect --format '{pid_fmt}' {CONTAINER}"],
            sudo=True, check=False,
        )
        pid = r.stdout.strip()
        assert pid.isdigit() and int(pid) > 0, (
            f"no running payload PID for {CONTAINER} (got {r.stdout!r} / {r.stderr!r})"
        )

        # The leaf cgroup the payload actually lives in (v2: single `0::<path>` line).
        cg = target.run(["cat", f"/proc/{pid}/cgroup"], sudo=True, check=True).stdout.strip()
        assert cg.startswith("0::"), f"unexpected cgroup line for {pid}: {cg!r}"
        cgroup_path = cg.split("::", 1)[1]
        print(f"\n----- payload {CONTAINER} pid {pid} cgroup -----\n{cgroup_path}\n"
              f"------------------------------------------------")

        mem_seen = _limit_in_chain(target, cgroup_path, "memory.max")
        pids_seen = _limit_in_chain(target, cgroup_path, "pids.max")
        print(f"----- enforced caps across container cgroup subtree -----\n"
              f"memory.max: {mem_seen}\npids.max:   {pids_seen}\n"
              f"--------------------------------------------------------")

        assert EXPECT_MEMORY_MAX in mem_seen.values(), (
            f"memory.max = {EXPECT_MEMORY_MAX} not found in the container cgroup "
            f"subtree (--memory=128M not enforced); saw {mem_seen}"
        )
        assert EXPECT_PIDS_MAX in pids_seen.values(), (
            f"pids.max = {EXPECT_PIDS_MAX} not found in the container cgroup "
            f"subtree (--pids-limit=100 not enforced); saw {pids_seen}"
        )
    finally:
        _purge_workload(target, WORKLOAD)
