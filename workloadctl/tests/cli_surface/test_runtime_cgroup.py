"""
test_runtime_cgroup.py — B3 runtime check: the load-bearing ADR-001 option-1b
invariant, proven on a real kernel.

The whole cgroup design rests on one claim that unit-file text can never show:
a workload's *container payload* actually runs under
`workloads.slice/user@<uid>.service/...`, not loose in the host hierarchy. If
that regresses, per-workload resource limits (set on the user@<uid> slice) stop
applying and the isolation guarantee is silently void. This test reads the live
payload PID's cgroup and asserts the placement, plus the drop-in that pins it.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import pytest

from fixtures import _enable_workload, _install_toml, _purge_workload

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-basic"
USER = "_wl-rt-basic"
CONTAINER = "workload-rt-basic"  # single-mode container name (generator convention)


def _dump_journal(target, name):
    """Print the workload unit's journal tail — the diagnosis on any failure."""
    r = target.run(
        ["journalctl", "--no-pager", "-n", "80", "-u", f"workload-{name}.service"],
        sudo=True, check=False,
    )
    print(f"\n----- journalctl -u workload-{name}.service (tail) -----\n"
          f"{r.stdout}\n{r.stderr}\n--------------------------------------------------------")


def test_cgroup_placement(target):
    """The running container payload lands under workloads.slice/user@<uid>.service,
    and the user@<uid> drop-in that puts it there carries Slice=workloads.slice."""
    _install_toml(target, "rt-basic.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            _dump_journal(target, WORKLOAD)
            raise

        # Resolve the workload uid at runtime — never hardcode 10000 (get_next_uid
        # scans the live passwd DB, so the slot shifts across hosts).
        r = target.run(["id", "-u", USER], sudo=False, check=True)
        uid = r.stdout.strip()
        assert uid.isdigit(), f"could not resolve uid for {USER}: {r.stdout!r}"

        # Live payload PID, via the workload user's own rootless podman. Run
        # from `/` inside a shell: runuser keeps the caller's CWD, and the
        # deploy user's home isn't traversable by _wl-*, so it must chdir
        # somewhere world-accessible before dropping privileges.
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

        # The invariant: the payload's cgroup path runs under the workload's
        # user manager slice.
        r = target.run(["cat", f"/proc/{pid}/cgroup"], sudo=True, check=True)
        cgroup = r.stdout.strip()
        print(f"\n----- /proc/{pid}/cgroup ({CONTAINER}) -----\n{cgroup}\n"
              f"------------------------------------------------")

        # --- diagnostics (kept: they explain any placement failure) ---
        dropin_path = f"/run/systemd/system/user@{uid}.service.d/50-workload.conf"
        d1 = target.run(["cat", dropin_path], sudo=True, check=False)
        d2 = target.run(["systemctl", "show", f"user@{uid}.service",
                         "-p", "Slice", "-p", "ActiveState", "-p", "SubState",
                         "-p", "ControlGroup"], sudo=True, check=False)
        d3 = target.run(["systemctl", "is-active", "workloads.slice"], sudo=True, check=False)
        print(f"----- drop-in {dropin_path} -----\n{d1.stdout}{d1.stderr}\n"
              f"----- systemctl show user@{uid}.service -----\n{d2.stdout}{d2.stderr}\n"
              f"----- workloads.slice is-active -----\n{d3.stdout}{d3.stderr}\n"
              f"------------------------------------------------")

        assert "workloads.slice" in cgroup, (
            f"payload PID {pid} is NOT under workloads.slice — ADR-001-1b regression:\n{cgroup}"
        )
        assert f"user@{uid}.service" in cgroup, (
            f"payload PID {pid} is NOT under user@{uid}.service — ADR-001-1b regression:\n{cgroup}"
        )

        # The drop-in that pins the placement must exist and set the slice.
        dropin = f"/run/systemd/system/user@{uid}.service.d/50-workload.conf"
        r = target.run(["cat", dropin], sudo=True, check=False)
        assert r.rc == 0, f"drop-in {dropin} missing:\n{r.stderr}"
        assert "Slice=workloads.slice" in r.stdout, (
            f"{dropin} does not set Slice=workloads.slice:\n{r.stdout}"
        )
    finally:
        _purge_workload(target, WORKLOAD)
