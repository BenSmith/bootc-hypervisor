"""
service_runtime — systemd/logind runtime primitives keyed on (uid, service_name).

Split out of workloadctl_core so `substrate` (and any other consumer) can depend
on these without importing the WorkloadConfig/WorkloadManager domain model. These
functions have zero domain-model dependency — they speak only to systemctl /
loginctl about a uid and a unit name. `tests/test_layering.py` enforces the
direction of that dependency.
"""

import os
import subprocess
import time


def manager_active(uid: int) -> bool:
    """True iff the persistent user manager (user@<uid>.service) is running.

    This — NOT the mere existence of /run/user/<uid> — is the real signal that
    linger is effective. A transient `sudo -u … podman` login session makes
    pam_systemd create /run/user/<uid> on session-open and remove it on
    session-close, so a dir-existence check can false-positive while no
    lingering manager is running at all.
    """
    try:
        r = subprocess.run(
            ["systemctl", "is-active", f"user@{uid}.service"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return False
    return r.stdout.strip() == "active"


def ensure_runtime_dir(uid: int, timeout: float = 8.0) -> bool:
    """Best-effort: make linger genuinely effective and wait for it.

    The workload's own `ExecStart=/usr/bin/podman` (and `ExecStartPre`) depend on
    `/run/user/<uid>` — kept alive only while a lingering `user@<uid>.service`
    manager runs. Under rapid create/purge/restart churn (esp. UID recycling)
    that manager can be torn down, so a plain `systemctl restart` then fails with
    `Failed to set up mount namespacing: /run/user/<uid>: No such file` →
    `226/NAMESPACE`. The setup oneshot (`RemainAfterExit=yes`) does NOT re-run on
    a bare restart, so the CLI restart paths (update/rollback/recreate/start) call
    this first to re-pin linger. `podman._ensure_runtime_dir` (the read-only
    CLI-as-user retry path) also delegates here, with a shorter 5s deadline.
    Swallows all errors — if it can't fix it, the caller's restart surfaces the
    original failure.

    Gate on `user@<uid>.service` being active, NOT on `/run/user/<uid>` merely
    existing: a transient login session creates that dir too, so a dir-only
    check false-positives while no lingering manager exists. Explicitly start the
    manager (queued after any in-flight stop of this recycled UID's prior
    occupant) so we don't latch onto a dying session's dir.

    Returns True if the manager is active and the dir exists by the deadline.
    """
    runtime_dir = f"/run/user/{uid}"
    if manager_active(uid) and os.path.isdir(runtime_dir):
        return True
    try:
        subprocess.run(
            ["loginctl", "enable-linger", str(uid)],
            capture_output=True, timeout=5,
        )
        subprocess.run(
            ["systemctl", "start", f"user@{uid}.service"],
            capture_output=True, timeout=30,
        )
    except Exception:
        pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if manager_active(uid) and os.path.isdir(runtime_dir):
            return True
        time.sleep(0.1)
    return manager_active(uid) and os.path.isdir(runtime_dir)


def restart_workload_service(
    uid: int, service_name: str, *, action: str = "restart", retries: int = 1
) -> None:
    """(Re)start a *container* workload service, tolerating transient
    runtime-dir / start-limit thrash. Pass `action="start"` for start-only
    semantics (won't bounce an already-running unit); the default restarts.

    Under rapid create/purge/restart churn — notably UID recycling, where a
    freshly recycled UID's `/run/user/<uid>` is still being torn down and
    recreated by logind — the unit's `ExecStartPre=podman system migrate` /
    `ExecStart` can race the runtime dir and fail `226/NAMESPACE`; a couple of
    quick (re)starts then trip `StartLimitBurst` (`start-limit-hit`), which a
    bare systemctl call can never clear on its own. This re-pins the runtime
    dir, runs the systemctl action, and on failure `reset-failed`s (clearing any
    start-limit lockout), re-pins, and retries. It is the unit-(re)start-path
    analogue of podman.py's self-healing retry (which only covers the
    CLI-as-user read path).

    Only valid for container workloads. A VM workload *does* have a `_wl-<name>`
    user and a resolvable `config.uid`, but `workload-ensure-user` skips linger
    for VMs (QEMU runs as a system service: `User=_wl-<name>` with a
    `/run/workload-vm/<name>` RuntimeDirectory, not a logind user session), so
    there is no `/run/user/<uid>`. Pointing this helper at a VM would spuriously
    `enable-linger` the VM user and then block waiting for a runtime dir that
    never appears. Callers must branch on `config.is_vm` and keep the plain
    systemctl call for VMs.

    Raises subprocess.CalledProcessError if it still fails after the retries are
    exhausted, so a genuine crash-loop still surfaces loudly.
    """
    ensure_runtime_dir(uid)
    cmd = ["systemctl", action, service_name]
    attempt = 0
    while True:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            return
        if attempt >= retries:
            raise subprocess.CalledProcessError(
                proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr,
            )
        attempt += 1
        # Clear any StartLimitBurst lockout and re-pin the runtime dir, then
        # give logind a moment to stabilise it before retrying.
        subprocess.run(["systemctl", "reset-failed", service_name],
                       capture_output=True)
        ensure_runtime_dir(uid)
        time.sleep(1.0)


def systemctl_show(unit: str, properties: list[str], extra_args: list[str] | None = None) -> dict[str, str]:
    """Run `systemctl show` and return a {key: value} dict."""
    r = subprocess.run(
        ["systemctl", "show", unit, f"--property={','.join(properties)}"] + (extra_args or []),
        capture_output=True, text=True,
    )
    result = {}
    for line in r.stdout.splitlines():
        key, _, value = line.partition("=")
        if key:
            result[key] = value
    return result


def parse_active_since(ts_raw: str):
    """Parse a `systemctl show --timestamp=unix` ActiveEnterTimestamp value
    (`@<epoch>`, or empty/`[n/a]` when never active) into a unix-epoch int,
    or None if unset/unparseable."""
    if not ts_raw or not ts_raw.startswith("@"):
        return None
    try:
        return int(float(ts_raw[1:]))
    except ValueError:
        return None
