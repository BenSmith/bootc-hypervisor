"""
test_runtime_linger_runtime_dir.py — C1 GAP #6: linger is effective (the user
*manager* is running), not merely "the runtime dir happens to exist", and it
stays that way across CLI polls and a same-name/same-UID recycle.

The hard-won invariant (see .reference/notes/linger-and-runtime-dir.md, Layer 4):
effective linger == `systemctl is-active user@<uid>.service` == active. The mere
existence of `/run/user/<uid>` is NOT proof — every `sudo -u _wl-… podman` opens
a `pam_systemd` login session that creates the dir for ~50ms and tears it down on
close, which looks identical to effective linger. workloadctl's fix gates every
linger assertion on the manager being active and explicitly starts
`user@<uid>.service`; none of that is observable from unit text, so it needs a
booted kernel with real logind.

Two deterministic checks (we do NOT try to reproduce Layer 3's nondeterministic
UID-recycle *thrash* — that self-heal retry is unit-tested in test_podman.py):

  Tier 1 — steady state: after enable, the manager is active, `/run/user/<uid>`
  stays present across a watcher window (no flap), and the user-scoped CLI reads
  that historically raced the `lstat /run/user/<uid>` crash (`health`, `images`)
  run without it.

  Tier 2 — stale-marker false-positive (Layer 2): the linger marker
  `/var/lib/systemd/linger/<user>` survives a bare userdel, so `show-user …
  Linger` can report `yes` while no manager runs. We recreate that exact setup —
  plant the marker with the manager provably dead — then re-enable and assert the
  manager is genuinely active again (the fix always re-issues + starts, rather
  than trusting the stale marker).

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import time

import pytest

from fixtures import _enable_workload, _install_toml, _purge_workload, dump_journal

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-basic"
USER = "_wl-rt-basic"
LINGER_MARKER = f"/var/lib/systemd/linger/{USER}"


def _uid(target, user=USER):
    """The workload user's numeric UID (the user is created by enable)."""
    r = target.run(["id", "-u", user], sudo=False, check=True)
    return r.stdout.strip()


def _manager_active(target, uid):
    """`systemctl is-active user@<uid>.service` — the real linger-effective proof."""
    r = target.run(["systemctl", "is-active", f"user@{uid}.service"],
                   sudo=False, check=False)
    return r.stdout.strip()


def _runtime_dir_present(target, uid):
    """True iff /run/user/<uid> exists right now. Observed as root, whose own
    session uses /run/user/0 — so the poll never itself creates/tears the dir."""
    return target.run(["test", "-d", f"/run/user/{uid}"],
                      sudo=True, check=False).rc == 0


def test_linger_manager_is_active_and_runtime_dir_is_stable(target):
    """Tier 1: after enable the user *manager* is active, /run/user/<uid> stays
    present across a watcher window, and the exposed CLI reads don't crash on a
    transiently-absent runtime dir."""
    _install_toml(target, "rt-basic.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        uid = _uid(target)

        # The invariant that dir-existence can't prove: the manager is live.
        state = _manager_active(target, uid)
        if state != "active":
            dump_journal(target, WORKLOAD)
        assert state == "active", (
            f"user@{uid}.service is {state!r}, expected active — linger is not "
            f"effective even if /run/user/{uid} momentarily exists"
        )

        # Watcher: /run/user/<uid> must stay present, not flap. A live manager
        # pins it across the pam_systemd login-session churn from CLI polls.
        samples = [_runtime_dir_present(target, uid) for _ in _tick(15, 0.2)]
        present = sum(samples)
        assert all(samples), (
            f"/run/user/{uid} flapped: present in {present}/{len(samples)} samples "
            f"({samples}) — a live user@{uid}.service should keep it durable"
        )

        # The historically crash-prone user-scoped reads. `images` is the most
        # exposed (it loops over *every* workload user). Neither may surface the
        # `lstat /run/user/<uid>: no such file` signature the self-heal guards.
        for cmd in (f"health {WORKLOAD}", "images"):
            r = target.wl(cmd, sudo=True, check=False)
            blob = f"{r.stdout}\n{r.stderr}"
            assert f"lstat /run/user/{uid}" not in blob, (
                f"`workloadctl {cmd}` hit the runtime-dir lstat crash:\n{blob[:2000]}"
            )
    finally:
        _purge_workload(target, WORKLOAD)


def test_linger_survives_stale_marker_recycle(target):
    """Tier 2: a stale `/var/lib/systemd/linger/<user>` marker with the manager
    dead must not fool the enable path — re-enable brings a genuinely active
    manager back, not a marker-says-yes-but-nothing-runs false positive."""
    _install_toml(target, "rt-basic.toml")
    try:
        # First enable → capture the UID it lands on, then purge it away.
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise
        uid = _uid(target)
        _purge_workload(target, WORKLOAD)

        # Recreate the Layer-2 false-positive: marker present (as it would be
        # after a bare userdel that skipped disable-linger) while the manager is
        # provably dead. purge already tore user@<uid> down; assert that, then
        # plant the marker keyed by the username systemd-sysusers will recreate.
        state = _manager_active(target, uid)
        assert state != "active", (
            f"user@{uid}.service still {state!r} after purge — precondition for "
            f"the stale-marker test not met"
        )
        target.run(["touch", LINGER_MARKER], sudo=True, check=True)

        # _purge_workload also rm -rf's the config dir, so restore it before the
        # re-enable (the marker we just planted is separate, under /var/lib).
        _install_toml(target, "rt-basic.toml")

        # Re-enable within the same boot: the same-name user is recreated (very
        # likely the same lowest-free UID) with the stale marker already reading
        # Linger=yes. The fix must re-issue + start the manager anyway.
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise
        uid2 = _uid(target)

        state = _manager_active(target, uid2)
        if state != "active":
            dump_journal(target, WORKLOAD)
        assert state == "active", (
            f"after re-enable over a stale linger marker, user@{uid2}.service is "
            f"{state!r}, expected active — the enable path trusted the stale "
            f"marker instead of (re)starting the manager"
        )
        assert _runtime_dir_present(target, uid2), (
            f"/run/user/{uid2} absent despite an active manager after recycle"
        )
    finally:
        _purge_workload(target, WORKLOAD)


def _tick(count, interval):
    """Yield `count` times, sleeping `interval` between yields (not before the
    first). Keeps the watcher loop above readable."""
    for i in range(count):
        if i:
            time.sleep(interval)
        yield i
