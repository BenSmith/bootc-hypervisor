"""
test_runtime_upgrade.py — workloadctl N -> N+1 with a workload running under it.

The rung had 15 runtime modules and none of them was an upgrade test:
`test_update_rollback.py` covers workload *image* and VM *disk* generations, not
the package upgrading beneath live workloads. That is the one transition an
operator performs most often and the only one where the code changes while the
units do not.

**No version bumping is needed, and no second checkout.** `Release` is
`1.<build timestamp>` — a monotonic build serial — so building the tree already
in the guest a second time yields a strictly newer NEVR and a genuine `$1 == 2`
dnf upgrade transaction. That is what makes this cheap: the harness already
rsynced the tree and ran `just rpm-install` once at launch, so "install N+1" is
re-running one recipe.

What the transition must and must not do, which is the whole point of pinning it:

  - the workload keeps running. `%post` does not regenerate units, so a live
    workload must be entirely undisturbed by the upgrade.
  - `%post` *warns* that the running units are the previous build's, because on
    a plain-RPM host that window stays open indefinitely and silently. (On a
    bootc host it cannot open — new code is only live after a reboot, which
    regenerates.)
  - `status --json` reports the skew via `units_generated_by`. That field is
    never null — it coalesces "stamps agree" to the running version — so the
    signal is the field compared against the *installed* NEVR, not against None.
  - `drift` stays **clean**, because it normalizes the provenance stamp out. If
    it did not, every workload would read as drifted after every upgrade
    including the byte-identical ones, which is how a signal stops being read.
  - `/var` state is untouched.
  - a plain `enable` afterwards clears the skew.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).

Verified end to end on tp 2026-07-29, `WLRT_MODE=dev`, all six assertions:
`0.1.0-1.20260729220333` -> `0.1.0-1.20260729220349`, 16 seconds of build serial
apart, and dnf logged the `Upgrading` + `Removing` pair that only the `$1 == 2`
path produces. So the premise really does hold: two builds of one tree are a
genuine upgrade transaction.
"""

import json

import pytest

from fixtures import _enable_workload, _install_toml, _purge_workload, dump_journal

pytestmark = pytest.mark.runtime

WORKLOAD = "rt-upgrade"
# Written into the workload's precious subtree before the upgrade; must survive.
SENTINEL = f"/var/lib/workloads/{WORKLOAD}/data/upgrade-sentinel"
SENTINEL_BODY = "state must outlive the package"

SRC = "~/clitest-src/workloadctl"


def _nevr(target) -> str:
    return target.run(
        ["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "workloadctl"],
        sudo=False, check=True).stdout.strip()


def _generated_by(target, name) -> str:
    """The build stamped on the live units, per `status --json`.

    Never null: the JSON coalesces `units_from_other_build()`'s None (stamps
    agree) to the running version, so the field always names *a* build. The skew
    signal is therefore this value compared against the *installed* NEVR — equal
    means the units are this build's, unequal means they are the previous
    build's.
    """
    r = target.wl(f"status --json {name}", sudo=True, check=False)
    try:
        return json.loads(r.stdout)["units_generated_by"]
    except (json.JSONDecodeError, KeyError):
        pytest.fail(f"unusable status --json output (rc={r.rc}):"
                    f"\n{r.stdout}\n{r.stderr}")


def _reinstall(target):
    """Build and install again from the tree already in the guest.

    A fresh build serial makes this an upgrade rather than a reinstall, so the
    `$1 >= 2` branch of %post runs. Returns the combined output — the %post
    warning goes to stderr, and dnf's own scriptlet relay can land it on either
    stream depending on version, so both are searched together.
    """
    r = target.run(["bash", "-c", f"cd {SRC} && just rpm-install"],
                   sudo=False, check=False, timeout=600)
    assert r.rc == 0, f"rpm-install failed (rc={r.rc}):\n{r.stdout}\n{r.stderr}"
    return r.stdout + r.stderr


def test_upgrade_under_a_running_workload(target):
    """N -> N+1 leaves the workload running and its state intact, reports the
    unit/build skew without reporting drift, and clears on re-enable."""
    _install_toml(target, f"{WORKLOAD}.toml")
    try:
        try:
            _enable_workload(target, WORKLOAD, timeout=180)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        target.run(["bash", "-c",
                    f"printf '%s' {SENTINEL_BODY!r} | sudo tee {SENTINEL} >/dev/null"],
                   sudo=False, check=True)

        before = _nevr(target)
        assert _generated_by(target, WORKLOAD) == before, \
            "units should be stamped with the installed build before any upgrade"

        output = _reinstall(target)
        after = _nevr(target)
        assert after != before, (
            f"build serial did not advance ({before} -> {after}); the upgrade "
            f"path was never exercised")

        # 1. The workload is undisturbed. Checked before anything else, since a
        #    restart here would invalidate every assertion below it.
        try:
            st = target.run(
                ["systemctl", "is-active", f"workload-{WORKLOAD}.service"],
                sudo=False, check=False)
            assert st.stdout.strip() == "active", \
                f"workload unit is {st.stdout.strip()!r} after the upgrade"
        except Exception:
            dump_journal(target, WORKLOAD)
            raise

        # 2. %post warned about units left from the previous build.
        assert "generated by the previous" in output, (
            "the %post upgrade warning did not fire with a live workload "
            f"present. Output was:\n{output[-3000:]}")

        # 3. status names the build that actually wrote the live units — the
        #    previous one, which is now different from what is installed. Both
        #    halves matter: `== before` alone also holds *before* the upgrade,
        #    so it is `!= after` that makes this the skew and not a tautology.
        stamped = _generated_by(target, WORKLOAD)
        assert stamped == before, (
            f"live units should still name the build that wrote them "
            f"({before}), got {stamped}")
        assert stamped != after

        # 4. ...and drift is still clean, because the stamp is normalized out.
        d = target.wl(f"drift {WORKLOAD}", sudo=True, check=False)
        assert d.rc == 0, (
            "an upgrade with a byte-identical unit body must not report drift "
            f"(rc={d.rc}):\n{d.stdout}")

        # 5. /var survived the package transaction.
        got = target.run(["sudo", "cat", SENTINEL], sudo=False, check=True)
        assert got.stdout.strip() == SENTINEL_BODY

        # 6. The documented remedy actually remedies it.
        try:
            _enable_workload(target, WORKLOAD, timeout=180, retries=0)
        except Exception:
            dump_journal(target, WORKLOAD)
            raise
        assert _generated_by(target, WORKLOAD) == after, \
            "re-enabling should restamp the units with the installed build"
        assert target.wl(f"drift {WORKLOAD}", sudo=True, check=False).rc == 0
    finally:
        _purge_workload(target, WORKLOAD)
