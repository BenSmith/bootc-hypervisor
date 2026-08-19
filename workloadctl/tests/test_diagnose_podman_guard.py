#!/usr/bin/env python3
"""Diagnose must survive a podman that cannot answer.

The image-inventory and container-liveness checks run under the workload's own
rootless podman, which needs the user manager and /run/user/<uid> up. A disabled
workload has neither — disable() drops linger and logind GCs the runtime dir —
so podman exits with `Failed to obtain podman configuration: lstat
/run/user/<uid>: no such file or directory` before it can answer anything.

Observed on a live host: `workloadctl diagnose <disabled-workload>` died at
Check 6 with a PodmanError traceback and the "this looks like a workloadctl bug"
banner, discarding every check after it — including Checks 8 and 9, which would
have said plainly that the workload was disabled. Diagnose is the first thing an
operator reaches for on a workload that is not running, so it is the one command
that must not fall over on one.

podman.py's own runtime-dir self-heal does not cover this, deliberately: it is
gated on linger already being enabled, so that a read path can never be what
turns linger on. For a disabled workload it declines and the error arrives here.

Pinned here:
- The battery completes rather than raising, in both the single- and
  multi-container shapes, and on both podman-backed checks.
- The unanswerable check is omitted, not passed. Claiming an image is present in
  a store that would not open is a guess, and diagnose's whole value is that it
  does not make them.
- The omission is announced, exactly once however many reads fail — a check that
  silently vanishes reads the same as one that passed.
- Enabled-ness decides whether that announcement is a fault: expected for a
  workload that is off, a real failure (with a fix) for one that is supposed to
  be running.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cmd_diagnose
import workload_lib
from podman import PodmanError
from workloadctl_core import WorkloadConfig

SINGLE_TOML = """\
[workload]
name = "app"

[container]
image = "localhost/app:latest"
"""

POD_TOML = """\
[workload]
name = "pod"
mode = "pod"

[[containers]]
name = "api"
[containers.container]
image = "localhost/api:latest"

[[containers]]
name = "db"
[containers.container]
image = "localhost/db:latest"
"""

# The live stderr, verbatim. The guard keys off the exception type rather than
# this text, but the reported detail is the last line of it.
RUNTIME_DIR_GONE = (
    "Failed to obtain podman configuration: lstat /run/user/10003: "
    "no such file or directory"
)


def _podman_error():
    return PodmanError(1, RUNTIME_DIR_GONE + "\n", ("inspect", "--type=image"))


class PodmanUnavailableTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        for name, toml in (("app", SINGLE_TOML), ("pod", POD_TOML)):
            (self.tmp / name).mkdir()
            (self.tmp / name / "workload.toml").write_text(toml)

        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        # Both podman-backed reads fail the way a missing runtime dir fails.
        self.manager.get_image_id.side_effect = _podman_error()
        self.podman = self.manager.podman.return_value
        self.podman.image_id.side_effect = _podman_error()
        self.podman.container_status.side_effect = _podman_error()

        # config.uid goes through a real pwd lookup for a user that does not
        # exist on the test host; the value is never asserted on.
        self.enterContext(mock.patch.object(
            WorkloadConfig, "uid", new_callable=mock.PropertyMock,
            return_value=10099))
        # The rest of the battery still shells out. Both doors get an answer
        # this suite discards; neither can make a check appear or vanish.
        self.enterContext(mock.patch.object(
            cmd_diagnose.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="")))
        self.enterContext(mock.patch.object(
            cmd_diagnose, "service_active", return_value=(False, "inactive")))

    def _enable(self, name):
        (self.tmp / name / workload_lib.ENABLED_MARKER_NAME).touch()

    def _collect(self, name="app"):
        return cmd_diagnose.collect_diagnose_checks(
            WorkloadConfig(name), self.manager)

    def _entry(self, checks, check_name):
        for c in checks:
            if c["check"] == check_name:
                return c
        return None

    def test_disabled_workload_completes_instead_of_raising(self):
        """The live failure: PodmanError escaped Check 6 and took the run with
        it. Checks 8 and 9 are the ones that name the actual state, and they
        come after — so the crash suppressed the answer."""
        checks, _ = self._collect()
        names = {c["check"] for c in checks}
        # ca_trust_anchors is Check 7f — it only exists in this list if the run
        # got past the Check 6 read that used to raise. The service checks that
        # name the actual state run later still; for a disabled workload they
        # arrive folded (see test_diagnose_disabled_fold).
        self.assertIn("ca_trust_anchors", names)
        self.assertIn("workload_disabled", names)

    def test_the_unanswerable_checks_are_omitted_not_passed(self):
        checks, _ = self._collect()
        names = {c["check"] for c in checks}
        self.assertNotIn("image_available", names)
        self.assertNotIn("container_running", names)

    def test_the_gap_is_announced_through_the_disabled_fold(self):
        """A skipped check that says nothing is indistinguishable from one that
        passed, which is how "I did not look" becomes "I looked and it was
        fine". For a disabled workload the announcement arrives folded — this
        pins that the fold carries it rather than swallowing it."""
        checks, _ = self._collect()
        entry = self._entry(checks, "workload_disabled")
        self.assertIsNotNone(entry)
        self.assertIn("podman_session", entry["message"])

    def test_a_disabled_workload_is_not_failed_for_it(self):
        """An unreachable podman is the expected consequence of being off. A
        failure here would be a finding the operator cannot act on without
        starting a workload they deliberately stopped."""
        checks, _ = self._collect()
        self.assertEqual(
            [c["check"] for c in checks if not c["passed"] and "podman" in c["check"]],
            [])

    def test_announced_once_however_many_reads_fail(self):
        """Two podman-backed checks fail per run; one line, not one per read.
        Asserted on the enabled path, where the entry survives unfolded."""
        self._enable("app")
        checks, _ = self._collect()
        self.assertEqual(
            [c["check"] for c in checks].count("podman_session"), 1)

    def test_an_enabled_workload_is_failed_for_it(self):
        """Same exception, opposite verdict: linger is supposed to be on, so
        podman not answering is a real fault rather than a consequence."""
        self._enable("app")
        checks, passed = self._collect()
        entry = self._entry(checks, "podman_session")
        self.assertFalse(entry["passed"])
        self.assertFalse(passed)
        self.assertIn("fix", entry)

    def test_the_failure_names_the_reason_not_the_command(self):
        """str(PodmanError) carries the whole argv; the operator needs the last
        line of stderr, which is the part that says what went wrong."""
        self._enable("app")
        checks, _ = self._collect()
        message = self._entry(checks, "podman_session")["message"]
        self.assertIn("/run/user/10003", message)
        self.assertNotIn("--type=image", message)

    def test_the_multi_container_shape_survives_too(self):
        """Both podman call sites are per-container in pod/bridge mode, so the
        loop must skip rather than abort — and still announce once, not twice
        per container. Enabled, so the announcement is not folded away."""
        self._enable("pod")
        checks, _ = self._collect("pod")
        names = [c["check"] for c in checks]
        self.assertEqual(names.count("podman_session"), 1)
        self.assertNotIn("image_available[api]", names)
        self.assertNotIn("container_running[db]", names)
        self.assertIn("service_active", names)


class PodmanAvailableTests(unittest.TestCase):
    """The guard must be invisible when podman answers."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        (self.tmp / "app").mkdir()
        (self.tmp / "app" / "workload.toml").write_text(SINGLE_TOML)
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.manager.get_image_id.return_value = "sha256:0123456789ab"
        self.manager.podman.return_value.container_status.return_value = "Up 3 minutes"
        self.enterContext(mock.patch.object(
            WorkloadConfig, "uid", new_callable=mock.PropertyMock,
            return_value=10099))
        self.enterContext(mock.patch.object(
            cmd_diagnose.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="")))
        self.enterContext(mock.patch.object(
            cmd_diagnose, "service_active", return_value=(False, "inactive")))

    def test_both_checks_still_report_and_nothing_is_announced(self):
        checks, _ = cmd_diagnose.collect_diagnose_checks(
            WorkloadConfig("app"), self.manager)
        by_name = {c["check"]: c for c in checks}
        self.assertTrue(by_name["image_available"]["passed"])
        self.assertTrue(by_name["container_running"]["passed"])
        self.assertNotIn("podman_session", by_name)


if __name__ == "__main__":
    unittest.main()
