#!/usr/bin/env python3
"""A disabled workload reports being disabled once, not eight times.

`disable` tears down linger, the runtime dir it implies, the per-workload
SELinux module, the generated units and the service state. Each of those has a
check, and each reports absence as a failure — so diagnosing a workload that was
stopped on purpose produced eight findings that were all the same fact, each
carrying a fix (`loginctl enable-linger`, `systemctl daemon-reload`,
`workloadctl enable`) that the operator must NOT follow. Measured on a lab host:
10/18 passed, "Issues found:" listing six consequences of the workload being
off, and above them the two findings that were about persistent state — the ones
worth reading, ranked below the noise.

The fold replaces them with one passing `workload_disabled` check. Passing
because a workload that is off is a state, not a fault.

Pinned here:
- What folds and what does not. On-disk state (subid ranges, labels, home,
  volumes) must stay correct while a workload is off — it is what the next
  enable builds on — so those failures are real findings and survive.
- Only *absences* fold. An entry that passed is residue (linger still on after
  disable, a unit still loaded), which is a genuine anomaly, and it stays
  visible rather than being tidied away by the thing that hides expected gaps.
- The fold names every check it swallowed, so nothing becomes unaccounted for.
- An enabled workload is untouched: the same absences are real failures there.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cmd_diagnose
import workload_lib
from cmd_diagnose import (
    DISABLED_CONSEQUENCE_CHECKS,
    collapse_disabled_consequences,
)
from workloadctl_core import WorkloadConfig

SINGLE_TOML = """\
[workload]
name = "app"

[container]
image = "localhost/app:latest"
"""


def _entry(name, passed, fix=None):
    e = {"check": name, "passed": passed, "message": f"{name} message"}
    if fix:
        e["fix"] = fix
    return e


class CollapseUnitTests(unittest.TestCase):
    """The list surgery on its own, with no battery around it."""

    def test_absences_fold_into_one_passing_check(self):
        checks = [
            _entry("user_exists", True),
            _entry("linger_enabled", False, fix="sudo loginctl enable-linger 10099"),
            _entry("runtime_dir", False),
            _entry("service_active", False),
        ]
        out = collapse_disabled_consequences(checks, "app")
        names = [c["check"] for c in out]
        self.assertEqual(names, ["user_exists", "workload_disabled"])
        self.assertTrue(out[1]["passed"])

    def test_the_fold_names_what_it_swallowed(self):
        """Otherwise it trades eight misleading findings for one opaque line."""
        checks = [_entry("linger_enabled", False), _entry("service_file", False)]
        out = collapse_disabled_consequences(checks, "app")
        self.assertIn("linger_enabled", out[0]["message"])
        self.assertIn("service_file", out[0]["message"])

    def test_the_fold_carries_no_fix(self):
        """The folded fixes are exactly the instructions that must not be
        followed on a workload someone stopped deliberately."""
        checks = [_entry("linger_enabled", False, fix="sudo loginctl enable-linger 10099")]
        out = collapse_disabled_consequences(checks, "app")
        self.assertNotIn("fix", out[0])
        self.assertIn("workloadctl enable app", out[0]["message"])

    def test_residue_does_not_fold(self):
        """Linger still on after disable is not an expected absence — it is
        teardown that did not finish, and the only place it is visible."""
        checks = [_entry("linger_enabled", True), _entry("service_active", False)]
        out = collapse_disabled_consequences(checks, "app")
        names = [c["check"] for c in out]
        self.assertEqual(names, ["linger_enabled", "workload_disabled"])

    def test_findings_about_persistent_state_survive(self):
        """The point of the fold: what is left is what is worth reading. These
        describe state the next enable builds on, so being off excuses none of
        them."""
        survivors = ("subid_derived", "subid_overlap", "selinux_labels",
                     "home_dir", "volume_paths", "mcs_labels", "user_exists")
        checks = [_entry(n, False) for n in survivors]
        checks.append(_entry("service_active", False))
        out = collapse_disabled_consequences(checks, "app")
        self.assertEqual([c["check"] for c in out],
                         list(survivors) + ["workload_disabled"])

    def test_it_lands_where_the_first_folded_check_was(self):
        """Ordering is the reading order of the run; the summary belongs at the
        point the runtime story starts, not appended at the end."""
        checks = [
            _entry("user_exists", True),
            _entry("linger_enabled", False),
            _entry("home_dir", True),
            _entry("service_active", False),
        ]
        out = collapse_disabled_consequences(checks, "app")
        self.assertEqual([c["check"] for c in out],
                         ["user_exists", "workload_disabled", "home_dir"])

    def test_nothing_to_fold_leaves_the_list_alone(self):
        """A disabled workload whose runtime state is somehow all present gets
        no summary — there is no absence to explain, and every one of those
        passes is residue worth seeing."""
        checks = [_entry("user_exists", True), _entry("linger_enabled", True)]
        self.assertEqual(collapse_disabled_consequences(checks, "app"), checks)

    def test_podman_session_folds_on_its_passing_form(self):
        """It inverts the rule: it is the *skip* line, so its pass is the
        absence. Its failing form only exists on the enabled path, where the
        fold never runs."""
        checks = [_entry("podman_session", True)]
        out = collapse_disabled_consequences(checks, "app")
        self.assertEqual([c["check"] for c in out], ["workload_disabled"])


class ConsequenceListTests(unittest.TestCase):
    def test_on_disk_state_is_not_in_the_list(self):
        """A standing guard on the list itself: adding one of these would make
        the fold hide the findings it exists to make visible."""
        for name in ("subid_derived", "subid_overlap", "selinux_labels",
                     "home_dir", "volume_paths", "mcs_labels", "user_exists",
                     "uid_mapping"):
            self.assertNotIn(name, DISABLED_CONSEQUENCE_CHECKS)


class BatteryIntegrationTests(unittest.TestCase):
    """End to end through collect_diagnose_checks, which is where the fold is
    gated on the enable marker."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        (self.tmp / "app").mkdir()
        (self.tmp / "app" / "workload.toml").write_text(SINGLE_TOML)
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.manager.get_image_id.return_value = "sha256:0123456789ab"
        self.manager.podman.return_value.container_status.return_value = ""
        self.enterContext(mock.patch.object(
            WorkloadConfig, "uid", new_callable=mock.PropertyMock,
            return_value=10099))
        # Every systemctl/loginctl probe answers "no": not enabled, not active,
        # no linger. That is the disabled workload's real shape.
        self.enterContext(mock.patch.object(
            cmd_diagnose.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="")))
        self.enterContext(mock.patch.object(
            cmd_diagnose, "service_active", return_value=(False, "inactive")))

    def _collect(self):
        return cmd_diagnose.collect_diagnose_checks(
            WorkloadConfig("app"), self.manager)

    def test_disabled_workload_gets_one_line_for_the_whole_story(self):
        checks, _ = self._collect()
        names = [c["check"] for c in checks]
        self.assertEqual(names.count("workload_disabled"), 1)
        for folded in ("linger_enabled", "runtime_dir", "service_file",
                       "service_enabled", "service_active"):
            self.assertNotIn(folded, names)

    def test_enabled_workload_still_reports_them_individually(self):
        """Same absences, opposite meaning: a workload that is supposed to be
        running and has no linger, no units and no service is broken, and each
        of those is separately actionable."""
        (self.tmp / "app" / workload_lib.ENABLED_MARKER_NAME).touch()
        checks, passed = self._collect()
        names = [c["check"] for c in checks]
        self.assertFalse(passed)
        self.assertNotIn("workload_disabled", names)
        for individual in ("linger_enabled", "service_enabled", "service_active"):
            self.assertIn(individual, names)


if __name__ == "__main__":
    unittest.main()
