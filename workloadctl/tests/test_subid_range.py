#!/usr/bin/env python3
"""Unit tests for the subordinate-id range derivation and its diagnose checks.

A workload user's subordinate range is *derived* from its UID
(SUBID_BASE + (uid - UID_MIN) * SUBID_COUNT) rather than recorded anywhere, so
recovering a UID recovers the range. Nothing corrected an entry that had
drifted off that formula, though: `configure_subuid_subgid` grandfathers any
existing entry — deliberately, since shifting a mapping under a running
container corrupts its namespace — which makes drift permanent *and* silent.
Three of six workload users on a lab host sat on pre-derivation ranges for
months, two of them inside the window Fedora's `useradd` allocates from, one
`useradd` away from sharing 55,360 subordinate ids between a human user and a
workload container.

Pinned here:
- The derivation itself, and that `workload-ensure-user` no longer carries a
  second copy of it (the drift being undetectable is what made one copy
  mandatory).
- login_defs_subid_window returns None — never a guessed default — for every
  can't-tell case, so "clear of the window" is never claimed on a guess.
- Both check verdicts, including the boundary case that must NOT fire: the
  first workload UID's derived range starts exactly at Fedora's SUB_UID_MAX.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import cmd_diagnose
import workload_lib
from workload_lib import (
    SUBID_BASE,
    SUBID_COUNT,
    UID_MIN,
    derived_subid_range,
    login_defs_subid_window,
)

from tests import REPO_ROOT

SUBUID = "/etc/subuid"
SUBGID = "/etc/subgid"

# Fedora's shipped values; the base was chosen to sit at SUB_UID_MAX.
FEDORA_WINDOW = (524288, 600100000)


class DerivationTests(unittest.TestCase):
    def test_first_workload_uid_starts_at_the_base(self):
        self.assertEqual(derived_subid_range(UID_MIN), (SUBID_BASE, SUBID_COUNT))

    def test_ranges_are_contiguous_and_non_overlapping(self):
        a = derived_subid_range(UID_MIN)
        b = derived_subid_range(UID_MIN + 1)
        self.assertEqual(b[0], a[0] + a[1])

    def test_every_workload_uid_clears_useradds_window(self):
        """The property SUBID_BASE exists for, across the whole UID range."""
        for uid in (UID_MIN, UID_MIN + 1, 10005, workload_lib.UID_MAX):
            self.assertGreaterEqual(derived_subid_range(uid)[0], FEDORA_WINDOW[1])

    def test_uid_below_the_workload_range_is_rejected(self):
        with self.assertRaises(ValueError):
            derived_subid_range(UID_MIN - 1)

    def test_uid_whose_range_would_overflow_uint32_is_rejected(self):
        with self.assertRaises(ValueError):
            derived_subid_range(workload_lib.UID_MAX + 100000)

    def test_ensure_user_does_not_carry_a_second_copy_of_the_formula(self):
        """The writer and the checks must assert against one formula.

        Two copies is how the drift stayed invisible: the writer grandfathers,
        so only an independent comparison can catch a range that is off — and
        it can only catch it if it is comparing against the same rule.
        """
        source = (REPO_ROOT / "libexec" / "workload-ensure-user").read_text()
        self.assertIn("derived_subid_range", source)
        self.assertNotIn(str(SUBID_BASE), source)


class LoginDefsWindowTests(unittest.TestCase):
    def _write(self, text):
        d = Path(self.enterContext(TemporaryDirectory()))
        path = d / "login.defs"
        path.write_text(text)
        return path

    def test_reads_both_keys(self):
        path = self._write(
            "# comment\nSUB_UID_MIN 524288\nUID_MAX 60000\nSUB_UID_MAX 600100000\n")
        self.assertEqual(login_defs_subid_window(path), FEDORA_WINDOW)

    def test_missing_file_is_none_not_a_default(self):
        self.assertIsNone(login_defs_subid_window("/nonexistent/login.defs"))

    def test_one_key_absent_is_none(self):
        path = self._write("SUB_UID_MIN 524288\n")
        self.assertIsNone(login_defs_subid_window(path))

    def test_unparseable_value_is_none(self):
        path = self._write("SUB_UID_MIN abc\nSUB_UID_MAX 600100000\n")
        self.assertIsNone(login_defs_subid_window(path))

    def test_commented_out_key_does_not_count(self):
        path = self._write("#SUB_UID_MIN 524288\nSUB_UID_MAX 600100000\n")
        self.assertIsNone(login_defs_subid_window(path))


class DerivedCheckTests(unittest.TestCase):
    def setUp(self):
        self.expected = derived_subid_range(10005)

    def test_both_files_on_the_derived_range_passes(self):
        entries = [(SUBUID, self.expected), (SUBGID, self.expected)]
        passed, message, fix = cmd_diagnose.subid_derived_check(
            entries, self.expected, 10005)
        self.assertTrue(passed)
        self.assertIn(str(self.expected[0]), message)
        self.assertIsNone(fix)

    def test_drifted_range_fails_and_names_the_file(self):
        entries = [(SUBUID, (200000, 65536)), (SUBGID, self.expected)]
        passed, message, fix = cmd_diagnose.subid_derived_check(
            entries, self.expected, 10005)
        self.assertFalse(passed)
        self.assertIn(SUBUID, message)
        self.assertIn("200000", message)
        self.assertNotIn(SUBGID, message)
        self.assertIn("state/", fix)

    def test_fix_scopes_the_chown_to_state_not_data(self):
        """The remap is only safe because state/ is the reconstructible half.

        Every file in data/ is owned by the workload UID itself, not out of the
        subordinate range, so a remap scoped to state/ leaves durable data
        untouched by construction. A fix that said "chown the workload root"
        would be a data-destroying instruction.
        """
        _, _, fix = cmd_diagnose.subid_derived_check(
            [(SUBUID, (200000, 65536))], self.expected, 10005)
        self.assertIn("state/", fix)
        self.assertIn("data/", fix)
        self.assertIn("workload stopped", fix)

    def test_wrong_count_on_the_right_start_still_fails(self):
        entries = [(SUBUID, (self.expected[0], 1000))]
        passed, _, _ = cmd_diagnose.subid_derived_check(
            entries, self.expected, 10005)
        self.assertFalse(passed)

    def test_absent_entry_is_not_this_checks_business(self):
        """A missing entry is subid_configured's failure, not a drift."""
        passed, _, _ = cmd_diagnose.subid_derived_check(
            [(SUBUID, None), (SUBGID, None)], self.expected, 10005)
        self.assertTrue(passed)


class OverlapCheckTests(unittest.TestCase):
    def test_derived_range_is_clear_of_the_window(self):
        entries = [(SUBUID, derived_subid_range(10005))]
        passed, message, fix = cmd_diagnose.subid_overlap_check(
            entries, FEDORA_WINDOW)
        self.assertTrue(passed)
        self.assertIsNone(fix)

    def test_first_workload_uid_at_the_boundary_does_not_fire(self):
        """SUBID_BASE == Fedora's SUB_UID_MAX, so UID_MIN's range starts
        exactly at the window's inclusive upper bound. `useradd` would have to
        allocate ~1.1M ranges to reach that single id; flagging every host's
        first workload for it would be noise, not a finding."""
        entries = [(SUBUID, derived_subid_range(UID_MIN))]
        passed, _, _ = cmd_diagnose.subid_overlap_check(entries, FEDORA_WINDOW)
        self.assertTrue(passed)

    def test_range_inside_the_window_fails(self):
        """The measured hazard: 600000 sits inside 524288-600100000, and a
        real user holding 524288-589823 puts the next useradd at 589824 —
        55,360 ids shared with the workload."""
        entries = [(SUBUID, (600000, 65536))]
        passed, message, fix = cmd_diagnose.subid_overlap_check(
            entries, FEDORA_WINDOW)
        self.assertFalse(passed)
        self.assertIn("600000", message)
        self.assertIn("user namespace", message)
        self.assertIsNotNone(fix)

    def test_range_far_below_the_window_still_fails(self):
        """200000 is below SUB_UID_MIN, so no useradd would pick it *today* —
        but SUB_UID_MIN is host-editable and the range is still off-formula,
        so the honest verdict is 'inside the territory useradd governs'."""
        entries = [(SUBUID, (200000, 65536))]
        passed, _, _ = cmd_diagnose.subid_overlap_check(entries, FEDORA_WINDOW)
        self.assertFalse(passed)

    def test_reports_every_offending_file(self):
        entries = [(SUBUID, (200000, 65536)), (SUBGID, (700000, 65536))]
        passed, message, _ = cmd_diagnose.subid_overlap_check(
            entries, FEDORA_WINDOW)
        self.assertFalse(passed)
        self.assertIn(SUBUID, message)
        self.assertIn(SUBGID, message)


if __name__ == "__main__":
    unittest.main()
