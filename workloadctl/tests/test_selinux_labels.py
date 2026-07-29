#!/usr/bin/env python3
"""Unit tests for the workload-tree SELinux labeling check in cmd_diagnose.

`workload-ensure-user` registers the fcontext rule for /var/lib/workloads and
then restorecons the tree. The registration is best-effort and the semanage
read lock is contended when several workloads enable at once or at boot, so it
can log one WARNING and return — after which restorecon applies the default
type and the container is denied writes to its own home, with the warning long
gone from the journal. That is Q6 Gap 3, and this check is the "surfaces it
later" half of closing it.

Pinned here:
- The three can't-tell inputs stay unknown rather than reading as broken.
- A wrong label fails, and says whether a relabel would even help.
- A correct label with no registered rule still fails — it is one relabel away
  from the denial, which is exactly the state a contended enable leaves behind.
"""

import subprocess
import unittest
from unittest import mock

import cmd_diagnose


class SelinuxLabelCheckTest(unittest.TestCase):
    def test_unknown_everything_passes_rather_than_guessing(self):
        passed, message, fix = cmd_diagnose.selinux_label_check(
            rule_present=None, label=None, name="app")
        self.assertTrue(passed)
        self.assertIn("unknown", message)
        self.assertIsNone(fix)

    def test_correct_label_and_registered_rule_passes_clean(self):
        passed, message, fix = cmd_diagnose.selinux_label_check(
            rule_present=True, label="container_file_t", name="app")
        self.assertTrue(passed)
        self.assertIsNone(fix)

    def test_wrong_label_fails_and_names_the_type_found(self):
        """var_lib_t is what a restorecon with no rule actually applies, so the
        message has to name it — that string is the operator's only link from
        the denial back to the skipped registration."""
        passed, message, fix = cmd_diagnose.selinux_label_check(
            rule_present=True, label="var_lib_t", name="app")
        self.assertFalse(passed)
        self.assertIn("var_lib_t", message)
        self.assertIn("workload-ensure-user app", fix)

    def test_wrong_label_with_no_rule_says_a_relabel_will_not_help(self):
        _, with_rule, _ = cmd_diagnose.selinux_label_check(
            rule_present=True, label="var_lib_t", name="app")
        _, without_rule, _ = cmd_diagnose.selinux_label_check(
            rule_present=False, label="var_lib_t", name="app")
        self.assertNotIn("relabel", with_rule)
        self.assertIn("relabel will not fix it", without_rule)

    def test_correct_label_but_unregistered_rule_still_fails(self):
        """The latent case, and the one the whole check exists for: it works
        today and breaks at the next relabel."""
        passed, message, fix = cmd_diagnose.selinux_label_check(
            rule_present=False, label="container_file_t", name="app")
        self.assertFalse(passed)
        self.assertIn("relabel", message)
        self.assertIn("semanage fcontext -a -t container_file_t", fix)
        self.assertIn("restorecon", fix)

    def test_unknown_rule_state_does_not_fail_a_correctly_labeled_tree(self):
        """semanage unreadable (including: the lock is contended right now)
        must not be reported as "no rule registered"."""
        passed, _, fix = cmd_diagnose.selinux_label_check(
            rule_present=None, label="container_file_t", name="app")
        self.assertTrue(passed)
        self.assertIsNone(fix)

    def test_wrong_label_fails_even_when_the_rule_state_is_unknown(self):
        passed, _, _ = cmd_diagnose.selinux_label_check(
            rule_present=None, label="var_lib_t", name="app")
        self.assertFalse(passed)


class SelinuxTypeTest(unittest.TestCase):
    def test_type_field_is_extracted_from_the_context(self):
        self._patch_xattr(b"system_u:object_r:container_file_t:s0\x00")
        self.assertEqual(cmd_diagnose._selinux_type("/x"), "container_file_t")

    def test_missing_xattr_is_unknown(self):
        """No label at all — SELinux disabled, or a filesystem that can't
        carry one. Must not read as "wrong label"."""
        def _raise(*a, **k):
            raise OSError(61, "No data available")
        self.enterContext(mock.patch.object(cmd_diagnose.os, "getxattr", _raise))
        self.assertIsNone(cmd_diagnose._selinux_type("/x"))

    def test_malformed_context_is_unknown_not_a_crash(self):
        self._patch_xattr(b"garbage\x00")
        self.assertIsNone(cmd_diagnose._selinux_type("/x"))

    def _patch_xattr(self, value):
        self.enterContext(mock.patch.object(
            cmd_diagnose.os, "getxattr", lambda *a, **k: value))


class FcontextRulePresentTest(unittest.TestCase):
    def test_missing_semanage_is_unknown_not_missing(self):
        with mock.patch.object(cmd_diagnose.shutil, "which", lambda _: None):
            self.assertIsNone(cmd_diagnose._fcontext_rule_present())

    def test_nonzero_exit_is_unknown_not_missing(self):
        """`semanage fcontext -l` exits nonzero when the read lock is
        contended — the very condition whose aftermath this detects. Calling
        that "no rule" would invent a failure on a healthy host."""
        self._patch(1, "")
        self.assertIsNone(cmd_diagnose._fcontext_rule_present())

    def test_rule_is_found_in_the_listing(self):
        self._patch(0, "/var/lib/workloads(/.*)?    all files    "
                       "system_u:object_r:container_file_t:s0\n")
        self.assertTrue(cmd_diagnose._fcontext_rule_present())

    def test_listing_without_the_rule_is_false(self):
        self._patch(0, "/var/lib/containers(/.*)?    all files    "
                       "system_u:object_r:container_var_lib_t:s0\n")
        self.assertFalse(cmd_diagnose._fcontext_rule_present())

    def _patch(self, returncode, stdout):
        self.enterContext(mock.patch.object(
            cmd_diagnose.shutil, "which", lambda _: "/usr/sbin/semanage"))
        self.enterContext(mock.patch.object(
            cmd_diagnose.subprocess, "run",
            lambda *a, **k: subprocess.CompletedProcess(
                a[0], returncode, stdout=stdout, stderr="")))


if __name__ == "__main__":
    unittest.main()
