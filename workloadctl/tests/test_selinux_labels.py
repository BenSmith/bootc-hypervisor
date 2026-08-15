#!/usr/bin/env python3
"""Unit tests for the workload-tree SELinux labeling check in cmd_diagnose.

A workload tree has to carry the label its substrate needs, and the fcontext
rule that keeps it across relabels has to be registered. The two fail
independently, and both fail quietly — the symptom is a permission denial much
later, with nothing at the point of failure connecting the two.

**The expected type differs by substrate.** Containers need container_file_t,
which rootless podman requires. VMs need svirt_image_t, because `virt_domain`
has no read, write, getattr or append on container_file_t — a confined QEMU
cannot use a disk image labelled with it. This check hardcoded
container_file_t until VM support needed otherwise, which would have reported
every correctly-labelled VM workload as broken.

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
        # The fix registers the rule and relabels. It deliberately no longer
        # points at workload-ensure-user: that script stopped registering the
        # blanket fcontext rule when the registration moved to the RPM's %post,
        # so running it would restorecon against a policy with no rule for this
        # path and re-apply the very default label being complained about.
        self.assertIn("semanage fcontext -a -t container_file_t", fix)
        self.assertIn("restorecon -RF", fix)

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


class SelinuxLabelCheckVmTest(unittest.TestCase):
    """The VM half: svirt_image_t, scoped to the workload's own subtree."""

    def test_vm_expects_svirt_image_t(self):
        passed, message, fix = cmd_diagnose.selinux_label_check(
            rule_present=True, label="svirt_image_t", name="vm1", is_vm=True)
        self.assertTrue(passed)
        self.assertIn("svirt_image_t", message)
        self.assertIsNone(fix)

    def test_container_file_t_on_a_vm_is_a_failure(self):
        # The exact state the blanket rule leaves a VM tree in, and the one
        # this distinction exists to catch: it looks correct by the container
        # rule and denies a confined QEMU its own disks.
        passed, message, fix = cmd_diagnose.selinux_label_check(
            rule_present=True, label="container_file_t", name="vm1", is_vm=True)
        self.assertFalse(passed)
        self.assertIn("container_file_t", message)
        self.assertIn("svirt_image_t", message)
        self.assertIn("QEMU", message)

    def test_svirt_image_t_on_a_container_is_a_failure(self):
        # The mirror image, so neither type is silently accepted for both.
        passed, message, _ = cmd_diagnose.selinux_label_check(
            rule_present=True, label="svirt_image_t", name="app", is_vm=False)
        self.assertFalse(passed)
        self.assertIn("container_file_t", message)

    def test_vm_fix_names_the_workload_subtree_not_the_base(self):
        # The VM rule is per workload and wins its subtree by specificity; a
        # fix naming /var/lib/workloads would relabel every sibling container
        # workload to svirt_image_t and break all of them.
        _, _, fix = cmd_diagnose.selinux_label_check(
            rule_present=False, label="svirt_image_t", name="vm1", is_vm=True)
        self.assertIn("/var/lib/workloads/vm1(/.*)?", fix)
        self.assertIn("svirt_image_t", fix)

    def test_every_fix_uses_dash_f(self):
        # Both types are customizable, so a plain `restorecon -R` skips them
        # and exits 0 — a remediation that appears to work and changes nothing.
        for is_vm, wrong in ((True, "container_file_t"), (False, "var_lib_t")):
            _, _, fix = cmd_diagnose.selinux_label_check(
                rule_present=True, label=wrong, name="w", is_vm=is_vm)
            self.assertIn("restorecon -RF", fix)


class VmSocketDirSelinuxCheckTest(unittest.TestCase):
    """The runtime half: /run/workload-vm, where QEMU puts its QMP socket.

    Written from a real outage. A host rebuild left this rule unregistered, so
    the directory came up var_run_t on a tmpfs that recreates it every boot,
    and confined QEMU died creating its first socket. Every VM workload on the
    host failed with `QMP socket not ready after 60s` — a message that names a
    socket, a timeout and nothing else, while diagnose reported 11/12 healthy.
    """

    def test_correct_label_and_registered_rule_passes_clean(self):
        passed, _, fix = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=True, label="qemu_var_run_t")
        self.assertTrue(passed)
        self.assertIsNone(fix)

    def test_the_alias_spelling_is_accepted_too(self):
        """The rule is written svirt_var_run_t and the kernel stores
        qemu_var_run_t. A check that knew only the spelling from the spec would
        report every correctly-labelled host as broken."""
        passed, _, _ = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=True, label="svirt_var_run_t")
        self.assertTrue(passed)

    def test_var_run_t_is_the_failure_and_the_message_names_qmp(self):
        """var_run_t is precisely what /run hands down when no rule matches,
        so it is the label an operator will actually be looking at — and the
        message has to reach the words they searched for."""
        passed, message, fix = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=True, label="var_run_t")
        self.assertFalse(passed)
        self.assertIn("var_run_t", message)
        self.assertIn("QMP", message)
        self.assertIn("restorecon", fix)

    def test_the_message_names_virtiofsd_as_well_as_qemu(self):
        """Reproduced on a real host both ways: QEMU times out on the QMP
        socket, but virtiofsd is denied its pid file first, so a VM with
        volumes fails one layer earlier with a plain "Permission denied" and
        never reaches QEMU. A message naming only QEMU does not match what
        that operator is looking at."""
        _, message, _ = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=True, label="var_run_t")
        self.assertIn("virtiofsd", message)
        self.assertIn("QEMU", message)

    def test_wrong_label_says_a_restart_will_not_clear_it(self):
        """RuntimeDirectoryPreserve=yes keeps the mislabelled directory across
        `systemctl restart`, so the first thing anyone tries cannot work. If
        the message does not say so they will try it repeatedly."""
        _, message, _ = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=True, label="var_run_t")
        self.assertIn("restart", message)

    def test_wrong_label_with_no_rule_says_the_boot_relabel_is_a_no_op(self):
        _, with_rule, _ = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=True, label="var_run_t")
        _, without_rule, _ = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=False, label="var_run_t")
        self.assertNotIn("no-op", with_rule)
        self.assertIn("no-op", without_rule)

    def test_missing_rule_fails_even_with_the_directory_absent(self):
        """The state a fresh rebuild is in: nothing is mislabelled yet because
        nothing exists yet, and the next boot breaks every VM on the host.
        Catching it here is the whole point — after the boot it is an outage.
        """
        passed, message, fix = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=False, label=None)
        self.assertFalse(passed)
        self.assertIn("/run/workload-vm(/.*)?", message)
        self.assertIn("semanage fcontext -a -t svirt_var_run_t", fix)

    def test_missing_rule_fails_even_when_the_label_is_right_today(self):
        """The latent case: someone relabelled by hand, it works now, and the
        next boot recreates the tmpfs directory with nothing to restore from."""
        passed, _, _ = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=True, label="qemu_var_run_t")
        self.assertTrue(passed)
        passed, _, _ = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=False, label="qemu_var_run_t")
        self.assertFalse(passed)

    def test_unknown_everything_passes_rather_than_guessing(self):
        passed, message, fix = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=None, label=None)
        self.assertTrue(passed)
        self.assertIn("unknown", message)
        self.assertIsNone(fix)

    def test_unknown_rule_state_does_not_fail_a_correct_label(self):
        """semanage unreadable, or its read lock contended right now. Must not
        read as "no rule registered"."""
        passed, _, fix = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=None, label="qemu_var_run_t")
        self.assertTrue(passed)
        self.assertIsNone(fix)

    def test_a_stopped_workload_is_not_a_finding(self):
        """No directory (label None) with the rule registered is the ordinary
        state of every stopped VM workload. Reporting it would make diagnose
        cry wolf on a host where nothing is wrong."""
        passed, _, _ = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=True, label=None)
        self.assertTrue(passed)

    def test_the_message_names_the_directory_actually_inspected(self):
        """The parent and one workload's preserved subdirectory can disagree,
        and the fix is useless if it names the one that was already fine."""
        _, message, _ = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=True, label="var_run_t",
            path="/run/workload-vm/git")
        self.assertIn("/run/workload-vm/git", message)

    def test_the_fix_does_not_use_dash_f(self):
        """Unlike the workload tree, neither var_run_t nor qemu_var_run_t is a
        customizable type, so -F buys nothing and would overreach."""
        _, _, fix = cmd_diagnose.vm_socket_dir_selinux_check(
            rule_present=True, label="var_run_t")
        self.assertIn("restorecon -R ", fix)
        self.assertNotIn("-RF", fix)


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
