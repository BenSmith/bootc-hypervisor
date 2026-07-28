#!/usr/bin/env python3
"""Unit tests for the NVIDIA-device-access SELinux check in cmd_diagnose.

The image grants no device access host-wide (see the SELinux block in
hypervisor.Containerfile): dri_device_t and hsa_device_t are covered without
a boolean, but /dev/nvidia* is xserver_misc_device_t and is not. This check
tells an operator which of the three paths to it — the scoped boolean, the
workload's own policy.cil, or the legacy blanket container_use_devices — is
actually in play, and fails only when none is.

Pinned here:
- _gpu_vendors reads both TOML shapes and ignores "none"/absent.
- _getsebool returns None (not False) for every can't-tell case, so an
  unknown state never reads as "denied".
- The four gpu_selinux_check outcomes, including that a host still carrying
  the blanket boolean PASSES with the migration in its message — image-side
  SELinux changes don't reach existing hosts on `bootc upgrade`, so that
  state is expected, not a fault.
"""

import subprocess
import tomllib
import unittest
from types import SimpleNamespace
from unittest import mock

import cmd_diagnose

from tests import REPO_ROOT


def _config(raw):
    return SimpleNamespace(config=raw, name="app")


class GpuVendorsTest(unittest.TestCase):
    def test_absent_devices_section_means_no_gpu(self):
        self.assertEqual(_vendors({"container": {"image": "x"}}), set())

    def test_explicit_none_means_no_gpu(self):
        self.assertEqual(_vendors({"devices": {"gpu": "none"}}), set())

    def test_single_mode_reads_top_level_devices(self):
        self.assertEqual(_vendors({"devices": {"gpu": "nvidia"}}), {"nvidia"})

    def test_vendor_spec_is_split_on_the_colon(self):
        """`gpu = "nvidia:GPU-<uuid>"` pins one card; the vendor is the half
        that decides which device type the policy has to allow."""
        self.assertEqual(
            _vendors({"devices": {"gpu": "nvidia:GPU-abc123"}}), {"nvidia"})

    def test_multi_container_shapes_are_unioned(self):
        raw = {"containers": [
            {"name": "a", "devices": {"gpu": "amd"}},
            {"name": "b", "devices": {"gpu": "nvidia"}},
            {"name": "c"},
        ]}
        self.assertEqual(_vendors(raw), {"amd", "nvidia"})

    def test_null_containers_key_does_not_explode(self):
        self.assertEqual(_vendors({"containers": None}), set())


def _vendors(raw):
    return cmd_diagnose._gpu_vendors(_config(raw))


class GetseboolTest(unittest.TestCase):
    def test_missing_binary_is_unknown_not_off(self):
        with mock.patch.object(cmd_diagnose.shutil, "which", lambda _: None):
            self.assertIsNone(cmd_diagnose._getsebool("container_use_devices"))

    def test_nonzero_exit_is_unknown_not_off(self):
        """An undefined boolean (older policy) exits nonzero. Reporting that
        as "off" would send the operator chasing a denial that isn't there."""
        self._patch(returncode=1, stdout="")
        self.assertIsNone(cmd_diagnose._getsebool("nonesuch"))

    def test_on_and_off_are_parsed(self):
        self._patch(returncode=0, stdout="container_use_devices --> on\n")
        self.assertTrue(cmd_diagnose._getsebool("container_use_devices"))
        self._patch(returncode=0, stdout="container_use_devices --> off\n")
        self.assertFalse(cmd_diagnose._getsebool("container_use_devices"))

    def _patch(self, returncode, stdout):
        self.enterContext(
            mock.patch.object(cmd_diagnose.shutil, "which", lambda _: "/usr/sbin/getsebool"))
        self.enterContext(mock.patch.object(
            cmd_diagnose.subprocess, "run",
            lambda *a, **k: subprocess.CompletedProcess(
                a[0], returncode, stdout=stdout, stderr="")))


class GpuSelinuxCheckTest(unittest.TestCase):
    def test_scoped_boolean_passes_clean(self):
        passed, message, fix = cmd_diagnose.gpu_selinux_check(
            xserver=True, blanket=False, module=None)
        self.assertTrue(passed)
        self.assertIn("container_use_xserver_devices on", message)
        self.assertIsNone(fix)

    def test_blanket_boolean_passes_but_advises_narrowing(self):
        passed, message, fix = cmd_diagnose.gpu_selinux_check(
            xserver=False, blanket=True, module=None)
        self.assertTrue(passed, "a working legacy host must not read as a fault")
        self.assertIn("container_use_devices off", message)
        self.assertIsNone(fix)

    def test_scoped_boolean_wins_over_blanket(self):
        _, message, _ = cmd_diagnose.gpu_selinux_check(
            xserver=True, blanket=True, module=None)
        self.assertNotIn("legacy", message)

    def test_own_policy_module_is_named_as_the_grant_path(self):
        passed, message, fix = cmd_diagnose.gpu_selinux_check(
            xserver=False, blanket=False, module="wl_app")
        self.assertTrue(passed)
        self.assertIn("wl_app", message)
        self.assertIsNone(fix)

    def test_no_path_at_all_fails_with_a_fix(self):
        passed, message, fix = cmd_diagnose.gpu_selinux_check(
            xserver=False, blanket=False, module=None)
        self.assertFalse(passed)
        self.assertIn("xserver_misc_device_t", message)
        self.assertEqual(fix, "sudo setsebool -P container_use_xserver_devices on")

    def test_unknown_state_passes_rather_than_guessing(self):
        passed, _, fix = cmd_diagnose.gpu_selinux_check(
            xserver=None, blanket=None, module=None)
        self.assertTrue(passed)
        self.assertIsNone(fix)



class ShippedBundleGrantsTest(unittest.TestCase):
    """Every bundle that has its own SELinux type AND asks for a GPU must
    grant xserver_misc_device_t itself.

    The NVIDIA images set container_use_xserver_devices, but the stock
    boolean is written against container_t, not the container_domain
    attribute a udica-derived wl_<name>.process belongs to — so a workload
    with its own policy.cil does not inherit it and must say so. The base
    image grants no device access host-wide, so a bundle that satisfies the
    predicate and omits the rule gets permission denied from the CUDA
    runtime on an NVIDIA host.

    This is a needs-based check on purpose. The first pass at this scoped
    the grant by grepping for bundles that already mentioned the type, which
    silently skipped vncdesktop-labwc and wolf-game-streaming — both of
    which have a policy.cil and a GPU, and neither of which mentioned it.
    """

    BUNDLES = REPO_ROOT / "workloads"

    def test_gpu_bundles_with_own_policy_grant_nvidia_nodes(self):
        missing = []
        checked = []
        for toml_path in sorted(self.BUNDLES.glob("*/workload.toml")):
            policy = toml_path.parent / "policy.cil"
            if not policy.is_file():
                continue  # runs as container_t; the boolean covers it
            with open(toml_path, "rb") as fh:
                config = tomllib.load(fh)
            if not cmd_diagnose._gpu_vendors(
                    SimpleNamespace(config=config, name="x")):
                continue
            checked.append(toml_path.parent.name)
            if "xserver_misc_device_t" not in policy.read_text():
                missing.append(toml_path.parent.name)

        self.assertTrue(checked, "found no GPU bundles with their own policy")
        self.assertEqual(
            missing, [],
            f"these bundles declare a GPU and ship a policy.cil but never grant "
            f"xserver_misc_device_t, so /dev/nvidia* is denied once the blanket "
            f"container_use_devices boolean is off: {missing}")

    def test_the_grant_is_not_the_narrow_setattr_only_form(self):
        """`setattr` alone was enough while container_use_devices supplied the
        rest; it is not enough on its own."""
        for toml_path in sorted(self.BUNDLES.glob("*/workload.toml")):
            policy = toml_path.parent / "policy.cil"
            if not policy.is_file():
                continue
            text = policy.read_text()
            if "xserver_misc_device_t" not in text:
                continue
            with self.subTest(bundle=toml_path.parent.name):
                for perm in ("open", "read", "write", "ioctl"):
                    self.assertRegex(
                        text,
                        r"xserver_misc_device_t\s*\n?\s*\(chr_file \([^)]*"
                        + perm,
                        f"{toml_path.parent.name} grants xserver_misc_device_t "
                        f"without '{perm}'")

if __name__ == "__main__":
    unittest.main()
