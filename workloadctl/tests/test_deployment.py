#!/usr/bin/env python3
"""Unit tests for deployment — the /var provenance marker and its cleanup rule.

The property under test is asymmetric, and the tests are ordered by what getting
it wrong would cost:

1. **Nothing here may ever cause a deletion.** Every uncertainty — no /ostree, an
   unreadable or corrupt marker, an unresolvable cmdline, a marker for some other
   workload — must land on the pre-marker behavior, which is "the caller decides".
   A rule that turns a missing file into a licence to rmtree /var is worse than
   the trap it replaces.
2. **The booted deployment is still swept.** The whole mechanism is worthless if
   deleting a TOML on the deployment you are sitting on stops working, and that
   is the easy row to get wrong: the marker names a deployment that still exists.
3. **The skip is explained.** Silence is what made the original failure mode a
   trap; state spared by the rule has to say so in the report.
"""

import io
import json
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

import cmd_cleanup
import deployment
from workloadctl_core import WorkloadManager


# A realistic pair, taken from onepiece 2026-07-29 (booted / rollback target).
BOOTED = "4f46afe780e6d01d4bf9f04a9adbf85ce20d312e3fddf4cc402f0c5afc592a08.0"
ROLLBACK = "f81edd5a40569e6bc3a367f31b5bc22fc52e9ee89a27a8fc7c2e3640fa3a03e8.0"
PRUNED = "cf5005ab" + "0" * 56 + ".0"
# The boot checksum from the same host's cmdline — deliberately NOT either
# deployment id, which is the whole point of trap 1 in the module docstring.
BOOT_CSUM = "8ae70cd906bfbd5b624b4f69c11df2a4a976967b8ba0505d1c9376696efe2959"


class _Host(unittest.TestCase):
    """A fake ostree host: a deploy tree, a cmdline, and the boot symlink."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.deploy_root = self.root / "ostree" / "deploy"
        self.cmdline = self.root / "cmdline"
        self.enterContext(
            mock.patch.object(deployment, "OSTREE_DEPLOY_ROOT", self.deploy_root))
        self.enterContext(
            mock.patch.object(deployment, "PROC_CMDLINE", self.cmdline))
        # Deliberately not under the "workloads" base the cleanup tests below
        # sweep — these cases exercise the helper against one root in isolation.
        self.wl_root = self.root / "solo" / "demo"
        self.wl_root.mkdir(parents=True)

    def make_host(self, *, deployments=(BOOTED, ROLLBACK), booted=BOOTED,
                  stateroot="default"):
        """Materialize the deploy dirs, the cmdline and the boot symlink."""
        deploy = self.deploy_root / stateroot / "deploy"
        deploy.mkdir(parents=True, exist_ok=True)
        for dep in deployments:
            (deploy / dep).mkdir(exist_ok=True)
        if booted is not None:
            boot = self.root / "ostree" / "boot.1" / stateroot / BOOT_CSUM
            boot.mkdir(parents=True, exist_ok=True)
            link = boot / "0"
            if link.is_symlink():
                link.unlink()
            # Relative, exactly as ostree writes it.
            link.symlink_to(
                os.path.relpath(deploy / booted, boot), target_is_directory=True)
            self.cmdline.write_text(
                f"BOOT_IMAGE=(hd2,gpt2)/ostree/default-{BOOT_CSUM}/vmlinuz "
                f"ostree={link} rw\n")
        else:
            self.cmdline.write_text("root=UUID=deadbeef rw\n")

    def stamp(self, deployment_id, *, name="demo", root=None):
        (root or self.wl_root).joinpath(deployment.PROVENANCE_NAME).write_text(
            json.dumps({"name": name, "deployment": deployment_id}))


# --------------------------------------------------------------------------- #
# 1. Reading the booted deployment
# --------------------------------------------------------------------------- #

class TestBootedDeploymentId(_Host):

    def test_resolves_the_deployment_not_the_boot_checksum(self):
        # Trap 1: the csum in the `ostree=` value is the *boot* checksum. Code
        # that parses the cmdline token instead of resolving it looks right and
        # never matches a deployment directory.
        self.make_host()
        self.assertEqual(deployment.booted_deployment_id(), BOOTED)
        self.assertNotEqual(deployment.booted_deployment_id(), BOOT_CSUM)

    def test_no_ostree_token_is_unknown(self):
        self.make_host(booted=None)
        self.assertIsNone(deployment.booted_deployment_id())

    def test_missing_cmdline_is_unknown(self):
        self.assertIsNone(deployment.booted_deployment_id())

    def test_dangling_link_is_unknown(self):
        self.make_host()
        self.cmdline.write_text(f"ostree={self.root}/ostree/boot.1/nope/0 rw\n")
        self.assertIsNone(deployment.booted_deployment_id())

    def test_unrecognized_shape_is_unknown(self):
        # A link resolving to something that isn't <64-hex>.<serial>. Returning
        # the junk would let it be compared against — and never match — which
        # reads as "the deployment is gone", i.e. sweep.
        self.make_host()
        boot = self.root / "ostree" / "boot.1" / "default" / BOOT_CSUM
        (boot / "0").unlink()
        (boot / "0").symlink_to(self.deploy_root)
        self.assertIsNone(deployment.booted_deployment_id())

    def test_alternate_stateroot(self):
        self.make_host(stateroot="fedora", deployments=(BOOTED,))
        self.assertEqual(deployment.booted_deployment_id(), BOOTED)


class TestDeploymentExists(_Host):

    def test_finds_a_deployment_under_any_stateroot(self):
        # Globbing the stateroot, not hardcoding "default": /var may be a
        # separate filesystem shared by every stateroot, so a two-stateroot host
        # must not have its other stateroot's state declared defunct.
        self.make_host(stateroot="other", deployments=(ROLLBACK,))
        self.assertTrue(deployment.deployment_exists(ROLLBACK))

    def test_pruned_deployment_is_gone(self):
        self.make_host()
        self.assertFalse(deployment.deployment_exists(PRUNED))

    def test_malformed_id_is_never_globbed(self):
        # The shape check is also the injection guard: an id is interpolated
        # into a glob pattern, so "*" must not be able to match everything.
        self.make_host()
        for junk in ("", "*", "*.0", "../../etc", BOOT_CSUM, "not-an-id"):
            with self.subTest(junk=junk):
                self.assertFalse(deployment.deployment_exists(junk))

    def test_no_ostree_is_not_readable(self):
        self.assertFalse(deployment.deployments_readable())


# --------------------------------------------------------------------------- #
# 2. The marker itself
# --------------------------------------------------------------------------- #

class TestMarker(_Host):

    def test_write_then_read_round_trip(self):
        self.make_host()
        self.assertTrue(deployment.write_marker(self.wl_root, "demo"))
        self.assertEqual(deployment.read_marker(self.wl_root),
                         {"name": "demo", "deployment": BOOTED})

    def test_rewrite_is_skipped_when_unchanged(self):
        # ensure-user runs on every service start; re-stamping identical content
        # on every boot would dirty /var for nothing.
        self.make_host()
        deployment.write_marker(self.wl_root, "demo")
        self.assertFalse(deployment.write_marker(self.wl_root, "demo"))

    def test_rewritten_when_the_deployment_changes(self):
        # The semantics the cleanup rule needs: "last provisioned under", not
        # "created under". Create-only stamping breaks the ordinary case — a
        # workload carried forward by the /etc merge and then deleted would
        # still name the older deployment, which still exists, and be skipped.
        self.make_host()
        deployment.write_marker(self.wl_root, "demo")
        self.make_host(booted=ROLLBACK)
        self.assertTrue(deployment.write_marker(self.wl_root, "demo"))
        self.assertEqual(
            deployment.read_marker(self.wl_root)["deployment"], ROLLBACK)

    def test_written_off_ostree_with_a_null_deployment(self):
        self.assertTrue(deployment.write_marker(self.wl_root, "demo"))
        self.assertEqual(deployment.read_marker(self.wl_root),
                         {"name": "demo", "deployment": None})

    def test_marker_is_root_owned_and_not_workload_writable(self):
        # It gates deletion of the workload's own state, so the workload user
        # must not be able to rewrite it. The root dir is root-owned; the file
        # is 0644 rather than group/other-writable.
        self.make_host()
        deployment.write_marker(self.wl_root, "demo")
        mode = deployment.marker_path(self.wl_root).stat().st_mode
        self.assertEqual(mode & 0o022, 0)

    def test_corrupt_marker_reads_as_absent(self):
        deployment.marker_path(self.wl_root).write_text("{not json")
        self.assertIsNone(deployment.read_marker(self.wl_root))

    def test_non_object_marker_reads_as_absent(self):
        deployment.marker_path(self.wl_root).write_text('["a list"]')
        self.assertIsNone(deployment.read_marker(self.wl_root))

    def test_absent_marker_reads_as_none(self):
        self.assertIsNone(deployment.read_marker(self.wl_root))


# --------------------------------------------------------------------------- #
# 3. The rule — the five rows of the table in lib/deployment.py
# --------------------------------------------------------------------------- #

class TestOtherDeploymentsState(_Host):

    def test_rollback_state_is_spared(self):
        # The row this whole change exists for: stamped with a deployment that
        # still exists but is not booted.
        self.make_host()
        self.stamp(ROLLBACK)
        self.assertEqual(
            deployment.other_deployments_state(self.wl_root, "demo"), ROLLBACK)

    def test_booted_deployment_is_still_swept(self):
        # Load-bearing. Without this row, deleting a TOML on the deployment you
        # are booted into stops being a sweepable orphan — cleanup would skip
        # the ordinary case it exists for.
        self.make_host()
        self.stamp(BOOTED)
        self.assertIsNone(deployment.other_deployments_state(self.wl_root, "demo"))

    def test_defunct_deployment_is_swept(self):
        self.make_host()
        self.stamp(PRUNED)
        self.assertIsNone(deployment.other_deployments_state(self.wl_root, "demo"))

    def test_absent_marker_is_swept(self):
        # Every workload root predating this change. No migration step: the
        # pre-marker behavior IS the fallback.
        self.make_host()
        self.assertIsNone(deployment.other_deployments_state(self.wl_root, "demo"))

    def test_off_ostree_the_rule_never_applies(self):
        # A plain-RPM host. Even a marker naming a live-looking deployment must
        # not spare state, because nothing here can check whether it exists.
        self.stamp(ROLLBACK)
        self.assertIsNone(deployment.other_deployments_state(self.wl_root, "demo"))

    def test_marker_for_another_workload_is_ignored(self):
        # A copied or renamed tree. Honoring it would let a stray file block a
        # sweep of state it does not describe.
        self.make_host()
        self.stamp(ROLLBACK, name="somethingelse")
        self.assertIsNone(deployment.other_deployments_state(self.wl_root, "demo"))

    def test_null_and_malformed_deployments_are_ignored(self):
        self.make_host()
        for value in (None, 42, ["x"], {"a": 1}, ""):
            with self.subTest(value=value):
                self.stamp(value)
                self.assertIsNone(
                    deployment.other_deployments_state(self.wl_root, "demo"))

    def test_corrupt_marker_does_not_spare_state(self):
        self.make_host()
        deployment.marker_path(self.wl_root).write_text("{")
        self.assertIsNone(deployment.other_deployments_state(self.wl_root, "demo"))

    def test_a_redeployed_pruned_commit_revives_its_marker(self):
        """Confirmed against ostree's allocator, not assumed.

        `allocate_deployserial` (ostree-sysroot-deploy.c) starts at 0 and bumps
        only past serials of deploy dirs that *currently exist* for that csum —
        it consults the directory listing, never any history. So pruning frees a
        serial, and redeploying the same commit reuses `<csum>.0`, reviving a
        marker that pointed at the pruned deployment.

        The effect is a skip of state that could have been swept, i.e. it errs
        toward never deleting. Pinned so it stays a known, deliberate residual
        rather than being rediscovered as a surprise.
        """
        # PRUNED is stamped while absent from the deploy tree: swept.
        self.make_host()
        self.stamp(PRUNED)
        self.assertIsNone(deployment.other_deployments_state(self.wl_root, "demo"))
        # Redeploy that same commit; ostree hands back the same dir name.
        self.make_host(deployments=(BOOTED, ROLLBACK, PRUNED))
        self.assertEqual(
            deployment.other_deployments_state(self.wl_root, "demo"), PRUNED)

    def test_an_id_from_another_stateroot_also_spares_state(self):
        """Same-direction corollary of the above, from the same allocator: the
        serial scan is per-osname, so two stateroots can hold the same
        `<csum>.<serial>`. `deployment_exists` globs `*/deploy/<id>` across
        stateroots on purpose — /var may be shared between them — so a marker
        written under one stateroot is honored by the other. Errs toward sparing,
        which is the direction this module always chooses when it can't be sure.
        """
        self.make_host(deployments=(BOOTED,))
        self.make_host(deployments=(ROLLBACK,), booted=None, stateroot="other")
        # Re-point the cmdline at the default stateroot's booted deployment.
        self.make_host(deployments=(BOOTED,))
        self.stamp(ROLLBACK)
        self.assertEqual(
            deployment.other_deployments_state(self.wl_root, "demo"), ROLLBACK)


# --------------------------------------------------------------------------- #
# 4. cleanup, which is the only caller that can destroy anything
# --------------------------------------------------------------------------- #

class TestCleanupHonorsTheMarker(_Host):
    """End-to-end through cmd_cleanup: the rule has to reach the sweep itself,
    not just the helper. Both scans (users and dirs) consult it, because a
    rollback can leave either shape behind — the passwd line is per-deployment,
    so after a rollback there is usually only a directory, but a TOML deleted on
    an upgraded deployment leaves a user too."""

    def setUp(self):
        super().setUp()
        self.base = self.root / "workloads"
        self.wl_root = self.base / "rolled-back"
        self.wl_root.mkdir(parents=True)
        self.enterContext(mock.patch.object(cmd_cleanup, "WORKLOADS_BASE", self.base))
        self.enterContext(mock.patch.object(cmd_cleanup, "require_root"))
        # No configs at all: every workload root below is an orphan by the
        # pre-existing definition, so anything spared is spared by the marker.
        self.enterContext(mock.patch.object(cmd_cleanup, "iter_workloads", return_value=[]))

    def _pw(self, name, uid=20001):
        entry = mock.MagicMock()
        entry.pw_name = f"_wl-{name}"
        entry.pw_uid = uid
        entry.pw_dir = str(self.base / name / "state")
        return entry

    def _run(self, *, apply=False, as_json=True, users=()):
        args = SimpleNamespace(apply=apply, json=as_json)
        out = io.StringIO()
        with mock.patch("pwd.getpwall", return_value=list(users)), \
                redirect_stdout(out):
            cmd_cleanup.cmd_cleanup(args, WorkloadManager())
        return json.loads(out.getvalue()) if as_json else out.getvalue()

    def test_rolled_back_dir_is_not_an_orphan(self):
        self.make_host()
        self.stamp(ROLLBACK, name="rolled-back")
        data = self._run()
        self.assertEqual(data["orphan_dirs"], [])
        self.assertEqual(data["skipped_other_deployment"], [{
            "name": "rolled-back",
            "path": str(self.wl_root),
            "deployment": ROLLBACK,
        }])

    def test_dir_stamped_with_the_booted_deployment_is_an_orphan(self):
        self.make_host()
        self.stamp(BOOTED, name="rolled-back")
        data = self._run()
        self.assertEqual(data["orphan_dirs"], [str(self.wl_root)])
        self.assertEqual(data["skipped_other_deployment"], [])

    def test_unstamped_dir_is_an_orphan(self):
        self.make_host()
        data = self._run()
        self.assertEqual(data["orphan_dirs"], [str(self.wl_root)])

    def test_rolled_back_user_is_not_an_orphan(self):
        self.make_host()
        self.stamp(ROLLBACK, name="rolled-back")
        data = self._run(users=[self._pw("rolled-back")])
        self.assertEqual(data["orphan_users"], [])
        self.assertEqual(data["orphan_dirs"], [])

    def test_a_workload_is_reported_once_not_twice(self):
        # Reached from the user scan and the dir scan; the memo keeps the
        # report from naming it twice.
        self.make_host()
        self.stamp(ROLLBACK, name="rolled-back")
        data = self._run(users=[self._pw("rolled-back")])
        self.assertEqual(len(data["skipped_other_deployment"]), 1)

    def test_key_present_even_when_empty(self):
        self.make_host()
        self.assertIn("skipped_other_deployment", self._run())

    def test_apply_does_not_remove_spared_state(self):
        # The one that matters: --apply is the destructive path, and a real
        # orphan alongside makes sure it actually ran rather than bailing out
        # at "nothing to clean up".
        self.make_host()
        self.stamp(ROLLBACK, name="rolled-back")
        real_orphan = self.base / "genuine"
        real_orphan.mkdir()
        data = self._run(apply=True)
        self.assertEqual(data["removed_dirs"], [str(real_orphan)])
        self.assertFalse(real_orphan.exists())
        self.assertTrue(self.wl_root.exists())
        self.assertTrue(deployment.marker_path(self.wl_root).exists())

    def test_skip_is_explained_in_the_text_report(self):
        # Silence is what made this a trap: an operator staring at unexplained
        # _wl-* state after a rollback has to be told why it wasn't touched.
        self.make_host()
        self.stamp(ROLLBACK, name="rolled-back")
        text = self._run(as_json=False)
        self.assertIn("State from another deployment", text)
        self.assertIn(str(self.wl_root), text)
        self.assertIn("rollback", text)

    def test_explained_even_when_there_is_nothing_else_to_report(self):
        # The common shape after a rollback is "everything is spared", which
        # takes the early "Nothing to clean up." return.
        self.make_host()
        self.stamp(ROLLBACK, name="rolled-back")
        text = self._run(as_json=False)
        self.assertIn("Nothing to clean up.", text)
        self.assertIn("State from another deployment", text)


if __name__ == "__main__":
    unittest.main()
