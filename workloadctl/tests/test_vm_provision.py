"""Tests for vm_provision — the record of whether a VM's cloud-init finished.

The bug this machinery exists for: a first boot cut short leaves the guest
half-provisioned *and* marked done by its own per-instance semaphores, while the
host reuses the same instance-id forever and every host-side check reads healthy.
So the tests below care most about the two asymmetries in the design — only a
recorded failure heals, and a heal happens at most once per lineage.
"""
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import vm_provision
from vm_provision import (
    MAX_HEAL_ATTEMPTS,
    PROVISION_DONE,
    PROVISION_FAILED,
    PROVISION_UNVERIFIED,
    _parse_guest_probe,
    guest_provision_result,
    heal_attempts,
    marker_reports_failure,
    marker_vouches_for,
    provision_marker_path,
    read_provision_marker,
    record_guest_provision_result,
    should_heal,
    write_provision_marker,
)
from cmd_diagnose import vm_provisioning_check


class TestMarkerPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_round_trip(self):
        write_provision_marker(self.tmp, "vm-abc", PROVISION_DONE)
        marker = read_provision_marker(self.tmp)
        self.assertEqual(marker["instance_id"], "vm-abc")
        self.assertEqual(marker["status"], PROVISION_DONE)
        self.assertEqual(marker["heal_attempts"], 0)

    def test_errors_are_recorded_and_omitted_when_empty(self):
        write_provision_marker(self.tmp, "vm-abc", PROVISION_FAILED,
                               errors=["KeyError: fedora"])
        self.assertEqual(read_provision_marker(self.tmp)["errors"],
                         ["KeyError: fedora"])
        write_provision_marker(self.tmp, "vm-abc", PROVISION_DONE, errors=[])
        self.assertNotIn("errors", read_provision_marker(self.tmp))

    def test_missing_marker_reads_as_none(self):
        # "No record" must be an ordinary state, not an error: a VM provisioned
        # by an older workloadctl has no marker at all.
        self.assertIsNone(read_provision_marker(self.tmp))

    def test_malformed_marker_reads_as_none(self):
        provision_marker_path(self.tmp).write_text("{not json")
        self.assertIsNone(read_provision_marker(self.tmp))

    def test_marker_without_instance_id_reads_as_none(self):
        # An id-less record can't vouch for anything, so it is no record.
        provision_marker_path(self.tmp).write_text('{"status": "done"}')
        self.assertIsNone(read_provision_marker(self.tmp))

    def test_write_leaves_no_temp_file_behind(self):
        write_provision_marker(self.tmp, "vm-abc", PROVISION_DONE)
        self.assertEqual([p.name for p in self.tmp.iterdir()],
                         [vm_provision.PROVISION_MARKER_FILE])

    def test_rewrite_replaces_a_file_owned_by_someone_else(self):
        # The two writers are root (workload-ensure-user, at mint) and the
        # workload user (the VM service's watch). tmp+rename means the second
        # writer needs only the state dir, which it owns — an in-place rewrite
        # of a root-owned file would fail.
        write_provision_marker(self.tmp, "vm-abc", PROVISION_UNVERIFIED)
        provision_marker_path(self.tmp).chmod(0o444)
        write_provision_marker(self.tmp, "vm-abc", PROVISION_DONE)
        self.assertEqual(read_provision_marker(self.tmp)["status"],
                         PROVISION_DONE)


class TestMarkerPredicates(unittest.TestCase):
    @staticmethod
    def _m(instance_id, status, attempts=0):
        return {"instance_id": instance_id, "status": status,
                "heal_attempts": attempts}

    def test_vouches_only_for_a_matching_successful_instance(self):
        self.assertTrue(marker_vouches_for(self._m("a", PROVISION_DONE), "a"))
        self.assertFalse(marker_vouches_for(self._m("a", PROVISION_DONE), "b"))
        self.assertFalse(marker_vouches_for(self._m("a", PROVISION_FAILED), "a"))
        self.assertFalse(marker_vouches_for(None, "a"))
        self.assertFalse(marker_vouches_for(self._m("a", PROVISION_DONE), None))

    def test_reports_failure_only_for_a_matching_instance(self):
        self.assertTrue(marker_reports_failure(self._m("a", PROVISION_FAILED), "a"))
        self.assertFalse(marker_reports_failure(self._m("b", PROVISION_FAILED), "a"))
        self.assertFalse(marker_reports_failure(self._m("a", PROVISION_UNVERIFIED), "a"))

    def test_heal_attempts_reset_across_instances(self):
        self.assertEqual(heal_attempts(self._m("a", PROVISION_FAILED, 1), "a"), 1)
        self.assertEqual(heal_attempts(self._m("a", PROVISION_FAILED, 1), "b"), 0)
        self.assertEqual(heal_attempts(None, "a"), 0)

    def test_heal_attempts_survives_a_corrupt_count(self):
        self.assertEqual(heal_attempts(self._m("a", PROVISION_FAILED, "lots"), "a"), 0)

    def test_should_heal_needs_failure_and_headroom(self):
        self.assertTrue(should_heal(self._m("a", PROVISION_FAILED), "a"))
        self.assertFalse(should_heal(self._m("a", PROVISION_UNVERIFIED), "a"))
        self.assertFalse(should_heal(self._m("a", PROVISION_DONE), "a"))
        self.assertFalse(should_heal(None, "a"))
        self.assertFalse(
            should_heal(self._m("a", PROVISION_FAILED, MAX_HEAL_ATTEMPTS), "a"))


def _probe_output(instance_id: str | None, payload: dict | str) -> str:
    """The two-part stdout the guest probe command produces."""
    body = payload if isinstance(payload, str) else json.dumps(payload)
    return f"{instance_id or ''}\n{body}"


class TestParseGuestProbe(unittest.TestCase):
    """The guest's `cloud-init status --format=json`, as the watch reads it."""

    def test_clean_run_is_done(self):
        status, guest_id, errors = _parse_guest_probe(_probe_output(
            "myvm-deadbeef", {"status": "done", "errors": []}))
        self.assertEqual(status, PROVISION_DONE)
        self.assertEqual(guest_id, "myvm-deadbeef")
        self.assertEqual(errors, [])

    def test_module_error_is_failure(self):
        # The shape the broken guest actually reported.
        status, _, errors = _parse_guest_probe(_probe_output(
            "myvm-deadbeef",
            {"status": "error", "errors": [
                "('ssh_authkey_fingerprints', KeyError(\"getpwnam(): "
                "name not found: 'fedora'\"))"]}))
        self.assertEqual(status, PROVISION_FAILED)
        self.assertIn("fedora", errors[0])

    def test_errors_without_error_status_is_still_failure(self):
        status, _, errors = _parse_guest_probe(_probe_output(
            "myvm-deadbeef", {"status": "done", "errors": ["boom"]}))
        self.assertEqual(status, PROVISION_FAILED)
        self.assertEqual(errors, ["boom"])

    def test_degraded_done_is_done(self):
        # A healthy Fedora Cloud guest reports "degraded done" purely from
        # recoverable_errors (deprecation + schema warnings). Reading those as
        # failure would re-provision every working VM on the fleet, so the check
        # keys on `errors` only. Measured on a live guest.
        status, _, errors = _parse_guest_probe(_probe_output(
            "myvm-deadbeef",
            {"status": "done", "extended_status": "degraded done",
             "errors": [],
             "init": {"recoverable_errors": {
                 "WARNING": ["cloud-config failed schema validation!"],
                 "DEPRECATED": ["Deprecated cloud-config provided: "
                                "chpasswd.list"]}}}))
        self.assertEqual(status, PROVISION_DONE)
        self.assertEqual(errors, [])

    def test_still_running_is_no_answer(self):
        self.assertIsNone(_parse_guest_probe(_probe_output(
            "myvm-deadbeef", {"status": "running", "errors": []})))

    def test_not_run_is_no_answer(self):
        self.assertIsNone(_parse_guest_probe(_probe_output(
            "myvm-deadbeef", {"status": "not run", "errors": []})))

    def test_disabled_is_done(self):
        # Nothing to finish, so the watch must stop rather than poll to its
        # deadline. Records done, which never heals.
        status, _, _ = _parse_guest_probe(_probe_output(
            "myvm-deadbeef", {"status": "disabled", "errors": []}))
        self.assertEqual(status, PROVISION_DONE)

    def test_empty_output_is_no_answer(self):
        # rc=0 with empty stdout is a real guest-SELinux failure shape (a
        # confined tool denied the write to sshd's pipe). It must never read as
        # a clean run.
        self.assertIsNone(_parse_guest_probe(""))
        self.assertIsNone(_parse_guest_probe("myvm-deadbeef\n"))

    def test_garbage_is_no_answer(self):
        self.assertIsNone(_parse_guest_probe(_probe_output(
            "myvm-deadbeef", "ssh: connect to host port 2222: refused")))
        self.assertIsNone(_parse_guest_probe(_probe_output(
            "myvm-deadbeef", "[1, 2, 3]")))

    def test_missing_guest_instance_id_still_reports(self):
        # The id is a cross-check, not a requirement — a guest that doesn't
        # write the file must not cost us the outcome.
        status, guest_id, _ = _parse_guest_probe(_probe_output(
            None, {"status": "done", "errors": []}))
        self.assertEqual(status, PROVISION_DONE)
        self.assertIsNone(guest_id)


class TestGuestProbeArgv(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_pins_the_host_key_and_never_prompts(self):
        argv = vm_provision._vm_ssh_probe_argv(
            "myvm", "workload", "127.128.0.1", 2222, self.tmp, 5, "true")
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn(f"UserKnownHostsFile={self.tmp / '.ssh' / 'vm_known_hosts'}",
                      argv)
        self.assertIn("HostKeyAlias=myvm", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertEqual(argv[-2:], ["--", "true"])
        self.assertIn("workload@127.128.0.1", argv)


class TestGuestProvisionResult(unittest.TestCase):
    """The probe as a whole: which VMs get asked, and what a failure means."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(
            vm_provision, "workload_state_dir", lambda name: self.tmp))
        self.enterContext(mock.patch.object(
            vm_provision, "workload_username", lambda name: "_wl-myvm"))
        self.enterContext(mock.patch.object(
            vm_provision.pwd, "getpwnam",
            lambda user: types.SimpleNamespace(pw_uid=10007)))
        self.toml = self.tmp / "workload.toml"
        self.enterContext(mock.patch.object(
            vm_provision, "workload_config_path", lambda name: self.toml))
        self.toml.write_text('[vm]\nuser = "workload"\n')

    def _run(self, stdout="", raises=None):
        def fake_run(argv, **kwargs):
            self.argv = argv
            if raises:
                raise raises
            return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        self.argv = None
        with mock.patch.object(vm_provision.subprocess, "run", fake_run):
            return guest_provision_result("myvm")

    def test_asks_the_management_address(self):
        answer = self._run(_probe_output("myvm-a", {"status": "done",
                                                    "errors": []}))
        self.assertEqual(answer[0], PROVISION_DONE)
        self.assertTrue(any(a.startswith("workload@127.") for a in self.argv))

    def test_timeout_is_no_answer(self):
        self.assertIsNone(self._run(
            raises=vm_provision.subprocess.TimeoutExpired("ssh", 15)))

    def test_missing_ssh_binary_is_no_answer(self):
        self.assertIsNone(self._run(raises=OSError("no ssh")))

    def test_bridge_pinned_vm_is_probed_at_its_discovered_address(self):
        # On an operator bridge the guest has its own LAN address; probing the
        # uid-derived management address instead would reach nothing (or worse,
        # a stranger). This is the shape the live forgejo VM is in.
        self.toml.write_text('[vm]\nuser = "git"\n'
                             '[vm.network]\nbridge = "br0"\n')
        with mock.patch.dict(sys.modules, {"substrate_vm": types.SimpleNamespace(
                _vm_guest_addresses=lambda name, bridge: ["192.168.0.157"])}):
            answer = self._run(_probe_output("myvm-a", {"status": "done",
                                                        "errors": []}))
        self.assertEqual(answer[0], PROVISION_DONE)
        self.assertIn("git@192.168.0.157", self.argv)
        self.assertEqual(self.argv[self.argv.index("-p") + 1], "22")

    def test_bridge_vm_with_no_resolvable_address_is_not_probed(self):
        self.toml.write_text('[vm]\nuser = "workload"\n'
                             '[vm.network]\nbridge = "br0"\n')
        with mock.patch.dict(sys.modules, {"substrate_vm": types.SimpleNamespace(
                _vm_guest_addresses=lambda name, bridge: [])}):
            self.assertIsNone(self._run("ignored"))
        self.assertIsNone(self.argv)

    def test_container_workload_is_not_probed(self):
        self.toml.write_text('[container]\nimage = "x"\n')
        self.assertIsNone(self._run("ignored"))
        self.assertIsNone(self.argv)

    def test_unknown_workload_user_is_no_answer(self):
        with mock.patch.object(vm_provision.pwd, "getpwnam",
                               side_effect=KeyError("nope")):
            self.assertIsNone(self._run("ignored"))

    def test_missing_config_is_no_answer(self):
        self.toml.unlink()
        self.assertIsNone(guest_provision_result("myvm"))


class TestRecordGuestProvisionResult(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def _record(self, answer, instance_id="myvm-deadbeef"):
        with mock.patch.object(vm_provision, "guest_provision_result",
                               lambda name, timeout=None: answer):
            return record_guest_provision_result(self.tmp, instance_id, "myvm")

    def test_records_the_outcome(self):
        self.assertEqual(
            self._record((PROVISION_FAILED, "myvm-deadbeef", ["boom"])),
            PROVISION_FAILED)
        marker = read_provision_marker(self.tmp)
        self.assertEqual(marker["status"], PROVISION_FAILED)
        self.assertEqual(marker["errors"], ["boom"])

    def test_no_answer_writes_nothing(self):
        self.assertIsNone(self._record(None))
        self.assertIsNone(read_provision_marker(self.tmp))

    def test_result_from_another_instance_is_not_attributed(self):
        # A guest that rebooted onto an older seed must not have its result
        # filed against the instance we think is running.
        self.assertIsNone(self._record((PROVISION_DONE, "myvm-0ldbeef0", [])))
        self.assertIsNone(read_provision_marker(self.tmp))

    def test_recording_preserves_the_heal_count(self):
        # Otherwise the cap resets every time an outcome is filed, and a guest
        # that fails deterministically re-provisions forever.
        write_provision_marker(self.tmp, "myvm-deadbeef", PROVISION_UNVERIFIED,
                               heal_attempts=1)
        self._record((PROVISION_FAILED, "myvm-deadbeef", ["boom"]))
        self.assertEqual(read_provision_marker(self.tmp)["heal_attempts"], 1)


class TestVmProvisioningCheck(unittest.TestCase):
    @staticmethod
    def _m(instance_id, status, attempts=0, errors=None):
        m = {"instance_id": instance_id, "status": status,
             "heal_attempts": attempts}
        if errors:
            m["errors"] = errors
        return m

    def test_clean_run_passes(self):
        passed, message, fix = vm_provisioning_check(
            self._m("a", PROVISION_DONE), "a", "myvm")
        self.assertTrue(passed)
        self.assertIsNone(fix)

    def test_failure_fails_and_names_the_remedy(self):
        passed, message, fix = vm_provisioning_check(
            self._m("a", PROVISION_FAILED, errors=["getpwnam: fedora"]), "a",
            "myvm")
        self.assertFalse(passed)
        self.assertIn("getpwnam: fedora", message)
        self.assertIn("restart myvm", fix)

    def test_exhausted_heal_escalates_to_update(self):
        # restart would only reuse the same id, so the fix must not suggest it.
        passed, _, fix = vm_provisioning_check(
            self._m("a", PROVISION_FAILED, attempts=MAX_HEAL_ATTEMPTS), "a",
            "myvm")
        self.assertFalse(passed)
        self.assertIn("update myvm", fix)
        self.assertNotIn("restart myvm", fix)

    def test_no_marker_passes_as_unobserved(self):
        # Not evidence of anything — most often no qemu-guest-agent. Failing
        # here would cry wolf on every guest without the agent.
        passed, message, fix = vm_provisioning_check(None, "a", "myvm")
        self.assertTrue(passed)
        self.assertIn("not recorded", message)

    def test_marker_for_another_instance_passes_as_unobserved(self):
        passed, message, _ = vm_provisioning_check(
            self._m("old", PROVISION_DONE), "a", "myvm")
        self.assertTrue(passed)
        self.assertIn("not recorded", message)

    def test_unverified_passes(self):
        passed, message, _ = vm_provisioning_check(
            self._m("a", PROVISION_UNVERIFIED), "a", "myvm")
        self.assertTrue(passed)
        self.assertIn("not reported an outcome", message)

    def test_no_instance_id_passes(self):
        passed, message, _ = vm_provisioning_check(None, None, "myvm")
        self.assertTrue(passed)
        self.assertIn("no instance provisioned", message)


if __name__ == "__main__":
    unittest.main()
