"""libexec/workload-container-inspect: the container counterpart of
workload-vm-inspect (P1-8/P1-9/P1-15, G18 in the container egress-parity
build spec).

Mirrors tests/test_vm_inspect.py's TestHelperArmsBothTables /
TestTheInternalFailureSaysWhatItCosts in style -- most properties are asserted
against the source the way that file does (the point being that the two
helpers agree, and a substring check on both fails the same way a real drift
would), plus a couple of real calls for the parts cheap enough to execute
directly (inspection_applies() and up()'s uninspected no-op, neither of
which touches pwd or the kernel).
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestInspectionAppliesDelegatesToTheSharedPredicate(unittest.TestCase):
    """G18 itself: this helper and the generator's run-file list (P1-9) must
    not be able to disagree about which workloads have an inspector, so both
    have to read the one source, container_uses_inspect()."""

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        cls.mod = load_script("libexec/workload-container-inspect")

    def test_a_triggered_config_applies(self):
        config = {"network": {"hosts": ["example.com"]}}
        self.assertTrue(self.mod.inspection_applies(config))

    def test_an_untriggered_config_does_not_apply(self):
        config = {"network": {}}
        self.assertFalse(self.mod.inspection_applies(config))

    def test_up_is_a_clean_noop_when_uninspected(self):
        """Cheap to call directly: the early return happens before pwd or
        any subprocess call, so an untriggered config must never reach
        either -- a config with no [network] trigger at all stops here."""
        import unittest.mock as mock
        with mock.patch.object(self.mod, "load_config",
                               return_value={"network": {}}), \
             mock.patch.object(self.mod, "pwd") as fake_pwd, \
             mock.patch.object(self.mod, "run") as fake_run:
            rc = self.mod.up("plain")
        self.assertEqual(rc, 0)
        fake_pwd.getpwnam.assert_not_called()
        fake_run.assert_not_called()

    def test_delegates_rather_than_restating(self):
        source = (ROOT / "libexec" / "workload-container-inspect").read_text()
        applies = source[source.index("def inspection_applies("):
                         source.index("def write_policy(")]
        self.assertIn("container_uses_inspect(config)", applies)


class TestHelperArmsBothTables(unittest.TestCase):
    """Same orchestration contract as workload-vm-inspect's twin: both
    skeletons before any element, no cgroup arming here (that belongs to the
    inspect service unit's own ExecStartPre/ExecStopPost, per the module
    docstring), and the `internal` exemptions purged before they're re-armed.
    """

    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "libexec" / "workload-container-inspect").read_text()
        cls.up = cls.source[cls.source.index("def up("):
                            cls.source.index("def down(")]
        cls.down = cls.source[cls.source.index("def down("):
                              cls.source.index("def main(")]

    def test_up_applies_both_skeletons_before_any_element(self):
        self.assertLess(self.up.index("NFT_PROXY_SKELETON"),
                        self.up.index("vm_inspect_element_commands"))
        self.assertLess(self.up.index("NFT_SKELETON"),
                        self.up.index("vm_inspect_element_commands"))
        self.assertIn("check=True", self.up)

    def test_up_never_arms_the_cgroup_elements(self):
        self.assertNotIn("vm_inspect_cgroup_command", self.up)
        self.assertNotIn("vm_inspect_cgroup_filter_command", self.up)

    def test_up_clears_the_previous_instances_status_file(self):
        self.assertIn("clear_status(vm_inspect_status_path(name))", self.up)

    def test_down_removes_elements_and_addresses_but_not_the_link(self):
        self.assertIn('vm_inspect_element_commands(uid, "delete")', self.down)
        self.assertIn("vm_inspect_link_delete_commands", self.down)
        self.assertNotIn('"link", "del"', self.down)
        self.assertNotIn("VM_ADVERTISED_ADDR", self.down)

    def test_up_arms_the_internal_exemptions_after_the_skeleton(self):
        self.assertIn("vm_internal_ok_commands", self.up)
        self.assertLess(self.up.index("NFT_SKELETON"),
                        self.up.index("vm_internal_ok_commands"))
        self.assertLess(
            self.up.index("purge_internal_exemptions(uid, name)"),
            self.up.index('vm_internal_ok_commands(uid, addresses, "add")'),
            "purge before arming, or an edited config leaves a dropped "
            "host's element behind")

    def test_up_purges_by_uid_rather_than_by_the_addresses_it_is_arming(self):
        self.assertNotIn(
            'vm_internal_ok_commands(uid, addresses, "delete")', self.up)

    def test_down_clears_the_internal_exemptions_and_tolerates_absence(self):
        self.assertIn("purge_internal_exemptions(uid, name)", self.down)
        self.assertIn("except (OSError, ValueError)", self.down)

    def test_down_never_resolves_a_name_to_decide_what_to_remove(self):
        """THE ROTATION HOLE, same as the VM side: re-resolving computes
        deletes for whatever the names mean NOW, not what was actually
        armed. Teardown must go by uid alone."""
        self.assertNotIn("container_internal_resolve", self.down)
        self.assertNotIn("container_internal_entries", self.down)

    def test_up_writes_the_policy_before_it_arms_the_redirect(self):
        self.assertIn("write_policy(name, net)", self.up)
        self.assertLess(self.up.index("write_policy(name, net)"),
                        self.up.index("vm_inspect_element_commands"))

    def test_the_policy_is_written_group_readable_and_not_world_readable(self):
        write = self.source[self.source.index("def write_policy("):
                            self.source.index("def internal_failure(")]
        self.assertIn("0o640", write)
        self.assertIn("os.replace(tmp, path)", write)


class TestTheInternalFailureSaysWhatItCosts(unittest.TestCase):
    """Container twin of the VM class of the same name. The wording differs
    (a container starts, it does not boot a guest), but the shape -- keep the
    cause, name the unit, state the blast radius, offer the safe way out --
    must not drift from the VM message's contract."""

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        cls.mod = load_script("libexec/workload-container-inspect")

    def _message(self):
        return self.mod.internal_failure(
            "web", "git.local",
            ValueError("[network].internal names 'git.local', which does "
                       "not resolve on this host"))

    def test_it_keeps_the_underlying_cause(self):
        self.assertIn("does not resolve on this host", self._message())

    def test_it_names_the_unit_that_will_not_start(self):
        self.assertIn("workload-web.service", self._message())

    def test_it_says_the_workload_will_not_start(self):
        """Not "boot" -- containers don't. Prose specific to the substrate,
        contract identical to the VM side's "will not boot"."""
        message = self._message()
        self.assertIn("fatal to the START", message)
        self.assertIn("will not start", message)

    def test_it_offers_removing_the_entry_as_a_way_out(self):
        message = self._message()
        self.assertIn("[[network.internal]]", message)
        self.assertIn("authorises nothing", message)

    def test_both_arming_failures_are_told_the_same_way(self):
        source = (ROOT / "libexec" / "workload-container-inspect").read_text()
        up = source[source.index("def up("):source.index("def down(")]
        self.assertEqual(up.count("internal_failure("), 2)
        self.assertIn("container_internal_resolve(host)", up)
        self.assertIn('vm_internal_ok_commands(uid, addresses, "add")', up)


if __name__ == "__main__":
    unittest.main()
