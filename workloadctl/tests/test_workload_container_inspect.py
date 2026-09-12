"""The container substrate of lib/inspect_arm.py, and libexec/workload-container-inspect
run end to end through main().

The arming body is shared with the VM helper and pinned once, in
tests/test_inspect.py; what is asserted here is only what the container
substrate contributes -- which predicate decides it is inspected, and what the
failure message may and may not name -- plus the shim's wiring.
"""

import io
import unittest
from contextlib import redirect_stderr
from unittest import mock

import inspect_arm
from container_network_config import container_uses_inspect
from tests import load_script


class TestInspectionAppliesDelegatesToTheSharedPredicate(unittest.TestCase):
    """This helper and the generator's run-file list must not be able to
    disagree about which workloads have an inspector, so both have to read
    the one source, container_uses_inspect()."""

    def test_the_predicate_is_the_generators(self):
        self.assertIs(inspect_arm.CONTAINER.applies, container_uses_inspect)

    def test_a_triggered_config_applies(self):
        config = {"network": {"hosts": ["example.com"]}}
        self.assertTrue(inspect_arm.CONTAINER.applies(config))

    def test_an_untriggered_config_does_not_apply(self):
        self.assertFalse(inspect_arm.CONTAINER.applies({"network": {}}))

    def test_up_is_a_clean_noop_when_uninspected(self):
        """Cheap to call directly: the early return happens before pwd or
        any subprocess call, so an untriggered config must never reach
        either -- a config with no [network] trigger at all stops here."""
        with mock.patch.object(inspect_arm, "load_workload_config",
                               return_value={"network": {}}), \
             mock.patch.object(inspect_arm, "pwd") as fake_pwd, \
             mock.patch.object(inspect_arm, "run") as fake_run:
            rc = inspect_arm.up(inspect_arm.CONTAINER, "plain")
        self.assertEqual(rc, 0)
        fake_pwd.getpwnam.assert_not_called()
        fake_run.assert_not_called()


class TestTheInternalFailureSaysWhatItCosts(unittest.TestCase):
    """Container twin of the VM class of the same name in test_inspect.py.
    The wording differs (a container starts, it does not boot a guest), but
    the shape -- keep the cause, name the unit, state the blast radius, offer
    the safe way out -- is one template, so it cannot drift."""

    def _message(self):
        return inspect_arm.internal_failure(
            inspect_arm.CONTAINER, "web", "git.local",
            ValueError("[network].internal names 'git.local', which does "
                       "not resolve on this host"))

    def test_it_keeps_the_underlying_cause(self):
        self.assertIn("does not resolve on this host", self._message())

    def test_it_names_the_socket_and_not_the_requiring_unit(self):
        """The unit that ARMS is nameable; the unit that requires it is not.

        The ExecStartPre this runs from is always workload-<name>-inspect.socket,
        so that name is safe to print. What Requires= that socket is not:
        workload-<name>.service in `single` mode, and the pod/net head unit in
        `pod`/`bridge` (the umbrella is After= its members, so the arming had
        to move -- see _head_unit in lib/gen_container_heads.py). A literal
        `workload-web.service` here sends a pod-mode operator to the wrong
        journal.
        """
        message = self._message()
        self.assertIn("workload-web-inspect.socket", message)
        self.assertNotIn("workload-web.service", message)

    def test_it_says_the_workload_will_not_start(self):
        """Not "boot" -- containers don't. Prose specific to the substrate,
        contract identical to the VM side's "will not boot"."""
        message = self._message()
        self.assertIn("fatal to the START", message)
        self.assertIn("will not start", message)
        self.assertNotIn("boot", message)

    def test_it_offers_removing_the_entry_as_a_way_out(self):
        message = self._message()
        self.assertIn("[[network.internal]]", message)
        self.assertIn("authorises nothing", message)


class TestContainerShim(unittest.TestCase):
    """libexec/workload-container-inspect run end to end through main(): argv
    in, inspect_arm.up bound to the container substrate, down unbound, exit
    code out."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_script("libexec/workload-container-inspect")

    def test_up_arms_the_container_substrate(self):
        with mock.patch.object(self.mod, "up", return_value=0) as up:
            self.assertEqual(self.mod.main(["x", "up", "web"]), 0)
        up.assert_called_once_with(inspect_arm.CONTAINER, "web")

    def test_down_needs_no_substrate(self):
        with mock.patch.object(self.mod, "down", return_value=0) as down:
            self.assertEqual(self.mod.main(["x", "down", "web"]), 0)
        down.assert_called_once_with("web")

    def test_a_bad_verb_is_a_usage_error(self):
        with mock.patch.object(self.mod, "up") as up, \
             redirect_stderr(io.StringIO()):
            self.assertEqual(self.mod.main(["x", "sideways", "web"]), 2)
        up.assert_not_called()


if __name__ == "__main__":
    unittest.main()
