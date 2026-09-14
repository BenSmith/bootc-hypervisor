"""lib/svcaddr_arm.py and libexec/workload-vm-svcaddr.

The one door a passt VM has onto its own host: its own derived address on the
shared dummy link, so a host service can publish on it and that workload's
guest can reach it. These rows pin the properties a silent edit drops — the
same source-level style test_inspect uses for the inspector's arming.
"""
import unittest
from unittest import mock

from tests import REPO_ROOT, load_script


ROOT = REPO_ROOT


class TestSvcaddrArm(unittest.TestCase):
    """lib/svcaddr_arm.py: up ensures the link and adds, down removes.

    The whole job is two verbs and two idempotent tolerances; the properties
    worth pinning are the ones an edit that still runs would break silently —
    arming before the link exists, or a down that creates instead of removes.
    """

    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "lib" / "svcaddr_arm.py").read_text()
        cls.up = cls.source[cls.source.index("def up("):
                            cls.source.index("def down(")]
        cls.down = cls.source[cls.source.index("def down("):]

    def test_up_ensures_the_link_before_it_adds_the_addresses(self):
        """An `ip addr add ... dev workload-proxy` against a missing link fails
        the start with a message that names neither this helper nor its intent;
        ensuring the link first is what makes the add meaningful."""
        self.assertLess(self.up.index("ensure_advertised_interface"),
                        self.up.index("add_listener_addresses"))

    def test_up_adds_but_down_removes(self):
        """The asymmetry is the point: up fails loudly (a VM that needs a host
        service and cannot reach it is worse than one that did not start);
        down tolerates absence (a start that died before arming left nothing
        to remove)."""
        self.assertIn("add_listener_addresses", self.up)
        self.assertNotIn("remove_listener_addresses", self.up)
        self.assertIn("remove_listener_addresses", self.down)
        self.assertNotIn("add_listener_addresses", self.down)

    def test_down_never_deletes_the_link(self):
        """The dummy link and its advertised address are shared and stay; only
        this workload's /32 and /128 go, on stop."""
        self.assertNotIn('"link", "del"', self.down)

    def test_both_halves_resolve_the_uid_from_the_workload_name(self):
        """The address is derived from the uid, so the uid must come from the
        workload's own user account, never from a config value."""
        self.assertIn("pwd.getpwnam", self.up)
        self.assertIn("pwd.getpwnam", self.down)


class TestSvcaddrEntrypoint(unittest.TestCase):
    """libexec/workload-vm-svcaddr main(): argv in, up/down out, exit code out."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_script("libexec/workload-vm-svcaddr")

    def test_up_dispatches(self):
        with mock.patch.object(self.mod, "up", return_value=0) as up:
            self.assertEqual(self.mod.main(["x", "up", "forge"]), 0)
        up.assert_called_once_with("forge")

    def test_down_dispatches(self):
        with mock.patch.object(self.mod, "down", return_value=0) as down:
            self.assertEqual(self.mod.main(["x", "down", "forge"]), 0)
        down.assert_called_once_with("forge")

    def test_a_bad_verb_is_a_usage_error(self):
        with mock.patch.object(self.mod, "up") as up:
            self.assertEqual(self.mod.main(["x", "sideways", "forge"]), 2)
        up.assert_not_called()


if __name__ == "__main__":
    unittest.main()
