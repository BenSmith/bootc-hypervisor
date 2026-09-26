"""security/workload-clock.cil: the clock keeper's SELinux domain.

The same class of assertion as tests/test_selinux_resolve_policy.py, and this
time made before the finding rather than after it: a helper under
/usr/libexec/workloadctl with no filecon runs as unconfined_service_t, and
NOTHING fails. The keeper parses what the guest's agent sends back, once a
minute, for every VM -- guest-supplied bytes on a timer, which is the shape
both sibling domains were written to end.

Deliberately not asserted: that the rule set is *sufficient*. That is an
empirical question about one Fedora policy version, answered by running
tests/manual/clock_rig.py on an enforcing host with `semodule -DB` in effect.
"""
import pathlib
import re
import unittest

from vm_clock import VM_CLOCK_KEEPER_BIN

ROOT = pathlib.Path(__file__).resolve().parent.parent
CIL = ROOT / "security" / "workload-clock.cil"
SPEC = ROOT / "rpm" / "workloadctl.spec"


def _body():
    """The module with comment lines stripped, so a rule quoted in a comment
    cannot satisfy an assertion about the rules."""
    return "\n".join(ln for ln in CIL.read_text().splitlines()
                     if not ln.lstrip().startswith(";"))


class TestFilecon(unittest.TestCase):
    def test_the_filecon_names_exactly_one_path(self):
        filecons = re.findall(r'\(filecon\s+"([^"]+)"', _body())
        self.assertEqual(len(filecons), 1, filecons)
        self.assertNotIn("*", filecons[0])

    def test_the_filecon_path_is_the_installed_keeper(self):
        """The drift guard: the module and lib/vm_clock.py each name this
        path, and a disagreement looks exactly like the domain not being
        applied -- which is indistinguishable from the module not existing."""
        filecons = re.findall(r'\(filecon\s+"([^"]+)"', _body())
        self.assertEqual(filecons[0], VM_CLOCK_KEEPER_BIN)

    def test_the_script_is_an_entrypoint_and_the_interpreter_is_not(self):
        body = _body()
        self.assertRegex(body, r"\(typetransition\s+init_t\s+wlclock_exec_t\s+process\s+wlclock_t\)")
        self.assertRegex(
            body,
            r"\(allow\s+wlclock_t\s+bin_t\s+\(file\s+\([^)]*execute")
        self.assertNotRegex(body, r"execute_no_trans")
        self.assertNotRegex(body, r"\(allow\s+wlclock_t\s+base_ro_file_type\s")


class TestTheGuestAgentSocket(unittest.TestCase):
    """The one thing the domain does, in the three grants it takes."""

    def test_the_socket_node_and_its_directory(self):
        body = _body()
        self.assertRegex(
            body,
            r"\(allow\s+wlclock_t\s+qemu_var_run_t\s+\(sock_file\s+\([^)]*write")
        self.assertRegex(
            body,
            r"\(allow\s+wlclock_t\s+qemu_var_run_t\s+\(dir\s+\([^)]*search")

    def test_connectto_is_on_qemus_domain_not_on_the_file(self):
        """The half missed by reading the denial for the file and stopping
        there: `connectto` is checked against the peer's domain, and QEMU's
        is svirt_t."""
        self.assertRegex(
            _body(),
            r"\(allow\s+wlclock_t\s+svirt_t\s+\(unix_stream_socket\s+\([^)]*connectto")

    def test_it_creates_nothing_in_the_runtime_directory(self):
        """The difference from both siblings. The keeper reads no document
        and writes no status; a directory grant wider than `search` here is
        a grant copied from a sibling rather than one this domain earned."""
        body = _body()
        dir_grants = re.findall(
            r"\(allow\s+wlclock_t\s+qemu_var_run_t\s+\(dir\s+\(([^)]*)\)", body)
        self.assertEqual(dir_grants, ["search"])
        self.assertNotRegex(
            body, r"\(allow\s+wlclock_t\s+qemu_var_run_t\s+\(file\s")


class TestWhatItIsNot(unittest.TestCase):
    def test_no_socket_activation_rules(self):
        """A oneshot on a timer. init_t creates no socket in this domain, so
        the init_t -> domain socket grants the two listeners carry would be
        an unearned widening here."""
        body = _body()
        self.assertNotRegex(body, r"\(allow\s+init_t\s+wlclock_t\s+\((tcp|udp)_socket")
        self.assertNotRegex(body, r"name_bind")
        self.assertNotRegex(body, r"node_bind")

    def test_no_inet_socket_at_all(self):
        self.assertNotRegex(_body(), r"wlclock_t\s+self\s+\((tcp|udp)_socket")


class TestPackaging(unittest.TestCase):
    def test_the_spec_installs_loads_and_removes_the_module(self):
        spec = SPEC.read_text()
        self.assertIn("security/workload-clock.cil", spec)
        self.assertIn("semodule -i %{_datadir}/workloadctl/workload-clock.cil",
                      spec)
        self.assertIn("semodule -r workload-clock", spec)

    def test_loading_restorecons_the_keeper(self):
        """A freshly loaded filecon does not touch an installed file, so on
        an upgrade the helper keeps bin_t until relabelled -- which is the
        unconfined state, silently, until the next reboot."""
        spec = SPEC.read_text()
        self.assertRegex(
            spec,
            r"semodule -i %\{_datadir\}/workloadctl/workload-clock\.cil[^\n]*\n"
            r"\s*restorecon " + re.escape(VM_CLOCK_KEEPER_BIN))
        self.assertRegex(
            spec,
            r"semodule -r workload-clock[^\n]*\n"
            r"\s*restorecon " + re.escape(VM_CLOCK_KEEPER_BIN))

    def test_the_spec_ships_the_helper(self):
        spec = SPEC.read_text()
        self.assertIn("libexec/workload-vm-clock", spec)
        self.assertIn("%{_libexecdir}/workloadctl/workload-vm-clock", spec)


if __name__ == "__main__":
    unittest.main()
