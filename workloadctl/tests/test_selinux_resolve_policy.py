"""security/workload-resolve.cil: the DNS responder's SELinux domain.

The same class of assertion as tests/test_selinux_inspect_policy.py, and for
the same reason: a module with the wrong filecon, or missing one of the two
transports, LOADS CLEANLY and mostly works. What it does instead is confine the
wrong file, or leave the TCP retry path unbindable so that only large answers
fail -- which reads as a flaky upstream, not as a policy gap.

The finding this module exists to prevent is worse than either. Before it, the
responder had no filecon at all: the script was bin_t, systemd's own rules ran
the service as unconfined_service_t, and a process parsing guest-supplied DNS
wire format ran unconfined for as long as it had existed. Nothing failed.
Nothing could fail. It was found by asking a running host for the label, on
2026-08-25, and the check that finds it again lives in
tests/manual/inspect_rig.py -- not here, because no static test can see it.

Deliberately not asserted: that the rule set is *sufficient*. That is an
empirical question about one Fedora policy version, answered by running the rig
on an enforcing host with `semodule -DB` in effect.
"""
import pathlib
import re
import unittest

from vm import VM_RESOLVE_LISTENER_BIN

ROOT = pathlib.Path(__file__).resolve().parent.parent
CIL = ROOT / "security" / "workload-resolve.cil"
SPEC = ROOT / "rpm" / "workloadctl.spec"


def _body():
    """The module with comment lines stripped, so a rule quoted in a comment
    cannot satisfy an assertion about the rules."""
    return "\n".join(l for l in CIL.read_text().splitlines()
                     if not l.lstrip().startswith(";"))


class TestFilecon(unittest.TestCase):
    def test_the_filecon_names_exactly_one_path(self):
        filecons = re.findall(r'\(filecon\s+"([^"]+)"', _body())
        self.assertEqual(len(filecons), 1, filecons)
        self.assertNotIn("*", filecons[0])

    def test_the_filecon_path_is_the_installed_responder(self):
        """The drift guard: the module and lib/vm.py each name this path, and
        a disagreement looks exactly like the domain not being applied -- which
        is indistinguishable from the module not existing, the state this was
        written to end."""
        filecons = re.findall(r'\(filecon\s+"([^"]+)"', _body())
        self.assertEqual(filecons[0], VM_RESOLVE_LISTENER_BIN)

    def test_the_script_is_an_entrypoint_and_the_interpreter_is_not(self):
        """Retyping /usr/bin/python3 would move every workloadctl entrypoint
        and most of the host into this domain."""
        body = _body()
        self.assertRegex(body, r"\(typetransition\s+init_t\s+wlresolve_exec_t\s+process\s+wlresolve_t\)")
        # Measured 2026-08-25, correcting the inverse assertion this test used
        # to make: `execute map` on bin_t, never execute_no_trans on the
        # attribute. See the same test in test_selinux_inspect_policy.py for
        # why the old rule could not fail.
        self.assertRegex(
            body,
            r"\(allow\s+wlresolve_t\s+bin_t\s+\(file\s+\([^)]*execute")
        self.assertNotRegex(body, r"execute_no_trans")
        self.assertNotRegex(body, r"\(allow\s+wlresolve_t\s+base_ro_file_type\s")


class TestSocketActivation(unittest.TestCase):
    def test_both_transports_can_bind_the_dns_port(self):
        """DNS is UDP until an answer does not fit. A grant covering only the
        datagram socket leaves the TCP retry unbindable, so ONLY large answers
        fail -- rare, and shaped like an upstream problem rather than a policy
        one."""
        body = _body()
        for cls in ("udp_socket", "tcp_socket"):
            with self.subTest(cls=cls):
                self.assertRegex(
                    body,
                    rf"\(allow\s+wlresolve_t\s+dns_port_t\s+\({cls}\s+\([^)]*name_bind")

    def test_init_creates_the_sockets_in_this_domain(self):
        """The rule that points the opposite way from the obvious guess:
        systemd's (sd-listen) creates and binds a socket unit's sockets in the
        SERVICE's domain, so the denial is init_t -> wlresolve_t. Without it
        the socket unit fails and the VM ordered after it fails with a bare
        dependency error."""
        body = _body()
        for cls in ("udp_socket", "tcp_socket"):
            with self.subTest(cls=cls):
                self.assertRegex(
                    body,
                    rf"\(allow\s+init_t\s+wlresolve_t\s+\({cls}\s+\([^)]*create")

    def test_init_can_flush_pending_connections(self):
        """`accept`, on the init_t rule rather than the domain's own.

        `Accept=no` does not mean systemd never accepts: when the service goes
        away with connections pending, systemd flushes them by accepting and
        closing. Denied, it retries at the socket's trigger interval and spins
        -- while the workload keeps working, which is why this was found by
        reading an audit log rather than by anything failing. Measured on an
        enforcing host 2026-08-27; see the comment on the rule.
        """
        self.assertRegex(
            _body(),
            r"\(allow\s+init_t\s+wlresolve_t\s+\(tcp_socket\s+\([^)]*accept")


class TestRuntimeDirectory(unittest.TestCase):
    def test_the_status_write_can_rename(self):
        """os.replace needs `rename`, and NO sibling grant carries it --
        wlproxy_t writes its log in place. A block copied from a sibling gets
        all the way to the replace and fails there, and the writer catches
        OSError by design, so the only symptom is a status file that never
        appears."""
        self.assertRegex(
            _body(),
            r"\(allow\s+wlresolve_t\s+qemu_var_run_t\s+\(file\s+\([^)]*rename")

    def test_the_policy_document_can_be_read(self):
        """resolve.json is read at start; without it the process exits and the
        socket restart-loops."""
        self.assertRegex(
            _body(),
            r"\(allow\s+wlresolve_t\s+qemu_var_run_t\s+\(file\s+\([^)]*read")


class TestPackaging(unittest.TestCase):
    def test_the_spec_installs_loads_and_removes_the_module(self):
        spec = SPEC.read_text()
        self.assertIn("security/workload-resolve.cil", spec)
        self.assertIn("semodule -i %{_datadir}/workloadctl/workload-resolve.cil",
                      spec)
        self.assertIn("semodule -r workload-resolve", spec)

    def test_loading_restorecons_the_responder(self):
        """semodule does not relabel existing files. On an UPGRADE the
        installed script keeps bin_t until something relabels it, so a load
        without this leaves the responder unconfined exactly as before -- the
        module present, the finding unfixed, and nothing failing."""
        spec = SPEC.read_text()
        self.assertRegex(
            spec, r"semodule -i %\{_datadir\}/workloadctl/workload-resolve\.cil"
                  r"[^\n]*\n\s*restorecon " + re.escape(VM_RESOLVE_LISTENER_BIN))


if __name__ == "__main__":
    unittest.main()
