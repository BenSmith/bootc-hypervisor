"""security/workload-inspect.cil: the egress inspector's SELinux domain.

These assert the properties of the module that cannot be seen by loading it —
a module with the wrong filecon, or with a name_bind it does not need, loads
cleanly and works. What it does instead is confine the wrong set of files, or
grant a permission whose absence would have been the tell that the socket unit
had failed. Both are silent, and both are the failure modes §7.9 names.

Deliberately not asserted here: that the rule set is *sufficient*. That is an
empirical question about one Fedora policy version and it is answered by
running tests/manual/inspect_rig.py on an enforcing host, not by reading the
file.
"""
import pathlib
import re
import unittest

from vm import VM_INSPECT_LISTENER_BIN

ROOT = pathlib.Path(__file__).resolve().parent.parent
CIL = ROOT / "security" / "workload-inspect.cil"
SPEC = ROOT / "rpm" / "workloadctl.spec"


def _body():
    """The module with comment lines stripped, so a rule quoted in a comment
    cannot satisfy an assertion about the rules."""
    return "\n".join(l for l in CIL.read_text().splitlines()
                     if not l.lstrip().startswith(";"))


class TestFilecon(unittest.TestCase):
    def test_the_filecon_names_exactly_one_path(self):
        """A glob over /usr/libexec/workloadctl would make every helper an
        entrypoint into this domain -- including workload-vm-inspect, which
        the socket unit runs privileged. Nothing would fail; the domain would
        just be enterable from six more binaries."""
        filecons = re.findall(r'\(filecon\s+"([^"]+)"', _body())
        self.assertEqual(len(filecons), 1, filecons)
        self.assertNotIn("*", filecons[0])
        self.assertNotIn("(", filecons[0])

    def test_the_filecon_path_is_the_installed_listener(self):
        """The drift guard. The module and lib/vm.py each name this path, and
        a disagreement looks exactly like the domain not being applied."""
        filecons = re.findall(r'\(filecon\s+"([^"]+)"', _body())
        self.assertEqual(filecons[0], VM_INSPECT_LISTENER_BIN)


class TestSocketActivation(unittest.TestCase):
    def test_both_plane_ports_are_bindable(self):
        """The two listener ports carry DIFFERENT labels -- 8080 is
        http_cache_port_t, 8443 is http_port_t -- so granting one and not the
        other yields a half-working inspector whose failing plane is whichever
        the reader did not think about. Socket activation does not move the
        bind out of the domain; systemd binds in the service's own context.
        Measured on an enforcing host, not reasoned: the design predicted no
        port label would be needed at all."""
        body = _body()
        for port_type in ("http_cache_port_t", "http_port_t"):
            self.assertRegex(
                body,
                r"\(allow\s+wlinspect_t\s+" + port_type
                + r"\s+\(tcp_socket\s+\([^)]*name_bind")

    def test_init_may_create_a_socket_in_this_domain(self):
        """The rule whose absence looks like the socket unit having failed --
        and it points the opposite way from what the design predicted.
        systemd creates a socket unit's sockets already labelled for the
        service's domain, so the denial is init_t creating a wlinspect_t
        socket, not this domain touching an init_t one. Measured, not
        reasoned: without it the process never starts at all and the VM
        ordered after the socket dies with a bare dependency failure."""
        body = _body()
        self.assertRegex(
            body,
            r"\(allow\s+init_t\s+wlinspect_t\s+\(tcp_socket\s+\([^)]*create")

    def test_the_fd_passing_socketpair_rule_is_present(self):
        """The rule whose absence leaves the audit log EMPTY.

        systemd creates the socket in a forked (sd-listen) helper and passes
        the fd back to PID 1 over a socketpair, so init_t also needs
        `read write` on the wlinspect_t socket. That denial is dontaudit'd in
        shipped policy: without this rule the unit fails with

            Failed to receive listening socket (198.18.1.1:8080):
              Channel number out of range

        -- receive_one_fd() reporting -ECHRNG for a control message that
        carried no descriptor -- and nothing in that names SELinux. It was
        found only by running `semodule -DB` to disable dontaudit rules.

        Asserted because deleting the line left the whole suite green, and of
        every rule in this module it is the one that costs the most to
        rediscover: a plain enforcing harvest cannot see the denial at all.
        """
        body = _body()
        self.assertRegex(
            body,
            r"\(allow\s+wlinspect_t\s+init_t\s+"
            r"\(unix_stream_socket\s+\([^)]*read")
        self.assertRegex(
            body,
            r"\(allow\s+wlinspect_t\s+init_t\s+"
            r"\(unix_stream_socket\s+\([^)]*write")

    def test_the_domain_owns_its_listening_and_accepted_sockets(self):
        """Both carry this domain's label, so both are `self`."""
        body = _body()
        self.assertRegex(
            body,
            r"\(allow\s+wlinspect_t\s+self\s+\(tcp_socket\s+\([^)]*accept")


class TestInterpreter(unittest.TestCase):
    def test_execute_no_trans_is_granted_on_the_attribute(self):
        """bin_t is one member of base_ro_file_type, not the whole of it.
        Naming bin_t alone works for /usr/bin/python3 and misses lib_t."""
        body = _body()
        self.assertRegex(
            body,
            r"\(allow\s+wlinspect_t\s+base_ro_file_type\s+"
            r"\(file\s+\([^)]*execute_no_trans")
        self.assertNotRegex(body, r"\(allow\s+wlinspect_t\s+bin_t\s")


class TestPackaging(unittest.TestCase):
    def test_the_spec_installs_loads_and_removes_the_module(self):
        """A .cil that ships without being loaded fails the way the QMP
        fcontext drop already has here: the unit starts, the label is wrong,
        and the symptom names something else."""
        spec = SPEC.read_text()
        self.assertIn("security/workload-inspect.cil", spec)
        self.assertIn("semodule -i %{_datadir}/workloadctl/workload-inspect.cil",
                      spec)
        self.assertIn("semodule -r workload-inspect", spec)

    def test_loading_restorecons_the_listener(self):
        """semodule does not relabel existing files, so a load without a
        restorecon leaves the binary bin_t until the next full relabel."""
        spec = SPEC.read_text()
        self.assertRegex(
            spec, r"semodule -i %\{_datadir\}/workloadctl/workload-inspect\.cil"
                  r"[^\n]*\n\s*restorecon " + re.escape(VM_INSPECT_LISTENER_BIN))


if __name__ == "__main__":
    unittest.main()


class TestBoundary(unittest.TestCase):
    """The filesystem boundary is what the separate domain is FOR.

    wlproxy_t exists apart from svirt_t so that the component terminating
    guest-controlled input cannot reach the workload's disks, volumes or state
    directory. The inspector inherits that reasoning. A green run with
    dontaudit disabled logs `search` denials on cert_t and container_file_t,
    and the run is green with them denied -- so granting them because they
    appear in a log is the first step back across the line, and nothing would
    fail to tell anyone.
    """

    def test_the_domain_cannot_reach_the_workload_state_tree(self):
        self.assertNotIn("container_file_t", _body())

    def test_the_domain_cannot_reach_the_host_trust_store(self):
        """§6 puts the CA in a subdirectory with its own label, so when the
        inspector does need a certificate the rule to add is that label --
        never cert_t, and never the state directory."""
        self.assertNotIn("cert_t", _body())
