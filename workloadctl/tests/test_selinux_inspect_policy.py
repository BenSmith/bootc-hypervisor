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
    def test_the_interpreter_is_execute_map_on_bin_t_not_execute_no_trans(self):
        """This test asserted the exact opposite until 2026-08-25, and the
        module's header argued for it: grant execute_no_trans on the
        base_ro_file_type attribute, by analogy with sshd_keygen_t, because
        naming bin_t alone "misses lib_t".

        A permissive harvest measured the truth. execute_no_trans is only
        checked when an exec does NOT cause a domain transition; sshd-keygen's
        does not and ours does -- the typetransition asserted above is the
        difference. The domain uses `execute map` on bin_t (/usr/bin/python3),
        and base_ro_file_type is used for NOTHING. lib_t is not missed: base
        policy already grants every domain read access to base_ro_file_type
        and execute/map on lib_t, which is why no denial ever appeared to
        contradict the old rule.

        The old assertion could not fail, because over-granting never
        produces a denial -- which is the whole reason it survived."""
        body = _body()
        self.assertRegex(
            body,
            r"\(allow\s+wlinspect_t\s+bin_t\s+\(file\s+\([^)]*execute")
        self.assertNotRegex(body, r"\(allow\s+wlinspect_t\s+base_ro_file_type\s")

    def test_execute_no_trans_is_the_mint_and_nothing_else(self):
        """Rung 3 DID need it -- for openssl, which is a different exec.

        The reasoning above still holds for the interpreter: an exec that
        causes a domain transition never checks execute_no_trans. openssl is
        run without one, so it does, and stdlib-only is why there is an exec at
        all -- binding a TLS library would be a Python dependency the RPM must
        not declare. Measured under enforcing on a KVM host 2026-08-26.

        This test exists so the permission stays attached to that reason: a
        later `execute_no_trans` on some other type would be a second program
        this domain runs, which is a thing to argue rather than to inherit.
        """
        granted = re.findall(
            r"\(allow\s+wlinspect_t\s+(\S+)\s+\(file\s+\(([^)]*)\)\)\)",
            _body())
        self.assertEqual(
            [t for t, perms in granted if "execute_no_trans" in perms.split()],
            ["bin_t"])


class TestTheUpstreamDial(unittest.TestCase):
    """The half of this domain that three green rig runs never executed.

    Every event the rig produced was a drop -- {"dropped": 5, "forwarded": 0,
    "spliced": 0} on a 31/31 run -- because the plain arm's allowlist is empty
    by construction and the proxy arm's traffic is exempted by wl_inspect_cg
    before the inspector sees it. So forward and splice were dead code under
    SELinux, and none of these rules existed.

    What makes the gap dangerous is its failure mode: a denial here does not
    crash anything. getaddrinfo() or connect() raises, the relay catches
    OSError, and the connection is counted as a drop with reason 'upstream
    unreachable' -- byte-identical to a genuinely dead host. Measured under
    enforcing with these rules absent: the guest got 502, and the log line read
    "upstream unreachable: [Errno -3] Temporary failure in name resolution".
    """

    def test_the_domain_can_connect_out_to_the_upstream_port(self):
        """80 and 443 are both http_port_t; 8080 (the listener) is
        http_cache_port_t. name_bind is the listen side and was already here.
        name_connect is the dial side."""
        self.assertRegex(
            _body(),
            r"\(allow\s+wlinspect_t\s+http_port_t\s+"
            r"\(tcp_socket\s+\([^)]*name_connect")

    def test_the_domain_creates_and_connects_its_own_tcp_socket(self):
        """The listening sockets are created by init_t and inherited. The
        upstream socket is not: the domain makes it itself."""
        body = _body()
        for perm in ("create", "connect"):
            with self.subTest(perm=perm):
                self.assertRegex(
                    body,
                    rf"\(allow\s+wlinspect_t\s+self\s+"
                    rf"\(tcp_socket\s+\([^)]*{perm}")

    def test_the_domain_can_resolve_a_hostname(self):
        """Resolution fails BEFORE any socket is created, so this is what the
        guest actually hits first. /etc/resolv.conf is net_conf_t and is a
        symlink on this host, hence both classes; the stub resolver is then
        dialled over a udp_socket the domain creates itself."""
        body = _body()
        self.assertRegex(
            body, r"\(allow\s+wlinspect_t\s+net_conf_t\s+\(file\s+\([^)]*read")
        self.assertRegex(
            body, r"\(allow\s+wlinspect_t\s+net_conf_t\s+\(lnk_file\s+\([^)]*read")
        for perm in ("create", "connect"):
            with self.subTest(perm=perm):
                self.assertRegex(
                    body,
                    rf"\(allow\s+wlinspect_t\s+self\s+"
                    rf"\(udp_socket\s+\([^)]*{perm}")

    def test_the_domain_can_fall_back_to_dns_over_tcp(self):
        """A UDP answer that does not fit sets TC and glibc retries over TCP.
        Denied, that retry surfaces as `upstream unreachable` -- a policy gap
        wearing a network error's clothes, and one that appears only for names
        whose answers are large."""
        self.assertRegex(
            _body(),
            r"\(allow\s+wlinspect_t\s+dns_port_t\s+"
            r"\(tcp_socket\s+\([^)]*name_connect")


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
    directory. The inspector inherits that reasoning.

    Rung 3 gave the domain a private key to read and a leaf cache to write,
    both of which live in that state directory beside the disk images — and the
    boundary held by MOVING the material rather than by widening the domain.
    So these tests no longer say "cert_t and container_file_t appear nowhere";
    they say what the domain may do with them, which is traverse and nothing
    else. Granting `svirt_image_t:file read` is the one-rule-shorter shape that
    works, and it is what these tests exist to catch.
    """

    def _perms(self, target, cls):
        """Every permission granted to wlinspect_t on one type/class, as a set."""
        pattern = (r"\(allow wlinspect_t " + re.escape(target)
                   + r" \(" + re.escape(cls) + r" \(([^)]*)\)\)\)")
        found = re.findall(pattern, _body())
        return set(" ".join(found).split())

    def test_the_workload_state_tree_is_traversable_and_not_readable(self):
        # /var/lib/workloads is container_file_t and the per-workload tree is
        # svirt_image_t; the path to the CA crosses both. `search` on a dir is
        # traversal only.
        for target in ("container_file_t", "svirt_image_t"):
            self.assertEqual(self._perms(target, "dir"), {"search"}, target)
            self.assertEqual(self._perms(target, "file"), set(), target)

    def test_the_trust_store_is_readable_and_not_writable(self):
        """The terminating listener verifies every upstream chain against it.

        A domain that cannot read /etc/pki fails EVERY host as unverifiable,
        which reads as the internet being down rather than as a policy gap.
        lnk_file is not optional: /etc/pki/tls/certs is a symlink farm.
        """
        self.assertTrue({"read", "open"} <= self._perms("cert_t", "file"))
        self.assertTrue(self._perms("cert_t", "lnk_file"))
        for cls in ("dir", "file", "lnk_file"):
            self.assertEqual(
                self._perms("cert_t", cls) & {"write", "create", "unlink",
                                              "rename", "append", "setattr"},
                set(), cls)

    def test_the_ca_is_readable_and_not_writable_by_the_inspector(self):
        """Two types, not one, and this is the difference between them.

        An inspector that could rewrite the CA could replace the anchor the
        guest was SEEDED with. Nothing recovers that but a re-provision, so the
        one permission worth spending a whole extra type on is the absence of
        write.
        """
        self.assertTrue({"read", "open"} <= self._perms("wlinspect_ca_t", "file"))
        self.assertEqual(
            self._perms("wlinspect_ca_t", "file") & {"write", "create",
                                                     "unlink", "rename"},
            set())
        self.assertEqual(
            self._perms("wlinspect_ca_t", "dir") & {"add_name", "remove_name",
                                                    "write"},
            set())

    def test_the_leaf_caches_are_writable(self):
        """Minting into them is the job, and the eviction is unlink+replace."""
        self.assertTrue(
            {"create", "read", "write", "rename", "setattr", "unlink"}
            <= self._perms("wlinspect_leaf_t", "file"))
        self.assertTrue(
            {"add_name", "remove_name", "search", "write"}
            <= self._perms("wlinspect_leaf_t", "dir"))
        # create/rmdir are the atomic landing: each mint stages into a
        # TemporaryDirectory INSIDE the cache so os.replace is a same-filesystem
        # rename. Without them every mint fails with EACCES on a name that looks
        # like a leaf and is a directory.
        self.assertTrue(
            {"create", "rmdir"} <= self._perms("wlinspect_leaf_t", "dir"))

    def test_systemd_may_mount_the_caches(self):
        """ReadWritePaths= is a bind mount init_t performs while setting up the
        unit's namespace, so the label is checked against INIT_T. Without it the
        unit never starts: "Failed at step NAMESPACE", naming the ExecStartPre
        rather than the mount."""
        self.assertIn("(allow init_t wlinspect_leaf_t (dir (mounton)))", _body())

    def test_both_pki_types_are_declared_as_file_types(self):
        """A type without the file_type attribute cannot be relabelled onto a
        file by setfiles, so `restorecon` silently leaves the subtree
        svirt_image_t and the inspector cannot read its own CA."""
        for t in ("wlinspect_ca_t", "wlinspect_leaf_t"):
            self.assertIn(f"(type {t})", _body())
            self.assertIn(f"(typeattributeset file_type ({t}))", _body())

    def test_the_pki_labels_are_not_declared_as_filecons_here(self):
        """They are registered with semanage, in file_contexts.local.

        A CIL filecon lands in the base file_contexts, and .local outranks the
        base file WHOLESALE — so a filecon under /var/lib/workloads does not
        lose on specificity, it is simply never consulted. The label an
        operator asked for is not applied and nothing errors.
        """
        for t in ("wlinspect_ca_t", "wlinspect_leaf_t"):
            self.assertNotIn(f"filecon", _body().split(f"(type {t})")[1])


if __name__ == "__main__":
    unittest.main()
