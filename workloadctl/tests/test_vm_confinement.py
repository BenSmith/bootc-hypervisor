#!/usr/bin/env python3
"""SELinux confinement of VM workloads: the svirt_t transition and wlvfsd.

Everything here is checkable without SELinux installed — the CIL module is
parsed as text and the launch argv is a pure function. What cannot be checked
here is whether the policy actually *compiles and permits*, which is what the
enforcing bench run is for.
"""

import unittest
from pathlib import Path
from types import SimpleNamespace

from provisioning import LOCAL_FCONTEXT_ROOTS, shadowed_filecon_paths
from vm import (
    VM_QEMU_CONTEXT, VM_QEMU_TYPE, VM_RUNCON_BIN, VM_SELINUX_CIL, VM_SELINUX_MODULE,
    qemu_launch_argv,
)

ROOT = Path(__file__).resolve().parent.parent
CIL = ROOT / "security" / "workload-vm.cil"
SPEC = ROOT / "rpm" / "workloadctl.spec"

QEMU = "/usr/libexec/qemu-kvm"
SAMPLE = [QEMU, "-machine", "q35", "-nographic"]


def vm_config(name="v1", volumes=None):
    cfg = {"vm": {}}
    if volumes:
        cfg["vm"]["volumes"] = volumes
    return SimpleNamespace(name=name, is_vm=True, config=cfg)


class TestLaunchArgv(unittest.TestCase):
    """The runcon prefix, and the two ways it must decline to apply."""

    def test_prefixes_runcon_with_the_svirt_context(self):
        argv = qemu_launch_argv(SAMPLE, enabled=True, runcon=__file__)
        self.assertEqual(argv[:2], [__file__, VM_QEMU_CONTEXT])
        self.assertEqual(argv[2:], SAMPLE)

    def test_execs_qemu_directly_with_no_shell_in_between(self):
        """The entrypoint is on qemu_exec_t; a bin_t shell is refused.

        This is the whole reason the transition is a runcon prefix rather than
        an `ExecStart=/bin/sh -c 'runcon … qemu …'`, so assert the binary runcon
        is handed is QEMU itself.
        """
        argv = qemu_launch_argv(SAMPLE, enabled=True, runcon=__file__)
        self.assertEqual(argv[2], QEMU)
        for arg in argv:
            self.assertNotIn("sh -c", arg)
            self.assertNotEqual(arg, "/bin/sh")

    def test_selinux_disabled_leaves_the_command_alone(self):
        """runcon's setexeccon fails on a disabled host and would kill QEMU."""
        self.assertEqual(qemu_launch_argv(SAMPLE, enabled=False), SAMPLE)

    def test_missing_runcon_leaves_the_command_alone(self):
        argv = qemu_launch_argv(SAMPLE, enabled=True,
                                runcon="/nonexistent/runcon")
        self.assertEqual(argv, SAMPLE)

    def test_returns_a_copy_not_the_caller_s_list(self):
        original = list(SAMPLE)
        argv = qemu_launch_argv(original, enabled=False)
        argv.append("-snapshot")
        self.assertEqual(original, SAMPLE)

    def test_context_names_svirt_t_at_s0(self):
        """s0 with no categories is deliberate (ADR 006 §9.5)."""
        user, role, typ, level = VM_QEMU_CONTEXT.split(":")
        self.assertEqual((user, role, typ, level),
                         ("system_u", "system_r", VM_QEMU_TYPE, "s0"))


class TestCilModule(unittest.TestCase):
    """Properties of security/wlvfsd.cil, parsed as text."""

    @classmethod
    def setUpClass(cls):
        cls.text = CIL.read_text()
        # Strip comments so an example inside the header can never satisfy a
        # rule assertion — the blanket allow this module exists to *replace* is
        # quoted up there verbatim.
        cls.rules = "\n".join(line for line in cls.text.splitlines()
                              if not line.lstrip().startswith(";"))

    def test_declares_the_domain_and_its_exec_type(self):
        for decl in ("(type wlvfsd_t)", "(type wlvfsd_exec_t)"):
            self.assertIn(decl, self.rules)
        self.assertIn("(typeattributeset domain (wlvfsd_t))", self.rules)
        self.assertIn("(roletype system_r wlvfsd_t)", self.rules)
        self.assertIn("(typeattributeset entry_type (wlvfsd_exec_t))",
                      self.rules)

    def test_entrypoint_is_the_retyped_binary_not_bin_t(self):
        """bin_t as the entrypoint would make every bin_t binary an entry."""
        self.assertRegex(self.rules,
                         r"allow wlvfsd_t wlvfsd_exec_t \(file \([^)]*entrypoint")
        self.assertNotRegex(self.rules,
                            r"allow wlvfsd_t bin_t \(file \([^)]*entrypoint")

    def test_retypes_the_virtiofsd_binary(self):
        self.assertIn('(filecon "/usr/libexec/virtiofsd" file', self.rules)
        self.assertIn("wlvfsd_exec_t", self.rules)

    def test_entry_is_a_type_transition_from_init_t(self):
        """A systemd sidecar has a real exec to transition on; no wrapper."""
        self.assertIn("(typetransition init_t wlvfsd_exec_t process wlvfsd_t)",
                      self.rules)
        self.assertIn("(allow init_t wlvfsd_t (process (transition)))",
                      self.rules)

    def test_grants_svirt_t_connectto_on_the_new_domain(self):
        """The one rule the module exists for."""
        self.assertIn(
            "(allow svirt_t wlvfsd_t (unix_stream_socket (connectto)))",
            self.rules)

    def test_does_not_ship_the_blanket_unconfined_service_t_allow(self):
        """The scoped grant above replaces it; both would defeat the point."""
        self.assertNotRegex(
            self.rules,
            r"allow svirt_t unconfined_service_t .*connectto")

    def test_no_user_namespace_permissions(self):
        """The sidecar runs --sandbox=none, so none of this should appear.

        If cap_userns or mounton ever show up the sandbox mode changed to
        namespace, which reopens the cost pasta_sandbox.cil exists to pay.
        sys_chroot going the same way is the chroot mode leaving.
        """
        for perm in ("cap_userns", "mounton", "pivot_root", "sys_chroot"):
            self.assertNotIn(perm, self.rules)

    def test_socket_dir_type_matches_what_the_rpm_registers(self):
        """/run/workload-vm is svirt_var_run_t, whose real name is qemu_var_run_t."""
        self.assertRegex(
            self.rules,
            r"allow wlvfsd_t qemu_var_run_t \(sock_file \([^)]*create")
        spec = SPEC.read_text()
        self.assertIn("-t svirt_var_run_t '/run/workload-vm(/.*)?'", spec)

    def test_shared_dir_type_matches_the_per_workload_fcontext(self):
        self.assertRegex(self.rules, r"allow wlvfsd_t svirt_image_t \(dir ")

    def test_serves_fuse_writes_not_just_directory_reads(self):
        """Serving FUSE means the whole write surface, not just opening the
        share. A harvest taken with no QEMU client attached never serves a
        request, so it measures the open-the-share rules and none of these."""
        for perm in ("create", "write", "unlink"):
            self.assertRegex(
                self.rules,
                rf"allow wlvfsd_t svirt_image_t \(file \([^)]*{perm}")
        for perm in ("add_name", "remove_name", "rmdir"):
            self.assertRegex(
                self.rules,
                rf"allow wlvfsd_t svirt_image_t \(dir \([^)]*{perm}")

    def test_can_map_the_guest_memory(self):
        """virtiofsd maps QEMU's memfd (svirt_tmpfs_t) to move FUSE payloads."""
        self.assertRegex(self.rules,
                         r"allow wlvfsd_t svirt_tmpfs_t \(file \([^)]*map")

    def test_can_traverse_the_container_file_t_parent(self):
        """/var/lib/workloads keeps the blanket rule; only the subdir is
        svirt_image_t, so reaching the share crosses a container_file_t dir."""
        self.assertIn("(allow wlvfsd_t container_file_t (dir (search)))",
                      self.rules)

    def test_grants_the_sidecar_no_capability_at_all(self):
        """The sidecar's unit sets CapabilityBoundingSet= empty, so the process
        holds nothing SELinux could be asked to permit. A capability rule here
        would be unreachable text — and, worse, would read as a claim that the
        daemon needs privilege. A capability denial for wlvfsd_t means the UNIT
        changed, and the question is why it needs the privilege."""
        self.assertNotIn("(capability", self.rules)
        for cap in ("chown", "dac_override", "dac_read_search", "setuid",
                    "setgid", "fowner", "fsetid", "sys_resource", "setpcap"):
            self.assertNotIn(cap, self.rules, f"{cap} is back")

    def test_serves_every_kind_of_node_a_filesystem_has(self):
        """A share is a filesystem, and these are the classes a workout of files
        and directories alone never reaches. Without lnk_file, `ln -s` in a share
        fails under enforcing while every other operation works; fifo_file and
        sock_file are the same gap one step out. Create without unlink is the
        same bug in miniature."""
        for cls in ("lnk_file", "fifo_file", "sock_file"):
            self.assertRegex(
                self.rules,
                rf"allow wlvfsd_t svirt_image_t \({cls} \([^)]*create",
                f"{cls} cannot be created in a share")
            self.assertRegex(
                self.rules,
                rf"allow wlvfsd_t svirt_image_t \({cls} \([^)]*unlink",
                f"{cls} can be created but not removed")

    def test_supports_moving_things_around(self):
        """`mv` within a directory needs rename; `mv` between directories needs
        reparent as well. Neither appears in a harvest that never runs one."""
        self.assertRegex(self.rules,
                         r"allow wlvfsd_t svirt_image_t \(dir \([^)]*rename")
        self.assertRegex(self.rules,
                         r"allow wlvfsd_t svirt_image_t \(dir \([^)]*reparent")
        self.assertRegex(self.rules,
                         r"allow wlvfsd_t svirt_image_t \(file \([^)]*rename")
        self.assertRegex(self.rules,
                         r"allow wlvfsd_t svirt_image_t \(file \([^)]*link")

    def test_directory_metadata_is_settable_not_just_file_metadata(self):
        """cloud-init chowns the default user's HOME, a directory. A file-only
        version of this rule passes every file-level test and still leaves a
        guest whose injected ssh key sshd will not accept."""
        self.assertRegex(self.rules,
                         r"allow wlvfsd_t svirt_image_t \(dir \([^)]*setattr")

    def test_drops_the_nss_lookups_socket_group_needed(self):
        """Resolving a group name is something only --socket-group=<user> would
        ask for, and the unit does not pass it — the socket is already owned by
        the user QEMU runs as. So the whole userdb/passwd block is absent,
        confirmed by a from-scratch permissive rebuild."""
        for t in ("systemd_userdbd_t", "systemd_homed_t",
                  "systemd_userdbd_runtime_t", "passwd_file_t"):
            self.assertNotIn(t, self.rules)

    def test_grants_what_qemus_native_passt_netdev_needs(self):
        """Both rules exist only because QEMU spawns passt, where libvirt does.

        The socketpair one is invisible to an ordinary audit harvest: the
        shipped policy dontaudits it, so the symptom is passt looping on
        "Failed to add fd to epoll" with an empty audit log.
        """
        self.assertIn("(allow svirt_t passt_t (process (signal)))", self.rules)
        self.assertIn(
            "(allow passt_t svirt_t (unix_stream_socket (read write)))",
            self.rules)

    def test_its_own_filecon_would_not_be_shadowed(self):
        """Dogfoods the validate rule: /usr/libexec is not in .local."""
        self.assertEqual(shadowed_filecon_paths(self.text), [])

    def test_parentheses_balance(self):
        """A cheap structural check; secilc is what really validates it."""
        depth = 0
        for line in self.rules.splitlines():
            depth += line.count("(") - line.count(")")
            self.assertGreaterEqual(depth, 0, f"unbalanced at: {line}")
        self.assertEqual(depth, 0)


class TestRpmShipsTheModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = SPEC.read_text()

    def test_installs_the_cil_where_diagnose_tells_operators_to_find_it(self):
        self.assertIn("security/workload-vm.cil", self.spec)
        # The path diagnose prints in its remediation must be the one the RPM
        # installs, or the fix it offers does not work.
        self.assertIn(VM_SELINUX_CIL.rsplit("/", 1)[-1], self.spec)
        self.assertEqual(VM_SELINUX_CIL,
                         "/usr/share/workloadctl/workload-vm.cil")

    def test_post_loads_it_and_relabels_the_binary(self):
        post = self.spec.split("%post", 1)[1].split("%preun", 1)[0]
        self.assertIn("semodule -i", post)
        self.assertIn("restorecon /usr/libexec/virtiofsd", post)

    def test_postun_removes_it_only_on_full_uninstall(self):
        postun = self.spec.split("%postun", 1)[1]
        self.assertIn(f"semodule -r {VM_SELINUX_MODULE}", postun)
        # Guarded by the same $1 -eq 0 block as the fcontext rules: an upgrade
        # must not unload the module out from under a running VM.
        block = postun.split("if [ $1 -eq 0 ]; then", 1)[1]
        self.assertIn(f"semodule -r {VM_SELINUX_MODULE}", block)


class TestSocketDirIsRelabelled(unittest.TestCase):
    """The fcontext rule alone is inert for a directory created at runtime."""

    def test_setup_relabels_the_vm_socket_dir(self):
        """The kernel labels a new file from its PARENT, not from file_contexts
        — that file is only consulted by userspace tools. So the %post semanage
        rule does nothing for a mkdir'd /run/workload-vm, which inherits
        var_run_t from /run, and a confined QEMU then cannot create its QMP
        socket. /run is a tmpfs, so this recurs every boot.
        """
        text = (ROOT / "libexec" / "workload-ensure-user").read_text()
        body = text.split("def setup_vm_socket_dir", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("restorecon", body)

    def test_relabel_happens_before_anything_is_written_into_the_dir(self):
        """Files created inside inherit from the directory, so a later relabel
        would leave the sockets and cloud-init.iso behind."""
        text = (ROOT / "libexec" / "workload-ensure-user").read_text()
        body = text.split("def setup_vm_socket_dir", 1)[1].split("\ndef ", 1)[0]
        self.assertLess(body.index("restorecon"), body.index("os.chown"))

    def test_rpm_registers_the_rule_the_relabel_resolves(self):
        spec = SPEC.read_text()
        self.assertIn("-t svirt_var_run_t '/run/workload-vm(/.*)?'", spec)


class TestShadowedFilecon(unittest.TestCase):
    """The validate warning: a CIL filecon under a semanage-registered path."""

    def test_flags_a_filecon_under_the_workload_tree(self):
        cil = '(filecon "/var/lib/workloads/foo/data(/.*)?" any (u r t ((s0)(s0))))'
        self.assertEqual(shadowed_filecon_paths(cil),
                         ["/var/lib/workloads/foo/data(/.*)?"])

    def test_flags_a_filecon_under_the_vm_runtime_dir(self):
        cil = '(filecon "/run/workload-vm/foo" dir (u r t ((s0)(s0))))'
        self.assertEqual(len(shadowed_filecon_paths(cil)), 1)

    def test_leaves_filecons_elsewhere_alone(self):
        cil = '(filecon "/usr/libexec/virtiofsd" file (u r t ((s0)(s0))))'
        self.assertEqual(shadowed_filecon_paths(cil), [])

    def test_does_not_match_a_prefix_that_is_not_a_path_component(self):
        cil = '(filecon "/var/lib/workloads-backup/x" dir (u r t ((s0)(s0))))'
        self.assertEqual(shadowed_filecon_paths(cil), [])

    def test_matches_the_registered_root_itself(self):
        for root in LOCAL_FCONTEXT_ROOTS:
            cil = f'(filecon "{root}" dir (u r t ((s0)(s0))))'
            self.assertEqual(shadowed_filecon_paths(cil), [root])

    def test_no_filecon_is_no_finding(self):
        self.assertEqual(shadowed_filecon_paths("(allow a b (file (read)))"), [])

    def test_handles_several_in_one_module(self):
        cil = ('(filecon "/usr/libexec/x" file (u r t ((s0)(s0))))\n'
               '(filecon "/var/lib/workloads/a" dir (u r t ((s0)(s0))))\n'
               '(filecon "/run/workload-vm/b" dir (u r t ((s0)(s0))))\n')
        self.assertEqual(len(shadowed_filecon_paths(cil)), 2)


class TestConfinementDiagnose(unittest.TestCase):
    """Verdict logic, with every observation injected."""

    @staticmethod
    def check(config, **kw):
        from cmd_diagnose import vm_confinement_check
        return vm_confinement_check(config, **kw)

    def test_skips_container_workloads(self):
        cfg = SimpleNamespace(name="c", is_vm=False, config={})
        self.assertIsNone(self.check(cfg))

    def test_selinux_disabled_passes_and_says_so(self):
        name, passed, msg = self.check(vm_config(), enabled=False)
        self.assertTrue(passed)
        self.assertIn("disabled", msg)

    def test_unconfined_qemu_fails_even_with_everything_else_right(self):
        _n, passed, msg = self.check(
            vm_config(), enabled=True, module_loaded=True,
            qemu_context="system_u:system_r:unconfined_service_t:s0")
        self.assertFalse(passed)
        self.assertIn("unconfined_service_t", msg)
        self.assertIn(VM_RUNCON_BIN, msg)

    def test_confined_qemu_passes(self):
        _n, passed, msg = self.check(
            vm_config(), enabled=True, module_loaded=True,
            qemu_context=f"system_u:system_r:{VM_QEMU_TYPE}:s0")
        self.assertTrue(passed)
        self.assertIn(VM_QEMU_TYPE, msg)

    def test_missing_module_fails_a_vm_that_has_volumes(self):
        _n, passed, msg = self.check(
            vm_config(volumes=["data:/srv"]), enabled=True,
            module_loaded=False,
            qemu_context=f"system_u:system_r:{VM_QEMU_TYPE}:s0")
        self.assertFalse(passed)
        self.assertIn(VM_SELINUX_MODULE, msg)
        self.assertIn("semodule -i", msg)

    def test_missing_module_does_not_fail_a_vm_with_no_volumes(self):
        """The module grants exactly one thing, and it is about virtiofs."""
        _n, passed, _msg = self.check(
            vm_config(), enabled=True, module_loaded=False,
            qemu_context=f"system_u:system_r:{VM_QEMU_TYPE}:s0")
        self.assertTrue(passed)

    def test_unconfined_outranks_a_missing_module(self):
        """Report the cause, not the consequence: an unconfined QEMU can reach
        virtiofsd regardless, so naming the module would misdirect."""
        _n, passed, msg = self.check(
            vm_config(volumes=["data:/srv"]), enabled=True,
            module_loaded=False,
            qemu_context="system_u:system_r:unconfined_service_t:s0")
        self.assertFalse(passed)
        self.assertIn("NOT confined", msg)

    def test_not_running_passes_and_reports_module_state(self):
        """None means observed-absent (no QEMU), not "go and probe"."""
        _n, passed, msg = self.check(vm_config(), enabled=True,
                                     module_loaded=True, qemu_context=None)
        self.assertTrue(passed)
        self.assertIn("not running", msg)
        self.assertIn("loaded", msg)

    def test_not_running_still_flags_a_missing_module(self):
        _n, passed, msg = self.check(vm_config(volumes=["data:/srv"]),
                                     enabled=True, module_loaded=False,
                                     qemu_context=None)
        self.assertFalse(passed)
        self.assertIn("semodule -i", msg)

    def test_unknown_module_state_is_not_reported_as_loaded(self):
        _n, passed, msg = self.check(
            vm_config(volumes=["data:/srv"]), enabled=True, module_loaded=None,
            qemu_context=f"system_u:system_r:{VM_QEMU_TYPE}:s0")
        self.assertTrue(passed)
        self.assertIn("unknown", msg)


class TestQemuProcessLookup(unittest.TestCase):
    """_vm_qemu_context must not match the wrapper that launched QEMU."""

    def test_requires_the_process_to_be_qemu_not_just_to_name_the_socket(self):
        """workload-vm-notify is invoked WITH the QEMU command line as its
        arguments, so its own cmdline contains the QMP socket path. Matching on
        the path alone finds the wrapper — a Python script, so
        unconfined_service_t — and reports every confined VM as unconfined.
        Observed live, with `ps -eo label` showing svirt_t at the same moment.
        """
        from cmd_diagnose import _vm_qemu_context
        import inspect
        # Body only: the docstring names /cmdline first while explaining this.
        body = inspect.getsource(_vm_qemu_context).split('"""')[-1]
        self.assertIn("/comm", body)
        self.assertLess(body.index("/comm"), body.index("/cmdline"))


class TestNotifyWrapperUsesTheTransition(unittest.TestCase):
    def test_notify_launches_qemu_through_qemu_launch_argv(self):
        """A regression guard: reverting to a bare Popen(qemu_cmd) would leave
        every VM unconfined with no test failing anywhere else."""
        text = (ROOT / "libexec" / "workload-vm-notify").read_text()
        self.assertIn("qemu_launch_argv", text)
        self.assertRegex(text, r"Popen\(\s*qemu_launch_argv\(qemu_cmd\)")
        self.assertNotRegex(text, r"Popen\(qemu_cmd,")


if __name__ == "__main__":
    unittest.main()
