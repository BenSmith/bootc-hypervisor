"""Where workloadctl keeps the inspector's per-request record.

The record itself -- the join key on every line, the one JSON object per
request -- is moatery's and tested there. What is workloadctl's is where
the file goes: a per-workload directory under a root tmpfiles creates,
named to the unit as its LogsDirectory, labelled for SELinux, and rotated
by logrotate.
"""

import importlib
import unittest
from pathlib import Path

from egress_policy import (
    INSPECT_RECORD_FILE,
    INSPECT_RECORD_ROOT,
    inspect_logs_directory,
    inspect_record_dir,
    inspect_record_path,
)
from nft_elements import INSPECT_RECORD_SELINUX_TYPE

ROOT = Path(__file__).resolve().parent.parent


class TestWhereTheRecordGoes(unittest.TestCase):
    """Not the journal, and not the workload tree. Both alternatives were
    argued and both are wrong for reasons the paths themselves cannot state,
    so the paths are pinned here."""

    def test_the_record_is_not_under_the_workload_tree(self):
        """state/ is svirt_image_t, the label the PKI rules exist to move
        material out of, and data/ is where `./` volume anchors resolve — a
        guest with a volume at the data root would read its own audit log."""
        path = str(inspect_record_path("demo"))
        self.assertNotIn("/var/lib/workloads", path)
        self.assertNotIn("/run/workload-vm", path)

    def test_the_path_is_per_workload(self):
        self.assertNotEqual(inspect_record_path("a"),
                            inspect_record_path("b"))
        self.assertEqual(inspect_record_path("a").name,
                         INSPECT_RECORD_FILE)
        self.assertEqual(inspect_record_dir("a").parent,
                         INSPECT_RECORD_ROOT)

    def test_the_logs_directory_names_the_same_place(self):
        """A LogsDirectory= naming a different path than the listener writes to
        gives the unit a writable directory nobody uses and a write that fails
        EROFS under ProtectSystem=strict — swallowed by the per-connection
        OSError handler, and shaped like a network fault."""
        self.assertEqual(
            Path("/var/log") / inspect_logs_directory("demo"),
            inspect_record_dir("demo"))

    def _root_line(self):
        conf = (ROOT / "systemd" / "workloads-dirs.conf").read_text()
        line = [ln for ln in conf.splitlines()
                if ln.split()[1:2] == [str(INSPECT_RECORD_ROOT)]]
        self.assertEqual(len(line), 1, conf)
        return line[0].split()

    def test_the_root_is_created_by_tmpfiles(self):
        """systemd applies LogsDirectoryMode= to the LEAF only and creates the
        parents 0755, so without this line the per-workload directories would
        sit 0700 under a root anyone could list."""
        fields = self._root_line()
        self.assertEqual(fields[3:5], ["root", "root"], fields)

    def test_the_root_is_traversable_by_the_workload_user(self):
        """THE SEARCH BIT IS LOAD-BEARING, and its absence is silent.

        The listener runs as User=_wl-<name>. It does not merely write inside
        its leaf -- it has to walk THROUGH this directory to get there, and a
        0700 root-owned parent refuses that walk to every uid but root. The
        write is guaranteed never to raise, so what a missing search bit
        produces is not an error: it is a journal warning, no record file, and
        `workloadctl egress` reporting a workload that made no requests. That
        is indistinguishable from a guest that made none.

        Measured on a KVM host 2026-08-31 as exactly that: 47 assertions green,
        eight failing on a file that could not be created, and no AVC -- the
        failure was DAC, not policy, which is why the SELinux harvest said
        nothing.

        Asserted as `others may search`, not as the literal 0711, because what
        is required is the traversal; the mode that grants it is a detail.
        Read but not listable stays pinned by the sibling test below.
        """
        mode = int(self._root_line()[2], 8)
        self.assertTrue(mode & 0o001,
                        f"the record root is {oct(mode)}: the workload user "
                        f"cannot traverse it to reach its own leaf")

    def test_the_root_is_not_readable_by_others(self):
        """The other half, and the reason this is not simply 0755: the search
        bit alone grants no read, so the set of workloads that have a record
        cannot be enumerated by a local user. Losing THIS is the disclosure the
        record was kept out of the journal to avoid."""
        mode = int(self._root_line()[2], 8)
        self.assertFalse(mode & 0o044,
                         f"the record root is {oct(mode)}: it can be listed")


class TestTheUnitCarriesTheDirectory(unittest.TestCase):
    """LogsDirectory= is doing three things at once — creating the directory as
    User=, recreating it when an operator deletes it, and adding it to the
    unit's writable set under ProtectSystem=strict. The third has no other
    statement in the unit, so losing this line loses the write silently."""

    def _unit(self):
        gen = importlib.import_module("gen_egress")
        config = {
            "workload": {"name": "recdemo", "mode": "vm"},
            "vm": {"image": "/tmp/x.qcow2", "memory": "1G", "cpus": 1,
                   "network": {"egress": "filtered",
                               "hosts": ["example.com"]}},
        }
        return gen.generate_inspect_service(config, "_wl-recdemo", 10004)

    def test_it_names_the_workloads_own_directory(self):
        self.assertIn(f"LogsDirectory={inspect_logs_directory('recdemo')}",
                      self._unit())

    def test_the_mode_is_0700(self):
        self.assertIn("LogsDirectoryMode=0700", self._unit())


class TestTheSubtreeIsLabelled(unittest.TestCase):
    """A record left as var_log_t is readable by every domain shipped policy
    lets read the system's logs — which is the ACL the decision to keep it out
    of the journal exists to avoid."""

    def _cil(self):
        return (ROOT / "security" / "workload-inspect.cil").read_text()

    def test_the_type_is_declared(self):
        self.assertIn(f"(type {INSPECT_RECORD_SELINUX_TYPE})", self._cil())

    def test_it_is_a_logfile_so_logrotate_needs_no_rule_of_ours(self):
        self.assertIn(
            f"(typeattributeset logfile ({INSPECT_RECORD_SELINUX_TYPE}))",
            self._cil())

    def test_the_filecon_covers_every_workload(self):
        self.assertIn(f'(filecon "{INSPECT_RECORD_ROOT}(/.*)?"', self._cil())

    def test_init_may_mount_it(self):
        """ReadWritePaths=/LogsDirectory= under ProtectSystem=strict is a bind
        mount init_t performs, so the label is checked against INIT_T. Without
        it the unit does not start and the message names the ExecStartPre."""
        self.assertRegex(
            self._cil(),
            rf"\(allow init_t {INSPECT_RECORD_SELINUX_TYPE} "
            rf"\(dir \([^)]*mounton")

    def test_the_filecon_is_not_shadowed(self):
        """A module filecon is silently ignored under a prefix workloadctl
        registers in file_contexts.local. /var/log is not one of those, which
        is the only reason this rule may live in the module at all."""
        from workload_selinux import LOCAL_FCONTEXT_ROOTS
        for root in LOCAL_FCONTEXT_ROOTS:
            self.assertFalse(str(INSPECT_RECORD_ROOT).startswith(root))


class TestRotationIsLogrotates(unittest.TestCase):
    """Writing our own was rejected: the failure mode of getting it wrong is a
    full /var on a hypervisor."""

    def _conf(self):
        return (ROOT / "logrotate" / "workloadctl-inspect").read_text()

    def _directives(self):
        """The file with its comments removed. A substring pin over the whole
        text counts the comment that ARGUES against a directive as the
        directive being present — the exact defect a rung-3 review found and
        the reason these assertions read the stanza rather than the file."""
        return "\n".join(
            ln for ln in self._conf().splitlines()
            if not ln.lstrip().startswith("#"))

    def test_it_covers_the_record_path(self):
        self.assertIn(f"{INSPECT_RECORD_ROOT}/*/{INSPECT_RECORD_FILE} {{",
                      self._directives())

    def test_it_does_not_create_the_file(self):
        """`create` takes ONE literal owner and this path is a glob, so it
        cannot produce <name>/requests.log owned by _wl-<name> per match. The
        listener recreates it on the HUP instead."""
        self.assertIn("nocreate", self._directives())
        self.assertNotRegex(self._directives(), r"(?m)^\s*create\b")

    def test_it_hups_rather_than_truncating(self):
        """copytruncate races an in-flight write and would tear a record."""
        self.assertNotIn("copytruncate", self._directives())
        self.assertIn("postrotate", self._directives())
        self.assertIn("-s HUP", self._directives())

    def test_a_failing_postrotate_does_not_abort_the_rotation(self):
        """The glob matches nothing on a host whose inspected workloads are all
        stopped, and a postrotate that fails aborts the rotate."""
        self.assertIn("|| true", self._directives())

    def test_compression_is_delayed(self):
        """The listener holds the current fd until its next write, so an idle
        workload has not acted on the HUP when the compress would run."""
        self.assertIn("delaycompress", self._directives())

    def test_there_is_a_hard_size_bound(self):
        """A chatty agent filling /var takes the hypervisor down, where a
        truncated history only loses evidence — so the cap matters more than
        the count, and `maxsize` rather than `size` keeps the daily run too."""
        self.assertRegex(self._directives(),
                         r"(?m)^\s*maxsize\s+\d+[KMG]\s*$")

    def test_it_ships(self):
        spec = (ROOT / "rpm" / "workloadctl.spec").read_text()
        self.assertIn("logrotate.d/workloadctl-inspect", spec)

    def test_the_numbers_survive_an_upgrade(self):
        """They are defaults to revisit; an operator who has revisited them
        must not lose that to an upgrade."""
        spec = (ROOT / "rpm" / "workloadctl.spec").read_text()
        self.assertIn(
            "%config(noreplace) %{_sysconfdir}/logrotate.d/workloadctl-inspect",
            spec)


if __name__ == "__main__":
    unittest.main()
