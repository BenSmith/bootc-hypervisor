"""lib/vm_status.py: the bound on every guest-keyed counter, and the status
file both producers replace.

The bound is the test nobody writes and the one that protects the HOST rather
than the workload. Every per-host figure in this design is keyed on a string
the guest chooses; unbounded, a guest touching a1.example.com ...
a100000.example.com grows the status file without limit and, through
libexec/workload-exporter, becomes a Prometheus cardinality explosion on the
machine running the workload it was supposed to contain.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import vm_status
from vm_status import (
    OTHER_KEY, STATUS_TOP_N, BoundedCounts, write_status,
)


class TestTheBound(unittest.TestCase):

    def test_two_hundred_hosts_at_top_n_twenty_is_twenty_plus_other(self):
        """The shape the design asks for, stated as the number it produces."""
        counts = BoundedCounts(top_n=20)
        for i in range(200):
            counts.add(f"h{i}.example.com")
        snap = counts.snapshot()
        self.assertEqual(len(snap), 21)
        self.assertEqual(snap[OTHER_KEY], 180)
        self.assertEqual(sum(1 for k in snap if k != OTHER_KEY), 20)

    def test_the_map_never_grows_past_the_bound_in_memory_either(self):
        """Reporting a bounded map while holding an unbounded one is the bug
        this is really about: the exporter would be safe and the listener's
        own RSS would not."""
        counts = BoundedCounts(top_n=5)
        for i in range(100_000):
            counts.add(f"h{i}.example.com")
        self.assertLessEqual(len(counts._counts), 5)

    def test_the_total_stays_exact_across_the_bound(self):
        """The bound costs attribution, never arithmetic. An operator reading
        'and N more' must be able to trust the N it is measured against."""
        counts = BoundedCounts(top_n=3)
        for i in range(50):
            counts.add(f"h{i}.example.com", 2)
        self.assertEqual(counts.total, 100)

    def test_a_named_host_keeps_accumulating_after_the_map_is_full(self):
        counts = BoundedCounts(top_n=2)
        counts.add("a.example.com")
        counts.add("b.example.com")
        counts.add("c.example.com")
        counts.add("a.example.com", 5)
        self.assertEqual(counts.snapshot()["a.example.com"], 6)

    def test_an_overflowed_host_stays_overflowed_on_its_next_hit(self):
        """What makes this fixed-size rather than merely fixed-size-looking:
        a late hit on an already-overflowed key must not claim a slot that a
        subsequent first-seen key would then be denied."""
        counts = BoundedCounts(top_n=1)
        counts.add("a.example.com")
        counts.add("b.example.com")
        counts.add("b.example.com")
        snap = counts.snapshot()
        self.assertNotIn("b.example.com", snap)
        self.assertEqual(snap[OTHER_KEY], 2)

    def test_other_is_absent_rather_than_zero_on_a_healthy_workload(self):
        """A bucket reading zero on every healthy workload trains an operator
        to skip the line, and this is the line that matters when it is not."""
        counts = BoundedCounts(top_n=20)
        counts.add("a.example.com")
        self.assertNotIn(OTHER_KEY, counts.snapshot())

    def test_the_default_bound_is_the_shared_constant(self):
        """Both producers must bound alike; a per-file default is how they
        stop doing so."""
        counts = BoundedCounts()
        for i in range(STATUS_TOP_N + 10):
            counts.add(f"h{i}.example.com")
        self.assertEqual(len(counts.snapshot()), STATUS_TOP_N + 1)


class TestTheStatusFile(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir))
        self.path = os.path.join(self.dir, "status.json")

    def test_it_stamps_when_it_was_written(self):
        """Absence of the file means 'never started', which is a healthy
        reading. A stale timestamp is the ONLY thing that separates a process
        that died from one that is quietly idle."""
        write_status(self.path, {"queries": 1})
        doc = json.loads(Path(self.path).read_text())
        self.assertIn("written_at", doc)
        self.assertGreater(doc["written_at"], 0)

    def test_it_replaces_rather_than_truncates(self):
        """A reader arrives at a moment nobody chose. Truncate-in-place hands
        it a half-written document; replace hands it the previous one."""
        write_status(self.path, {"n": 1})
        first = Path(self.path).read_text()
        write_status(self.path, {"n": 2})
        self.assertNotEqual(Path(self.path).read_text(), first)
        self.assertEqual(json.loads(Path(self.path).read_text())["n"], 2)

    def test_it_leaves_no_temporary_file_behind(self):
        write_status(self.path, {"n": 1})
        self.assertEqual(os.listdir(self.dir), ["status.json"])

    def test_the_payload_is_not_mutated_by_the_write(self):
        """The caller's snapshot is live state in one of the two producers;
        stamping it in place would put written_at into the counters."""
        payload = {"n": 1}
        write_status(self.path, payload)
        self.assertEqual(payload, {"n": 1})


class TestClearStatus(unittest.TestCase):
    """The RuntimeDirectory outlives the instance, so arming has to clear."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "inspect-status.json")

    def test_it_removes_the_previous_instances_file(self):
        """Both producers are socket-activated, so between a VM start and the
        guest's first dial the file on disk is the LAST boot's -- presented,
        with nothing to mark it, as this boot's."""
        vm_status.write_status(self.path, {"dispositions": {"dropped": 7}})
        vm_status.clear_status(self.path)
        self.assertFalse(os.path.exists(self.path))

    def test_it_removes_a_temp_file_left_by_a_killed_writer(self):
        """A SIGKILL between the write and the replace leaves the .tmp, and
        RuntimeDirectoryPreserve keeps it for the life of the host."""
        open(f"{self.path}.tmp", "w").close()
        vm_status.clear_status(self.path)
        self.assertFalse(os.path.exists(f"{self.path}.tmp"))

    def test_a_first_start_has_nothing_to_clear_and_that_is_not_an_error(self):
        vm_status.clear_status(self.path)   # must not raise

    def test_an_unreachable_path_never_fails_the_arm(self):
        """This runs as an ExecStartPre. A diagnostic that could not be
        cleared must not be the reason a VM does not boot."""
        vm_status.clear_status(os.path.join(self.dir, "no", "such", "s.json"))


if __name__ == "__main__":
    unittest.main()
