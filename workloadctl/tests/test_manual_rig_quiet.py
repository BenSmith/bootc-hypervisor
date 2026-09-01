"""`--quiet` must never be the reason a failure went unseen.

WHY THIS EXISTS

inspect_rig.py's --quiet exists to make a hardware run cheap to read back over
ssh: a green run drops from 57 PASS lines, several carrying whole JSON
documents, to a single tally. That is a worthwhile trade exactly once -- for
the passes. A flag that also swallowed a FAIL, or the section header telling
you which phase it was in, would be strictly worse than printing everything,
because the failure detail is the entire product of a run that costs a trip to
a KVM host.

Nothing else can catch that. The rig needs root, KVM and a base image, so the
quiet path runs only in the place where being wrong is most expensive, and
only its FAILING runs exercise the branch that matters -- which are the runs
nobody wants to repeat. So the reporting layer is pinned here, where it can be
imported without any of that.
"""
import importlib.util
import io
import pathlib
import unittest
from contextlib import redirect_stdout

RIG = pathlib.Path(__file__).resolve().parent / "manual" / "inspect_rig.py"


def _load():
    """A fresh module object per test -- the rig keeps its report state in
    module globals, so sharing one instance would leak `results` and the
    remembered section between cases."""
    spec = importlib.util.spec_from_file_location("_rig_inspect_quiet", RIG)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class QuietReportingTest(unittest.TestCase):
    def _run(self, quiet, script):
        mod = _load()
        mod.QUIET = quiet
        buf = io.StringIO()
        with redirect_stdout(buf):
            script(mod)
        return mod, buf.getvalue()

    def test_quiet_suppresses_passes(self):
        _, out = self._run(True, lambda m: m.record("a label", True, "detail"))
        self.assertEqual(out, "")

    def test_quiet_prints_failures_in_full(self):
        """Detail and all: the failure's own evidence is what tells a rig bug
        from a product bug."""
        _, out = self._run(True, lambda m: m.record("a label", False, "detail"))
        self.assertIn("FAIL  a label: detail", out)

    def test_quiet_prints_the_section_of_a_failure(self):
        def script(m):
            m.say("== a phase ==")
            m.record("a label", False, "detail")
        _, out = self._run(True, script)
        self.assertIn("== a phase ==", out)
        self.assertLess(out.index("== a phase =="), out.index("FAIL"))

    def test_the_section_is_printed_once_for_many_failures(self):
        def script(m):
            m.say("== a phase ==")
            m.record("one", False, "d")
            m.record("two", False, "d")
        _, out = self._run(True, script)
        self.assertEqual(out.count("== a phase =="), 1)

    def test_a_later_section_replaces_the_earlier_one(self):
        """The remembered header is the phase the failure is IN, not the first
        phase of the run -- a stale header sends the reader to the wrong place,
        which is the failure mode this whole helper exists to prevent."""
        def script(m):
            m.say("== first ==")
            m.record("passing", True, "d")
            m.say("== second ==")
            m.record("failing", False, "d")
        _, out = self._run(True, script)
        self.assertIn("== second ==", out)
        self.assertNotIn("== first ==", out)

    def test_an_escaping_exception_names_its_phase(self):
        """`_show_section` is what main()'s except clause calls, so a quiet
        run's traceback is not the first thing on an otherwise blank screen."""
        def script(m):
            m.say("== a phase ==")
            m._show_section()
        _, out = self._run(True, script)
        self.assertIn("== a phase ==", out)

    def test_a_full_run_still_prints_everything(self):
        """The default is unchanged. --quiet is opt-in, and a rig invoked the
        way every existing note and script invokes it must behave as it did."""
        def script(m):
            m.say("== a phase ==")
            m.record("a label", True, "detail")
        _, out = self._run(False, script)
        self.assertIn("== a phase ==", out)
        self.assertIn("PASS  a label: detail", out)

    def test_the_flag_exists_by_that_name(self):
        """Pins the spelling `--quiet`, so a rename cannot leave the reporting
        tests above passing while every caller's flag is rejected."""
        import subprocess
        import sys
        p = subprocess.run([sys.executable, str(RIG), "--help"],
                           capture_output=True, text=True, timeout=60)
        self.assertIn("--quiet", p.stdout)


if __name__ == "__main__":
    unittest.main()
