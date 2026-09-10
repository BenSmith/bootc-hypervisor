#!/usr/bin/env python3
"""Rung 5 T3 — drift for the inspector's policy document.

`workloadctl drift` answers "do the running units match what this TOML would
produce". The inspector's policy document is not a unit and is not in the unit
tree: it lives at /run/workload-vm/<name>/inspect.json, is written by
`workload-vm-inspect up` at socket start rather than by the boot generator, and
is read once by the listener at ITS start. So a workload can be exactly in sync
in the unit tree and still have an inspector enforcing the previous start's
policy — the state detail §7.7 names, and the one nothing could see before.

Two properties carry the whole unit:

* the comparison is a BYTE comparison, so there is exactly one renderer
  (`inspect_policy_text`) and `write_policy` writes what it returns; and
* the scan is driven by what is on disk, so a stopped workload with no document
  is not drift while a document whose workload is gone is.

doctor's half of the wiring is gated in test_cmd_doctor.py, where the harness
that drives a whole report already lives.
"""

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import cmd_drift  # noqa: E402
from egress_policy import inspect_policy, inspect_policy_text
from workload_lib import container_inspect_policy_text  # noqa: E402

from tests import load_script

ROOT = Path(__file__).resolve().parent.parent

_INSPECTED = '''\
[vm]
image = "x.qcow2"

[vm.network]
egress = "filtered"
hosts = ["api.example.com"]
'''

# The container shapes. A container writes its policy document to the same
# path, so these are what distinguishes "no renderer for this substrate" from
# "this workload should have no document".
_CONTAINER_INSPECTED = '''\
[container]
image = "example.test/img"

[network]
hosts = ["api.example.com"]
'''

_CONTAINER_PLAIN = '''\
[container]
image = "example.test/img"
'''


class TestThereIsOneRenderer(unittest.TestCase):
    """A formatting difference between writer and comparator would report every
    inspected workload as permanently drifted, which is how a signal stops being
    read. So the bytes come from one function."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_script("libexec/workload-vm-inspect")

    def test_the_text_is_the_document_json_encoded(self):
        net = {"hosts": ["b.example.com", "a.example.com"], "tls": "inspect"}
        text = inspect_policy_text(net)
        self.assertEqual(json.loads(text), inspect_policy(net))

    def test_the_text_ends_in_a_newline(self):
        # A text file ends in one; without it every hunk of the drift diff
        # carries "\\ No newline at end of file".
        self.assertTrue(inspect_policy_text({}).endswith("\n"))

    def test_the_keys_are_sorted(self):
        # The document has to be a pure function of the TOML, and dict order
        # is not. Finding 1 of the rung plan rests on this.
        text = inspect_policy_text({"hosts": ["a"]})
        keys = [line.split('"')[1] for line in text.splitlines()
                if line.startswith('  "')]
        self.assertEqual(keys, sorted(keys))

    def test_write_policy_writes_exactly_that_text(self):
        """The gate. Not a source pin: the file is written and read back."""
        net = {"egress": "filtered", "hosts": ["api.example.com"]}
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "inspect.json")
            with mock.patch.object(self.mod, "network_config",
                                   lambda _name: net), \
                 mock.patch.object(self.mod, "inspect_policy_path",
                                   lambda _name: path), \
                 mock.patch.object(self.mod.os, "chown", lambda *a: None), \
                 mock.patch.object(self.mod.pwd, "getpwnam",
                                   lambda _n: mock.Mock(pw_gid=10000)):
                self.mod.write_policy("demo")
            self.assertEqual(Path(path).read_text(), inspect_policy_text(net))


class _PolicyDriftCase(unittest.TestCase):
    """A staged config dir and a staged /run/workload-vm, and nothing else."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="policy-drift-")
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.cfg = root / "cfg"
        self.cfg.mkdir()
        self.run = root / "run-vm"
        self.run.mkdir()
        self.enterContext(mock.patch.object(
            cmd_drift, "POLICY_ROOT", self.run))
        self.enterContext(mock.patch.object(
            cmd_drift, "workload_config_path",
            lambda name: self.cfg / name / "workload.toml"))

    def _config(self, name, text=_INSPECTED):
        d = self.cfg / name
        d.mkdir(exist_ok=True)
        (d / "workload.toml").write_text(text)

    def _document(self, name, text=None):
        d = self.run / name
        d.mkdir(exist_ok=True)
        if text is None:
            import tomllib
            with open(self.cfg / name / "workload.toml", "rb") as f:
                net = tomllib.load(f)["vm"]["network"]
            text = inspect_policy_text(net)
        (d / "inspect.json").write_text(text)
        return d / "inspect.json"


class TestWhatCountsAsDrift(_PolicyDriftCase):
    def test_a_document_matching_its_toml_is_not_drift(self):
        self._config("demo")
        self._document("demo")
        self.assertEqual(cmd_drift.collect_policy_drift(), [])

    def test_an_edited_toml_is_drift(self):
        self._config("demo")
        self._document("demo")
        self._config("demo", _INSPECTED.replace("api.example.com",
                                                "other.example.com"))
        diffs = cmd_drift.collect_policy_drift()
        self.assertEqual([f for f, _, _ in diffs], ["demo/inspect.json"])
        live, gen = diffs[0][1], diffs[0][2]
        self.assertIn("api.example.com", live)
        self.assertIn("other.example.com", gen)

    def test_a_workload_that_never_started_is_not_drift(self):
        """No document at all. The ordinary state of a stopped VM — reporting
        it would mark every stopped workload as drifted forever."""
        self._config("demo")
        self.assertEqual(cmd_drift.collect_policy_drift(), [])

    def test_an_inspected_container_is_COMPARED_not_skipped(self):
        """G8 routed: the container renderer is what it is compared against.

        History, because both wrong answers shipped. First `_rendered_policy`
        returned "" -- the orphan answer -- and every inspected container read
        as a whole file REMOVED: permanent drift on a healthy workload, with a
        remedy (restart) that could not clear it, and `doctor` carrying the
        same diff. FOUND ON HARDWARE 2026-09-05. Then it returned None, which
        is "no renderer for this substrate", and the caller skipped -- honest,
        but it meant no container's document was ever checked.

        Now it renders. A document matching the TOML is not drift.
        """
        self._config("cwl", _CONTAINER_INSPECTED)
        self._document("cwl", container_inspect_policy_text(
            {"hosts": ["api.example.com"]}))
        self.assertEqual(cmd_drift.collect_policy_drift(), [])

    def test_an_inspected_containers_STALE_document_is_reported(self):
        """What the skip was costing. This is the case the whole comparison
        exists for, and it was unreachable for containers for as long as the
        renderer was VM-only -- an edited allowlist that never reached the
        listener looked exactly like a healthy workload."""
        self._config("cwl", _CONTAINER_INSPECTED)
        self._document("cwl", container_inspect_policy_text(
            {"hosts": ["stale.example.com"]}))
        diffs = cmd_drift.collect_policy_drift()
        self.assertEqual([f for f, _, _ in diffs], ["cwl/inspect.json"])
        self.assertIn("stale.example.com", diffs[0][1])
        self.assertIn("api.example.com", diffs[0][2])

    def test_a_container_is_compared_against_the_CONTAINER_renderer(self):
        """The reason routing the predicate alone was refused.

        A hosts-only container is "splice" by the three-rung ladder and the VM
        renderer would default the same TOML to "inspect". Comparing a
        container's document against the VM render would report drift on every
        inspected container on the fleet -- forever, and unclearable -- which
        is how a drift signal stops being read.
        """
        self._config("cwl", _CONTAINER_INSPECTED)
        self._document("cwl", container_inspect_policy_text(
            {"hosts": ["api.example.com"]}))
        self.assertEqual(cmd_drift.collect_policy_drift(), [])
        self.assertIn('"tls": "splice"', container_inspect_policy_text(
            {"hosts": ["api.example.com"]}))

    def test_an_uninspected_containers_leftover_document_is_still_an_orphan(self):
        """The other side of the skip above. A container that has no [network]
        trigger should have no document, so one on disk is the same stale-file
        condition a de-filtered VM leaves and must still be reported."""
        self._config("cwl", _CONTAINER_PLAIN)
        self._document("cwl", '{"hosts": ["example.com"]}\n')
        diffs = cmd_drift.collect_policy_drift()
        self.assertEqual([f for f, _, _ in diffs], ["cwl/inspect.json"])
        self.assertEqual(diffs[0][2], "")

    def test_a_document_whose_workload_is_gone_is_an_orphan(self):
        self._config("demo")
        self._document("demo")
        (self.cfg / "demo" / "workload.toml").unlink()
        diffs = cmd_drift.collect_policy_drift()
        self.assertEqual([f for f, _, _ in diffs], ["demo/inspect.json"])
        self.assertEqual(diffs[0][2], "")

    def test_a_document_whose_workload_stopped_being_inspected_is_an_orphan(self):
        """`egress = "open"` removes the inspector but not the file `down`
        never deletes. An operator reading the stale document has no way to
        tell it from a live one."""
        self._config("demo")
        self._document("demo")
        self._config("demo", _INSPECTED.replace('egress = "filtered"',
                                                'egress = "open"'))
        diffs = cmd_drift.collect_policy_drift()
        self.assertEqual([f for f, _, _ in diffs], ["demo/inspect.json"])
        self.assertEqual(diffs[0][2], "")

    def test_an_unparseable_toml_is_loud(self):
        """Not skipped: it is the state in which the document is least likely
        to match, so omitting it makes "No drift detected" a false all-clear."""
        self._config("demo")
        self._document("demo")
        self._config("demo", "this is not = = toml")
        with self.assertRaises(RuntimeError):
            cmd_drift.collect_policy_drift()

    def test_the_workload_filter_scopes_it(self):
        for name in ("demo", "other"):
            self._config(name)
            self._document(name)
            self._config(name, _INSPECTED.replace("api", name))
        self.assertEqual([f for f, _, _ in cmd_drift.collect_policy_drift("demo")],
                         ["demo/inspect.json"])

    def test_a_missing_root_is_empty_not_an_error(self):
        # /run/workload-vm does not exist on a host that has never run a VM.
        # Pinned as behaviour rather than guarded in code: Path.glob on a
        # missing directory already yields nothing.
        with mock.patch.object(cmd_drift, "POLICY_ROOT", self.run / "nope"):
            self.assertEqual(cmd_drift.collect_policy_drift(), [])

    def test_the_tuple_shape_is_the_one_doctor_consumes(self):
        self._config("demo")
        self._document("demo", "{}\n")
        for fname, live, gen in cmd_drift.collect_policy_drift():
            self.assertIsInstance(fname, str)
            self.assertIsInstance(live, str)
            self.assertIsInstance(gen, str)


class TestTheCommandReportsIt(_PolicyDriftCase):
    """cmd_drift renders it with the diff it already has, and names the remedy
    that differs."""

    def setUp(self):
        super().setUp()
        self.enterContext(mock.patch.object(
            cmd_drift, "collect_drift", lambda name=None: []))

    def _run(self, workload=None, json_output=False):
        args = argparse.Namespace(workload=workload, json=json_output)
        out = io.StringIO()
        code = None
        try:
            with redirect_stdout(out):
                cmd_drift.cmd_drift(args, manager=None)
        except SystemExit as e:
            code = e.code
        return code, out.getvalue()

    def _drifted(self):
        self._config("demo")
        self._document("demo")
        self._config("demo", _INSPECTED.replace("api.example.com", "edited"))

    def test_a_clean_host_still_says_no_drift(self):
        self._config("demo")
        self._document("demo")
        code, out = self._run()
        self.assertEqual(code, 0)
        self.assertIn("No drift", out)

    def test_the_document_is_named_and_diffed(self):
        self._drifted()
        code, out = self._run()
        self.assertEqual(code, 1)
        self.assertIn("demo/inspect.json", out)
        self.assertIn("-", out)
        self.assertIn("edited", out)

    def test_the_remedy_is_a_restart_not_a_regenerate(self):
        """The document is written by the inspect socket's ExecStartPre and
        read once at listener start, so regenerating the unit tree applies
        nothing. An operator handed the unit-tree remedy would run it, see the
        drift persist, and conclude the report was wrong."""
        self._drifted()
        _code, out = self._run()
        self.assertIn("systemctl restart workload-demo-inspect.socket", out)

    def test_json_puts_it_under_documents_not_units(self):
        """A consumer that fed this to `systemctl daemon-reload` would be
        acting on the wrong noun."""
        self._drifted()
        code, out = self._run(json_output=True)
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertTrue(payload["drifted"])
        self.assertEqual(payload["units"], [])
        self.assertEqual([d["document"] for d in payload["documents"]],
                         ["demo/inspect.json"])
        self.assertIn("edited", payload["documents"][0]["diff"])

    def test_json_on_a_clean_host_is_not_drifted(self):
        self._config("demo")
        self._document("demo")
        code, out = self._run(json_output=True)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertFalse(payload["drifted"])
        self.assertEqual(payload["documents"], [])


if __name__ == "__main__":
    unittest.main()
