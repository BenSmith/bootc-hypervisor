#!/usr/bin/env python3
"""Unit tests for cli_log — the prose channel and the mutating verbs' JSON result.

Two invariants carry the whole design and are what these tests pin:

- **Prose vs output.** `--quiet` may silence narration (info) but must never
  silence a failure (warn/error), and must never eat a command's actual output
  — the dry-run plans and reports still print, because they go through print(),
  not cli_log.
- **Stdout is the result document.** Under `--json` nothing else may land on
  stdout, or `workloadctl update --all --json | jq` breaks on the first
  progress line.
"""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

import cli_log


class CliLogRoutingTest(unittest.TestCase):
    """Severity decides the stream; the mode decides whether it speaks."""

    def setUp(self):
        self.addCleanup(cli_log.reset)
        cli_log.reset()

    def _emit_all(self):
        """Emit one of each severity; return (stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            cli_log.info("progress")
            cli_log.warn("careful")
            cli_log.error("broken")
        return out.getvalue(), err.getvalue()

    def test_default_mode_splits_streams(self):
        out, err = self._emit_all()
        self.assertEqual(out, "progress\n")
        self.assertIn("careful", err)
        self.assertIn("broken", err)
        self.assertNotIn("careful", out)

    def test_quiet_drops_prose_but_not_failures(self):
        cli_log.configure(quiet=True)
        out, err = self._emit_all()
        self.assertEqual(out, "")
        self.assertIn("careful", err)
        self.assertIn("broken", err)

    def test_json_mode_reserves_stdout(self):
        # Prose on stdout would corrupt the result document — a scripted caller
        # pipes stdout straight into a parser.
        cli_log.configure(json_mode=True, command="update")
        out, err = self._emit_all()
        self.assertEqual(out, "")
        self.assertIn("broken", err)

    def test_partial_writes_without_newline_and_honors_quiet(self):
        out = io.StringIO()
        with redirect_stdout(out):
            cli_log.partial("waiting...")
            cli_log.info(" done")
        self.assertEqual(out.getvalue(), "waiting... done\n")

        cli_log.configure(quiet=True)
        out = io.StringIO()
        with redirect_stdout(out):
            cli_log.partial("waiting...")
        self.assertEqual(out.getvalue(), "")

    def test_handlers_follow_a_redirected_stream(self):
        # The handler must resolve sys.stdout per record, not bind it once at
        # import: every caller that captures output (this suite included)
        # replaces the stream long after cli_log was imported.
        first, second = io.StringIO(), io.StringIO()
        with redirect_stdout(first):
            cli_log.info("one")
        with redirect_stdout(second):
            cli_log.info("two")
        self.assertEqual(first.getvalue(), "one\n")
        self.assertEqual(second.getvalue(), "two\n")

    def test_is_quiet_covers_both_suppressing_modes(self):
        self.assertFalse(cli_log.is_quiet())
        cli_log.configure(quiet=True)
        self.assertTrue(cli_log.is_quiet())
        cli_log.configure(json_mode=True)
        self.assertTrue(cli_log.is_quiet())
        self.assertTrue(cli_log.json_enabled())


class EmitResultTest(unittest.TestCase):
    """The result document: shape, and who is allowed to write it."""

    def setUp(self):
        self.addCleanup(cli_log.reset)
        cli_log.reset()

    def _capture(self, fn):
        out = io.StringIO()
        with redirect_stdout(out):
            fn()
        return out.getvalue()

    def test_no_output_unless_json_mode(self):
        text = self._capture(
            lambda: cli_log.emit_result([{"workload": "w", "result": "enabled"}]))
        self.assertEqual(text, "")

    def test_result_shape(self):
        cli_log.configure(json_mode=True, command="enable")
        text = self._capture(
            lambda: cli_log.emit_result([{"workload": "w", "result": "enabled"}]))
        payload = json.loads(text)
        self.assertEqual(payload["command"], "enable")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["workloads"],
                         [{"workload": "w", "result": "enabled"}])

    def test_extra_keys_ride_at_top_level(self):
        cli_log.configure(json_mode=True, command="update")
        text = self._capture(
            lambda: cli_log.emit_result([], summary={"updated": 0}))
        self.assertEqual(json.loads(text)["summary"], {"updated": 0})

    def test_non_serializable_values_degrade_to_str(self):
        # A VM rollback target names its generation file as a Path. A
        # serialization crash must not be how an operator learns the command ran.
        from pathlib import Path
        cli_log.configure(json_mode=True, command="rollback")
        text = self._capture(lambda: cli_log.emit_result(
            [{"workload": "vm", "result": "listed",
              "targets": [{"path": Path("/var/lib/x/system.qcow2.gen-3")}]}]))
        target = json.loads(text)["workloads"][0]["targets"][0]
        self.assertEqual(target["path"], "/var/lib/x/system.qcow2.gen-3")

    def test_failure_document_when_command_died(self):
        cli_log.configure(json_mode=True, command="enable")
        text = self._capture(lambda: cli_log.emit_failure("boom"))
        payload = json.loads(text)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "boom")
        self.assertEqual(payload["workloads"], [])

    def test_failure_never_overwrites_a_reported_result(self):
        # `update --all` reports per-workload rows and *then* exits nonzero.
        # The exit ladder's backstop must not append a second, poorer document.
        cli_log.configure(json_mode=True, command="update")
        text = self._capture(lambda: (
            cli_log.emit_result([{"workload": "a", "result": "failed"}], ok=False),
            cli_log.emit_failure("command failed (exit 1); see stderr"),
        ))
        self.assertEqual(len(text.strip().split("\n}\n")), 1)
        payload = json.loads(text)
        self.assertEqual(payload["workloads"], [{"workload": "a", "result": "failed"}])


if __name__ == "__main__":
    unittest.main()
