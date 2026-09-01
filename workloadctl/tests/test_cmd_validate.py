#!/usr/bin/env python3
"""Unit tests for cmd_validate dispatch (the --all aggregation wrapper).

validate_single's per-check logic is covered in test_cmd_admin.py /
test_json_output.py. This pins the dispatcher around it: the --all rollup
(all_passed reflects the worst single result), the json-vs-text branch, the
exit codes, and the single-workload "name required" guard. validate_single
itself is stubbed so each test controls pass/fail directly.
"""

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock


import cmd_validate  # noqa: E402
import workload_lib  # noqa: E402
from workloadctl_core import WorkloadConfig, WorkloadManager  # noqa: E402


def _ns(**kw):
    base = dict(all=False, json=False, workload=None)
    base.update(kw)
    return argparse.Namespace(**base)


class ValidateDispatchTest(unittest.TestCase):
    def setUp(self):
        self.manager = mock.Mock()
        # Map config name -> passed bool; validate_single stub honors it.
        self.verdicts: dict = {}

        def fake_validate(config, manager, json_mode=False):
            name = getattr(config, "name", config)
            passed = self.verdicts.get(name, True)
            return {"workload": name, "passed": passed, "checks": []}

        self.enterContext(mock.patch.object(cmd_validate, "validate_single", fake_validate))
        self.enterContext(mock.patch.object(
            cmd_validate, "WorkloadConfig",
            lambda n: argparse.Namespace(name=n)))

    def _run(self, **kw):
        out, err = io.StringIO(), io.StringIO()
        code = None
        try:
            with redirect_stdout(out), redirect_stderr(err):
                cmd_validate.cmd_validate(_ns(**kw), self.manager)
        except SystemExit as e:
            code = e.code
        self._out, self._err = out.getvalue(), err.getvalue()
        return code

    def _set_configs(self, *names):
        self.manager.get_all_configs.return_value = [
            argparse.Namespace(name=n) for n in names]

    # --- --all rollup ------------------------------------------------------

    def test_all_pass_exits_0(self):
        self._set_configs("a", "b")
        self.assertEqual(self._run(all=True), 0)

    def test_all_one_failure_exits_1(self):
        self._set_configs("a", "b", "c")
        self.verdicts["b"] = False
        self.assertEqual(self._run(all=True), 1)

    def test_all_empty_exits_0(self):
        self._set_configs()
        self.assertEqual(self._run(all=True), 0)

    def test_all_json_reports_each_and_rollup(self):
        self._set_configs("a", "b")
        self.verdicts["a"] = False
        code = self._run(all=True, json=True)
        self.assertEqual(code, 1)
        doc = json.loads(self._out)
        self.assertEqual([r["workload"] for r in doc["validation_results"]], ["a", "b"])
        self.assertFalse(doc["all_passed"])

    # --- single workload ---------------------------------------------------

    def test_single_requires_name(self):
        code = self._run(all=False, workload=None)
        self.assertEqual(code, 1)
        self.assertIn("required", self._err)

    def test_single_pass_exits_0(self):
        code = self._run(workload="web")
        self.assertEqual(code, 0)

    def test_single_fail_exits_1(self):
        self.verdicts["web"] = False
        code = self._run(workload="web")
        self.assertEqual(code, 1)

    def test_single_json_emits_one_result(self):
        code = self._run(workload="web", json=True)
        self.assertEqual(code, 0)
        doc = json.loads(self._out)
        self.assertEqual(doc["workload"], "web")
        self.assertTrue(doc["passed"])


class ValidateSingleCredentialsTest(unittest.TestCase):
    """validate_single cross-checks ${SECRET:name} references against the
    credstore so a missing secret is a named, config-time error instead of a
    cryptic namespace/ExecStart failure at service-start time."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.credstore = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(cmd_validate, "CREDSTORE_DIR", self.credstore))

    def _validate(self, name, toml):
        (self.tmp / name).mkdir()
        (self.tmp / name / "workload.toml").write_text(toml)
        config = WorkloadConfig(name)
        manager = mock.Mock(spec=WorkloadManager)
        manager.user_exists.return_value = False
        manager.get_all_configs.return_value = []
        return cmd_validate.validate_single(config, manager, json_mode=True)

    def test_no_secret_refs_ok(self):
        result = self._validate(
            "clitest-nosecret",
            '[workload]\nname = "clitest-nosecret"\n\n'
            '[container]\nimage = "x:latest"\n',
        )
        creds = [c for c in result["checks"] if c["check"] == "credentials"]
        self.assertEqual(len(creds), 1)
        self.assertTrue(creds[0]["passed"])
        self.assertEqual(creds[0]["message"], "No credential references")

    def test_all_refs_present_ok(self):
        (self.credstore / "dbpass").write_text("secret")
        result = self._validate(
            "clitest-present",
            '[workload]\nname = "clitest-present"\n\n'
            '[container]\nimage = "x:latest"\n'
            '[container.environment]\nDB_PASS = "${SECRET:dbpass}"\n',
        )
        creds = [c for c in result["checks"] if c["check"] == "credentials"]
        self.assertEqual(len(creds), 1)
        self.assertTrue(creds[0]["passed"])
        self.assertIn("dbpass", creds[0]["message"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["errors"], 0)

    def test_missing_ref_errors(self):
        result = self._validate(
            "clitest-missing",
            '[workload]\nname = "clitest-missing"\n\n'
            '[container]\nimage = "x:latest"\n'
            '[container.environment]\nDB_PASS = "${SECRET:dbpass}"\n',
        )
        creds = [c for c in result["checks"] if c["check"] == "credentials"]
        self.assertTrue(creds and not creds[0]["passed"])
        self.assertIn("dbpass", creds[0]["message"])
        self.assertFalse(result["passed"])
        self.assertGreaterEqual(result["errors"], 1)

    def test_permission_error_warns_not_errors(self):
        class _NoPermDir:
            """Stands in for a 0700 credstore this process can't read into."""
            def __truediv__(self, other):
                raise PermissionError(13, "Permission denied")

        with mock.patch.object(cmd_validate, "CREDSTORE_DIR", _NoPermDir()):
            result = self._validate(
                "clitest-noperm",
                '[workload]\nname = "clitest-noperm"\n\n'
                '[container]\nimage = "x:latest"\n'
                '[container.environment]\nDB_PASS = "${SECRET:dbpass}"\n',
            )
        creds = [c for c in result["checks"] if c["check"] == "credentials"]
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["severity"], "warning")
        self.assertTrue(creds[0]["passed"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["errors"], 0)
        self.assertGreaterEqual(result["warnings"], 1)


class ValidateSingleBrokerCredentialsTest(unittest.TestCase):
    """The same question one subtree down, and the only check that answers it.

    Broker material cannot be reached by the ${SECRET:} check and never will
    be: SECRET_PATTERN has no `/`, which is exactly what keeps it out of
    workload env -- so auto_detect_credentials returns nothing for it by
    construction and the existing check is silent on a workload whose provider
    keys are all missing.

    That silence is also what makes this the actionable half of a gap `backup`
    leaves on purpose. `backup` copies the credentials a config DEMANDS, which
    is those same ${SECRET:} occurrences, so a restored workload comes back
    without its provider keys -- and RESTORE says nothing, because the restored
    config demands no ${SECRET:} the archive lacks. This check is what fires on
    the restored host and names the material.
    """

    TOML = """
[workload]
name = "{name}"

[vm]
image = "https://example.invalid/x.qcow2"

[vm.network]
hosts = ["api.example.com"]

[[vm.network.credential]]
name = "tok"
placeholder = "sk-000000000000PLACEHOLDER"
env = "API_TOKEN"

[[vm.network.policy]]
host = "api.example.com"
methods = ["GET"]
paths = ["/v1/*"]
credential = "tok"
"""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(
            workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.credstore = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(
            cmd_validate, "CREDSTORE_DIR", self.credstore))

    def _validate(self, name, toml=None):
        (self.tmp / name).mkdir()
        (self.tmp / name / "workload.toml").write_text(
            (toml or self.TOML).format(name=name))
        config = WorkloadConfig(name)
        manager = mock.Mock(spec=WorkloadManager)
        manager.user_exists.return_value = False
        manager.get_all_configs.return_value = []
        return cmd_validate.validate_single(config, manager, json_mode=True)

    def _checks(self, result):
        return [c for c in result["checks"] if c["check"] == "broker-credentials"]

    def test_missing_material_is_an_error_naming_the_scoped_name(self):
        checks = self._checks(self._validate("clitest-brokermissing"))
        self.assertEqual(len(checks), 1, checks)
        self.assertFalse(checks[0]["passed"])
        self.assertIn("tok", checks[0]["message"])
        # The fix is the command that creates it, at the scoped name -- an
        # operator on a restored host has no other way to learn the path.
        self.assertIn("broker/clitest-brokermissing/tok", checks[0]["fix"])

    def test_present_material_passes(self):
        name = "clitest-brokerpresent"
        path = self.credstore / "broker" / name / "tok"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"sealed")
        checks = self._checks(self._validate(name))
        self.assertEqual(len(checks), 1, checks)
        self.assertTrue(checks[0]["passed"])
        self.assertIn("tok", checks[0]["message"])

    def test_another_workloads_material_does_not_satisfy_it(self):
        """The scope is the point. Material under a different workload is not
        this workload's, and a check reading only the leaf name would call a
        missing key present on any host where some other workload has one."""
        name = "clitest-brokerscope"
        path = self.credstore / "broker" / "someone-else" / "tok"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"sealed")
        checks = self._checks(self._validate(name))
        self.assertFalse(checks[0]["passed"], checks)

    def test_a_workload_with_no_credential_blocks_gets_no_check(self):
        """Silence rather than an "ok" row: almost every workload on a host has
        no broker material, and a passing row on each of them is a line that
        stops being read."""
        result = self._validate(
            "clitest-nobroker",
            '[workload]\nname = "{name}"\n\n'
            '[container]\nimage = "x:latest"\n')
        self.assertEqual(self._checks(result), [])

    def test_the_secret_check_stays_silent_about_broker_material(self):
        """The two checks must not both claim it: auto_detect_credentials
        cannot see a credential block, so a "credentials" row mentioning `tok`
        would mean something started scanning the wrong table."""
        result = self._validate("clitest-brokeronly")
        creds = [c for c in result["checks"] if c["check"] == "credentials"]
        self.assertEqual(len(creds), 1)
        self.assertNotIn("tok", creds[0]["message"])


class ValidateSingleBuildTest(unittest.TestCase):
    """validate_single's [build]/[containers.build] checks: containerfile paths
    must stay inside the build context, per-container containerfiles are checked
    (and labeled) individually, shared-image build conflicts are lint errors
    instead of build-time crashes, and a name-less container (a schema error in
    its own right) must not crash the linter."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))

    def _validate(self, name, toml):
        (self.tmp / name).mkdir()
        (self.tmp / name / "workload.toml").write_text(toml)
        config = WorkloadConfig(name)
        manager = mock.Mock(spec=WorkloadManager)
        manager.user_exists.return_value = False
        manager.get_all_configs.return_value = []
        return cmd_validate.validate_single(config, manager, json_mode=True)

    @staticmethod
    def _checks(result, name):
        return [c for c in result["checks"] if c["check"] == name]

    def test_build_summary_lists_workload_and_container_files(self):
        result = self._validate(
            "clitest-multi",
            '[workload]\nname = "clitest-multi"\nmode = "pod"\n'
            '[build]\ncontainerfile = "Containerfile.default"\n'
            '[[containers]]\nname = "a"\n'
            '[containers.container]\nimage = "localhost/a:latest"\npull = "never"\n'
            '[containers.build]\ncontainerfile = "Containerfile.a"\n'
            '[[containers]]\nname = "b"\n'
            '[containers.container]\nimage = "localhost/b:latest"\npull = "never"\n',
        )
        ok = self._checks(result, "build")
        self.assertEqual(len(ok), 1)
        self.assertIn("Containerfile.default", ok[0]["message"])
        self.assertIn("Containerfile.a", ok[0]["message"])

    def test_per_container_traversal_containerfile_errors(self):
        result = self._validate(
            "clitest-badcf",
            '[workload]\nname = "clitest-badcf"\nmode = "pod"\n'
            '[[containers]]\nname = "a"\n'
            '[containers.container]\nimage = "localhost/a:latest"\npull = "never"\n'
            '[containers.build]\ncontainerfile = "../escape"\n',
        )
        bad = self._checks(result, "build_containerfile")
        self.assertEqual(len(bad), 1)
        self.assertIn("(a)", bad[0]["message"])
        self.assertFalse(result["passed"])
        # No misleading ok-summary alongside the error.
        self.assertEqual(self._checks(result, "build"), [])

    def test_shared_image_build_conflict_errors(self):
        result = self._validate(
            "clitest-conflict",
            '[workload]\nname = "clitest-conflict"\nmode = "pod"\n'
            '[[containers]]\nname = "a"\n'
            '[containers.container]\nimage = "localhost/shared:latest"\npull = "never"\n'
            '[containers.build]\ncontainerfile = "Containerfile.a"\n'
            '[[containers]]\nname = "b"\n'
            '[containers.container]\nimage = "localhost/shared:latest"\npull = "never"\n'
            '[containers.build]\ncontainerfile = "Containerfile.b"\n',
        )
        conflict = self._checks(result, "build_conflict")
        self.assertEqual(len(conflict), 1)
        self.assertIn("shared", conflict[0]["message"])
        self.assertFalse(result["passed"])

    def test_nameless_container_does_not_crash_linter(self):
        result = self._validate(
            "clitest-noname",
            '[workload]\nname = "clitest-noname"\nmode = "pod"\n'
            '[[containers]]\n'
            '[containers.container]\nimage = "localhost/x:latest"\npull = "never"\n'
            '[containers.build]\ncontainerfile = "../escape"\n',
        )
        bad = self._checks(result, "build_containerfile")
        self.assertEqual(len(bad), 1)
        self.assertIn("containers[0]", bad[0]["message"])
        self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()


class ValidateSingleInlinedSecretsTest(unittest.TestCase):
    """validate_single flags credential-shaped literals typed into a config.

    The mirror of the credentials check: that one asks whether the credstore
    holds what the config references, this one asks whether someone skipped the
    credstore. Nothing sets a mode on /etc/workloads.d/*/workload.toml, so a
    pasted key is world-readable on the host.
    """

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        self.credstore = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(cmd_validate, "CREDSTORE_DIR", self.credstore))

    def _checks(self, name, toml):
        (self.tmp / name).mkdir()
        (self.tmp / name / "workload.toml").write_text(toml)
        config = WorkloadConfig(name)
        manager = mock.Mock(spec=WorkloadManager)
        manager.user_exists.return_value = False
        manager.get_all_configs.return_value = []
        result = cmd_validate.validate_single(config, manager, json_mode=True)
        return [c for c in result["checks"] if c["check"] == "inlined_secrets"]

    def test_clean_config_passes(self):
        checks = self._checks(
            "clitest-noinline",
            '[workload]\nname = "clitest-noinline"\n\n'
            '[container]\nimage = "x:latest"\n'
            '[container.environment]\nTOKEN = "${SECRET:gh-token}"\n',
        )
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0]["passed"])

    def test_pasted_key_warns_and_names_the_path(self):
        checks = self._checks(
            "clitest-inline",
            '[workload]\nname = "clitest-inline"\n\n'
            '[container]\nimage = "x:latest"\n'
            '[container.environment]\nGITHUB_TOKEN = "ghp_' + "a" * 36 + '"\n',
        )
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0]["passed"])
        # A warning, not an error: the check is a prefix heuristic, and blocking
        # enable on a guess is how a check gets routed around.
        self.assertEqual(checks[0]["severity"], "warning")
        self.assertIn("container.environment.GITHUB_TOKEN", checks[0]["message"])
        self.assertIn("GitHub token", checks[0]["message"])

    def test_message_never_carries_the_value(self):
        """validate output gets pasted into issues and chat, so a check whose
        point is 'this secret is in the wrong place' must not copy it into a
        second wrong place."""
        secret = "ghp_" + "b" * 36
        checks = self._checks(
            "clitest-inline-quiet",
            '[workload]\nname = "clitest-inline-quiet"\n\n'
            '[container]\nimage = "x:latest"\n'
            '[container.environment]\nGITHUB_TOKEN = "' + secret + '"\n',
        )
        self.assertFalse(checks[0]["passed"])
        for field in checks[0].values():
            self.assertNotIn(secret, str(field))

    def test_vm_placeholder_is_exempt(self):
        """The fake credential a sandboxed guest holds is key-shaped on purpose;
        flagging it would fire on every correct credential-backed workload."""
        checks = self._checks(
            "clitest-placeholder",
            '[workload]\nname = "clitest-placeholder"\n\n'
            '[vm]\nmemory = "2G"\n\n'
            '[[vm.network.policy]]\nhost = "api.github.com"\n'
            'credential = "gh-token"\n'
            'placeholder = "ghp_' + "0" * 36 + '"\n',
        )
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0]["passed"])
