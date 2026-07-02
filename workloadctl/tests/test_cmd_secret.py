#!/usr/bin/env python3
"""Unit tests for cmd_secret subcommands and the passphrase handling.

Only `secret list --json` was covered before. These exercise the
create/delete/rotate/export/import argument, path, and error logic that runs
*before* (and around) the external systemd-creds/openssl calls — those calls
are stubbed. The credstore lives at a hardcoded /etc path, so we redirect just
that one Path() through a tmp dir; everything else uses real paths.
"""

import argparse
import io
import os
import pathlib
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

import workload_lib          # noqa: E402
import cmd_secret           # noqa: E402
import workloadctl_core     # noqa: E402

_REAL_PATH = pathlib.Path


def _ns(**kw):
    return argparse.Namespace(**kw)


def _run(args):
    """Run cmd_secret, capturing stdout/stderr and any SystemExit code."""
    out, err = io.StringIO(), io.StringIO()
    code = None
    manager = mock.Mock()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            cmd_secret.cmd_secret(args, manager)
    except SystemExit as e:
        code = e.code
    return out.getvalue(), err.getvalue(), code


class SecretTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.cred_dir = self.tmp / "credstore"
        self.wl_dir = self.tmp / "workloads"
        self.wl_dir.mkdir()

        # Redirect only the hardcoded credstore path; all other Path() calls
        # (temp files, args.file, ...) fall through to the real thing.
        def _fake_path(p, *a):
            if str(p) == "/etc/credstore.encrypted":
                return self.cred_dir
            return _REAL_PATH(p, *a)

        self.enterContext(mock.patch.object(cmd_secret, "Path", _fake_path))
        self.enterContext(mock.patch.object(cmd_secret, "require_root", lambda: None))
        self.enterContext(mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.wl_dir))

    def _seed_cred(self, name, content=b"blob"):
        self.cred_dir.mkdir(parents=True, exist_ok=True)
        (self.cred_dir / name).write_bytes(content)


class CreateTest(SecretTestBase):
    def test_rejects_invalid_name(self):
        out, err, code = _run(_ns(subcommand="create", name="bad name",
                                  force=False, key_type=None, file=None))
        self.assertEqual(code, 1)
        self.assertIn("only letters", err)

    def test_existing_without_force_errors(self):
        self._seed_cred("api")
        out, err, code = _run(_ns(subcommand="create", name="api",
                                  force=False, key_type=None, file=None))
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)

    def test_create_from_stdin_builds_tpm2_command(self):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            _REAL_PATH(cmd[-1]).write_bytes(b"x")  # systemd-creds writes the blob
            return types.SimpleNamespace(returncode=0)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run):
            out, err, code = _run(_ns(subcommand="create", name="api",
                                      force=False, key_type=None, file=None))
        self.assertIsNone(code)
        cmd = captured["cmd"]
        self.assertEqual(cmd[:2], ["systemd-creds", "encrypt"])
        self.assertIn("--with-key=tpm2", cmd)       # default key type
        self.assertIn("--name=api", cmd)
        self.assertEqual(cmd[-1], str(self.cred_dir / "api"))

    def test_create_key_type_and_file_mode(self):
        secret_file = self.tmp / "plain.txt"
        secret_file.write_text("hunter2")
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            _REAL_PATH(cmd[-1]).write_bytes(b"x")
            return types.SimpleNamespace(returncode=0)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run):
            out, err, code = _run(_ns(subcommand="create", name="api",
                                      force=False, key_type="host",
                                      file=str(secret_file)))
        self.assertIsNone(code)
        cmd = captured["cmd"]
        self.assertIn("--with-key=host", cmd)        # override honored
        self.assertIn(str(secret_file), cmd)         # file path passed through
        self.assertNotIn("--name=api", cmd)          # --name only for stdin mode


class DeleteTest(SecretTestBase):
    def test_missing_errors(self):
        out, err, code = _run(_ns(subcommand="delete", name="ghost", force=True))
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_force_deletes(self):
        self._seed_cred("api")
        out, err, code = _run(_ns(subcommand="delete", name="api", force=True))
        self.assertIsNone(code)
        self.assertFalse((self.cred_dir / "api").exists())

    def test_prompt_no_cancels(self):
        self._seed_cred("api")
        with mock.patch("builtins.input", lambda prompt="": "n"):
            out, err, code = _run(_ns(subcommand="delete", name="api", force=False))
        self.assertIsNone(code)
        self.assertIn("Cancelled", out)
        self.assertTrue((self.cred_dir / "api").exists())  # untouched


class RotateTest(SecretTestBase):
    def test_missing_errors(self):
        out, err, code = _run(_ns(subcommand="rotate", name="ghost", key_type=None))
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_detects_affected_workloads_via_env_ref(self):
        self._seed_cred("api-key")
        (self.wl_dir / "web").mkdir()
        (self.wl_dir / "web" / "workload.toml").write_text(
            '[workload]\nname = "web"\n[container]\nimage = "x"\n'
            '[container.environment]\nTOKEN = "${SECRET:api-key}"\n')
        (self.wl_dir / "other").mkdir()
        (self.wl_dir / "other" / "workload.toml").write_text(
            '[workload]\nname = "other"\n[container]\nimage = "y"\n')

        # Stub the encrypt + any restart so we only assert the detection output.
        with mock.patch.object(cmd_secret.subprocess, "run",
                               lambda *a, **k: types.SimpleNamespace(returncode=0)), \
             mock.patch.object(cmd_secret, "restart_workload_service", lambda *a, **k: None), \
             mock.patch.object(cmd_secret, "WorkloadConfig",
                               lambda n: types.SimpleNamespace(
                                   is_vm=False, uid=10001, service_name=f"workload-{n}.service")):
            out, err, code = _run(_ns(subcommand="rotate", name="api-key", key_type=None))
        self.assertIsNone(code)
        self.assertIn("web", out)        # the env-ref user is listed
        self.assertNotIn("- other", out)  # the non-user is not


class ImportExportTest(SecretTestBase):
    def test_import_missing_file_errors(self):
        out, err, code = _run(_ns(subcommand="import", name="api",
                                  file=str(self.tmp / "nope.secret"),
                                  force=False, key_type=None,
                                  passphrase_stdin=False, passphrase_file=None))
        self.assertEqual(code, 1)
        self.assertIn("File not found", err)

    def test_import_existing_without_force_errors(self):
        self._seed_cred("api")
        infile = self.tmp / "in.secret"
        infile.write_bytes(b"enc")
        out, err, code = _run(_ns(subcommand="import", name="api",
                                  file=str(infile), force=False, key_type=None,
                                  passphrase_stdin=False, passphrase_file=None))
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)

    def test_export_missing_errors(self):
        out, err, code = _run(_ns(subcommand="export", name="ghost", output=None,
                                  passphrase_stdin=False, passphrase_file=None))
        self.assertEqual(code, 1)
        self.assertIn("not found", err)


class PassphraseTest(unittest.TestCase):
    """_read_passphrase / _strip_trailing_newline — the export/import secret
    handling. Pure, no credstore, security-relevant."""

    def test_strip_trailing_newline_exact(self):
        self.assertEqual(cmd_secret._strip_trailing_newline("pw\n"), "pw")
        self.assertEqual(cmd_secret._strip_trailing_newline("pw\r\n"), "pw")
        self.assertEqual(cmd_secret._strip_trailing_newline("pw"), "pw")
        self.assertEqual(cmd_secret._strip_trailing_newline("pw\n\n"), "pw\n")

    def _read(self, args, stdin_bytes=None):
        out, err = io.StringIO(), io.StringIO()
        code = None
        ctx = mock.patch.object(
            cmd_secret.sys, "stdin",
            types.SimpleNamespace(buffer=io.BytesIO(stdin_bytes or b"")))
        try:
            with ctx, redirect_stdout(out), redirect_stderr(err):
                val = cmd_secret._read_passphrase(args, prompt="P: ", confirm=False)
            return val, None, err.getvalue()
        except SystemExit as e:
            return None, e.code, err.getvalue()

    def test_stdin_source_strips_one_newline(self):
        args = _ns(passphrase_stdin=True, passphrase_file=None)
        val, code, _ = self._read(args, stdin_bytes=b"s3cret\n")
        self.assertEqual(val, "s3cret")

    def test_file_source(self):
        with tempfile.NamedTemporaryFile("w", suffix=".pass", delete=False) as f:
            f.write("frompw\n")
            fname = f.name
        try:
            args = _ns(passphrase_stdin=False, passphrase_file=fname)
            val, code, _ = self._read(args)
            self.assertEqual(val, "frompw")
        finally:
            os.unlink(fname)

    def test_empty_passphrase_rejected(self):
        args = _ns(passphrase_stdin=True, passphrase_file=None)
        val, code, err = self._read(args, stdin_bytes=b"\n")
        self.assertEqual(code, 1)
        self.assertIn("cannot be empty", err)

    def test_embedded_newline_rejected(self):
        args = _ns(passphrase_stdin=True, passphrase_file=None)
        val, code, err = self._read(args, stdin_bytes=b"line1\nline2\n")
        self.assertEqual(code, 1)
        self.assertIn("single line", err)

    def test_interactive_confirm_mismatch_rejected(self):
        args = _ns(passphrase_stdin=False, passphrase_file=None)
        replies = iter(["first", "second"])
        with mock.patch.object(cmd_secret.getpass, "getpass",
                               lambda *a, **k: next(replies)):
            err = io.StringIO()
            with self.assertRaises(SystemExit) as cm, \
                 redirect_stdout(io.StringIO()), redirect_stderr(err):
                cmd_secret._read_passphrase(args, prompt="P: ", confirm=True)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("do not match", err.getvalue())


if __name__ == "__main__":
    unittest.main()
