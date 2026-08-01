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
import tempfile
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock


import workload_lib          # noqa: E402
import cmd_secret           # noqa: E402

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

        # Never let a test touch the real stdin. `create`/`rotate` read it
        # in-process now, so an unmocked test inherits whatever the runner
        # gives us: a TTY makes getpass prompt, and a pipe that never sees EOF
        # (GitHub Actions) makes buffer.read() block forever — the suite hangs
        # with no failing test to point at. Default to an empty non-TTY pipe;
        # tests that care override it (see _tty/_piped).
        stdin = mock.Mock(isatty=lambda: False)
        stdin.buffer.read.return_value = b""
        self.enterContext(mock.patch.object(cmd_secret.sys, "stdin", stdin))
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
        # --name is passed in every mode (stdin, file, rotate, import). systemd-
        # creds would infer it from the destination basename, but only while the
        # destination stays cred_dir/<name> — pass it explicitly so the embedded
        # name never silently depends on that.
        self.assertIn("--name=api", cmd)


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

    def test_detects_multi_container_env_ref(self):
        # Regression for A1: the old scan only walked top-level
        # [container.environment], so a credential used solely by a
        # [[containers]] block (pod/bridge shape) was missed and its workload
        # never restarted. Route through auto_detect_credentials → detected.
        self._seed_cred("api-key")
        (self.wl_dir / "pod").mkdir()
        (self.wl_dir / "pod" / "workload.toml").write_text(
            '[workload]\nname = "pod"\nmode = "pod"\n'
            '[[containers]]\nname = "app"\nimage = "x"\n'
            '[containers.environment]\nTOKEN = "${SECRET:api-key}"\n')

        with mock.patch.object(cmd_secret.subprocess, "run",
                               lambda *a, **k: types.SimpleNamespace(returncode=0)), \
             mock.patch.object(cmd_secret, "restart_workload_service", lambda *a, **k: None), \
             mock.patch.object(cmd_secret, "WorkloadConfig",
                               lambda n: types.SimpleNamespace(
                                   is_vm=False, uid=10001, service_name=f"workload-{n}.service")):
            out, err, code = _run(_ns(subcommand="rotate", name="api-key", key_type=None))
        self.assertIsNone(code)
        self.assertIn("pod", out)  # the multi-container env-ref user is listed


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


class CreateFailureTest(SecretTestBase):
    def test_subprocess_failure_errors(self):
        def fake_run(cmd, **kw):
            raise cmd_secret.subprocess.CalledProcessError(1, cmd)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run):
            out, err, code = _run(_ns(subcommand="create", name="api",
                                      force=False, key_type=None, file=None))
        self.assertEqual(code, 1)
        self.assertIn("Failed to create credential", err)


class ListTest(SecretTestBase):
    def test_no_dir_text(self):
        out, err, code = _run(_ns(subcommand="list", json=False))
        self.assertIsNone(code)
        self.assertIn("does not exist", out)

    def test_no_dir_json(self):
        out, err, code = _run(_ns(subcommand="list", json=True))
        self.assertEqual(cmd_secret.json.loads(out), {"credentials": []})

    def test_empty_dir_text(self):
        self.cred_dir.mkdir()
        out, err, code = _run(_ns(subcommand="list", json=False))
        self.assertIn("No credentials found", out)

    def test_populated_text(self):
        self._seed_cred("api")
        self._seed_cred("db")
        out, err, code = _run(_ns(subcommand="list", json=False))
        self.assertIn("api", out)
        self.assertIn("db", out)
        self.assertIn("Total: 2", out)

    def test_populated_json(self):
        self._seed_cred("api", b"hello")
        out, err, code = _run(_ns(subcommand="list", json=True))
        data = cmd_secret.json.loads(out)
        self.assertEqual(data["credentials"][0]["name"], "api")
        self.assertEqual(data["credentials"][0]["size"], 5)


class ShowTest(SecretTestBase):
    def test_missing_errors(self):
        out, err, code = _run(_ns(subcommand="show", name="ghost"))
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_decrypt_failure(self):
        self._seed_cred("api")

        def fake_run(cmd, **kw):
            raise cmd_secret.subprocess.CalledProcessError(1, cmd)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run):
            out, err, code = _run(_ns(subcommand="show", name="api"))
        self.assertEqual(code, 1)
        self.assertIn("Failed to decrypt", err)

    def test_decrypt_success_adds_newline(self):
        self._seed_cred("api")
        with mock.patch.object(
                cmd_secret.subprocess, "run",
                lambda *a, **k: types.SimpleNamespace(stdout="secretval")):
            out, err, code = _run(_ns(subcommand="show", name="api"))
        self.assertIsNone(code)
        self.assertIn("Value: secretval\n", out)

    def test_decrypt_success_no_extra_newline(self):
        self._seed_cred("api")
        with mock.patch.object(
                cmd_secret.subprocess, "run",
                lambda *a, **k: types.SimpleNamespace(stdout="secretval\n")):
            out, err, code = _run(_ns(subcommand="show", name="api"))
        self.assertIsNone(code)
        self.assertEqual(out.count("secretval"), 1)


class RotateExtraTest(SecretTestBase):
    def test_bad_toml_ignored(self):
        self._seed_cred("api-key")
        (self.wl_dir / "broken").mkdir()
        (self.wl_dir / "broken" / "workload.toml").write_text("not valid toml [[[")

        with mock.patch.object(cmd_secret.subprocess, "run",
                               lambda *a, **k: types.SimpleNamespace(returncode=0)):
            out, err, code = _run(_ns(subcommand="rotate", name="api-key", key_type=None))
        self.assertIsNone(code)
        self.assertNotIn("following workloads", out)

    def test_detects_via_secrets_files(self):
        self._seed_cred("api-key")
        (self.wl_dir / "web").mkdir()
        (self.wl_dir / "web" / "workload.toml").write_text(
            '[workload]\nname = "web"\n[container]\nimage = "x"\n'
            '[[secrets.files]]\ncredential = "api-key"\npath = "/run/x"\n')

        with mock.patch.object(cmd_secret.subprocess, "run",
                               lambda *a, **k: types.SimpleNamespace(returncode=0)), \
             mock.patch.object(cmd_secret, "restart_workload_service", lambda *a, **k: None), \
             mock.patch.object(cmd_secret, "WorkloadConfig",
                               lambda n: types.SimpleNamespace(
                                   is_vm=False, uid=10001, service_name=f"workload-{n}.service")):
            out, err, code = _run(_ns(subcommand="rotate", name="api-key", key_type=None))
        self.assertIsNone(code)
        self.assertIn("web", out)
        self.assertIn("Restarted web", out)

    def test_vm_restart_uses_systemctl(self):
        self._seed_cred("api-key")
        (self.wl_dir / "vmwl").mkdir()
        (self.wl_dir / "vmwl" / "workload.toml").write_text(
            '[workload]\nname = "vmwl"\n[container]\nimage = "x"\n'
            '[container.environment]\nTOKEN = "${SECRET:api-key}"\n')

        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return types.SimpleNamespace(returncode=0)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run), \
             mock.patch.object(cmd_secret, "WorkloadConfig",
                               lambda n: types.SimpleNamespace(
                                   is_vm=True, uid=10001, service_name=f"workload-{n}.service")):
            out, err, code = _run(_ns(subcommand="rotate", name="api-key", key_type=None))
        self.assertIsNone(code)
        self.assertIn(["systemctl", "restart", "workload-vmwl.service"], calls)
        self.assertIn("Restarted vmwl", out)

    def test_restart_failure_reported(self):
        self._seed_cred("api-key")
        (self.wl_dir / "web").mkdir()
        (self.wl_dir / "web" / "workload.toml").write_text(
            '[workload]\nname = "web"\n[container]\nimage = "x"\n'
            '[container.environment]\nTOKEN = "${SECRET:api-key}"\n')

        def boom(*a, **k):
            raise RuntimeError("nope")

        with mock.patch.object(cmd_secret.subprocess, "run",
                               lambda *a, **k: types.SimpleNamespace(returncode=0)), \
             mock.patch.object(cmd_secret, "restart_workload_service", boom), \
             mock.patch.object(cmd_secret, "WorkloadConfig",
                               lambda n: types.SimpleNamespace(
                                   is_vm=False, uid=10001, service_name=f"workload-{n}.service")):
            out, err, code = _run(_ns(subcommand="rotate", name="api-key", key_type=None))
        self.assertIsNone(code)
        self.assertIn("Failed to restart web", err)

    def test_encrypt_failure_errors(self):
        self._seed_cred("api-key")

        def fake_run(cmd, **kw):
            raise cmd_secret.subprocess.CalledProcessError(1, cmd)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run):
            out, err, code = _run(_ns(subcommand="rotate", name="api-key", key_type=None))
        self.assertEqual(code, 1)
        self.assertIn("Failed to rotate credential", err)


class ExportImportFlowTest(SecretTestBase):
    def test_export_decrypt_failure(self):
        self._seed_cred("api")

        def fake_run(cmd, **kw):
            raise cmd_secret.subprocess.CalledProcessError(1, cmd)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run):
            out, err, code = _run(_ns(subcommand="export", name="api", output=None,
                                      passphrase_stdin=True, passphrase_file=None))
        self.assertEqual(code, 1)
        self.assertIn("TPM unavailable", err)

    def test_export_success_full_flow_with_stdin_passphrase(self):
        self._seed_cred("api")
        output = self.tmp / "out.secret"
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[:2] == ["systemd-creds", "decrypt"]:
                return types.SimpleNamespace(stdout=b"plaintext")
            # openssl enc now streams the ciphertext on stdout (no -out); the
            # HMAC + header are added in-process and written by output.write_bytes.
            return types.SimpleNamespace(stdout=b"encblob", returncode=0)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run), \
             mock.patch.object(cmd_secret.sys, "stdin",
                               types.SimpleNamespace(buffer=io.BytesIO(b"pw123\n"))):
            out, err, code = _run(_ns(subcommand="export", name="api",
                                      output=str(output),
                                      passphrase_stdin=True, passphrase_file=None))
        self.assertIsNone(code)
        self.assertIn("Exported credential", out)
        # v2 output carries the version header + HMAC over the openssl ciphertext.
        self.assertTrue(output.read_bytes().startswith(cmd_secret.SECRET_EXPORT_V2_MAGIC))
        openssl_calls = [c for c in calls if c[0] == "openssl"]
        self.assertEqual(len(openssl_calls), 1)
        self.assertIn("-pbkdf2", openssl_calls[0])
        self.assertIn("600000", openssl_calls[0])

    def test_export_openssl_failure(self):
        self._seed_cred("api")

        def fake_run(cmd, **kw):
            if cmd[:2] == ["systemd-creds", "decrypt"]:
                return types.SimpleNamespace(stdout=b"plaintext")
            raise cmd_secret.subprocess.CalledProcessError(1, cmd)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run), \
             mock.patch.object(cmd_secret.sys, "stdin",
                               types.SimpleNamespace(buffer=io.BytesIO(b"pw123\n"))):
            out, err, code = _run(_ns(subcommand="export", name="api", output=None,
                                      passphrase_stdin=True, passphrase_file=None))
        self.assertEqual(code, 1)
        self.assertIn("Failed to encrypt with passphrase", err)

    def test_import_decrypt_failure_wrong_passphrase(self):
        infile = self.tmp / "in.secret"
        infile.write_bytes(b"enc")

        def fake_run(cmd, **kw):
            raise cmd_secret.subprocess.CalledProcessError(1, cmd)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run), \
             mock.patch.object(cmd_secret.sys, "stdin",
                               types.SimpleNamespace(buffer=io.BytesIO(b"pw123\n"))):
            out, err, code = _run(_ns(subcommand="import", name="api",
                                      file=str(infile), force=False, key_type=None,
                                      passphrase_stdin=True, passphrase_file=None))
        self.assertEqual(code, 1)
        self.assertIn("wrong passphrase", err)

    def test_import_encrypt_failure(self):
        infile = self.tmp / "in.secret"
        infile.write_bytes(b"enc")

        def fake_run(cmd, **kw):
            if cmd[0] == "openssl":
                return types.SimpleNamespace(stdout=b"plaintext", returncode=0)
            raise cmd_secret.subprocess.CalledProcessError(1, cmd)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run), \
             mock.patch.object(cmd_secret.sys, "stdin",
                               types.SimpleNamespace(buffer=io.BytesIO(b"pw123\n"))):
            out, err, code = _run(_ns(subcommand="import", name="api",
                                      file=str(infile), force=False, key_type=None,
                                      passphrase_stdin=True, passphrase_file=None))
        self.assertEqual(code, 1)
        self.assertIn("Failed to encrypt with systemd-creds", err)

    def test_import_success_suggests_restart(self):
        infile = self.tmp / "in.secret"
        infile.write_bytes(b"enc")
        (self.wl_dir / "web").mkdir()
        (self.wl_dir / "web" / "workload.toml").write_text(
            '[workload]\nname = "web"\n[container]\nimage = "x"\n'
            '[container.environment]\nTOKEN = "${SECRET:api}"\n')

        def fake_run(cmd, **kw):
            if cmd[0] == "openssl":
                return types.SimpleNamespace(stdout=b"plaintext", returncode=0)
            Path(cmd[-1]).write_bytes(b"x")  # systemd-creds writes the blob
            return types.SimpleNamespace(returncode=0)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run), \
             mock.patch.object(cmd_secret.sys, "stdin",
                               types.SimpleNamespace(buffer=io.BytesIO(b"pw123\n"))):
            out, err, code = _run(_ns(subcommand="import", name="api",
                                      file=str(infile), force=False, key_type=None,
                                      passphrase_stdin=True, passphrase_file=None))
        self.assertIsNone(code)
        self.assertIn("Imported credential", out)
        self.assertIn("sudo workloadctl recreate web", out)
        self.assertTrue((self.cred_dir / "api").exists())


class PassphraseFileErrorTest(unittest.TestCase):
    def test_unreadable_file_errors(self):
        args = _ns(passphrase_stdin=False, passphrase_file="/nonexistent/nope.pass")
        err = io.StringIO()
        with self.assertRaises(SystemExit) as cm, \
             redirect_stdout(io.StringIO()), redirect_stderr(err):
            cmd_secret._read_passphrase(args, prompt="P: ", confirm=False)
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("Cannot read passphrase file", err.getvalue())


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


import shutil
import subprocess


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class SecretExportCryptoTest(unittest.TestCase):
    """The versioned, integrity-protected v2 export format (ADR 004 / B14),
    exercised against real openssl."""

    PW = "correct horse battery staple"
    PT = b"api-token-value\x00\x01\xff binary-safe"

    def test_v2_roundtrip(self):
        blob = cmd_secret._secret_export_encrypt_v2(self.PT, self.PW)
        self.assertTrue(blob.startswith(cmd_secret.SECRET_EXPORT_V2_MAGIC))
        self.assertEqual(cmd_secret._secret_export_decrypt(blob, self.PW), self.PT)

    def test_v2_tamper_is_detected(self):
        blob = bytearray(cmd_secret._secret_export_encrypt_v2(self.PT, self.PW))
        blob[-1] ^= 0xFF  # flip a ciphertext byte
        with self.assertRaises(ValueError):
            cmd_secret._secret_export_decrypt(bytes(blob), self.PW)

    def test_v2_wrong_passphrase_fails_integrity(self):
        blob = cmd_secret._secret_export_encrypt_v2(self.PT, self.PW)
        with self.assertRaises(ValueError):
            cmd_secret._secret_export_decrypt(blob, "not-the-passphrase")

    def test_v1_legacy_blob_still_imports(self):
        # A v1 blob (openssl aes-256-cbc -pbkdf2, no header) stays restorable.
        with tempfile.NamedTemporaryFile("w", suffix=".pass") as pf:
            pf.write(self.PW)
            pf.flush()
            os.chmod(pf.name, 0o600)
            v1 = subprocess.run(
                ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
                 "-pass", f"file:{pf.name}"],
                input=self.PT, capture_output=True, check=True,
            ).stdout
        self.assertFalse(v1.startswith(cmd_secret.SECRET_EXPORT_V2_MAGIC))
        self.assertEqual(cmd_secret._secret_export_decrypt(v1, self.PW), self.PT)

    def test_v2_uses_high_iteration_pbkdf2(self):
        self.assertGreaterEqual(cmd_secret._SECRET_PBKDF2_ITERS, 600000)


class ReadSecretValueTest(SecretTestBase):
    """The interactive prompt must not echo, and must not append a newline.

    Regression: `create`/`rotate` used to print a prompt and let systemd-creds
    read the inherited TTY directly. That displayed the credential as it was
    typed, and the Enter-then-Ctrl+D needed to end the input embedded a
    trailing newline — which only surfaced much later, as three workload units
    failing to start because env injection rejects newlines in a secret.
    """

    def _tty(self, *values):
        """Interactive stdin: getpass returns `values` in order."""
        self.enterContext(mock.patch.object(
            cmd_secret.sys, "stdin", mock.Mock(isatty=lambda: True)))
        return self.enterContext(mock.patch.object(
            cmd_secret.getpass, "getpass", mock.Mock(side_effect=list(values))))

    def _piped(self, data: bytes):
        """Non-interactive stdin carrying `data`."""
        stdin = mock.Mock(isatty=lambda: False)
        stdin.buffer.read.return_value = data
        self.enterContext(mock.patch.object(cmd_secret.sys, "stdin", stdin))

    def test_interactive_never_reaches_the_terminal(self):
        prompts = self._tty("hunter2", "hunter2")
        self.assertEqual(cmd_secret._read_secret_value("api", action="Enter"),
                         b"hunter2")
        # Read via getpass (echo off), not print()+inherited stdin.
        self.assertEqual(prompts.call_count, 2)

    def test_interactive_value_has_no_trailing_newline(self):
        self._tty("hunter2", "hunter2")
        self.assertEqual(cmd_secret._read_secret_value("api", action="Enter"),
                         b"hunter2")

    def test_interactive_mismatch_aborts(self):
        self._tty("hunter2", "typo")
        with self.assertRaises(SystemExit) as cm:
            with redirect_stderr(io.StringIO()) as err:
                cmd_secret._read_secret_value("api", action="Enter")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("do not match", err.getvalue())

    def test_interactive_empty_rejected(self):
        self._tty("", "")
        with self.assertRaises(SystemExit) as cm:
            with redirect_stderr(io.StringIO()):
                cmd_secret._read_secret_value("api", action="Enter")
        self.assertEqual(cm.exception.code, 1)

    def test_piped_trailing_newline_warns_but_is_not_altered(self):
        # `echo` without -n. Warn (stderr), never strip: silently changing a
        # credential is worse than a noisy one.
        self._piped(b"oops\n")
        with redirect_stderr(io.StringIO()) as err:
            value = cmd_secret._read_secret_value("api", action="Enter")
        self.assertEqual(value, b"oops\n")
        self.assertIn("ends with a newline", err.getvalue())

    def test_piped_without_trailing_newline_is_silent(self):
        self._piped(b"clean")
        with redirect_stderr(io.StringIO()) as err:
            cmd_secret._read_secret_value("api", action="Enter")
        self.assertEqual(err.getvalue(), "")

    def test_interactive_never_warns(self):
        # getpass strips the terminator, so the warning can't fire here.
        self._tty("hunter2", "hunter2")
        with redirect_stderr(io.StringIO()) as err:
            cmd_secret._read_secret_value("api", action="Enter")
        self.assertEqual(err.getvalue(), "")

    def test_closed_stdin_errors_instead_of_traceback(self):
        # `... secret create x 0<&-` leaves sys.stdin as None.
        self.enterContext(mock.patch.object(cmd_secret.sys, "stdin", None))
        with self.assertRaises(SystemExit) as cm:
            with redirect_stderr(io.StringIO()) as err:
                cmd_secret._read_secret_value("api", action="Enter")
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("No stdin", err.getvalue())

    def test_piped_is_verbatim(self):
        # No strip, no decode: `echo -n` idioms and binary payloads are
        # byte-preserved, including a value that legitimately ends in a newline.
        for payload in (b"p@ss$$w0rd", bytes(range(256)), b"trailing\n"):
            with self.subTest(payload=payload[:12]):
                with mock.patch.object(cmd_secret.sys, "stdin",
                                       mock.Mock(isatty=lambda: False)) as si:
                    si.buffer.read.return_value = payload
                    self.assertEqual(
                        cmd_secret._read_secret_value("api", action="Enter"),
                        payload)

    def test_create_pipes_value_to_systemd_creds(self):
        self._piped(b"s3cret")
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"], captured["input"] = cmd, kw.get("input")
            _REAL_PATH(cmd[-1]).write_bytes(b"x")
            return types.SimpleNamespace(returncode=0)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run):
            _, _, code = _run(_ns(subcommand="create", name="api", force=False,
                                  key_type=None, file=None))
        self.assertIsNone(code)
        self.assertEqual(captured["input"], b"s3cret")
        self.assertIn("-", captured["cmd"])

    def test_create_from_file_passes_no_stdin(self):
        # --file still hands systemd-creds the path; nothing is read from stdin.
        secret_file = self.tmp / "plain.txt"
        secret_file.write_text("hunter2")
        captured = {}

        def fake_run(cmd, **kw):
            captured["input"] = kw.get("input")
            _REAL_PATH(cmd[-1]).write_bytes(b"x")
            return types.SimpleNamespace(returncode=0)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run):
            _, _, code = _run(_ns(subcommand="create", name="api", force=False,
                                  key_type="host", file=str(secret_file)))
        self.assertIsNone(code)
        self.assertIsNone(captured["input"])

    def test_rotate_pipes_value_to_systemd_creds(self):
        self._seed_cred("api")
        self._piped(b"rotated")
        captured = {}

        def fake_run(cmd, **kw):
            captured["input"] = kw.get("input")
            return types.SimpleNamespace(returncode=0)

        with mock.patch.object(cmd_secret.subprocess, "run", fake_run):
            _, _, code = _run(_ns(subcommand="rotate", name="api", key_type=None))
        self.assertIsNone(code)
        self.assertEqual(captured["input"], b"rotated")


if __name__ == "__main__":
    unittest.main()
