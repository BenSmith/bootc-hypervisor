#!/usr/bin/env python3
"""Tests for the RPM %postun uninstall scriptlet (rpm/workloadctl.spec).

On full uninstall the scriptlet reverses the host-global state that
workload-ensure-user accretes but per-workload teardown can't safely remove:
the semanage fcontext rule for /var/lib/workloads, and the *managed* VM bridge's
allow line in /etc/qemu/bridge.conf. A custom/admin bridge (allow br0) must be
left alone, and on an upgrade ($1 != 0) nothing should happen.

We can't run a real `dnf remove` here, so we extract the scriptlet's shell body
from the spec and execute it under /bin/sh with:
  * $1 set to 0 (uninstall) or 1 (upgrade),
  * a stub `semanage` on PATH that records its args instead of touching policy,
  * /etc/qemu/bridge.conf rewritten to a temp file.
The real sed expression and guard run unchanged, so the regex (only the managed
line) and the upgrade guard are exercised exactly as shipped.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SPEC = Path(__file__).resolve().parent.parent / "rpm" / "workloadctl.spec"
REAL_BRIDGE_CONF = "/etc/qemu/bridge.conf"

# Real spec sections that terminate the %postun body. A %macro call like
# %systemd_postun_with_restart is NOT a section — it's stripped, not a boundary.
_SECTION_RE = re.compile(
    r"^%(files|changelog|package|description|prep|build|install|check|clean"
    r"|post|posttrans|pretrans|preun|pre|trigger|verifyscript)\b"
)


def _extract_postun_body() -> str:
    """Return the shell body of %postun (RPM %macro lines stripped)."""
    lines = SPEC.read_text().splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip() == "%postun")
    body = []
    for l in lines[start + 1:]:
        if _SECTION_RE.match(l):
            break  # next spec section — body ends here
        if l.startswith("%"):
            continue  # RPM macro line — not shell, drop it
        body.append(l)
    return "\n".join(body)


class TestPostunScriptlet(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        tmp = Path(self._tmp)

        # Stub semanage: append its args to a log so we can assert the call.
        self._semanage_log = tmp / "semanage.log"
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "semanage"
        stub.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{self._semanage_log}"\n'
        )
        stub.chmod(0o755)
        self._bin_dir = bin_dir

        self._bridge_conf = tmp / "bridge.conf"

        # Real scriptlet body with the hardcoded bridge path pointed at our temp
        # file. The semanage call resolves to the stub via PATH.
        body = _extract_postun_body().replace(REAL_BRIDGE_CONF,
                                              str(self._bridge_conf))
        self.assertNotIn(REAL_BRIDGE_CONF, body)
        self._script = body

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, arg: str):
        env = dict(os.environ)
        env["PATH"] = f"{self._bin_dir}:{env['PATH']}"
        proc = subprocess.run(
            ["/bin/sh", "-s", arg],
            input=self._script, text=True, env=env,
            capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def _semanage_calls(self):
        if not self._semanage_log.exists():
            return []
        return self._semanage_log.read_text().splitlines()

    # ── uninstall ($1 == 0) ──────────────────────────────────────────────────

    def test_uninstall_removes_only_managed_bridge_line(self):
        self._bridge_conf.write_text(
            "allow virbr0\n"
            "allow _workload-br\n"
            "allow br0\n"
        )
        self._run("0")
        self.assertEqual(
            self._bridge_conf.read_text(),
            "allow virbr0\nallow br0\n",
        )

    def test_uninstall_removes_fcontext_rule(self):
        self._run("0")
        calls = self._semanage_calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], "fcontext -d /var/lib/workloads(/.*)?")

    def test_uninstall_missing_bridge_conf_is_noop(self):
        # No bridge.conf present — the -f guard must keep it from erroring.
        self.assertFalse(self._bridge_conf.exists())
        self._run("0")  # _run asserts rc == 0
        self.assertFalse(self._bridge_conf.exists())

    def test_uninstall_preserves_bridge_conf_without_managed_line(self):
        self._bridge_conf.write_text("allow br0\nallow virbr0\n")
        self._run("0")
        self.assertEqual(
            self._bridge_conf.read_text(),
            "allow br0\nallow virbr0\n",
        )

    # ── upgrade ($1 >= 1) ────────────────────────────────────────────────────

    def test_upgrade_is_a_noop(self):
        self._bridge_conf.write_text("allow _workload-br\nallow br0\n")
        self._run("1")
        # Bridge file untouched and semanage never called.
        self.assertEqual(
            self._bridge_conf.read_text(),
            "allow _workload-br\nallow br0\n",
        )
        self.assertEqual(self._semanage_calls(), [])


class TestPostunSpecText(unittest.TestCase):
    """Cheap regression guards on the literal scriptlet, so a future reformat
    can't silently loosen the bridge regex or drop the upgrade guard."""

    def test_guarded_on_full_uninstall(self):
        self.assertIn("if [ $1 -eq 0 ]; then", _extract_postun_body())

    def test_bridge_sed_is_anchored_to_managed_bridge(self):
        # Anchored, exact line — never a bare /allow/d that would nuke admin lines.
        self.assertIn("/^allow _workload-br$/d", _extract_postun_body())


if __name__ == "__main__":
    unittest.main()
