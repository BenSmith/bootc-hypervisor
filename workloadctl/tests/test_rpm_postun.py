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
  * stubs on PATH for every tool it runs — semanage, semodule, restorecon,
    firewall-cmd — each recording its args instead of doing the thing,
  * every absolute `[ -x ... ]` probe pointed at those stubs,
  * /etc/qemu/bridge.conf rewritten to a temp file.
The real sed expression and guard run unchanged, so the regex (only the managed
line) and the upgrade guard are exercised exactly as shipped.

The probes are as load-bearing as the stubs, and the sharper half. `semodule -r`
is gated on `[ -x /usr/sbin/semodule ]`; left pointing at the host, that branch
runs `semodule -r workload-vm` against the real policy store — uninstalling
workloadctl's SELinux policy from whatever machine ran the test, and saying
nothing, since every line in the scriptlet ends in `2>/dev/null || :`.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SPEC = Path(__file__).resolve().parent.parent / "rpm" / "workloadctl.spec"
REAL_BRIDGE_CONF = "/etc/qemu/bridge.conf"
REAL_FIREWALL_CMD = "/usr/bin/firewall-cmd"
REAL_SEMODULE = "/usr/sbin/semodule"

# Real spec sections that terminate the %postun body. A %macro call like
# %systemd_postun_with_restart is NOT a section — it's stripped, not a boundary.
_SECTION_RE = re.compile(
    r"^%(files|changelog|package|description|prep|build|install|check|clean"
    r"|post|posttrans|pretrans|preun|pre|trigger|verifyscript)\b"
)


def _extract_postun_body() -> str:
    """Return the shell body of %postun (RPM %macro lines stripped)."""
    lines = SPEC.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "%postun")
    body = []
    for line in lines[start + 1:]:
        if _SECTION_RE.match(line):
            break  # next spec section — body ends here
        if line.lstrip().startswith("%"):
            # RPM macro line — not shell, drop it. Match it at any indentation:
            # macros expand wherever they appear, so a macro nested inside the
            # uninstall `if` (e.g. %{?firewalld_reload}) is just as much a macro
            # as one at column 0, and feeding it to sh makes `%` a job spec.
            continue
        body.append(line)
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

        # Stub firewall-cmd: the scriptlet's reload resolves through PATH, so on
        # a host that actually has firewalld this keeps the test from reloading
        # the developer's live firewall.
        self._firewall_log = tmp / "firewall-cmd.log"
        fw_stub = bin_dir / "firewall-cmd"
        fw_stub.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{self._firewall_log}"\n'
        )
        fw_stub.chmod(0o755)

        # Stub semodule and restorecon for the same reason, more sharply.
        # `semodule -r workload-vm` *removes* a policy module from the host's
        # store and restorecon relabels a real binary, so an unstubbed run on a
        # machine that has workloadctl's policy loaded uninstalls it — silently,
        # because every line here is `2>/dev/null || :`.
        self._policy_log = tmp / "policy.log"
        for name in ("semodule", "restorecon"):
            policy_stub = bin_dir / name
            policy_stub.write_text(
                "#!/bin/sh\n"
                f'printf "%s\\n" "$(basename "$0") $*" >> "{self._policy_log}"\n'
            )
            policy_stub.chmod(0o755)

        self._bridge_conf = tmp / "bridge.conf"

        # Real scriptlet body with the hardcoded bridge path pointed at our temp
        # file. The semanage call resolves to the stub via PATH.
        body = _extract_postun_body().replace(REAL_BRIDGE_CONF,
                                              str(self._bridge_conf))
        self.assertNotIn(REAL_BRIDGE_CONF, body)
        # The semodule branch is gated on an absolute `[ -x ... ]`, so a PATH
        # stub alone does not reach it: the probe finds the host's real binary
        # and the branch runs against the host's real policy store.
        body = body.replace(REAL_SEMODULE, str(bin_dir / "semodule"))
        self.assertNotIn(REAL_SEMODULE, body)
        # The reload's `test -x` guard names firewall-cmd by absolute path;
        # point it at the stub so the branch is exercised the same way whether
        # or not the test host has firewalld installed.
        body = body.replace(REAL_FIREWALL_CMD, str(fw_stub))
        self.assertNotIn(REAL_FIREWALL_CMD, body)
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

    def _firewall_calls(self):
        if not self._firewall_log.exists():
            return []
        return self._firewall_log.read_text().splitlines()

    def _policy_calls(self):
        if not self._policy_log.exists():
            return []
        return self._policy_log.read_text().splitlines()

    # ── uninstall ($1 == 0) ──────────────────────────────────────────────────

    def test_uninstall_removes_fcontext_rules(self):
        # Both rules %post registers: the blanket workload tree and the VM
        # runtime socket dir. Per-workload VM overrides are not here — those
        # are unregistered by `disable`, which owns them.
        self._run("0")
        self.assertEqual(
            self._semanage_calls(),
            ["fcontext -d /var/lib/workloads(/.*)?",
             "fcontext -d /run/workload-vm(/.*)?"])

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

    def test_uninstall_removes_the_policy_modules_and_relabels(self):
        """The other half of what %post installed. Untested until now, because
        the branch is gated on an absolute `[ -x /usr/sbin/semodule ]` that no
        stub was standing in for — so on a host with semodule it ran for real
        and on one without it never ran at all. Neither is a test."""
        self._run("0")
        self.assertEqual(
            self._policy_calls(),
            ["semodule -r workload-vm",
             "restorecon /usr/libexec/virtiofsd",
             "semodule -r workload-inspect",
             "restorecon /usr/libexec/workloadctl/workload-vm-inspect-listener",
             "semodule -r workload-resolve",
             "restorecon /usr/libexec/workloadctl/workload-vm-resolve"])

    def test_upgrade_is_a_noop(self):
        # An admin's own bridge allow-list is never touched at any $1, and
        # semanage runs only on a full uninstall.
        self._bridge_conf.write_text("allow br0\n")
        self._run("1")
        self.assertEqual(self._bridge_conf.read_text(), "allow br0\n")
        self.assertEqual(self._semanage_calls(), [])
        self.assertEqual(self._policy_calls(), [],
                         "an upgrade must not unload the policy modules")

    def test_no_probe_survives_for_a_real_tool(self):
        """The guard that would have caught this. An absolute `[ -x ... ]` left
        pointing at the host decides whether the branch under it runs against
        the host, and here that branch is `semodule -r`, which uninstalls
        workloadctl's SELinux policy from the machine running the test."""
        self.assertNotIn("[ -x /usr/", self._script)


class TestPostunSpecText(unittest.TestCase):
    """Cheap regression guards on the literal scriptlet, so a future reformat
    can't silently loosen the bridge regex or drop the upgrade guard."""

    def test_guarded_on_full_uninstall(self):
        self.assertIn("if [ $1 -eq 0 ]; then", _extract_postun_body())

