#!/usr/bin/env python3
"""The spec must install every libexec helper, once, under its own name.

`%install` and `%files` are two hand-maintained lists of the same set, and a
copy-pasted `install -Dpm` line is invisible to every other test in the suite:
the Python imports fine, the generator emits the right ExecStartPre, and only
`rpmbuild` notices -- if it notices at all. A line whose source and
destination basenames disagree installs one helper's *content* under another
helper's *name*, which builds cleanly whenever both names appear somewhere in
the file, and ships a package where the unit's ExecStartPre runs the wrong
script.

Caught for real on 2026-08-10: adding workload-vm-netdev cloned the
workload-vm-notify install line, leaving netdev holding notify's content and
netdev missing from %files entirely.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "rpm" / "workloadctl.spec"
LIBEXEC = ROOT / "libexec"

# `install -Dpm 0755 %{_sourcedir}/<src> \\\n    %{buildroot}<dest>`
INSTALL_RE = re.compile(
    r"install\s+-Dpm\s+\d+\s+%\{_sourcedir\}/(\S+)\s*\\?\s*\n?\s*"
    r"%\{buildroot\}(\S+)")


class TestSpecInstallsEveryHelper(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.spec = SPEC.read_text()
        body = cls.spec
        files_start = body.index("\n%files")
        cls.files_section = body[files_start:]
        cls.installs = INSTALL_RE.findall(body[:files_start])

    def test_source_and_destination_basenames_agree(self):
        """The bug that shipped: a cloned install line renaming a helper.

        Scoped to the private libexec dir. Elsewhere a rename is deliberate --
        completions/workloadctl-completion.bash has to land as `workloadctl`
        because bash-completion looks it up by command name.
        """
        for src, dest in self.installs:
            if "/workloadctl/" not in dest or "libexec" not in dest:
                continue
            src_name, dest_name = Path(src).name, Path(dest).name
            self.assertEqual(
                src_name, dest_name,
                f"%install puts {src} at {dest}: the installed file would "
                f"hold {src_name}'s content under the name {dest_name}")

    def test_every_libexec_helper_is_installed_and_packaged(self):
        installed = {Path(dest).name for _, dest in self.installs}
        for helper in sorted(p.name for p in LIBEXEC.iterdir() if p.is_file()):
            self.assertIn(
                helper, installed,
                f"libexec/{helper} exists in the tree but no %install line "
                f"puts it in the buildroot")
            self.assertRegex(
                self.files_section,
                rf"(?m)^%{{_libexecdir}}/workloadctl/{re.escape(helper)}$",
                f"libexec/{helper} is installed but absent from %files, so "
                f"rpmbuild would fail on unpackaged files (or silently drop "
                f"it if a glob covers the directory)")

    def test_no_helper_is_installed_twice(self):
        dests = [dest for _, dest in self.installs]
        dupes = {d for d in dests if dests.count(d) > 1}
        self.assertFalse(dupes, f"duplicate %install destinations: {dupes}")


if __name__ == "__main__":
    unittest.main()
