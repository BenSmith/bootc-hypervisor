#!/usr/bin/env python3
"""The spec must install every libexec helper and generator, once, under its
own name.

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

`generators/` is checked on the same terms as `libexec/`, and the asymmetry
that makes it worth stating: `lib/*.py` is installed by a GLOB, so a new
library module ships with no spec change at all, while every file in
`libexec/` and `generators/` is a hand-written `install -Dpm` line. That is
the whole reason a file split should move code DOWN into lib/ rather than
sideways into a new sibling entrypoint -- sideways is the shape that needs the
spec edited, and forgetting it ships a package whose unit points at a file
that is not there. This test is what turns that from a silent RPM defect into
a failing unit run.

The two generators do not share a destination -- workload-generator is a
systemd system-generator and lands under %{_prefix}/lib/systemd, while
workload-generate is a libexec-dir helper -- so the check is "installed
somewhere and packaged at that same path", not a fixed directory.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "rpm" / "workloadctl.spec"
LIBEXEC = ROOT / "libexec"
GENERATORS = ROOT / "generators"

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

    def test_every_generator_is_installed_and_packaged(self):
        """Same contract as the libexec helpers, different destinations.

        Asserted against the install line's own destination rather than an
        expected directory, because the two generators legitimately land in
        different trees and a test that pinned one would have to be edited to
        add a generator that belongs in the other.
        """
        by_source = {Path(src).name: dest for src, dest in self.installs}
        for gen in sorted(p.name for p in GENERATORS.iterdir() if p.is_file()):
            self.assertIn(
                gen, by_source,
                f"generators/{gen} exists in the tree but no %install line "
                f"puts it in the buildroot. Unlike lib/*.py, which the spec "
                f"installs by glob, every generator needs its own line")
            dest = by_source[gen]
            self.assertRegex(
                self.files_section,
                rf"(?m)^{re.escape(dest)}$",
                f"generators/{gen} is installed to {dest} but that path is "
                f"absent from %files")

    def test_no_helper_is_installed_twice(self):
        dests = [dest for _, dest in self.installs]
        dupes = {d for d in dests if dests.count(d) > 1}
        self.assertFalse(dupes, f"duplicate %install destinations: {dupes}")


if __name__ == "__main__":
    unittest.main()
