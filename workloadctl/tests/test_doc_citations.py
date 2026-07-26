#!/usr/bin/env python3
"""Policy: tracked files may not cite untracked docs.

A citation is a promise that a reader can follow it. `docs/wip/` is gitignored
("kept local until promoted to tracked docs"), and the promotion kept not
happening — so tracked code, three ADRs and several CI workflows ended up
pointing at files that were never shippable and in some cases never existed at
all. Rationale that lives only in an unreachable file is worse than no citation:
it reads as authoritative and cannot be checked.

This walks every tracked file, finds `*.md` references, and asserts each one
resolves to a tracked file. It covers the whole repository, not just
workloadctl/ — the original rot was spread across both halves, and the citing
side is what this enforces, wherever it lives.

Skipped cleanly when git isn't available or the tree isn't a checkout.
"""
import re
import subprocess
import unittest
from pathlib import Path

from tests import REPO_ROOT

# workloadctl/ is nested inside the image repo; the policy is repo-wide.
GIT_ROOT = REPO_ROOT.parent

CITATION = re.compile(r"(?<![A-Za-z0-9])(/?[A-Za-z0-9_][A-Za-z0-9_./-]*\.md)(?![A-Za-z0-9])")

# Absolute paths naming a location on a *running host*, not a file in the repo.
RUNTIME_PREFIXES = ("/usr/", "/etc/", "/var/", "/run/", "/tmp/", "/home/", "/opt/")

# Citations into someone else's source tree. The policy is about docs *we* own;
# an upstream filename is a useful pointer even though it is not in this repo.
# Keep this list short — every entry is a citation a reader cannot follow from a
# clean checkout, so it needs to be worth that.
EXTERNAL = {
    # podman's own docs, read from the gitignored .reference/podman clone.
    "options/cgroups.md",
}


def _git(*args):
    return subprocess.run(
        ["git", *args], cwd=GIT_ROOT,
        capture_output=True, text=True, check=True,
    ).stdout


class TestDocCitations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.tracked = set(_git("ls-files").split())
        except (OSError, subprocess.CalledProcessError) as e:
            raise unittest.SkipTest(f"git unavailable: {e}")
        if not cls.tracked:
            raise unittest.SkipTest("no tracked files")

    def _resolves(self, citing: Path, cite: str) -> bool:
        """Does `cite`, as written in `citing`, name a tracked file?"""
        bare = cite.lstrip("/")
        if "/" in bare:
            # A path is resolved against each ancestor directory of the citing
            # file, innermost first: `docs/workloads.md` inside workloadctl/
            # means workloadctl/docs/workloads.md, and the same string at the
            # repo root means the root docs/. Both are legitimate.
            for base in citing.parents:
                candidate = (base / bare).resolve()
                try:
                    rel = candidate.relative_to(GIT_ROOT).as_posix()
                except ValueError:
                    continue
                if rel in self.tracked:
                    return True
                if base == GIT_ROOT:
                    break
            return False
        # A bare filename is a relative link whose base depends on where the
        # reader is (a docs/ index row, a "see cli.md" in a sibling doc), so it
        # is enough that some tracked file has that name. Case-sensitive on
        # purpose: `readme.md` does not resolve to `README.md` on the
        # case-sensitive filesystems this ships to.
        return any(t.rsplit("/", 1)[-1] == bare for t in self.tracked)

    def _violations(self):
        found = []
        own = Path(__file__).resolve().relative_to(GIT_ROOT).as_posix()
        for rel in sorted(self.tracked):
            path = GIT_ROOT / rel
            if not path.is_file():
                continue
            # This module's own `*.md` strings are the fixtures the regression
            # test feeds the checker: names chosen precisely because they do not
            # resolve. Scanning them would make the file fail itself.
            if rel == own:
                continue
            try:
                text = path.read_text()
            except (UnicodeDecodeError, OSError):
                continue  # binary or unreadable: nothing to cite from
            for lineno, line in enumerate(text.splitlines(), 1):
                # An RPM macro path is a build destination, not a citation.
                if "%{" in line:
                    continue
                for m in CITATION.finditer(line):
                    cite = m.group(1)
                    if cite in EXTERNAL or cite.startswith(RUNTIME_PREFIXES):
                        continue
                    before = line[:m.start()]
                    if "http://" in before or "https://" in before:
                        continue
                    if not self._resolves(path, cite):
                        found.append(f"{rel}:{lineno} cites {cite!r}")
        return found

    def test_every_cited_doc_is_tracked(self):
        violations = self._violations()
        self.assertEqual(
            violations, [],
            "tracked files cite docs that are not tracked — write the doc, "
            "retarget the citation at something tracked, or drop it:\n  "
            + "\n  ".join(violations))

    def test_the_checker_would_notice_a_regression(self):
        """A green result is only meaningful if the check can fail. Guards
        against a future refactor that quietly stops matching anything."""
        probe = GIT_ROOT / "workloadctl" / "lib" / "workload_lib.py"
        self.assertIn(probe.as_posix().replace(GIT_ROOT.as_posix() + "/", ""),
                      self.tracked, "probe file is not tracked")
        self.assertFalse(self._resolves(probe, "docs/wip/does-not-exist.md"))
        self.assertFalse(self._resolves(probe, "totally-made-up-name.md"))
        # And a real one still resolves, so it is not just rejecting everything.
        self.assertTrue(self._resolves(probe, "docs/workloads.md"))


if __name__ == "__main__":
    unittest.main()
