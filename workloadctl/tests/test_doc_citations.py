#!/usr/bin/env python3
"""Policy: tracked files may not cite untracked docs.

A citation is a promise that a reader can follow it. `docs/wip/` is gitignored
("kept local until promoted to tracked docs"), and the promotion kept not
happening — so tracked code, three ADRs and several CI workflows ended up
pointing at files that were never shippable and in some cases never existed at
all. Rationale that lives only in an unreachable file is worse than no citation:
it reads as authoritative and cannot be checked.

This walks every tracked file and asserts that two kinds of citation resolve to
something tracked:

  1. a bare `*.md` reference, anywhere — prose, a comment, a workflow;
  2. a **markdown link target**, `[text](path)`, at any extension.

(2) exists because Q3-9 was a `.md` → `.yml` citation, outside (1)'s net. The
axis is link *syntax*, not file extension, and that was measured rather than
guessed (2026-07-29): widening (1) to any path-with-an-extension matches 262
citations of which 99 resolve to nothing, and they are illustrative rather than
referential — systemd unit-name fragments like
`user@<uid>.service.d/50-workload.conf`, `~/.config/...` paths, in-container
paths, upstream repo paths, test fixture strings, and outputs being created by
the command on that line. Exempting all of that is a list that grows every time
a test gains a path-shaped string. Link targets have none of that problem: 68
in the tree, 24 of them non-`.md`, and the only three that did not resolve were
real — `workloadctl/docs/workloads.md` pointing into `../workloads.d/`, the
pre-bundle layout, which has zero tracked files. A `[text](target)` is
syntactically a promise the reader can follow it; a path in prose or in a code
line is not.

It covers the whole repository, not just workloadctl/ — the original rot was
spread across both halves, and the citing side is what this enforces, wherever
it lives.

Skipped cleanly when git isn't available or the tree isn't a checkout.
"""
import re
import subprocess
import unittest
from pathlib import Path

from tests import REPO_ROOT

# workloadctl/ is nested inside the image repo; the policy is repo-wide.
GIT_ROOT = REPO_ROOT.parent

# A leading dot is part of the path, not a boundary: `.github/workflows/x.md`
# must be matched whole, or it degrades to `github/workflows/x.md` and resolves
# to nothing.
CITATION = re.compile(
    r"(?<![A-Za-z0-9])(/?\.?[A-Za-z0-9_][A-Za-z0-9_./-]*\.md)(?![A-Za-z0-9])")

# `[text](target)`, with an optional "title" after the target. Reference-style
# links and bare autolinks are deliberately not matched — neither appears in
# this tree, and both would need their own resolution rules.
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

# Anything with a scheme is somebody else's namespace. Stripped from the line
# before scanning rather than guarded against afterwards: a citation regex can
# match starting *inside* a URL (`https://just.systems/install.sh` matches from
# the `/`), and a guard that inspects the text before the match then sees only
# `https:` and lets it through.
URL = re.compile(r"[a-z][a-z0-9+.-]*://\S+")
SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:")

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

    def _link_resolves(self, citing: Path, target: str) -> bool:
        """Does a markdown link target name something a reader can open?

        Same resolution as a citation, with two additions a link needs and a
        prose mention doesn't: a trailing `#anchor` is part of the link, not
        the path; and a link may legitimately point at a directory.
        """
        target = target.split("#", 1)[0]
        if not target:
            return True  # pure in-page anchor
        if self._resolves(citing, target):
            return True
        bare = target.lstrip("/")
        if "/" not in bare:
            return False
        for base in citing.parents:
            candidate = (base / bare).resolve()
            try:
                rel = candidate.relative_to(GIT_ROOT).as_posix()
            except ValueError:
                continue
            # A directory counts only if the repo actually tracks something
            # under it — an empty or gitignored directory is as unfollowable
            # from a clean checkout as a missing file.
            if any(t == rel or t.startswith(rel.rstrip("/") + "/")
                   for t in self.tracked):
                return True
            if base == GIT_ROOT:
                break
        return False

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
                for m in LINK.finditer(line):
                    target = m.group(1)
                    if SCHEME.match(target) or target.startswith("#"):
                        continue  # URL, mailto:, in-page anchor
                    if target in EXTERNAL or target.startswith(RUNTIME_PREFIXES):
                        continue
                    if not self._link_resolves(path, target):
                        found.append(f"{rel}:{lineno} links to {target!r}")
                for m in CITATION.finditer(URL.sub(" ", line)):
                    cite = m.group(1)
                    if cite in EXTERNAL or cite.startswith(RUNTIME_PREFIXES):
                        continue
                    if not self._resolves(path, cite):
                        found.append(f"{rel}:{lineno} cites {cite!r}")
        return found

    def test_every_cited_doc_is_tracked(self):
        violations = self._violations()
        self.assertEqual(
            violations, [],
            "tracked files cite or link to paths that are not tracked — write "
            "the file, retarget at something tracked, or drop it:\n  "
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

    def test_link_targets_are_checked_at_any_extension(self):
        """The Q3-9 class: a `.md` → non-`.md` link. The extension filter on
        CITATION means only the link rule can see these."""
        probe = GIT_ROOT / "workloadctl" / "docs" / "workloads.md"
        self.assertFalse(self._link_resolves(probe, "../workloads.d/gone.toml"))
        self.assertFalse(
            self._link_resolves(probe, ".forgejo/workflows/nonesuch.yml"))
        self.assertTrue(self._link_resolves(probe, "schema-reference.toml"))
        self.assertTrue(
            self._link_resolves(probe, "../workloads/webproxy-demo/workload.toml"))

    def test_link_anchor_is_not_part_of_the_path(self):
        probe = GIT_ROOT / "workloadctl" / "docs" / "workloads.md"
        self.assertTrue(self._link_resolves(probe, "cli.md#logs"))
        self.assertFalse(self._link_resolves(probe, "no-such-doc.md#logs"))

    def test_link_may_point_at_a_directory_that_has_tracked_content(self):
        probe = GIT_ROOT / "workloadctl" / "docs" / "workloads.md"
        self.assertTrue(self._link_resolves(probe, "../workloads/webproxy-demo"))
        self.assertFalse(self._link_resolves(probe, "../workloads/no-such-bundle"))
        # docs/wip/ is gitignored: it exists on this machine but has nothing
        # tracked under it, which is the whole point of the policy.
        self.assertFalse(self._link_resolves(probe, "wip"))

    def test_dotted_directories_are_matched_whole(self):
        """`.forgejo/...` must not degrade to `forgejo/...`, which resolves to
        nothing and would make every CI citation a false positive."""
        m = CITATION.search("see .forgejo/workflows/nope.md for details")
        self.assertEqual(m.group(1), ".forgejo/workflows/nope.md")

    def test_a_path_inside_a_url_is_not_a_citation(self):
        """A citation regex can match starting mid-URL, so URLs are stripped
        from the line before scanning rather than guarded against after."""
        line = "curl -sSf https://example.com/docs/nonexistent.md -o x"
        self.assertIsNone(CITATION.search(URL.sub(" ", line)))
        # The link rule has its own scheme guard.
        self.assertTrue(SCHEME.match("https://example.com/a.yml"))


if __name__ == "__main__":
    unittest.main()
