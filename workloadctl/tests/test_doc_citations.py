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

# `~/...` is the same idea as RUNTIME_PREFIXES one syntax over: it names a
# location in whoever-is-reading's home directory, which is by construction not
# a file in this repo. Stripped from the line rather than guarded against after
# the match, for the reason URLs are: CITATION starts matching *inside* it
# (`~/.claude/CLAUDE.md` matches from the slash, yielding `/.claude/CLAUDE.md`),
# so a check on the text before the match sees only `~/` on a path the regex
# has already reduced to a repo-shaped one.
HOME_RELATIVE = re.compile(r"~/\S*")


def _scannable(line: str) -> str:
    """The part of a line that can hold a citation to a file in this repo."""
    return HOME_RELATIVE.sub(" ", URL.sub(" ", line))

# Citations into someone else's source tree. The policy is about docs *we* own;
# an upstream filename is a useful pointer even though it is not in this repo.
# Keep this list short — every entry is a citation a reader cannot follow from a
# clean checkout, so it needs to be worth that.
EXTERNAL = {
    # podman's own docs, read from the gitignored .reference/podman clone.
    "options/cgroups.md",
}


def _resolves_against(tracked, citing: Path, cite: str) -> bool:
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
            if rel in tracked:
                return True
            if base == GIT_ROOT:
                break
        return False
    # A bare filename is a relative link whose base depends on where the
    # reader is (a docs/ index row, a "see cli.md" in a sibling doc), so it
    # is enough that some tracked file has that name. Case-sensitive on
    # purpose: `readme.md` does not resolve to `README.md` on the
    # case-sensitive filesystems this ships to.
    return any(t.rsplit("/", 1)[-1] == bare for t in tracked)


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
        return _resolves_against(self.tracked, citing, cite)

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
                    if target.startswith("~/"):
                        continue  # the reader's home, not this repo
                    if not self._link_resolves(path, target):
                        found.append(f"{rel}:{lineno} links to {target!r}")
                for m in CITATION.finditer(_scannable(line)):
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

    def test_a_home_relative_path_is_not_a_citation(self):
        """`~/.claude/CLAUDE.md` names a file in the reader's home. Left
        unstripped, CITATION matches from the dot and reports it as the repo
        path `/.claude/CLAUDE.md`, so the tilde has to come off the line
        before the scan rather than be inspected after it."""
        line = "rtk init --global   # Add RTK to ~/.claude/CLAUDE.md"
        self.assertEqual(CITATION.search(line).group(1), "/.claude/CLAUDE.md")
        self.assertIsNone(CITATION.search(_scannable(line)))
        # Only the tilde path is removed: a real citation on the same line
        # still has to resolve.
        both = "see docs/workloads.md and ~/.config/notes.md"
        self.assertEqual(
            [m.group(1) for m in CITATION.finditer(_scannable(both))],
            ["docs/workloads.md"])
        # And a link target is skipped by its own guard, not by _scannable.
        probe = GIT_ROOT / "workloadctl" / "docs" / "workloads.md"
        self.assertFalse(self._link_resolves(probe, "~/.claude/CLAUDE.md"))

    def test_a_path_inside_a_url_is_not_a_citation(self):
        """A citation regex can match starting mid-URL, so URLs are stripped
        from the line before scanning rather than guarded against after."""
        line = "curl -sSf https://example.com/docs/nonexistent.md -o x"
        self.assertIsNone(CITATION.search(URL.sub(" ", line)))
        # The link rule has its own scheme guard.
        self.assertTrue(SCHEME.match("https://example.com/a.yml"))


if __name__ == "__main__":
    unittest.main()


# The same policy one file-type over: a comment that names a test module is a
# citation, and it has to resolve.
#
# The `.md` rule above cannot see these — a `tests/test_x.py` in a comment is
# not a markdown link and does not end in `.md` — and code cites tests
# constantly in this tree, because "restating this constant is safe, and here
# is the pin that makes it safe" is the standard justification for a second
# definition of a listener string. A pin named in a comment and absent from the
# tree is that justification with nothing behind it.
CODE_CITATION = re.compile(
    r"(?<![A-Za-z0-9_./-])(tests/(?:[A-Za-z0-9_]+/)*[A-Za-z0-9_]+\.py)"
    r"(?![A-Za-z0-9_])")

# Citations to a module that has been DELETED, kept as history rather than as a
# pointer ("it lived in tests/test_vm_proxy.py until rung 2 deleted that
# module"). Naming a file in order to say it is gone is not a promise the
# reader can open it, and rewriting the sentence to avoid the name would lose
# the only thing that makes the move traceable.
#
# Keep this list short, and add to it only for that shape. An entry here is a
# citation the check can no longer see, so a LIVE citation that drifted onto a
# retired name would be waved through with it.
RETIRED = {
    "tests/test_vm_proxy.py",
    # Deleted at rung 6 with the mechanism it dialled -- a host-wide broker at
    # an advertised endpoint. The sentences that still name it say plainly that
    # it is gone and that its replacement is unwritten, which is the condition
    # this allowlist is for: a citation that is HISTORY, not a live pointer.
    "tests/manual/broker_rig.py",
}


class TestCodeCitations(unittest.TestCase):
    """A comment that names a test file must name one that exists.

    WHAT THIS CATCHES is the deletion and rename class: a test module that
    moves or goes away, leaving every comment that pointed at it claiming a
    guarantee that is no longer anywhere. Measured before it was written
    (2026-09-01): 45 such citations across the tracked tree, of which exactly
    one did not resolve, and that one is the retired-module sentence above.

    WHAT IT DOES NOT CATCH, said plainly because the check was written after
    two of these and would have caught neither: a citation that resolves to the
    WRONG tracked file. `lib/vm.py` pointed its internal-prefix pin at
    `tests/test_cmd_egress.py` (the assertion is in `tests/test_vm_egress.py`)
    and its log-field pin at `tests/test_vm_inspect_diagnose.py` (it is in
    `tests/test_vm_inspect_record.py`); both exist, so both pass here. A
    reciprocity rule — require the cited module to name the definition the
    comment is attached to — was prototyped against the same 45 and rejected:
    only 14 yielded a subject at all, and two of the three it flagged were
    sound citations whose subject the heuristic had misread. A gate with
    thirty blind spots and a two-thirds false-positive rate teaches people to
    ignore it. Misdirection stays a thing review finds.
    """

    @classmethod
    def setUpClass(cls):
        try:
            cls.tracked = set(_git("ls-files").split())
        except (OSError, subprocess.CalledProcessError) as e:
            raise unittest.SkipTest(f"git unavailable: {e}")
        if not cls.tracked:
            raise unittest.SkipTest("no tracked files")

    def _violations(self):
        found = []
        own = Path(__file__).resolve().relative_to(GIT_ROOT).as_posix()
        for rel in sorted(self.tracked):
            path = GIT_ROOT / rel
            if not path.is_file() or rel == own:
                continue
            try:
                text = path.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                for m in CODE_CITATION.finditer(_scannable(line)):
                    cite = m.group(1)
                    if cite in RETIRED:
                        continue
                    if not self._code_resolves(path, cite):
                        found.append(f"{rel}:{lineno} cites {cite!r}")
        return found

    def _code_resolves(self, citing: Path, cite: str) -> bool:
        """The ancestor walk, plus one base the doc rule does not need.

        workloadctl/ is a self-contained project nested in the image repo, and
        files at the ROOT that discuss it write its paths project-relative,
        because that is how they read to somebody working in it: the root
        CLAUDE.md says `tests/test_vm_broker.py` and hypervisor.Containerfile
        names the modules that need the openssl CLI. Those are followable —
        the reader is told which project — so resolving them only against the
        citing file's own ancestors would fail three sound citations and the
        first person to hit it would delete the check rather than the comment.

        One extra base, not "any directory that has a tests/": the repo has
        exactly one nested project, and a wildcard would let a citation
        resolve against a tree it was never about.
        """
        return (_resolves_against(self.tracked, citing, cite)
                or _resolves_against(self.tracked, REPO_ROOT / "x", cite))

    def test_every_cited_test_module_is_tracked(self):
        violations = self._violations()
        self.assertEqual(
            violations, [],
            "tracked files name test modules that are not tracked — retarget "
            "at the module that actually holds the assertion, or say plainly "
            "that it is gone and add it to RETIRED:\n  "
            + "\n  ".join(violations))

    def test_the_checker_would_notice_a_regression(self):
        """Vacuous-green guard, for the reason the doc rule has one: this
        regex walks comments, and a green run over zero matches looks
        identical to a green run over all of them."""
        probe = GIT_ROOT / "workloadctl" / "lib" / "vm.py"
        self.assertFalse(
            _resolves_against(self.tracked, probe, "tests/test_nonesuch.py"))
        self.assertTrue(
            _resolves_against(self.tracked, probe, "tests/test_vm_egress.py"))

    def test_the_scan_actually_finds_citations(self):
        """The other half of the same guard, on the REGEX rather than on the
        resolver: a pattern that stopped matching would make _violations()
        return [] over nothing at all."""
        text = (GIT_ROOT / "workloadctl" / "lib" / "vm.py").read_text()
        hits = {m.group(1) for m in CODE_CITATION.finditer(text)}
        self.assertIn("tests/test_vm_egress.py", hits)
        self.assertGreater(len(hits), 1)

    def test_a_root_file_may_write_a_workloadctl_relative_path(self):
        """The root CLAUDE.md and hypervisor.Containerfile both do. Pinned so
        the extra base is not quietly dropped as redundant."""
        root_file = GIT_ROOT / "CLAUDE.md"
        self.assertFalse(
            _resolves_against(self.tracked, root_file,
                              "tests/test_vm_broker.py"))
        self.assertTrue(
            self._code_resolves(root_file, "tests/test_vm_broker.py"))
        self.assertFalse(
            self._code_resolves(root_file, "tests/test_nonesuch.py"))

    def test_a_retired_name_is_exempt_only_by_being_listed(self):
        """RETIRED is an allowlist, not a wildcard: a second deleted module
        does not inherit the first one's exemption."""
        self.assertIn("tests/test_vm_proxy.py", RETIRED)
        self.assertFalse(
            _resolves_against(self.tracked,
                              GIT_ROOT / "workloadctl" / "lib" / "vm.py",
                              "tests/test_vm_proxy.py"))
