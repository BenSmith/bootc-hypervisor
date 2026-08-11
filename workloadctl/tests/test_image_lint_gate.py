#!/usr/bin/env python3
"""Every hypervisor image lints itself, with the same exemptions.

`bootc container lint --fatal-warnings` runs *inside* each Containerfile, so it
is a build gate rather than a post-hoc check: an image that exists at all is an
image whose lint exited 0. That matters for the variants — the two NVIDIA images
are private on ghcr and cannot be pulled for an independent check, but they are
built by the same matrix as the base, so a green build already is the
verification. Nothing here needs to pull an image.

What is *not* self-verifying is that all four images carry the gate, and carry
the same skip-set. A variant that dropped `--fatal-warnings` would still build
green while linting nothing, and a variant that skipped a fourth lint would hide
a real regression behind an exemption the base image never granted. Both are
silent, so both are pinned here.

Skipped in a standalone workloadctl checkout, where the image half is absent.
"""
import re
import unittest

from tests import REPO_ROOT

# workloadctl/ is nested inside the image repo.
GIT_ROOT = REPO_ROOT.parent
CONTAINERFILES = sorted(GIT_ROOT.glob("hypervisor*.Containerfile"))

# The exemptions the base image justifies (see the comment on its lint call).
# Every image gets these three and no others.
EXPECTED_SKIPS = frozenset({"var-tmpfiles", "var-log", "nonempty-run-tmp"})

# Everything up to the first newline that is not a `\`-continuation.
LINT_CALL = re.compile(r"bootc container lint\b(?:[^\n\\]|\\\n)*")


def _lint_calls(text: str) -> list[str]:
    """Each `bootc container lint` invocation, continuations folded in."""
    return [m.group(0).replace("\\\n", " ") for m in LINT_CALL.finditer(text)]


@unittest.skipUnless(CONTAINERFILES,
                     "image half not present (standalone workloadctl checkout)")
class TestImageLintGate(unittest.TestCase):
    def test_every_hypervisor_image_lints_itself(self):
        """A variant with no lint call builds green while checking nothing.

        At least one, not exactly one. The base image lints twice on purpose:
        once partway through, so a regression in the packages layer fails at
        the packages layer, and once at the end, because everything after the
        first call — the workloadctl RPM and what it drags in — was otherwise
        checked only incidentally by the variants. That gap is what turned a
        tinyproxy packaging bug into a hypervisor-amd build failure.

        The count is not the invariant. The invariant is that every call is a
        real gate, which the two tests below check on ALL calls rather than on
        the first — a second call that quietly dropped --fatal-warnings or
        granted itself an extra --skip would otherwise be invisible here.
        """
        for cf in CONTAINERFILES:
            with self.subTest(containerfile=cf.name):
                self.assertGreaterEqual(
                    len(_lint_calls(cf.read_text())), 1,
                    f"{cf.name} should run `bootc container lint` at least once")

    def test_warnings_are_fatal_everywhere(self):
        """Without --fatal-warnings bootc exits 0 on warnings, which is how the
        pre-`--skip` allowlist managed to be decorative for so long."""
        for cf in CONTAINERFILES:
            for i, call in enumerate(_lint_calls(cf.read_text())):
                with self.subTest(containerfile=cf.name, call=i):
                    self.assertIn("--fatal-warnings", call)

    def test_the_skip_set_is_identical_across_variants(self):
        """The base image's three exemptions are the whole exemption budget. A
        variant granting a fourth would suppress a lint the base still enforces,
        and only its own build would ever know. The same applies to a second
        call within one file, so this checks every call and not just the first.
        """
        for cf in CONTAINERFILES:
            for i, call in enumerate(_lint_calls(cf.read_text())):
                with self.subTest(containerfile=cf.name, call=i):
                    skips = set(re.findall(r"--skip\s+(\S+)", call))
                    self.assertEqual(skips, set(EXPECTED_SKIPS))
