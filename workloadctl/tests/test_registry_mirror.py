#!/usr/bin/env python3
"""The registry.local mirror ships only where the homelab CA ships.

`registries.conf.d/mirrors.conf` points docker.io, ghcr.io, quay.io,
codeberg.org and registry.fedoraproject.org at a registry.local mirror that is
tried *first*. registry.local resolves over mDNS — the image enables avahi and
puts mdns4_minimal ahead of dns in nsswitch, and .local is mDNS's own domain —
so the name is claimable by anything on the link. Two things keep that from
being a hijack of every third-party pull, and both are one edit away from being
lost:

  * the mirror is installed only inside the ca-trust-inject conditional, so the
    public ghcr image (no homelab CA, no meaning for the name) never gets it;
  * TLS verification is on, so an impostor needs a cert the homelab CA chain
    validates.

policy.json does not backstop either one: those five scopes are
allowlisted-unverified, and the policy is keyed on the ref the user wrote, not
on the host actually contacted. An unconditional COPY, or `insecure = true`,
would reopen it silently — nothing would fail, pulls would just quietly start
trusting whoever answered.

This is a repo-wide check like test_doc_citations.py; it lives here because
this is the only suite the repo has. Skipped cleanly in a standalone
workloadctl checkout, where the image half is absent.
"""
import re
import unittest
from pathlib import Path

from tests import REPO_ROOT

# workloadctl/ is nested inside the image repo.
GIT_ROOT = REPO_ROOT.parent
CONTAINERFILE = GIT_ROOT / "hypervisor.Containerfile"
MIRRORS = GIT_ROOT / "registries.conf.d" / "mirrors.conf"

# A `RUN ...` stanza with its line continuations folded in.
RUN_BLOCK = re.compile(r"^RUN .*?(?<!\\)$", re.MULTILINE | re.DOTALL)


def _run_blocks(text: str) -> list[str]:
    """Every RUN instruction in the file, backslash-continuations joined."""
    blocks, current = [], None
    for line in text.splitlines():
        if current is not None:
            current.append(line)
            if not line.rstrip().endswith("\\"):
                blocks.append("\n".join(current))
                current = None
        elif line.startswith("RUN "):
            current = [line]
            if not line.rstrip().endswith("\\"):
                blocks.append(line)
                current = None
    if current is not None:
        blocks.append("\n".join(current))
    return blocks


@unittest.skipUnless(CONTAINERFILE.is_file(),
                     "image half not present (standalone workloadctl checkout)")
class TestRegistryMirrorIsGated(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.containerfile = CONTAINERFILE.read_text()
        cls.mirrors = MIRRORS.read_text()

    def _directives(self) -> str:
        """The file with comments and blank lines stripped."""
        return "\n".join(line for line in self.mirrors.splitlines()
                         if line.strip() and not line.lstrip().startswith("#"))

    def test_mirror_is_never_copied_straight_into_etc(self):
        # A bare `COPY registries.conf.d/mirrors.conf /etc/...` is the
        # regression: it puts the mirror in the public image too.
        for line in self.containerfile.splitlines():
            if line.startswith("COPY ") and "mirrors.conf" in line:
                self.assertNotIn("/etc/containers", line, line)

    def test_the_only_install_into_etc_is_ca_gated(self):
        installing = [b for b in _run_blocks(self.containerfile)
                      if "mirrors.conf" in b
                      and "/etc/containers/registries.conf.d" in b]
        self.assertEqual(len(installing), 1, self.containerfile)
        # Same block must be the one testing for an injected anchor, so the
        # mirror cannot outlive the CA that secures it.
        self.assertIn("ca-trust-inject", installing[0])
        self.assertIn(".crt", installing[0])

    def test_tls_verification_stays_on(self):
        # `insecure = true` disables the only check standing between a spoofed
        # mDNS reply and every mirrored pull. Directives only — the file's own
        # header explains why the flag is absent, and saying so is not setting
        # it.
        self.assertNotIn("insecure", self._directives())

    def test_every_mirror_is_the_homelab_cache(self):
        locations = re.findall(r"^location = \"(.+)\"$", self._directives(),
                               re.MULTILINE)
        mirrors = [loc for loc in locations if loc == "registry.local"]
        # One [[registry]] + one [[registry.mirror]] per upstream, and every
        # mirror is the cache — a mirror pointing anywhere else is not a cache.
        self.assertEqual(len(locations), 2 * len(mirrors), self.mirrors)
        self.assertGreater(len(mirrors), 0)


if __name__ == "__main__":
    unittest.main()
