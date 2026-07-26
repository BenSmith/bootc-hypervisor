#!/usr/bin/env python3
"""The shipped seccomp baseline, as an artifact.

Every non-privileged workload runs under this profile, so a malformed or
self-contradicting file breaks every container on the host at once — and it fails
at `podman run` time, far from the edit that caused it. Nothing else in the suite
looks at the file's contents.
"""
import json
import re
import unittest

from tests import REPO_ROOT

PROFILE = REPO_ROOT / "seccomp-workload-baseline.json"
GENERATOR = REPO_ROOT / "generators" / "workload-generate"
SPEC = REPO_ROOT / "rpm" / "workloadctl.spec"

# The futex2 syscalls. glibc currently probes and falls back to `futex` when
# these are denied, which is why blocking them was invisible; a release that
# stops falling back would turn it into an EPERM with no recovery.
FUTEX2 = {"futex_requeue", "futex_wait", "futex_waitv", "futex_wake"}


class TestSeccompBaseline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = json.loads(PROFILE.read_text())

    def _entries(self, action):
        return [s for s in self.profile["syscalls"] if s["action"] == action]

    def _ungated_allow_names(self):
        """Names allowed unconditionally — no includes/excludes gating.

        A name allowed only under `includes` (a capability, an arch) is not
        allowed for an ordinary workload, so gated entries cannot be treated as
        equivalent to a plain allow.
        """
        names = set()
        for s in self._entries("SCMP_ACT_ALLOW"):
            if not s.get("includes") and not s.get("excludes"):
                names.update(s["names"])
        return names

    def test_profile_is_valid_json_with_the_expected_shape(self):
        self.assertEqual(self.profile["defaultAction"], "SCMP_ACT_ERRNO")
        self.assertTrue(self.profile["syscalls"])
        for s in self.profile["syscalls"]:
            self.assertIn("action", s)
            self.assertTrue(s.get("names"), "a syscalls entry has no names")

    def test_no_syscall_is_both_ungated_allowed_and_ungated_denied(self):
        """The failure mode this guards: adding a name to the allow list while
        leaving it in a deny entry. Which rule wins is a libseccomp ordering
        detail, so the profile must not depend on it."""
        allowed = self._ungated_allow_names()
        for s in self.profile["syscalls"]:
            if s["action"] == "SCMP_ACT_ALLOW":
                continue
            if s.get("includes") or s.get("excludes"):
                continue
            overlap = allowed & set(s["names"])
            self.assertEqual(
                overlap, set(),
                f"{sorted(overlap)} appear in both the allow list and a "
                f"{s['action']} entry")

    # `setns` is in the plain allow list *and* in the deny-unless-CAP_SYS_ADMIN
    # entry, so the capability gate on it is at best order-dependent. The other
    # five names in that gated set are correctly absent from the plain allow
    # list, which is what marks this one as a slip rather than a decision.
    # Recorded rather than fixed: dropping it from the allow list is a runtime
    # behaviour change for any workload that calls setns without CAP_SYS_ADMIN.
    KNOWN_UNGATED_DESPITE_CAP_GATE = {"setns"}

    def test_capability_gated_denials_are_not_quietly_undone(self):
        """A name in the plain allow list overrides — or races — the cap-gated
        deny that was meant to restrict it. Asserting the exact set means a new
        one cannot join the existing exception unnoticed."""
        allowed = self._ungated_allow_names()
        undone = set()
        for s in self.profile["syscalls"]:
            if s["action"] == "SCMP_ACT_ALLOW":
                continue
            if not (s.get("includes") or s.get("excludes")):
                continue
            undone |= allowed & set(s["names"])
        self.assertEqual(undone, self.KNOWN_UNGATED_DESPITE_CAP_GATE)

    def test_futex2_family_is_allowed(self):
        """Denying futex2 while allowing `futex` gains nothing — the same
        synchronisation capability is already reachable — and diverges from
        upstream containers-common."""
        allowed = self._ungated_allow_names()
        self.assertLessEqual(FUTEX2, allowed)
        self.assertIn("futex", allowed)
        self.assertIn("futex_time64", allowed)

    def test_names_within_each_entry_are_sorted(self):
        """These lists are maintained by hand and diffed against upstream;
        sorted order is what keeps that diff readable."""
        for s in self.profile["syscalls"]:
            names = s["names"]
            self.assertEqual(names, sorted(names),
                             f"unsorted names in a {s['action']} entry")

    def test_generator_and_rpm_agree_on_where_it_lands(self):
        """The generator points every unit at an absolute path; the spec is what
        puts the file there. A rename that touches one and not the other yields
        units referencing a profile that does not exist."""
        m = re.search(r'^SECCOMP_BASELINE = "([^"]+)"', GENERATOR.read_text(), re.M)
        self.assertIsNotNone(m, "SECCOMP_BASELINE not found in the generator")
        baseline = m.group(1)
        self.assertEqual(baseline.rsplit("/", 1)[-1], PROFILE.name)
        spec = SPEC.read_text()
        installed = baseline.replace("/usr/share", "%{_datadir}")
        self.assertIn(installed, spec,
                      f"{installed} is not installed by the spec")


if __name__ == "__main__":
    unittest.main()
