#!/usr/bin/env python3
"""The shipped seccomp baseline, as an artifact.

Every non-privileged workload runs under this profile, so a malformed or
self-contradicting file breaks every container on the host at once — and it fails
at `podman run` time, far from the edit that caused it. Nothing else in the suite
looks at the file's contents. A workload's [security] seccomp_allow derives
a profile from it, and the same checks hold every derived one.
"""
import json
import re
import unittest

from tests import REPO_ROOT
from workload_seccomp import derived_profile

PROFILE = REPO_ROOT / "seccomp-workload-baseline.json"
SPEC = REPO_ROOT / "rpm" / "workloadctl.spec"
TROUBLESHOOTING = REPO_ROOT.parent / "docs" / "TROUBLESHOOTING.md"
WORKLOADS = REPO_ROOT / "docs" / "workloads.md"

ENOSYS_TEXT = "Function not implemented"
EPERM_TEXT = "Operation not permitted"

# The futex2 syscalls. glibc currently probes and falls back to `futex` when
# these are denied, which is why blocking them was invisible; a release that
# stops falling back would turn it into an EPERM with no recovery.
FUTEX2 = {"futex_requeue", "futex_wait", "futex_waitv", "futex_wake"}


class ProfileChecks:
    """What every profile a workload runs under must hold: the baseline, and
    each derived from it by [security] seccomp_allow."""

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

    def test_capability_gated_denials_are_not_quietly_undone(self):
        """A name in the plain allow list wins over the cap-gated deny that was
        meant to restrict it — measured, not assumed: with `setns` in both, a
        container under this profile got EBADF from `setns(-1, 0)` rather than
        the EPERM the gate implies. So an overlap silently disables the gate."""
        allowed = self._ungated_allow_names()
        undone = set()
        for s in self.profile["syscalls"]:
            if s["action"] == "SCMP_ACT_ALLOW":
                continue
            if not (s.get("includes") or s.get("excludes")):
                continue
            undone |= allowed & set(s["names"])
        self.assertEqual(undone, set())

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


class TestSeccompBaseline(ProfileChecks, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = json.loads(PROFILE.read_text())

    def test_setns_is_only_reachable_with_cap_sys_admin(self):
        """This profile is deliberately stricter than upstream containers-common
        here: upstream lists `setns` in both the plain allow list and the
        deny-unless-CAP_SYS_ADMIN entry, which leaves it reachable by every
        rootless container. `setns` joins an existing namespace given an fd — the
        one syscall in that gated set most worth denying — and no shipped
        workload grants CAP_SYS_ADMIN, so the gate costs us nothing."""
        self.assertNotIn("setns", self._ungated_allow_names())
        gated = [s for s in self.profile["syscalls"]
                 if "setns" in s["names"]]
        self.assertEqual(len(gated), 2, "expected only the includes/excludes pair")
        for s in gated:
            self.assertTrue(s.get("includes") or s.get("excludes"))

    def test_cap_sys_admin_gate_covers_the_same_names_both_ways(self):
        """The CAP_SYS_ADMIN gate is a *pair* of entries — allow-when-included,
        ERRNO-when-excluded — and the two name lists must match exactly.

        A name only in the excludes half is denied unconditionally, which is
        stricter than the gate reads and silently diverges from the upstream
        profile we vendored. `perf_event_open` was missing from the allow half
        for exactly that reason: harmless in effect, but it dated our copy and
        made the pair look like two unrelated entries rather than one gate.
        """
        halves = {}
        for s in self.profile["syscalls"]:
            caps = (s.get("includes", {}).get("caps")
                    or s.get("excludes", {}).get("caps") or [])
            if caps != ["CAP_SYS_ADMIN"]:
                continue
            side = "includes" if s.get("includes", {}).get("caps") else "excludes"
            halves.setdefault(side, set()).update(s["names"])
        self.assertEqual(sorted(halves), ["excludes", "includes"],
                         "expected both halves of the CAP_SYS_ADMIN gate")
        self.assertEqual(halves["includes"], halves["excludes"])

    def test_generator_and_rpm_agree_on_where_it_lands(self):
        """The generator points every unit at an absolute path; the spec is what
        puts the file there. A rename that touches one and not the other yields
        units referencing a profile that does not exist."""
        # Imported, not scanned for. This used to regex the generator's source
        # by path; when the container generators moved to gen_container the
        # regex found nothing, which is the same reading it would give for a
        # constant that had genuinely been deleted.
        from workload_seccomp import SECCOMP_BASELINE as baseline
        self.assertEqual(baseline.rsplit("/", 1)[-1], PROFILE.name)
        spec = SPEC.read_text()
        installed = baseline.replace("/usr/share", "%{_datadir}")
        self.assertIn(installed, spec,
                      f"{installed} is not installed by the spec")

    @unittest.skipUnless(
        TROUBLESHOOTING.is_file(),
        "image half not present (standalone workloadctl checkout)")
    def test_the_docs_name_the_error_each_blocked_syscall_gives(self):
        """A syscall the baseline never names falls to defaultErrnoRet, 38:
        gdb in a stock workload prints 'ptrace: Function not implemented',
        and docs promising 'Operation not permitted' send the reader looking
        for the wrong layer. Measured 2026-10-04, a container per profile on
        a Fedora 44 host, each syscall called with an argument the kernel
        itself rejects, so the errno tells which layer refused:

            syscall            podman default    baseline   baseline + ptrace
            ptrace             ESRCH (kernel)    ENOSYS     ESRCH (kernel)
            process_vm_readv   0 (kernel)        ENOSYS     0 (kernel)
            keyctl             EOPNOTSUPP        ENOSYS     ENOSYS
            setns(-1, 0)       EBADF (kernel)    EPERM      EPERM
        """
        doc = _section(TROUBLESHOOTING.read_text(),
                       "### 9. Syscall blocked by seccomp profile")
        listed = re.search(r"The blocked syscalls are: (.*)", doc).group(1)
        names = re.findall(r"`([a-z0-9_]+)`", listed)
        self.assertTrue(names, "TROUBLESHOOTING.md §9 lists no syscalls")
        guide = _section(WORKLOADS.read_text(), "### Seccomp Filtering")
        for n in names:
            errno = _errno_for_an_uncapable_container(self.profile, n)
            with self.subTest(syscall=n, errno=errno):
                self.assertIn(errno, (1, 38), "allowed, yet listed as blocked")
                text = ENOSYS_TEXT if errno == 38 else EPERM_TEXT
                self.assertIn(text, doc)
                row = re.search(rf"^\| `{n[:10]}.*$", guide, re.M)
                self.assertIsNotNone(row, f"workloads.md has no row for {n}")
                self.assertIn(text, row.group(0))


def _errno_for_an_uncapable_container(profile, name):
    """The errno the profile returns for `name` in a container with no
    added capabilities, or None if it is allowed: an ungated entry decides
    first, then a capability gate's deny half, then the default."""
    for s in profile["syscalls"]:
        if name in s["names"] and not s.get("includes") \
                and not s.get("excludes") and not s.get("args"):
            if s["action"] == "SCMP_ACT_ALLOW":
                return None
            return s.get("errnoRet", profile["defaultErrnoRet"])
    for s in profile["syscalls"]:
        if name in s["names"] and s.get("excludes") \
                and s["action"] == "SCMP_ACT_ERRNO":
            return s.get("errnoRet", profile["defaultErrnoRet"])
    return profile["defaultErrnoRet"]


def _section(text, heading):
    """From `heading` to the next heading of the same or a higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    start = text.index(heading)
    rest = text[start + len(heading):]
    end = re.search(rf"^#{{1,{level}}} ", rest, re.M)
    return text[start:start + len(heading) + (end.start() if end else
                                              len(rest))]


def _restricted_names(profile):
    """Every name an entry of `profile` restricts: in a deny, behind a gate
    or an argument filter."""
    return sorted({n for s in profile["syscalls"]
                   if s["action"] != "SCMP_ACT_ALLOW" or s.get("includes")
                   or s.get("excludes") or s.get("args")
                   for n in s["names"]})


class TestAProfileAllowingEveryRestrictedName(ProfileChecks,
                                              unittest.TestCase):
    """The hardest seccomp_allow: every name the baseline denies, gates or
    filters by argument, at once. Each must come out of its entries, gate
    pairs included, or the derived profile breaks a check above."""

    @classmethod
    def setUpClass(cls):
        baseline = json.loads(PROFILE.read_text())
        cls.profile = derived_profile(baseline, _restricted_names(baseline))


class TestAProfileAllowingTheDebuggersCalls(ProfileChecks,
                                            unittest.TestCase):
    """What a debugger needs: ptrace and process_vm_*, which the baseline
    leaves to its default errno."""

    @classmethod
    def setUpClass(cls):
        baseline = json.loads(PROFILE.read_text())
        cls.profile = derived_profile(
            baseline, ["process_vm_readv", "process_vm_writev", "ptrace"])


class TestDerivedProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = json.loads(PROFILE.read_text())

    def test_each_restricted_name_is_allowed_by_one_entry_alone(self):
        """One name at a time: it appears in exactly one entry, an
        unconditional allow, and every other name keeps its entries."""
        for name in _restricted_names(self.baseline):
            with self.subTest(name=name):
                profile = derived_profile(self.baseline, [name])
                holding = [s for s in profile["syscalls"]
                           if name in s["names"]]
                self.assertEqual(holding, [{"names": [name],
                                            "action": "SCMP_ACT_ALLOW"}])
                rest = [dict(s, names=[n for n in s["names"] if n != name])
                        for s in self.baseline["syscalls"]]
                self.assertEqual(profile["syscalls"][:-1],
                                 [s for s in rest if s["names"]])

    def test_everything_but_the_syscalls_is_the_baselines(self):
        profile = derived_profile(self.baseline, ["ptrace"])
        self.assertEqual({k: v for k, v in profile.items()
                          if k != "syscalls"},
                         {k: v for k, v in self.baseline.items()
                          if k != "syscalls"})

    def test_the_baseline_is_not_changed(self):
        before = json.dumps(self.baseline)
        derived_profile(self.baseline, _restricted_names(self.baseline))
        self.assertEqual(json.dumps(self.baseline), before)


if __name__ == "__main__":
    unittest.main()
