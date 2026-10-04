#!/usr/bin/env python3
"""PINNED: three findings from the 2026-10-04 audit of how workloads alter
seccomp. These tests fail on purpose until the findings are fixed; each
failure message starts "PINNED seccomp finding N/3" and says what is wrong
and what fixed looks like.

Findings 1 and 2 are about gamedev-sway, a bundle on the `internal` branch,
and need a design decision, so they fail unconditionally: delete each once
it is fixed. Finding 3 is checked against the docs and passes on its own
once they are corrected.

How the audit measured (a container per profile on a Fedora 44 host, each
syscall called with an argument the kernel itself rejects, so the errno
tells which layer refused):

    syscall            podman default    baseline          baseline + ptrace
    ptrace             ESRCH (kernel)    ENOSYS            ESRCH (kernel)
    process_vm_readv   0 (kernel)        ENOSYS            0 (kernel)
    keyctl             EOPNOTSUPP        ENOSYS            ENOSYS
    setns(-1, 0)       EBADF (kernel)    EPERM             EPERM
"""
import json
import re
import unittest

from tests import REPO_ROOT

PROFILE = REPO_ROOT / "seccomp-workload-baseline.json"
TROUBLESHOOTING = REPO_ROOT.parent / "docs" / "TROUBLESHOOTING.md"
WORKLOADS = REPO_ROOT / "docs" / "workloads.md"

ENOSYS_TEXT = "Function not implemented"


def _errno_under_baseline(profile, name):
    """The errno the baseline returns for `name` in a container with no
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


class TestPinnedSeccompFindings(unittest.TestCase):
    def test_finding_1_gamedev_sways_profile_goes_stale(self):
        self.fail(
            "PINNED seccomp finding 1/3 (a derived profile goes stale): "
            "gamedev-sway (internal branch) writes "
            "${WORKLOAD_INSTANCE_DIR}/seccomp.json in its setup.sh enable() "
            "as a copy of seccomp-workload-baseline.json plus ptrace, "
            "process_vm_readv and process_vm_writev. Only `workloadctl "
            "enable` runs it, so a baseline fix an RPM update ships (8125b4f1, "
            "the setns gate, is one) never reaches an instance until it is "
            "enabled again; setup.sh's comment that it 'can't drift' holds "
            "only right after an enable. Fixed when the derived profile is "
            "rebuilt from the live baseline whenever the units are (or "
            "workloadctl renders it itself), and `doctor` reports one that "
            "differs from the baseline plus its additions. Then delete this "
            "test.")

    def test_finding_2_gamedev_sways_profile_is_an_untested_append(self):
        self.fail(
            "PINNED seccomp finding 2/3 (an untested append): the same profile "
            "is built by appending one SCMP_ACT_ALLOW entry, in inline Python "
            "inside a bash heredoc. That is right only while ptrace and "
            "process_vm_* appear in no other baseline entry: if the baseline "
            "ever lists one in an ERRNO entry, the result has the "
            "allow-plus-deny overlap test_seccomp_baseline forbids for the "
            "baseline itself, and no test looks at derived profiles. Fixed "
            "when per-workload seccomp additions are a workloadctl feature "
            "(say [security] seccomp_allow = [...]) that takes the names out "
            "of any deny entry, is held by the same checks as the baseline, "
            "and gamedev-sway uses it. Then delete this test.")

    def test_finding_3_the_docs_name_the_error_a_blocked_syscall_gives(self):
        profile = json.loads(PROFILE.read_text())
        doc = _section(TROUBLESHOOTING.read_text(),
                       "### 9. Syscall blocked by seccomp profile")
        listed = re.search(r"The blocked syscalls are: (.*)", doc).group(1)
        names = re.findall(r"`([a-z0-9_]+)`", listed)
        enosys = sorted(n for n in names
                        if _errno_under_baseline(profile, n) == 38)
        self.assertTrue(names, "TROUBLESHOOTING.md §9 lists no syscalls")
        guide = _section(WORKLOADS.read_text(), "### Seccomp Filtering")
        wrong = [path.name for path, text in ((TROUBLESHOOTING, doc),
                                              (WORKLOADS, guide))
                 if enosys and ENOSYS_TEXT not in text]
        self.assertEqual(
            wrong, [],
            f"PINNED seccomp finding 3/3 (the docs name the wrong error): "
            f"{' and '.join(wrong)} say a blocked syscall fails with "
            f"'Operation not permitted', but under the baseline {enosys} "
            f"fall to defaultErrnoRet 38 and fail with '{ENOSYS_TEXT}' "
            f"(ENOSYS): gdb in a stock workload prints 'ptrace: Function not "
            f"implemented'. Only the explicitly denied ones (bpf, "
            f"perf_event_open, setns, ...) give EPERM. Fixed when "
            f"TROUBLESHOOTING.md §9 and workloads.md's Seccomp Filtering "
            f"section say which error each gives.")


if __name__ == "__main__":
    unittest.main()
