#!/usr/bin/env python3
"""`[[network.allow]]` is pinned at ARM TIME, and something has to say so.

The property: an allow entry that names a HOST is resolved exactly once, when
the element is armed, and nftables then holds a literal address. Nothing
re-resolves it. When the name's answer moves, the workload dials an address no
element authorises, the packet falls past every accept to the default deny, and
it lands on a drop counter shared with every other filtered workload on the
host.

WHY THIS FILE EXISTS RATHER THAN A COMMENT SAYING SO. That disposition is not
in question and never was -- container_egress_rig.py's rotation row confirmed
it on hardware on 2026-09-06, twice, in both directions. What that row ALSO
measured is that no surface named it: `diagnose`, `doctor` and `validate`
between them mentioned neither the stale address nor the entry that pinned it,
and `egress` had nothing at all, because the inspector is not in this path and
never sees the connection. The whole operator-visible symptom was a dial that
used to work.

The failure this guards against is therefore not "the check is wrong" but "the
check is not called", which is why the wiring cases below go through
collect_diagnose_checks on real configs of BOTH substrates rather than calling
the function directly. A check nobody calls passes its own unit tests, reads as
coverage, and reports nothing.
"""

import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cmd_diagnose
import workload_lib
from workloadctl_core import WorkloadConfig

UID = 10001

CONTAINER_TOML = """\
[workload]
name = "capp"

[container]
image = "localhost/app:latest"

[network]
hosts = ["example.invalid"]

[[network.allow]]
host   = "svc.invalid"
port   = 8888
reason = "a service on a port no redirect touches"
"""

# An address entry cannot drift: there is no resolution to go stale. Its
# presence must not make the check report on it, and must not make the check
# vanish for the named entries beside it either.
CONTAINER_ADDRESS_ONLY_TOML = """\
[workload]
name = "cappaddr"

[container]
image = "localhost/app:latest"

[network]
hosts = ["example.invalid"]

[[network.allow]]
address = "203.0.113.9"
port    = 8888
reason  = "a literal, which has nothing to re-resolve"
"""

# Filtered, inspected, and with no `allow` at all: the check has nothing to
# say and must say nothing rather than emitting a vacuous pass.
CONTAINER_NO_ALLOW_TOML = """\
[workload]
name = "cnone"

[container]
image = "localhost/app:latest"

[network]
hosts = ["example.invalid"]
"""

VM_TOML = """\
[workload]
name = "vmw"

[vm]
memory = "2G"
vcpus = 2
image = "https://example.invalid/cloud.qcow2"

[vm.network]
egress = "filtered"
hosts = ["example.invalid"]

[[vm.network.allow]]
address = "svc.invalid:8888"
reason  = "the VM spelling of the same entry"
"""


def _set(*concats):
    """One `nft -j list set` document holding these concat elements."""
    return {"nftables": [{"set": {"elem": [{"concat": list(c)}
                                           for c in concats]}}]}


class AllowDriftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        for name, toml in (("capp", CONTAINER_TOML),
                           ("cappaddr", CONTAINER_ADDRESS_ONLY_TOML),
                           ("cnone", CONTAINER_NO_ALLOW_TOML),
                           ("vmw", VM_TOML)):
            (self.tmp / name).mkdir()
            (self.tmp / name / "workload.toml").write_text(toml)
        self.enterContext(mock.patch.object(
            WorkloadConfig, "uid", new_callable=mock.PropertyMock,
            return_value=UID))

    def _arm(self, *concats):
        """Answer every nft query with these elements, whichever set is asked.

        The check reads wl_allow4 and wl_allow6 and merges them, so answering
        both with the same document would double-count if it did not. It does
        not: the merge is into a set.
        """
        return mock.patch.object(cmd_diagnose, "_nft_json",
                                 return_value=_set(*concats))

    def _resolve(self, *addrs):
        return mock.patch.object(
            cmd_diagnose, "container_allow_resolve",
            return_value=[ipaddress.ip_address(a) for a in addrs])

    def _run(self, name="capp"):
        return cmd_diagnose.allow_drift_check(WorkloadConfig(name))

    # --- the happy case, which has to be a real assertion --------------------

    def test_agreement_passes_and_names_the_entry(self):
        with self._arm((UID, "203.0.113.5", 8888)), self._resolve("203.0.113.5"):
            check, ok, message = self._run()
        self.assertEqual(check, "allow_drift")
        self.assertTrue(ok, message)
        self.assertIn("svc.invalid:8888", message)

    def test_one_of_several_answers_still_agrees(self):
        """A dual-stack name answers with more than one address, and arming
        keeps ALL of them. Agreement is an intersection, not equality: a name
        that gained a second address has not drifted, and reporting it as drift
        would make every round-robin a permanent red."""
        with self._arm((UID, "203.0.113.5", 8888)), \
                self._resolve("203.0.113.5", "203.0.113.6"):
            _, ok, message = self._run()
        self.assertTrue(ok, message)

    # --- the case the hardware row found -------------------------------------

    def test_drift_fails_and_names_both_addresses(self):
        with self._arm((UID, "203.0.113.5", 8888)), self._resolve("203.0.113.9"):
            _, ok, message = self._run()
        self.assertFalse(ok)
        # Both, because either alone leaves the operator guessing which way
        # round it went -- and the remedy differs if the ARMED one is the one
        # they meant.
        self.assertIn("203.0.113.5", message)
        self.assertIn("203.0.113.9", message)
        self.assertIn("svc.invalid:8888", message)
        self.assertIn("restart workload-capp.service", message)

    def test_a_different_port_is_not_read_as_drift(self):
        """The element is a (uid, address, port) triple and the port is part of
        the identity. An element for the SAME address on another port must not
        stand in for this entry's -- that would report agreement for an entry
        nothing has armed."""
        with self._arm((UID, "203.0.113.5", 9999)), self._resolve("203.0.113.9"):
            _, ok, message = self._run()
        self.assertFalse(ok)

    # --- the two neighbouring failures, which need different remedies --------

    def test_nothing_armed_at_all_is_its_own_message(self):
        with mock.patch.object(cmd_diagnose, "_nft_json",
                               return_value=_set()), self._resolve("203.0.113.5"):
            _, ok, message = self._run()
        self.assertFalse(ok)
        self.assertIn("no element", message)

    def test_an_unresolvable_name_warns_about_the_NEXT_restart(self):
        """Arming is not tolerant of a name that does not resolve -- it fails
        the start. So the armed element still works and nothing is broken yet,
        and telling the operator to restart would be telling them to break it.
        """
        with self._arm((UID, "203.0.113.5", 8888)), \
                mock.patch.object(cmd_diagnose, "container_allow_resolve",
                                  side_effect=ValueError("does not resolve")):
            _, ok, message = self._run()
        self.assertFalse(ok)
        self.assertIn("next restart", message.lower())
        self.assertNotIn("Re-arm to re-resolve", message)

    # --- when the check must stay silent -------------------------------------

    def test_a_workload_with_no_allow_entries_gets_no_line(self):
        with self._arm((UID, "203.0.113.5", 8888)):
            self.assertIsNone(self._run("cnone"))

    def test_an_address_only_entry_gets_no_line(self):
        # Nothing to re-resolve, so there is nothing this check can say -- and
        # a line saying "no drift" about a literal is noise that trains an
        # operator to skim.
        with self._arm((UID, "203.0.113.9", 8888)):
            self.assertIsNone(self._run("cappaddr"))

    # --- the VM half, which is the same property with a different parser -----

    def test_the_vm_spelling_drifts_identically(self):
        with self._arm((UID, "203.0.113.5", 8888)), \
                mock.patch.object(cmd_diagnose, "vm_allow_resolve",
                                  return_value=[ipaddress.ip_address("203.0.113.9")]):
            _, ok, message = self._run("vmw")
        self.assertFalse(ok)
        self.assertIn("[vm.network].allow", message)
        self.assertIn("203.0.113.5", message)


class AllowDriftIsWiredTests(unittest.TestCase):
    """Through collect_diagnose_checks, on both substrates.

    The mutation that this and nothing else catches: deleting the two-line call
    site. `allow_drift_check` keeps every test above green while emitting no
    line for any workload on the host -- which is precisely the state the
    hardware row measured before this existed.
    """

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", self.tmp))
        for name, toml in (("capp", CONTAINER_TOML), ("vmw", VM_TOML)):
            (self.tmp / name).mkdir()
            (self.tmp / name / "workload.toml").write_text(toml)
        self.manager = mock.Mock()
        self.manager.user_exists.return_value = True
        self.manager.get_image_id.return_value = "sha256:" + "0" * 64
        self.manager.podman.return_value.image_id.return_value = (
            "sha256:" + "0" * 64)
        self.enterContext(mock.patch.object(
            WorkloadConfig, "uid", new_callable=mock.PropertyMock,
            return_value=UID))
        self.enterContext(mock.patch.object(
            cmd_diagnose.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="")))
        self.enterContext(mock.patch.object(
            cmd_diagnose, "service_active", return_value=(False, "inactive")))

    def _names(self, name):
        checks, _ = cmd_diagnose.collect_diagnose_checks(
            WorkloadConfig(name), self.manager)
        return {c["check"] for c in checks}

    def test_a_filtered_container_gets_an_allow_drift_line(self):
        self.assertIn("allow_drift", self._names("capp"))

    def test_a_filtered_vm_gets_one_too(self):
        self.assertIn("allow_drift", self._names("vmw"))


if __name__ == "__main__":
    unittest.main()
