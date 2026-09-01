#!/usr/bin/env python3
"""Memory vs. disk: the two things a running inspector can be wrong about.

`workloadctl drift` compares the policy document on disk against a re-render
from the TOML -- disk vs. intent. Nothing compared what the RUNNING listener
holds against what is on disk, and the two failures have no overlap: both sides
of the drift comparison match while a listener started before the last rewrite
enforces a document nobody can see.

Both halves here are that shape.

T4, the policy document. It is reachable through `diagnose`'s own printed
remedy: every re-arm branch ends in `systemctl restart <name>-inspect.socket`,
that socket's ExecStartPre rewrites the document, and the listener is `PartOf=`
the VM rather than the socket -- so it is not stopped and keeps enforcing what
it read at its own start.

T7, the CA. ADR 008 decision 4 says the CA does not rotate and the minter reads
it once, so divergence means the state tree moved under a running process --
generational rollback being the way that happens. Every leaf then chains to an
anchor the guest does not trust, and the failure is entirely inside the guest.

What is pinned: the digest has ONE producer (a second hashlib call at either
end is a permanent false alarm, not a missed one), the listener digests the
text it PARSED rather than a re-read, and every unknown is silence rather than
a manufactured failure.
"""

import io
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import cmd_diagnose
from vm import (
    VM_CA_EXPIRY_WARN_DAYS, VM_INSPECT_DIGEST_KEY, VM_INSPECT_DIGEST_SHORT,
    vm_inspect_digest_short, vm_inspect_policy_digest,
    vm_inspect_policy_text,
)

from tests.test_vm_inspect_listener import _mod

UID = 10001
NET = {"hosts": ["example.com"], "egress": "filtered"}


class TestTheDigestProducer(unittest.TestCase):

    def test_it_is_over_the_text_not_the_parsed_document(self):
        """Both sides hold text -- the listener the string it read, the reader
        the file. Digesting a re-parsed structure would make the value depend
        on this Python's dict ordering rather than on the file."""
        text = vm_inspect_policy_text(NET)
        self.assertEqual(vm_inspect_policy_digest(text),
                         vm_inspect_policy_digest(text))

    def test_a_document_that_differs_by_one_byte_digests_differently(self):
        text = vm_inspect_policy_text(NET)
        self.assertNotEqual(vm_inspect_policy_digest(text),
                            vm_inspect_policy_digest(text + " "))

    def test_the_short_form_is_the_prefix_of_the_full_one(self):
        digest = vm_inspect_policy_digest("x")
        self.assertEqual(vm_inspect_digest_short(digest),
                         digest[:VM_INSPECT_DIGEST_SHORT])

    def test_a_missing_digest_shortens_to_a_word_not_an_empty_string(self):
        """It reaches a sentence. An empty string there renders as a gap where
        a value was promised, which reads as a rendering bug rather than as an
        unknown."""
        self.assertEqual(vm_inspect_digest_short(None), "unknown")
        self.assertEqual(vm_inspect_digest_short(""), "unknown")


class TestTheListenerReportsWhatItLoaded(unittest.TestCase):

    def setUp(self):
        self.mod = _mod()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, text):
        path = Path(self.tmp.name) / "inspect.json"
        path.write_text(text)
        return str(path)

    def test_the_loaded_policy_carries_the_documents_digest(self):
        text = vm_inspect_policy_text(NET)
        policy = self.mod.load_policy(self._write(text))
        self.assertEqual(policy.digest, vm_inspect_policy_digest(text))

    def test_the_digest_is_of_the_bytes_that_were_parsed(self):
        """Not of a re-read. A rewrite landing between the read and the digest
        would otherwise give a listener that advertises the NEW document's
        digest while enforcing the old one -- green on the one case the
        comparison exists for.

        Driven by handing the second `open` of the path a DIFFERENT document,
        which is what an implementation that re-opened to digest would pick up.
        The call count is asserted too: one open is the property, and a second
        one that happened to return the same bytes would pass the digest
        comparison while leaving the race wide open.
        """
        first = vm_inspect_policy_text(NET)
        second = vm_inspect_policy_text({"hosts": ["other.example"],
                                         "egress": "filtered"})
        path = self._write(first)
        opened = []

        def versioned_open(*args, **kwargs):
            opened.append(args[0] if args else kwargs.get("file"))
            return io.StringIO(first if len(opened) == 1 else second)

        with mock.patch.object(self.mod, "open", versioned_open, create=True):
            policy = self.mod.load_policy(path)
        self.assertEqual(len(opened), 1)
        self.assertEqual(policy.digest, vm_inspect_policy_digest(first))
        self.assertNotEqual(policy.digest, vm_inspect_policy_digest(second))

    def test_the_digest_reaches_the_status_document(self):
        """The status file is the only channel from a running listener to the
        host. A digest held in memory and never written is unreadable by the
        check that exists to read it."""
        policy = self.mod.load_policy(self._write(vm_inspect_policy_text(NET)))
        listener = self.mod.Listener([], policy=policy)
        self.assertEqual(listener.status()[VM_INSPECT_DIGEST_KEY],
                         policy.digest)

    def test_the_key_is_written_even_when_empty(self):
        """A key that appeared only when non-empty would make "no digest" and
        "a listener from before this rung" indistinguishable, and the reader
        treats one of those as silence."""
        listener = self.mod.Listener([], policy=self.mod.Policy(
            tls="inspect", hosts=("example.com",)))
        self.assertIn(VM_INSPECT_DIGEST_KEY, listener.status())
        self.assertEqual(listener.status()[VM_INSPECT_DIGEST_KEY], "")


class TestTheStaleChecks(unittest.TestCase):

    def _line(self, *, status=None, disk_digest=None, disk_ca=None):
        cfg = SimpleNamespace(
            name="vm1", uid=UID, vm_bridge=None,
            vm_network={"egress": "filtered"},
            config={"vm": {"network": {"egress": "filtered"}}})
        elems = [{"concat": [UID, 80]}, {"concat": [UID, 443]}]
        kw = {}
        if disk_digest is not None:
            kw["disk_digest"] = disk_digest
        if disk_ca is not None:
            kw["disk_ca"] = disk_ca
        return cmd_diagnose.vm_inspect_check(
            cfg, elements4=elems, elements6=elems, socket_active=True,
            v6_route=True, self_dials=None, status=status, filter_sets={},
            **kw)

    # --- T4 ---

    def test_a_matching_digest_passes(self):
        _name, ok, detail = self._line(
            status={VM_INSPECT_DIGEST_KEY: "abc123"}, disk_digest="abc123")
        self.assertTrue(ok, detail)
        self.assertNotIn("DIFFERENT policy", detail)

    def test_a_differing_digest_fails(self):
        _name, ok, detail = self._line(
            status={VM_INSPECT_DIGEST_KEY: "aaaa1111"}, disk_digest="bbbb2222")
        self.assertFalse(ok)
        self.assertIn("DIFFERENT policy", detail)

    def test_both_digests_are_shown_short(self):
        running = vm_inspect_policy_digest("a")
        disk = vm_inspect_policy_digest("b")
        _name, _ok, detail = self._line(
            status={VM_INSPECT_DIGEST_KEY: running}, disk_digest=disk)
        self.assertIn(running[:VM_INSPECT_DIGEST_SHORT], detail)
        self.assertIn(disk[:VM_INSPECT_DIGEST_SHORT], detail)

    def test_the_remedy_is_the_vm_not_the_socket(self):
        """Restarting the socket is what CREATES this state -- its ExecStartPre
        rewrites the document and the listener is PartOf= the VM. A message
        repeating the socket remedy would loop the operator through the same
        non-fix."""
        _name, _ok, detail = self._line(
            status={VM_INSPECT_DIGEST_KEY: "aaaa"}, disk_digest="bbbb")
        self.assertIn("systemctl restart workload-vm1.service", detail)
        self.assertIn("does NOT fix this", detail)

    def test_no_status_says_nothing(self):
        """A socket-activated inspector a guest has never dialled has written
        no status file, which is the normal state of a healthy VM between boot
        and its first connection."""
        _name, ok, detail = self._line(status=None)
        self.assertTrue(ok, detail)
        self.assertNotIn("DIFFERENT policy", detail)

    def test_a_listener_with_no_digest_key_says_nothing(self):
        _name, ok, detail = self._line(status={"drop_reasons": {}})
        self.assertTrue(ok, detail)
        self.assertNotIn("DIFFERENT policy", detail)

    def test_an_unreadable_document_says_nothing(self):
        """T3's `drift` already reports a missing document; a second line here
        sends an operator to the same fix twice."""
        _name, ok, detail = self._line(
            status={VM_INSPECT_DIGEST_KEY: "aaaa"}, disk_digest="")
        self.assertTrue(ok, detail)
        self.assertNotIn("DIFFERENT policy", detail)

    # --- T7 ---

    def _ca_status(self, sha256="AA:BB", not_after=None):
        ca = {"sha256": sha256}
        if not_after is not None:
            ca["not_after"] = not_after
        return {"mint": {"ca": ca}}

    def test_a_matching_ca_passes(self):
        _name, ok, detail = self._line(
            status=self._ca_status("AA:BB"), disk_ca="AA:BB")
        self.assertTrue(ok, detail)
        self.assertNotIn("DIFFERENT CA", detail)

    def test_a_differing_ca_fails_and_names_both(self):
        _name, ok, detail = self._line(
            status=self._ca_status("AA:BB"), disk_ca="CC:DD")
        self.assertFalse(ok)
        self.assertIn("AA:BB", detail)
        self.assertIn("CC:DD", detail)

    def test_the_ca_message_says_where_the_failure_is_visible(self):
        """Nothing on the host can see it: the validation failure happens in
        the guest's TLS library. An operator not told that goes looking for a
        host-side symptom that does not exist."""
        _name, _ok, detail = self._line(
            status=self._ca_status("AA:BB"), disk_ca="CC:DD")
        self.assertIn("inside the guest", detail)

    def test_a_workload_with_no_minter_says_nothing(self):
        """`splice` has no CA in play at all, and an `inspect` workload whose
        guest has not dialled anything has no mint section yet."""
        _name, ok, detail = self._line(status={"drop_reasons": {}})
        self.assertTrue(ok, detail)
        self.assertNotIn("DIFFERENT CA", detail)

    def test_an_unreadable_disk_ca_says_nothing(self):
        _name, ok, detail = self._line(
            status=self._ca_status("AA:BB"), disk_ca="")
        self.assertTrue(ok, detail)
        self.assertNotIn("DIFFERENT CA", detail)


class TestTheExpiryWarning(unittest.TestCase):

    DAY = 86400

    def _fragments(self, remaining_days, now=1_800_000_000.0):
        status = {"mint": {"ca": {
            "sha256": "AA:BB",
            "not_after": now + remaining_days * self.DAY}}}
        with mock.patch.object(cmd_diagnose.time, "time", return_value=now):
            return cmd_diagnose._ca_fragments(status)

    def test_a_distant_expiry_says_nothing(self):
        """Ten years is the shipped validity. A line on every healthy workload
        for a date in 2036 is noise that trains the reader past the line that
        matters."""
        self.assertEqual(self._fragments(VM_CA_EXPIRY_WARN_DAYS + 10), [])

    def test_inside_the_window_it_warns(self):
        fragments = self._fragments(VM_CA_EXPIRY_WARN_DAYS - 10)
        self.assertEqual(len(fragments), 1)
        self.assertIn("expires on", fragments[0])

    def test_the_warning_names_the_real_remedy(self):
        """Replacing the CA means re-provisioning: cloud-init runs once per
        instance-id, so the anchor cannot be re-seeded into a running guest.
        An operator who reads this as "restart it" schedules the wrong work."""
        fragments = self._fragments(30)
        self.assertIn("RE-PROVISIONING", fragments[0])

    def test_an_expired_ca_says_so_in_the_past_tense(self):
        """Present-tense wording for a CA that already expired reads as time
        remaining, and the guest's HTTPS is already down."""
        fragments = self._fragments(-1)
        self.assertEqual(len(fragments), 1)
        self.assertIn("EXPIRED", fragments[0])

    def test_the_boundary_warns(self):
        """A window that excluded its own edge would leave a workload silent on
        the day the promise in VM_CA_VALIDITY_DAYS' comment comes due."""
        self.assertEqual(len(self._fragments(VM_CA_EXPIRY_WARN_DAYS)), 1)

    def test_a_status_with_no_expiry_says_nothing(self):
        self.assertEqual(cmd_diagnose._ca_fragments(
            {"mint": {"ca": {"sha256": "AA:BB"}}}), [])

    def test_a_malformed_ca_report_says_nothing(self):
        """Every unknown in this check is silence. A traceback here would take
        out the twenty other checks that were about to run."""
        for status in (None, {}, {"mint": None}, {"mint": {"ca": "no"}},
                       {"mint": {"ca": {"not_after": "soon"}}}):
            self.assertEqual(cmd_diagnose._ca_fragments(status), [], status)


class TestTheStatusReadIsDefensiveEverywhere(unittest.TestCase):
    """Nothing wraps vm_inspect_check, so a raise here is not one lost line.

    `_inspect_status` guarantees only that the TOP LEVEL of the status document
    is a dict. A truthy non-dict under `mint` -- a number, a string, a
    non-empty list -- only a bug in the writer produces, and a bug in the
    writer is precisely the state in which somebody runs `diagnose`. Before
    this the verdict path indexed straight through it while `_ca_fragments`,
    reading the same document a few lines later, guarded every level; the two
    halves of one figure disagreed about whether the file could be trusted.
    """

    HOSTILE = (None, {}, {"mint": None}, {"mint": 5}, {"mint": "x"},
               {"mint": [1]}, {"mint": {"ca": 7}}, {"mint": {"ca": []}},
               {"mint": {"ca": {"sha256": None}}})

    def test_no_shape_of_status_raises_out_of_the_ca_read(self):
        for status in self.HOSTILE:
            self.assertIsInstance(cmd_diagnose._ca_report(status), dict, status)
            self.assertEqual(cmd_diagnose._ca_fragments(status), [], status)

    def test_no_shape_of_status_raises_out_of_the_whole_check(self):
        cfg = SimpleNamespace(
            name="vm1", uid=UID, vm_bridge=None,
            vm_network={"egress": "filtered"},
            config={"vm": {"network": {"egress": "filtered"}}})
        elems = [{"concat": [UID, 80]}, {"concat": [UID, 443]}]
        for status in self.HOSTILE:
            cmd_diagnose.vm_inspect_check(
                cfg, elements4=elems, elements6=elems, socket_active=True,
                v6_route=True, self_dials=None, status=status,
                filter_sets={}, disk_digest="", disk_ca="AA:BB")


class TestTheDiskReadsAreDefensiveToo(unittest.TestCase):
    """The other half of TestTheStatusReadIsDefensiveEverywhere.

    That class hardens the STATUS side and then injects `disk_digest` and
    `disk_ca`, so the two functions that actually touch the filesystem were
    never exercised with a damaged file. Both read TEXT at the locale's
    encoding, so a byte the codec rejects raises UnicodeDecodeError -- a
    ValueError, not an OSError, and `except OSError` let it straight out. There
    is no wrapper around vm_inspect_check, so that ends the whole command and
    every later check with it.

    The reachable one is the CA. `_ca_fingerprint_on_disk` runs whenever the
    minter reported a fingerprint, and a CA file left truncated or garbage
    under a running listener is precisely the state T7 was written to report --
    so the check died of the fault it exists for.
    """

    GARBAGE = b"-----BEGIN CERTIFICATE-----\n\xff\xfe garbage\n-----END CERTIFICATE-----\n"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def test_a_ca_pem_that_is_not_text_reads_as_unknown(self):
        cert = self.dir / "ca.crt"
        cert.write_bytes(self.GARBAGE)
        with mock.patch.object(cmd_diagnose, "workload_state_dir",
                               return_value=self.dir), \
             mock.patch.object(cmd_diagnose, "vm_ca_cert_path",
                               return_value=cert):
            self.assertIsNone(cmd_diagnose._ca_fingerprint_on_disk("vm1"))

    def test_a_policy_document_that_is_not_text_reads_as_unknown(self):
        doc = self.dir / "inspect.json"
        doc.write_bytes(b'{"hosts": ["\xff\xfe"]}')
        with mock.patch.object(cmd_diagnose, "vm_inspect_policy_path",
                               return_value=str(doc)):
            self.assertIsNone(cmd_diagnose._policy_digest_on_disk("vm1"))

    def test_a_damaged_ca_does_not_end_the_check(self):
        """The whole point: silence, and the twenty checks after this one still
        run. A raise here is not one lost line."""
        cert = self.dir / "ca.crt"
        cert.write_bytes(self.GARBAGE)
        cfg = SimpleNamespace(
            name="vm1", uid=UID, vm_bridge=None,
            vm_network=dict(NET),
            config={"vm": {"network": dict(NET)}})
        elems = [{"concat": [UID, 80]}, {"concat": [UID, 443]}]
        with mock.patch.object(cmd_diagnose, "workload_state_dir",
                               return_value=self.dir), \
             mock.patch.object(cmd_diagnose, "vm_ca_cert_path",
                               return_value=cert):
            _name, ok, detail = cmd_diagnose.vm_inspect_check(
                cfg, elements4=elems, elements6=elems, socket_active=True,
                v6_route=True, self_dials=None, filter_sets={},
                disk_digest="", status={"mint": {"ca": {"sha256": "AA:BB"}}})
        self.assertTrue(ok, detail)
        self.assertNotIn("DIFFERENT CA", detail)


class TestTheFingerprintIsShownShort(unittest.TestCase):
    """Two 95-character fingerprints in one sentence is a line nobody reads.

    VM_INSPECT_DIGEST_SHORT already fixes how much of a digest is enough to
    tell two apart by eye; this is the certificate spelling of the same
    number, cut on a byte boundary rather than through the middle of a pair.
    """

    FULL = ":".join(f"{n:02X}" for n in range(32))

    def test_it_keeps_the_leading_bytes_and_marks_the_cut(self):
        short = cmd_diagnose._short_fingerprint(self.FULL)
        self.assertTrue(self.FULL.startswith(short.rstrip(":\u2026")))
        self.assertLess(len(short), len(self.FULL))
        self.assertEqual(len(short.split(":")[:-1]),
                         VM_INSPECT_DIGEST_SHORT // 2)

    def test_an_already_short_value_is_left_alone(self):
        """The tests and the rig use two-byte stand-ins; truncating one to a
        prefix of itself would make a mismatch render as a match."""
        self.assertEqual(cmd_diagnose._short_fingerprint("AA:BB"), "AA:BB")

    def test_a_missing_fingerprint_is_a_word_not_an_exception(self):
        self.assertEqual(cmd_diagnose._short_fingerprint(None), "unknown")

    def test_two_different_cas_stay_different_when_shortened(self):
        """A shortening that collided would report a real mismatch as two
        identical strings, which reads as the check having lost its mind."""
        other = ":".join(f"{n:02X}" for n in range(100, 132))
        self.assertNotEqual(cmd_diagnose._short_fingerprint(self.FULL),
                            cmd_diagnose._short_fingerprint(other))


if __name__ == "__main__":
    unittest.main()
