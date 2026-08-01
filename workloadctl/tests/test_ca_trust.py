"""Tests for the CA trust-anchor check (Z-CA).

The failure being detected: an anchor installed under
`/etc/pki/ca-trust/source/anchors` that never made it into the extracted TLS
bundle, so it grants no trust while looking entirely correct. On a bootc host
that is the ostree /etc merge — `extracted/` is marked locally modified the
first time anyone runs `update-ca-trust` by hand, so the image's extraction is
discarded from then on while new anchor *files* still land.

The verdict function is pure over two facts, so every outcome is testable
without a trust store; the probe is tested against a fixture tree.
"""
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from cmd_diagnose import (
    CA_ANCHOR_DIR,
    CA_TLS_BUNDLE,
    _ca_trust_facts,
    _cert_fingerprints,
    ca_trust_anchor_check,
)


def _der(seed: bytes) -> bytes:
    """A byte string shaped enough like a DER certificate for the probe.

    Only the leading SEQUENCE tag matters — nothing here parses ASN.1, and the
    fingerprint is a hash of the whole body either way.
    """
    return b"\x30\x82" + seed.ljust(64, b"\x00")


def _pem(der: bytes) -> bytes:
    b64 = base64.encodebytes(der)
    return (b"-----BEGIN CERTIFICATE-----\n" + b64
            + b"-----END CERTIFICATE-----\n")


def _fp(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


class TestCertFingerprints(unittest.TestCase):
    def test_pem_and_der_of_one_cert_agree(self):
        """The whole point: an anchor shipped as DER must match a PEM bundle."""
        der = _der(b"homelab-root")
        self.assertEqual(_cert_fingerprints(der), {_fp(der)})
        self.assertEqual(_cert_fingerprints(_pem(der)), {_fp(der)})

    def test_multi_cert_bundle_yields_every_fingerprint(self):
        a, b = _der(b"a"), _der(b"b")
        bundle = b"# comment\n" + _pem(a) + b"# another\n" + _pem(b)
        self.assertEqual(_cert_fingerprints(bundle), {_fp(a), _fp(b)})

    def test_readme_is_not_a_certificate(self):
        """A README in the anchor dir must not read as an untrusted anchor."""
        self.assertEqual(_cert_fingerprints(b"This directory holds anchors.\n"),
                         set())

    def test_empty_file_yields_nothing(self):
        self.assertEqual(_cert_fingerprints(b""), set())

    def test_truncated_pem_does_not_raise(self):
        got = _cert_fingerprints(b"-----BEGIN CERTIFICATE-----\nnot base64 %%%")
        self.assertIsInstance(got, set)


class TestCaTrustAnchorCheck(unittest.TestCase):
    """The verdict is on trust, not on divergence — see the docstring."""

    def test_all_anchors_bundled_passes(self):
        passed, message, fix = ca_trust_anchor_check([], [])
        self.assertTrue(passed)
        self.assertIsNone(fix)

    def test_unbundled_anchor_fails_and_names_it(self):
        passed, message, fix = ca_trust_anchor_check(["homelab-root.crt"], [])
        self.assertFalse(passed)
        self.assertIn("homelab-root.crt", message)
        self.assertIn("local issuer", message)

    def test_image_only_anchors_get_the_converging_repair(self):
        """Restoring from /usr/etc brings config-diff clean, so the merge
        tracks the image again and later rotations need no repair at all."""
        _, _, fix = ca_trust_anchor_check(["homelab-root.crt"], [])
        self.assertIn("/usr/etc/pki/ca-trust/extracted", fix)
        self.assertIn("restorecon", fix)

    def test_locally_added_anchor_is_never_offered_the_restore(self):
        """Restoring would drop a hand-added anchor from the bundle, revoking
        trust the operator installed deliberately — a worse failure than the
        one being repaired. Regeneration is named instead, with its cost."""
        _, _, fix = ca_trust_anchor_check(["homelab-root.crt"],
                                          ["caddy-root.crt"])
        self.assertIn("update-ca-trust", fix)
        self.assertNotIn("/usr/etc", fix)
        self.assertIn("caddy-root.crt", fix)

    def test_non_ostree_host_gets_plain_regeneration(self):
        """No /usr/etc means no merge to converge back to, so regeneration
        carries none of the divergence cost it does on a bootc host."""
        _, _, fix = ca_trust_anchor_check(["homelab-root.crt"], None)
        self.assertEqual(fix, "sudo update-ca-trust")


class TestCaTrustFacts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.anchors = self.root / "etc" / CA_ANCHOR_DIR
        self.anchors.mkdir(parents=True)
        self.bundle = self.root / "etc" / CA_TLS_BUNDLE
        self.bundle.parent.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _ship(self, name: str, data: bytes):
        """Put an anchor in /usr/etc as well — i.e. the image installed it."""
        shipped = self.root / "usr/etc" / CA_ANCHOR_DIR
        shipped.mkdir(parents=True, exist_ok=True)
        (shipped / name).write_bytes(data)

    def test_anchor_present_in_bundle_is_not_reported(self):
        der = _der(b"homelab")
        (self.anchors / "homelab-root.crt").write_bytes(_pem(der))
        self.bundle.write_bytes(_pem(der))
        self.assertEqual(_ca_trust_facts(self.root), ([], None))

    def test_anchor_missing_from_bundle_is_reported(self):
        """The measured storage-host state: anchor installed, bundle predates it."""
        (self.anchors / "homelab-root.crt").write_bytes(_pem(_der(b"homelab")))
        self.bundle.write_bytes(_pem(_der(b"some-public-ca")))
        unbundled, _ = _ca_trust_facts(self.root)
        self.assertEqual(unbundled, ["homelab-root.crt"])

    def test_der_anchor_matches_a_pem_bundle(self):
        der = _der(b"homelab")
        (self.anchors / "homelab-root.crt").write_bytes(der)
        self.bundle.write_bytes(_pem(der))
        unbundled, _ = _ca_trust_facts(self.root)
        self.assertEqual(unbundled, [])

    def test_readme_in_the_anchor_dir_is_ignored(self):
        (self.anchors / "README").write_bytes(b"Drop anchors here.\n")
        self.bundle.write_bytes(_pem(_der(b"public")))
        unbundled, _ = _ca_trust_facts(self.root)
        self.assertEqual(unbundled, [])

    def test_local_anchor_is_distinguished_from_a_shipped_one(self):
        shipped_der, local_der = _der(b"homelab"), _der(b"caddy")
        (self.anchors / "homelab-root.crt").write_bytes(_pem(shipped_der))
        (self.anchors / "caddy-root.crt").write_bytes(_pem(local_der))
        self._ship("homelab-root.crt", _pem(shipped_der))
        self.bundle.write_bytes(b"")
        unbundled, local = _ca_trust_facts(self.root)
        self.assertEqual(sorted(unbundled),
                         ["caddy-root.crt", "homelab-root.crt"])
        self.assertEqual(local, ["caddy-root.crt"])

    def test_edited_shipped_anchor_counts_as_local(self):
        """Same filename, different bytes — the merge keeps the host's copy,
        so restoring extracted/ from the image would not match it either."""
        (self.anchors / "homelab-root.crt").write_bytes(_pem(_der(b"edited")))
        self._ship("homelab-root.crt", _pem(_der(b"original")))
        self.bundle.write_bytes(b"")
        _, local = _ca_trust_facts(self.root)
        self.assertEqual(local, ["homelab-root.crt"])

    def test_no_usr_etc_reports_local_anchors_as_unknown(self):
        """A non-ostree host has no merge, so 'locally added' has no meaning
        there — None, never an empty list, which would claim it checked."""
        (self.anchors / "homelab-root.crt").write_bytes(_pem(_der(b"h")))
        self.bundle.write_bytes(b"")
        _, local = _ca_trust_facts(self.root)
        self.assertIsNone(local)

    def test_unreadable_store_returns_none_so_the_check_is_omitted(self):
        """Omitted rather than passed: 'trust is intact' must not be asserted
        about a store that could not be opened."""
        self.assertIsNone(_ca_trust_facts(self.root))  # no bundle written yet


if __name__ == "__main__":
    unittest.main()
