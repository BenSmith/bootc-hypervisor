"""The per-workload egress CA: how it is minted, and that it is minted once.

The assertions here parse the CERTIFICATE rather than matching the argv that
produced it. That is the whole point of the file. Three extensions are load-
bearing and invisible to most clients -- a CA missing them works under curl, Go
and Node and fails only under Python's ssl, presenting as a trust failure
indistinguishable from "the guest never installed our CA" -- so a test that
asserted `-addext subjectKeyIdentifier=hash` appeared in a list would pass
against an openssl that ignored it.
"""

import os
import shutil
import subprocess
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from vm import (VM_CA_BACKDATE_SECONDS, VM_CA_CERT_NAME, VM_CA_KEY_NAME,
                VM_CA_VALIDITY_DAYS, vm_ca_cert_path, vm_ca_dir,
                vm_ca_key_path, vm_ca_openssl_argv, vm_ca_subject)

from tests import load_script

HAVE_OPENSSL = shutil.which("openssl") is not None


def _mint(tmp, name="myvm", now=None):
    key = Path(tmp) / VM_CA_KEY_NAME
    cert = Path(tmp) / VM_CA_CERT_NAME
    argv = vm_ca_openssl_argv(name, key, cert, now=now or time.time())
    p = subprocess.run(argv, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return key, cert


def _text(cert, *args):
    return subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", *args],
                          capture_output=True, text=True).stdout


class TestCaPaths(unittest.TestCase):
    def test_the_ca_lives_under_the_state_dir(self):
        # state/, not data/: `backup` never captures state/, which is what
        # keeps the private key out of every archive with no exclusion rule.
        d = vm_ca_dir("/var/lib/workloads/myvm/state")
        self.assertEqual(d, Path("/var/lib/workloads/myvm/state/ca"))
        self.assertEqual(vm_ca_key_path("/var/lib/workloads/myvm/state"),
                         d / VM_CA_KEY_NAME)
        self.assertEqual(vm_ca_cert_path("/var/lib/workloads/myvm/state"),
                         d / VM_CA_CERT_NAME)

    def test_the_subject_names_the_workload(self):
        # An operator reading a certificate error inside a guest has to be able
        # to tell which of several workloads' CAs it came from.
        self.assertIn("myvm", vm_ca_subject("myvm"))


class TestBackdate(unittest.TestCase):
    def test_not_before_is_backdated_an_hour(self):
        argv = vm_ca_openssl_argv("myvm", "/k", "/c", now=1787000000.0)
        stamp = argv[argv.index("-not_before") + 1]
        self.assertEqual(
            stamp,
            time.strftime("%Y%m%d%H%M%SZ",
                          time.gmtime(1787000000.0 - VM_CA_BACKDATE_SECONDS)))

    def test_not_before_is_explicit_rather_than_defaulted(self):
        # Letting notBefore default to "now" would make the hour of skew
        # tolerance a property of WHEN THE PROCESS RAN rather than of the
        # certificate, which is not a thing anything downstream can read.
        self.assertIn("-not_before", vm_ca_openssl_argv("m", "/k", "/c", now=0.0))


@unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
class TestTheMintedCertificate(unittest.TestCase):
    """Everything here parses what OpenSSL actually emitted."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.now = time.time()
        cls.key, cls.cert = _mint(cls.tmp, now=cls.now)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_it_is_a_ca(self):
        self.assertIn("CA:TRUE", _text(self.cert, "-ext", "basicConstraints"))

    def test_basic_constraints_is_critical(self):
        self.assertIn("critical", _text(self.cert, "-ext", "basicConstraints"))

    def test_it_carries_a_subject_key_identifier(self):
        # Without this, Python 3.14 / OpenSSL 3.5 rejects the chain with
        # `Missing Authority Key Identifier` -- naming the LEAF's extension for
        # a defect in the CA, which is why it is worth its own test.
        #
        # Measured 2026-08-26: OpenSSL 3.5 adds SKI to a self-signed CA on its
        # own, so `-addext subjectKeyIdentifier=hash` is belt-and-braces and
        # REMOVING IT DOES NOT FAIL THIS TEST. Said plainly because a reader
        # who breaks it on purpose finds that out and concludes the test is
        # worthless. It is not: it pins a property we depend on against an
        # OpenSSL whose default differs, which is the case this must survive.
        out = _text(self.cert, "-ext", "subjectKeyIdentifier")
        self.assertIn("Subject Key Identifier", out)

    def test_it_carries_key_usage_for_signing_certificates(self):
        # The second failure Python raises once SKI is present:
        # `CA cert does not include key usage extension`. Unlike SKI above,
        # OpenSSL does NOT add this by itself -- it is what the -addext
        # actually buys, and dropping that line fails here.
        out = _text(self.cert, "-ext", "keyUsage")
        self.assertIn("Certificate Sign", out)
        self.assertIn("CRL Sign", out)
        self.assertIn("critical", out)

    def test_the_key_is_ecdsa_p256(self):
        # Matching the leaves. RSA-2048 minting is slow enough to be noticeable
        # on a cold cache, and a CA of a different family than its leaves buys
        # nothing.
        out = subprocess.run(["openssl", "pkey", "-in", str(self.key),
                              "-noout", "-text"],
                             capture_output=True, text=True).stdout
        self.assertIn("prime256v1", out)

    def test_the_private_key_is_not_encrypted(self):
        # -noenc, because nothing is present to type a passphrase at boot.
        self.assertNotIn("ENCRYPTED", self.key.read_text())

    def test_it_lasts_about_ten_years(self):
        # The exact date depends on when the test ran; what is asserted is that
        # the validity is the decade the never-rotate argument requires and not,
        # say, the 365 days a copied recipe would give it.
        out = _text(self.cert, "-enddate").strip()
        end = time.mktime(time.strptime(out.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z"))
        days = (end - self.now) / 86400
        self.assertGreater(days, VM_CA_VALIDITY_DAYS - 2)

    def test_python_ssl_will_at_least_load_it_as_an_anchor(self):
        # Deliberately NOT called "a Python client accepts it". Loading an
        # anchor parses the certificate; it does not verify a chain, so none of
        # the extension failures above can surface here -- those are raised
        # during verification, against a LEAF, and there are no leaves until
        # T4. This is the cheap half; the real proof is a handshake, owed by
        # the rung that mints something to hand a client.
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=str(self.cert))
        self.assertEqual(len(ctx.get_ca_certs()), 1)


class TestGeneratorIsIdempotent(unittest.TestCase):
    """Re-minting invalidates a provisioned guest's anchor, and cloud-init runs
    once per instance-id -- so the replacement never arrives and every HTTPS
    request fails validation on a VM `diagnose` calls healthy. The guard is the
    whole feature."""

    def setUp(self):
        self.mod = load_script("libexec/workload-ensure-user")
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.state = Path(self.tmp) / "state"
        self.state.mkdir()
        self.pw = types.SimpleNamespace(
            pw_dir=self.tmp, pw_uid=os.getuid(), pw_gid=os.getgid(),
            pw_name="_wl-myvm")
        self._patch()

    def _patch(self):
        mod = self.mod
        self._orig_state = mod.workload_state_dir
        self._orig_chown = mod.os.chown
        mod.workload_state_dir = lambda name: self.state
        mod.os.chown = lambda *a, **k: None
        self.addCleanup(setattr, mod, "workload_state_dir", self._orig_state)
        self.addCleanup(setattr, mod.os, "chown", self._orig_chown)

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_it_mints_once_and_leaves_it_alone(self):
        self.mod.generate_vm_egress_ca(self.pw, "myvm")
        cert = vm_ca_cert_path(self.state)
        key = vm_ca_key_path(self.state)
        self.assertTrue(cert.exists() and key.exists())
        first = (cert.read_bytes(), key.read_bytes())

        self.mod.generate_vm_egress_ca(self.pw, "myvm")
        self.assertEqual((cert.read_bytes(), key.read_bytes()), first,
                         "the CA was re-minted; a provisioned guest's anchor "
                         "is now stale and cloud-init will never replace it")

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_the_private_half_is_not_world_readable(self):
        self.mod.generate_vm_egress_ca(self.pw, "myvm")
        self.assertEqual(vm_ca_key_path(self.state).stat().st_mode & 0o777, 0o600)
        # The certificate is a public anchor -- the seed builder and `diagnose`
        # both read it -- so it is deliberately NOT 0600.
        self.assertEqual(vm_ca_cert_path(self.state).stat().st_mode & 0o777, 0o644)
        self.assertEqual(vm_ca_dir(self.state).stat().st_mode & 0o777, 0o700)

    def test_openssl_failing_raises_rather_than_returning_quietly(self):
        # A silent failure here yields a filtered VM with no CA, which does not
        # surface until the guest's first HTTPS request.
        # mock.patch.object, NOT `self.mod.subprocess.run = ...`: `mod.subprocess`
        # is the shared stdlib module, so a bare assignment replaces run() for
        # the whole process and leaks into every later test. It did, and it
        # presented as the REAL mint failing with this fake's error string.
        fake = types.SimpleNamespace(
            returncode=1, stdout="", stderr="openssl: unrecognised option")
        with mock.patch.object(self.mod.subprocess, "run", return_value=fake):
            with self.assertRaises(RuntimeError) as ctx:
                self.mod.generate_vm_egress_ca(self.pw, "myvm")
        self.assertIn("unrecognised option", str(ctx.exception))

    def test_a_failure_with_no_output_still_says_something(self):
        # Same both-streams reasoning as _ssh_keygen: reporting stderr alone
        # yields an empty diagnostic on precisely the runs that need one.
        fake = types.SimpleNamespace(returncode=3, stdout="", stderr="")
        with mock.patch.object(self.mod.subprocess, "run", return_value=fake):
            with self.assertRaises(RuntimeError) as ctx:
                self.mod.generate_vm_egress_ca(self.pw, "myvm")
        self.assertIn("exit 3", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()


class TestTheCaReachesTheSeed(unittest.TestCase):
    """The built-in cloud-config carries the CA by BOTH routes.

    Either alone leaves a measured population of clients failing: the system
    trust store covers almost everything, and the runtimes that carry their own
    root list (upstream Node, certifi) consult only the file the five
    environment variables name. So `ca_certs.trusted` and the write_files entry
    are not redundant, and a test asserting one would pass against a seed that
    breaks half the guest.
    """

    PEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"

    def setUp(self):
        self.mod = load_script("libexec/workload-ensure-user")

    def _render(self, **kw):
        return self.mod._render_default_user_data(
            name="myvm", guest_user="fedora", pubkey="ssh-ed25519 AAAA u@h",
            mounts=[], has_data_disk=False, **kw)

    def test_the_bundle_is_written_where_the_env_vars_point(self):
        from vm import VM_CA_BUNDLE_PATH
        out = self._render(ca_cert=self.PEM)
        self.assertIn(f"  - path: {VM_CA_BUNDLE_PATH}", out)
        self.assertIn("-----BEGIN CERTIFICATE-----", out)

    def test_it_also_goes_into_the_system_trust_store(self):
        out = self._render(ca_cert=self.PEM)
        self.assertIn("ca_certs:", out)
        self.assertIn("  trusted:", out)

    def test_write_files_is_emitted_once_when_both_halves_want_it(self):
        # The env block and the CA bundle are two entries under ONE write_files
        # key. Two `write_files:` keys is not a cloud-config -- the second
        # silently replaces the first, and the loser is whichever half the
        # renderer emitted earlier.
        out = self._render(ca_cert=self.PEM, guest_env={"SSL_CERT_FILE": "/x"})
        self.assertEqual(out.count("write_files:"), 1)

    def test_a_workload_with_no_ca_gets_neither_block(self):
        # egress = "open": no inspector, so nothing to trust.
        out = self._render(ca_cert="")
        self.assertNotIn("ca_certs:", out)

    def test_the_env_block_still_stands_on_its_own(self):
        # Guarding the write_files header on `guest_env or ca_cert` is easy to
        # get wrong in the direction that drops the env block for a workload
        # with no CA.
        out = self._render(guest_env={"WORKLOAD_BROKER_URL": "http://x"})
        self.assertIn("write_files:", out)
        self.assertIn("/etc/environment", out)
