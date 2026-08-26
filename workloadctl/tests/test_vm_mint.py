"""Leaf minting, the two caches, and the token bucket (rung 3 T4).

The certificates here are REAL -- minted by the same openssl argv the listener
will run -- and the assertions read them back rather than reading the argv. An
argv assertion proves we asked for something; only the certificate proves we got
it, and the two have already diverged once on this rung: a leaf with an empty
subject needs its subjectAltName marked CRITICAL, which no reading of the argv
suggests and which a real handshake rejects the certificate for.
"""

import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import vm
import vm_mint
from vm import LeafRefused, vm_ca_openssl_argv, vm_leaf_openssl_argv, vm_leaf_san


def _mint_ca(state_dir: Path, name="wl-test") -> None:
    (state_dir / "ca").mkdir(mode=0o700, parents=True, exist_ok=True)
    subprocess.run(
        vm_ca_openssl_argv(name, vm.vm_ca_key_path(state_dir),
                           vm.vm_ca_cert_path(state_dir), now=time.time()),
        capture_output=True, text=True, check=True)


def _certificate(path: Path, *fields: str) -> str:
    return subprocess.run(
        ["openssl", "x509", "-in", str(path), "-noout", *fields],
        capture_output=True, text=True, check=True).stdout


class TestTheNameCheckIsAnAllowlist(unittest.TestCase):
    """vm_leaf_san is the only thing standing between guest-chosen bytes and an
    openssl `-addext` argument, so it is tested as a boundary, not a formatter."""

    def test_an_ordinary_name_becomes_a_dns_san(self):
        self.assertEqual(vm_leaf_san("example.com"), "DNS:example.com")

    def test_the_name_is_normalised_first(self):
        self.assertEqual(vm_leaf_san("EXAMPLE.com."), "DNS:example.com")

    def test_an_address_becomes_an_ip_san_not_a_dns_one(self):
        # A DNS: entry holding an address does not match when a client connects
        # to that address, so this is the difference between a certificate that
        # verifies and one that fails for no legible reason.
        self.assertEqual(vm_leaf_san("192.0.2.7"), "IP:192.0.2.7")
        self.assertEqual(vm_leaf_san("2001:db8::1"), "IP:2001:db8::1")

    def test_a_comma_is_refused(self):
        # The one that matters: subjectAltName takes a comma-separated list, so
        # a name carrying a comma would append extensions of the guest's
        # choosing to a certificate the host signs.
        with self.assertRaises(LeafRefused):
            vm_leaf_san("example.com,DNS:victim.example")

    def test_the_extension_separator_is_refused(self):
        with self.assertRaises(LeafRefused):
            vm_leaf_san("a=b.example.com")

    def test_a_newline_is_refused(self):
        with self.assertRaises(LeafRefused):
            vm_leaf_san("example.com\nDNS:victim.example")

    def test_an_empty_name_is_refused(self):
        with self.assertRaises(LeafRefused):
            vm_leaf_san("")

    def test_an_empty_label_is_refused(self):
        with self.assertRaises(LeafRefused):
            vm_leaf_san("a..b.example")

    def test_an_over_long_name_is_refused(self):
        with self.assertRaises(LeafRefused):
            vm_leaf_san(".".join(["a" * 40] * 8))

    def test_an_over_long_label_is_refused(self):
        with self.assertRaises(LeafRefused):
            vm_leaf_san("a" * 64 + ".example.com")

    def test_underscores_are_permitted(self):
        # Deliberate: RFC 1035 forbids them in a hostname label, real service
        # names use them anyway, and every client this design faces resolves
        # and validates such names. Refusing them would break traffic the
        # allowlist authorised.
        self.assertEqual(vm_leaf_san("_svc.example.com"), "DNS:_svc.example.com")

    def test_the_argv_builder_refuses_before_it_builds(self):
        # Nothing downstream re-checks, so the refusal has to happen here and
        # not merely inside vm_leaf_san where a caller might route around it.
        with self.assertRaises(LeafRefused):
            vm_leaf_openssl_argv("a,b.example", "k", "c", "lk", "lc",
                                 now=time.time())


class TestTheMintedLeaf(unittest.TestCase):
    """Parses the certificate. See the module docstring on why not the argv."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.state = Path(cls._tmp.name)
        _mint_ca(cls.state)
        cls.leaf_key = cls.state / "leaf.key"
        cls.leaf_crt = cls.state / "leaf.crt"
        subprocess.run(
            vm_leaf_openssl_argv(
                "example.com", vm.vm_ca_key_path(cls.state),
                vm.vm_ca_cert_path(cls.state), cls.leaf_key, cls.leaf_crt,
                now=time.time()),
            capture_output=True, text=True, check=True)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_it_is_issued_by_this_workloads_ca(self):
        self.assertIn("workloadctl egress CA",
                      _certificate(self.leaf_crt, "-issuer"))

    def test_the_subject_is_empty(self):
        self.assertEqual(_certificate(self.leaf_crt, "-subject").strip(),
                         "subject=")

    def test_the_san_is_critical(self):
        # MEASURED, NOT ASSUMED. Without the flag, Python's ssl rejects the
        # chain with "Subject empty and Subject Alt Name extension not
        # critical" -- a verify failure that names neither the SAN nor the CA,
        # so it reads like a broken anchor and sends a reader to the wrong half.
        text = _certificate(self.leaf_crt, "-ext", "subjectAltName")
        self.assertIn("critical", text)
        self.assertIn("DNS:example.com", text)

    def test_it_is_not_a_ca(self):
        self.assertIn("CA:FALSE",
                      _certificate(self.leaf_crt, "-ext", "basicConstraints"))

    def test_it_is_a_server_certificate_only(self):
        text = _certificate(self.leaf_crt, "-ext", "extendedKeyUsage")
        self.assertIn("TLS Web Server Authentication", text)
        self.assertNotIn("TLS Web Client Authentication", text)

    def test_it_carries_an_authority_key_identifier(self):
        self.assertIn("Authority Key Identifier",
                      _certificate(self.leaf_crt, "-ext",
                                   "authorityKeyIdentifier"))

    def test_not_before_is_backdated_an_hour(self):
        text = _certificate(self.leaf_crt, "-startdate")
        when = ssl.cert_time_to_seconds(text.split("=", 1)[1].strip())
        self.assertAlmostEqual(time.time() - when, vm.VM_CA_BACKDATE_SECONDS,
                               delta=120)

    def test_it_expires_in_thirty_days(self):
        text = _certificate(self.leaf_crt, "-enddate")
        when = ssl.cert_time_to_seconds(text.split("=", 1)[1].strip())
        self.assertAlmostEqual((when - time.time()) / 86400,
                               vm.VM_LEAF_VALIDITY_DAYS, delta=1)

    def test_a_real_client_completes_a_real_handshake_against_it(self):
        """The proof the rung actually needs, and the only one that counts.

        T1 could show a Python client PARSING the CA as an anchor, which is not
        verification -- load_verify_locations reads a file and says nothing
        about a chain. This is the deferred half: a genuine TLS session, the CA
        as the only anchor, the hostname checked. It is what caught the
        critical-SAN requirement.
        """
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(self.leaf_crt, self.leaf_key)
        client = ssl.create_default_context(
            cafile=str(vm.vm_ca_cert_path(self.state)))

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        failure = []

        def serve():
            conn, _ = listener.accept()
            try:
                server.wrap_socket(conn, server_side=True).close()
            except Exception as exc:  # surfaced by the client's own failure
                failure.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with socket.create_connection(("127.0.0.1", port)) as sock:
                with client.wrap_socket(sock, server_hostname="example.com") as tls:
                    self.assertEqual(tls.getpeercert()["subjectAltName"],
                                     (("DNS", "example.com"),))
        finally:
            thread.join(timeout=5)
            listener.close()
        self.assertEqual(failure, [])

    def test_the_same_client_rejects_it_for_another_name(self):
        """One name asked for, one name signed -- asserted from the client side.

        The wildcard temptation this closes: minting for the allowlist PATTERN
        that matched would hand the guest a certificate valid for every name
        under it, including ones a later narrowing of the list removes.
        """
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(self.leaf_crt, self.leaf_key)
        client = ssl.create_default_context(
            cafile=str(vm.vm_ca_cert_path(self.state)))

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            try:
                server.wrap_socket(conn, server_side=True).close()
            except Exception:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with socket.create_connection(("127.0.0.1", port)) as sock:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    client.wrap_socket(sock, server_hostname="other.example")
        finally:
            thread.join(timeout=5)
            listener.close()


class TestTheTokenBucket(unittest.TestCase):
    """Injected clock throughout: a test that asserts a refill rate by waiting
    for it is a test that is slow when it passes and flaky when it fails."""

    def setUp(self):
        self.now = 1000.0
        self.slept = []

    def _clock(self):
        return self.now

    def _sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds

    def _bucket(self, capacity=4, refill=1.0):
        return vm_mint.TokenBucket(capacity, refill,
                                   clock=self._clock, sleep=self._sleep)

    def test_it_starts_full(self):
        self.assertEqual(self._bucket().tokens, 4.0)

    def test_take_empties_it_and_then_refuses(self):
        bucket = self._bucket()
        for _ in range(4):
            self.assertTrue(bucket.take())
        self.assertFalse(bucket.take())

    def test_it_refills_at_the_stated_rate(self):
        bucket = self._bucket()
        for _ in range(4):
            bucket.take()
        self.now += 2.0
        self.assertTrue(bucket.take())
        self.assertTrue(bucket.take())
        self.assertFalse(bucket.take())

    def test_it_never_refills_past_capacity(self):
        bucket = self._bucket()
        self.now += 10_000.0
        self.assertEqual(bucket.tokens, 4.0)

    def test_wait_returns_once_a_token_arrives(self):
        bucket = self._bucket()
        for _ in range(4):
            bucket.take()
        self.assertTrue(bucket.wait(5.0))
        self.assertTrue(self.slept)

    def test_wait_gives_up_at_the_deadline(self):
        bucket = self._bucket(capacity=1, refill=0.001)
        bucket.take()
        self.assertFalse(bucket.wait(1.0))

    def test_a_backwards_host_clock_does_not_freeze_it(self):
        # The rung's own clock resync can step the HOST clock too. monotonic is
        # what makes that a non-event; this asserts the bucket does not treat a
        # negative elapsed time as a debt.
        bucket = self._bucket()
        bucket.take()
        self.now -= 3600.0
        bucket.take()
        self.assertGreaterEqual(bucket.tokens, 2.0)

    def test_it_is_safe_under_concurrent_takes(self):
        # Real threads, real lock: the listener is one thread per connection
        # and the bucket is shared, so a check-then-decrement race would hand
        # out more tokens than the capacity under exactly that load.
        bucket = vm_mint.TokenBucket(50, 0.0)
        taken = []
        lock = threading.Lock()

        def drain():
            got = sum(1 for _ in range(20) if bucket.take())
            with lock:
                taken.append(got)

        threads = [threading.Thread(target=drain) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(taken), 50)


class _MinterCase(unittest.TestCase):
    """A Minter over a real CA in a temp state directory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name)
        _mint_ca(self.state)
        self.clock_checks = []
        self.addCleanup(self._tmp.cleanup)

    def _clock_check(self):
        self.clock_checks.append(True)
        return "ok"

    def minter(self, **kwargs):
        kwargs.setdefault("clock_check", self._clock_check)
        return vm_mint.Minter("wl-test", self.state, **kwargs)


class TestMinting(_MinterCase):

    def test_it_mints_a_usable_leaf(self):
        leaf = self.minter().leaf("example.com", denied=False)
        self.assertTrue(leaf.path.exists())
        # One PEM holding cert AND key, which is what load_cert_chain takes
        # with no keyfile argument.
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(leaf.path)

    def test_the_pem_is_not_world_readable(self):
        leaf = self.minter().leaf("example.com", denied=False)
        self.assertEqual(os.stat(leaf.path).st_mode & 0o077, 0)

    def test_a_second_request_is_a_cache_hit_and_does_not_re_mint(self):
        minter = self.minter()
        first = minter.leaf("example.com", denied=False)
        second = minter.leaf("example.com", denied=False)
        self.assertEqual(first.path, second.path)
        self.assertEqual(minter.stats["mints"], 1)
        self.assertEqual(minter.stats["hits"], 1)

    def test_a_restart_adopts_the_working_set_rather_than_re_minting(self):
        # The reason the working set is on disk at all: the listener is
        # socket-activated and PartOf= the VM, so it restarts far more often
        # than the guest does.
        first = self.minter()
        first.leaf("example.com", denied=False)
        second = self.minter()
        second.leaf("example.com", denied=False)
        self.assertEqual(second.stats["mints"], 0)
        self.assertEqual(second.stats["hits"], 1)

    def test_the_clock_is_checked_before_minting_and_not_on_a_hit(self):
        # The T2 seam. A remedy that covers every pause path by being
        # demand-driven is worth nothing if the mint path does not consult it --
        # and consulting it on a cache HIT would put a guest-agent round trip
        # on every connection.
        minter = self.minter()
        minter.leaf("example.com", denied=False)
        self.assertEqual(len(self.clock_checks), 1)
        minter.leaf("example.com", denied=False)
        self.assertEqual(len(self.clock_checks), 1)

    def test_a_resync_is_counted(self):
        minter = self.minter(clock_check=lambda: "resynced")
        minter.leaf("example.com", denied=False)
        self.assertEqual(minter.stats["clock_resyncs"], 1)

    def test_a_refused_name_never_reaches_openssl(self):
        ran = []
        minter = self.minter(runner=lambda *a, **k: ran.append(a))
        with self.assertRaises(LeafRefused):
            minter.leaf("evil.com,DNS:victim.example", denied=False)
        self.assertEqual(ran, [])

    def test_an_openssl_failure_carries_openssls_words(self):
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="boom")
        minter = self.minter(runner=lambda *a, **k: failed)
        with self.assertRaises(vm_mint.MintFailed) as caught:
            minter.leaf("example.com", denied=False)
        self.assertIn("boom", str(caught.exception))
        self.assertEqual(minter.stats["failed"], 1)

    def test_a_failed_mint_leaves_nothing_cached(self):
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="boom")
        minter = self.minter(runner=lambda *a, **k: failed)
        with self.assertRaises(vm_mint.MintFailed):
            minter.leaf("example.com", denied=False)
        self.assertEqual(len(minter.working_set), 0)


class TestTheTwoCachesCannotEvictEachOther(_MinterCase):
    """The property the split exists for, asserted in both directions.

    With one shared cache, "flood it with invented names" is a denial of
    service against the workload's real destinations, spelled in ordinary
    traffic and invisible in every counter.
    """

    def test_a_flood_of_denials_evicts_nothing_from_the_working_set(self):
        # The bound is shrunk rather than the flood being run at its real size:
        # these are real openssl mints, and 148 of them would put six seconds
        # on the unit suite to demonstrate a property that eight demonstrate.
        with mock.patch.object(vm_mint, "DENIAL_CACHE_MAX", 8):
            minter = self.minter(bucket=vm_mint.TokenBucket(10_000, 0.0))
            minter.leaf("real.example", denied=False)
            for i in range(28):
                minter.leaf(f"invented{i}.example", denied=True)
            self.assertIn("real.example", minter.working_set)
            self.assertEqual(len(minter.denials), 8)
        # And the file is still there, not merely the memory entry -- eviction
        # unlinks, so a shared directory would have been the real damage.
        self.assertTrue(minter.working_set.path_for("real.example").exists())

    def test_a_denial_entry_is_never_served_to_an_allowed_lookup(self):
        # "Never promoted", structurally: the two sets are separate objects
        # over separate directories, so there is no path that moves an entry.
        minter = self.minter()
        denied = minter.leaf("example.com", denied=True)
        allowed = minter.leaf("example.com", denied=False)
        self.assertNotEqual(denied.path, allowed.path)
        self.assertEqual(minter.stats["mints"], 2)

    def test_the_working_set_is_bounded_too(self):
        cache = vm_mint.LeafCache(3, self.state / "bounded")
        for i in range(10):
            path = cache.path_for(f"h{i}.example")
            path.write_text("")
            cache.put(vm_mint.Leaf(f"h{i}.example", path, time.time() + 1e6))
        self.assertEqual(len(cache), 3)

    def test_eviction_unlinks_the_pem(self):
        cache = vm_mint.LeafCache(1, self.state / "bounded")
        first = cache.path_for("a.example")
        first.write_text("")
        cache.put(vm_mint.Leaf("a.example", first, time.time() + 1e6))
        second = cache.path_for("b.example")
        second.write_text("")
        cache.put(vm_mint.Leaf("b.example", second, time.time() + 1e6))
        self.assertFalse(first.exists())
        self.assertTrue(second.exists())

    def test_a_directory_left_over_from_a_previous_process_is_trimmed(self):
        # Eviction alone cannot bound the directory across restarts: files
        # evicted in a previous process were never in this one's LRU.
        directory = self.state / "stale"
        directory.mkdir()
        for i in range(20):
            (directory / f"{i:064x}.pem").write_text("")
        vm_mint.LeafCache(5, directory)
        self.assertEqual(len(list(directory.glob("*.pem"))), 5)


class TestOverflowDiffersByDisposition(_MinterCase):
    """The part of T4 most worth getting right -- and the part where the design
    deliberately accepts, as an overflow, the behaviour it rejects as a default."""

    def test_a_denial_does_not_wait_on_an_empty_bucket(self):
        slept = []
        bucket = vm_mint.TokenBucket(1, 0.0, sleep=slept.append)
        minter = self.minter(bucket=bucket)
        minter.leaf("first.example", denied=True)
        with self.assertRaises(vm_mint.MintThrottled) as caught:
            minter.leaf("second.example", denied=True)
        self.assertTrue(caught.exception.denied)
        self.assertEqual(slept, [])

    def test_an_allowlisted_name_waits_and_then_fails_distinguishably(self):
        slept = []
        bucket = vm_mint.TokenBucket(1, 0.0, sleep=slept.append)
        minter = self.minter(bucket=bucket)
        minter.leaf("first.example", denied=False)
        with self.assertRaises(vm_mint.MintThrottled) as caught:
            minter.leaf("second.example", denied=False)
        self.assertFalse(caught.exception.denied)
        self.assertTrue(slept, "an allowlisted mint must wait for a token")
        self.assertEqual(minter.stats["throttled"], 1)

    def test_an_allowlisted_name_survives_a_bucket_that_refills_in_time(self):
        bucket = vm_mint.TokenBucket(1, 1000.0)
        minter = self.minter(bucket=bucket)
        minter.leaf("first.example", denied=False)
        leaf = minter.leaf("second.example", denied=False)
        self.assertTrue(leaf.path.exists())

    def test_a_cache_hit_spends_no_token(self):
        # What keeps legitimate traffic out of the bucket entirely: the guest's
        # usual hosts cost one token each ever.
        bucket = vm_mint.TokenBucket(1, 0.0)
        minter = self.minter(bucket=bucket)
        minter.leaf("example.com", denied=False)
        for _ in range(50):
            minter.leaf("example.com", denied=False)
        self.assertEqual(minter.stats["mints"], 1)


class TestRenewal(_MinterCase):

    def test_a_leaf_inside_the_renewal_window_is_a_miss(self):
        minter = self.minter()
        first = minter.leaf("example.com", denied=False)
        later = first.not_after - vm.VM_LEAF_RENEW_WITHIN_SECONDS + 60
        with mock.patch.object(minter, "_clock", lambda: later):
            minter.leaf("example.com", denied=False)
        self.assertEqual(minter.stats["mints"], 2)

    def test_a_leaf_outside_it_is_a_hit(self):
        minter = self.minter()
        first = minter.leaf("example.com", denied=False)
        earlier = first.not_after - vm.VM_LEAF_RENEW_WITHIN_SECONDS - 3600
        with mock.patch.object(minter, "_clock", lambda: earlier):
            minter.leaf("example.com", denied=False)
        self.assertEqual(minter.stats["mints"], 1)

    def test_a_pem_deleted_underneath_the_cache_is_a_miss(self):
        minter = self.minter()
        leaf = minter.leaf("example.com", denied=False)
        leaf.path.unlink()
        minter.leaf("example.com", denied=False)
        self.assertEqual(minter.stats["mints"], 2)


class TestTheClockCheckIsNotOptional(unittest.TestCase):

    def test_a_minter_cannot_be_constructed_without_one(self):
        """`clock_check` has no default ON PURPOSE.

        The mint-time check is the entire remedy for a paused guest, and it
        covers every pause path precisely because it is demand-driven rather
        than hooked per caller. A default would let a future caller construct a
        Minter with no check and lose that silently, on a path where the
        failure is a guest that reaches its old hosts and no new ones.
        """
        with self.assertRaises(TypeError):
            vm_mint.Minter("wl-test", "/nonexistent")


class TestWhatTheMinterReports(_MinterCase):
    """Rung 3 T8. The figures exist here because this is where the events are;
    rendering them is a later rung's work over numbers that by then exist."""

    def test_the_denial_figures_are_subsets_of_the_totals(self):
        """The split is the signal: legitimate traffic mints a few working-set
        leaves and then lives on hits, while a guest driving the minter shows
        up almost entirely in the denial half."""
        minter = self.minter()
        minter.leaf("good.example", denied=False)
        minter.leaf("good.example", denied=False)          # a hit
        minter.leaf("bad.example", denied=True)
        minter.leaf("bad.example", denied=True)            # a denial hit
        snap = minter.snapshot()
        self.assertEqual(snap["mints"], 2)
        self.assertEqual(snap["denied_mints"], 1)
        self.assertEqual(snap["hits"], 2)
        self.assertEqual(snap["denied_hits"], 1)

    def test_the_two_caches_are_sized_separately(self):
        minter = self.minter()
        minter.leaf("good.example", denied=False)
        minter.leaf("bad.example", denied=True)
        snap = minter.snapshot()
        self.assertEqual((snap["working_set"], snap["denials"]), (1, 1))

    def test_a_guest_with_no_agent_is_counted_as_such(self):
        """The figure `diagnose` needs. A guest with no qemu-guest-agent is a
        SUPPORTED configuration in which the mint-time clock remedy is inert --
        the failure it exists to prevent is still possible, and nothing else
        says so."""
        minter = self.minter(clock_check=lambda: "unavailable")
        minter.leaf("example.com", denied=False)
        snap = minter.snapshot()
        self.assertEqual(snap["clock_unavailable"], 1)
        self.assertEqual(snap["clock_resyncs"], 0)
        self.assertEqual(snap["clock_failed"], 0)

    def test_each_clock_outcome_lands_in_its_own_figure(self):
        for outcome, key in (("resynced", "clock_resyncs"),
                             ("failed", "clock_failed"),
                             ("unavailable", "clock_unavailable")):
            with self.subTest(outcome=outcome):
                minter = self.minter(clock_check=lambda o=outcome: o)
                minter.leaf(f"{outcome}.example", denied=False)
                self.assertEqual(minter.snapshot()[key], 1)

    def test_a_healthy_clock_gets_no_figure_of_its_own(self):
        """It would track the mint count and say nothing further."""
        minter = self.minter()
        minter.leaf("example.com", denied=False)
        snap = minter.snapshot()
        self.assertEqual(
            [snap[k] for k in ("clock_resyncs", "clock_unavailable",
                               "clock_failed")], [0, 0, 0])

    def test_the_ca_fingerprint_is_the_one_openssl_prints(self):
        """The value exists to be compared by eye against the anchor installed
        in the guest, so it has to be spelled the way the tool an operator will
        reach for spells it."""
        minter = self.minter()
        printed = _certificate(vm.vm_ca_cert_path(self.state),
                               "-fingerprint", "-sha256").strip()
        _, _, expected = printed.partition("=")
        self.assertEqual(minter.ca_identity()["sha256"], expected)

    def test_the_ca_not_after_is_a_readable_date(self):
        """A ten-year validity is invisible until something prints the date it
        ends on."""
        minter = self.minter()
        not_after = minter.ca_identity()["not_after"]
        self.assertIsInstance(not_after, float)
        self.assertGreater(not_after, time.time() + 365 * 24 * 3600)

    def test_the_ca_is_read_once_and_remembered(self):
        """It does not rotate, so re-reading it per status write would be
        syscalls to confirm a constant."""
        minter = self.minter()
        first = minter.ca_identity()
        vm.vm_ca_cert_path(self.state).unlink()
        self.assertEqual(minter.ca_identity(), first)

    def test_an_unreadable_ca_costs_the_figure_and_not_the_status(self):
        """A status file is never worth a connection."""
        vm.vm_ca_cert_path(self.state).write_text("not a certificate\n")
        minter = self.minter()
        self.assertEqual(minter.ca_identity(),
                         {"sha256": None, "not_after": None})

    def test_the_snapshot_is_a_copy(self):
        """A caller that mutated it would be mutating the counters."""
        minter = self.minter()
        minter.snapshot()["mints"] = 99
        self.assertEqual(minter.snapshot()["mints"], 0)


if __name__ == "__main__":
    unittest.main()
