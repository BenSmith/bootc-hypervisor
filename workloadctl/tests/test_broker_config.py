"""The credential broker: config loading and per-sandbox profile resolution."""

import contextlib
import io
import tempfile
import textwrap
import unittest
from pathlib import Path

from tests import load_script

broker = load_script("libexec/agent-broker")


@contextlib.contextmanager
def config_file(text):
    with tempfile.NamedTemporaryFile("w", suffix=".toml") as fh:
        fh.write(textwrap.dedent(text))
        fh.flush()
        yield fh.name


def load(text):
    with config_file(text) as path:
        return broker.load_config(path)


BASE = """
    listen_address = "127.129.0.3"
    upstream = "https://api.example.com"
    credential = "main-key"
"""

# The shortest config that loads: a listen address, and one host under one
# sandbox. Every dimension of the profile table has to be present, because
# neither has a default any more.
MINIMAL = BASE + """
    [sandboxes.agent.hosts."api.example.com"]
"""


class TestStaleConfigIsRefused(unittest.TestCase):
    """The address-keyed schema cannot work under the current topology: every
    guest arrives from one address, so those entries match nothing and 403
    everything. A stale file must fail loudly rather than look applied."""

    def assertExits(self, text, expect):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                load(text)
        self.assertIn(expect, str(caught.exception))

    def test_address_keyed_sandboxes_are_refused(self):
        self.assertExits(BASE + """
            [sandboxes]
            "192.168.200.11" = "agent-scratch"
        """, "workload NAME")

    def test_the_address_keyed_permissive_flag_is_refused(self):
        # ABOVE the sandbox tables, deliberately: a scalar written below one is
        # parsed INTO it, which is the trap the shipped example already carries
        # a comment about -- and a test written the other way would pass while
        # asserting nothing about the top-level check.
        self.assertExits("""
            allow_unknown_sources = true
        """ + MINIMAL, "arriving from the same one")

    def test_the_uid_keyed_permissive_flag_is_refused_too(self):
        """It replaced allow_unknown_sources and did not survive either.

        A default profile for an unenumerated caller is the one switch that
        turns off the uid check, on the component whose whole job is the uid
        check -- and with a per-workload instance generated from that
        workload's own TOML there is no caller it could apply to.
        """
        self.assertExits("""
            allow_unknown_callers = true
        """ + MINIMAL, "serves one workload")

    def test_the_one_profile_per_sandbox_shape_is_refused(self):
        """The pre-rung-6 file, which is not a typo but a working config for a
        broker that fronted one upstream per caller. The message has to name
        the dimension that was added, not the four keys that moved."""
        self.assertExits(BASE + """
            [sandboxes.agent]
            credential = "agent-key"
        """, "(workload, Host)")


class TestUnknownKeysAreRefused(TestStaleConfigIsRefused):
    """A key the broker does not read is a policy the operator thinks they set.

    Every one of these silently applies a default instead: the broker starts,
    logs nothing unusual and reports itself healthy while allowing callers it
    was told to refuse, or serving plaintext where a cert was meant. There is
    no legitimate extra key, so the cost of refusing is zero.
    """

    def test_a_misspelt_top_level_key_is_refused(self):
        self.assertExits("""
            listen_addr = "127.129.0.3"
        """ + MINIMAL, "listen_address")  # the suggestion, not just the rejection

    def test_a_misspelt_host_key_is_refused(self):
        self.assertExits(BASE + """
            [sandboxes.agent.hosts."api.example.com"]
            credentials = "other-key"
        """, 'hosts."api.example.com"')

    def test_the_rejection_names_the_key(self):
        self.assertExits("""
            tls_certificate = "/etc/x.pem"
        """ + MINIMAL, "tls_certificate")

    def test_every_documented_key_is_accepted(self):
        """The other half: the list must not have gone stale against the code
        that reads it, or a valid config stops loading."""
        cfg = load("""
            upstream = "https://api.example.com"
            credential = "main-key"
            listen_address = "127.129.0.3"
            listen_port = 8081
            auth_header = "x-api-key"
            auth_format = "{secret}"
            connect_timeout = 15.0
            read_timeout = 900.0
            relax_x509_strict = false
            tls_cert = "/etc/broker.pem"
            tls_key = "/etc/broker.key"

            [sandboxes.agent.hosts."other.example.com"]
            upstream = "https://other.example.com"
            credential = "agent-key"
            placeholder = "sk-000000000000"
            auth_header = "authorization"
            auth_format = "Bearer {secret}"
        """)
        self.assertEqual(cfg["listen_port"], 8081)
        self.assertIn("agent", cfg["sandboxes"])


class TestTheListenAddressIsNotDefaulted(TestStaleConfigIsRefused):
    """ADR 007's "second detail that will bite".

    An instance must bind the address derived for ITS workload. A default of
    127.0.0.1 puts one workload's broker where every other workload's inspector
    also dials, which grows back the hole decision 6 closes -- so a missing
    value is a refusal to start rather than a silent 127.0.0.1, and 0.0.0.0,
    which binds the derived address AND every other one, is refused by name.
    """

    def test_a_missing_listen_address_is_refused(self):
        self.assertExits("""
            upstream = "https://api.example.com"
            credential = "main-key"

            [sandboxes.agent.hosts."api.example.com"]
        """, "no safe default")

    def test_binding_everything_is_refused_by_name(self):
        for value in ("0.0.0.0", "::", "*"):
            with self.subTest(value=value):
                self.assertExits(f"""
                    listen_address = "{value}"
                    upstream = "https://api.example.com"
                    credential = "main-key"

                    [sandboxes.agent.hosts."api.example.com"]
                """, "binds every address")

    def test_a_broker_with_no_hosts_at_all_is_refused(self):
        """It would hold credentials for nothing and 403 every request, which
        looks from the guest exactly like the broker being down."""
        self.assertExits(BASE, "holds credentials for nothing")


class TestTheShippedExampleIsValid(unittest.TestCase):
    """The example is the file operators are told to copy, so a defect in it is
    a defect in every deployment that follows the instructions.

    It had one: `allow_unknown_callers` sat after the [sandboxes.*] tables, so
    TOML parsed it into the last of them and the broker never read it. Setting
    it for local testing did nothing at all, silently. That key is gone now, but
    the trap it demonstrated is not -- the file still ends in tables, and the
    scalars above them are still swallowed by a preceding one if they move.
    """

    def _example(self):
        return str(Path(__file__).resolve().parents[1] /
                   "docs" / "agent-broker.toml.example")

    def test_it_loads(self):
        cfg = broker.load_config(self._example())
        # Not just that it parses: that the keys landed at the level that reads
        # them. A scalar swallowed by a preceding table still parses fine.
        self.assertEqual(cfg["listen_port"], 8081)
        self.assertTrue(cfg["sandboxes"], "the example shows no sandboxes")

    def test_its_profiles_resolve(self):
        """Loading is the weaker half. The example is copied and edited, so a
        shape that parses and then fails at build_profiles would send an
        operator to their own edits."""
        cfg = broker.load_config(self._example())
        profiles = broker.build_profiles(cfg, load=lambda n: f"secret-of-{n}")
        self.assertTrue(profiles)
        self.assertTrue(all(len(k) == 2 for k in profiles), list(profiles))


class TestProfiles(unittest.TestCase):

    def build(self, text):
        cfg = load(text)
        return broker.build_profiles(cfg, load=lambda name: f"secret-of-{name}")


    def test_a_host_entry_inherits_the_top_level_settings(self):
        profiles = self.build(BASE + """
            [sandboxes.agent-scratch.hosts."api.example.com"]
        """)
        profile = profiles[("agent-scratch", "api.example.com")]
        self.assertEqual(profile.host, "api.example.com")
        self.assertEqual(profile.port, 443)
        self.assertEqual(profile.secret, "secret-of-main-key")
        self.assertEqual(profile.auth_header, "x-api-key")

    def test_the_table_is_keyed_by_both_workload_and_host(self):
        """ADR 007 decision 3. The key that makes one workload able to hold
        several credentials, and the reason a Host cannot be a default."""
        profiles = self.build(BASE + """
            [sandboxes.agent.hosts."api.example.com"]
            credential = "anthropic-key"

            [sandboxes.agent.hosts."api.github.com"]
            upstream = "https://api.github.com"
            credential = "github-token"

            [sandboxes.other.hosts."api.example.com"]
            credential = "other-key"
        """)
        self.assertEqual(
            profiles[("agent", "api.example.com")].secret,
            "secret-of-anthropic-key")
        self.assertEqual(
            profiles[("agent", "api.github.com")].secret,
            "secret-of-github-token")
        # Two workloads, one host, two credentials -- the property that makes an
        # instance's table its own rather than the host's.
        self.assertEqual(
            profiles[("other", "api.example.com")].secret, "secret-of-other-key")

    def test_a_host_entry_can_target_a_different_provider(self):
        profiles = self.build(BASE + """
            [sandboxes.agent.hosts."inference.internal"]
            upstream = "https://inference.internal:8443"
            auth_header = "Authorization"
            auth_format = "Bearer {secret}"
        """)
        profile = profiles[("agent", "inference.internal")]
        self.assertEqual((profile.host, profile.port),
                         ("inference.internal", 8443))
        self.assertEqual(profile.auth_format, "Bearer {secret}")

    def test_an_upstream_carrying_a_path_is_refused(self):
        """`prefix` is deleted, not guarded, and this is what replaces it.

        A base path was prepended to every forwarded request, which rewrites
        the very path [[vm.network.policy]].paths admitted: a guest's
        /repos/myorg/x, checked against that pattern, would leave as
        /v1/repos/myorg/x. The two layers would disagree about what request was
        made, and the one holding the credential would win.
        """
        for url in ("https://api.example.com/v1",
                    "https://api.example.com/v1/"):
            with self.subTest(url=url):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as caught:
                        self.build(f"""
                            listen_address = "127.129.0.3"
                            credential = "main-key"

                            [sandboxes.agent.hosts."api.example.com"]
                            upstream = "{url}"
                        """)
                self.assertIn("must not carry a path", str(caught.exception))
        # A bare origin and one with a trailing slash are both fine: neither
        # carries a path to prepend.
        self.assertTrue(self.build(BASE + """
            [sandboxes.agent.hosts."api.example.com"]
            upstream = "https://api.example.com/"
        """))

    def test_each_credential_is_read_once_however_many_entries_share_it(self):
        reads = []
        cfg = load(BASE + """
            [sandboxes.a.hosts."api.example.com"]
            [sandboxes.b.hosts."api.example.com"]
            [sandboxes.c.hosts."api.example.com"]
            credential = "other-key"
        """)
        broker.build_profiles(cfg, load=lambda name: reads.append(name) or name)
        self.assertEqual(sorted(reads), ["main-key", "other-key"])

    def test_a_host_entry_with_no_credential_anywhere_is_refused(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                self.build("""
                    listen_address = "127.129.0.3"
                    upstream = "https://api.example.com"

                    [sandboxes.agent.hosts."api.example.com"]
                """)
        self.assertIn("attaching nothing", str(caught.exception))

    def test_a_placeholder_equal_to_the_real_key_refuses_the_start(self):
        """The one startup cross-check that survives generation.

        The other two §7.8 asked for cannot fail on a config that is a pure
        function of the TOML. This one can, because it fires on the mistake
        generation cannot prevent: a real provider key pasted into a plain-text
        workload.toml, which for a shipped bundle is very likely committed.
        """
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                self.build(BASE + """
                    [sandboxes.agent.hosts."api.example.com"]
                    placeholder = "secret-of-main-key"
                """)
        message = str(caught.exception)
        self.assertIn("byte-identical", message)
        # Neither value is echoed: the message is printed to a terminal, a log
        # and quite possibly a bug report.
        self.assertNotIn("secret-of-main-key", message)

    def test_a_plausible_placeholder_is_accepted_and_never_used(self):
        """It is not compared to anything at request time and does not reach a
        Profile: the broker discards whatever credential arrived and sets its
        own header regardless, which is what makes substitution work whether
        the guest sent a fiction or nothing."""
        profiles = self.build(BASE + """
            [sandboxes.agent.hosts."api.example.com"]
            placeholder = "sk-ant-api00-000000PLACEHOLDER"
        """)
        profile = profiles[("agent", "api.example.com")]
        self.assertFalse(hasattr(profile, "placeholder"))
        self.assertEqual(profile.secret, "secret-of-main-key")


    def test_the_credential_is_rendered_into_the_header_at_startup(self):
        """Not per request. auth_format is operator-written and str.format
        raises on a typo, so rendering it here is the difference between a
        refusal to start and a broker that comes up clean and 500s every
        request it is ever given."""
        profiles = self.build(BASE + """
            [sandboxes.local.hosts."api.example.com"]
            auth_header = "Authorization"
            auth_format = "Bearer {secret}"
        """)
        self.assertEqual(profiles[("local", "api.example.com")].auth_value,
                         "Bearer secret-of-main-key")

    def test_an_unusable_auth_format_is_refused_at_startup(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                self.build(BASE + """
                    [sandboxes.typo.hosts."api.example.com"]
                    auth_format = "Bearer {token}"
                """)
        self.assertIn("[sandboxes.typo.hosts.", str(caught.exception))
        self.assertIn("auth_format", str(caught.exception))

    def test_the_refusal_does_not_echo_the_format_string(self):
        """It is the string a secret is substituted into; a wrong one may
        already hold part of it."""
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                self.build(BASE + """
                    [sandboxes.typo.hosts."api.example.com"]
                    auth_format = "Bearer {token}-leaky"
                """)
        self.assertNotIn("leaky", str(caught.exception))

    def test_a_non_https_upstream_is_refused(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                self.build(BASE + """
                    [sandboxes.plain.hosts."api.example.com"]
                    upstream = "http://api.example.com"
                """)
        self.assertIn("[sandboxes.plain.hosts.", str(caught.exception))


class TestHostKeysAreNormalised(unittest.TestCase):
    """`Host` arrives in three spellings that every resolver treats as one.

    A table keyed by the raw string refuses two of the three while the config
    looks right, and the failure is a 403 on a host the operator can see listed.
    """

    def test_case_port_and_root_dot_all_collapse(self):
        for raw in ("API.Example.com", "api.example.com:443",
                    "api.example.com.", "  api.example.com  "):
            with self.subTest(raw=raw):
                self.assertEqual(broker.normalise_host(raw), "api.example.com")

    def test_an_unusable_value_is_none_and_never_a_fallback(self):
        for raw in (None, "", "   ", 7, ":443", "[unterminated"):
            with self.subTest(raw=raw):
                self.assertIsNone(broker.normalise_host(raw))

    def test_a_bracketed_literal_keeps_its_brackets(self):
        self.assertEqual(broker.normalise_host("[2001:db8::1]:8443"),
                         "[2001:db8::1]")

    def test_two_spellings_of_one_host_under_one_sandbox_are_refused(self):
        """Last-wins would make which credential a request gets depend on table
        order, which the file does not state."""
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                broker.build_profiles(load(BASE + """
                    [sandboxes.agent.hosts."api.example.com"]
                    [sandboxes.agent.hosts."API.example.com:443"]
                """), load=lambda n: n)
        self.assertIn("already configured", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
