"""The credential broker: config loading and per-sandbox profile resolution."""

import contextlib
import io
import tempfile
import textwrap
import unittest

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
    upstream = "https://api.example.com/v1"
    credential = "main-key"
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

    def test_the_old_permissive_flag_is_refused(self):
        self.assertExits(BASE + """
            allow_unknown_sources = true
        """, "allow_unknown_callers")


class TestProfiles(unittest.TestCase):

    def build(self, text):
        cfg = load(text)
        return broker.build_profiles(cfg, load=lambda name: f"secret-of-{name}")

    def test_a_sandbox_inherits_the_top_level_settings(self):
        profiles, _ = self.build(BASE + """
            [sandboxes.agent-scratch]
        """)
        profile = profiles["agent-scratch"]
        self.assertEqual(profile.host, "api.example.com")
        self.assertEqual(profile.port, 443)
        self.assertEqual(profile.prefix, "/v1")
        self.assertEqual(profile.secret, "secret-of-main-key")
        self.assertEqual(profile.auth_header, "x-api-key")

    def test_a_sandbox_can_carry_its_own_credential(self):
        """The point of identifying the caller: one sandbox on a spend-capped
        key, another on the main one."""
        profiles, _ = self.build(BASE + """
            [sandboxes.agent-scratch]
            credential = "cheap-key"

            [sandboxes.agent-review]
        """)
        self.assertEqual(profiles["agent-scratch"].secret, "secret-of-cheap-key")
        self.assertEqual(profiles["agent-review"].secret, "secret-of-main-key")

    def test_a_sandbox_can_target_a_different_provider(self):
        profiles, _ = self.build(BASE + """
            [sandboxes.local]
            upstream = "https://inference.internal:8443"
            auth_header = "Authorization"
            auth_format = "Bearer {secret}"
        """)
        profile = profiles["local"]
        self.assertEqual((profile.host, profile.port), ("inference.internal", 8443))
        self.assertEqual(profile.prefix, "")
        self.assertEqual(profile.auth_format, "Bearer {secret}")

    def test_each_credential_is_read_once_however_many_sandboxes_share_it(self):
        reads = []
        cfg = load(BASE + """
            [sandboxes.a]
            [sandboxes.b]
            [sandboxes.c]
            credential = "other-key"
        """)
        broker.build_profiles(cfg, load=lambda name: reads.append(name) or name)
        self.assertEqual(sorted(reads), ["main-key", "other-key"])

    def test_unknown_callers_get_nothing_by_default(self):
        _, fallback = self.build(BASE)
        self.assertIsNone(fallback)

    def test_unknown_callers_get_the_defaults_when_permitted(self):
        _, fallback = self.build(BASE + """
            allow_unknown_callers = true
        """)
        self.assertIsNotNone(fallback)
        self.assertEqual(fallback.secret, "secret-of-main-key")

    def test_the_credential_is_rendered_into_the_header_at_startup(self):
        """Not per request. auth_format is operator-written and str.format
        raises on a typo, so rendering it here is the difference between a
        refusal to start and a broker that comes up clean and 500s every
        request it is ever given."""
        profiles, _ = self.build(BASE + """
            [sandboxes.local]
            auth_header = "Authorization"
            auth_format = "Bearer {secret}"
        """)
        self.assertEqual(profiles["local"].auth_value, "Bearer secret-of-main-key")

    def test_an_unusable_auth_format_is_refused_at_startup(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                self.build(BASE + """
                    [sandboxes.typo]
                    auth_format = "Bearer {token}"
                """)
        self.assertIn("[sandboxes.typo]", str(caught.exception))
        self.assertIn("auth_format", str(caught.exception))

    def test_the_refusal_does_not_echo_the_format_string(self):
        """It is the string a secret is substituted into; a wrong one may
        already hold part of it."""
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                self.build(BASE + """
                    [sandboxes.typo]
                    auth_format = "Bearer {token}-leaky"
                """)
        self.assertNotIn("leaky", str(caught.exception))

    def test_a_non_https_upstream_is_refused(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                self.build(BASE + """
                    [sandboxes.plain]
                    upstream = "http://api.example.com"
                """)
        self.assertIn("[sandboxes.plain]", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
