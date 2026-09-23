"""The credential broker: what it makes of its flags, and the per-Host table.

The broker read a broker.toml until the flags, and this file held that
reader to a key vocabulary at three levels. The reader is gone with the
document; what survives is every refusal that was about the VALUES rather
than the file -- the listen address, the placeholder, the auth format, two
spellings of one host -- each now asserted on the flag it moved to.
"""

import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

import broker_profiles
import broker_server
from tests import load_script


def build(hosts, placeholders=(), auth_headers=(), auth_formats=(),
          name="agent", load=None):
    return broker_profiles.build_profiles(
        name, hosts, placeholders, auth_headers, auth_formats,
        load=load or (lambda cred_id: f"secret-of-{cred_id}"))


def refused(fn, *args, **kwargs):
    with contextlib.redirect_stderr(io.StringIO()):
        with unittest.TestCase().assertRaises(
                broker_profiles.BrokerConfigError) as caught:
            fn(*args, **kwargs)
    return str(caught.exception)


class TestTheListenAddressIsNotDefaulted(unittest.TestCase):
    """ADR 007's "first detail that will bite".

    An instance must bind the address derived for ITS workload. A default of
    127.0.0.1 puts one workload's broker where every other workload's inspector
    also dials, which grows back the hole decision 6 closes -- so the flag is
    required by the parser (TestEntrypointWiring) rather than defaulted, and
    0.0.0.0, which binds the derived address AND every other one, is refused
    by name.
    """

    def test_the_derived_address_and_port_are_split(self):
        self.assertEqual(broker_profiles.listen_endpoint("127.129.0.3:8081"),
                         ("127.129.0.3", 8081))

    def test_binding_everything_is_refused_by_name(self):
        for value in ("0.0.0.0", "::", "*", "[::]"):
            with self.subTest(value=value):
                self.assertIn("binds every address", refused(
                    broker_profiles.listen_endpoint, f"{value}:8081"))

    def test_no_port_is_refused(self):
        self.assertIn("ADDRESS:PORT", refused(
            broker_profiles.listen_endpoint, "127.129.0.3"))

    def test_a_port_that_is_not_one_is_refused(self):
        self.assertIn("not a number", refused(
            broker_profiles.listen_endpoint, "127.129.0.3:http"))
        self.assertIn("out of range", refused(
            broker_profiles.listen_endpoint, "127.129.0.3:70000"))


class TestThePairFlags(unittest.TestCase):
    """KEY=VALUE, split on the first `=`: the value may carry one."""

    def test_the_value_keeps_its_own_equals_signs(self):
        self.assertEqual(broker_profiles.split_pair("k=a=b", "--x"), ("k", "a=b"))

    def test_no_equals_is_refused_rather_than_read_as_empty(self):
        self.assertIn("KEY=VALUE", refused(broker_profiles.split_pair, "k", "--x"))

    def test_no_key_is_refused(self):
        self.assertIn("KEY=VALUE", refused(broker_profiles.split_pair, "=v", "--x"))

    def test_the_refusal_names_the_flag(self):
        self.assertIn("--placeholder", refused(
            broker_profiles.split_pair, "oops", "--placeholder"))


class TestProfiles(unittest.TestCase):

    def test_a_host_gets_the_brokers_defaults_when_told_nothing_more(self):
        profiles = build(["api.example.com=main-key"])
        profile = profiles["api.example.com"]
        self.assertEqual(profile.host, "api.example.com")
        self.assertEqual(profile.port, 443)
        self.assertEqual(profile.secret, "secret-of-main-key")
        self.assertEqual(profile.auth_header, "x-api-key")
        self.assertEqual(profile.auth_value, "secret-of-main-key")
        self.assertEqual(profile.name, "agent/api.example.com")

    def test_the_table_is_keyed_by_host(self):
        """ADR 007 decision 3. The key that makes one workload able to hold
        several credentials, and the reason a Host cannot be a default."""
        profiles = build(["api.example.com=anthropic-key",
                          "api.github.com=github-token"])
        self.assertEqual(profiles["api.example.com"].secret,
                         "secret-of-anthropic-key")
        self.assertEqual(profiles["api.github.com"].secret,
                         "secret-of-github-token")

    def test_no_host_at_all_is_refused(self):
        """It would hold credentials for nothing and 403 every request, which
        looks from the guest exactly like the broker being down."""
        self.assertIn("holds credentials for nothing", refused(build, []))

    def test_a_host_with_no_credential_is_refused(self):
        self.assertIn("attaching nothing", refused(build, ["api.example.com="]))

    def test_the_upstream_is_the_host_and_nothing_else(self):
        """`upstream` was a key and could carry a port and, once, a path.
        A base path was prepended to every forwarded request, which
        rewrites the very path [[vm.network.policy]].paths admitted: a
        guest's /repos/myorg/x, checked against that pattern, would leave
        as /v1/repos/myorg/x. There is no flag for it now: the profile's
        host IS the Host and its port is the one https port."""
        profile = build(["api.example.com=k"])["api.example.com"]
        self.assertEqual((profile.host, profile.port),
                         ("api.example.com", broker_profiles.UPSTREAM_PORT))
        self.assertEqual(broker_profiles.UPSTREAM_PORT, 443)

    def test_each_credential_is_read_once_however_many_hosts_share_it(self):
        reads = []
        build(["a.example.com=main-key", "b.example.com=main-key",
               "c.example.com=other-key"],
              load=lambda cred_id: reads.append(cred_id) or cred_id)
        self.assertEqual(sorted(reads), ["main-key", "other-key"])

    def test_a_placeholder_equal_to_the_real_key_refuses_the_start(self):
        """The one startup cross-check that survived generation, and now
        the flags. It fires on the mistake generation cannot prevent: a real
        provider key pasted into a plain-text workload.toml, which for a
        shipped bundle is very likely committed.
        """
        message = refused(build, ["api.example.com=main-key"],
                          ["main-key=secret-of-main-key"])
        self.assertIn("byte-identical", message)
        # Neither value is echoed: the message is printed to a terminal, a log
        # and quite possibly a bug report.
        self.assertNotIn("secret-of-main-key", message)

    def test_a_plausible_placeholder_is_accepted_and_never_used(self):
        """It is not compared to anything at request time and does not reach a
        Profile: the broker discards whatever credential arrived and sets its
        own header regardless, which is what makes substitution work whether
        the guest sent a fiction or nothing."""
        profiles = build(["api.example.com=main-key"],
                         ["main-key=sk-ant-api00-000000PLACEHOLDER"])
        profile = profiles["api.example.com"]
        self.assertFalse(hasattr(profile, "placeholder"))
        self.assertEqual(profile.secret, "secret-of-main-key")

    def test_the_credential_is_rendered_into_the_header_at_startup(self):
        """Not per request. auth_format is operator-written and str.format
        raises on a typo, so rendering it here is the difference between a
        refusal to start and a broker that comes up clean and 500s every
        request it is ever given."""
        profiles = build(["api.example.com=main-key"],
                         auth_headers=["main-key=Authorization"],
                         auth_formats=["main-key=Bearer {secret}"])
        self.assertEqual(profiles["api.example.com"].auth_header,
                         "Authorization")
        self.assertEqual(profiles["api.example.com"].auth_value,
                         "Bearer secret-of-main-key")

    def test_an_unusable_auth_format_is_refused_at_startup(self):
        message = refused(build, ["api.example.com=main-key"],
                          auth_formats=["main-key=Bearer {token}"])
        self.assertIn("--auth-format main-key=", message)

    def test_the_refusal_does_not_echo_the_format_string(self):
        """It is the string a secret is substituted into; a wrong one may
        already hold part of it."""
        message = refused(build, ["api.example.com=main-key"],
                          auth_formats=["main-key=Bearer {token}-leaky"])
        self.assertNotIn("leaky", message)

    def test_a_description_for_a_credential_no_host_selects_is_refused(self):
        """The generator never emits one, so its presence is a hand-edited
        unit -- and the description that went unapplied may have been meant
        for a host spelled wrong on another flag."""
        for flag, kwargs in (("--placeholder", {"placeholders": ["x=P"]}),
                             ("--auth-header", {"auth_headers": ["x=H"]}),
                             ("--auth-format", {"auth_formats": ["x={secret}"]})):
            with self.subTest(flag):
                message = refused(build, ["api.example.com=main-key"], **kwargs)
                self.assertIn(flag, message)
                self.assertIn("no --host selects", message)

    def test_a_credential_described_twice_is_refused(self):
        """Last-wins would make which fiction the guest is checked against
        depend on flag order, which nothing states."""
        self.assertIn("given twice", refused(
            build, ["api.example.com=k"], ["k=one", "k=two"]))


class TestHostKeysAreNormalised(unittest.TestCase):
    """`Host` arrives in three spellings that every resolver treats as one.

    A table keyed by the raw string refuses two of the three while the flag
    looks right, and the failure is a 403 on a host the operator can see listed.
    """

    def test_case_port_and_root_dot_all_collapse(self):
        for raw in ("API.Example.com", "api.example.com:443",
                    "api.example.com.", "  api.example.com  "):
            with self.subTest(raw=raw):
                self.assertEqual(broker_profiles.normalise_host(raw), "api.example.com")

    def test_an_unusable_value_is_none_and_never_a_fallback(self):
        for raw in (None, "", "   ", 7, ":443", "[unterminated"):
            with self.subTest(raw=raw):
                self.assertIsNone(broker_profiles.normalise_host(raw))

    def test_a_bracketed_literal_keeps_its_brackets(self):
        self.assertEqual(broker_profiles.normalise_host("[2001:db8::1]:8443"),
                         "[2001:db8::1]")

    def test_the_table_is_keyed_by_the_normalised_spelling(self):
        self.assertIn("api.example.com", build(["API.Example.com:443=k"]))

    def test_an_unusable_host_is_refused(self):
        self.assertIn("not a usable Host", refused(build, [":443=k"]))

    def test_two_spellings_of_one_host_are_refused(self):
        """Last-wins would make which credential a request gets depend on flag
        order, which the unit does not state."""
        self.assertIn("already configured", refused(
            build, ["api.example.com=k", "API.example.com:443=k"]))


class TestLoadCredential(unittest.TestCase):

    def test_a_missing_file_is_a_refusal_naming_the_seam(self):
        """The --host names an id the unit did not load: the two halves of
        the ExecStart= disagree, and the message says which."""
        with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": "/nonexistent"}):
            message = refused(broker_profiles.load_credential, "broker-a-k")
        self.assertIn("LoadCredentialEncrypted=", message)
        self.assertIn("broker-a-k", message)


class TestEntrypointWiring(unittest.TestCase):
    """main() past the parser, with a real Server on an ephemeral port.

    Every other test enters below main(): the reader, the handler, the
    server. What none of them sees is whether the program still hands the
    reader's output to the handler and the handler to the server after a
    move -- an attribute set on the wrong object there is a broker that
    starts clean and refuses every request.
    """

    def setUp(self):
        self.saved = {k: getattr(broker_server.Handler, k)
                      for k in ("name", "workload_uid", "profiles", "overflow",
                                "upstream_context", "connect_timeout",
                                "read_timeout")}
        self.addCleanup(lambda: [setattr(broker_server.Handler, k, v)
                                 for k, v in self.saved.items()])
        self.mod = load_script("libexec/agent-broker")
        self.env = mock.patch.dict(os.environ, {"AGENT_BROKER_SECRET": "sk-test"},
                                   clear=False)
        self.env.start(); self.addCleanup(self.env.stop)
        os.environ.pop("CREDENTIALS_DIRECTORY", None)

    MINIMAL = ["agent-broker", "--name", "agent", "--listen", "127.0.0.1:0",
               "--caller-uid", "10000", "--host", "api.example.com=main-key"]

    def _run(self, argv, **patches):
        seen = {}

        def serve_forever(server):
            seen["server"] = server

        with mock.patch.object(broker_server.Server, "serve_forever", serve_forever), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            for target, value in patches.items():
                stack = mock.patch.object(self.mod, target, value)
                stack.start(); self.addCleanup(stack.stop)
            self.mod.main(argv)
        seen["server"].server_close()
        return seen["server"], err.getvalue()

    def test_the_profiles_reach_the_handler_and_the_server_binds(self):
        server, err = self._run(self.MINIMAL + [
            "--connect-timeout", "3", "--read-timeout", "4"])
        self.assertEqual(list(broker_server.Handler.profiles), ["api.example.com"])
        self.assertEqual(broker_server.Handler.profiles["api.example.com"]
                         .auth_value, "sk-test")
        self.assertEqual(broker_server.Handler.name, "agent")
        self.assertEqual(broker_server.Handler.workload_uid, 10000)
        self.assertEqual((broker_server.Handler.connect_timeout,
                          broker_server.Handler.read_timeout), (3.0, 4.0))
        self.assertIsNotNone(broker_server.Handler.upstream_context)
        self.assertIsNone(server.guest_tls_context)
        self.assertIs(server.RequestHandlerClass, broker_server.Handler)
        self.assertNotEqual(server.server_address[1], 0, "the port was bound")
        self.assertIn("listening url=http://127.0.0.1:", err)
        self.assertIn("using AGENT_BROKER_SECRET", err)

    def test_the_timeouts_default_to_the_servers(self):
        self._run(self.MINIMAL)
        self.assertEqual((broker_server.Handler.connect_timeout,
                          broker_server.Handler.read_timeout),
                         (broker_server.CONNECT_TIMEOUT,
                          broker_server.READ_TIMEOUT))

    def test_every_required_flag_is_required(self):
        """argparse, not a default: each of these is a value the broker
        cannot derive, and a unit that dropped one must fail its start
        rather than bind 127.0.0.1 or serve uid 0."""
        for flag in ("--name", "--listen", "--caller-uid"):
            with self.subTest(flag):
                argv = list(self.MINIMAL)
                i = argv.index(flag)
                del argv[i:i + 2]
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as caught:
                        self.mod.main(argv)
                self.assertEqual(caught.exception.code, 2)

    def test_binding_everything_refuses_to_start(self):
        argv = list(self.MINIMAL)
        argv[argv.index("--listen") + 1] = "0.0.0.0:8081"
        with self.assertRaises(SystemExit) as caught:
            self._run(argv)
        self.assertIn("binds every address", str(caught.exception))

    def test_the_env_fallback_refuses_a_second_credential(self):
        """AGENT_BROKER_SECRET is one value, and load_credential gives it
        for every id: two ids under it sent one provider's key to the other
        provider's host."""
        with self.assertRaises(SystemExit) as caught:
            self._run(self.MINIMAL + ["--host", "api.github.com=gh-key"])
        self.assertIn("AGENT_BROKER_SECRET", str(caught.exception))
        self.assertIn("gh-key", str(caught.exception))
        self.assertIn("main-key", str(caught.exception))

    def test_the_env_fallback_serves_one_credential_on_two_hosts(self):
        """The refusal counts credentials, not hosts: one key on two names
        of one provider is what the fallback is for."""
        self._run(self.MINIMAL + ["--host", "api2.example.com=main-key"])
        self.assertEqual(sorted(broker_server.Handler.profiles),
                         ["api.example.com", "api2.example.com"])

    def test_a_credentials_directory_serves_two_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            for name, secret in (("main-key", "sk-main\n"),
                                 ("gh-key", "sk-gh\n")):
                with open(os.path.join(d, name), "w") as f:
                    f.write(secret)
            with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": d}):
                self._run(self.MINIMAL + ["--host", "api.github.com=gh-key"])
        self.assertEqual(
            {h: p.auth_value
             for h, p in broker_server.Handler.profiles.items()},
            {"api.example.com": "sk-main", "api.github.com": "sk-gh"})

    def test_an_unmappable_caller_refuses_to_start(self):
        with self.assertRaises(SystemExit) as caught:
            self._run(self.MINIMAL,
                      unmappable_uids=lambda uids, uid_map: list(uids))
        self.assertIn("PrivateUsers=", str(caught.exception))
        self.assertIn("10000", str(caught.exception))

    def test_a_tls_cert_without_its_key_is_a_parser_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                self.mod.main(self.MINIMAL + ["--tls-cert", "/x.pem"])
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
