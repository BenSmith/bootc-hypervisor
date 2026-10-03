"""The synthesising responder for a filtered container.

A filtered container resolves through the same moat-resolve a filtered VM
does, reached the same way: podman starts pasta with `--dns-forward`, and
the workload's `--network=` adds `--dns-host` pointing that address at the
responder. What is asserted here is the container half -- which workloads
get one, the pasta option, and the units that bind and start it. The
program's own behaviour is moatery's, and the static map's is in
tests/test_vm_resolve.py and tests/test_egress.py.

The failure every row here stands against is silent: a responder generated
but never pointed at, or pointed at but never started, leaves a container
resolving nothing while every unit reads active.
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from container_run_args import container_network_mode_arg
from diagnose_resolve import container_resolve_check
from validation import collect_config_warnings
from egress_policy import container_uses_resolve
from tests.test_generator import run_generator, write_config
from workload_addr import resolve_address

UID = 10004

FILTERED = {"network": {"hosts": ["api.example.test"]}}


class TestWhichContainersResolve(unittest.TestCase):

    def test_a_filtered_pasta_container_resolves(self):
        self.assertTrue(container_uses_resolve(FILTERED))

    def test_pasta_with_options_of_its_own_still_resolves(self):
        config = {"network": {"hosts": ["a"], "mode": "pasta:--mtu,1400"}}
        self.assertTrue(container_uses_resolve(config))

    def test_a_pod_resolves(self):
        config = {"containers": [{"name": "a"}], **FILTERED}
        self.assertTrue(container_uses_resolve(config))

    def test_an_unfiltered_container_does_not(self):
        """No trigger, no inspector, and so nothing for a synthesised answer
        to point at."""
        self.assertFalse(container_uses_resolve({"network": {}}))
        self.assertFalse(container_uses_resolve({}))

    def test_a_bridge_container_does_not(self):
        """aardvark-dns answers it, and takes no --dns-host."""
        config = {"workload": {"mode": "bridge"}, **FILTERED}
        self.assertFalse(container_uses_resolve(config))

    def test_a_network_pasta_is_not_on_does_not(self):
        for mode in ("slirp4netns", "none", "host"):
            with self.subTest(mode=mode):
                config = {"network": {"hosts": ["a"], "mode": mode}}
                self.assertFalse(container_uses_resolve(config))


class TestThePastaOption(unittest.TestCase):

    def test_the_responder_is_the_dns_host(self):
        self.assertEqual(
            container_network_mode_arg(FILTERED, UID),
            f"pasta:--dns-host,{resolve_address(UID)}")

    def test_it_joins_the_operators_own_pasta_options(self):
        """pasta's options after the colon are comma-separated, so a second
        colon would be one malformed option rather than two."""
        config = {"network": {"hosts": ["a"], "mode": "pasta:--mtu,1400"}}
        self.assertEqual(
            container_network_mode_arg(config, UID),
            f"pasta:--mtu,1400,--dns-host,{resolve_address(UID)}")

    def test_an_unfiltered_mode_is_passed_through(self):
        self.assertEqual(container_network_mode_arg({"network": {}}, UID),
                         "pasta")
        self.assertEqual(
            container_network_mode_arg({"network": {"mode": "host"}}, UID),
            "host")


class _Generated(unittest.TestCase):
    """Run the generator on one TOML and read back what it wrote."""

    TOML = ""
    NAME = ""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        config, self.services, sysusers = (
            root / "c", root / "s", root / "u")
        for d in (config, self.services, sysusers):
            d.mkdir()
        write_config(config, self.NAME, self.TOML)
        result = run_generator(config, self.services, sysusers)
        self.assertEqual(result.returncode, 0, result.stderr)

    def unit(self, suffix):
        path = self.services / f"workload-{self.NAME}{suffix}"
        self.assertTrue(path.exists(), f"{path.name} was not generated")
        return path.read_text()

    def lines(self, suffix, key):
        return [line for line in self.unit(suffix).splitlines()
                if line.startswith(f"{key}=")]


class TestASingleContainer(_Generated):
    NAME = "rs"
    TOML = """\
    [workload]
    name = "rs"

    [container]
    image = "docker.io/library/nginx:latest"

    [network]
    hosts = ["api.example.test"]
    """

    def test_both_responder_units_are_generated(self):
        self.assertIn("ListenDatagram=", self.unit("-resolve.socket"))
        self.assertIn("moat-resolve", self.unit("-resolve.service"))

    def test_the_container_is_pointed_at_it(self):
        self.assertIn('--network="pasta:--dns-host,127.130.',
                      self.unit(".service"))

    def test_the_container_requires_and_follows_the_socket(self):
        """Before= on the socket orders it; only this starts it."""
        self.assertIn("Requires=workload-rs-resolve.socket",
                      self.lines(".service", "Requires"))
        self.assertIn("After=workload-rs-resolve.socket",
                      self.lines(".service", "After"))

    def test_aaaa_is_not_synthesised(self):
        """pasta can copy the inspector's own v6 address onto the
        container's interface, so an AAAA answer naming it is a dial the
        container refuses to itself. With no --address6, AAAA gets no
        records and clients use v4."""
        exec_start = self.lines("-resolve.service", "ExecStart")[0]
        self.assertIn("--address ", exec_start)
        self.assertNotIn("--address6", exec_start)

    def test_the_socket_and_the_pasta_option_name_one_address(self):
        """A --dns-host that disagrees with the socket is a nameserver with
        nothing behind it."""
        listen = self.lines("-resolve.socket", "ListenDatagram")[0]
        address = listen.split("=", 1)[1].rsplit(":", 1)[0]
        self.assertIn(f"--dns-host,{address}", self.unit(".service"))


class TestAPod(_Generated):
    NAME = "rp"
    TOML = """\
    [workload]
    name = "rp"

    [[containers]]
    name = "web"
    [containers.container]
    image = "docker.io/library/nginx:latest"

    [[containers]]
    name = "db"
    [containers.container]
    image = "docker.io/library/postgres:latest"

    [network]
    hosts = ["api.example.test"]
    """

    def test_the_pod_is_created_on_the_responder(self):
        """Members join the pod's network, so the option belongs on the
        create and not on any member."""
        self.assertIn("--network=pasta:--dns-host,127.130.",
                      self.unit("-pod.service"))
        self.assertNotIn("--dns-host", self.unit("-web.service"))

    def test_the_head_unit_requires_and_follows_the_socket(self):
        """The head unit is the one ordered before every member; the
        umbrella is After= them."""
        self.assertIn("Requires=workload-rp-resolve.socket",
                      self.lines("-pod.service", "Requires"))
        self.assertIn("After=workload-rp-resolve.socket",
                      self.lines("-pod.service", "After"))


class TestABridge(_Generated):
    NAME = "rb"
    TOML = """\
    [workload]
    name = "rb"
    mode = "bridge"

    [[containers]]
    name = "web"
    [containers.container]
    image = "docker.io/library/nginx:latest"

    [network]
    hosts = ["api.example.test"]
    """

    def test_no_responder_and_no_option(self):
        self.assertFalse(
            (self.services / "workload-rb-resolve.socket").exists())
        self.assertNotIn("--dns-host", self.unit("-net.service"))
        self.assertNotIn("resolve.socket", self.unit("-net.service"))


class TestAnUnfilteredContainer(_Generated):
    NAME = "ru"
    TOML = """\
    [workload]
    name = "ru"

    [container]
    image = "docker.io/library/nginx:latest"
    """

    def test_nothing_changes(self):
        self.assertFalse(
            (self.services / "workload-ru-resolve.socket").exists())
        self.assertIn('--network="pasta" ', self.unit(".service"))
        self.assertNotIn("resolve.socket", self.unit(".service"))


class TestTheDiagnoseLine(unittest.TestCase):
    """The responder is the only nameserver that answers the container, so
    a socket that is down or a map that is missing is total DNS failure with
    every other line passing."""

    def _check(self, config=None, **observed):
        workload = SimpleNamespace(is_vm=False, config=config or FILTERED,
                                   uid=UID, name="web")
        return container_resolve_check(workload, **observed)

    def test_a_socket_that_is_down_fails_and_names_it(self):
        name, ok, message = self._check(socket_active=False,
                                        static_present=True)
        self.assertEqual((name, ok), ("container_resolve", False))
        self.assertIn("systemctl restart workload-web-resolve.socket",
                      message)

    def test_a_missing_map_fails_and_names_the_prestart(self):
        _, ok, message = self._check(socket_active=True,
                                     static_present=False)
        self.assertFalse(ok)
        self.assertIn("systemctl restart workload-web.service", message)

    def test_both_present_passes_and_names_the_address(self):
        _, ok, message = self._check(socket_active=True,
                                     static_present=True)
        self.assertTrue(ok)
        self.assertIn(resolve_address(UID), message)

    def test_no_responder_no_line(self):
        bridge = {"workload": {"mode": "bridge"}, **FILTERED}
        self.assertIsNone(self._check(bridge, socket_active=False))
        self.assertIsNone(self._check({"network": {}}, socket_active=False))
        vm = SimpleNamespace(is_vm=True, config=FILTERED, uid=UID,
                             name="web")
        self.assertIsNone(container_resolve_check(vm, socket_active=False))


class TestTheResolverAllowWarning(unittest.TestCase):
    """An `allow` entry on 53 hands the container a nameserver the
    responder does not stand in front of."""

    def _warnings(self, **net):
        return collect_config_warnings({
            "workload": {"name": "web"}, "container": {"image": "img"},
            "network": {"hosts": ["a"], **net}})

    def test_an_allow_entry_on_53_is_warned(self):
        found = self._warnings(allow=[{"address": "192.0.2.53", "port": 53,
                                       "reason": "lan dns"}])
        self.assertTrue(any("192.0.2.53:53" in w for w in found), found)

    def test_another_port_is_not(self):
        found = self._warnings(allow=[{"address": "192.0.2.53", "port": 22,
                                       "reason": "ssh"}])
        self.assertFalse(any(":53" in w for w in found), found)

    def test_a_bridge_workload_is_not(self):
        """No responder to go past: that entry is how a bridge-mode
        container reaches a LAN resolver at all."""
        found = collect_config_warnings({
            "workload": {"name": "web", "mode": "bridge"},
            "containers": [{"name": "a", "container": {"image": "img"}}],
            "network": {"hosts": ["a"], "allow": [
                {"address": "192.0.2.53", "port": 53, "reason": "lan"}]}})
        self.assertFalse(any(":53" in w for w in found), found)


if __name__ == "__main__":
    unittest.main()
