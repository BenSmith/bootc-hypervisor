"""The workload.toml each manual rig writes must still be a valid config.

WHY THIS EXISTS

tests/manual/*.py build their `workload.toml` as a list of strings and hand it
straight to a real host. Nothing else in `just test` parses that TOML, so a
schema change lands, the whole suite stays green, and the rig stays broken
until someone carries it to a KVM host -- which for these rigs is weeks.

That is not merely inconvenient. The failure LOOKS LIKE the thing under test:
the config is refused, no units are generated, and the host ends up with no VM,
no listener and no status file -- the same surface a missing SELinux grant
produces. inspect_rig.py failed exactly this way on 2026-08-25, carrying the
bare-string `allow` spelling that rung 2 retired, and only the generator's
error message distinguished a stale rig from a policy gap.

WHAT THIS DOES NOT DO

It does not run the rigs, and it cannot: they need root, KVM, and a base image.
It asserts only that what they GENERATE would be accepted, which is the half
that rots silently.
"""
import importlib.util
import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANUAL = ROOT / "tests" / "manual"


def _load(path):
    """Import a rig by path. They are scripts, not modules, and not importable
    as tests.manual.* -- there is no package there and adding one would put
    root-only code on the discovery path."""
    spec = importlib.util.spec_from_file_location(f"_rig_{path.stem}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _rigs():
    """Every rig that generates a workload config, found rather than listed.

    A hard-coded list is the same decay one level up: a rig added later would
    not be covered and nothing would say so.
    """
    for path in sorted(MANUAL.glob("*.py")):
        # Read before importing. Not every file in tests/manual is a rig --
        # stub_upstream.py is a helper that parses sys.argv at module level and
        # blows up on the unittest argv. Selecting by source text keeps this
        # from importing anything that was never meant to be imported.
        src = path.read_text()
        if "def toml_for(" not in src or "ARMS = " not in src:
            continue
        mod = _load(path)
        yield path.name, mod


class TestGeneratedConfigs(unittest.TestCase):
    def test_at_least_one_rig_is_covered(self):
        """Guards the discovery above: a glob that matches nothing makes every
        other test in this module vacuously pass."""
        self.assertTrue(list(_rigs()))

    def test_every_generated_config_parses(self):
        for name, mod in _rigs():
            for arm in mod.ARMS:
                with self.subTest(rig=name, arm=arm.name):
                    try:
                        tomllib.loads(mod.toml_for(arm))
                    except tomllib.TOMLDecodeError as exc:
                        self.fail(f"{name} arm {arm.name}: {exc}")

    def test_every_generated_network_section_validates(self):
        """The half that catches a retired spelling: parsing is not enough,
        because `allow = ["1.1.1.1:53"]` is perfectly good TOML and a refused
        config all the same."""
        from vm import _validate_egress
        for name, mod in _rigs():
            for arm in mod.ARMS:
                with self.subTest(rig=name, arm=arm.name):
                    doc = tomllib.loads(mod.toml_for(arm))
                    net = (doc.get("vm") or {}).get("network")
                    if net is None:
                        continue
                    errors = _validate_egress(net)
                    self.assertEqual(errors, [], f"{name} arm {arm.name}: {errors}")

    def test_network_scalars_precede_the_allow_table(self):
        """The ordering trap, asserted on the generated TEXT rather than on the
        parsed document -- because a scalar written below [[vm.network.allow]]
        parses fine and lands in the allow entry, which is exactly the mistake
        that is hard to see by reading."""
        for name, mod in _rigs():
            for arm in mod.ARMS:
                with self.subTest(rig=name, arm=arm.name):
                    text = mod.toml_for(arm)
                    if "[[vm.network.allow]]" not in text:
                        continue
                    tail = text.split("[[vm.network.allow]]", 1)[1]
                    for line in tail.splitlines():
                        key = line.split("=")[0].strip()
                        if key in ("egress", "hosts", "resolver", "ports",
                                   "bridge", "tls"):
                            self.fail(f"{name} arm {arm.name}: `{key}` is "
                                      f"written below [[vm.network.allow]] and "
                                      f"belongs to the allow entry, not to "
                                      f"[vm.network]")


if __name__ == "__main__":
    unittest.main()
