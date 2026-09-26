"""The generated units, with systemd's implicit edges, form no ordering cycle.

Every unit the generator writes is read back, its explicit After=/Before=
collected, and the edges systemd adds on its own put beside them: the
default dependencies of each unit type, basic.target's ordering after the
early targets, and a target's After= on what it Wants=. A cycle in that graph
is one systemd breaks at runtime by deleting a job of its own choosing.

The shape it guards: a socket ordered After= its workload's setup.service
while keeping default dependencies. The socket's implicit Before=sockets.target
and setup's implicit After=basic.target close a loop through basic.target.
Starting never trips it -- sockets.target is reached before anything pulls the
socket in -- so every unit came up active, and the only sign was a shutdown
journal line: "Found ordering cycle ... Job workload-<name>-setup.service/stop
deleted to break ordering cycle". A text assertion on either unit cannot see
it; the loop lives in neither.
"""

import tempfile
import unittest
from pathlib import Path

from tests.test_generator import run_generator, write_config

# What systemd adds per unit type when DefaultDependencies=yes, as
# (after, before) target lists -- system manager, the ordering half only.
# Sources: systemd.service(5), systemd.socket(5), systemd.timer(5),
# systemd.path(5), "Default Dependencies" sections.
DEFAULT_ORDERING = {
    "service": (("sysinit.target", "basic.target"), ("shutdown.target",)),
    "socket": (("sysinit.target",), ("sockets.target", "shutdown.target")),
    "timer": (("sysinit.target",), ("timers.target", "shutdown.target")),
    "path": (("sysinit.target",), ("paths.target", "shutdown.target")),
}

# Fixed edges of the stock targets the generated units hang off:
# basic.target's own After= line (systemd's units/basic.target), and the
# early-boot chain into it.
TARGET_AFTER = {
    "basic.target": ("sysinit.target", "sockets.target", "paths.target",
                     "slices.target"),
    "multi-user.target": ("basic.target",),
}

FILTERED_VM = """\
[workload]
name = "fvm"

[vm]
cloud_image_url = "https://example.test/fedora.qcow2"
cloud_image_checksum = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
user = "ben"
volumes = ["./home:/home/ben"]

[vm.network]
egress = "filtered"
hosts = ["api.example.test"]

[[vm.network.credential]]
name = "example-token"
placeholder = "sk-000000PLACEHOLDER"
env = "EXAMPLE_API_KEY"

[[vm.network.policy]]
host = "api.example.test"
credential = "example-token"
"""

FILTERED_CONTAINER = """\
[workload]
name = "fct"

[container]
image = "docker.io/library/nginx:latest"

[network]
hosts = ["api.example.test"]
ca_delivery = "env"

[[network.credential]]
name = "example-token"
placeholder = "sk-000000PLACEHOLDER"
env = "EXAMPLE_API_KEY"

[[network.policy]]
host = "api.example.test"
credential = "example-token"
"""


def parse_unit(text):
    """{(section, key): [values]} with repeated keys kept and each value
    split on whitespace -- configparser would keep only the last line."""
    out, section = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, sep, value = line.partition("=")
        if sep:
            out.setdefault((section, key.strip()), []).extend(value.split())
    return out


def ordering_graph(units):
    """Edges a -> b meaning a is ordered before b, from `units`
    ({unit name: text}) plus the implicit edges described above."""
    edges = set()
    for target, afters in TARGET_AFTER.items():
        edges.update((a, target) for a in afters)
    for name, text in units.items():
        d = parse_unit(text)
        edges.update((a, name) for a in d.get(("Unit", "After"), []))
        edges.update((name, b) for b in d.get(("Unit", "Before"), []))
        defaults = d.get(("Unit", "DefaultDependencies"), ["yes"])[-1]
        kind = name.rsplit(".", 1)[-1]
        if defaults == "yes" and kind in DEFAULT_ORDERING:
            afters, befores = DEFAULT_ORDERING[kind]
            edges.update((a, name) for a in afters)
            edges.update((name, b) for b in befores)
        # A target with default dependencies is ordered after the units it
        # Wants=/Requires=, which is what [Install] WantedBy= turns into.
        for key in ("WantedBy", "RequiredBy"):
            for target in d.get(("Install", key), []):
                if target.endswith(".target"):
                    edges.add((name, target))
    return edges


def find_cycle(edges):
    """One cycle as a list of unit names, or None."""
    succ = {}
    for a, b in edges:
        succ.setdefault(a, []).append(b)
    state, stack = {}, []

    def visit(node):
        state[node] = "open"
        stack.append(node)
        for nxt in sorted(succ.get(node, ())):
            if state.get(nxt) == "open":
                return stack[stack.index(nxt):] + [nxt]
            if nxt not in state:
                found = visit(nxt)
                if found:
                    return found
        stack.pop()
        state[node] = "done"
        return None

    for node in sorted(succ):
        if node not in state:
            found = visit(node)
            if found:
                return found
    return None


def generated_units(toml):
    with tempfile.TemporaryDirectory() as tmp:
        config_dir, services_dir, sysusers_dir = (
            Path(tmp) / "c", Path(tmp) / "s", Path(tmp) / "u")
        for d in (config_dir, services_dir, sysusers_dir):
            d.mkdir()
        name = parse_unit(toml)[("workload", "name")][0].strip('"')
        write_config(config_dir, name, toml)
        result = run_generator(config_dir, services_dir, sysusers_dir)
        # The generator exits 0 on a refused config, by design; a refusal
        # generates nothing, and nothing is trivially acyclic.
        if result.returncode != 0 or "ERROR" in result.stderr:
            raise AssertionError(result.stderr)
        return {p.name: p.read_text() for p in services_dir.iterdir()
                if p.is_file() and p.suffix in (".service", ".socket",
                                                ".timer", ".path",
                                                ".target", ".mount")}


class TestTheModel(unittest.TestCase):
    """The checker has to see the shape that shipped, or its green is
    nothing."""

    def test_the_shipped_socket_shape_is_a_cycle(self):
        units = {
            "workload-x-setup.service": "[Unit]\nDescription=setup\n",
            "workload-x-inspect.socket": (
                "[Unit]\nRequires=workload-x-setup.service\n"
                "After=workload-x-setup.service\n"
                "Before=workload-x.service\n"),
        }
        cycle = find_cycle(ordering_graph(units))
        self.assertIsNotNone(cycle)
        self.assertIn("basic.target", cycle)
        self.assertIn("sockets.target", cycle)

    def test_dropping_the_default_dependencies_breaks_it(self):
        units = {
            "workload-x-setup.service": "[Unit]\nDescription=setup\n",
            "workload-x-inspect.socket": (
                "[Unit]\nAfter=workload-x-setup.service\n"
                "DefaultDependencies=no\n"),
        }
        self.assertIsNone(find_cycle(ordering_graph(units)))


class TestGeneratedUnitsAreAcyclic(unittest.TestCase):

    def assert_acyclic(self, toml):
        units = generated_units(toml)
        cycle = find_cycle(ordering_graph(units))
        self.assertIsNone(cycle, "ordering cycle: " + " -> ".join(cycle or ()))
        return units

    def test_a_filtered_vm(self):
        units = self.assert_acyclic(FILTERED_VM)
        # The shape under test has to have been generated, or this is vacuous.
        for unit in ("workload-fvm-inspect.socket", "workload-fvm-resolve.socket",
                     "workload-fvm-broker.service", "workload-fvm-setup.service"):
            self.assertIn(unit, units)

    def test_a_filtered_container(self):
        units = self.assert_acyclic(FILTERED_CONTAINER)
        for unit in ("workload-fct-inspect.socket", "workload-fct-resolve.socket",
                     "workload-fct-broker.service"):
            self.assertIn(unit, units)


if __name__ == "__main__":
    unittest.main()
