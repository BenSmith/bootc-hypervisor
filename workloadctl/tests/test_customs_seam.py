"""Where workloadctl meets customs, held from workloadctl's side.

The egress inspector and the credential broker are customs' programs:
workloadctl writes the policy document the inspector reads, and the units
whose ExecStart= hands each program its flags, and imports a published set
of names. customs' own suite holds its side of each of these (its
test_interface and test_closure); what can drift unseen is the half
written here, since a document key the reader ignores, a flag the program
does not take, or a name customs does not publish all fail at a workload's
start or at import, long after the generator ran.

The programs are read from tests.CUSTOMS_LIBEXEC: the installed directory,
or a checkout's when CUSTOMS_CHECKOUT is set.
"""

import ast
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from customs.inspect_policy import Policy, load_policy
from tests import CUSTOMS_CHECKOUT, CUSTOMS_LIBEXEC, REPO_ROOT, script_env

# customs' interface document, "Imported names": what customs keeps stable
# for workloadctl. Copied, not read, because an install without docs has no
# interface document to read; customs' test_interface holds the list to
# its code.
PUBLISHED = {
    "customs.broker_profiles": {
        "BROKER_DEFAULT_AUTH_FORMAT", "BROKER_DEFAULT_AUTH_HEADER"},
    "customs.egress_ca": {
        "CA_DIR_NAME", "DENIAL_DIR_NAME", "LEAF_DIR_NAME", "ca_cert_path",
        "ca_dir", "ca_key_path", "ca_openssl_argv", "denial_dir",
        "leaf_dir"},
    "customs.egress_mint": {"pem_fingerprint"},
    "customs.egress_plane": {"CLEARTEXT", "PLANES", "TLS"},
    "customs.egress_record": {
        "DROP_BROKER_UNREACHABLE", "DROP_MISDIRECTED",
        "DROP_MISDIRECTED_LISTED", "DROP_NOT_HTTP", "DROP_NOT_HTTP_POLICY",
        "DROP_REASONS", "LOG_ID_FIELD", "LOG_REQ_FIELD", "RECORD_DECISIONS",
        "RECORD_MODES"},
    "customs.egress_status": {
        "BoundedCounts", "OTHER_KEY", "STATUS_TOP_N", "clear_status",
        "write_status"},
    "customs.inspect_document": {
        "INSPECT_DIGEST_KEY", "TLS_DEFAULT", "TLS_MODES", "VmPolicyEntry",
        "hostname_control_character", "hostname_match",
        "inspect_policy_digest", "normalise_hostname", "patterns_overlap",
        "policy_governs"},
    "customs.sd_listen": {"NotSocketActivated",
                          "inherited_listening_sockets"},
}

INSPECT = CUSTOMS_LIBEXEC / "customs-inspect"
BROKER = CUSTOMS_LIBEXEC / "customs-broker"

# The inspector's flags the generator hands, exactly: one per value the
# inspector must be told and cannot derive. customs-inspect takes two more,
# --caller-uid and --netns-pid, for placements workloadctl does not use.
INSPECT_HANDED = frozenset({
    "--name",       # a label: the CA subject and the log lines
    "--policy",     # where the policy document is
    "--state-dir",  # where the CA and the leaf caches are
    "--status",     # where the counters go
    "--record",     # where the per-request record goes
    "--broker",     # what the uid became, and the broker's port
})
BROKER_REQUIRED = frozenset({"--name", "--listen", "--caller-uid", "--host"})
BROKER_HANDED = BROKER_REQUIRED | {
    "--placeholder", "--auth-header", "--auth-format"}

# Keys the document carries that the reader has no field for. `http2` is
# always empty: customs relays no HTTP/2 and refuses a list naming a host,
# and the key stays so every workload's policy digest is unchanged.
DOCUMENT_ONLY = frozenset({"http2"})
# Reader fields no document carries: the digest is the status file's.
READER_ONLY = frozenset({"digest"})

SHIPPED = ("lib", "bin", "libexec", "generators")


def _program_flags(path):
    """{flag: required} of every add_argument in a program's source."""
    flags = {}
    for node in ast.walk(ast.parse(path.read_text())):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"
                and node.args and isinstance(node.args[0], ast.Constant)
                and str(node.args[0].value).startswith("--")):
            required = any(k.arg == "required"
                           and isinstance(k.value, ast.Constant)
                           and k.value.value is True for k in node.keywords)
            flags[node.args[0].value] = required
    return flags


def _shipped_sources():
    for top in SHIPPED:
        for path in sorted((Path(REPO_ROOT) / top).iterdir()):
            if not path.is_file():
                continue
            text = path.read_text(errors="replace")
            if path.suffix == ".py" or text.startswith("#!/usr/bin/python3") \
                    or text.startswith("#!/usr/bin/env python3"):
                yield path, text


class TestTheScannerSeesTheTree(unittest.TestCase):

    def test_the_programs_are_there(self):
        self.assertTrue(INSPECT.exists(), INSPECT)
        self.assertTrue(BROKER.exists(), BROKER)

    def test_the_flag_reader_finds_the_programs_flags(self):
        self.assertTrue(_program_flags(INSPECT)["--policy"])
        self.assertFalse(_program_flags(INSPECT)["--broker"])
        self.assertTrue(_program_flags(BROKER)["--listen"])

    def test_one_customs_is_under_test(self):
        """This process, a child launched with script_env(), and the
        programs read from CUSTOMS_LIBEXEC are one customs. With a checkout
        named on a host that also has customs installed, a checkout behind
        site-packages splits them: the imports here are the installed
        release, the programs and the children the checkout."""
        import subprocess
        import sys

        import customs
        here = Path(customs.__file__).resolve()
        child = subprocess.run(
            [sys.executable, "-c", "import customs; print(customs.__file__)"],
            capture_output=True, text=True, check=True, env=script_env(),
            cwd="/")
        self.assertEqual(Path(child.stdout.strip()).resolve(), here)
        if CUSTOMS_CHECKOUT:
            self.assertEqual(here.parent.parent, Path(CUSTOMS_CHECKOUT))
            self.assertEqual(CUSTOMS_LIBEXEC, Path(CUSTOMS_CHECKOUT) / "libexec")

    def test_the_import_scan_finds_imports(self):
        found = [p for p, text in _shipped_sources()
                 if "from customs.inspect_document import" in text]
        self.assertGreater(len(found), 5)


class TestWorkloadctlImportsOnlyWhatCustomsPublishes(unittest.TestCase):

    def test_every_name_imported_from_customs_is_published(self):
        """A name customs does not publish is one it may rename in any
        release, and the rename is an ImportError in workloadctl."""
        unpublished = []
        for path, text in _shipped_sources():
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] == "customs":
                            unpublished.append((path.name, alias.name))
                if not isinstance(node, ast.ImportFrom) or not node.module:
                    continue
                if node.module == "customs":
                    unpublished.extend(
                        (path.name, f"customs.{a.name}") for a in node.names)
                elif node.module.startswith("customs."):
                    for alias in node.names:
                        if alias.name not in PUBLISHED.get(node.module, ()):
                            unpublished.append(
                                (path.name, f"{node.module}.{alias.name}"))
        self.assertEqual(unpublished, [])

    def test_every_published_name_is_in_customs(self):
        import importlib
        for module, names in PUBLISHED.items():
            mod = importlib.import_module(module)
            for name in sorted(names):
                with self.subTest(name=f"{module}.{name}"):
                    self.assertTrue(hasattr(mod, name))


class TestTheDocumentIsTheOneCustomsReads(unittest.TestCase):
    """Both renderers against customs' reader, not against a literal:
    load_policy reads by key and ignores what it does not know, so a key
    written and never read loads clean and authorises nothing."""

    def _load(self, doc):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "inspect.json")
        with open(path, "w") as f:
            json.dump(doc, f)
        return load_policy(path)

    def test_every_key_written_is_a_key_read(self):
        from egress_policy import container_inspect_policy, vm_inspect_policy
        vm = vm_inspect_policy({
            "hosts": ["example.com"],
            "internal": [{"host": "nas.example.com", "reason": "nas"}],
            "splice": [{"host": "pinned.example.com", "reason": "pinned"}],
            "policy": [{"host": "api.example.com", "methods": ["GET"]}]})
        container = container_inspect_policy({
            "hosts": ["example.com"],
            "policy": [{"host": "api.example.com", "methods": ["GET"]}]})
        fields = set(Policy._fields) - READER_ONLY
        self.assertEqual(set(vm) | set(container), fields | DOCUMENT_ONLY)
        for doc in (vm, container):
            self.assertLessEqual(set(doc), fields | DOCUMENT_ONLY)
            for key in DOCUMENT_ONLY:
                self.assertEqual(doc[key], [])
            for key in READER_ONLY:
                self.assertNotIn(key, doc)

    def test_the_lists_arrive(self):
        from egress_policy import vm_inspect_policy
        policy = self._load(vm_inspect_policy({
            "hosts": ["example.com", "nas.example.com",
                      "sum.golang.org"],
            "tls": "inspect",
            "internal": [{"host": "nas.example.com", "reason": "nas"}],
            "splice": [{"host": "sum.golang.org", "reason": "a log"}]}))
        self.assertEqual(policy.hosts,
                         ("example.com", "nas.example.com",
                          "sum.golang.org"))
        self.assertEqual(policy.tls, "inspect")
        self.assertEqual(policy.internal, ("nas.example.com",))
        self.assertEqual(policy.splice, ("sum.golang.org",))

    def test_a_policy_entry_arrives_with_its_credential(self):
        from egress_policy import vm_inspect_policy
        entry, = self._load(vm_inspect_policy({
            "policy": [{"host": "api.example", "methods": ["POST"],
                        "paths": ["/v1/*"], "credential": "tok"}]})).policy
        self.assertEqual((entry.host, entry.methods, entry.paths,
                          entry.credential),
                         ("api.example", ("POST",), ("/v1/*",), "tok"))

    def test_an_absent_key_arrives_as_absent(self):
        """null is ANY and [] is NONE; a loader that collapsed them would
        deny everything on a host the config permits, in silence."""
        from egress_policy import vm_inspect_policy
        entry, = self._load(vm_inspect_policy({
            "policy": [{"host": "a.example"}]})).policy
        self.assertIsNone(entry.methods)
        self.assertIsNone(entry.paths)
        self.assertTrue(entry.permits("DELETE", "/anything"))

    def test_the_empty_http2_list_is_accepted_and_a_named_host_is_not(self):
        from egress_policy import vm_inspect_policy
        doc = vm_inspect_policy({"hosts": ["a.example"]})
        self.assertEqual(self._load(doc).hosts, ("a.example",))
        with self.assertRaises(ValueError):
            self._load({**doc, "http2": ["a.example"]})


class TestTheGeneratorHandsCustomsItsFlags(unittest.TestCase):

    def test_the_inspector_is_handed_every_value(self):
        from egress_policy import (
            inspect_policy_path, inspect_record_path, inspect_status_path,
        )
        from gen_egress import inspect_listener_command
        from workload_addr import (
            BROKER_INSTANCE_PORT, INSPECT_LISTENER_BIN, broker_listen_address,
        )
        from workload_lib import workload_state_dir
        cmd = inspect_listener_command("web", 10004)
        self.assertEqual(cmd[0], INSPECT_LISTENER_BIN)
        flags = {cmd[i]: cmd[i + 1] for i in range(1, len(cmd), 2)}
        self.assertEqual(flags, {
            "--name": "web",
            "--policy": inspect_policy_path("web"),
            "--state-dir": str(workload_state_dir("web")),
            "--status": inspect_status_path("web"),
            "--record": str(inspect_record_path("web")),
            "--broker":
                f"{broker_listen_address(10004)}:{BROKER_INSTANCE_PORT}",
        })

    def test_the_inspector_takes_each_handed_flag_and_requires_no_other(self):
        """A flag it does not take is an argparse error at start; a
        required one not handed is a missing argument. Both fail the
        start, on the guest's first dial."""
        taken = _program_flags(INSPECT)
        self.assertLessEqual(INSPECT_HANDED, set(taken))
        required = {f for f, req in taken.items() if req}
        self.assertLessEqual(required, INSPECT_HANDED)

    def test_the_broker_is_handed_every_value(self):
        from broker_config import BROKER_BIN, broker_command, broker_credential
        from workload_addr import BROKER_INSTANCE_PORT, broker_listen_address

        from tests.test_broker import flags_of

        class Cred:
            def __init__(self, **kw):
                self.__dict__.update(
                    {"auth_header": None, "auth_format": None}, **kw)

        _path, cred_id = broker_credential("web", "tok")
        cmd = broker_command("web", 10004, [("api.x.test", "tok")],
                             [Cred(name="tok", placeholder="P")])
        self.assertEqual(cmd[0], BROKER_BIN)
        self.assertEqual(flags_of(cmd), {
            "--name": ["web"],
            "--listen":
                [f"{broker_listen_address(10004)}:{BROKER_INSTANCE_PORT}"],
            "--caller-uid": ["10004"],
            "--host": [f"api.x.test={cred_id}"],
            "--placeholder": [f"{cred_id}=P"],
        })
        cmd = broker_command("web", 10004, [("api.x.test", "tok")],
                             [Cred(name="tok", placeholder="P",
                                   auth_header="Authorization",
                                   auth_format="Bearer {secret}")])
        self.assertEqual(set(flags_of(cmd)), BROKER_HANDED)

    def test_the_broker_takes_each_handed_flag_and_requires_no_other(self):
        taken = _program_flags(BROKER)
        self.assertLessEqual(BROKER_HANDED, set(taken))
        required = {f for f, req in taken.items() if req}
        self.assertLessEqual(required, BROKER_REQUIRED)


class TestTheProgramsAreCustoms(unittest.TestCase):

    def test_the_units_name_customs_programs(self):
        """The generated units run customs' programs by the path its RPM
        installs them at, and the spec requires that RPM."""
        from broker_config import BROKER_BIN
        from workload_addr import INSPECT_LISTENER_BIN
        self.assertEqual(INSPECT_LISTENER_BIN,
                         "/usr/libexec/customs/customs-inspect")
        self.assertEqual(BROKER_BIN, "/usr/libexec/customs/customs-broker")
        spec = (Path(REPO_ROOT) / "rpm" / "workloadctl.spec").read_text()
        self.assertRegex(spec, r"(?m)^Requires:\s+customs >= ")

    def test_seed_isos_carry_customs(self):
        """A VM's seed ISO carries customs' RPM beside workloadctl's, which
        its bootstrap cannot install alone."""
        from ensure_vm import BUNDLED_RPMS
        self.assertIn("customs.rpm", BUNDLED_RPMS)


CONTAINERFILE = Path(REPO_ROOT).parent / "hypervisor.Containerfile"


@unittest.skipUnless(CONTAINERFILE.is_file(),
                     "image half not present (standalone workloadctl checkout)")
class TestTheImageInstallsCustoms(unittest.TestCase):

    def test_the_pinned_customs_satisfies_the_spec(self):
        """The hypervisor image takes customs' RPM from the image its build
        pins, installs it in the stage that runs this suite and in the
        image, and caches it for VM seed ISOs. The pinned tag satisfies the
        spec's minimum, or the image's `dnf install` refuses workloadctl."""
        spec = (Path(REPO_ROOT) / "rpm" / "workloadctl.spec").read_text()
        minimum = re.search(
            r"(?m)^Requires:\s+customs >= (\S+)$", spec).group(1)
        containerfile = CONTAINERFILE.read_text()
        pinned = re.search(
            r"(?m)^ARG CUSTOMS_RPM=\S+:(\S+)$", containerfile).group(1)

        def version(text):
            return tuple(int(part) for part in text.split("."))

        self.assertGreaterEqual(version(pinned), version(minimum))
        self.assertIn("FROM ${CUSTOMS_RPM} AS customs", containerfile)
        self.assertEqual(containerfile.count(
            "COPY --from=customs /customs.rpm /tmp/customs.rpm"), 2)
        self.assertIn("/usr/share/workloadctl/customs.rpm", containerfile)

if __name__ == "__main__":
    unittest.main()
