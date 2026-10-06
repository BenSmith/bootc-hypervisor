"""Where workloadctl meets moatery, held from workloadctl's side.

The egress inspector, the credential broker and the DNS responder are
moatery's programs: workloadctl writes the policy document the inspector
reads, the static map the responder reads, and the units whose ExecStart=
hands each program its flags, reads the responder's status file, and
imports a published set of names. moatery's own suite holds its side of each of these (its
test_interface and test_closure); what can drift unseen is the half
written here, since a document key the reader ignores, a flag the program
does not take, or a name moatery does not publish all fail at a workload's
start or at import, long after the generator ran.

The programs are read from tests.MOATERY_LIBEXEC: the installed directory,
or a checkout's when MOATERY_CHECKOUT is set.
"""

import ast
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from moatery.inspect_policy import Policy, load_policy
from tests import MOATERY_CHECKOUT, MOATERY_LIBEXEC, REPO_ROOT, script_env

# moatery's interface document, "Imported names": what moatery keeps stable
# for workloadctl. Copied, not read, because an install without docs has no
# interface document to read; moatery's test_interface holds the list to
# its code.
PUBLISHED = {
    "moatery.broker_profiles": {
        "BROKER_DEFAULT_AUTH_FORMAT", "BROKER_DEFAULT_AUTH_HEADER"},
    "moatery.egress_ca": {
        "CA_DIR_NAME", "DENIAL_DIR_NAME", "LEAF_DIR_NAME", "ca_cert_path",
        "ca_dir", "ca_key_path", "ca_openssl_argv", "denial_dir",
        "leaf_dir"},
    "moatery.egress_mint": {"pem_fingerprint"},
    "moatery.egress_plane": {"CLEARTEXT", "PLANES", "TLS"},
    "moatery.egress_record": {
        "DROP_BROKER_UNREACHABLE", "DROP_MISDIRECTED",
        "DROP_MISDIRECTED_LISTED", "DROP_NOT_HTTP", "DROP_NOT_HTTP_POLICY",
        "DROP_REASONS", "LOG_ID_FIELD", "LOG_REQ_FIELD", "RECORD_DECISIONS",
        "RECORD_MODES"},
    "moatery.egress_status": {
        "BoundedCounts", "OTHER_KEY", "STATUS_TOP_N", "clear_status",
        "write_status"},
    "moatery.inspect_document": {
        "INSPECT_DIGEST_KEY", "TLS_DEFAULT", "TLS_MODES", "VmPolicyEntry",
        "hostname_control_character", "hostname_match",
        "inspect_policy_digest", "normalize_hostname", "patterns_overlap",
        "policy_governs"},
    "moatery.sd_listen": {"NotSocketActivated",
                          "inherited_listening_sockets"},
}

INSPECT = MOATERY_LIBEXEC / "moat-inspect"
BROKER = MOATERY_LIBEXEC / "moat-broker"
RESOLVE = MOATERY_LIBEXEC / "moat-resolve"
MINT = MOATERY_LIBEXEC / "moat-mint-ca"

# moatery's interface document, "The responder's status file": the keys
# workloadctl may read from it. Copied for the reason PUBLISHED is.
RESOLVE_STATUS_PUBLISHED = frozenset({
    ("queries", "synthesised"), ("queries", "static"), ("queries", "nodata"),
    ("queries", "malformed"), ("unlisted",), ("unlisted_names",),
    ("written_at",)})

# The inspector's flags the generator hands, exactly: one per value the
# inspector must be told and cannot derive. moat-inspect takes two more,
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
# The responder's, every one it takes but --address6, withheld because pasta
# and passt can copy the inspector's v6 address onto the workload itself
# (gen_egress.resolve_command).
RESOLVE_WITHHELD = frozenset({"--address6"})
RESOLVE_HANDED = frozenset({
    "--name",      # a label: the log lines
    "--address",   # the inspector's v4 address, every synthesised A
    "--policy",    # the inspector's document, read to count unlisted names
    "--static",    # the allow-by-name map
    "--status",    # where the counters go
})
# The CA mint's, every one it takes.
MINT_HANDED = frozenset({
    "--name",       # carried on the CA's subject
    "--state-dir",  # the inspector's --state-dir, where the CA goes
})
BROKER_HANDED = BROKER_REQUIRED | {
    "--placeholder", "--auth-header", "--auth-format"}

# Keys the document carries that the reader has no field for. `http2` is
# always empty: moatery relays no HTTP/2 and refuses a list naming a host,
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
        self.assertTrue(RESOLVE.exists(), RESOLVE)

    def test_the_flag_reader_finds_the_programs_flags(self):
        self.assertTrue(_program_flags(INSPECT)["--policy"])
        self.assertFalse(_program_flags(INSPECT)["--broker"])
        self.assertTrue(_program_flags(BROKER)["--listen"])
        self.assertFalse(_program_flags(RESOLVE)["--static"])

    def test_one_moatery_is_under_test(self):
        """This process, a child launched with script_env(), and the
        programs read from MOATERY_LIBEXEC are one moatery. With a checkout
        named on a host that also has moatery installed, a checkout behind
        site-packages splits them: the imports here are the installed
        release, the programs and the children the checkout."""
        import subprocess
        import sys

        import moatery
        here = Path(moatery.__file__).resolve()
        child = subprocess.run(
            [sys.executable, "-c", "import moatery; print(moatery.__file__)"],
            capture_output=True, text=True, check=True, env=script_env(),
            cwd="/")
        self.assertEqual(Path(child.stdout.strip()).resolve(), here)
        if MOATERY_CHECKOUT:
            self.assertEqual(here.parent.parent, Path(MOATERY_CHECKOUT))
            self.assertEqual(MOATERY_LIBEXEC, Path(MOATERY_CHECKOUT) / "libexec")

    def test_the_import_scan_finds_imports(self):
        found = [p for p, text in _shipped_sources()
                 if "from moatery.inspect_document import" in text]
        self.assertGreater(len(found), 5)


class TestWorkloadctlImportsOnlyWhatMoateryPublishes(unittest.TestCase):

    def test_every_name_imported_from_moatery_is_published(self):
        """A name moatery does not publish is one it may rename in any
        release, and the rename is an ImportError in workloadctl."""
        unpublished = []
        for path, text in _shipped_sources():
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] == "moatery":
                            unpublished.append((path.name, alias.name))
                if not isinstance(node, ast.ImportFrom) or not node.module:
                    continue
                if node.module == "moatery":
                    unpublished.extend(
                        (path.name, f"moatery.{a.name}") for a in node.names)
                elif node.module.startswith("moatery."):
                    for alias in node.names:
                        if alias.name not in PUBLISHED.get(node.module, ()):
                            unpublished.append(
                                (path.name, f"{node.module}.{alias.name}"))
        self.assertEqual(unpublished, [])

    def test_every_published_name_is_in_moatery(self):
        import importlib
        for module, names in PUBLISHED.items():
            mod = importlib.import_module(module)
            for name in sorted(names):
                with self.subTest(name=f"{module}.{name}"):
                    self.assertTrue(hasattr(mod, name))


class TestTheDocumentIsTheOneMoateryReads(unittest.TestCase):
    """Both renderers against moatery's reader, not against a literal:
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
        self.assertEqual(policy.internal_expected, ("nas.example.com",))
        self.assertEqual(policy.splice, ("sum.golang.org",))

    def test_the_internal_list_is_carried_under_its_new_name(self):
        """The rendered key is `internal_expected`, not `internal`.

        moatery renamed it because the list admits nothing -- it only
        attributes a failed private-address dial -- and the old name read
        like an allow-list. A non-empty legacy key now refuses the
        inspector's start, so a writer still emitting `internal` is not a
        cosmetic drift; it is a workload whose inspector will not run.
        """
        from egress_policy import container_inspect_policy, vm_inspect_policy
        net = {
            "hosts": ["nas.example.com"],
            "internal": [{"host": "nas.example.com", "reason": "nas"}],
        }
        for doc in (vm_inspect_policy(net), container_inspect_policy(net)):
            self.assertEqual(doc["internal_expected"], ["nas.example.com"])
            self.assertNotIn("internal", doc)

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


class TestTheGeneratorHandsMoateryItsFlags(unittest.TestCase):

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

    def test_the_responder_is_handed_every_value(self):
        from egress_policy import inspect_policy_path
        from gen_egress import resolve_command
        from nft_elements import resolve_status_path
        from egress_policy import resolve_static_path
        from workload_addr import RESOLVE_LISTENER_BIN, inspect_address
        cmd = resolve_command("web", 10004)
        self.assertEqual(cmd[0], RESOLVE_LISTENER_BIN)
        flags = {cmd[i]: cmd[i + 1] for i in range(1, len(cmd), 2)}
        self.assertEqual(flags, {
            "--name": "web",
            "--address": inspect_address(10004).v4,
            "--policy": inspect_policy_path("web"),
            "--static": resolve_static_path("web"),
            "--status": resolve_status_path("web"),
        })

    def test_the_responder_runs_with_the_user_site_off(self):
        """ExecStart= runs the program itself, so its shebang is the only
        thing keeping site.py from statting a site-packages dir under the
        workload's home, which wlresolve_t may not traverse
        (security/workload-resolve.cil). moatery 0.5.1 is the first whose
        shebang carries -s; the spec's floor is held to that."""
        shebang = RESOLVE.read_text().splitlines()[0]
        self.assertRegex(shebang, r"^#!\S*python3\S*(\s+-\w*s\w*)\b")

    def test_the_responder_takes_each_handed_flag_and_requires_no_other(self):
        taken = _program_flags(RESOLVE)
        self.assertEqual(set(taken), RESOLVE_HANDED | RESOLVE_WITHHELD)
        self.assertFalse(any(taken[f] for f in RESOLVE_WITHHELD), taken)


class TestTheResponderStatusIsReadByPublishedKeys(unittest.TestCase):

    def test_every_figure_read_is_a_published_key(self):
        """A key moatery does not publish is one it may rename, and a
        figure read from a missing key reads 0 -- a legal value, so the
        rename shows as a quiet responder."""
        from inspect_figures import FIGURES, NAMES
        read = {fig.path for fig in FIGURES
                if fig.group == NAMES and fig.derive is None}
        self.assertTrue(read)
        self.assertLessEqual(read, RESOLVE_STATUS_PUBLISHED)


class TestTheCaMintIsHandedItsFlags(unittest.TestCase):
    """generate_egress_ca runs moat-mint-ca: a flag it does not take is
    a workload that cannot start, found at the first boot of a filtered
    one."""

    def _argv(self):
        import ensure_common
        state = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, state, ignore_errors=True)
        pw = type("pw", (), {"pw_uid": os.getuid(), "pw_gid": os.getgid()})
        ran = []

        def fake_run(argv, **kwargs):
            ran.append(argv)
            raise OSError("stop here")

        with mock.patch.object(ensure_common, "workload_state_dir",
                               return_value=state), \
                mock.patch.object(ensure_common.os, "chown"), \
                mock.patch.object(ensure_common.subprocess, "run", fake_run):
            with self.assertRaises(RuntimeError):
                ensure_common.generate_egress_ca(pw, "web")
        self.assertEqual(len(ran), 1)
        return ran[0], state

    def test_the_command_is_the_program_and_its_two_flags(self):
        import ensure_common
        argv, state = self._argv()
        self.assertEqual(argv[0], ensure_common.CA_MINT_BIN)
        self.assertEqual(Path(argv[0]).name, MINT.name)
        self.assertEqual(Path(argv[0]).parent,
                         Path("/usr/libexec/moatery"))
        flags = {argv[i]: argv[i + 1] for i in range(1, len(argv), 2)}
        self.assertEqual(flags, {"--name": "web", "--state-dir": str(state)})

    def test_the_state_dir_is_the_inspectors(self):
        """The CA the mint writes is the one the inspector signs with, so
        the two are handed one directory."""
        from gen_egress import inspect_listener_command
        argv, state = self._argv()
        mint_dir = argv[argv.index("--state-dir") + 1]
        with mock.patch("gen_egress.workload_state_dir", return_value=state):
            cmd = inspect_listener_command("web", 10004)
        self.assertEqual(cmd[cmd.index("--state-dir") + 1], mint_dir)

    def test_the_mint_takes_each_handed_flag_and_requires_it(self):
        taken = _program_flags(MINT)
        self.assertEqual(set(taken), MINT_HANDED)
        self.assertTrue(all(taken.values()), taken)


def _query(ident, name, qtype):
    labels = b"".join(bytes([len(part)]) + part.encode()
                      for part in name.split("."))
    return (struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
            + labels + b"\0" + struct.pack("!HH", qtype, 1))


def _addresses(reply):
    """The A/AAAA rdata of a reply to one of _query's questions."""
    ancount = struct.unpack("!H", reply[6:8])[0]
    offset = 12
    while reply[offset]:
        offset += reply[offset] + 1
    offset += 5
    out = []
    for _ in range(ancount):
        offset += 2    # a pointer back to the question
        rtype, _cls, _ttl, length = struct.unpack(
            "!HHIH", reply[offset:offset + 10])
        offset += 10
        rdata = reply[offset:offset + length]
        offset += length
        if rtype in (1, 28):
            out.append(str(ipaddress.ip_address(rdata)))
    return out


class TestTheResponderRunsOnWhatWorkloadctlWrites(unittest.TestCase):
    """moat-resolve started with the generator's command, on the
    inspector policy and static map workloadctl renders, and asked over a
    real socket. The rows above hold the flags and the keys one at a time;
    this is the only one that sees what the program makes of the files."""

    def test_static_synthesised_and_unlisted(self):
        from egress_policy import resolve_static, vm_inspect_policy_text
        from gen_egress import resolve_command
        from vm_network_config import VmAllowEntry
        from workload_addr import inspect_address

        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        paths = {flag: os.path.join(d, name) for flag, name in (
            ("--policy", "inspect.json"), ("--static", "static.json"),
            ("--status", "status.json"))}
        Path(paths["--policy"]).write_text(vm_inspect_policy_text({
            "hosts": ["listed.example"],
            "policy": [{"host": "*.api.example"}]}))
        forge = VmAllowEntry(address=None, host="Git.Local", port=2222,
                             reason="forge")
        Path(paths["--static"]).write_text(json.dumps(resolve_static(
            [(forge, [ipaddress.IPv4Address("192.0.2.9")])])))
        _binary, *args = resolve_command("web", 10004)
        for i in range(0, len(args), 2):
            args[i + 1] = paths.get(args[i], args[i + 1])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind(("127.0.0.1", 0))
        proc = subprocess.Popen(
            ["/bin/sh", "-c", 'LISTEN_PID=$$ LISTEN_FDS=1 exec "$@"', "sh",
             sys.executable, str(RESOLVE), *args],
            env=script_env(), pass_fds=(3,),
            preexec_fn=lambda: os.dup2(sock.fileno(), 3),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(proc.stderr.close)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(client.close)
        client.settimeout(10)
        inspect = inspect_address(10004)
        asked = [("git.local", 1, ["192.0.2.9"]),
                 ("git.local", 28, []),
                 ("elsewhere.example", 1, [inspect.v4]),
                 ("elsewhere.example", 28, []),  # no --address6 handed
                 ("listed.example", 1, [inspect.v4]),
                 ("v1.api.example", 1, [inspect.v4]),
                 ("api.example", 1, [inspect.v4])]
        for ident, (name, qtype, want) in enumerate(asked, 1):
            client.sendto(_query(ident, name, qtype), sock.getsockname())
            try:
                reply = client.recv(512)
            except TimeoutError:
                proc.kill()
                self.fail(f"no answer for {name}: "
                          f"{proc.stderr.read().decode()}")
            self.assertEqual(struct.unpack("!H", reply[:2])[0], ident)
            self.assertEqual(_addresses(reply), want, (name, qtype))

        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=10), 0,
                         proc.stderr.read().decode())
        status = json.loads(Path(paths["--status"]).read_text())
        self.assertEqual(status["queries"]["static"], 2)
        # The four A answers; the AAAA had no address to synthesise.
        self.assertEqual(status["queries"]["synthesised"], 4)
        # A `hosts` name, a policy wildcard and a static name are listed;
        # the policy wildcard's apex is not.
        self.assertEqual(status["unlisted"], 3)
        self.assertEqual(set(status["unlisted_names"]),
                         {"elsewhere.example", "api.example"})
        self.assertIn("written_at", status)



class TestTheBrokerSaysItIsReady(unittest.TestCase):
    """The broker's unit is Type=notify (gen_egress), so it is started only
    when moat-broker, run with the generator's command, sends READY=1.
    One that never sends it times out starting and takes the workload with
    it; one that sends it before binding lets the unit ordered after it
    reach a socket that is not there."""

    def test_ready_once_listening(self):
        from broker_config import broker_command, broker_credential

        class Cred:
            def __init__(self, **kw):
                self.__dict__.update(
                    {"auth_header": None, "auth_format": None}, **kw)

        uid = 10004 + os.getpid() % 1000
        _path, cred_id = broker_credential("web", "tok")
        _binary, *args = broker_command(
            "web", uid, [("api.x.test", "tok")],
            [Cred(name="tok", placeholder="P")])
        listen = args[args.index("--listen") + 1]
        host, port = listen.rsplit(":", 1)

        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        creds = Path(d, "creds")
        creds.mkdir()
        (creds / cred_id).write_text("secret")
        notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(notify.close)
        notify.bind(os.path.join(d, "notify"))
        notify.settimeout(10)

        env = dict(script_env(), NOTIFY_SOCKET=os.path.join(d, "notify"),
                   CREDENTIALS_DIRECTORY=str(creds))
        proc = subprocess.Popen(
            [sys.executable, str(BROKER), *args], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(proc.stderr.close)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        try:
            message = notify.recv(64)
        except TimeoutError:
            proc.kill()
            self.fail(f"no READY=1: {proc.stderr.read().decode()}")
        self.assertEqual(message, b"READY=1")
        with socket.create_connection((host, int(port)), timeout=5):
            pass


class TestTheProgramsAreMoatery(unittest.TestCase):

    def test_the_units_name_moatery_programs(self):
        """The generated units run moatery's programs by the path its RPM
        installs them at, and the spec requires that RPM."""
        from broker_config import BROKER_BIN
        from workload_addr import (
            INSPECT_LISTENER_BIN, RESOLVE_LISTENER_BIN)
        self.assertEqual(INSPECT_LISTENER_BIN,
                         "/usr/libexec/moatery/moat-inspect")
        self.assertEqual(RESOLVE_LISTENER_BIN,
                         "/usr/libexec/moatery/moat-resolve")
        self.assertEqual(BROKER_BIN, "/usr/libexec/moatery/moat-broker")

    def test_the_spec_requires_a_moatery_with_everything_used_here(self):
        """0.3.0 is the first release whose moat-resolve takes --static;
        0.4.0 is the first whose policy document names internal_expected;
        0.5.0 is the first whose broker sends READY=1, which its Type=notify
        unit waits for; 0.6.0 is the first named moatery, the package the
        units' paths and lib/'s imports name. A lower floor installs against an older moatery, and
        the responder then fails its start on an unrecognised flag (at the
        guest's first query), the inspector refuses the rendered document (at
        its start), or the broker's start times out."""
        spec = (Path(REPO_ROOT) / "rpm" / "workloadctl.spec").read_text()
        minimum = re.search(
            r"(?m)^Requires:\s+moatery >= (\S+)$", spec).group(1)
        self.assertGreaterEqual(
            tuple(int(part) for part in minimum.split(".")), (0, 6, 0))

    def test_seed_isos_carry_moatery(self):
        """A VM's seed ISO carries moatery's RPM beside workloadctl's, which
        its bootstrap cannot install alone."""
        from ensure_vm import BUNDLED_RPMS
        self.assertIn("moatery.rpm", BUNDLED_RPMS)


CONTAINERFILE = Path(REPO_ROOT).parent / "hypervisor.Containerfile"


@unittest.skipUnless(CONTAINERFILE.is_file(),
                     "image half not present (standalone workloadctl checkout)")
class TestTheImageInstallsMoatery(unittest.TestCase):

    def test_the_pinned_moatery_satisfies_the_spec(self):
        """The hypervisor image fetches moatery's RPM at the version its
        build pins, installs it in the stage that runs this suite and in the
        image, and caches it for VM seed ISOs. The pinned version satisfies
        the spec's minimum, or the image's `dnf install` refuses
        workloadctl."""
        spec = (Path(REPO_ROOT) / "rpm" / "workloadctl.spec").read_text()
        minimum = re.search(
            r"(?m)^Requires:\s+moatery >= (\S+)$", spec).group(1)
        containerfile = CONTAINERFILE.read_text()
        pinned = re.search(
            r"(?m)^ARG MOATERY_VERSION=(\S+)$", containerfile).group(1)

        def version(text):
            return tuple(int(part) for part in text.split("."))

        self.assertGreaterEqual(version(pinned), version(minimum))
        self.assertIn('/tmp/moatery-copr/fetch "${MOATERY_VERSION}" '
                      "/moatery.rpm", containerfile)
        self.assertEqual(containerfile.count(
            "COPY --from=moatery /moatery.rpm /tmp/moatery.rpm"), 2)
        self.assertIn("/usr/share/workloadctl/moatery.rpm", containerfile)

    def test_the_fetch_refuses_what_the_project_key_did_not_sign(self):
        """dnf download checks no signature, so the fetch's rpmkeys is the
        only check between Copr and the image. It reads the key committed
        beside it, and _pkgverify_level makes it refuse an unsigned package,
        which `rpmkeys -K` alone passes on its digests (both seen
        2026-10-06: a package signed by another key and an unsigned one,
        each served from a local repository, were refused)."""
        copr = CONTAINERFILE.parent / "moatery-copr"
        fetch = (copr / "fetch").read_text()
        self.assertTrue((copr / "pubkey.gpg").read_text().startswith(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        self.assertIn('/pubkey.gpg', fetch)
        self.assertIn("--define '_pkgverify_level signature' -K", fetch)
        self.assertIn('install -m 0644 "$1" "$dest"', fetch)

if __name__ == "__main__":
    unittest.main()
