#!/usr/bin/env python3
"""`workloadctl pcap` — the CLI layer over lib/pcap.py.

WHY THIS EXISTS

lib/pcap.py is pure and well covered; everything that *decides and executes*
lived in lib/cmd_pcap.py with no test that imported it. The module read 9% —
158 statements, 139 missed, and 0 partial branches out of 58, which is the
signature of code that never runs at all rather than code that runs one way.

What coverage there was (`TestDetachVerifies` in tests/test_pcap.py) reads
cmd_pcap.py as TEXT and asserts on substring order. That guards the three facts
it names and nothing else, and it cannot survive the file moving. These tests
execute the module instead.

THE ARGS COME FROM THE REAL PARSER

`cmd_pcap` reads every flag through `getattr(args, name, default)`, so a dest
renamed in bin/workloadctl does not raise — it silently takes the default and
the flag becomes inert. A hand-built Namespace cannot see that. `_args()` runs
the actual argparse parser out of `main()`, and `test_every_flag_cmd_pcap_reads_
is_a_real_dest` closes the loop from the other side.

WHAT IS NOT HERE

The real `systemd-run`, the nftables rule, the QEMU object and the foreground
`journalctl -f`. Those need a host and belong to the manual rigs; every
subprocess here is a fake, so what is proven is the decision, not the capture.
"""

import ast
import json
import unittest
import unittest.mock as mock
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import cli_log
import cmd_pcap
from cmd_pcap import (
    _helper_args, _list_captures, _report_vantages, _say, _settled,
    _start_capture, _stdout_is_claimed, _stop_capture, cmd_pcap as run,
)
from pcap import (
    DIRECTION_DEFAULT, DURATION_DEFAULT, MAX_SIZE_DEFAULT, PCAP_UNIT_PREFIX,
    build_plan, parse_duration, parse_size, parse_snaplen, pcap_unit_name,
)

from tests import load_script
from tests.test_pcap import container_config, vm_config

ROOT = Path(__file__).resolve().parent.parent


# --- the fixture ------------------------------------------------------------

_CLI = None


def _args(*argv):
    """A real argparse Namespace for `workloadctl pcap ...`.

    `set_defaults(func=cmd_pcap)` resolves the module global when main() runs,
    so patching it captures the parsed args without dispatching.
    """
    global _CLI
    if _CLI is None:
        _CLI = load_script("bin/workloadctl")
    captured = {}

    def capture(args, manager):
        captured["args"] = args

    with mock.patch.object(_CLI, "cmd_pcap", capture), \
            mock.patch.object(_CLI, "WorkloadManager", lambda: None), \
            mock.patch.object(_CLI.sys, "argv", ["workloadctl", "pcap", *argv]):
        _CLI.main()
    return captured["args"]


class FakeRun:
    """`subprocess.run` for the four commands cmd_pcap shells out to.

    `is_active` is consumed one reading per call and the last value repeats, so
    a test can say "active, then failed" without knowing how many times the
    dwell looks.
    """

    def __init__(self, is_active=("active",), systemd_run_rc=0, stop_rc=0,
                 list_out="", stderr="boom"):
        self.states = list(is_active)
        self.systemd_run_rc = systemd_run_rc
        self.stop_rc = stop_rc
        self.list_out = list_out
        self.stderr = stderr
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[:2] == ["systemctl", "is-active"]:
            state = self.states[0] if len(self.states) == 1 else self.states.pop(0)
            return SimpleNamespace(returncode=0, stdout=state + "\n", stderr="")
        if argv[:2] == ["systemctl", "stop"]:
            return SimpleNamespace(returncode=self.stop_rc, stdout="",
                                   stderr=self.stderr)
        if argv[0] == "systemctl":                      # list-units
            return SimpleNamespace(returncode=0, stdout=self.list_out, stderr="")
        if argv[0] == "systemd-run":
            return SimpleNamespace(returncode=self.systemd_run_rc, stdout="",
                                   stderr=self.stderr)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def ran(self, program):
        return [c for c in self.calls if c and c[0] == program]


class PcapTestCase(unittest.TestCase):
    """Captures both streams and neutralises root and the settle dwell.

    cli_log resolves sys.stderr at emit time, so redirect_stderr catches its
    diagnostics as well as bare prints.
    """

    def setUp(self):
        cli_log.configure(quiet=False, json_mode=False, command="pcap")
        self.out, self.err = StringIO(), StringIO()
        for patcher in (
            mock.patch.object(cmd_pcap, "require_root", lambda: None),
            # Whether tcpdump is on the machine running the tests must not
            # decide whether the host vantage validates.
            mock.patch("pcap.shutil.which", return_value="/usr/bin/tcpdump"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def call(self, func, *args, **kwargs):
        with redirect_stdout(self.out), redirect_stderr(self.err):
            return func(*args, **kwargs)

    @property
    def stdout(self):
        return self.out.getvalue()

    @property
    def stderr(self):
        return self.err.getvalue()


# --- the parser contract ----------------------------------------------------

class TestArgsAreTheParsersOwn(PcapTestCase):

    def test_the_bare_form_defaults_to_nothing_selected(self):
        args = _args("fj")
        self.assertEqual(args.workload, "fj")
        self.assertIsNone(args.interface)
        self.assertFalse(args.list or args.stop or args.list_interfaces)

    def test_the_short_flags_land_where_cmd_pcap_reads_them(self):
        args = _args("-i", "guest", "-Q", "in", "-s", "128", "-w", "/tmp/a.pcapng",
                     "-c", "10", "-C", "1", "-W", "2", "-G", "3", "-n", "fj")
        self.assertEqual(args.interface, ["guest"])
        self.assertEqual(args.direction, "in")
        self.assertEqual(args.snapshot_length, "128")
        self.assertEqual(args.write, "/tmp/a.pcapng")
        self.assertEqual((args.packet_count, args.rotate_size,
                          args.file_count, args.rotate_seconds), (10, 1, 2, 3))
        self.assertTrue(args.numeric)

    def test_the_filter_is_taken_verbatim(self):
        self.assertEqual(_args("fj", "port", "443").filter, ["port", "443"])

    def test_every_flag_cmd_pcap_reads_is_a_real_dest(self):
        """The other half of the getattr default.

        A flag cmd_pcap reads under a name the parser does not define is not an
        error at any point: it takes the default forever, so `-Q in` or `-n`
        would be accepted and ignored. Derived from the source so it covers the
        NEXT flag, not the ones that exist today.
        """
        source = (ROOT / "lib" / "cmd_pcap.py").read_text()
        read, assigned = set(), set()
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "getattr"
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id == "args"
                    and isinstance(node.args[1], ast.Constant)):
                read.add(node.args[1].value)
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and node.value.id == "args"):
                (assigned if isinstance(node.ctx, ast.Store) else read).add(node.attr)
        namespace = vars(_args("fj"))
        missing = sorted(read - assigned - set(namespace))
        self.assertEqual(missing, [],
                         f"cmd_pcap reads args attributes the pcap parser does "
                         f"not define, so they are permanently their default: "
                         f"{missing}")


# --- the prose channel ------------------------------------------------------

class TestStdoutIsClaimed(PcapTestCase):
    """Whatever binds stdout pushes prose to stderr — and `-w -` binds it
    exactly as `--json` does."""

    def test_plain_run_owns_stdout(self):
        self.assertFalse(_stdout_is_claimed(_args("fj")))

    def test_json_claims_it(self):
        self.assertTrue(_stdout_is_claimed(_args("--json", "-w", "/tmp/a", "fj")))

    def test_a_file_does_not_claim_it(self):
        self.assertFalse(_stdout_is_claimed(_args("-w", "/tmp/a.pcapng", "fj")))

    def test_dash_claims_it(self):
        self.assertTrue(_stdout_is_claimed(_args("-w", "-", "fj")))

    def test_say_follows_the_claim(self):
        self.call(_say, _args("fj"), "hello")
        self.assertIn("hello", self.stdout)
        self.assertNotIn("hello", self.stderr)

    def test_say_steps_aside_when_stdout_is_claimed(self):
        self.call(_say, _args("-w", "-", "fj"), "hello")
        self.assertEqual(self.stdout, "")
        self.assertIn("hello", self.stderr)

    def test_quiet_silences_prose_on_both_streams(self):
        self.call(_say, _args("-q", "fj"), "hello")
        self.assertEqual((self.stdout, self.stderr), ("", ""))


# --- dispatch ---------------------------------------------------------------

class TestDispatch(PcapTestCase):

    def test_list_answers_without_loading_a_config(self):
        """`--list` takes no workload, so reaching the loader at all would be
        the bug."""
        def explode(*a, **k):
            raise AssertionError("loaded a config for --list")
        with mock.patch.object(cmd_pcap, "load_config_or_exit", explode), \
                mock.patch("cmd_pcap.subprocess.run", FakeRun()):
            self.assertEqual(self.call(run, _args("--list"), None), 0)

    def test_a_missing_workload_is_a_usage_error(self):
        self.assertEqual(self.call(run, _args(), None), 2)
        self.assertIn("--list", self.stderr)

    def test_D_reports_vantages(self):
        config = vm_config()
        with mock.patch.object(cmd_pcap, "load_config_or_exit",
                               return_value=config):
            self.assertEqual(self.call(run, _args("-D", "fj"), None), 0)
        self.assertIn("Vantages for 'fj'", self.stdout)

    def test_stop_routes_to_stop(self):
        fake = FakeRun()
        with mock.patch.object(cmd_pcap, "load_config_or_exit",
                               return_value=vm_config()), \
                mock.patch("cmd_pcap.subprocess.run", fake):
            self.assertEqual(self.call(run, _args("--stop", "fj"), None), 0)
        self.assertEqual(fake.ran("systemctl")[0][:2], ["systemctl", "stop"])

    def test_a_container_is_split_off_the_workload_name(self):
        """Accepting `<workload>/<container>` and passing the whole string to
        the loader would look up a workload that cannot exist."""
        seen = {}

        def loader(name, json_mode=False):
            seen["name"] = name
            return container_config(name="web", containers=["a", "b"],
                                    topology="bridge")
        with mock.patch.object(cmd_pcap, "load_config_or_exit", loader):
            self.call(run, _args("-D", "web/a"), None)
        self.assertEqual(seen["name"], "web")

    def test_a_bare_workload_leaves_the_container_unset(self):
        args = _args("-D", "fj")
        with mock.patch.object(cmd_pcap, "load_config_or_exit",
                               return_value=vm_config()):
            self.call(run, args, None)
        self.assertIsNone(args.container)


# --- reporting --------------------------------------------------------------

class TestReportVantages(PcapTestCase):

    def test_an_unavailable_vantage_is_listed_with_its_reason(self):
        """Omitting it would read as "there is no such vantage" rather than
        "here is why you cannot have it"."""
        self.call(_report_vantages, _args("-D", "fj"), vm_config(bridge="br0"))
        self.assertIn("✗ host", self.stdout)
        self.assertIn("✓ guest", self.stdout)
        self.assertIn("bridge", self.stdout)

    def test_limits_are_named_only_for_a_vantage_you_can_use(self):
        self.call(_report_vantages, _args("-D", "fj"), vm_config())
        self.assertIn("takes no BPF filter", self.stdout)

    def test_json_carries_every_capability(self):
        self.call(_report_vantages, _args("-D", "--json", "-w", "/tmp/a", "fj"),
                  vm_config())
        doc = json.loads(self.stdout)
        self.assertEqual(doc["workload"], "fj")
        self.assertEqual({v["name"] for v in doc["vantages"]}, {"host", "guest"})
        for vantage in doc["vantages"]:
            self.assertEqual(
                set(vantage), {"name", "available", "detail", "supports_filter",
                               "supports_direction", "supports_rotation"})


class TestListCaptures(PcapTestCase):

    UNITS = (f"{PCAP_UNIT_PREFIX}fj.service loaded active running Capture\n"
             f"{PCAP_UNIT_PREFIX}web.service loaded active running Capture\n")

    def test_the_unit_name_is_the_first_field(self):
        with mock.patch("cmd_pcap.subprocess.run",
                        FakeRun(list_out=self.UNITS)) as _:
            self.assertEqual(self.call(_list_captures, _args("--list")), 0)
        self.assertIn("fj", self.stdout)
        self.assertIn(f"{PCAP_UNIT_PREFIX}web.service", self.stdout)

    def test_the_workload_name_is_recovered_from_the_unit(self):
        with mock.patch("cmd_pcap.subprocess.run", FakeRun(list_out=self.UNITS)):
            self.call(_list_captures, _args("--list"))
        line = [l for l in self.stdout.splitlines() if "fj" in l][0]
        self.assertTrue(line.strip().startswith("fj"), line)

    def test_nothing_running_says_so_rather_than_printing_a_header(self):
        with mock.patch("cmd_pcap.subprocess.run", FakeRun(list_out="\n")):
            self.assertEqual(self.call(_list_captures, _args("--list")), 0)
        self.assertIn("No captures running", self.stdout)

    def test_json_is_a_list_of_units(self):
        args = _args("--list", "--json", "-w", "/tmp/a", "fj")
        with mock.patch("cmd_pcap.subprocess.run", FakeRun(list_out=self.UNITS)):
            self.call(_list_captures, args)
        self.assertEqual(json.loads(self.stdout)["captures"],
                         [f"{PCAP_UNIT_PREFIX}fj.service",
                          f"{PCAP_UNIT_PREFIX}web.service"])

    def test_json_says_empty_rather_than_omitting_the_key(self):
        args = _args("--list", "--json", "-w", "/tmp/a", "fj")
        with mock.patch("cmd_pcap.subprocess.run", FakeRun(list_out="")):
            self.call(_list_captures, args)
        self.assertEqual(json.loads(self.stdout), {"captures": []})


class TestStopCapture(PcapTestCase):

    def test_a_stop_names_what_teardown_removed(self):
        with mock.patch("cmd_pcap.subprocess.run", FakeRun()):
            self.assertEqual(
                self.call(_stop_capture, _args("--stop", "fj"), vm_config()), 0)
        self.assertIn(pcap_unit_name("fj"), self.stdout)
        self.assertIn("ExecStopPost", self.stdout)

    def test_a_failed_stop_is_reported_with_systemd_own_words(self):
        fake = FakeRun(stop_rc=1, stderr="Unit not loaded.")
        with mock.patch("cmd_pcap.subprocess.run", fake):
            self.assertEqual(
                self.call(_stop_capture, _args("--stop", "fj"), vm_config()), 1)
        self.assertIn("Unit not loaded.", self.stderr)


# --- starting ---------------------------------------------------------------

class TestStartRefusals(PcapTestCase):
    """Everything that must be refused BEFORE anything is started."""

    def test_an_unparseable_bound_is_a_usage_error(self):
        rc = self.call(_start_capture, _args("--duration", "5 fortnights", "fj"),
                       vm_config())
        self.assertEqual(rc, 2)

    def test_an_incoherent_request_lists_the_vantages_that_exist(self):
        """The error says what is wrong; without this the operator has to guess
        what would have been right."""
        rc = self.call(_start_capture, _args("-i", "wire", "fj"), vm_config())
        self.assertEqual(rc, 2)
        self.assertIn("available vantages", self.stderr)
        self.assertIn("host", self.stderr)

    def test_a_second_capture_is_refused_and_starts_nothing(self):
        """The unit name is per-workload, so a second invocation collides — and
        it is almost always a forgotten first one."""
        fake = FakeRun(is_active=("active",))
        with mock.patch("cmd_pcap.subprocess.run", fake):
            rc = self.call(_start_capture, _args("fj"), vm_config())
        self.assertEqual(rc, 1)
        self.assertIn("already being captured", self.stderr)
        self.assertEqual(fake.ran("systemd-run"), [])

    def test_the_plan_is_not_narrated_for_a_capture_that_will_not_happen(self):
        with mock.patch("cmd_pcap.subprocess.run", FakeRun(is_active=("active",))):
            self.call(_start_capture, _args("fj"), vm_config())
        self.assertNotIn("nflog", self.stdout)


class TestDryRun(PcapTestCase):

    def test_a_dry_run_changes_nothing_and_needs_no_root(self):
        def explode():
            raise AssertionError("--dry-run asked for root")
        with mock.patch.object(cmd_pcap, "require_root", explode), \
                mock.patch("cmd_pcap.subprocess.run") as runner:
            rc = self.call(_start_capture, _args("--dry-run", "fj"), vm_config())
        self.assertEqual(rc, 0)
        runner.assert_not_called()
        self.assertIn("Nothing was changed", self.stdout)

    def test_the_dry_run_plan_is_the_plan(self):
        """§6.6's contract: what was printed is what runs. A renderer of its
        own would let the two drift with nothing failing."""
        config = vm_config()
        args = _args("--dry-run", "--json", "-w", "/tmp/fj.pcapng", "fj")
        with mock.patch("cmd_pcap.subprocess.run"):
            self.call(_start_capture, args, config)
        expected = build_plan(
            config, vantages=["host"],
            snaplen=parse_snaplen(None, ["host"]), direction=DIRECTION_DEFAULT,
            write="/tmp/fj.pcapng", duration=parse_duration(DURATION_DEFAULT),
            max_size=parse_size(MAX_SIZE_DEFAULT), bpf=[], container=None)
        doc = json.loads(self.stdout)
        self.assertEqual(doc["result"], "dry-run")
        self.assertEqual(doc["plan"], expected.to_json())

    def test_a_repeated_vantage_is_not_captured_twice(self):
        args = _args("--dry-run", "--json", "-i", "host", "-i", "host",
                     "-w", "/tmp/fj.pcapng", "fj")
        with mock.patch("cmd_pcap.subprocess.run"):
            self.call(_start_capture, args, vm_config())
        self.assertEqual(json.loads(self.stdout)["plan"]["vantages"], ["host"])


class TestStartOutcomes(PcapTestCase):

    def setUp(self):
        super().setUp()
        # The dwell has its own tests; here it is only in the way.
        patcher = mock.patch.object(cmd_pcap, "_settled", return_value=True)
        self.settled = patcher.start()
        self.addCleanup(patcher.stop)

    def _start(self, *argv, fake=None):
        fake = fake or FakeRun(is_active=("inactive",))
        with mock.patch("cmd_pcap.subprocess.run", fake):
            rc = self.call(_start_capture, _args(*argv), vm_config())
        return rc, fake

    def test_a_refused_unit_is_a_failure_not_a_silent_success(self):
        rc, _ = self._start("fj", fake=FakeRun(is_active=("inactive",),
                                               systemd_run_rc=1,
                                               stderr="Unit already exists."))
        self.assertEqual(rc, 1)
        self.assertIn("Unit already exists.", self.stderr)

    def test_a_unit_that_does_not_stay_running_is_a_failure(self):
        """Detached, a rejected object-add happens after this command would
        have exited 0 — so the reading that matters is the late one."""
        self.settled.return_value = False
        rc, _ = self._start("--detach", "-w", "/tmp/fj.pcapng", "fj")
        self.assertEqual(rc, 1)
        self.assertIn("journalctl", self.stderr)

    def test_detach_returns_after_confirming_and_names_the_stop(self):
        rc, fake = self._start("--detach", "-w", "/tmp/fj.pcapng", "fj")
        self.assertEqual(rc, 0)
        self.assertTrue(self.settled.called)
        self.assertIn("pcap --stop fj", self.stdout)
        self.assertEqual(fake.ran("journalctl"), [])

    def test_detached_json_is_the_result_object(self):
        rc, _ = self._start("--detach", "--json", "-w", "/tmp/fj.pcapng", "fj")
        self.assertEqual(rc, 0)
        doc = json.loads(self.stdout)
        self.assertEqual(doc["result"], "started")
        self.assertEqual(doc["unit"], pcap_unit_name("fj"))
        self.assertIn("plan", doc)

    def test_the_foreground_follows_the_unit_and_stops_it_on_the_way_out(self):
        """Foreground is this command *following* the unit, not running the
        capture — so leaving it running would outlive the session that asked."""
        rc, fake = self._start("fj")
        self.assertEqual(rc, 0)
        self.assertEqual(fake.ran("journalctl")[0][:3],
                         ["journalctl", "-u", pcap_unit_name("fj")])
        self.assertEqual([c for c in fake.calls
                          if c[:2] == ["systemctl", "stop"]][-1][2],
                         pcap_unit_name("fj"))

    def test_ctrl_c_stops_the_capture_rather_than_leaving_it_behind(self):
        fake = FakeRun(is_active=("inactive",))
        real = fake.__call__

        def interrupt(argv, **kwargs):
            if argv and argv[0] == "journalctl":
                fake.calls.append(list(argv))
                raise KeyboardInterrupt
            return real(argv, **kwargs)
        with mock.patch("cmd_pcap.subprocess.run", interrupt):
            rc = self.call(_start_capture, _args("fj"), vm_config())
        self.assertEqual(rc, 0)
        self.assertTrue([c for c in fake.calls if c[:2] == ["systemctl", "stop"]])


class TestHelperArgs(PcapTestCase):
    """The plan travels as JSON. The helper re-deriving it from the config
    would let what was printed and what runs disagree."""

    def _payload(self, *argv):
        config = vm_config()
        args = _args(*argv)
        plan = build_plan(config, vantages=["host"],
                          snaplen=parse_snaplen(None, ["host"]),
                          direction=DIRECTION_DEFAULT, write=None,
                          duration=parse_duration(DURATION_DEFAULT),
                          max_size=parse_size(MAX_SIZE_DEFAULT))
        verb, name, blob = _helper_args(config, plan, args,
                                        list(args.filter or []))
        self.assertEqual((verb, name), ("run", "fj"))
        return plan, json.loads(blob)

    def test_the_plan_travels_whole(self):
        plan, payload = self._payload("fj")
        for key, value in plan.to_json().items():
            self.assertEqual(payload[key], value, key)

    def test_the_tcpdump_only_options_ride_along(self):
        """None of these is in the plan — the helper is the only thing that
        can act on them, so dropping one is silent."""
        _, payload = self._payload("-n", "-c", "10", "-C", "1", "-W", "2",
                                   "-G", "3", "fj", "port", "443")
        self.assertEqual(payload["numeric"], True)
        self.assertEqual(payload["packet_count"], 10)
        self.assertEqual(payload["rotate_size"], 1)
        self.assertEqual(payload["file_count"], 2)
        self.assertEqual(payload["rotate_seconds"], 3)
        self.assertEqual(payload["bpf"], ["port", "443"])

    def test_the_keys_are_present_when_unset_rather_than_absent(self):
        """Absent and null are different facts to the helper's reader."""
        _, payload = self._payload("fj")
        for key in ("bpf", "numeric", "packet_count", "rotate_size",
                    "file_count", "rotate_seconds"):
            self.assertIn(key, payload)


class TestSettled(PcapTestCase):
    """Type=exec marks a unit active the moment the exec succeeds, so a helper
    that dies a moment later is observably active first. Found on the bench,
    where a refused object-add was reported as "Capturing in the background"."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch("time.sleep")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_unit_that_fails_during_the_dwell_is_not_settled(self):
        """The whole point: the FIRST reading is 'active' and it is wrong."""
        fake = FakeRun(is_active=("active", "active", "failed"))
        with mock.patch("cmd_pcap.subprocess.run", fake):
            self.assertFalse(_settled("u.service", settle=0.05))
        self.assertGreaterEqual(len(fake.ran("systemctl")), 3)

    def test_a_unit_that_exits_cleanly_during_the_dwell_is_not_settled(self):
        with mock.patch("cmd_pcap.subprocess.run",
                        FakeRun(is_active=("active", "inactive"))):
            self.assertFalse(_settled("u.service", settle=0.05))

    def test_a_unit_still_running_after_the_dwell_is_settled(self):
        with mock.patch("cmd_pcap.subprocess.run", FakeRun(is_active=("active",))):
            self.assertTrue(_settled("u.service", settle=0.05))

    def test_the_dwell_does_not_return_on_the_first_active_reading(self):
        fake = FakeRun(is_active=("active",))
        with mock.patch("cmd_pcap.subprocess.run", fake):
            _settled("u.service", settle=0.05)
        self.assertGreater(len(fake.ran("systemctl")), 1,
                           "returned on the first reading, which is the "
                           "reading that is wrong")


if __name__ == "__main__":
    unittest.main()
