#!/usr/bin/env python3
"""Q6 Gap 1 — host-global artifacts a workload's setup.sh installs.

`workload_run_files()` says in its own docstring that it never includes shared
infra or anything outside the generator's output, and every diagnostic verb is
built on it. So a `setup.sh` sidecar is invisible: on onepiece,
`games-udev-relay.service` restart-looped 2012 times in seven days while
`systemctl list-units --failed` stayed clean and `doctor` reported the workload
healthy.

The fix asks the script — a third, read-only action — rather than inferring the
set from the host or duplicating it in TOML. These tests cover both halves:

  * `provisioning.host_setup_artifacts()` — the three answers (undeclared /
    declares-nothing / declares-a-set), instance-vs-bundle naming, and the
    failure modes that must not be mistaken for any of them.
  * `cmd_diagnose.host_artifact_check()` + `collect_host_artifact_checks()` —
    the verdicts, including the restart-loop case that is the whole point.

Plus one guard over the shipped bundles: every setup.sh we ship answers the
action, so the four conversions can't silently regress to "undeclared".
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cmd_diagnose
import provisioning
import workload_lib
import workloadctl_core
from provisioning import (
    HostArtifact,
    HostArtifacts,
    host_setup_artifacts,
    _parse_host_artifacts,
)
from cmd_diagnose import collect_host_artifact_checks, host_artifact_check

from tests import REPO_ROOT

_TOML = """\
[workload]
name = "{name}"

[container]
image = "example.com/test:latest"
pull = "never"

[host]
setup = "setup.sh"
"""

_TOML_NO_HOST = """\
[workload]
name = "{name}"

[container]
image = "example.com/test:latest"
pull = "never"
"""


class _Bundle:
    """A workload dir with a real, executable setup.sh.

    Runs the script for real rather than mocking subprocess: the contract being
    tested is a *shell* one — what a nonzero exit means, what stdout is parsed
    as — and a mock would let a script that can't actually run pass.
    """

    def __init__(self, script: str | None, name: str = "test-wl",
                 toml: str = _TOML, enabled: bool = True):
        self._script = script
        self._name = name
        self._toml = toml
        self._enabled = enabled

    def __enter__(self):
        self._tmp = tempfile.mkdtemp()
        d = Path(self._tmp) / self._name
        d.mkdir()
        (d / "workload.toml").write_text(self._toml.format(name=self._name))
        if self._enabled:
            (d / workload_lib.ENABLED_MARKER_NAME).write_text("")
        if self._script is not None:
            path = d / "setup.sh"
            path.write_text(self._script)
            path.chmod(0o755)
        self._patcher = patch.object(
            workload_lib, "WORKLOAD_CONFIG_DIR", Path(self._tmp))
        self._patcher.start()
        return workloadctl_core.WorkloadConfig(self._name)

    def __exit__(self, *_):
        self._patcher.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)


_DISPATCH = """\
#!/bin/bash
set -euo pipefail
case "${1:-}" in
    artifacts) %s ;;
    *) echo "Usage: $0 {enable|disable}" >&2; exit 1 ;;
esac
"""


def _script(body: str) -> str:
    return _DISPATCH % body


# ── the three answers ───────────────────────────────────────────────────────

class HostSetupArtifactsTest(unittest.TestCase):
    def test_no_host_setup_configured_returns_none(self):
        """Nothing to ask is not the same as an empty answer — a workload with
        no [host] section must not produce a check at all."""
        with _Bundle(None, toml=_TOML_NO_HOST) as cfg:
            self.assertIsNone(host_setup_artifacts(cfg))

    def test_configured_but_absent_script_returns_none(self):
        """The enable path already warns about a missing script; reporting it
        here too would count one fault twice."""
        with _Bundle(None) as cfg:
            self.assertIsNone(host_setup_artifacts(cfg))

    def test_nonzero_exit_is_undeclared_not_empty(self):
        """An older bundle falls through its own dispatch `*)` arm. That has to
        read as *unknown*, because rendering it as "installs nothing" would
        quietly promise the sidecars are checked when they aren't."""
        script = "#!/bin/bash\necho 'Usage: enable|disable' >&2\nexit 1\n"
        with _Bundle(script) as cfg:
            result = host_setup_artifacts(cfg)
        self.assertEqual(result, HostArtifacts(False, [], [], None))

    def test_exit_zero_with_no_output_declares_nothing(self):
        """Distinct from the above: jellyfin implements the action and owns no
        host artifacts (its only host effect is a shared SELinux boolean)."""
        with _Bundle(_script("true")) as cfg:
            result = host_setup_artifacts(cfg)
        self.assertEqual(result.supported, True)
        self.assertEqual(result.artifacts, [])
        self.assertIsNone(result.error)

    def test_declared_set_is_parsed(self):
        body = ('printf "unit foo.service\\nfile /etc/avahi/services/foo.xml\\n"')
        with _Bundle(_script(body)) as cfg:
            result = host_setup_artifacts(cfg)
        self.assertEqual(result.artifacts, [
            HostArtifact("unit", "foo.service"),
            HostArtifact("file", "/etc/avahi/services/foo.xml"),
        ])
        self.assertEqual(result.unparsed, [])

    def test_timeout_is_an_error_not_an_answer(self):
        """A hung script must not stall a read verb, and must not be filed as
        either "undeclared" or "nothing" — both would be a silent pass."""
        with _Bundle(_script("sleep 30")) as cfg:
            with patch.object(provisioning, "HOST_SETUP_ARTIFACTS_TIMEOUT", 1):
                result = host_setup_artifacts(cfg)
        self.assertFalse(result.supported)
        self.assertIn("did not answer", result.error)

    def test_action_name_is_what_the_script_receives(self):
        """Echoes $1 back as a declaration, so the assertion is on the real
        argv rather than on a mock's recorded call."""
        with _Bundle(_script('echo "file /$1"')) as cfg:
            result = host_setup_artifacts(cfg)
        self.assertEqual(
            result.artifacts,
            [HostArtifact("file", "/" + provisioning.HOST_SETUP_ARTIFACTS_ACTION)])

    def test_env_carries_the_instance_name_not_the_bundle(self):
        """The reason host_setup_env() exists, applied to the read path: an
        `init --as` instance named `games` must declare `games-udev-relay`, not
        `sunshine-streaming-udev-relay`. Declaring the bundle's name would
        report a healthy sidecar as missing and hide the real one — the same
        class of bug one layer up from the one this closes."""
        with _Bundle(_script('echo "unit ${WORKLOAD_NAME}-udev-relay.service"'),
                     name="games") as cfg:
            result = host_setup_artifacts(cfg)
        self.assertEqual(result.artifacts,
                         [HostArtifact("unit", "games-udev-relay.service")])

    def test_the_read_action_never_raises_lifecycle_error(self):
        """run_host_setup raises on a nonzero enable so the CLI stops before
        starting a service whose prerequisites are absent. The read path shares
        the script but not that contract — doctor must survive anything."""
        with _Bundle("#!/bin/bash\nexit 7\n") as cfg:
            result = host_setup_artifacts(cfg)   # must not raise
        self.assertFalse(result.supported)


# ── parsing ─────────────────────────────────────────────────────────────────

class ParseHostArtifactsTest(unittest.TestCase):
    def test_blank_lines_and_comments_are_skipped(self):
        artifacts, unparsed = _parse_host_artifacts(
            "\n# a comment\nunit a.service\n\n")
        self.assertEqual(artifacts, [HostArtifact("unit", "a.service")])
        self.assertEqual(unparsed, [])

    def test_extra_whitespace_between_kind_and_ref(self):
        artifacts, _ = _parse_host_artifacts("file    /etc/x.conf")
        self.assertEqual(artifacts, [HostArtifact("file", "/etc/x.conf")])

    def test_a_ref_may_contain_spaces(self):
        """Split on the first field only: a path with a space is legal, and
        losing its tail would check the wrong file."""
        artifacts, _ = _parse_host_artifacts("file /etc/a b/c.conf")
        self.assertEqual(artifacts, [HostArtifact("file", "/etc/a b/c.conf")])

    def test_unknown_kind_is_reported_not_dropped(self):
        """A typo'd kind silently ignored would erase an artifact from the
        checked set — reintroducing the invisibility this exists to end."""
        artifacts, unparsed = _parse_host_artifacts(
            "unti a.service\nunit b.service")
        self.assertEqual(artifacts, [HostArtifact("unit", "b.service")])
        self.assertEqual(unparsed, ["unti a.service"])

    def test_progress_chatter_is_reported_not_dropped(self):
        artifacts, unparsed = _parse_host_artifacts(
            "  [host] Installing relay...\nunit a.service")
        self.assertEqual(artifacts, [HostArtifact("unit", "a.service")])
        self.assertEqual(unparsed, ["[host] Installing relay..."])

    def test_kind_with_no_ref_is_unparsed(self):
        artifacts, unparsed = _parse_host_artifacts("unit\nfile   ")
        self.assertEqual(artifacts, [])
        self.assertEqual(unparsed, ["unit", "file"])


# ── verdicts ────────────────────────────────────────────────────────────────

_UNIT = HostArtifact("unit", "games-udev-relay.service")
_FILE = HostArtifact("file", "/etc/avahi/services/games-sunshine.service")


class HostArtifactCheckTest(unittest.TestCase):
    def test_active_unit_passes(self):
        passed, message, fix = host_artifact_check(
            _UNIT, {"ActiveState": "active", "SubState": "running",
                    "NRestarts": "0"}, "games")
        self.assertTrue(passed)
        self.assertIn("active", message)
        self.assertIsNone(fix)

    def test_restart_looping_unit_fails_even_while_active(self):
        """The onepiece case. The unit was `active` at every sampling — a unit
        that is restarted on failure never settles into `failed`, which is why
        `list-units --failed` was clean for seven days."""
        passed, message, fix = host_artifact_check(
            _UNIT, {"ActiveState": "active", "SubState": "running",
                    "NRestarts": "2012"}, "games")
        self.assertFalse(passed)
        self.assertIn("2012", message)
        self.assertIn("restart-looping", message)
        self.assertIn("journalctl", fix)

    def test_absent_unit_fails_and_points_at_enable(self):
        passed, message, fix = host_artifact_check(_UNIT, None, "games")
        self.assertFalse(passed)
        self.assertIn("not installed", message)
        self.assertIn("workloadctl enable games", fix)

    def test_failed_unit_fails_with_its_result(self):
        passed, message, _ = host_artifact_check(
            _UNIT, {"ActiveState": "failed", "SubState": "failed",
                    "Result": "exit-code", "NRestarts": "0"}, "games")
        self.assertFalse(passed)
        self.assertIn("exit-code", message)

    def test_activating_unit_fails(self):
        """Stuck mid-start is not healthy, and is what a flapping unit looks
        like when sampled between restarts."""
        passed, _, _ = host_artifact_check(
            _UNIT, {"ActiveState": "activating", "SubState": "start",
                    "NRestarts": "0"}, "games")
        self.assertFalse(passed)

    def test_unparseable_nrestarts_does_not_crash_the_check(self):
        passed, _, _ = host_artifact_check(
            _UNIT, {"ActiveState": "active", "NRestarts": ""}, "games")
        self.assertTrue(passed)

    def test_present_file_passes_and_missing_file_fails(self):
        passed, _, _ = host_artifact_check(_FILE, True, "games")
        self.assertTrue(passed)
        passed, message, fix = host_artifact_check(_FILE, False, "games")
        self.assertFalse(passed)
        self.assertIn(_FILE.ref, message)
        self.assertIn("workloadctl enable games", fix)


# ── the diagnose battery ────────────────────────────────────────────────────

class CollectHostArtifactChecksTest(unittest.TestCase):
    def _collect(self, cfg):
        checks = []

        def _check(name, passed, message, fix=None):
            entry = {"check": name, "passed": passed, "message": message}
            if fix:
                entry["fix"] = fix
            checks.append(entry)

        collect_host_artifact_checks(cfg, _check)
        return checks

    def test_disabled_workload_is_not_checked(self):
        """disable() removes these, so a disabled workload is *supposed* to be
        missing them — checking would report every disabled workload broken."""
        with _Bundle(_script('echo "unit nope.service"'), enabled=False) as cfg:
            self.assertEqual(self._collect(cfg), [])

    def test_no_host_section_produces_no_checks(self):
        with _Bundle(None, toml=_TOML_NO_HOST) as cfg:
            self.assertEqual(self._collect(cfg), [])

    def test_undeclared_is_a_pass_that_still_says_so(self):
        """An un-updated bundle is not a fault of the host being diagnosed, so
        it must not fail — but it must be visible, or the operator reads a
        green report as "the sidecars are fine"."""
        with _Bundle("#!/bin/bash\nexit 1\n") as cfg:
            checks = self._collect(cfg)
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0]["passed"])
        self.assertIn("undeclared", checks[0]["message"])

    def test_declares_nothing_is_a_pass_that_says_nothing_to_check(self):
        with _Bundle(_script("true")) as cfg:
            checks = self._collect(cfg)
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0]["passed"])
        self.assertIn("no host-global artifacts", checks[0]["message"])

    def test_missing_declared_file_fails(self):
        with _Bundle(_script('echo "file /nonexistent/x.conf"')) as cfg:
            checks = self._collect(cfg)
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0]["passed"])
        self.assertIn("/nonexistent/x.conf", checks[0]["message"])

    def test_present_declared_file_passes(self):
        with tempfile.NamedTemporaryFile() as tf:
            with _Bundle(_script(f'echo "file {tf.name}"')) as cfg:
                checks = self._collect(cfg)
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0]["passed"])

    def test_declared_unit_is_probed_by_name(self):
        with _Bundle(_script('echo "unit games-udev-relay.service"')) as cfg:
            with patch.object(cmd_diagnose, "_unit_props",
                              return_value=None) as props:
                checks = self._collect(cfg)
        props.assert_called_once_with("games-udev-relay.service")
        self.assertFalse(checks[0]["passed"])
        self.assertEqual(checks[0]["check"],
                         "host_artifact[games-udev-relay.service]")

    def test_unparsed_output_fails_alongside_the_artifacts_it_did_parse(self):
        body = 'printf "chatter\\nfile /nonexistent/x.conf\\n"'
        with _Bundle(_script(body)) as cfg:
            checks = self._collect(cfg)
        self.assertEqual(len(checks), 2)
        self.assertFalse(checks[0]["passed"])
        self.assertIn("not a declaration", checks[0]["message"])

    def test_a_script_that_cannot_be_asked_is_a_failing_check(self):
        with _Bundle(_script("sleep 30")) as cfg:
            with patch.object(provisioning, "HOST_SETUP_ARTIFACTS_TIMEOUT", 1):
                checks = self._collect(cfg)
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0]["passed"])


# ── the shared bridge (the other half of the same blind spot) ───────────────

_VM_TOML = """\
[workload]
name = "{name}"

[vm]
memory = "2G"
vcpus = 2
"""

_VM_OWN_BRIDGE_TOML = """\
[workload]
name = "{name}"

[vm]
memory = "2G"
vcpus = 2

[vm.network]
bridge = "br0"
"""


class SharedBridgeCheckTest(unittest.TestCase):
    def test_active_bridge_passes(self):
        passed, message, fix = cmd_diagnose.shared_bridge_check(
            {"ActiveState": "active", "SubState": "exited"}, "forgejo")
        self.assertTrue(passed)
        self.assertIsNone(fix)

    def test_failed_bridge_fails_and_says_why_it_matters(self):
        """tp's actual symptom: five failed starts, and no verb mentioned it.
        The message has to connect the unit to the consequence, or an operator
        looking at a VM with no network won't recognise this line as the cause."""
        passed, message, fix = cmd_diagnose.shared_bridge_check(
            {"ActiveState": "failed", "Result": "exit-code"}, "forgejo")
        self.assertFalse(passed)
        self.assertIn("exit-code", message)
        self.assertIn("network path", message)
        self.assertIn("journalctl", fix)

    def test_absent_bridge_unit_fails(self):
        passed, message, fix = cmd_diagnose.shared_bridge_check(None, "forgejo")
        self.assertFalse(passed)
        self.assertIn("not installed", message)
        self.assertIn("workloadctl enable forgejo", fix)


class SharedBridgeWiringTest(unittest.TestCase):
    """The gate: which workloads get the check at all."""

    def _checks(self, toml, enabled=True):
        # The battery runs end to end, so the checks past the one under test
        # still shell out to systemctl — which does not exist in the RPM build
        # container the test suite also runs in. Stub the two doors to it: a
        # non-zero `subprocess.run` and an inactive `service_active` are both
        # answers this test discards, and neither can make a shared_bridge
        # check appear or vanish.
        completed = subprocess.CompletedProcess([], 1, stdout="", stderr="")
        with _Bundle(None, name="forgejo", toml=toml, enabled=enabled) as cfg:
            with patch.object(cmd_diagnose, "_unit_props",
                              return_value={"ActiveState": "active"}), \
                 patch.object(cmd_diagnose, "collect_host_artifact_checks"), \
                 patch.object(cmd_diagnose, "service_active",
                              return_value=(False, "inactive")), \
                 patch.object(cmd_diagnose.subprocess, "run",
                              return_value=completed):
                checks, _ = cmd_diagnose.collect_diagnose_checks(
                    cfg, _StubManager())
        return [c for c in checks if c["check"] == "shared_bridge"]

    def test_managed_bridge_vm_is_checked(self):
        self.assertEqual(len(self._checks(_VM_TOML)), 1)

    def test_vm_on_a_user_provided_bridge_is_not_checked(self):
        """The generator deliberately doesn't emit workload-bridge.service for
        a VM bridged onto br0, so requiring it would fail a correct host."""
        self.assertEqual(self._checks(_VM_OWN_BRIDGE_TOML), [])

    def test_container_workload_is_not_checked(self):
        self.assertEqual(self._checks(_TOML_NO_HOST), [])

    def test_disabled_vm_is_not_checked(self):
        self.assertEqual(self._checks(_VM_TOML, enabled=False), [])


class _StubManager:
    """Minimal WorkloadManager stand-in: the battery only needs user_exists()
    to be answerable before it reaches the checks under test here."""

    def user_exists(self, config):
        return False

    def podman(self, config):
        raise AssertionError("the bridge check must not touch podman")


# ── the shipped bundles ─────────────────────────────────────────────────────

class ShippedSetupScriptsTest(unittest.TestCase):
    """Every setup.sh we ship answers the action.

    The mechanism tolerates a script that doesn't — that is what makes the
    rollout incremental — which is exactly why the four converted ones need a
    guard: a regression here degrades to "undeclared", a *passing* check, and
    would go unnoticed.
    """

    @classmethod
    def setUpClass(cls):
        cls.scripts = sorted(
            (REPO_ROOT / "workloads").glob("*/setup.sh"))
        if not cls.scripts:
            raise unittest.SkipTest("no shipped setup.sh found")
        cls._instances = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._instances.cleanup)
        cls._instance_dirs = {}

    @classmethod
    def _instance_dir(cls, bundle: str, name: str) -> Path:
        """A stand-in for /etc/workloads.d/<name>/, built the way `init` builds it.

        `cmd_init` copies **only** workload.toml out of the bundle, under the
        *instance* name, and leaves every other control file to resolve back to
        the bundle via resolve_control_file(). Reproducing that shape matters
        here for one reason: pointing WORKLOAD_INSTANCE_DIR at the bundle dir
        instead — which is one directory away and reads as a harmless
        simplification — makes every instance-keyed path a script derives from
        it contain the bundle name, so the assertion below fires on correct
        scripts (gamedev-sway's ${WORKLOAD_INSTANCE_DIR}/seccomp.json) and can
        never fire on the hardcoded ones it exists to catch.
        """
        # The parent is random rather than the bundle name: every path a script
        # derives from this one is checked against the bundle name below, so a
        # tidy `<tmp>/<bundle>/<name>` layout would reintroduce the same false
        # positive one level up.
        key = (bundle, name)
        path = cls._instance_dirs.get(key)
        if path is None:
            path = Path(tempfile.mkdtemp(dir=cls._instances.name)) / name
            path.mkdir()
            toml = REPO_ROOT / "workloads" / bundle / "workload.toml"
            if toml.exists():
                shutil.copy(toml, path / "workload.toml")
            cls._instance_dirs[key] = path
        return path

    def test_every_shipped_script_answers_the_action(self):
        for script in self.scripts:
            with self.subTest(bundle=script.parent.name):
                result = subprocess.run(
                    [str(script), provisioning.HOST_SETUP_ARTIFACTS_ACTION],
                    capture_output=True, text=True, timeout=30,
                    env=self._env(script.parent.name),
                )
                self.assertEqual(
                    result.returncode, 0,
                    f"{script.parent.name}/setup.sh does not implement "
                    f"'{provisioning.HOST_SETUP_ARTIFACTS_ACTION}': "
                    f"{result.stderr}")
                _, unparsed = _parse_host_artifacts(result.stdout)
                self.assertEqual(
                    unparsed, [],
                    f"{script.parent.name}/setup.sh printed non-declarations "
                    f"on stdout")

    def test_declared_refs_are_keyed_to_the_instance(self):
        """Run under an instance name that is not the bundle name, and assert
        nothing declared mentions the bundle. A hardcoded bundle name is the
        failure mode host_setup_env() was written to prevent."""
        for script in self.scripts:
            bundle = script.parent.name
            with self.subTest(bundle=bundle):
                result = subprocess.run(
                    [str(script), provisioning.HOST_SETUP_ARTIFACTS_ACTION],
                    capture_output=True, text=True, timeout=30,
                    env=self._env(bundle, name="zzinstance"),
                )
                self.assertEqual(result.returncode, 0)
                for artifact in _parse_host_artifacts(result.stdout)[0]:
                    self.assertFalse(
                        self._names_bundle(artifact.ref, bundle),
                        f"{bundle}/setup.sh declared {artifact.ref!r}, which "
                        f"names the bundle rather than the instance")

    @staticmethod
    def _names_bundle(ref: str, bundle: str) -> bool:
        """Is the bundle name used where the instance name belongs?

        Matched on path segments and on the unit-name prefix, not as a bare
        substring: caddy's snippet is `homelab-ca.caddyfile`, which contains
        "caddy" incidentally while being correctly keyed to the instance.
        """
        return (ref.startswith(f"{bundle}-")
                or ref.startswith(f"{bundle}.")
                or f"/{bundle}/" in ref
                or ref.endswith(f"/{bundle}"))

    @classmethod
    def _env(cls, bundle: str, name: str = "zzinstance") -> dict:
        bundle_dir = REPO_ROOT / "workloads" / bundle
        return {
            "PATH": "/usr/bin:/bin",
            "WORKLOAD_NAME": name,
            "WORKLOAD_BUNDLE": bundle,
            "WORKLOAD_BUNDLE_DIR": str(bundle_dir),
            "WORKLOAD_USER": f"_wl-{name}",
            # A real per-instance dir carrying the bundle's workload.toml, so
            # sunshine's script can read its port out of it before dispatching
            # and nothing derived from it inherits the bundle name.
            "WORKLOAD_INSTANCE_DIR": str(cls._instance_dir(bundle, name)),
            "WORKLOAD_ROOT_DIR": f"/var/lib/workloads/{name}",
            "WORKLOAD_STATE_DIR": f"/var/lib/workloads/{name}/state",
            "WORKLOAD_DATA_DIR": f"/var/lib/workloads/{name}/data",
            # Point the homelab CA at nothing, so the conditional branches take
            # their "not on this host" path deterministically rather than
            # depending on whether the test runner has a CA installed.
            "HOMELAB_CA_CERT": "/nonexistent/ca.crt",
            "HOMELAB_CA_KEY": "/nonexistent/ca.key",
        }


if __name__ == "__main__":
    unittest.main()
