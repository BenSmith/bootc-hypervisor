#!/usr/bin/env python3
"""TDD contracts for the B15 shared run-file topology helper.

Background: `docs/workload-run-files.md` is the authoritative definition of the
per-workload run-files a workload owns, but that set is currently hand-enumerated
in ~8 places plus the generator (grep `f"workload-{` across lib/ generators/
libexec/). B15 replaces those with a single `workload_run_files(config)` family in
`workload_lib`. This module is the *risky-step contract* for that work, written
the helper existed (TDD); it is now the enforcing contract for the shipped API:

  * TestCurrentDestructiveGolden pins the disable/purge deletion set — the
    systemd-side files a workload owns, per mode. It is driven by the helper's
    *removable* view (`workload_run_files(config)` minus the env-tree), so a change
    to that deletion behavior must be an intentional edit to this golden.

  * TestRunFilesMembership / TestRunFilesBoundary  -> the exact emitted set per
    mode/kind, and the owned/excluded boundary as a helper property.
  * TestRunFilesParityOracle                       -> helper == what the generator
    actually emits for THIS config.

Two properties the helper's API is shaped around:

  1. EXACT vs SUPERSET are two different views. The removable view intentionally
     over-lists: it includes `workload-<name>-pod.service` and `-net.service` for
     *every* container workload regardless of mode, relying on missing_ok at delete
     time rather than branching on topology. The generator emits only the units a
     given mode actually needs. So:
       - the parity oracle compares the generator's output to the helper's
         *emitted* view (files that exist for THIS exact config);
       - the destructive golden pins the helper's *removable* view (the
         safe-deletion superset).
     The helper distinguishes these via a per-entry `emitted: bool` (True iff the
     generator writes it for this config).

  2. The owned set spans two storage roots: systemd units + sysusers .conf + the
     cgroup drop-in (under RUN_SYSTEMD_SYSTEM), and the `.env` / `.secrets` files
     (under WORKLOAD_ENV_DIR). The helper unifies them, tagging each entry with a
     `kind` so callers filter instead of re-deriving. The env-file coverage lives
     in test_disable_purge.py; this module owns the systemd-side golden.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import workload_lib
from workloadctl_core import WorkloadConfig
from covhelper import python_cmd

from tests import script_env


# The helper under test does not exist yet (Stage 0). Guard the import so this
# module is collectable today; the contract classes skip until it lands.
try:
    from workload_lib import workload_run_files  # noqa: F401
    HAVE_HELPER = True
except ImportError:
    HAVE_HELPER = False

PENDING = unittest.skipUnless(
    HAVE_HELPER,
    "workload_run_files not implemented yet (B15 Stage 0) — contract pending",
)

GENERATOR = os.path.join(os.path.dirname(__file__), '..', 'generators', 'workload-generate')


# --------------------------------------------------------------------------- #
# Fixtures — the mode/kind matrix the helper must cover.
# --------------------------------------------------------------------------- #

SINGLE_TOML = """\
[workload]
name = "{name}"

[container]
image = "example.com/test:latest"
"""

POD_TOML = """\
[workload]
name = "{name}"
mode = "pod"

[[containers]]
name = "web"
[containers.container]
image = "example.com/web:latest"

[[containers]]
name = "db"
[containers.container]
image = "example.com/db:latest"
"""

BRIDGE_TOML = """\
[workload]
name = "{name}"
mode = "bridge"

[[containers]]
name = "front"
[containers.container]
image = "example.com/front:latest"

[[containers]]
name = "back"
[containers.container]
image = "example.com/back:latest"
"""

# Adversarial: [[containers]] present but mode explicitly forced to "single".
# validate_workload_config rejects this, but `edit`/hand-authored TOML can reach
# workload_run_files without re-validating. The two per-container gates
# (units, .secrets) must agree on such a config so disable/purge stays complete.
CONTRADICTION_TOML = """\
[workload]
name = "{name}"
mode = "single"

[[containers]]
name = "web"
[containers.container]
image = "example.com/web:latest"

[[containers]]
name = "db"
[containers.container]
image = "example.com/db:latest"
"""

VM_TOML = """\
[workload]
name = "{name}"

[vm.network]
egress = "open"

[vm]
cloud_image_url = "https://example.com/img.qcow2"
cloud_image_checksum = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
memory = "2G"
system_disk_size = "10G"
"""

# A VM that references *another* workload and rides the shared bridge — the
# adversarial input for the boundary contract. The excluded set (generate/bridge/
# dnsmasq/cross-refs) must never appear in this workload's owned files.
VM_WITH_REFS_TOML = """\
[workload]
name = "{name}"
requires = ["other"]

[vm.network]
egress = "open"

[vm]
cloud_image_url = "https://example.com/img.qcow2"
cloud_image_checksum = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
memory = "2G"
system_disk_size = "10G"
"""


class _Config:
    """Build a WorkloadConfig from an inline TOML in a temp WORKLOAD_CONFIG_DIR.

    Mirrors test_disable_purge._Env. No workload user is created, so the UID-keyed
    cgroup drop-in (user@<uid>.service.d/50-workload.conf) is absent — the same
    branch workload_run_files takes on a missing user. Drop-in coverage is called
    out in the contracts but not asserted here (needs a real passwd entry).
    """

    def __init__(self, toml, name):
        self._toml = toml.format(name=name)
        self._name = name

    def __enter__(self):
        self._tmp = tempfile.mkdtemp()
        root = Path(self._tmp)
        (root / self._name).mkdir()
        (root / self._name / 'workload.toml').write_text(self._toml)
        self._patch = patch.object(workload_lib, 'WORKLOAD_CONFIG_DIR', root)
        self._patch.start()
        return WorkloadConfig(self._name)

    def __exit__(self, *_):
        self._patch.stop()
        shutil.rmtree(self._tmp, ignore_errors=True)


def _rel(paths):
    """Paths relative to /run/systemd/system, as posix strings, for stable compare.

    Using relpath (not basename) keeps the autostart symlink
    multi-user.target.wants/workload-<name>.service distinct from the main unit
    workload-<name>.service — they share a basename.
    """
    run = workload_lib.RUN_SYSTEMD_SYSTEM
    out = set()
    for p in paths:
        p = Path(p)
        try:
            out.add(p.relative_to(run).as_posix())
        except ValueError:
            out.add(p.as_posix())
    return out


# --------------------------------------------------------------------------- #
# Stage 3 safety net — GREEN today. Characterizes the current deletion set.
# --------------------------------------------------------------------------- #

class TestCurrentDestructiveGolden(unittest.TestCase):
    """Freeze the systemd-side deletion set per mode.

    The authoritative record of what disable/purge removes: the helper's
    removable view (workload_run_files minus the env-tree). A diff here is
    either an intended change to the deletion set or a regression — never
    silent.

    Note the deliberate over-listing: -pod and -net appear for single mode too.
    That is the "superset + missing_ok" contract, not a bug.
    """

    def _golden(self, config):
        return _rel(rf.path for rf in workload_run_files(config)
                    if rf.kind != 'env-file')

    def test_single(self):
        with _Config(SINGLE_TOML, 'app') as config:
            self.assertEqual(self._golden(config), {
                'workload-app.conf',
                'workload-app-setup.service',
                'workload-app.service',
                'multi-user.target.wants/workload-app.service',
                # deliberate superset (single mode emits neither):
                'workload-app-pod.service',
                'workload-app-net.service',
            })

    def test_pod(self):
        with _Config(POD_TOML, 'stack') as config:
            self.assertEqual(self._golden(config), {
                'workload-stack.conf',
                'workload-stack-setup.service',
                'workload-stack.service',
                'multi-user.target.wants/workload-stack.service',
                'workload-stack-pod.service',
                'workload-stack-net.service',
                'workload-stack-web.service',
                'workload-stack-db.service',
            })

    def test_vm(self):
        with _Config(VM_TOML, 'forge') as config:
            self.assertEqual(self._golden(config), {
                'workload-forge.conf',
                'workload-forge-setup.service',
                'workload-forge.service',
                'multi-user.target.wants/workload-forge.service',
                'workload-forge-build.service',
                # Superset semantics, like -pod/-net for containers: the proxy
                # unit is always listed so the destructive view can unlink it,
                # and emitted only when [vm.network].hosts is set.
                'workload-forge-proxy.service',
                # Superset semantics, like the proxy: the inspector socket and
                # service are always listed so the destructive view can unlink
                # them, emitted only when egress inspection applies (not
                # bridged, egress filtered). This fixture is egress = "open",
                # so both are listed-but-not-emitted here.
                'workload-forge-inspect.socket',
                'workload-forge-inspect.service',
                # no pod/net (VM branch); no virtiofs units (no vm.volumes)
            })


# --------------------------------------------------------------------------- #
# Stage 0 — the helper's exact emitted set per mode/kind.  PENDING.
# --------------------------------------------------------------------------- #

@PENDING
class TestRunFilesMembership(unittest.TestCase):
    """`workload_run_files(config)` must name exactly the files that exist for
    THIS config, each tagged with kind (unit|wants-symlink|env-file|sysusers|
    dropin) and a role (main|setup|build|pod|net|container|virtiofs|secrets|...).

    The `emitted` view (files the generator actually writes for this config) is
    what read-only consumers and the parity oracle use. Unlike the destructive
    superset, single mode here must NOT include pod/net.
    """

    def _emitted_rel(self, config):
        return _rel(rf.path for rf in workload_run_files(config) if rf.emitted)

    def test_single_emits_no_pod_or_net(self):
        with _Config(SINGLE_TOML, 'app') as config:
            got = self._emitted_rel(config)
            self.assertIn('workload-app.service', got)
            self.assertIn('workload-app-setup.service', got)
            self.assertIn('multi-user.target.wants/workload-app.service', got)
            self.assertNotIn('workload-app-pod.service', got)
            self.assertNotIn('workload-app-net.service', got)

    def test_pod_emits_pod_unit_and_per_container(self):
        with _Config(POD_TOML, 'stack') as config:
            got = self._emitted_rel(config)
            self.assertIn('workload-stack-pod.service', got)
            self.assertIn('workload-stack-web.service', got)
            self.assertIn('workload-stack-db.service', got)
            self.assertNotIn('workload-stack-net.service', got)

    def test_bridge_emits_net_unit_and_per_container(self):
        with _Config(BRIDGE_TOML, 'mesh') as config:
            got = self._emitted_rel(config)
            self.assertIn('workload-mesh-net.service', got)
            self.assertIn('workload-mesh-front.service', got)
            self.assertIn('workload-mesh-back.service', got)
            self.assertNotIn('workload-mesh-pod.service', got)

    def test_vm_emits_build_not_pod_net(self):
        with _Config(VM_TOML, 'forge') as config:
            got = self._emitted_rel(config)
            self.assertIn('workload-forge-build.service', got)
            self.assertNotIn('workload-forge-pod.service', got)
            self.assertNotIn('workload-forge-net.service', got)

    def test_dropin_emitted_when_user_exists(self):
        # The parity oracle can't exercise the cgroup drop-in (its fixtures have no
        # workload user, and a pure helper won't allocate a UID). Cover the
        # with-user branch directly: when config.uid resolves, the helper emits
        # user@<uid>.service.d/50-workload.conf, tagged kind='dropin'.
        import collections
        fake_pw = collections.namedtuple('pw', 'pw_uid')(12345)
        with _Config(SINGLE_TOML, 'app') as config:
            with patch('workloadctl_core.pwd.getpwnam', return_value=fake_pw):
                dropins = [rf for rf in workload_run_files(config)
                           if rf.kind == 'dropin']
            self.assertEqual(len(dropins), 1)
            self.assertTrue(dropins[0].emitted)
            self.assertEqual(Path(dropins[0].path).name, '50-workload.conf')
            self.assertIn('user@12345.service.d', dropins[0].path.as_posix())

    def test_kinds_are_tagged(self):
        with _Config(POD_TOML, 'stack') as config:
            by_kind = {}
            for rf in workload_run_files(config):
                by_kind.setdefault(rf.kind, set()).add(Path(rf.path).name)
            self.assertIn('workload-stack.service', by_kind.get('wants-symlink', set()))
            self.assertIn('workload-stack.service', by_kind.get('unit', set()))
            # env-files are owned run-files too, not systemd units:
            self.assertTrue(by_kind.get('env-file'))

    def _per_container_names(self, config):
        """(units, secrets): container-local names carried by the per-container
        .service units and by the per-container .secrets env-files."""
        prefix = f'workload-{config.name}-'
        units, secrets = set(), set()
        for rf in workload_run_files(config):
            base = Path(rf.path).name
            if not base.startswith(prefix):
                continue
            if rf.kind == 'unit' and rf.role == 'container':
                units.add(base[len(prefix):-len('.service')])
            elif rf.kind == 'env-file' and rf.role == 'secrets':
                secrets.add(base[len(prefix):-len('.secrets')])
        return units, secrets

    def test_per_container_units_and_secrets_share_one_gate(self):
        # Both sets must key off the same discriminator; a split lets disable
        # unlink per-container .secrets while never listing the matching units.
        for toml, name in ((POD_TOML, 'stack'), (BRIDGE_TOML, 'mesh')):
            with self.subTest(name=name), _Config(toml, name) as config:
                units, secrets = self._per_container_names(config)
                self.assertTrue(units)
                self.assertEqual(units, secrets)

    def test_contradicting_mode_gates_units_and_secrets_together(self):
        # is_multi is True (has [[containers]]) but mode == "single": both
        # per-container sets must be empty, not split.
        with _Config(CONTRADICTION_TOML, 'skew') as config:
            self.assertTrue(config.is_multi)
            self.assertEqual(config.mode, 'single')
            units, secrets = self._per_container_names(config)
            self.assertEqual(units, set())
            self.assertEqual(secrets, set())


@PENDING
class TestRunTreeScansCoverRunFiles(unittest.TestCase):
    """`RUN_TREE_SCANS` (drift's tree-walk table) must name exactly the run-file
    kinds that land under RUN_SYSTEMD_SYSTEM.

    workload_run_files() is the per-config source of truth; RUN_TREE_SCANS is its
    tree-walking companion. If a new tree kind is added to one without the other,
    drift silently stops comparing (or over-globs) it — the exact drift hazard the
    shared helpers exist to kill. This test pins the two together.
    """

    # env-file kinds live under WORKLOAD_ENV_DIR, not the systemd run tree, so
    # drift never scans them.
    _ENV_KINDS = {'env-file'}

    def test_scans_match_emitted_tree_kinds(self):
        import collections
        emitted_kinds = set()
        fake_pw = collections.namedtuple('pw', 'pw_uid')(12345)
        for toml, name in (
            (SINGLE_TOML, 'app'), (POD_TOML, 'stack'),
            (BRIDGE_TOML, 'mesh'), (VM_TOML, 'forge'),
        ):
            with _Config(toml, name) as config:
                # Force the with-user branch so the UID-keyed drop-in is included.
                with patch('workloadctl_core.pwd.getpwnam', return_value=fake_pw):
                    for rf in workload_run_files(config):
                        if rf.emitted and rf.kind not in self._ENV_KINDS:
                            emitted_kinds.add(rf.kind)

        scan_kinds = {s.kind for s in workload_lib.RUN_TREE_SCANS}
        self.assertEqual(scan_kinds, emitted_kinds)


# --------------------------------------------------------------------------- #
# Stage 0 — owned/excluded boundary, asserted as a property of the helper.
# Locked before any consumer trusts the output (not deferred to Stage 3).
# --------------------------------------------------------------------------- #

@PENDING
class TestRunFilesBoundary(unittest.TestCase):
    """The excluded set must NEVER appear, even for an adversarial VM workload
    that references another workload: the global workload-generate.service, and
    any reference to a *different* workload's unit (inter-workload ordering is
    not an owned file).

    workload-bridge.service is still listed as forbidden although the generator
    can no longer emit it (ADR 006). The assertion costs nothing and states the
    boundary rather than the current implementation, which is the point of a
    boundary test.
    """

    FORBIDDEN_EXACT = {
        'workload-generate.service',
        'workload-bridge.service',
    }

    def _all_names(self, config):
        return {Path(rf.path).name for rf in workload_run_files(config)}

    def test_excluded_infra_absent(self):
        with _Config(VM_WITH_REFS_TOML, 'git') as config:
            names = self._all_names(config)
            self.assertFalse(names & self.FORBIDDEN_EXACT,
                             f"owned set leaked shared infra: {names & self.FORBIDDEN_EXACT}")
            self.assertFalse(any('dnsmasq' in n for n in names),
                             "dnsmasq is shared bridge infra, not workload-owned")

    def test_no_cross_workload_references_owned(self):
        with _Config(VM_WITH_REFS_TOML, 'git') as config:
            names = self._all_names(config)
            # requires=["other"] must not pull workload-other.service into git's set.
            self.assertFalse(any(n.startswith('workload-other') for n in names),
                             "referenced sibling workload unit must not be owned")


# --------------------------------------------------------------------------- #
# Stage 1 — parity oracle: helper's emitted view == what the generator writes.
# This proves the helper against the authoritative *producer*, not doc prose.
# --------------------------------------------------------------------------- #

@PENDING
class TestRunFilesParityOracle(unittest.TestCase):
    """Run the generator over each fixture; the set of files it materializes must
    equal the helper's emitted view. Only files the generator actually writes are
    compared (units, the wants symlink, sysusers .conf, the cgroup drop-in) — the
    `.env`/`.secrets` env-files are written at runtime by workload-write-env /
    workload-ensure-user, not the generator, so they are excluded from parity.
    """

    GENERATOR_KINDS = {'unit', 'wants-symlink', 'sysusers', 'dropin'}

    def _run_generator(self, toml, name):
        config_dir = tempfile.mkdtemp()
        services_dir = tempfile.mkdtemp()
        try:
            wl = Path(config_dir) / name
            wl.mkdir()
            (wl / 'workload.toml').write_text(toml.format(name=name))
            (wl / '.enabled').touch()
            env = script_env(
                WORKLOAD_CONFIG_DIR=config_dir,
                SYSUSERS_DIR=services_dir,
                WORKLOAD_GENERATE_LOG_STDERR='1',
            )
            subprocess.run(python_cmd(GENERATOR, services_dir),
                           capture_output=True, text=True, env=env, check=False)
            emitted = {p.relative_to(services_dir).as_posix()
                       for p in Path(services_dir).rglob('*') if p.is_file()}
            return emitted
        finally:
            shutil.rmtree(config_dir, ignore_errors=True)
            shutil.rmtree(services_dir, ignore_errors=True)

    def _assert_parity(self, toml, name):
        generated = self._run_generator(toml, name)
        with _Config(toml, name) as config:
            helper = _rel(rf.path for rf in workload_run_files(config)
                          if rf.emitted and rf.kind in self.GENERATOR_KINDS)
        # Normalize both sides down to *this workload's owned* generated files:
        #
        #  - Drop the cgroup drop-in (user@<uid>.service.d/50-workload.conf). The
        #    generator *allocates* a UID (getpwnam-else-get_next_uid) and always
        #    writes the drop-in, even for a workload whose user does not exist yet.
        #    workload_run_files is a pure, side-effect-free query (called from
        #    read-only inspect/metrics/drift paths; it must never allocate a UID),
        #    so for a userless fixture it cannot reconstruct that path and omits the
        #    drop-in — matching the removal path's own graceful degradation. The
        #    drop-in's removal-side behavior is covered in test_disable_purge.py.
        #  - Drop any shared VM bridge infra. The generator no longer emits it
        #    at all (ADR 006), so this filter is now vestigial; it is kept so a
        #    host carrying units from a pre-ADR-006 build still compares equal.
        def owned_only(s):
            return {p for p in s
                    if not p.startswith('user@')
                    and 'workload-bridge' not in p}
        self.assertEqual(owned_only(helper), owned_only(generated),
                         f"helper/generator disagree for {name}")

    def test_parity_single(self):
        self._assert_parity(SINGLE_TOML, 'app')

    def test_parity_pod(self):
        self._assert_parity(POD_TOML, 'stack')

    def test_parity_bridge(self):
        self._assert_parity(BRIDGE_TOML, 'mesh')

    def test_parity_vm(self):
        self._assert_parity(VM_TOML, 'forge')


class TestSysusersRender(unittest.TestCase):
    """render_sysusers_config renders the workload user's sysusers .conf. The
    generator is its sole caller and the single producer of the .conf; enable
    consumes that output rather than re-rendering. These pin the content
    contract (the reason B15/B6 exist).
    """

    def _render(self, **kw):
        kw.setdefault('name', 'app')
        kw.setdefault('user_name', '_wl-app')
        kw.setdefault('uid', 10000)
        kw.setdefault('home_dir', '/var/lib/workloads/app/state')
        return workload_lib.render_sysusers_config(**kw)

    def test_container_basic(self):
        out = self._render()
        self.assertEqual(out, (
            '# Workload user for app\n'
            'u _wl-app 10000 "app workload" /var/lib/workloads/app/state\n'
        ))

    def test_extra_groups_appended(self):
        out = self._render(extra_groups=['render', 'video'])
        self.assertIn('m _wl-app render\n', out)
        self.assertIn('m _wl-app video\n', out)

    def test_vm_gets_implicit_kvm(self):
        out = self._render(is_vm=True)
        self.assertIn('# Workload user for app (VM)\n', out)
        self.assertIn('m _wl-app kvm\n', out)

    def test_vm_kvm_not_duplicated(self):
        # kvm listed explicitly in extra_groups must not emit a second line —
        # the bug the old inline enable-path renderer had.
        out = self._render(is_vm=True, extra_groups=['kvm', 'render'])
        self.assertEqual(out.count('m _wl-app kvm\n'), 1)
        self.assertIn('m _wl-app render\n', out)


if __name__ == '__main__':
    unittest.main()
