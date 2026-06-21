"""
test_bundle_ergonomics.py — bundle verbs: catalog, init, validate, duplicate.

These tests exercise the bundle-instantiation surface end-to-end on the target.
No workload is enabled — all tests operate at the TOML / validation layer and
complete in seconds.

Covers:
  - catalog --json lists bundles
  - init <bundle> --as <name> creates the TOML
  - init records bundle = "..." when --as renames the instance
  - init rejects an already-existing name (no silent clobber)
  - validate passes after a clean init
  - validate correctly passes workload-relative (./sub) volume paths
    that don't exist yet (regression: they were incorrectly reported as errors
    before the "will be created on enable" fix)
  - duplicate creates a copy with the original bundle field preserved
"""

import json

import pytest

from target import Target

# All test-provisioned workload names start with "clitest-" so the
# session-level purge fixture in conftest.py cleans them up automatically.
_INIT_NAME   = "clitest-bundle-init"
_DUP_NAME    = "clitest-bundle-dup"
_RELPATH_NAME = "clitest-bundle-relpath"

# A simple bundle guaranteed to be shipped with workloadctl (no required
# absolute paths that might be absent on the test host, no relative volumes).
_TEST_BUNDLE = "webproxy-demo"

# Minimal TOML with a workload-relative (./data) volume mount.  Used to verify
# that relative-path volumes under /var/lib/workloads/<name>/ do NOT fail
# validation as "does not exist" — they are created by enable, not init.
_RELPATH_TOML = """\
[workload]
name = "clitest-bundle-relpath"
enabled = false

[container]
image = "docker.io/library/caddy:2-alpine"

[storage]
volumes = [
    "./data:/srv/data:ro",
]

[resources]
memory_max = "128M"
"""


# ---------------------------------------------------------------------------
# Per-test cleanup (idempotent: safe to run before AND after each test)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _cleanup(target: Target):
    _rm_toml(target, _INIT_NAME)
    _rm_toml(target, _DUP_NAME)
    _rm_toml(target, _RELPATH_NAME)
    yield
    _rm_toml(target, _INIT_NAME)
    _rm_toml(target, _DUP_NAME)
    _rm_toml(target, _RELPATH_NAME)


def _rm_toml(target: Target, name: str):
    target.run(["rm", "-f", f"/etc/workloads.d/{name}.toml"], sudo=True, check=False)


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------

class TestCatalog:
    def test_catalog_lists_bundles(self, target: Target, record_property):
        """catalog --json returns a non-empty list containing the test bundle."""
        record_property("cell", "catalog/container")
        r = target.wl("catalog --json", sudo=False, check=True)
        data = json.loads(r.stdout)
        assert isinstance(data, list) and data, "catalog --json returned empty list"
        names = [b["bundle"] for b in data]
        assert _TEST_BUNDLE in names, (
            f"{_TEST_BUNDLE!r} not in catalog: {names}"
        )


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_creates_toml(self, target: Target, record_property):
        """init <bundle> --as <name> writes /etc/workloads.d/<name>.toml."""
        record_property("cell", "init/container")
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        assert target.remote_path_exists(f"/etc/workloads.d/{_INIT_NAME}.toml"), (
            f"/etc/workloads.d/{_INIT_NAME}.toml not created by init"
        )

    def test_init_sets_bundle_field(self, target: Target):
        """When --as renames the instance, the TOML records bundle = '<source>'."""
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        content = target.read(f"/etc/workloads.d/{_INIT_NAME}.toml")
        assert f'bundle = "{_TEST_BUNDLE}"' in content, (
            f"Expected bundle = {_TEST_BUNDLE!r} in TOML:\n{content}"
        )

    def test_init_validate_passes(self, target: Target, record_property):
        """validate passes cleanly after init for a simple bundle."""
        record_property("cell", "validate/container")
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        r = target.wl(f"validate {_INIT_NAME}", sudo=False, check=False)
        assert r.rc == 0, (
            f"validate failed after init of {_TEST_BUNDLE!r}:\n{r.stdout}\n{r.stderr}"
        )

    def test_init_rejects_existing_name(self, target: Target):
        """init of an already-existing workload name exits non-zero (no clobber)."""
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        r = target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=False)
        assert r.rc != 0, "Expected init to fail when the TOML already exists"


# ---------------------------------------------------------------------------
# validate — relative volume paths (regression)
# ---------------------------------------------------------------------------

class TestValidateRelativePaths:
    def test_relative_volume_passes_validation(self, target: Target, record_property):
        """Volumes under /var/lib/workloads/<name>/ must not fail validate.

        Regression: before the fix, ./data expanded to
        /var/lib/workloads/<name>/data/data which doesn't exist on a fresh host,
        causing validate to error with "Volume path does not exist".
        After the fix, workload-relative paths are recognised as auto-created
        by enable and pass with "will be created on enable".
        """
        record_property("cell", "validate/container")
        target.put_content(
            _RELPATH_TOML,
            f"/etc/workloads.d/{_RELPATH_NAME}.toml",
        )
        r = target.wl(f"validate --json {_RELPATH_NAME}", sudo=False, check=False)
        data = json.loads(r.stdout)
        vol_checks = [
            c for c in data.get("checks", [])
            if c.get("check") == "volume_path"
        ]
        failed_vol = [c for c in vol_checks if not c.get("passed")]
        assert not failed_vol, (
            "Relative volume path(s) failed validation (regression):\n"
            + "\n".join(c.get("message", str(c)) for c in failed_vol)
        )


# ---------------------------------------------------------------------------
# duplicate
# ---------------------------------------------------------------------------

class TestDuplicate:
    def test_duplicate_creates_toml(self, target: Target, record_property):
        """duplicate <source> <new> writes a new TOML for the copy."""
        record_property("cell", "duplicate/container")
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        target.wl(f"duplicate {_INIT_NAME} {_DUP_NAME}", check=True)
        assert target.remote_path_exists(f"/etc/workloads.d/{_DUP_NAME}.toml"), (
            f"/etc/workloads.d/{_DUP_NAME}.toml not created by duplicate"
        )

    def test_duplicate_preserves_bundle_field(self, target: Target):
        """A duplicate-of-an-init still points at the original bundle, not the init copy."""
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        target.wl(f"duplicate {_INIT_NAME} {_DUP_NAME}", check=True)
        content = target.read(f"/etc/workloads.d/{_DUP_NAME}.toml")
        assert f'bundle = "{_TEST_BUNDLE}"' in content, (
            f"Expected bundle = {_TEST_BUNDLE!r} in duplicate TOML:\n{content}"
        )
