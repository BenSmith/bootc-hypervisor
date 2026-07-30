"""
test_bundle_ergonomics.py — bundle verbs: catalog, init, validate, duplicate,
info --files, edit (control-file override), build.

These tests exercise the bundle-instantiation + control-file-override surface
end-to-end on the target. No workload is enabled — all tests operate at the
TOML / control-file layer and complete in seconds (the heavy real-image build
is not exercised here; it's covered by tests/test_imagebuild.py at the unit
layer and the merged-context override is asserted there).

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
  - info --files: empty for a pull-only bundle; lists a seeded override as
    source=override; lists a *nested* override (sub/x) too
  - edit <name> <file>: seeds an /etc copy-on-write override, makes a
    shebang'd hook executable even without a .sh suffix, and refuses to write
    through a pre-planted symlink component (no escape out of the override tree)
  - build: graceful, non-crashing refusal for a workload that pulls a
    published image (no build context)
  - info --files / diagnose: a [workload] bundle with a `..` traversal is
    rejected with a clear error, and diagnose does not crash with a traceback

These last groups port the live checks that previously lived only in the
ad-hoc host exercise script, so the bundle command surface stays covered by the
standing harness.
"""

import json

import pytest

from target import Target

# All test-provisioned workload names start with "clitest-" so the
# session-level purge fixture in conftest.py cleans them up automatically.
_INIT_NAME   = "clitest-bundle-init"
_DUP_NAME    = "clitest-bundle-dup"
_RELPATH_NAME = "clitest-bundle-relpath"
_BAD_NAME    = "clitest-bundle-badb"

# A sentinel outside the override tree; the symlink-escape test asserts edit
# never writes here through a pre-planted symlink component.
_ESCAPE_LEAK = "/tmp/clitest-bundle-pwned"

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
    _scrub(target)
    yield
    _scrub(target)


def _scrub(target: Target):
    for name in (_INIT_NAME, _DUP_NAME, _RELPATH_NAME, _BAD_NAME):
        _rm_workload(target, name)
    # The symlink-escape sentinel must never exist; remove any stray copy.
    target.run(["rm", "-f", _ESCAPE_LEAK], sudo=True, check=False)


def _rm_toml(target: Target, name: str):
    # Legacy sweep: a pre-flip run may have left a flat <name>.toml behind.
    target.run(["rm", "-f", f"/etc/workloads.d/{name}.toml"], sudo=True, check=False)


def _workload_toml(name: str) -> str:
    """Step-2 config path for a workload: /etc/workloads.d/<name>/workload.toml."""
    return f"/etc/workloads.d/{name}/workload.toml"


def _put_workload(target: Target, name: str, content: str):
    """Write a workload TOML into its Step-2 subdir (creating the dir first)."""
    target.run(["mkdir", "-p", f"/etc/workloads.d/{name}"], sudo=True, check=True)
    target.put_content(content, _workload_toml(name))


def _rm_workload(target: Target, name: str):
    """Remove a workload's TOML *and* its /etc override tree.

    `rm -rf` on the override dir removes any pre-planted symlink component as a
    link (it does not follow it), so the symlink-escape fixture can't delete the
    symlink's target.
    """
    _rm_toml(target, name)
    target.run(["rm", "-rf", f"/etc/workloads.d/{name}"], sudo=True, check=False)


def _put_editor(target: Target, body: str) -> str:
    """Upload a non-interactive $EDITOR script (root-owned, executable)."""
    remote = "/tmp/clitest-bundle-editor.sh"
    target.put_content(body, remote)
    target.run(["chmod", "+x", remote], sudo=True, check=True)
    return remote


def _edit(target: Target, name: str, rel: str, editor: str, *, check: bool):
    """Run `workloadctl edit <name> <rel>` with EDITOR set (sudo scrubs env, so
    pass it through `env` inside the sudo context, mirroring TestEdit)."""
    return target.run(
        ["sudo", "-n", "env", f"EDITOR={editor}",
         "workloadctl", "edit", name, rel],
        sudo=False, check=check,
    )


def _control_files(target: Target, name: str) -> list[dict]:
    """Return the `info --files --json` control_files list for a workload."""
    r = target.wl(f"info {name} --files --json", check=True)
    return json.loads(r.stdout).get("control_files", [])


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
        """init <bundle> --as <name> writes /etc/workloads.d/<name>/workload.toml."""
        record_property("cell", "init/container")
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        assert target.remote_path_exists(_workload_toml(_INIT_NAME)), (
            f"{_workload_toml(_INIT_NAME)} not created by init"
        )

    def test_init_sets_bundle_field(self, target: Target):
        """When --as renames the instance, the TOML records bundle = '<source>'."""
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        content = target.read(_workload_toml(_INIT_NAME))
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
        _put_workload(target, _RELPATH_NAME, _RELPATH_TOML)
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
        assert target.remote_path_exists(_workload_toml(_DUP_NAME)), (
            f"{_workload_toml(_DUP_NAME)} not created by duplicate"
        )

    def test_duplicate_preserves_bundle_field(self, target: Target):
        """A duplicate-of-an-init still points at the original bundle, not the init copy."""
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        target.wl(f"duplicate {_INIT_NAME} {_DUP_NAME}", check=True)
        content = target.read(_workload_toml(_DUP_NAME))
        assert f'bundle = "{_TEST_BUNDLE}"' in content, (
            f"Expected bundle = {_TEST_BUNDLE!r} in duplicate TOML:\n{content}"
        )


# ---------------------------------------------------------------------------
# info --files (merged control-file view)
# ---------------------------------------------------------------------------

class TestInfoFiles:
    def test_info_files_empty_for_pull_only_bundle(self, target: Target, record_property):
        """A bundle that ships no control files reports an empty merged view."""
        record_property("cell", "info/container")
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        files = _control_files(target, _INIT_NAME)
        assert files == [], (
            f"{_TEST_BUNDLE!r} ships no control files; expected [], got: {files}"
        )

    def test_info_files_lists_override(self, target: Target, record_property):
        """A seeded /etc override shows up in info --files with source=etc."""
        record_property("cell", "info/container")
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        editor = _put_editor(
            target,
            "#!/bin/sh\nprintf '#!/bin/sh\\necho clitest-hook\\n' > \"$1\"\n",
        )
        _edit(target, _INIT_NAME, "testhook", editor, check=True)

        files = _control_files(target, _INIT_NAME)
        hook = next((f for f in files if f["file"] == "testhook"), None)
        assert hook is not None, f"testhook override not listed in info --files: {files}"
        assert hook["source"] == "etc", (
            f"Expected override (source=etc), got {hook['source']!r}: {hook}"
        )

    def test_info_files_lists_nested_override(self, target: Target, record_property):
        """A nested override (sub/x) is surfaced — it must not silently shadow."""
        record_property("cell", "info/container")
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        target.run(["mkdir", "-p", f"/etc/workloads.d/{_INIT_NAME}/sub"],
                   sudo=True, check=True)
        target.put_content("x\n", f"/etc/workloads.d/{_INIT_NAME}/sub/nested.conf")

        files = _control_files(target, _INIT_NAME)
        nested = next((f for f in files if f["file"] == "sub/nested.conf"), None)
        assert nested is not None, (
            f"nested override sub/nested.conf not listed in info --files: {files}"
        )
        assert nested["source"] == "etc"


# ---------------------------------------------------------------------------
# edit — control-file copy-on-write override
# ---------------------------------------------------------------------------

class TestEditOverride:
    def test_edit_seeds_executable_hook(self, target: Target, record_property):
        """edit seeds an /etc override; a shebang'd hook becomes executable even
        without a .sh suffix (so a no-extension hook is runnable)."""
        record_property("cell", "edit/container")
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        editor = _put_editor(
            target,
            "#!/bin/sh\nprintf '#!/bin/sh\\necho clitest-hook\\n' > \"$1\"\n",
        )
        _edit(target, _INIT_NAME, "testhook", editor, check=True)

        ov = f"/etc/workloads.d/{_INIT_NAME}/testhook"
        assert target.remote_path_exists(ov), f"override {ov} not seeded"
        # Shebang content with no .sh suffix must still be chmod +x.
        assert target.run(["test", "-x", ov], sudo=True, check=False).rc == 0, (
            f"seeded shebang hook {ov} is not executable"
        )

    def test_edit_refuses_symlink_escape(self, target: Target, record_property):
        """A pre-planted symlink component must not let edit write outside the
        override tree (no write to the /tmp sentinel)."""
        record_property("cell", "edit/container")
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        # Ensure the override base exists, then plant `escape` -> /tmp.
        target.run(["mkdir", "-p", f"/etc/workloads.d/{_INIT_NAME}"],
                   sudo=True, check=True)
        target.run(["ln", "-sfn", "/tmp", f"/etc/workloads.d/{_INIT_NAME}/escape"],
                   sudo=True, check=True)
        target.run(["rm", "-f", _ESCAPE_LEAK], sudo=True, check=False)

        # EDITOR=/bin/true would write nothing anyway; the point is the symlink
        # guard rejects *before* any write, so edit exits non-zero …
        r = _edit(target, _INIT_NAME,
                  f"escape/{_ESCAPE_LEAK.split('/')[-1]}", "/bin/true", check=False)
        assert r.rc != 0, "edit through a symlinked component should be rejected"
        # … and nothing leaked through the link.
        assert not target.remote_path_exists(_ESCAPE_LEAK), (
            f"WRITE LEAKED through symlink to {_ESCAPE_LEAK}"
        )


# ---------------------------------------------------------------------------
# build — graceful refusal when there is nothing to build
# ---------------------------------------------------------------------------

class TestBuild:
    def test_build_pull_only_bundle_refuses_cleanly(self, target: Target, record_property):
        """build on a workload that pulls a published image exits non-zero with a
        clear message — not a crash."""
        record_property("cell", "build/container")
        target.wl(f"init {_TEST_BUNDLE} --as {_INIT_NAME}", check=True)
        r = target.wl(f"build {_INIT_NAME}", check=False)
        assert r.rc != 0, "build of a pull-only bundle should refuse (non-zero)"
        out = (r.stdout + r.stderr).lower()
        assert "nothing to build" in out or "pulls a published" in out, (
            f"build refusal lacked a clear message:\n{r.stdout}\n{r.stderr}"
        )
        assert "traceback" not in out, f"build crashed with a traceback:\n{r.stderr}"


# ---------------------------------------------------------------------------
# bundle-traversal guard (a [workload] bundle = "../.." must not escape)
# ---------------------------------------------------------------------------

_BAD_BUNDLE_TOML = """\
[workload]
name = "clitest-bundle-badb"
bundle = "../../etc/evil"
enabled = false

[container]
image = "localhost/x:latest"
pull = "never"
"""


class TestBadBundle:
    def test_info_files_rejects_traversal_bundle(self, target: Target, record_property):
        """info --files on a `..`-laden bundle fails closed with a clear error."""
        record_property("cell", "info/container")
        _put_workload(target, _BAD_NAME, _BAD_BUNDLE_TOML)
        r = target.wl(f"info {_BAD_NAME} --files", check=False)
        assert r.rc != 0, "info --files should reject a traversal bundle"
        err = (r.stdout + r.stderr).lower()
        assert "bundle" in err and "invalid" in err, (
            f"traversal-bundle error was not clear:\n{r.stdout}\n{r.stderr}"
        )

    def test_diagnose_no_traceback_on_bad_bundle(self, target: Target, record_property):
        """diagnose must not crash with a Python traceback on a bad bundle."""
        record_property("cell", "diagnose/container")
        _put_workload(target, _BAD_NAME, _BAD_BUNDLE_TOML)
        r = target.wl(f"diagnose {_BAD_NAME}", check=False)
        assert "traceback" not in (r.stdout + r.stderr).lower(), (
            f"diagnose crashed on a bad bundle:\n{r.stdout}\n{r.stderr}"
        )
