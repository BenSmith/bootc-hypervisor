"""
conftest.py — pytest configuration for the CLI-surface acceptance harness.

Options:
  --target  SSH destination (e.g. user@host) or "local" — required
  --deploy  rsync+rpm-install the local workloadctl tree before testing
  --key-type  secret key type: auto (default), tpm2, host
"""

import json
import os
import subprocess
import time

import pytest

from target import Target


# Register the workload-provisioning fixtures. pytest only auto-discovers
# fixtures in conftest.py, test modules, and plugins — a bare fixtures.py is
# never imported on its own. Star-importing it here pulls every clitest_*
# fixture into the conftest namespace, where pytest registers them. fixtures.py
# is self-contained (it does NOT import from conftest) so there is no cycle;
# the skip helpers it defines are re-exported below for tests that import them.
from fixtures import *  # noqa: E402,F401,F403


# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    parser.addoption(
        "--target",
        default=None,
        help="SSH destination of the system under test (e.g. user@host), or 'local'. "
             "Required to run tests; collection/introspection works without it.",
    )
    parser.addoption(
        "--deploy",
        action="store_true",
        default=False,
        help="Rsync workloadctl tree to target and rpm-install before testing",
    )
    parser.addoption(
        "--key-type",
        default="auto",
        choices=["auto", "tpm2", "host", "host+tpm2"],
        help="Secret encryption key type (default: auto = tpm2 if available, else host)",
    )


# ---------------------------------------------------------------------------
# Markers
# ---------------------------------------------------------------------------

def pytest_configure(config):
    config.addinivalue_line("markers", "container: tests that exercise the container substrate")
    config.addinivalue_line("markers", "vm: tests that require VM substrate (needs has_kvm)")
    config.addinivalue_line("markers", "slow: tests that take a long time (VM boot, image pull)")
    config.addinivalue_line("markers", "interactive: tests that exercise interactive/pty verbs (smoke-grade)")
    config.addinivalue_line("markers", "mutating: tests that modify workload state")
    config.addinivalue_line("markers", "destructive: tests that permanently remove state")
    config.addinivalue_line("markers", "runtime: runtime-rung checks that boot a VM (--target=vm:<mode>)")


# ---------------------------------------------------------------------------
# Session-scoped Target fixture
# ---------------------------------------------------------------------------

def _keep_vm_notice(t) -> None:
    """Print (and persist) reconnect details for a WLRT_KEEP_VM guest.

    The VM and its swtpm are deliberately NOT reaped, so their run dir (holding
    the ephemeral ssh key) survives for manual inspection. pytest may capture
    stdout at teardown, so the same notice is written to ~/wlrt-keep-vm.txt."""
    swtpm_pid = getattr(t, "_swtpm_pid_path", None)
    poweroff = f"kill $(cat {t._pid_path})"
    if swtpm_pid:
        poweroff += f" $(cat {swtpm_pid})"
    poweroff += f" 2>/dev/null; rm -rf {t._run_dir}"
    msg = "\n".join([
        "",
        "=" * 72,
        "WLRT_KEEP_VM set — guest left RUNNING for inspection (not powered off).",
        f"  connect:  {t.connect_hint()}",
        f"  run dir:  {t._run_dir}",
        f"  teardown: {poweroff}",
        "=" * 72,
        "",
    ])
    print(msg)
    try:
        with open(os.path.expanduser("~/wlrt-keep-vm.txt"), "w") as f:
            f.write(msg + "\n")
    except OSError:
        pass


@pytest.fixture(scope="session")
def target(request) -> Target:
    """Construct and yield the Target; handle optional --deploy.

    `--target=vm:<mode>` (dev|gate) boots a harness-owned VM via the runtime
    launcher and yields a VMTarget; every other dest is the existing
    hand-provisioned `user@host`/`local` path, unchanged."""
    dest = request.config.getoption("--target")
    if not dest:
        pytest.exit(
            "--target is required to run the CLI-surface harness "
            "(e.g. --target=user@host or --target=local).",
            returncode=3,
        )

    if dest.startswith("vm:"):
        mode = dest.split(":", 1)[1]
        # Import the launcher lazily so normal (user@host/local) runs never
        # touch the runtime layer.
        import sys
        from pathlib import Path
        runtime_dir = Path(__file__).parent.parent / "runtime"
        if str(runtime_dir) not in sys.path:
            sys.path.insert(0, str(runtime_dir))
        import vmlaunch

        missing = vmlaunch.missing_prereqs(mode)
        if missing:
            pytest.skip(
                f"runtime harness ({dest}) needs: {', '.join(missing)} "
                "— skipping (default-safe on a box without KVM/QEMU)"
            )
        # 4 GiB by default (override WLRT_MEM_MIB): the B6 VM-workload smoke runs
        # a *nested* guest inside this one, which needs headroom beyond the bootc
        # host + podman. Harmless surplus for the other runtime checks.
        mem_mib = int(os.environ.get("WLRT_MEM_MIB", "4096"))
        t = vmlaunch.launch(mode, mem_mib=mem_mib)
        if os.environ.get("WLRT_KEEP_VM"):
            # Leave the guest (and swtpm) running so a failed run can be
            # inspected live instead of being reaped in teardown.
            request.addfinalizer(lambda: _keep_vm_notice(t))
        else:
            request.addfinalizer(t.poweroff)
        yield t
        return

    t = Target.from_dest(dest)

    # Validate connectivity
    r = t.run(["echo", "ping"], sudo=False, check=False)
    if r.rc != 0:
        pytest.exit(
            f"Cannot reach target {dest!r}: {r.stderr.strip()}\n"
            "Check that SSH works and the target is reachable.",
            returncode=3,
        )

    # Optional deploy step
    if request.config.getoption("--deploy"):
        _deploy_workloadctl(t)

    yield t
    t.close()


@pytest.fixture
def reset_vm(target):
    """Revert a VMTarget to its clean `base` snapshot before the test.

    A no-op for a plain Target (hand-provisioned host has no free reset), so the
    same runtime check module can run against either without change."""
    revert = getattr(target, "revert", None)
    if callable(revert):
        target.revert("base")
    yield


def _deploy_workloadctl(t: Target):
    """Rsync the local workloadctl tree to ~/clitest-src/workloadctl/ and rpm-install."""
    from pathlib import Path

    # Find repo root relative to this file
    harness_dir = Path(__file__).parent
    repo_root = harness_dir.parents[2]  # cli_surface -> tests -> workloadctl -> repo
    workloadctl_src = repo_root / "workloadctl"

    if not workloadctl_src.exists():
        pytest.exit(f"Could not find workloadctl source at {workloadctl_src}", returncode=3)

    dest = t.dest
    target_dir = "~/clitest-src/workloadctl/"

    print(f"\nDeploying workloadctl to {dest}:{target_dir} ...")
    rsync_cmd = [
        "rsync", "-av", "--delete",
        "--exclude=rpmbuild/",
        "--exclude=__pycache__/",
        "--exclude=*.pyc",
        "--exclude=.pytest_cache/",
        "--exclude=tests/cli_surface/",  # don't rsync ourselves into clitest-src
        str(workloadctl_src) + "/",
        f"{dest}:{target_dir}",
    ]
    result = subprocess.run(rsync_cmd, capture_output=False)
    if result.returncode != 0:
        pytest.exit("rsync failed", returncode=3)

    print("Running just rpm-install on target ...")
    r = t.run(
        ["bash", "-c", "cd ~/clitest-src/workloadctl && just rpm-install"],
        sudo=False, check=False, timeout=300,
    )
    if r.rc != 0:
        pytest.exit(f"rpm-install failed: {r.stderr[:1000]}", returncode=3)
    print("Deploy complete.")


# ---------------------------------------------------------------------------
# Secret key type
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def key_type(request, target) -> str:
    """Resolve the --key-type option (auto → tpm2 if available, else host)."""
    kt = request.config.getoption("--key-type")
    if kt == "auto":
        return "tpm2" if target.capabilities["has_tpm2"] else "host"
    return kt


# ---------------------------------------------------------------------------
# Session-start purge (idempotency)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def purge_stray_clitest_workloads(target):
    """Purge any clitest-* workloads left over from prior runs.

    Runs once at session start so back-to-back runs are clean.
    """
    _purge_all_clitest(target)
    yield
    # Also purge at session end so no residue is left
    _purge_all_clitest(target)


def _purge_all_clitest(target: Target):
    """Disable --purge all clitest-* workloads and remove their TOML files."""
    # List currently configured clitest workloads
    r = target.wl("list --json", check=False)
    if r.rc != 0 or not r.stdout.strip():
        # workloadctl not installed or no workloads — still try to clean files
        _remove_clitest_tomls(target)
        return

    try:
        data = json.loads(r.stdout)
        workloads = data.get("workloads", [])
    except (json.JSONDecodeError, KeyError):
        workloads = []

    clitest = [w["name"] for w in workloads if w["name"].startswith("clitest-")]

    for name in clitest:
        # Stop service first (ignore errors)
        target.wl(f"disable --purge {name}", check=False)
        time.sleep(0.5)

    _remove_clitest_tomls(target)


def _remove_clitest_tomls(target: Target):
    """Remove any leftover clitest-* workload configs.

    Step-2 layout puts each workload in /etc/workloads.d/<name>/workload.toml, so
    remove the whole clitest-* subdir. Also sweep any stray flat clitest-*.toml
    left by a pre-flip run.
    """
    r = target.run(
        ["bash", "-c",
         "ls -d /etc/workloads.d/clitest-* 2>/dev/null || true"],
        sudo=False, check=False,
    )
    paths = [p.strip() for p in r.stdout.strip().splitlines() if p.strip()]
    for p in paths:
        target.run(["rm", "-rf", p], sudo=True, check=False)


# Capability-gate skip helpers (skip_if_no_kvm / skip_if_no_br0) live in
# fixtures.py and are re-exported into this namespace via `from fixtures import
# *` above, so `from conftest import skip_if_no_kvm` keeps working.


# ---------------------------------------------------------------------------
# Matrix tracking (record_property integration)
# ---------------------------------------------------------------------------

# Each item stores (cell, outcome) where cell = "verb/substrate"
_MATRIX: list[tuple[str, str]] = []


@pytest.fixture(autouse=True)
def _record_matrix_cell(request, record_property):
    """After each test, record its cell(s) and outcome in the global matrix."""
    yield
    # A test declares its cell(s) via record_property("cell", "verb/substrate").
    # A single test may legitimately span more than one cell (e.g. the VM
    # update→rollback test), so record every declared cell, not just the last.
    cells = [val for key, val in request.node.user_properties if key == "cell"]
    if not cells:
        return

    rep = request.node.rep_call if hasattr(request.node, "rep_call") else None
    if rep is None:
        outcome = "SKIP"
    elif rep.passed:
        outcome = "PASS"
    elif rep.skipped:
        outcome = "SKIP"
    else:
        outcome = "FAIL"

    for cell in cells:
        _MATRIX.append((cell, outcome))


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Attach the call report to the node for access in fixtures."""
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)


# ---------------------------------------------------------------------------
# Terminal summary: verb × substrate matrix + findings
# ---------------------------------------------------------------------------

def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print verb × substrate matrix at the end of the session."""
    if not _MATRIX:
        return

    # Collect all verbs and substrates
    verbs_set = set()
    subs_set = set()
    results: dict[tuple, str] = {}

    for cell, outcome in _MATRIX:
        if "/" in cell:
            verb, sub = cell.split("/", 1)
        else:
            verb, sub = cell, "unknown"
        verbs_set.add(verb)
        subs_set.add(sub)
        # Last outcome wins (in case of reruns)
        results[(verb, sub)] = outcome

    verbs = sorted(verbs_set)
    subs = sorted(subs_set)

    # Print matrix
    terminalreporter.write_sep("=", "verb × substrate matrix")
    verb_w = max(len(v) for v in verbs) + 2
    col_w = 8

    header = f"{'VERB':<{verb_w}}" + "".join(f"{s:<{col_w}}" for s in subs)
    terminalreporter.write_line(header)
    terminalreporter.write_line("-" * len(header))

    for verb in verbs:
        row = f"{verb:<{verb_w}}"
        for sub in subs:
            outcome = results.get((verb, sub), "—")
            row += f"{outcome:<{col_w}}"
        terminalreporter.write_line(row)

    # Print findings
    findings = [
        (cell, outcome)
        for cell, outcome in _MATRIX
        if outcome == "FAIL"
    ]
    if findings:
        terminalreporter.write_sep("=", "findings (workloadctl bugs / unexpected failures)")
        for cell, outcome in findings:
            terminalreporter.write_line(f"  FAIL: {cell}")
        terminalreporter.write_line(
            "\n  Review each FAIL above — it may indicate a workloadctl bug "
            "(e.g. an unguarded verb crashing on the wrong substrate)."
        )
