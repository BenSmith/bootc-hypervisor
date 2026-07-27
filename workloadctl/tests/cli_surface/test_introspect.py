"""
test_introspect.py — read-only introspection verbs.

Covers: list, info, status, health, diagnose, validate, drift, logs, stats.
Port and uid-map data are tested via `info --json` (network.accessible_at,
user.subuid). VM substrate cells are gated on has_kvm and marked slow.
"""

import json
import time

import pytest

from conftest import skip_if_no_kvm
from fixtures import unit_state
from target import Target


def _health_json(target: Target, ref: str, retries: int = 5):
    """Run `health --json <ref>` and return the parsed dict.

    `health` can transiently print nothing to stdout right after a workload
    comes up: if it hits an internal error while the rootless user's runtime
    is still settling, workloadctl's top-level handler writes `Error: …` to
    stderr (no traceback) and exits, leaving stdout empty. That's a cold-start
    race, not a product defect — health emits valid JSON (HEALTHY or
    UNHEALTHY) once it can complete. Poll briefly for parseable output rather
    than letting a bare json.loads('') raise an opaque JSONDecodeError.
    """
    last = None
    for _ in range(retries):
        r = target.wl(f"health --json {ref}", sudo=False, check=False)
        assert "Traceback" not in r.stderr, f"health crashed: {r.stderr}"
        if r.stdout.strip():
            try:
                return json.loads(r.stdout)
            except json.JSONDecodeError:
                pass
        last = r
        time.sleep(2)
    assert last is not None
    raise AssertionError(
        f"health --json {ref} never produced parseable JSON; "
        f"last stdout={last.stdout!r} stderr={last.stderr!r}"
    )


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

class TestList:
    def test_list_plain(self, target, record_property):
        record_property("cell", "list/any")
        r = target.wl("list", sudo=False, check=True)
        assert r.rc == 0

    def test_list_json(self, target, record_property):
        record_property("cell", "list/any")
        r = target.wl("list --json", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "workloads" in data
        assert isinstance(data["workloads"], list)
        # Each entry has required fields
        for wl in data["workloads"]:
            for field in ("name", "kind", "enabled", "mode"):
                assert field in wl, f"Missing field {field!r} in workload entry"

    def test_list_shows_workload(self, target, clitest_single, record_property):
        record_property("cell", "list/container")
        r = target.wl("list --json", sudo=False, check=True)
        data = json.loads(r.stdout)
        names = [w["name"] for w in data["workloads"]]
        assert clitest_single in names




# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

class TestStatus:
    def test_status_all_plain(self, target, record_property):
        """status without args delegates to list (no error)."""
        record_property("cell", "status/any")
        r = target.wl("status", sudo=False, check=True)
        assert r.rc == 0

    def test_status_single(self, target, clitest_single, record_property):
        record_property("cell", "status/container")
        r = target.wl(f"status {clitest_single}", sudo=False, check=True)
        assert r.rc == 0

    def test_status_json_single(self, target, clitest_single, record_property):
        record_property("cell", "status/container")
        r = target.wl(f"status --json {clitest_single}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert data["workload"] == clitest_single
        assert "state" in data
        assert "service" in data

    def test_status_json_shape(self, target, clitest_single, record_property):
        record_property("cell", "status/container")
        r = target.wl(f"status --json {clitest_single}", sudo=False, check=True)
        data = json.loads(r.stdout)
        for key in ("workload", "service", "state", "enabled"):
            assert key in data

    def test_status_running_workload_is_active(self, target, clitest_single, record_property):
        record_property("cell", "status/container")
        r = target.wl(f"status --json {clitest_single}", sudo=False, check=True)
        data = json.loads(r.stdout)
        assert data["state"] == "active", f"Expected active, got: {data['state']}"

    def test_status_pod(self, target, clitest_pod, record_property):
        record_property("cell", "status/container/pod")
        r = target.wl(f"status --json {clitest_pod}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert data["state"] == "active"
        assert "containers" in data  # multi-container fields present

    def test_status_bridge(self, target, clitest_bridge, record_property):
        record_property("cell", "status/container/bridge")
        r = target.wl(f"status --json {clitest_bridge}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert data["state"] == "active"

    @pytest.mark.vm
    @pytest.mark.slow
    def test_status_vm(self, target, clitest_vm, record_property):
        record_property("cell", "status/vm")
        r = target.wl(f"status --json {clitest_vm}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert data["state"] == "active"


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

class TestInfo:
    def test_info_plain(self, target, clitest_single, record_property):
        record_property("cell", "info/container")
        r = target.wl(f"info {clitest_single}", sudo=False, check=True)
        assert r.rc == 0

    def test_info_json(self, target, clitest_single, record_property):
        record_property("cell", "info/container")
        r = target.wl(f"info --json {clitest_single}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert data["workload"]["name"] == clitest_single
        assert "user" in data
        assert "service" in data

    def test_info_json_pod(self, target, clitest_pod, record_property):
        record_property("cell", "info/container/pod")
        r = target.wl(f"info --json {clitest_pod}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        # A pod-mode workload must report its member containers as a list.
        assert isinstance(data.get("containers"), list), (
            f"pod info should list containers, got: {data.get('containers')!r}"
        )
        assert len(data["containers"]) >= 2, (
            f"clitest-pod has 2 containers, info reported: {data['containers']}"
        )

    @pytest.mark.vm
    @pytest.mark.slow
    def test_info_vm(self, target, clitest_vm, record_property):
        record_property("cell", "info/vm")
        r = target.wl(f"info --json {clitest_vm}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "vm" in data
        assert data["workload"]["name"] == clitest_vm


# ---------------------------------------------------------------------------
# ports (via info)
# ---------------------------------------------------------------------------

class TestPorts:
    """Port data is surfaced through `info --json` under network.ports / network.accessible_at."""

    def test_ports_in_info_json(self, target, clitest_single, record_property):
        record_property("cell", "ports/container")
        r = target.wl(f"info --json {clitest_single}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "network" in data
        assert "ports" in data["network"]
        assert "accessible_at" in data["network"]
        assert any("19080" in p for p in data["network"]["ports"])

    def test_ports_accessible_at(self, target, clitest_single, record_property):
        record_property("cell", "ports/container")
        r = target.wl(f"info --json {clitest_single}", sudo=False, check=True)
        data = json.loads(r.stdout)
        accessible = data["network"]["accessible_at"]
        assert isinstance(accessible, list)
        assert len(accessible) > 0
        assert "host" in accessible[0]

    def test_ports_host_mode(self, target, clitest_host, record_property):
        """host-mode workload: info reports host network_mode with no mapped ports."""
        record_property("cell", "ports/container/host")
        r = target.wl(f"info --json {clitest_host}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert data["network"]["mode"] == "host"

    @pytest.mark.vm
    @pytest.mark.slow
    def test_ports_vm(self, target, clitest_vm, record_property):
        """info on a VM includes a network section (ports list may be empty — no crash)."""
        record_property("cell", "ports/vm")
        r = target.wl(f"info --json {clitest_vm}", check=False)
        assert r.rc == 0, f"info crashed on VM (rc={r.rc}): {r.stderr}"
        assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_single(self, target, clitest_single, record_property):
        record_property("cell", "health/container")
        r = target.wl(f"health {clitest_single}", sudo=False, check=False)
        # Healthy or unhealthy — just must not crash and must parse
        assert "Traceback" not in r.stderr

    def test_health_json_single(self, target, clitest_single, record_property):
        record_property("cell", "health/container")
        data = _health_json(target, clitest_single)
        assert "workload" in data
        assert "overall" in data
        assert "checks" in data

    def test_health_pod(self, target, clitest_pod, record_property):
        record_property("cell", "health/container/pod")
        data = _health_json(target, clitest_pod)
        assert data["overall"] in ("HEALTHY", "UNHEALTHY")

    @pytest.mark.vm
    @pytest.mark.slow
    def test_health_vm(self, target, clitest_vm, record_property):
        record_property("cell", "health/vm")
        r = target.wl(f"health --json {clitest_vm}", sudo=False, check=False)
        assert "Traceback" not in r.stderr, f"health crashed on VM: {r.stderr}"
        data = json.loads(r.stdout)
        assert "overall" in data


# ---------------------------------------------------------------------------
# uid-map (via info)
# ---------------------------------------------------------------------------

class TestUidMap:
    """UID/subuid data is surfaced through `info --json` under user.uid / user.subuid."""

    def test_uid_in_info_json(self, target, clitest_single, record_property):
        record_property("cell", "uid-map/container")
        r = target.wl(f"info --json {clitest_single}", check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "user" in data
        assert "uid" in data["user"]
        assert data["user"]["uid"] is not None

    def test_subuid_in_info_json(self, target, clitest_single, record_property):
        record_property("cell", "uid-map/container")
        r = target.wl(f"info --json {clitest_single}", check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "subuid" in data["user"]
        assert "subgid" in data["user"]
        assert data["user"]["subuid"]["start"] is not None


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

class TestValidate:
    def test_validate_single(self, target, clitest_single, record_property):
        record_property("cell", "validate/container")
        r = target.wl(f"validate {clitest_single}", check=True)
        assert r.rc == 0

    def test_validate_json(self, target, clitest_single, record_property):
        record_property("cell", "validate/container")
        r = target.wl(f"validate --json {clitest_single}", check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "errors" in data or "valid" in str(data) or "checks" in data

    def test_validate_broken(self, target, clitest_broken, record_property):
        """validate on a broken TOML must fail cleanly (no traceback)."""
        record_property("cell", "validate/broken")
        r = target.wl(f"validate {clitest_broken}", check=False)
        # Must exit nonzero
        assert r.rc != 0, "validate should fail on broken TOML"
        # Must not produce a traceback
        assert "Traceback" not in r.stderr, f"validate raised unhandled exception: {r.stderr}"

    def test_validate_all(self, target, clitest_single, record_property):
        record_property("cell", "validate/any")
        r = target.wl("validate --all", check=False)
        # May exit nonzero if any workload has issues; just must not crash
        assert "Traceback" not in r.stderr

    @pytest.mark.vm
    @pytest.mark.slow
    def test_validate_vm(self, target, clitest_vm, record_property):
        record_property("cell", "validate/vm")
        r = target.wl(f"validate {clitest_vm}", check=True)
        assert r.rc == 0


# ---------------------------------------------------------------------------
# diagnose
# ---------------------------------------------------------------------------

class TestDiagnose:
    def test_diagnose_single(self, target, clitest_single, record_property):
        record_property("cell", "diagnose/container")
        r = target.wl(f"diagnose {clitest_single}", check=False)
        # diagnose may exit nonzero (not fully provisioned), but must not crash
        assert "Traceback" not in r.stderr

    def test_diagnose_json(self, target, clitest_single, record_property):
        record_property("cell", "diagnose/container")
        r = target.wl(f"diagnose --json {clitest_single}", check=False)
        assert "Traceback" not in r.stderr
        data = json.loads(r.stdout)
        assert isinstance(data, dict)

    def test_diagnose_broken(self, target, clitest_broken, record_property):
        """diagnose on broken TOML must fail cleanly."""
        record_property("cell", "diagnose/broken")
        r = target.wl(f"diagnose {clitest_broken}", check=False)
        assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

class TestDoctor:
    """`doctor` is the aggregate an operator runs when something is already
    wrong, and almost all of its input is host state — this boot's generator
    journal lines, live unit properties, drift computed by re-running the
    generator, health. A unit test has to mock away the entire subject, so this
    rung is the only place its behaviour against a real host is observable.
    """

    def test_doctor_reports_on_a_live_workload(self, target, clitest_single,
                                               record_property):
        """doctor produces a real report and exits on its documented ladder.

        rc 0 means healthy and 1 means problems found, so both are legitimate
        here and the exit code alone would not show the command did any work.
        Asserting the main unit appears in the report is what proves it actually
        inspected the host rather than bailing early.
        """
        record_property("cell", "doctor/container")
        r = target.wl(f"doctor {clitest_single}", check=False, timeout=120)
        assert "Traceback" not in r.stderr, f"doctor crashed: {r.stderr}"
        assert r.rc in (0, 1), (
            f"doctor exited {r.rc}, outside its documented 0-healthy/1-problems "
            f"ladder: {r.stderr}"
        )
        assert f"workload-{clitest_single}.service" in r.stdout, (
            f"doctor reported no unit rows for {clitest_single}; it did not "
            f"inspect the host:\n{r.stdout}"
        )

    def test_doctor_does_not_change_state(self, target, clitest_single,
                                          record_property):
        """doctor is read-only — running it must not disturb the workload.

        It reaches deep into live state (drift regenerates units to compare, and
        health can shell out to the runtime), so "read-only" is a property that
        could quietly stop holding. An operator runs this *while* debugging a
        production workload; restarting it under them would be its own outage.
        """
        record_property("cell", "doctor/container")
        before = unit_state(target, f"workload-{clitest_single}.service")
        target.wl(f"doctor {clitest_single}", check=False, timeout=120)
        after = unit_state(target, f"workload-{clitest_single}.service")
        assert before == after, (
            f"doctor changed {clitest_single} from {before!r} to {after!r}"
        )

    def test_doctor_broken_toml_fails_cleanly(self, target, clitest_broken,
                                              record_property):
        """doctor on an unparseable config reports the fault, not a traceback."""
        record_property("cell", "doctor/broken")
        r = target.wl(f"doctor {clitest_broken}", check=False, timeout=60)
        assert "Traceback" not in r.stderr, f"doctor crashed: {r.stderr}"
        assert r.rc != 0, "doctor exited 0 on an invalid workload config"


# ---------------------------------------------------------------------------
# drift
# ---------------------------------------------------------------------------

class TestDrift:
    def test_drift_no_crash(self, target, clitest_single, record_property):
        """drift exits 0 (no drift) or 1 (drift detected) but never crashes."""
        record_property("cell", "drift/container")
        r = target.wl(f"drift {clitest_single}", check=False)
        assert r.rc in (0, 1), f"drift exited {r.rc}: {r.stderr}"
        assert "Traceback" not in r.stderr

    def test_drift_json(self, target, clitest_single, record_property):
        record_property("cell", "drift/container")
        r = target.wl(f"drift --json {clitest_single}", check=False)
        assert r.rc in (0, 1)
        assert "Traceback" not in r.stderr
        data = json.loads(r.stdout)
        assert "drifted" in data
        assert "units" in data

    def test_drift_all(self, target, clitest_single, record_property):
        record_property("cell", "drift/any")
        r = target.wl("drift", check=False)
        assert r.rc in (0, 1)
        assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------

class TestLogs:
    def test_logs_single(self, target, clitest_single, record_property):
        record_property("cell", "logs/container")
        r = target.wl(f"logs -n 10 {clitest_single}", sudo=False, check=True)
        assert r.rc == 0
        assert "Traceback" not in r.stderr

    def test_logs_pod_container(self, target, clitest_pod, record_property):
        """logs for a specific container in a pod-mode workload."""
        record_property("cell", "logs/container/pod")
        r = target.wl(f"logs -n 5 {clitest_pod}/app", sudo=False, check=True)
        assert r.rc == 0

    def test_logs_bridge_container(self, target, clitest_bridge, record_property):
        record_property("cell", "logs/container/bridge")
        r = target.wl(f"logs -n 5 {clitest_bridge}/proxy", sudo=False, check=True)
        assert r.rc == 0

    @pytest.mark.vm
    @pytest.mark.slow
    def test_logs_vm(self, target, clitest_vm, record_property):
        record_property("cell", "logs/vm")
        r = target.wl(f"logs -n 10 {clitest_vm}", sudo=False, check=True)
        assert r.rc == 0


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_container(self, target, clitest_single, record_property):
        record_property("cell", "stats/container")
        r = target.wl(f"stats {clitest_single}", check=True)
        assert r.rc == 0
        assert "Traceback" not in r.stderr

    def test_stats_json_container(self, target, clitest_single, record_property):
        record_property("cell", "stats/container")
        r = target.wl(f"stats --json {clitest_single}", check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "stats" in data

    def test_stats_vm(self, target, clitest_vm, record_property):
        """stats on a VM: exit 0, sourced from QMP.

        VMSubstrate.resource_usage reads the VM's qmp-metrics.sock, so a running
        VM gets a usage table. A VM that isn't up has no socket to read, which is
        a NotApplicable — cmd_stats reports it and still exits 0. Either outcome
        is correct here; an unhandled exception or a nonzero exit is not.
        """
        record_property("cell", "stats/vm")
        skip_if_no_kvm(target)
        r = target.wl(f"stats {clitest_vm}", check=False)
        assert r.rc == 0, (
            f"stats on VM should exit 0, got rc={r.rc}\nstderr: {r.stderr}"
        )
        assert "Traceback" not in r.stderr, "stats raised unhandled exception on VM"
        combined = (r.stdout + r.stderr).lower()
        assert "mem usage" in combined or "not applicable" in combined, (
            f"stats on VM printed neither a usage table nor a not-applicable "
            f"message:\n{combined}"
        )


# ---------------------------------------------------------------------------
# images
# ---------------------------------------------------------------------------

class TestImages:
    def test_images_list_plain(self, target, clitest_single, record_property):
        record_property("cell", "images/container")
        r = target.wl("images", check=True)
        assert r.rc == 0

    def test_images_list_json(self, target, clitest_single, record_property):
        record_property("cell", "images/container")
        r = target.wl("images --json", check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "images" in data

    def test_images_vm_finding(self, target, clitest_vm, record_property):
        """images on a VM substrate: scrutinize for crashes (finding cell).

        cmd_images iterates workload users and calls podman on each.
        A VM workload user exists but no container — it may crash trying
        to call config.image on a VM config. Document the behavior.
        """
        record_property("cell", "images/vm")
        skip_if_no_kvm(target)
        r = target.wl("images --json", check=False)
        if r.rc != 0:
            # A traceback or error here is a finding (workloadctl bug)
            assert "Traceback" not in r.stderr, (
                f"FINDING: images crashes with VM workload present: {r.stderr[:500]}"
            )
        else:
            data = json.loads(r.stdout)
            assert "images" in data
