"""
test_introspect.py — read-only introspection verbs.

Covers: list, ps, info, status, ports, health, uid-map, verify, validate, drift, logs, stats.

Each verb is exercised against every applicable topology; VM substrate cells
are gated on has_kvm and marked slow.
"""

import json

import pytest

from conftest import skip_if_no_kvm
from target import Target


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
# ps
# ---------------------------------------------------------------------------

class TestPs:
    def test_ps_plain(self, target, clitest_single, record_property):
        record_property("cell", "ps/container")
        r = target.wl("ps", sudo=False, check=True)
        assert r.rc == 0

    def test_ps_json(self, target, clitest_single, record_property):
        record_property("cell", "ps/container")
        r = target.wl("ps --json", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "containers" in data
        assert isinstance(data["containers"], list)

    def test_ps_shows_running_container(self, target, clitest_single, record_property):
        record_property("cell", "ps/container")
        r = target.wl("ps --json", sudo=False, check=True)
        data = json.loads(r.stdout)
        # At least one container should be running for our enabled workload
        running_names = [c.get("name", "") for c in data["containers"]]
        assert any(clitest_single in n for n in running_names), (
            f"Expected running container for {clitest_single!r}, got: {running_names}"
        )


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
# ports
# ---------------------------------------------------------------------------

class TestPorts:
    def test_ports_plain(self, target, clitest_single, record_property):
        record_property("cell", "ports/container")
        r = target.wl(f"ports {clitest_single}", sudo=False, check=True)
        assert r.rc == 0
        assert "19080" in r.stdout

    def test_ports_json(self, target, clitest_single, record_property):
        record_property("cell", "ports/container")
        r = target.wl(f"ports --json {clitest_single}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "ports" in data
        assert "workload" in data

    def test_ports_host_mode(self, target, clitest_host, record_property):
        """host-mode workload: ports verb returns correct network_mode."""
        record_property("cell", "ports/container/host")
        r = target.wl(f"ports --json {clitest_host}", sudo=False, check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert data["network_mode"] == "host"

    @pytest.mark.vm
    @pytest.mark.slow
    def test_ports_vm(self, target, clitest_vm, record_property):
        """ports on a VM — exits 0 (no crash), returns a parseable result.

        VMs don't have published ports in the container sense; the verb reads
        the TOML and returns an empty ports list. It must not crash.
        """
        record_property("cell", "ports/vm")
        r = target.wl(f"ports --json {clitest_vm}", check=False)
        assert r.rc == 0, f"ports crashed on VM (rc={r.rc}): {r.stderr}"
        assert "Traceback" not in r.stderr, "ports raised an unhandled exception on VM"
        data = json.loads(r.stdout)
        assert "workload" in data


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
        r = target.wl(f"health --json {clitest_single}", sudo=False, check=False)
        assert "Traceback" not in r.stderr
        data = json.loads(r.stdout)
        assert "workload" in data
        assert "overall" in data
        assert "checks" in data

    def test_health_pod(self, target, clitest_pod, record_property):
        record_property("cell", "health/container/pod")
        r = target.wl(f"health --json {clitest_pod}", sudo=False, check=False)
        assert "Traceback" not in r.stderr
        data = json.loads(r.stdout)
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
# uid-map
# ---------------------------------------------------------------------------

class TestUidMap:
    def test_uid_map_plain(self, target, clitest_single, record_property):
        record_property("cell", "uid-map/container")
        r = target.wl(f"uid-map {clitest_single}", check=True)
        assert r.rc == 0

    def test_uid_map_json(self, target, clitest_single, record_property):
        record_property("cell", "uid-map/container")
        r = target.wl(f"uid-map --json {clitest_single}", check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "workload" in data
        assert "username" in data
        assert "host_uid" in data
        assert data["host_uid"] is not None


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
# verify
# ---------------------------------------------------------------------------

class TestVerify:
    def test_verify_single(self, target, clitest_single, record_property):
        record_property("cell", "verify/container")
        r = target.wl(f"verify {clitest_single}", check=False)
        # verify may exit nonzero (not fully provisioned), but must not crash
        assert "Traceback" not in r.stderr

    def test_verify_json(self, target, clitest_single, record_property):
        record_property("cell", "verify/container")
        r = target.wl(f"verify --json {clitest_single}", check=False)
        assert "Traceback" not in r.stderr
        data = json.loads(r.stdout)
        # verify returns a dict with checks
        assert isinstance(data, dict)

    def test_verify_broken(self, target, clitest_broken, record_property):
        """verify on broken TOML must fail cleanly."""
        record_property("cell", "verify/broken")
        r = target.wl(f"verify {clitest_broken}", check=False)
        assert "Traceback" not in r.stderr


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

    def test_stats_vm_is_na(self, target, clitest_vm, record_property):
        """stats on a VM: designed-N/A, must exit 0 with a clear message.

        VMSubstrate.resource_usage raises NotApplicable; cmd_stats catches it
        and exits 0.
        """
        record_property("cell", "stats/vm")
        skip_if_no_kvm(target)
        r = target.wl(f"stats {clitest_vm}", check=False)
        assert r.rc == 0, (
            f"stats on VM should exit 0 (designed-N/A), got rc={r.rc}\n"
            f"stderr: {r.stderr}"
        )
        assert "Traceback" not in r.stderr, "stats raised unhandled exception on VM"
        # Should mention "not applicable"
        combined = r.stdout + r.stderr
        assert "not applicable" in combined.lower() or "vm" in combined.lower()


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
