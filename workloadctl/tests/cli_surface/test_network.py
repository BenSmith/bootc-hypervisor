"""
test_network.py — network create verb.

Covers: network <name> create <workload>

Side-effect: the podman network is visible in `podman network ls` as the
workload user.
"""

import json

import pytest

from target import Target


# ---------------------------------------------------------------------------
# network create
# ---------------------------------------------------------------------------

class TestNetworkCreate:
    @pytest.mark.mutating
    def test_network_create_for_workload(self, target, clitest_single, record_property):
        """network create: creates a podman network as the workload user."""
        record_property("cell", "network/container")
        net_name = "clitest-testnet"

        r = target.wl(
            f"network {net_name} create {clitest_single}",
            check=True, timeout=30,
        )
        assert r.rc == 0
        assert "Traceback" not in r.stderr

        # Verify the network exists for the workload user
        # Get the workload's UID
        uid_r = target.wl(f"uid-map --json {clitest_single}", check=False)
        uid = None
        if uid_r.rc == 0:
            try:
                data = json.loads(uid_r.stdout)
                uid_val = data.get("host_uid")
                if uid_val:
                    uid = int(uid_val)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                pass

        if uid is not None:
            username = f"_wl-{clitest_single}"
            # Run podman as the workload user. sudo's `-E KEY=VAL` form does not
            # exist; set the env via `env` in the target command instead.
            r2 = target.run(
                ["sudo", "-n", "-u", username, "env",
                 f"XDG_RUNTIME_DIR=/run/user/{uid}",
                 f"HOME=/var/lib/workloads/{clitest_single}",
                 "podman", "network", "ls", "--format", "{{.Name}}"],
                sudo=False, check=False,
            )
            assert net_name in r2.stdout, (
                f"Network {net_name!r} not found in workload user's networks: {r2.stdout}"
            )

    @pytest.mark.mutating
    def test_network_create_bridge_workload(self, target, clitest_bridge, record_property):
        """network create for a bridge-mode workload."""
        record_property("cell", "network/container/bridge")
        net_name = "clitest-bridgenet"
        r = target.wl(
            f"network {net_name} create {clitest_bridge}",
            check=True, timeout=30,
        )
        assert r.rc == 0
        assert "Traceback" not in r.stderr

    def test_network_create_missing_workload_fails(self, target, record_property):
        """network create on a nonexistent workload fails cleanly."""
        record_property("cell", "network/error")
        r = target.wl(
            "network testnet create clitest-doesnotexist-xxx",
            check=False, timeout=15,
        )
        assert r.rc != 0
        assert "Traceback" not in r.stderr
