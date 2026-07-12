#!/usr/bin/env python3
"""Acceptance-oracle safety net for the A1 generator refactor (Step 0).

Renders a fixture matrix — one minimal TOML per branch of
`generate_system_service` + the head units — through the real generator
subprocess (same invocation pattern as `test_generator.py`) and captures
every emitted `.service` unit's full text. `render_matrix()` is reused by
later refactor steps to diff before/after output: the bar is semantic
equivalence (systemd accepts the same directives), not byte-identical text.

This module owns two independent checks:
  1. A snapshot smoke test — the render harness works and produces
     plausible unit files. No golden files are committed; later steps
     supply their own before/after snapshots.
  2. A `systemd-analyze verify` gate over every emitted unit. Skipped
     cleanly when the `systemd-analyze` binary is absent (PR/CI without
     systemd). On a dev host without podman installed, `ExecStart=/usr/bin/
     podman ...` (and other libexec helpers) fail verify's "is the command
     executable" check even though the unit is syntactically valid — that
     failure mode is host-environment noise, not a generator bug, so it's
     filtered out; any other verify complaint fails the test.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from covhelper import python_cmd

GENERATOR = os.path.join(os.path.dirname(__file__), '..', 'generators', 'workload-generate')
LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')

# Messages systemd-analyze verify emits purely because THIS host is missing
# pieces the real hypervisor image ships elsewhere — not because the
# generated unit is malformed. Environment artifacts, not generator bugs;
# the same units verify clean on a host with podman + the nvidia driver
# layer installed.
#   - ExecStart*/ExecStop* command not present/executable (e.g. no podman
#     installed on a dev sandbox)
#   - nvidia-cdi-generator.service (Requires=/After=, emitted for GPU
#     workloads) is provided by the nvidia driver layer, not workloadctl
_BENIGN_VERIFY_PATTERNS = (
    re.compile(r"Command .* is not executable: No such file or directory"),
    re.compile(r"Unit nvidia-cdi-generator\.service not found"),
)


def _is_benign_verify_line(line):
    return any(pattern.search(line) for pattern in _BENIGN_VERIFY_PATTERNS)


def run_generator(config_dir, services_dir, sysusers_dir):
    """Run the generator and return the CompletedProcess."""
    env = os.environ.copy()
    env["WORKLOAD_CONFIG_DIR"] = str(config_dir)
    env["SYSUSERS_DIR"] = str(sysusers_dir)
    env["PYTHONPATH"] = LIB_DIR
    env["WORKLOAD_GENERATE_LOG_STDERR"] = "1"
    return subprocess.run(
        python_cmd(GENERATOR, str(services_dir)),
        capture_output=True, text=True, env=env,
    )


def write_config(config_dir, name, toml_content, enabled=True):
    """Write a TOML config file to the config directory."""
    (Path(config_dir) / name).mkdir(exist_ok=True)
    path = Path(config_dir) / name / "workload.toml"
    path.write_text(textwrap.dedent(toml_content))
    if enabled:
        (Path(config_dir) / name / ".enabled").touch()
    return path


# ---------------------------------------------------------------------------
# Fixture matrix (doc: "Fixture matrix (Step 0)")
#
# Each fixture is a list of (workload_name, toml_content) tuples written into
# one shared config dir and rendered with a single generator invocation —
# this lets fixtures exercise cross-workload branches (requires/after) by
# grouping two+ workload configs together.
# ---------------------------------------------------------------------------

FIXTURES = {
    # modes: single / pod / bridge
    "mode-single": [
        ("single", """\
            [workload]
            name = "single"

            [container]
            image = "docker.io/nginx:latest"

            [network]
            ports = ["8080:80"]
        """),
    ],
    "mode-pod": [
        ("podwl", """\
            [workload]
            name = "podwl"
            mode = "pod"

            [[containers]]
            name = "a"
            [containers.container]
            image = "img-a"

            [[containers]]
            name = "b"
            [containers.container]
            image = "img-b"
        """),
    ],
    "mode-bridge": [
        ("bridgewl", """\
            [workload]
            name = "bridgewl"
            mode = "bridge"

            [[containers]]
            name = "db"
            [containers.container]
            image = "postgres:16"

            [[containers]]
            name = "web"
            [containers.container]
            image = "myapp:latest"
            [containers.network]
            ports = ["3000:3000"]
        """),
    ],

    # gpu: none (covered by mode-single default), nvidia, nvidia:<uuid>, amd, auto
    "gpu-nvidia": [
        ("gpunv", """\
            [workload]
            name = "gpunv"

            [container]
            image = "cuda-app"

            [devices]
            gpu = "nvidia"

            [security]
            extra_groups = ["video"]
        """),
    ],
    "gpu-nvidia-pinned": [
        ("gpunvpin", """\
            [workload]
            name = "gpunvpin"

            [container]
            image = "cuda-app"

            [devices]
            gpu = "nvidia:GPU-b6297698-1234-5678-9abc-def012345678"

            [security]
            extra_groups = ["video"]
        """),
    ],
    "gpu-amd": [
        ("gpuamd", """\
            [workload]
            name = "gpuamd"

            [container]
            image = "rocm-app"

            [devices]
            gpu = "amd"

            [security]
            extra_groups = ["video", "render"]
        """),
    ],
    "gpu-auto": [
        ("gpuauto", """\
            [workload]
            name = "gpuauto"

            [container]
            image = "gpu-app"

            [devices]
            gpu = "auto"
        """),
    ],

    # devices: input, audio, virtualization, generic devices=[...]
    "devices-misc": [
        ("devmisc", """\
            [workload]
            name = "devmisc"

            [container]
            image = "myapp"

            [devices]
            devices = ["/dev/ttyUSB0"]
            input = true
            audio = true
            virtualization = true

            [security]
            extra_groups = ["input", "audio", "kvm", "dialout"]
        """),
    ],

    # lifecycle: pet (single-mode only; cattle is the default exercised elsewhere)
    "lifecycle-pet": [
        ("petwl", """\
            [workload]
            name = "petwl"
            lifecycle = "pet"

            [container]
            image = "myapp"
        """),
    ],

    # secrets: ${SECRET:x} env var + [secrets] files block
    "secrets": [
        ("secretwl", """\
            [workload]
            name = "secretwl"

            [container]
            image = "myapp"

            [container.environment]
            API_KEY = "${SECRET:api-key}"
            PLAIN = "visible"

            [secrets]
            files = [
                { credential = "tls-cert", path = "/etc/ssl/cert.pem", mode = "ro" }
            ]
        """),
    ],

    # security: capabilities, security_opt, selinux_policy, extra_groups
    "security-caps-selinux": [
        ("secopts", """\
            [workload]
            name = "secopts"

            [container]
            image = "myapp"

            [security]
            capabilities = ["NET_BIND_SERVICE", "CHOWN"]
            security_opt = ["no-new-privileges=true"]
            selinux_policy = true
            extra_groups = ["video", "audio"]
        """),
    ],
    "security-privileged": [
        ("privwl", """\
            [workload]
            name = "privwl"

            [container]
            image = "myapp"

            [security]
            privileged = true
        """),
    ],

    # userns modes (valid_userns_mode branches)
    "userns-keepid-remap": [
        ("userns1", """\
            [workload]
            name = "userns1"

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:uid=1000,gid=1000"
        """),
    ],
    "userns-host": [
        ("usernshost", """\
            [workload]
            name = "usernshost"

            [container]
            image = "myapp"

            [security]
            userns = "host"
            unsafe_host_userns = true
        """),
    ],

    # resources: memory_max, cpu_quota, cpu_weight, tasks_max, shm_size,
    # io_read/write_bandwidth_max, timeout_start/stop_sec, custom_directives
    "resources": [
        ("reswl", """\
            [workload]
            name = "reswl"

            [container]
            image = "myapp"

            [resources]
            memory_max = "2G"
            cpu_quota = "150%"
            cpu_weight = 200
            tasks_max = 256
            shm_size = "256m"
            io_read_bandwidth_max = ["/dev/sda 50M"]
            io_write_bandwidth_max = ["/dev/sda 20M"]
            timeout_start_sec = 120
            timeout_stop_sec = 45
            custom_directives = { Nice = "-5" }
        """),
    ],

    # network: pasta (default, with ports covered in mode-single), host, none
    "network-host": [
        ("nethost", """\
            [workload]
            name = "nethost"

            [container]
            image = "myapp"

            [network]
            mode = "host"
        """),
    ],
    "network-none": [
        ("netnone", """\
            [workload]
            name = "netnone"

            [container]
            image = "myapp"

            [network]
            mode = "none"
        """),
    ],

    # workload deps (requires/after across two workloads), container.systemd,
    # container.user, volumes
    "deps-systemd-user-volumes": [
        ("base", """\
            [workload]
            name = "base"

            [container]
            image = "alpine"
        """),
        ("dependent", """\
            [workload]
            name = "dependent"
            requires = ["base"]
            after = ["base"]

            [container]
            image = "myapp"
            user = "0"
            systemd = "always"

            [storage]
            volumes = ["./data:/app/data:rw"]
        """),
    ],
}


def _generate_fixture(fixture_id, workloads):
    """Run one fixture's workload configs through the generator.

    Returns (services_dir, result). Caller owns cleanup of config_dir,
    services_dir, sysusers_dir (all three are created here).
    """
    config_dir = tempfile.mkdtemp()
    services_dir = tempfile.mkdtemp()
    sysusers_dir = tempfile.mkdtemp()
    for name, toml_content in workloads:
        write_config(config_dir, name, toml_content)
    result = run_generator(config_dir, services_dir, sysusers_dir)
    assert result.returncode == 0, (
        f"generator exited {result.returncode} for fixture "
        f"{fixture_id!r}: {result.stderr}"
    )
    return config_dir, services_dir, sysusers_dir, result


def render_matrix():
    """Render the full fixture matrix through the real generator subprocess.

    Returns {"<fixture_id>/<unit_filename>": unit_text} for every *.service
    emitted across all fixtures. Reused by later A1 steps to diff before/after
    generator output — the bar is semantic equivalence, not byte-identity.
    """
    matrix = {}
    for fixture_id, workloads in FIXTURES.items():
        config_dir, services_dir, sysusers_dir, _ = _generate_fixture(fixture_id, workloads)
        try:
            for unit_path in sorted(Path(services_dir).glob("*.service")):
                matrix[f"{fixture_id}/{unit_path.name}"] = unit_path.read_text()
        finally:
            shutil.rmtree(config_dir)
            shutil.rmtree(services_dir)
            shutil.rmtree(sysusers_dir)
    return matrix


_UNIT_HEADER_RE = re.compile(r"^\[(Unit|Service|Install)\]", re.MULTILINE)


class TestRenderMatrixSnapshot(unittest.TestCase):
    """Snapshot smoke test: the render harness works and yields plausible units.

    No golden files are committed here — later refactor steps capture their
    own before/after snapshots via render_matrix() and diff them.
    """

    def test_render_matrix_is_nonempty_and_plausible(self):
        matrix = render_matrix()
        self.assertGreater(len(matrix), 0, "render_matrix() produced no units")
        for filename, text in matrix.items():
            self.assertTrue(
                _UNIT_HEADER_RE.search(text),
                f"{filename} doesn't look like a unit file (no [Unit]/[Service]/"
                f"[Install] header):\n{text}",
            )

    def test_every_fixture_emits_at_least_one_unit(self):
        matrix = render_matrix()
        seen_fixtures = {key.split("/", 1)[0] for key in matrix}
        missing = set(FIXTURES) - seen_fixtures
        self.assertFalse(
            missing, f"fixtures emitted no units at all: {sorted(missing)}"
        )


class TestSystemdAnalyzeVerify(unittest.TestCase):
    """Gate: systemd-analyze verify accepts every emitted unit.

    Verified one fixture at a time, all of that fixture's units together in
    their real directory (original filenames intact) — a workload's units
    reference each other by name via Requires=/BindsTo=/PartOf= (e.g. the
    umbrella Requires= its per-container units, a per-container unit
    BindsTo= its pod/net head unit), and verify actually resolves those
    against sibling files given on the command line. Flattening filenames or
    verifying units one at a time turns those real cross-refs into spurious
    "Unit ... not found" failures.
    """

    @classmethod
    def setUpClass(cls):
        cls.systemd_analyze = shutil.which("systemd-analyze")
        if cls.systemd_analyze is None:
            raise unittest.SkipTest("systemd-analyze not present on this host")

    def test_units_verify_clean(self):
        failures = []
        for fixture_id, workloads in FIXTURES.items():
            config_dir, services_dir, sysusers_dir, _ = _generate_fixture(fixture_id, workloads)
            try:
                unit_paths = sorted(Path(services_dir).glob("*.service"))
                if not unit_paths:
                    continue
                result = subprocess.run(
                    [self.systemd_analyze, "verify", *[str(p) for p in unit_paths]],
                    capture_output=True, text=True,
                )
                if result.returncode == 0:
                    continue
                stderr_lines = [
                    line for line in result.stderr.splitlines() if line.strip()
                ]
                real_problems = [
                    line for line in stderr_lines
                    if not _is_benign_verify_line(line)
                ]
                if real_problems:
                    failures.append(
                        f"{fixture_id}: rc={result.returncode}\n" + "\n".join(real_problems)
                    )
            finally:
                shutil.rmtree(config_dir)
                shutil.rmtree(services_dir)
                shutil.rmtree(sysusers_dir)
        if failures:
            self.fail(
                f"{len(failures)} fixture(s) failed systemd-analyze verify:\n\n"
                + "\n\n".join(failures)
            )


if __name__ == "__main__":
    unittest.main()
