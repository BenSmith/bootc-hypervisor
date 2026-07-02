#!/usr/bin/env python3
"""Snapshot tests for the workload generator against workloads.d/ TOMLs.

Runs the generator over every TOML in workloads.d/ (excluding the
schema reference) and compares every emitted unit file to checked-in
snapshots in tests/snapshots/.

For each workload:
  - sysusers: workload-<name>.conf
  - service:  workload-<name>.service
  - setup:    workload-<name>-setup.service
  - helper:   workload-<name>-pod.service (pod mode) or
              workload-<name>-net.service (bridge mode)
  - per container in multi-container mode: workload-<name>-<ctr>.service

The generator allocates each workload a UID by scanning /etc/passwd for a
free slot in 10000-52948, so the raw output is machine-dependent (the UID
lands in the sysusers .conf, in ReadWritePaths=.../run/user/<uid>, and in
any --uidmap/--gidmap @<uid> entries). Snapshots would otherwise drift on
every machine. _normalize() masks each workload's allocated UID with
__UID__ before comparing or writing, which keeps the snapshots a hermetic
check of generator *behavior* rather than of the host's user table.

To regenerate snapshots after intentional changes:
    UPDATE_SNAPSHOTS=1 python3 -m unittest tests.test_snapshots

Snapshot drift is reported as a warning and does NOT fail the test suite
by default, since it reflects an expected (if unreviewed) generator change
rather than a correctness bug. Set STRICT_SNAPSHOTS=1 to turn drift back
into a hard failure (e.g. in a gate that should block on it).
"""
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "generators" / "workload-generate"
LIB_DIR = ROOT / "lib"
WORKLOADS_DIR = ROOT / "workloads"
SNAPSHOTS_DIR = Path(__file__).parent / "snapshots"

sys.path.insert(0, str(LIB_DIR))
from workload_lib import infer_workload_mode, normalize_containers  # noqa: E402

# sysusers 'u' line: `u <name> <uid> "<gecos>" <home>`
_SYSUSERS_UID_RE = re.compile(r'^u\s+\S+\s+(\d+)\s', re.M)


def _enable_toml(src: Path, dst: Path):
    """Copy a TOML and create the .enabled marker so the generator processes it."""
    dst.write_text(src.read_text())
    (dst.parent / ".enabled").touch()


def _workload_uid(conf_text: str) -> str | None:
    """Extract the allocated UID from a sysusers .conf, or None (range form)."""
    m = _SYSUSERS_UID_RE.search(conf_text)
    return m.group(1) if m else None


def _normalize(text: str, uid: str | None, svc_dir: str | None = None) -> str:
    """Mask machine-dependent fragments before comparing.

    - The workload's allocated UID → __UID__
    - The test's per-run services tmpdir → __SVCDIR__ (setup service's
      systemd-sysusers ExecStart references SERVICES_DIR, which we pass as
      a tempdir during tests)
    """
    if uid:
        text = re.sub(rf'(?<!\d){re.escape(uid)}(?!\d)', '__UID__', text)
    if svc_dir:
        text = text.replace(svc_dir, "__SVCDIR__")
    return text


def _expected_units(stem: str, toml_text: str) -> list[tuple[str, str]]:
    """Return [(emitted-file-name, snapshot-suffix), ...] for one workload.

    Snapshot suffix is the unit name with the leading "workload-<stem>"
    stripped so files land at tests/snapshots/<stem><suffix>:
      - <stem>.service                 (the workload service / umbrella)
      - <stem>-setup.service           (user/dir provisioning oneshot)
      - <stem>-pod.service / -net.service for multi-container
      - <stem>-<ctr>.service for each [[containers]] entry
    """
    config = tomllib.loads(toml_text)
    mode = infer_workload_mode(config)
    units = [
        (f"workload-{stem}.service",       f"{stem}.service"),
        (f"workload-{stem}-setup.service", f"{stem}-setup.service"),
    ]
    if mode == "pod":
        units.append((f"workload-{stem}-pod.service", f"{stem}-pod.service"))
    elif mode == "bridge":
        units.append((f"workload-{stem}-net.service", f"{stem}-net.service"))
    if mode != "single":
        for c in normalize_containers(config):
            ctr = c["name"]
            units.append((f"workload-{stem}-{ctr}.service", f"{stem}-{ctr}.service"))
    return units


class TestWorkloadSnapshots(unittest.TestCase):
    def test_all_workloads_match_snapshots(self):
        SNAPSHOTS_DIR.mkdir(exist_ok=True)
        update = os.environ.get("UPDATE_SNAPSHOTS") == "1"
        strict = os.environ.get("STRICT_SNAPSHOTS") == "1"
        drift = []

        # Each shipped bundle is workloads/<bundle>/workload.toml; the bundle
        # dir name is the workload identity (snapshot stem + cfg filename).
        tomls = sorted(WORKLOADS_DIR.glob("*/workload.toml"))
        self.assertGreater(len(tomls), 0, "no workload TOMLs found")

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            cfg = tmp / "cfg"
            svc = tmp / "svc"
            sys_d = tmp / "sys"
            cfg.mkdir(); svc.mkdir(); sys_d.mkdir()

            for src in tomls:
                name = src.parent.name
                (cfg / name).mkdir(exist_ok=True)
                _enable_toml(src, cfg / name / "workload.toml")

            env = os.environ.copy()
            env["WORKLOAD_CONFIG_DIR"] = str(cfg)
            env["SYSUSERS_DIR"] = str(sys_d)
            env["PYTHONPATH"] = str(LIB_DIR)
            # Pin GPU auto-resolution so snapshots are host-independent: the
            # generator otherwise reads the build host's PCI vendor IDs, so
            # `gpu = "auto"` workloads would differ between an NVIDIA dev box and
            # a GPU-less CI runner. NVIDIA is the canonical deployment target.
            env["WORKLOAD_GPU_OVERRIDE"] = "nvidia"
            r = subprocess.run([sys.executable, str(GENERATOR), str(svc)],
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)

            for src in tomls:
                stem = src.parent.name
                conf_text = (sys_d / f"workload-{stem}.conf").read_text()
                uid = _workload_uid(conf_text)

                outputs = [(stem + ".conf", conf_text)]
                for unit_name, suffix in _expected_units(stem, (cfg / stem / "workload.toml").read_text()):
                    unit_path = svc / unit_name
                    self.assertTrue(unit_path.is_file(),
                                    f"generator did not emit {unit_name} for {stem}")
                    outputs.append((suffix, unit_path.read_text()))

                for snap_name, raw in outputs:
                    actual = _normalize(raw, uid, str(svc))
                    snap = SNAPSHOTS_DIR / snap_name
                    if update or not snap.exists():
                        snap.write_text(actual)
                        continue
                    if actual != snap.read_text():
                        drift.append(snap_name)

        if drift:
            msg = (
                f"snapshot drift for {len(drift)} file(s): {', '.join(sorted(drift))}\n"
                f"To accept: UPDATE_SNAPSHOTS=1 just test"
            )
            if strict:
                self.fail(msg)
            warnings.warn(msg, stacklevel=2)


if __name__ == "__main__":
    unittest.main()
