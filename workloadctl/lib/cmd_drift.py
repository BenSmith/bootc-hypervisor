"""
cmd_drift — show diff between generated and deployed unit files.

Generates workload units into a temp dir (using the same workload-generate
script that runs at boot), then diffs against /run/systemd/system to show
what is deployed vs what would be generated from the current TOML configs.
Outputs nothing if units are in sync; exits 1 if drift is detected.
"""

import difflib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from workload_lib import WORKLOAD_CONFIG_DIR


# The generator script location (installed path first, dev checkout fallback)
_GENERATOR_CANDIDATES = [
    Path("/usr/libexec/workloadctl/workload-generate"),
    Path(__file__).parent.parent / "generators" / "workload-generate",
]

LIVE_UNITS_DIR = Path("/run/systemd/system")


def _find_generator() -> Path:
    for p in _GENERATOR_CANDIDATES:
        if p.is_file():
            return p
    print(
        "Error: workload-generate script not found. "
        "Is workloadctl installed?",
        file=sys.stderr,
    )
    sys.exit(1)


def cmd_drift(args, manager):
    """Show diff between TOML-generated units and running units.

    Runs the generator in a scratch directory and diffs the output against
    /run/systemd/system.  No changes are applied.  Exits 1 if drift exists,
    0 if everything is in sync.
    """
    generator = _find_generator()
    workload_name = getattr(args, "workload", None)
    json_output = getattr(args, "json", False)

    with tempfile.TemporaryDirectory(prefix="workload-drift-") as tmpdir:
        env = {
            **os.environ,
            "WORKLOAD_CONFIG_DIR": str(WORKLOAD_CONFIG_DIR),
            "SYSUSERS_DIR": tmpdir,
        }
        result = subprocess.run(
            [str(generator), tmpdir],
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(
                f"Error: generator failed:\n{result.stderr.strip()}",
                file=sys.stderr,
            )
            sys.exit(1)

        gen_dir = Path(tmpdir)

        # The generator embeds the services output dir into the sysusers ExecStart
        # path.  Normalize it to the canonical live path so the diff only shows
        # real content changes, not the temp-dir artifact.
        _tmpdir_prefix = tmpdir + "/"
        _live_prefix = str(LIVE_UNITS_DIR) + "/"

        def _normalize(text: str) -> str:
            return text.replace(_tmpdir_prefix, _live_prefix)

        diffs = []  # list of (filename, live_text, gen_text)

        for gen_file in sorted(gen_dir.glob("workload-*.service")):
            if workload_name:
                # Filter to units that belong to the named workload
                stem = gen_file.stem
                # matches workload-NAME.service and workload-NAME-*.service
                if not (
                    stem == f"workload-{workload_name}"
                    or stem.startswith(f"workload-{workload_name}-")
                ):
                    continue

            live_file = LIVE_UNITS_DIR / gen_file.name
            gen_text = _normalize(gen_file.read_text())
            live_text = live_file.read_text() if live_file.exists() else ""

            if gen_text != live_text:
                diffs.append((gen_file.name, live_text, gen_text))

        # Also check for live units that have no generated counterpart
        # (workload removed from /etc/workloads.d but service still running)
        gen_names = {f.name for f in gen_dir.glob("workload-*.service")}
        if LIVE_UNITS_DIR.is_dir():
            for live_file in sorted(LIVE_UNITS_DIR.glob("workload-*.service")):
                if workload_name:
                    stem = live_file.stem
                    if not (
                        stem == f"workload-{workload_name}"
                        or stem.startswith(f"workload-{workload_name}-")
                    ):
                        continue
                if live_file.name not in gen_names:
                    live_text = live_file.read_text()
                    diffs.append((live_file.name, live_text, ""))

        # Compare user@<uid>.service.d/50-workload.conf drop-ins (ADR 001 option
        # 1b): these carry the Slice= redirect and workload-level caps, so they
        # are as load-bearing as the service units themselves.
        for gen_dropin_dir in sorted(gen_dir.glob("user@*.service.d")):
            dropin_name = f"{gen_dropin_dir.name}/50-workload.conf"
            gen_dropin = gen_dropin_dir / "50-workload.conf"
            if not gen_dropin.exists():
                continue
            gen_text = _normalize(gen_dropin.read_text())
            live_dropin = LIVE_UNITS_DIR / gen_dropin_dir.name / "50-workload.conf"
            live_text = live_dropin.read_text() if live_dropin.exists() else ""
            if gen_text != live_text:
                diffs.append((dropin_name, live_text, gen_text))

        # Orphan drop-ins: live drop-in exists but no generated counterpart
        gen_dropin_dirs = {d.name for d in gen_dir.glob("user@*.service.d")}
        if LIVE_UNITS_DIR.is_dir():
            for live_dropin_dir in sorted(LIVE_UNITS_DIR.glob("user@*.service.d")):
                live_dropin = live_dropin_dir / "50-workload.conf"
                if not live_dropin.exists():
                    continue
                if live_dropin_dir.name not in gen_dropin_dirs:
                    dropin_name = f"{live_dropin_dir.name}/50-workload.conf"
                    diffs.append((dropin_name, live_dropin.read_text(), ""))

    if json_output:
        import json
        out = []
        for fname, live_text, gen_text in diffs:
            diff_lines = list(difflib.unified_diff(
                live_text.splitlines(keepends=True),
                gen_text.splitlines(keepends=True),
                fromfile=f"running/{fname}",
                tofile=f"generated/{fname}",
            ))
            out.append({
                "unit": fname,
                "drifted": True,
                "diff": "".join(diff_lines),
            })
        if not out:
            out_obj = {"drifted": False, "units": []}
        else:
            out_obj = {"drifted": True, "units": out}
        print(json.dumps(out_obj, indent=2))
        sys.exit(1 if out else 0)

    if not diffs:
        print("No drift detected — running units match generated output")
        sys.exit(0)

    for fname, live_text, gen_text in diffs:
        from_label = f"running/{fname}" if live_text else "/dev/null"
        to_label = f"generated/{fname}" if gen_text else "/dev/null"
        diff_lines = difflib.unified_diff(
            live_text.splitlines(keepends=True),
            gen_text.splitlines(keepends=True),
            fromfile=from_label,
            tofile=to_label,
        )
        sys.stdout.writelines(diff_lines)
        print()

    sys.exit(1)
