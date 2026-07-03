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

from workload_lib import workload_config_dir


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
            "WORKLOAD_CONFIG_DIR": str(workload_config_dir()),
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

        def _belongs(stem: str) -> bool:
            # With no --workload filter every workload-* file is in scope.
            # Otherwise keep workload-NAME.service and workload-NAME-*.service
            # (main unit and its per-container/helper units + sysusers .conf).
            if not workload_name:
                return True
            return (
                stem == f"workload-{workload_name}"
                or stem.startswith(f"workload-{workload_name}-")
            )

        diffs = []  # list of (filename, live_text, gen_text)

        for gen_file in sorted(gen_dir.glob("workload-*.service")):
            if not _belongs(gen_file.stem):
                continue

            live_file = LIVE_UNITS_DIR / gen_file.name
            gen_text = _normalize(gen_file.read_text())
            live_text = live_file.read_text() if live_file.exists() else ""

            if gen_text != live_text:
                diffs.append((gen_file.name, live_text, gen_text))

        # Same owned-vs-live content diff for the sysusers .conf — an edited
        # extra_groups/UID that was never re-enabled drifts exactly like a unit,
        # and a generated-but-absent .conf (owned-but-missing) surfaces here too.
        for gen_file in sorted(gen_dir.glob("workload-*.conf")):
            if not _belongs(gen_file.stem):
                continue
            live_file = LIVE_UNITS_DIR / gen_file.name
            gen_text = _normalize(gen_file.read_text())
            live_text = live_file.read_text() if live_file.exists() else ""
            if gen_text != live_text:
                diffs.append((gen_file.name, live_text, gen_text))

        # Owned-but-missing enablement symlink: the generator wants it but the
        # live tree lacks it, so the workload would not auto-start on boot.
        gen_wants_dir_check = gen_dir / "multi-user.target.wants"
        live_wants_dir_check = LIVE_UNITS_DIR / "multi-user.target.wants"
        if gen_wants_dir_check.is_dir():
            for link in sorted(gen_wants_dir_check.glob("workload-*.service")):
                if not _belongs(link.stem):
                    continue
                if not (live_wants_dir_check / link.name).exists():
                    target = os.readlink(link) if link.is_symlink() else ""
                    diffs.append((
                        f"multi-user.target.wants/{link.name}",
                        "",
                        f"# missing enablement symlink -> {target}\n",
                    ))

        # Live files with no generated counterpart — a workload removed from
        # /etc/workloads.d whose run-files still linger in the tmpfs (until the
        # next reboot wipes it). The generator only writes, so a skipped or
        # partial `disable` strands them; reporting every kind it emits into this
        # tree keeps "No drift detected" from being a false all-clear. Covered:
        # the .service units, the sysusers .conf, and the enablement symlink —
        # the same run-file set `workload disable` is responsible for removing.
        if LIVE_UNITS_DIR.is_dir():
            gen_services = {f.name for f in gen_dir.glob("workload-*.service")}
            for live_file in sorted(LIVE_UNITS_DIR.glob("workload-*.service")):
                if _belongs(live_file.stem) and live_file.name not in gen_services:
                    diffs.append((live_file.name, live_file.read_text(), ""))

            gen_sysusers = {f.name for f in gen_dir.glob("workload-*.conf")}
            for live_file in sorted(LIVE_UNITS_DIR.glob("workload-*.conf")):
                if _belongs(live_file.stem) and live_file.name not in gen_sysusers:
                    diffs.append((live_file.name, live_file.read_text(), ""))

            gen_wants_dir = gen_dir / "multi-user.target.wants"
            gen_wants = (
                {f.name for f in gen_wants_dir.glob("workload-*.service")}
                if gen_wants_dir.is_dir() else set()
            )
            live_wants_dir = LIVE_UNITS_DIR / "multi-user.target.wants"
            if live_wants_dir.is_dir():
                for link in sorted(live_wants_dir.glob("workload-*.service")):
                    if _belongs(link.stem) and link.name not in gen_wants:
                        target = os.readlink(link) if link.is_symlink() else ""
                        diffs.append((
                            f"multi-user.target.wants/{link.name}",
                            f"# orphaned enablement symlink -> {target}\n",
                            "",
                        ))

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
        diff_lines = list(difflib.unified_diff(
            live_text.splitlines(keepends=True),
            gen_text.splitlines(keepends=True),
            fromfile=from_label,
            tofile=to_label,
        ))
        sys.stdout.writelines(diff_lines)
        print()

    sys.exit(1)
