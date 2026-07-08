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

from workload_lib import RUN_TREE_SCANS, workload_config_dir


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
    raise RuntimeError(
        "workload-generate script not found. Is workloadctl installed?"
    )


def collect_drift(workload_name=None) -> list:
    """Return the drift set as a list of (filename, live_text, gen_text).

    Runs the generator into a scratch dir and compares its output against
    LIVE_UNITS_DIR without touching either. Raises RuntimeError if the
    generator is missing or fails. Shared by cmd_drift and doctor.
    """
    generator = _find_generator()

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
            raise RuntimeError(
                f"generator failed:\n{result.stderr.strip()}"
            )

        gen_dir = Path(tmpdir)

        # The generator embeds the services output dir into the sysusers ExecStart
        # path.  Normalize it to the canonical live path so the diff only shows
        # real content changes, not the temp-dir artifact.
        _tmpdir_prefix = tmpdir + "/"
        _live_prefix = str(LIVE_UNITS_DIR) + "/"

        def _normalize(text: str) -> str:
            return text.replace(_tmpdir_prefix, _live_prefix)

        def _in_scope(rel: Path, scan) -> bool:
            # With no --workload filter every run-file is in scope. Drop-ins are
            # keyed by UID (name_filtered False), so the name filter can't apply
            # to them either — they are always compared. Otherwise keep
            # workload-NAME.service and workload-NAME-*.service (the main unit and
            # its per-container/helper units + sysusers .conf + wants symlink).
            if not workload_name or not scan.name_filtered:
                return True
            return (
                rel.stem == f"workload-{workload_name}"
                or rel.stem.startswith(f"workload-{workload_name}-")
            )

        diffs = []  # list of (filename, live_text, gen_text)

        # One pass per run-file kind (RUN_TREE_SCANS is the single source of which
        # kinds land in this tree), each comparing generated-vs-live in both
        # directions. Forward catches content drift and owned-but-missing files;
        # the orphan sweep catches live run-files a removed/partially-disabled
        # workload stranded in the tmpfs. Reporting every kind keeps "No drift
        # detected" from being a false all-clear.
        for scan in RUN_TREE_SCANS:
            gen_rels = set()
            for gen_file in sorted(gen_dir.glob(scan.glob)):
                rel = gen_file.relative_to(gen_dir)
                if not _in_scope(rel, scan):
                    continue
                gen_rels.add(rel)
                live_file = LIVE_UNITS_DIR / rel
                if scan.content:
                    gen_text = _normalize(gen_file.read_text())
                    live_text = (
                        live_file.read_text() if live_file.exists() else ""
                    )
                    if gen_text != live_text:
                        diffs.append((str(rel), live_text, gen_text))
                else:
                    # Enablement symlink: the only drift is presence. is_symlink()
                    # covers a *dangling* live link (target removed out from under
                    # it) — the link file is present, so enablement is not
                    # "missing" even though exists() follows it and returns False.
                    if not (live_file.exists() or live_file.is_symlink()):
                        target = os.readlink(gen_file) if gen_file.is_symlink() else ""
                        diffs.append((
                            str(rel), "",
                            f"# missing enablement symlink -> {target}\n",
                        ))

            if not LIVE_UNITS_DIR.is_dir():
                continue
            for live_file in sorted(LIVE_UNITS_DIR.glob(scan.glob)):
                rel = live_file.relative_to(LIVE_UNITS_DIR)
                if not _in_scope(rel, scan) or rel in gen_rels:
                    continue
                if scan.content:
                    diffs.append((str(rel), live_file.read_text(), ""))
                else:
                    target = os.readlink(live_file) if live_file.is_symlink() else ""
                    diffs.append((
                        str(rel),
                        f"# orphaned enablement symlink -> {target}\n",
                        "",
                    ))

    return diffs


def cmd_drift(args, manager):
    """Show diff between TOML-generated units and running units.

    Runs the generator in a scratch directory and diffs the output against
    /run/systemd/system.  No changes are applied.  Exits 1 if drift exists,
    0 if everything is in sync.
    """
    workload_name = getattr(args, "workload", None)
    json_output = getattr(args, "json", False)

    try:
        diffs = collect_drift(workload_name)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

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
