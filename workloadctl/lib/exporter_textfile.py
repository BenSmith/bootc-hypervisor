"""
The exporter's drop: where each producer's textfile goes and how it lands.

Both producers write into DROP_DIR, one file each, because node_exporter's
textfile collector globs the directory. _write_atomic() is the one way a
file gets there -- a sibling temp file renamed onto the final name -- so a
concurrent reader never sees a partial exposition. write_metrics() and
write_disk_metrics() are the two producers end to end: collect, render,
drop.
"""

import os
from pathlib import Path

from exporter_collect import collect_all, collect_disk, collect_inspect
from exporter_render import format_disk_metrics, format_metrics

DROP_DIR = Path("/run/workload-exporter")
# Default drop names, one per producer; both land in DROP_DIR so Alloy's
# directory-globbing textfile collector ingests both.
DEFAULT_OUTPUT = DROP_DIR / "workloads.prom"
DEFAULT_DISK_OUTPUT = DROP_DIR / "workloads-disk.prom"


def parse_args(argv):
    """Parse argv into (disk_mode, output_override).

    Accepts an optional `--disk` flag and an optional positional output path
    (the latter kept so tests can redirect writes to a scratch file).
    """
    disk_mode = False
    output_override = None
    for arg in argv[1:]:
        if arg == "--disk":
            disk_mode = True
        else:
            output_override = arg
    return disk_mode, output_override


def output_path(disk_mode, override):
    """Where the run drops its exposition: the positional override, else the
    default for the producer that is running."""
    if override:
        return Path(override)
    return DEFAULT_DISK_OUTPUT if disk_mode else DEFAULT_OUTPUT


def _write_atomic(output_path, body):
    """Write body to output_path atomically, world-readable.

    Writes a sibling temp file and renames it onto the final name so a
    concurrently-reading textfile collector never sees a partial file. The
    parent dir is created 0755 and the file 0644 (world-readable): the only
    reader is the rootless Alloy container, which reads the file across a
    read-only bind mount and cannot chown a root-owned file (see the
    homelab-root.crt pattern), so it must be readable as-is.
    """
    output_path = Path(output_path)
    parent = output_path.parent
    if not parent.exists():
        # In production tmpfiles owns this dir (0755); only set the mode when we
        # create it ourselves, so we never loosen an existing dir's perms.
        parent.mkdir(parents=True, exist_ok=True)
        os.chmod(parent, 0o755)
    tmp = output_path.with_name("." + output_path.name + ".tmp")
    tmp.write_text(body)
    os.chmod(tmp, 0o644)
    os.replace(tmp, output_path)


def write_metrics(output_path):
    """Render the fast exposition and write it atomically to output_path."""
    _write_atomic(output_path,
                  format_metrics(collect_all(), collect_inspect()))


def write_disk_metrics(output_path):
    """Render the disk-usage exposition and write it atomically."""
    _write_atomic(output_path, format_disk_metrics(collect_disk()))
