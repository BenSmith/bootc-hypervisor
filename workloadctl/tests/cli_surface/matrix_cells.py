"""matrix_cells — the cells the verb × substrate matrix must contain.

The matrix in conftest.py is built from `record_property("cell", …)` calls and
printed in the terminal summary. Printed, never checked: a cell used to vanish
silently when a test was renamed or deleted, which made the matrix an instrument
nobody was required to read rather than a gate.

This module is that gate's data. `tests/test_cli_surface_matrix.py` (rung 1, so
it runs in the normal `just test` with no host and no KVM) AST-scans the harness
and fails if the declared cells differ from EXPECTED_CELLS in either direction:
a missing cell means coverage disappeared, an unexpected one means a new cell
was added without saying so here. Adding coverage is meant to be a two-line
change — write the test, add its cell — and deleting coverage is meant to be
loud.

What this pins is *declaration*, not execution: a cell listed here whose test
skips for want of /dev/kvm is still covered as far as this gate is concerned.
Execution is what the printed matrix shows, and it necessarily varies with the
host and the marker filter.
"""

# Cells declared as string literals. Keep sorted; one line per cell.
EXPECTED_CELLS = frozenset({
    "attach/container",
    "attach/vm",
    "backup/container",
    "backup/vm",
    "backup_all/any",
    "backup_crash/vm",
    "build/container",
    "catalog/container",
    "cleanup/apply",
    "cleanup/dry_run",
    "cp/container",
    "cp/vm",
    "create/container",
    "diagnose/broken",
    "diagnose/container",
    "disable/container",
    "disable_purge/container",
    "disable_purge/vm",
    "doctor/broken",
    "doctor/container",
    "drift/any",
    "drift/container",
    "duplicate/container",
    "edit/container",
    "enable/container",
    "exec/container",
    "exec/container/bridge",
    "exec/container/pod",
    "exec/vm",
    "health/container",
    "health/container/pod",
    "health/vm",
    "images/container",
    "images/vm",
    "info/container",
    "info/container/pod",
    "info/vm",
    "init/container",
    "list/any",
    "list/container",
    "logs/container",
    "logs/container/bridge",
    "logs/container/pod",
    "logs/vm",
    "ports/container",
    "ports/container/host",
    "ports/vm",
    "reboot/container",
    "reboot/vm",
    "recreate/container",
    "recreate/vm",
    "restore/container",
    "restore/error",
    "restore/vm",
    "rollback/container",
    "rollback/vm",
    "secret_create/any",
    "secret_delete/any",
    "secret_export_import/any",
    "secret_list/any",
    "secret_rotate/any",
    "secret_show/any",
    "shell/container",
    "shell/vm",
    "start/container",
    "start/vm",
    "stats/container",
    "stats/vm",
    "status/any",
    "status/container",
    "status/container/bridge",
    "status/container/pod",
    "status/vm",
    "stop/container",
    "stop/vm",
    "uid-map/container",
    "update/container",
    "update/vm",
    "update_all/container",
    "validate/any",
    "validate/broken",
    "validate/container",
    "validate/vm",
})

# Cells a test builds at runtime, which an AST scan cannot read. One entry per
# module that declares any: the checker asserts the module still contains a
# non-constant cell declaration, so deleting the test is caught even though its
# cell names are not literals.
DYNAMIC_CELLS = {
    # test_topology_is_active parametrizes over the container topologies and
    # spells its cell as f"enable/{fixture_name...}".
    "test_lifecycle.py": frozenset({
        "enable/single",
        "enable/pod",
        "enable/bridge",
        "enable/host",
    }),
}


def all_expected_cells() -> frozenset[str]:
    """Every cell the harness is expected to declare, static and dynamic."""
    return EXPECTED_CELLS.union(*DYNAMIC_CELLS.values())
