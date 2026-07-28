"""test_cli_surface_matrix — the verb × substrate matrix as a gate, not a report.

The cli_surface harness declares one or more cells per test via
`record_property("cell", "<verb>/<substrate>")`, and conftest prints them as a
matrix in the terminal summary. Printed only: a cell used to disappear silently
when a test was renamed or deleted, which made the matrix an instrument nobody
was required to read.

This is the missing gate. It AST-scans the harness for cell declarations and
compares them with `tests/cli_surface/matrix_cells.py`. Rung 1 on purpose — no
target, no /dev/kvm, no pytest — so the check runs in the normal `just test` and
in the PR gate, where the rung-3 tests themselves cannot.

It pins *declaration*, not execution: whether a VM cell actually ran depends on
the host, which is what the printed matrix is for.
"""

import ast
import importlib.util
import unittest
from pathlib import Path

CLI_SURFACE = Path(__file__).parent / "cli_surface"


def _load_matrix_cells():
    """Import cli_surface/matrix_cells.py by path.

    tests/cli_surface is the harness's own rootdir and is not on sys.path for
    the unit suite — and must not be put there, since importing its conftest
    would drag pytest fixtures into a unittest run.
    """
    spec = importlib.util.spec_from_file_location(
        "matrix_cells", CLI_SURFACE / "matrix_cells.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scan_cells(path: Path) -> tuple[set[str], int]:
    """(literal cells declared in this module, count of non-literal ones)."""
    literal: set[str] = set()
    dynamic = 0
    for node in ast.walk(ast.parse(path.read_text())):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "record_property"
                and len(node.args) == 2
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "cell"):
            continue
        value = node.args[1]
        if isinstance(value, ast.Constant):
            literal.add(value.value)
        else:
            dynamic += 1
    return literal, dynamic


class MatrixCellsTest(unittest.TestCase):
    def setUp(self):
        self.mc = _load_matrix_cells()
        self.declared: set[str] = set()
        self.dynamic_modules: dict[str, int] = {}
        for path in sorted(CLI_SURFACE.glob("test_*.py")):
            literal, dynamic = _scan_cells(path)
            self.declared |= literal
            if dynamic:
                self.dynamic_modules[path.name] = dynamic

    def test_no_declared_cell_has_disappeared(self):
        """Every expected cell is still declared by some harness test."""
        missing = sorted(self.mc.EXPECTED_CELLS - self.declared)
        self.assertFalse(missing, (
            f"matrix cells no longer declared anywhere in tests/cli_surface: "
            f"{missing}. A renamed or deleted test drops its coverage silently; "
            f"if the removal is deliberate, delete the cell from "
            f"tests/cli_surface/matrix_cells.py in the same change."
        ))

    def test_no_cell_was_added_without_declaring_it(self):
        """New cells must be listed, so added coverage is visible in review."""
        extra = sorted(self.declared - self.mc.EXPECTED_CELLS)
        self.assertFalse(extra, (
            f"matrix cells declared by tests but absent from EXPECTED_CELLS: "
            f"{extra}. Add them to tests/cli_surface/matrix_cells.py."
        ))

    def test_dynamic_cell_sites_still_exist(self):
        """A module credited with runtime-built cells must still build some.

        f-string cells (the parametrized topology test) are invisible to the
        scan, so deleting that test would otherwise pass both checks above.
        """
        for module in sorted(self.mc.DYNAMIC_CELLS):
            self.assertIn(module, self.dynamic_modules, (
                f"{module} is credited with runtime-built cells "
                f"({sorted(self.mc.DYNAMIC_CELLS[module])}) but declares none — "
                f"the test that built them is gone, or its cells became literals."
            ))

    def test_every_dynamic_module_is_accounted_for(self):
        """The reverse: a new f-string cell site must be registered."""
        unregistered = sorted(set(self.dynamic_modules) - set(self.mc.DYNAMIC_CELLS))
        self.assertFalse(unregistered, (
            f"modules build cell names at runtime without an entry in "
            f"DYNAMIC_CELLS: {unregistered}. The scan cannot see those cells, so "
            f"list them there or the matrix gate is blind to them."
        ))

    def test_cells_are_well_formed(self):
        """Every cell is verb/substrate — the shape conftest splits on."""
        for cell in sorted(self.mc.all_expected_cells()):
            self.assertIn("/", cell, f"cell {cell!r} has no substrate part")
            verb, _, substrate = cell.partition("/")
            self.assertTrue(verb and substrate, f"malformed cell: {cell!r}")


if __name__ == "__main__":
    unittest.main()
