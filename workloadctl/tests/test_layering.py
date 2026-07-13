#!/usr/bin/env python3
"""Layering invariant: the library core raises, only the CLI leaf exits.

`sys.exit()` raises SystemExit, which inherits BaseException specifically so it
passes through `except Exception:` handlers untouched. At a CLI leaf that is
exactly right — the process is meant to end. In library code it is a trapdoor:
a helper that exits takes the whole process with it, past any caller that meant
to recover, and hands the caller no way to distinguish "failed" from "decided to
end the program".

So the boundary is: `bin/workloadctl` and `lib/cmd_*.py` may exit; every other
module in `lib/` must raise (see the typed exceptions in workloadctl_core and
substrate, mapped to exit codes by `_run_cli()`).

That boundary held by convention alone. This module checks it, so the next
`sys.exit()` to land in podman.py fails the suite instead of shipping.
"""

import ast
import unittest
from pathlib import Path

from tests import REPO_ROOT

LIB_DIR = Path(REPO_ROOT) / "lib"

# Process-ending calls. `exit`/`quit` are site builtins that may not exist under
# `python -S`, and are a code smell in shipped code regardless.
FORBIDDEN = {"sys.exit", "os._exit", "exit", "quit"}


def _core_modules():
    """Every lib/ module the rule binds: the whole flat module set minus the
    command layer. Pattern-based on purpose — a new core module is covered the
    moment it lands, without anyone remembering to add it to a list."""
    return sorted(p for p in LIB_DIR.glob("*.py") if not p.name.startswith("cmd_"))


def _called_name(node: ast.Call) -> str | None:
    """Dotted name of a call target: `sys.exit` for sys.exit(1), `exit` for exit()."""
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    if isinstance(func, ast.Name):
        return func.id
    return None


class TestNoExitInLibraryCore(unittest.TestCase):

    def test_core_modules_exist(self):
        """Guard the guard: a bad glob would make every assertion below vacuous."""
        names = [p.name for p in _core_modules()]
        self.assertIn("workload_lib.py", names)
        self.assertIn("substrate.py", names)
        self.assertGreater(len(names), 5)

    def test_no_process_exit_in_core(self):
        offenders = []
        for path in _core_modules():
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _called_name(node)
                    if name in FORBIDDEN:
                        offenders.append(f"{path.name}:{node.lineno}: {name}()")

        self.assertEqual(
            offenders, [],
            "Library core must raise, not exit — the CLI (bin/workloadctl, "
            "lib/cmd_*.py) owns the exit code. Raise a typed exception "
            "(UsageError, NotRoot, LifecycleError, ProvisionFailed, …) and let "
            "_run_cli() map it. Offenders:\n  " + "\n  ".join(offenders),
        )
