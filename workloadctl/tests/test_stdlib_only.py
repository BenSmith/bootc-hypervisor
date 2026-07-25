#!/usr/bin/env python3
"""Guards the stdlib-only invariant for shipped code.

workloadctl runs against the system python3 with no venv, no package manager and
no third-party deps: `rpm/workloadctl.spec` declares `Requires: python3 >= 3.14`
plus system tools, and *no* Python library dependency. That is what lets the RPM
install onto a bootc host — where `pip` is not an option and every Python
dependency would have to become another layered RPM.

The invariant is easy to break by accident: a `import yaml` or `import requests`
added during development works fine in a dev container that happens to have it
and fails at import time on a host, long after the PR gate is green. So we parse
every shipped Python file and check that each imported top-level module is either
in the standard library or a sibling module installed alongside it.

Scope is the four runtime trees (bin, lib, generators, libexec) — exactly what
the spec installs into %{_libexecdir}/workloadctl. `tests/` is deliberately not
covered: test-only helpers may use whatever is available.
"""

import ast
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC = REPO_ROOT / "rpm" / "workloadctl.spec"

# The trees the RPM installs. Everything here lands in one flat directory on the
# host, so any lib/*.py stem is importable by a bare name from any of them.
RUNTIME_DIRS = ("bin", "lib", "generators", "libexec")

# Modules that are neither stdlib nor a checked-in sibling, but are legitimately
# importable at runtime. Keep this list short and justified.
ALLOWED_NON_STDLIB = {
    # Generated at RPM build time into the install dir (workloadctl.spec, the
    # `cat > .../_version.py` block) so `workloadctl --version` reports the full
    # NEVR. Absent from a source checkout, hence the ImportError fallback in
    # bin/workloadctl.
    "_version",
}

# Stdlib by name, but split into their own subpackage on Fedora — importing one
# would need a Requires: the spec does not have, so treat them as forbidden.
SPLIT_OUT_ON_FEDORA = {
    "tkinter",      # python3-tkinter
    "turtle",       # python3-tkinter
    "turtledemo",   # python3-tkinter
    "idlelib",      # python3-idle
    "test",         # python3-test
}


def _is_python(path: Path) -> bool:
    """True for a .py file, or an extension-less entrypoint with a python shebang."""
    if path.suffix == ".py":
        return True
    if path.suffix:
        return False
    try:
        with path.open("rb") as handle:
            first = handle.readline()
    except OSError:
        return False
    return first.startswith(b"#!") and b"python" in first


def runtime_files():
    """Every shipped Python file, sorted for a stable failure order."""
    found = []
    for dirname in RUNTIME_DIRS:
        directory = REPO_ROOT / dirname
        for path in sorted(directory.iterdir()):
            if path.is_file() and _is_python(path):
                found.append(path)
    return found


def sibling_modules():
    """Bare names importable on a host: the flat lib/*.py modules."""
    return {path.stem for path in (REPO_ROOT / "lib").glob("*.py")}


def _imports(tree):
    """Yield (top_level_module_name, lineno, level) for every import in `tree`.

    `level` is the ImportFrom dot count: 0 for absolute, >0 for relative.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0], node.lineno, 0
        elif isinstance(node, ast.ImportFrom):
            # `from . import x` has module=None; the name we care about is the
            # package, which for a flat layout is a bug regardless.
            top = (node.module or "").split(".")[0]
            yield top, node.lineno, node.level


class TestStdlibOnly(unittest.TestCase):

    def test_files_were_found(self):
        """A path typo that silently scans nothing would make every other test pass."""
        files = runtime_files()
        self.assertGreater(len(files), 30, "runtime tree scan found almost nothing")
        names = {path.name for path in files}
        # Spot-check one entrypoint per tree, including the extension-less ones.
        self.assertIn("workloadctl", names)        # bin/
        self.assertIn("workload_lib.py", names)    # lib/
        self.assertIn("workload-generate", names)  # generators/
        self.assertIn("workload-ensure-user", names)  # libexec/

    def test_no_third_party_imports(self):
        """Every import resolves to the stdlib, a sibling module, or the allowlist."""
        allowed = (
            sys.stdlib_module_names
            | sibling_modules()
            | ALLOWED_NON_STDLIB
        ) - SPLIT_OUT_ON_FEDORA

        offenders = []
        for path in runtime_files():
            tree = ast.parse(path.read_text(), filename=str(path))
            rel = path.relative_to(REPO_ROOT)
            for name, lineno, level in _imports(tree):
                if level:
                    offenders.append(
                        f"{rel}:{lineno}: relative import (level {level}) — "
                        f"shipped modules are flat, not a package"
                    )
                elif name not in allowed:
                    offenders.append(f"{rel}:{lineno}: import {name!r}")

        self.assertEqual(
            offenders, [],
            "shipped code may only import the standard library and its own "
            "modules (rpm/workloadctl.spec declares no Python dependency):\n  "
            + "\n  ".join(offenders),
        )

    def test_no_dynamic_imports(self):
        """Keep the AST scan above honest.

        `__import__("yaml")` / `importlib.import_module(name)` hide the module
        name behind a runtime string, so the check would not see it. Nothing
        shipped needs that today. If it ever does, verify the target by hand and
        widen this test rather than deleting it.
        """
        offenders = []
        for path in runtime_files():
            tree = ast.parse(path.read_text(), filename=str(path))
            rel = path.relative_to(REPO_ROOT)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name) and func.id == "__import__":
                        offenders.append(f"{rel}:{node.lineno}: __import__()")
                    elif (isinstance(func, ast.Attribute)
                          and func.attr == "import_module"):
                        offenders.append(f"{rel}:{node.lineno}: import_module()")

        self.assertEqual(
            offenders, [],
            "dynamic imports bypass the stdlib-only scan:\n  "
            + "\n  ".join(offenders),
        )


class TestSpecDeclaresNoPythonDeps(unittest.TestCase):
    """The other half of the invariant: the package must not acquire one either.

    An `import yaml` paired with a `Requires: python3-pyyaml` would sail past the
    AST check while still adding a dependency to every host.
    """

    # python3 itself is the interpreter, not a library. Matches python3-foo and
    # the auto-generated python3dist(foo) / python3.14dist(foo) forms.
    _PY_LIB_RE = re.compile(
        r"^(?:Requires|Recommends|Suggests):\s*"
        r"(python3-\S+|python3(?:\.\d+)?dist\(\S+)",
        re.MULTILINE,
    )

    def test_no_python_library_requires(self):
        matches = self._PY_LIB_RE.findall(SPEC.read_text())
        # policycoreutils-python-utils is a system CLI package, not a Python
        # import dependency — it does not start with python3-, so it never
        # matches here. Anything that does match is a real library dep.
        self.assertEqual(
            matches, [],
            "rpm/workloadctl.spec must not depend on a Python library; "
            f"found: {matches}",
        )

    def test_interpreter_requirement_still_declared(self):
        # Guards against the regex above passing because the spec was gutted.
        # Compiled with MULTILINE so ^ anchors to a line, not the whole file.
        self.assertRegex(
            SPEC.read_text(),
            re.compile(r"^Requires:\s+python3 >= 3\.\d+", re.MULTILINE),
            msg="spec no longer declares the python3 interpreter",
        )


if __name__ == "__main__":
    unittest.main()
