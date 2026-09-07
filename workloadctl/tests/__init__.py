"""Test-package bootstrap: puts the code under test on sys.path.

Test modules are imported as ``tests.<name>``, so this runs before any of them
and is the one place that knows the checkout layout.

Shipped code in ``lib/`` is a flat set of top-level modules. On a host every
entrypoint is installed beside them in ``/usr/libexec/workloadctl`` and finds
them via its own ``sys.path[0]``; from a checkout that job is ours. ``tests/``
itself goes on the path too, so sibling helpers (e.g.
``covhelper``) import by bare name. The entrypoints under ``bin/``, ``generators/``
and ``libexec/`` have no ``.py`` extension and so cannot be imported by name --
use :func:`load_script`. Subprocess launches of those scripts need the same lib
path handed down in the child env -- use :func:`script_env`.
"""

import importlib.machinery
import importlib.util
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"

# str, not Path: it is spelled straight into os.path.join() and env["PYTHONPATH"].
LIB_DIR = str(REPO_ROOT / "lib")

for _dir in (LIB_DIR, str(TESTS_DIR)):
    if _dir not in sys.path:
        sys.path.insert(0, _dir)


def load_script(relpath, name=None):
    """Import an extension-less entrypoint, e.g. ``generators/workload-generate``.

    The scripts guard execution behind ``if __name__ == "__main__"``, so importing
    one under any other name is side-effect free beyond its top-level imports.
    `name` defaults to the filename with dashes turned into underscores.
    """
    path = REPO_ROOT / relpath
    name = name or path.name.replace("-", "_")
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def script_env(**overrides):
    """A copy of os.environ with PYTHONPATH set, for running a script as a subprocess.

    Overrides are stringified, so callers can pass Paths and ints directly.

    NO_COLOR is forced on, and it is not cosmetic. Python 3.14's argparse
    colourises its own help, and it decides that from the ENVIRONMENT
    (FORCE_COLOR) as well as from isatty -- so a developer or runner with
    FORCE_COLOR set gets ANSI escapes on a captured pipe, where every earlier
    Python emitted plain text. A test that reads a line out of `--help` then
    sees a line beginning with an escape sequence rather than the verb, and
    fails somewhere unrelated to what it was checking. That is what happened to
    test_cli_docs's `egress` check the first time this suite ran in an
    environment with FORCE_COLOR=3.

    Set centrally rather than per test because the property wanted is not
    "this test does not want colour" but "our scripts' output is parsed by
    machine here", which is true of every caller. NO_COLOR wins over
    FORCE_COLOR in CPython's resolution, so this holds regardless of what the
    ambient environment asked for, and an override still wins over both for a
    test that genuinely wants to see colour.
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = LIB_DIR
    env["NO_COLOR"] = "1"
    env.update({key: str(value) for key, value in overrides.items()})
    return env
