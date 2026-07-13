"""Test-package bootstrap: puts the code under test on sys.path.

Test modules are imported as ``tests.<name>``, so this runs before any of them
and is the one place that knows the checkout layout.

Shipped code in ``lib/`` is a flat set of top-level modules: on a host the RPM's
.pth file puts ``/usr/libexec/workloadctl`` on sys.path, and from a checkout that
job is ours. ``tests/`` itself goes on the path too, so sibling helpers (e.g.
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
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = LIB_DIR
    env.update({key: str(value) for key, value in overrides.items()})
    return env
