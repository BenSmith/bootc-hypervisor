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

The egress inspector and the credential broker are customs': its package
(``import customs``) and its programs, which the generator names. Installed,
the package is in site-packages and the programs in ``/usr/libexec/customs``;
``CUSTOMS_CHECKOUT`` names a customs checkout to use instead, for a host that
has not installed it.
"""

import importlib.machinery
import importlib.util
import os
import sys
from pathlib import Path

# Keep the suite safe however it is launched, `just test` or a bare
# `python3 -m unittest`. The justfile's test recipe passes -B AND exports
# PYTHONDONTWRITEBYTECODE, but only the export reaches the subprocesses, which
# is the half that matters: this suite mutation-tests lib/ deliberately
# (perturb a file, run, restore it inside the same second), and a child that
# writes a .pyc during a perturbation window records the original mtime, which
# a later import then trusts and executes as stale bytecode -- a false failure
# that reads as a real one (a tar that exits 2 for no reason). -B alone cannot
# fix it: sys.dont_write_bytecode is per-interpreter and is not inherited. So
# this package pins both, for the parent (in case it was started without -B)
# and -- via os.environ -- for every child script_env() launches.
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"

# str, not Path: it is spelled straight into os.path.join() and env["PYTHONPATH"].
LIB_DIR = str(REPO_ROOT / "lib")

for _dir in (LIB_DIR, str(TESTS_DIR)):
    if _dir not in sys.path:
        sys.path.insert(0, _dir)

CUSTOMS_CHECKOUT = os.environ.get("CUSTOMS_CHECKOUT")
# Absolute, and written back: it reaches subprocesses through PYTHONPATH and
# the inherited environment, and some of those run with another cwd, where a
# relative checkout path names a different directory.
if CUSTOMS_CHECKOUT:
    CUSTOMS_CHECKOUT = str(Path(CUSTOMS_CHECKOUT).resolve())
    os.environ["CUSTOMS_CHECKOUT"] = CUSTOMS_CHECKOUT
# Right after lib/, as script_env() orders it for a child: ahead of
# site-packages, so that on a host with customs installed this process and
# its children import the same customs -- the checkout's, whose programs
# CUSTOMS_LIBEXEC names.
if CUSTOMS_CHECKOUT and CUSTOMS_CHECKOUT not in sys.path:
    sys.path.insert(sys.path.index(LIB_DIR) + 1, CUSTOMS_CHECKOUT)
# The directory customs' programs are read from: the installed one, or the
# checkout's own.
CUSTOMS_LIBEXEC = (Path(CUSTOMS_CHECKOUT) / "libexec" if CUSTOMS_CHECKOUT
                   else Path("/usr/libexec/customs"))


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
    env["PYTHONPATH"] = os.pathsep.join(
        [LIB_DIR] + ([CUSTOMS_CHECKOUT] if CUSTOMS_CHECKOUT else []))
    env["NO_COLOR"] = "1"
    env.update({key: str(value) for key, value in overrides.items()})
    return env


def assert_bare_refusal(case, response, status, phrase):
    """`response` is one refusal of ours that says nothing about us.

    Checked field by field against what an origin's own refusal looks like:
    the status line, a `Date`, no `Server`, and the reason phrase as the whole
    body. Anything more in the body is a sentence of ours reaching the guest.
    """
    head, sep, body = response.partition(b"\r\n\r\n")
    case.assertTrue(sep, f"no complete head in {response!r}")
    lines = head.split(b"\r\n")
    case.assertEqual(lines[0], f"HTTP/1.1 {status} {phrase}".encode())
    names = {line.split(b":", 1)[0].strip().lower() for line in lines[1:]}
    case.assertIn(b"date", names)
    case.assertNotIn(b"server", names)
    case.assertEqual(body, f"{phrase}\n".encode())
