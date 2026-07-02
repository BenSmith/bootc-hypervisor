"""Helpers for measuring coverage of scripts we invoke as subprocesses.

Some tests exercise our extension-less scripts (e.g. the systemd generator) by
running them as real subprocesses for clean argv/env isolation. coverage.py
cannot see into a plain ``subprocess.run([python, script])`` call, so those
scripts read as untested even when they are thoroughly exercised.

``python_cmd()`` transparently re-routes the invocation through
``coverage run --parallel-mode`` when a coverage session is active (signalled by
the ``COVERAGE_PROCESS_START`` env var, which the ``just coverage`` recipe sets).
The parent run then ``coverage combine``s the per-subprocess data files. Outside
a coverage run it is a no-op, so production/normal test behaviour is unchanged.
"""

import os
import sys


def python_cmd(script, *args):
    """Build an argv list to run ``script`` under coverage when active."""
    rcfile = os.environ.get("COVERAGE_PROCESS_START")
    base = [sys.executable]
    if rcfile:
        base += ["-m", "coverage", "run", "--parallel-mode", "--rcfile=" + rcfile]
    return base + [str(script), *[str(a) for a in args]]
