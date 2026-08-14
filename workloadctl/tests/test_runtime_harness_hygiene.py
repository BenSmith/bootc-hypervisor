#!/usr/bin/env python3
"""Guards on how runtime tests talk to a target.

There is no shell on the far end of `Target.run` / `VMTarget.run`. Both take a
string command, `shlex.split` it, and `shlex.quote` every token back together
before handing it to ssh:

    cmd_list   = shlex.split(cmd)
    remote_cmd = " ".join(shlex.quote(str(a)) for a in cmd_list)

So a redirection, a pipe or a `&` written bare in a command string does not
redirect, pipe or background anything — it arrives at the far end as a literal
argument. The failure is silent in the worst way: `printf ... '>>' /etc/hosts`
prints its arguments and exits 0, so `check=True` is satisfied while the file
is never written, and a test built on it goes on to assert against state that
was never set up.

Two spellings are safe and both appear in the suite:
  * a **list** command — no split happens, so each element stays one argument;
  * `bash -c '<quoted script>'` — shlex round-trips the quoted token intact,
    which is why the fragments already written that way have always worked.

This runs in the PR gate on purpose. The tests it guards are runtime-marked
and only execute in the weekly gate rung, so a defect here otherwise sits
undetected for as long as nobody runs `WLRT_MODE=gate` — which is how four of
these reached a gate run at once.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEARCH_DIRS = (ROOT / "cli_surface", ROOT / "runtime")

# A string-form .run("...") / .wl_exec("...") call, capturing the command.
_CALL = re.compile(r'\.(?:run|wl_exec)\(\s*f?(["\'])(.+?)\1', re.S)

# Shell syntax that only means anything to a shell.
_SHELL_SYNTAX = re.compile(r'(?<!\\)(>>|>|\||&&|\|\||[^\\]\$\(|\s&\s|\s&$)')

# `bash -c '...'` / `sh -c "..."`, optionally behind sudo or timeout — the
# quoted form that survives the round trip.
_WRAPPED = re.compile(r'^\s*(sudo\s+)?(timeout\s+\d+\s+)?(bash|sh)\s+-c\s+["\']')


def _offenders(source: str):
    for match in _CALL.finditer(source):
        command = match.group(2)
        if not _SHELL_SYNTAX.search(command):
            continue
        if _WRAPPED.match(command):
            continue
        yield source[:match.start()].count("\n") + 1, command


class TestNoBareShellSyntaxInTargetCommands(unittest.TestCase):

    def test_every_runtime_command_is_a_list_or_wrapped_in_bash_c(self):
        found = []
        for directory in SEARCH_DIRS:
            for path in sorted(directory.rglob("*.py")):
                for line, command in _offenders(path.read_text()):
                    found.append(
                        f"{path.relative_to(ROOT.parent)}:{line}: {command[:100]}")
        self.assertEqual(found, [], "\n".join([
            "",
            "Shell syntax in a target command that is not a list and not",
            "wrapped in `bash -c '...'`. There is no shell on the far end, so",
            "this arrives as a literal argument and silently does nothing —",
            "including exiting 0, which keeps check=True happy.",
            "",
            "Pass a list, or wrap the script in bash -c:",
            '    target.run(["bash", "-c", "printf x >> /etc/hosts"], sudo=True)',
            "",
            *found,
        ]))

    def test_the_guard_detects_the_shapes_it_claims_to(self):
        """A guard that cannot fail is worse than none, and every offender here
        is a string this file never sees at runtime — so check it directly."""
        caught = dict(_offenders('''
            target.run(f"printf 'x' >> /etc/hosts", sudo=True)
            target.run(f"setsid nohup python3 {S} >/dev/null 2>&1 & echo $! > {P}")
            target.run(f"test -f {P} && kill $(cat {P}) || true")
            target.run(f"grep x /f | wc -l")
        '''))
        self.assertEqual(len(caught), 4, f"missed one: {caught}")

    def test_the_guard_accepts_the_two_safe_spellings(self):
        self.assertEqual(list(_offenders('''
            target.run(["bash", "-c", "printf 'x' >> /etc/hosts"], sudo=True)
            target.run(f"timeout 5 bash -c 'echo > /dev/tcp/127.0.0.1/443'")
            target.run(["rm", "-f", STUB_PID])
            target.run(f"systemctl is-active {unit}")
        ''')), [])


if __name__ == "__main__":
    unittest.main()
