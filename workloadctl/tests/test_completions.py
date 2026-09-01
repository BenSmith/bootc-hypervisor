#!/usr/bin/env python3
"""Contracts binding completions/workloadctl-completion.bash to the real CLI.

The completion file is the one shipped artifact nothing executes: a stale entry
costs a tab-complete, never an error, so drift accumulates silently. It did —
`install`, `pcap` and `doctor` were absent and a non-existent `help` verb was
offered for months, and the helper-unit filter did not know about a VM's
`-proxy.service`, so `workloadctl exec myvm/<TAB>` offered `proxy` as if it
were a container.

Each test here derives its expectation from the source of truth rather than
restating it, which is the only shape that catches the *next* subcommand:

  * the command list, from argparse's own choices;
  * the per-command flags, from each subparser's --help;
  * the helper-unit filter, from `workload_lib.workload_run_files()`.

Flags are checked one way only — offered-but-unreal fails, unoffered is allowed.
A completion may reasonably omit a flag as noise; offering one the parser will
reject is always a bug.
"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import workload_lib
from workloadctl_core import WorkloadConfig

from tests import script_env

REPO = Path(__file__).resolve().parent.parent
COMPLETION = REPO / "completions" / "workloadctl-completion.bash"


def _source():
    """The completion file with full-line comments stripped.

    Comments name flags in prose (`-y/--yes`, `init --as`), which would
    otherwise read as offers and produce findings that are not in the file's
    behavior at all.
    """
    return "\n".join(
        line for line in COMPLETION.read_text().splitlines()
        if not line.lstrip().startswith("#")
    )


def _cli_help(*args):
    p = subprocess.run(
        ["python3", str(REPO / "bin" / "workloadctl"), *args, "--help"],
        capture_output=True, text=True, env=script_env(), timeout=60)
    return p.stdout


def _parser_commands():
    """The subcommand names argparse accepts, from its own usage line."""
    return set(re.search(r"\{([a-z,]+)\}", _cli_help()).group(1).split(","))


def _completion_commands():
    return set(re.search(r'local commands="([^"]+)"', _source()).group(1).split())


def _branches():
    """{command: branch body} for each arm of the top-level case statement.

    `cmd_a|cmd_b)` arms are expanded, so a flag offered to a group is checked
    against every command in it — that grouping is exactly where a flag one
    member lacks would hide.
    """
    body = _source().split('case "${words[1]}" in', 1)[1]
    out = {}
    for names, blk in re.findall(r"\n        ([a-z|]+)\)\n(.*?)\n            ;;",
                                 body, re.S):
        for name in names.split("|"):
            out[name] = blk
    return out


class CommandListTest(unittest.TestCase):
    """The offered verbs are exactly the verbs argparse accepts."""

    def test_no_command_is_missing(self):
        missing = _parser_commands() - _completion_commands()
        self.assertEqual(missing, set(),
                         f"CLI subcommands with no completion entry: {sorted(missing)}")

    def test_no_command_is_invented(self):
        extra = _completion_commands() - _parser_commands()
        self.assertEqual(extra, set(),
                         f"completion offers verbs the CLI rejects: {sorted(extra)}")

    def test_every_branch_names_a_real_command(self):
        unknown = set(_branches()) - _parser_commands()
        self.assertEqual(unknown, set(),
                         f"case arms for non-existent commands: {sorted(unknown)}")


class OfferedFlagsTest(unittest.TestCase):
    """Every long flag offered for a command is one that command accepts."""

    def test_flags_exist_in_their_subparser(self):
        # `secret` dispatches to its own subparsers, so its arm offers flags
        # belonging to `secret create`/`import`/... rather than to `secret`
        # itself; those are covered by SecretSubcommandTest below.
        bad = {}
        for cmd, blk in sorted(_branches().items()):
            if cmd == "secret":
                continue
            real = set(re.findall(r"--[a-zA-Z][a-zA-Z0-9-]*", _cli_help(cmd)))
            offered = set(re.findall(r"--[a-zA-Z][a-zA-Z0-9-]*", blk))
            if offered - real:
                bad[cmd] = sorted(offered - real)
        self.assertEqual(bad, {}, f"flags offered but not accepted: {bad}")


class OfferedChoiceValuesTest(unittest.TestCase):
    """Every VALUE offered for a flag is one that flag's `choices=` accepts.

    Flags were checked, values were not — so `egress`'s arm restated three
    closed vocabularies (`forward drop`, `forward terminate splice h2`,
    `tls cleartext`) as bash literals under a comment claiming they came from
    the values cmd_egress validates against. They did not; they were a fourth
    copy, and the next value added to VM_INSPECT_RECORD_MODES would simply
    never be offered.

    Derived the same way the flag test is, from argparse's own rendering:
    a `choices=` flag prints as `--flag {a,b,c}` in --help. One direction only,
    for the reason stated at the top of this file — an arm may omit a value as
    noise; offering one the parser will reject is always a bug.
    """

    def _offered(self, blk):
        """{flag: {values}} for each `$prev == "--flag"` arm that offers a -W list."""
        out = {}
        for flag, words in re.findall(
                r'"\$prev" == "(--[a-zA-Z][a-zA-Z0-9-]*)"[^\n]*\n[^\n]*'
                r'-W "([^"]+)"', blk):
            out[flag] = set(words.split())
        return out

    def test_offered_values_are_accepted_choices(self):
        bad = {}
        for cmd, blk in sorted(_branches().items()):
            if cmd == "secret":
                continue
            help_text = _cli_help(cmd)
            declared = {f"--{name}": set(values.split(","))
                        for name, values in re.findall(
                            r"--([a-zA-Z][a-zA-Z0-9-]*) \{([^}]+)\}", help_text)}
            for flag, offered in self._offered(blk).items():
                if flag not in declared:
                    # No `choices=` on that flag: it takes free text (--host,
                    # --reason), and whatever the arm offers is a hint, not a
                    # claim about a closed set.
                    continue
                if offered - declared[flag]:
                    bad[f"{cmd} {flag}"] = sorted(offered - declared[flag])
        self.assertEqual(bad, {}, f"values offered but not accepted: {bad}")

    def test_the_check_can_see_at_least_one_closed_vocabulary(self):
        """A selector that matches nothing passes vacuously — check it bites.

        The regex above walks bash, and bash is not a language this file
        parses reliably; an arm reformatted onto different lines would make
        every command contribute an empty dict and the test above go green
        having compared nothing.
        """
        found = {flag for cmd, blk in _branches().items()
                 if cmd != "secret"
                 for flag in self._offered(blk)}
        self.assertIn("--decision", found)


class SecretSubcommandTest(unittest.TestCase):
    """`secret`'s nested verbs, checked against the nested parser."""

    def test_offered_subcommands_exist(self):
        blk = _branches()["secret"]
        offered = set(re.search(r'-W "([a-z ]+)" -- "\$cur"', blk).group(1).split())
        real = set(re.search(r"\{([a-z,]+)\}", _cli_help("secret")).group(1).split(","))
        self.assertEqual(offered, real)

    def test_flags_exist_in_their_subparser(self):
        blk = _branches()["secret"]
        bad = {}
        for sub, sub_blk in re.findall(r"\n                    ([a-z]+)\)\n(.*?)\n                        ;;",
                                       blk, re.S):
            real = set(re.findall(r"--[a-zA-Z][a-zA-Z0-9-]*", _cli_help("secret", sub)))
            offered = set(re.findall(r"--[a-zA-Z][a-zA-Z0-9-]*", sub_blk))
            if offered - real:
                bad[sub] = sorted(offered - real)
        self.assertEqual(bad, {}, f"flags offered but not accepted: {bad}")


class HelperUnitFilterTest(unittest.TestCase):
    """Helper units must not be offered as container names.

    `_workloadctl_ref_complete` lists `workload-<wl>-*.service` and subtracts a
    fixed set of suffixes to leave the containers. Every unit the generator
    emits alongside the containers shares that shape, so a new helper is
    offered as a container until this filter learns it — the defect this test
    exists to fail on, derived from the run-file helper rather than restated.
    """

    TOMLS = {
        # A volume and a `hosts` policy, so the fixture reaches the two VM-only
        # helpers (`-virtiofs-<tag>`, `-proxy`) rather than only the shared ones.
        "vm": '[workload]\nname = "{name}"\n\n[vm]\n'
              'image = "https://example.invalid/x.qcow2"\n'
              'volumes = ["/mnt/data:/mnt/data"]\n\n'
              '[vm.network]\negress = "filtered"\nhosts = ["example.com"]\n',
        "pod": '[workload]\nname = "{name}"\nmode = "pod"\n\n'
               '[[containers]]\nname = "one"\nimage = "docker.io/x:latest"\n',
        "bridge": '[workload]\nname = "{name}"\nmode = "bridge"\n\n'
                  '[[containers]]\nname = "one"\nimage = "docker.io/x:latest"\n',
    }

    def _filter_pattern(self):
        return re.search(r"grep -Ev '\^\((.*?)\)\$'", _source()).group(1)

    def _helper_suffixes(self, toml, name="wl"):
        """Suffixes of workload-<name>-<suffix>.service, minus container names."""
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / name).mkdir()
            (tmp / name / "workload.toml").write_text(toml.format(name=name))
            with patch.object(workload_lib, "WORKLOAD_CONFIG_DIR", tmp):
                config = WorkloadConfig(name)
                files = workload_lib.workload_run_files(config)
            containers = {c.get("name") for c in config.config.get("containers", [])}
            found = set()
            for entry in files:
                m = re.fullmatch(rf"workload-{name}-(.+)\.service", entry.path.name)
                if m and m.group(1) not in containers:
                    found.add(m.group(1))
            return found
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_every_helper_unit_is_filtered_out(self):
        pattern = self._filter_pattern()
        unfiltered = set()
        for toml in self.TOMLS.values():
            for suffix in self._helper_suffixes(toml):
                if not re.fullmatch(pattern.replace("|", "|"), suffix):
                    unfiltered.add(suffix)
        self.assertEqual(
            unfiltered, set(),
            f"helper units offered as containers by {COMPLETION.name}: "
            f"{sorted(unfiltered)} (filter is '{pattern}')")


if __name__ == "__main__":
    unittest.main()
