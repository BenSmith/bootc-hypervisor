#!/usr/bin/env python3
"""Contracts binding docs/cli.md to the real CLI.

WHY THIS EXISTS

cli.md is a command reference nothing executes, so a verb added without a
section costs nothing at the time and is invisible afterwards: the file still
reads as complete, because a reference's only symptom of being incomplete is a
thing that is not in it. Four verbs had accumulated that way — `doctor`,
`egress`, `pcap` and `rules` — and the oldest of them predates the rung that
noticed. `completions/workloadctl-completion.bash` had the identical rot and
`tests/test_completions.py` is what stopped it; this is the same guard one
artifact over.

Every expectation is DERIVED from argparse rather than restated, which is the
only shape that catches the *next* subcommand rather than the four that
prompted the file.

WHAT IT DOES NOT DO

It does not check that a section is accurate, or that documented flags exist —
prose is not derivable and a doc that lags a flag is a different, milder
failure. What it checks is presence and reachability: every verb is listed,
every verb has a section, nothing is documented that the CLI would reject, and
every link in the command table lands on a heading that exists.
"""

import re
import subprocess
import unittest
from pathlib import Path

from tests import script_env

REPO = Path(__file__).resolve().parent.parent
CLI_DOC = REPO / "docs" / "cli.md"

def _doc():
    return CLI_DOC.read_text()


def _parser_commands():
    """The subcommand names argparse accepts, from its own usage line."""
    out = subprocess.run(["python3", str(REPO / "bin" / "workloadctl"), "--help"],
                         capture_output=True, text=True, env=script_env(),
                         timeout=60).stdout
    return set(re.search(r"\{([a-z,]+)\}", out).group(1).split(","))


def _table_rows():
    """{verb: anchor} for the command table, aliases included.

    A row is `| [`verb`](#anchor) | description |`, and an alias rides in the
    same first cell (`[`duplicate`](#...) / `clone``), so every backticked name
    in the cell counts as documented.
    """
    rows = {}
    for cell, anchor in re.findall(r"^\| (\[`[a-z ]+`\]\(#([a-z-]+)\)[^|]*)\|",
                                   _doc(), re.M):
        for name in re.findall(r"`([a-z]+)`", cell):
            rows[name] = anchor
    return rows


def _sections():
    """Every verb a `###` heading documents, aliases included.

    ALL backticked names in the heading, not the first: `duplicate` is
    documented as "### `duplicate` (alias `clone`)" and `clone` is a real verb
    argparse accepts, so a first-name-only reader reports it as undocumented.
    `secret` rides in on its `### secret create` headings the same way, which
    is why it needs no exception here.
    """
    names = set()
    for heading in re.findall(r"^### (.+)$", _doc(), re.M):
        names.update(re.findall(r"`([a-z]+)", heading))
    return names


def _headings():
    """Every heading's GitHub anchor slug."""
    slugs = set()
    for line in _doc().splitlines():
        m = re.match(r"^#{1,6} (.+)$", line)
        if not m:
            continue
        text = m.group(1).lower().replace("`", "")
        slugs.add(re.sub(r"[^a-z0-9 -]", "", text).strip().replace(" ", "-"))
    return slugs


class CommandTableTest(unittest.TestCase):

    def test_every_command_is_listed(self):
        missing = _parser_commands() - set(_table_rows())
        self.assertEqual(missing, set(),
                         f"CLI subcommands absent from the command table: "
                         f"{sorted(missing)}")

    def test_no_listed_command_is_invented(self):
        extra = set(_table_rows()) - _parser_commands()
        self.assertEqual(extra, set(),
                         f"documented verbs the CLI rejects: {sorted(extra)}")

    def test_the_table_is_alphabetical(self):
        """A row inserted in the wrong place is how the next reader concludes
        the list is unordered and stops looking for the verb they wanted."""
        listed = [re.search(r"\[`([a-z]+)`\]", cell).group(1)
                  for cell in re.findall(r"^\| (\[`[a-z ]+`\]\(#[a-z-]+\)[^|]*)\|",
                                         _doc(), re.M)]
        self.assertEqual(listed, sorted(listed))


class SectionTest(unittest.TestCase):

    def test_every_command_has_a_section(self):
        missing = _parser_commands() - _sections()
        self.assertEqual(missing, set(),
                         f"CLI subcommands with a table row but no section: "
                         f"{sorted(missing)}")

    def test_no_section_documents_a_nonexistent_command(self):
        extra = _sections() - _parser_commands()
        self.assertEqual(extra, set(),
                         f"sections for verbs the CLI rejects: {sorted(extra)}")


class AnchorTest(unittest.TestCase):

    def test_every_table_link_resolves(self):
        """A table whose links 404 is worse than one with no links: it reads as
        navigable and is not."""
        headings = _headings()
        broken = {verb: anchor for verb, anchor in _table_rows().items()
                  if anchor not in headings}
        self.assertEqual(broken, {},
                         f"command-table links with no matching heading: {broken}")


if __name__ == "__main__":
    unittest.main()
