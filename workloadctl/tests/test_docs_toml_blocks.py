"""Every ```toml block in a tracked doc must be TOML, in this schema.

WHY THIS EXISTS

Same reason as tests/test_docs_examples.py one level out: a config that no gate
parses rots at the speed of the schema, and a fenced block in prose is a config
a reader will copy. Three had already rotted where nothing could see it --
docs/workloads.md carried a multi-line inline table (TOML has no such thing, so
it fails the moment you paste it), a basic VM config the validator rejects for
having no [vm.network], and a [[vm.volumes]] table with host_path/guest_path
keys for a schema whose volumes are "host:guest[:opts]" strings.

THE THREE CHECKS, AND WHY THE THIRD IS NAME-LEVEL

  1. every block parses;
  2. a block that is a whole config -- it has [workload].name -- validates;
  3. every key and every table name in every block is one docs/schema-reference.toml
     documents.

(2) can only see self-contained blocks, and most blocks in prose are fragments:
a [vm.network] stanza with no [workload], a [resources] excerpt. Filling in the
missing halves to make them validatable means inventing an egress mode or an
image source, and the invented value is what most of the errors then come from.
(3) needs no invention -- it compares names against the reference the schema
already keeps -- and it is exactly the check that catches host_path. Measured
before it was written: 48 blocks, zero false positives.

The oracle for (3) is docs/schema-reference.toml itself, which is not
independent of the docs it checks. That is the point: it makes the reference the
one place a new key has to be written down, and a key added to the code and to
prose but not to the reference fails here.
"""
import pathlib
import re
import subprocess
import sys
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
REFERENCE = DOCS / "schema-reference.toml"

sys.path.insert(0, str(ROOT / "lib"))
from validation import validate_workload_config  # noqa: E402

BLOCK = re.compile(r"```toml\n(.*?)```", re.S)
# Keys and table headers, read through a leading "# " so a commented-out example
# in the reference counts as documented -- most of the reference is commented.
KEY = re.compile(r"^([a-z_][a-z0-9_]*)\s*=")
TABLE = re.compile(r"^\[\[?([a-z0-9_.]+)\]\]?$")

# Blocks that deliberately do not parse, because what they illustrate is a
# choice between spellings of the same key. Keyed by a distinctive line rather
# than a line number so ordinary edits above them don't need a change here.
# Every entry is a block a reader cannot copy whole -- keep the list short.
WONT_PARSE = {
    'name = "my-very-long-workload-name"',   # a bad name beside a good one
    "security_opt = [\"seccomp=/usr/share/containers/seccomp.json\"]",  # three alternatives
}


def _names(text: str) -> tuple[set[str], set[str]]:
    """The key names and table names in a TOML-ish text, comments included."""
    keys, tables = set(), set()
    for line in text.splitlines():
        stripped = line.lstrip("# ").strip()
        m = KEY.match(stripped)
        if m:
            keys.add(m.group(1))
        m = TABLE.match(stripped)
        if m:
            tables.add(m.group(1))
    return keys, tables


# Beyond docs/: the overview files carry copyable blocks too, and the repo-root
# README's block is one that had rotted (a flat /etc/workloads.d/<name>.toml,
# a path nothing globs). Named rather than globbed -- these are the three
# hand-written overviews, not every README in the tree.
EXTRA_DOCS = (ROOT / "README.md", ROOT / "llms.txt", ROOT.parent / "README.md")


def _tracked_docs() -> list[pathlib.Path]:
    # The RPM build runs the suite inside a container that has no git and no
    # .git, so this has to skip rather than error there -- same treatment
    # test_doc_citations gives its own ls-files.
    try:
        out = subprocess.run(
            ["git", "ls-files", "docs"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError) as e:
        raise unittest.SkipTest(f"git unavailable: {e}")
    docs = [ROOT / p for p in out.stdout.split() if p.endswith(".md")]
    if not docs:
        raise unittest.SkipTest("no tracked docs")
    return docs + [p for p in EXTRA_DOCS if p.exists()]


def _rel(path: pathlib.Path) -> str:
    """Repo-relative, since EXTRA_DOCS reaches one level above ROOT."""
    return path.relative_to(ROOT.parent).as_posix()


def _blocks():
    """(path, line, text) for every fenced toml block in every tracked doc."""
    for path in _tracked_docs():
        text = path.read_text()
        for m in BLOCK.finditer(text):
            yield path, text[: m.start()].count("\n") + 1, m.group(1)


class TestDocTomlBlocks(unittest.TestCase):
    def setUp(self):
        self.keys, self.tables = _names(REFERENCE.read_text())

    def test_the_docs_still_have_toml_blocks(self):
        """A guard on the regex, not on the docs: a fence style change would
        otherwise pass every test below by iterating over nothing."""
        self.assertGreaterEqual(len(list(_blocks())), 40)

    def test_the_reference_still_documents_a_schema(self):
        """Same guard for the oracle: an unreadable reference makes check (3)
        vacuous in the permissive direction, where nothing fails."""
        self.assertGreaterEqual(len(self.keys), 80)
        self.assertIn("vm.network", self.tables)

    def test_blocks_parse(self):
        for path, line, text in _blocks():
            rel = _rel(path)
            if any(marker in text for marker in WONT_PARSE):
                continue
            with self.subTest(block=f"{rel}:{line}"):
                try:
                    tomllib.loads(text)
                except tomllib.TOMLDecodeError as e:
                    self.fail(f"{rel}:{line} is not valid TOML: {e}")

    def test_whole_configs_validate(self):
        for path, line, text in _blocks():
            rel = _rel(path)
            if any(marker in text for marker in WONT_PARSE):
                continue
            config = tomllib.loads(text)
            if "name" not in config.get("workload", {}):
                continue
            with self.subTest(block=f"{rel}:{line}"):
                self.assertEqual(
                    validate_workload_config(config), [],
                    f"{rel}:{line} is a complete config the validator rejects",
                )

    def test_every_name_is_in_the_schema_reference(self):
        for path, line, text in _blocks():
            rel = _rel(path)
            keys, tables = _names(text)
            with self.subTest(block=f"{rel}:{line}"):
                self.assertEqual(
                    sorted(keys - self.keys), [],
                    f"{rel}:{line} uses keys docs/schema-reference.toml does not document",
                )
                self.assertEqual(
                    sorted(tables - self.tables), [],
                    f"{rel}:{line} uses tables docs/schema-reference.toml does not document",
                )


if __name__ == "__main__":
    unittest.main()
