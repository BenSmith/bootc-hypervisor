"""Every example in docs/schema-reference.toml must be a config that validates.

WHY THIS EXISTS

The reference is the one document an operator writes a workload from, and its
examples are what they copy. Nothing parsed them. So the file could -- and did
-- carry a "complete example" that `workloadctl validate` refuses with five
errors, sitting under prose that correctly explained each of those five
conflicts elsewhere on the same page. Prose and example drifted apart because
only the prose had a reader.

That is the same decay tests/test_manual_rig_configs.py catches one layer over:
a config that no gate parses is a config that rots at the speed of the schema.
The remedy is the same one -- parse it here, where it is free.

WHAT IT DOES NOT DO

It does not check that an example is a GOOD example, or that its prose is true.
An example can validate and still recommend something foolish. This asserts the
floor: what we tell an operator to copy is at least accepted by the tool we
tell them to run.
"""
import pathlib
import sys
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
REFERENCE = ROOT / "docs" / "schema-reference.toml"

sys.path.insert(0, str(ROOT / "lib"))
from validation import validate_workload_config  # noqa: E402


def examples():
    """Every commented example block, as (line number, TOML text).

    An example starts at a commented `[workload]` header -- every complete one
    in the file does -- and runs to the first line that is not a comment. The
    blocks are found rather than listed for the reason the rig gate gives: a
    hard-coded list is the same rot one level up.

    SO A BLANK LINE ENDS AN EXAMPLE. Several examples are followed by prose in
    the same comment run ("To verify groups work:", "Setup:"), which is not
    TOML and must not be read as part of the config; a real blank line between
    the two is what separates them. Prose appended without one fails this
    module with a TOML parse error naming the line -- loudly, which is the
    point, but the fix is a blank line rather than anything about the example.

    This is a convention holding a document together, which is the weaker
    half of this gate: it catches drift between the examples and the schema,
    and does nothing about the prose around them, which is still checked by
    nobody.
    """
    lines = REFERENCE.read_text().splitlines()
    found = []
    i = 0
    while i < len(lines):
        if lines[i].strip() == "# [workload]":
            start = i
            body = []
            while i < len(lines) and lines[i].startswith("#"):
                body.append(lines[i][1:].removeprefix(" "))
                i += 1
            found.append((start + 1, "\n".join(body) + "\n"))
        else:
            i += 1
    return found


class TestTheExamplesAreConfigs(unittest.TestCase):
    def test_the_file_still_has_examples_to_check(self):
        """A guard on the extractor, not on the document: if the comment style
        ever changes, this test would otherwise pass by finding nothing and the
        gate would be gone without a failure."""
        self.assertGreaterEqual(len(examples()), 15)

    def test_every_example_parses_as_toml(self):
        for line, text in examples():
            with self.subTest(line=line):
                try:
                    tomllib.loads(text)
                except tomllib.TOMLDecodeError as e:
                    self.fail(f"example at line {line} is not valid TOML: {e}")

    def test_every_example_validates(self):
        """The check the complete VM example failed until 2026-08-25."""
        for line, text in examples():
            with self.subTest(line=line):
                errors = validate_workload_config(tomllib.loads(text))
                self.assertEqual(
                    errors, [],
                    f"example at line {line} of docs/schema-reference.toml "
                    f"would be refused by `workloadctl validate`:\n  "
                    + "\n  ".join(errors))
