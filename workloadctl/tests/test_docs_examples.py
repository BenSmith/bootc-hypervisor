"""Every file in docs/examples/ must be a config that validates.

WHY THIS EXISTS

Same reason as tests/test_schema_reference_examples.py and
tests/test_manual_rig_configs.py: a config that no gate parses rots at the
speed of the schema. These five files are the ones an operator copies whole
into /etc/workloads.d/, and nothing read them -- so the only thing keeping
them current was someone remembering they were there.

WHAT IT DOES NOT DO

It does not check the prose around the config, which is where these had
actually drifted (a workload named one thing, its user and its unit named
another). That half is still checked by nobody.
"""
import pathlib
import sys
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "docs" / "examples"

sys.path.insert(0, str(ROOT / "lib"))
from validation import validate_workload_config  # noqa: E402


class TestTheExamplesAreConfigs(unittest.TestCase):
    def test_the_directory_still_has_examples(self):
        """A guard on the glob, not on the documents: an empty directory would
        otherwise pass every test below by iterating over nothing."""
        self.assertGreaterEqual(len(list(EXAMPLES.glob("*.toml"))), 5)

    def test_every_example_parses_and_validates(self):
        for path in sorted(EXAMPLES.glob("*.toml")):
            with self.subTest(example=path.name):
                try:
                    config = tomllib.loads(path.read_text())
                except tomllib.TOMLDecodeError as e:
                    self.fail(f"{path.name} is not valid TOML: {e}")
                errors = validate_workload_config(config)
                self.assertEqual(
                    errors, [],
                    f"docs/examples/{path.name} would be refused by "
                    f"`workloadctl validate`:\n  " + "\n  ".join(errors))

    def test_the_workload_name_matches_the_file(self):
        """The prose in these files names the user (`_wl-<name>`), the unit
        (`workload-<name>.service`) and the CLI argument, all derived from
        [workload].name. Every one of those was wrong in two files because the
        name and the filename had diverged and nothing tied them together."""
        for path in sorted(EXAMPLES.glob("*.toml")):
            with self.subTest(example=path.name):
                config = tomllib.loads(path.read_text())
                self.assertEqual(config["workload"]["name"], path.stem)


if __name__ == "__main__":
    unittest.main()
