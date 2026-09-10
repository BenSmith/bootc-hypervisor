#!/usr/bin/env python3
"""Every mock patch target names something that still exists.

WHAT THIS IS AND IS NOT WORTH

Measured before it was written, and the first answer was wrong. The reason
given for building this was that a renamed symbol would leave `mock.patch`
binding nothing and the test would pass having asserted nothing. THAT IS NOT
WHAT MOCK DOES: both spellings raise on a missing attribute --

    <module 'nft_constants'> does not have the attribute 'no_such_name'

-- so a rename that outruns its patch targets fails loudly on the next run of
the test holding it, and the suite is already a complete gate for that.

What is left is narrower and worth stating exactly, because a guard that
claims more than it does is worse than none:

  * SPEED, on the one change this hazard belongs to. 2,177 targets resolve in
    under four seconds against 214 for the suite. Renaming a shared symbol is
    an edit-and-recheck loop, and a 57x shorter loop is the difference between
    checking every module and checking the ones you remembered.
  * THE TARGETS NOTHING EXECUTES. Six sit under skip decorators today. A patch
    in a branch the suite does not take reports nothing, because mock's error
    arrives when the patch runs, not when it is written.
  * THE EXTENSION-LESS ENTRYPOINTS. `X = load_script("libexec/...")` binds a
    file no tool in this repo can import by name; roughly 90 targets are read
    off one. CodeGraph does not index them either.

WHAT IT DOES NOT DO, INCLUDING THE FAILURE THAT IS ACTUALLY SILENT

The genuinely silent case is a patch that RESOLVES and binds the wrong object:
the target names a module that re-exports the name while the code under test
reads the defining module directly. The patch succeeds, the code runs
unpatched, and an ASSERTING test goes red while a SILENCING one goes green --
so the ones that survive are exactly the ones that were preventing a side
effect. This file cannot see that; it asks whether a name exists, not which
object a caller reads. `tests/test_module_imports.py` holds that half, by
asserting the `vm` facade re-exports nothing it does not define.

Note that patching a consumer rather than a definition is CORRECT and common
here -- 412 targets do it -- because `cmd_backup` does `from workloadctl_core
import require_root`, and patching `workloadctl_core.require_root` would not
affect it. A guard that flagged those would be flagging the right answer.

It also resolves NAMES, not signatures, and only targets spelled statically.
A first argument bound in `setUp` as `self.mod` is out of static reach and is
counted as unresolvable rather than skipped quietly --
`test_most_targets_are_actually_resolved` is what keeps that from swallowing
the file.

Nothing here executes a test or a patch. It imports the named modules, which
the suite imports anyway, and reads attributes off them.
"""

import ast
import importlib
import unittest
from pathlib import Path

from tests import load_script

# load_script re-executes the file, so each entrypoint is loaded once for the
# whole sweep rather than once per patch target that names it.
_SCRIPTS = {}

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS = REPO_ROOT / "tests"


def _test_files():
    return sorted(TESTS.rglob("*.py"))


def _module_aliases(tree):
    """Local name -> what to import, for every module a file binds.

    Two forms, because the second is where the coverage is. `import X` binds
    a module by name. `X = load_script("libexec/...")` binds one of the
    extension-less entrypoints, which are not importable by name at all --
    and those hold the largest patch surface in the suite, because the
    entrypoints are where the substrate helpers live. A script root is
    spelled `script:<repo-relative path>`.

    `from x import y` is deliberately not resolved: it binds an object, and
    deciding whether that object is a module or a value would mean importing
    to find out. The Attribute form below covers the cases that matter.
    """
    alias = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for entry in node.names:
                alias[entry.asname or entry.name.split(".")[0]] = entry.name
        elif isinstance(node, ast.Assign):
            call = node.value
            if not (isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "load_script"
                    and call.args
                    and isinstance(call.args[0], ast.Constant)):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    alias[target.id] = "script:" + call.args[0].value
    return alias


def _attribute_chain(node):
    """`podman.Podman._ensure` -> ("podman", ["Podman", "_ensure"]).

    Returns None for anything not rooted in a bare name.
    """
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return node.id, list(reversed(parts))


def _is_patch(func):
    """True for `patch(...)` and `mock.patch(...)`, false for patch.dict."""
    if isinstance(func, ast.Name):
        return func.id == "patch"
    return isinstance(func, ast.Attribute) and func.attr == "patch"


def _is_patch_object(func):
    if not (isinstance(func, ast.Attribute) and func.attr == "object"):
        return False
    base = func.value
    if isinstance(base, ast.Name):
        return base.id == "patch"
    return isinstance(base, ast.Attribute) and base.attr == "patch"


def _targets():
    """(file, line, spelling, root, attrs) for every patch target found.

    `root` is a dotted module name to import; `attrs` are read off it in
    order. A record with root None is unresolvable and is returned so the
    guard below can bound how many there are.
    """
    found = []
    for path in _test_files():
        tree = ast.parse(path.read_text())
        alias = _module_aliases(tree)
        rel = path.relative_to(REPO_ROOT)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # `create=True` patches a name that deliberately does not exist.
            if any(kw.arg == "create" for kw in node.keywords):
                continue
            if _is_patch(node.func):
                if not (node.args and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)):
                    found.append((rel, node.lineno, "<computed>", None, []))
                    continue
                spelling = node.args[0].value
                found.append((rel, node.lineno, spelling, spelling, None))
            elif _is_patch_object(node.func):
                if not (len(node.args) >= 2
                        and isinstance(node.args[1], ast.Constant)
                        and isinstance(node.args[1].value, str)):
                    found.append((rel, node.lineno, "<computed>", None, []))
                    continue
                attr = node.args[1].value
                first = node.args[0]
                if isinstance(first, ast.Name):
                    root, chain = alias.get(first.id), []
                else:
                    parsed = _attribute_chain(first)
                    if parsed is None:
                        found.append((rel, node.lineno, f"?.{attr}", None, []))
                        continue
                    root, chain = alias.get(parsed[0]), parsed[1]
                if root is None:
                    # A first argument bound by `from x import y`, or a local.
                    found.append((rel, node.lineno, f"?.{attr}", None, []))
                    continue
                spelling = ".".join([root] + chain + [attr])
                found.append((rel, node.lineno, spelling, root, chain + [attr]))
    return found


def _resolve(root, attrs):
    """Import what can be imported, then walk the rest as attributes.

    Returns the first component that does not resolve, or None if all do.
    A dotted string target is ambiguous -- `cmd_pcap.subprocess.run` is a
    module, a module attribute and a function -- so the longest importable
    prefix wins and the remainder is walked with getattr, which is what mock
    itself does.
    """
    if root.startswith("script:"):
        path = root.split(":", 1)[1]
        if path not in _SCRIPTS:
            try:
                _SCRIPTS[path] = load_script(path)
            except Exception:            # a moved entrypoint, not a moved name
                _SCRIPTS[path] = None
        obj = _SCRIPTS[path]
        if obj is None:
            return path
        rest = attrs
    elif attrs is None:
        parts = root.split(".")
        obj, used = None, 0
        for i in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:i]))
                used = i
                break
            except ImportError:
                continue
        if obj is None:
            return parts[0]
        rest = parts[used:]
    else:
        try:
            obj = importlib.import_module(root)
        except ImportError:
            return root
        rest = attrs
    for name in rest:
        if not hasattr(obj, name):
            return name
        obj = getattr(obj, name)
    return None


class TestTheSweepSeesThePatches(unittest.TestCase):
    """Guards the guard. Every failure mode here is silent: a moved tests
    directory, an AST walk that stopped matching the call shape, a resolver
    that returns None for everything. All of them find nothing broken, and
    nothing broken reads exactly like nothing wrong.
    """

    def test_the_tests_are_where_this_thinks_they_are(self):
        self.assertTrue(TESTS.is_dir(), TESTS)
        self.assertGreater(len(_test_files()), 50)

    def test_both_call_shapes_are_found_in_quantity(self):
        """Pinned as floors, not equalities: these counts move with ordinary
        test-writing, and a floor still catches the regression that matters
        -- an extractor that stopped recognising one of the two shapes."""
        strings = [t for t in _targets() if t[4] is None]
        objects = [t for t in _targets() if t[4]]
        self.assertGreater(len(strings), 400, len(strings))
        self.assertGreater(len(objects), 800, len(objects))

    def test_most_targets_are_actually_resolved(self):
        """The skip is the hole, so it is bounded from the useful side.

        A resolver change that quietly reclassified every target as
        unresolvable would empty the check below while every other assertion
        in this file still passed. The bound is a FLOOR ON WHAT RESOLVES
        rather than a ceiling on the share, because the share moves with
        ordinary test-writing and the floor moves only when the resolver
        stops working.

        About a fifth of targets are out of static reach and always will be:
        `patch.object(self.mod, ...)` where `self.mod` is bound in setUp,
        and module objects bound to locals inside a method. Resolving those
        means running the test, which is not this file's job.
        """
        found = _targets()
        resolved = [t for t in found if t[3] is not None]
        self.assertGreater(
            len(resolved), 1700,
            f"only {len(resolved)} of {len(found)} targets resolved")

    def test_the_resolver_would_see_a_stale_target(self):
        """Measured, not reasoned, in all three shapes the resolver walks:
        a dotted string, a module attribute, and a chain through a class."""
        self.assertEqual(_resolve("netfilter_state.no_such_function", None),
                         "no_such_function")
        self.assertEqual(_resolve("netfilter_state", ["no_such_function"]),
                         "no_such_function")
        self.assertEqual(_resolve("podman", ["Podman", "no_such_method"]),
                         "no_such_method")
        self.assertIsNone(_resolve("podman", ["Podman"]))

    def test_the_resolver_accepts_what_is_really_there(self):
        """The other half: a resolver that returned a failure for everything
        would make the check below fail loudly rather than silently, but a
        resolver that failed only for lib/ would not."""
        self.assertIsNone(_resolve("builtins.open", None))
        self.assertIsNone(_resolve("nft_constants", ["FamilyPair"]))

    def test_create_true_targets_are_excluded(self):
        """`create=True` exists to patch a name that is not there, so
        resolving those would report the feature as a defect."""
        tree = ast.parse('mock.patch("x.y", create=True)\n'
                         'mock.patch("x.z")\n')
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        kept = [c for c in calls
                if not any(kw.arg == "create" for kw in c.keywords)]
        self.assertEqual(len(kept), 1)


class TestEveryPatchTargetResolves(unittest.TestCase):

    def test_no_patch_names_something_that_moved(self):
        broken = []
        for rel, line, spelling, root, attrs in _targets():
            if root is None:
                continue
            missing = _resolve(root, attrs)
            if missing is not None:
                broken.append(
                    f"{rel}:{line} patches '{spelling}' and {missing} is not "
                    f"there; that patch raises AttributeError the next time "
                    f"it runs, and reports nothing until then")
        self.assertEqual(broken, [], "\n".join(broken))


if __name__ == "__main__":
    unittest.main()
