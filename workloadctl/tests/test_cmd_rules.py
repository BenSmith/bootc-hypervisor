"""Rung 5 T6 — the effective-rules report.

WHAT THESE PIN, and why each one is here rather than being obvious:

The report exists because reading the file is NOT the same as knowing what
applies. `vm_policy_governs()`'s docstring has said so since rung 3: host
patterns union among themselves, so `*.example.com` and `api.example.com` both
govern `api.example.com` and neither overrides the other. Every test below is
either that composition rule as an operator would see it rendered, or one of the
three places a renderer can quietly get it wrong -- the union reading, the
absent/empty distinction, and a splice pattern on a host no list admits.

The report calls the shipped matcher, so what is NOT tested here is matching
itself; `tests/test_vm_egress.py` owns that. What is tested is that the report
asks the matcher the same question the listener asks it.
"""

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import cmd_rules


def doc(**over):
    """A policy document with every key present, as vm_inspect_policy renders
    one. Written out rather than built by calling the renderer: a test that
    generated its input from the code under test's own upstream would follow a
    mistake there into a green run here."""
    base = {"tls": "inspect", "hosts": [], "internal": [], "splice": [],
            "http2": [], "policy": []}
    base.update(over)
    return base


def entry(host, methods=None, paths=None):
    return {"host": host, "methods": methods, "paths": paths}


class CompositionRuleTest(unittest.TestCase):
    """§3: a host any policy entry matches is governed by THOSE ENTRIES ALONE."""

    def test_a_governed_host_does_not_report_the_allowlist_as_permitting_it(self):
        """The union reading, which is the failure this report exists to make
        visible rather than to commit. `*.example.com` in `hosts` covers the
        host, but a policy entry governs it, so the allowlist is not consulted
        -- and the report must not print `any method, any path`."""
        d = doc(hosts=["*.example.com"],
                policy=[entry("api.example.com", methods=["GET"])])
        view = cmd_rules.explain(d, "api.example.com")
        self.assertEqual([e.host for e in view["governing"]], ["api.example.com"])
        text = "\n".join(cmd_rules.render_query(view, d, "disk", "/p", "wl"))
        self.assertIn("NOT consulted", text)
        self.assertNotIn("any method, any path", text)

    def test_both_patterns_are_shown_against_the_one_name(self):
        """The trap in the docstring, stated positively: two entries govern and
        neither overrides, so both must appear."""
        d = doc(policy=[entry("*.example.com", methods=["GET"]),
                        entry("api.example.com", paths=["/v1/*"])])
        view = cmd_rules.explain(d, "api.example.com")
        self.assertEqual(len(view["governing"]), 2)
        text = "\n".join(cmd_rules.render_query(view, d, "disk", "/p", "wl"))
        self.assertIn("*.example.com", text)
        self.assertIn("/v1/*", text)
        self.assertIn("override one another", text)

    def test_an_ungoverned_allowlisted_host_is_any_method_any_path(self):
        d = doc(hosts=["files.example.com"])
        text = "\n".join(cmd_rules.render_query(
            cmd_rules.explain(d, "files.example.com"), d, "disk", "/p", "wl"))
        self.assertIn("any method, any path", text)

    def test_a_policy_entry_admits_its_own_host(self):
        """Mirrors the listener's Policy.admits(): a name in `policy` need not
        also appear in `hosts`. A report checking `hosts` alone would print
        `not allowlisted` for a host the operator's file plainly names."""
        d = doc(policy=[entry("api.example.com", methods=["GET"])])
        view = cmd_rules.explain(d, "api.example.com")
        self.assertTrue(view["admitted"])
        text = "\n".join(cmd_rules.render_query(view, d, "disk", "/p", "wl"))
        self.assertIn("policy entries alone", text)

    def test_a_host_on_no_list_is_refused(self):
        d = doc(hosts=["a.example.com"])
        text = "\n".join(cmd_rules.render_query(
            cmd_rules.explain(d, "b.example.com"), d, "disk", "/p", "wl"))
        self.assertIn("every connection", text)
        self.assertIn("is refused", text)

    def test_the_refusal_names_the_two_lists_that_admit(self):
        """`internal`, `splice` and `http2` admit nothing on their own, so a
        host sitting in one of them and in neither `hosts` nor `policy` is
        still refused -- and saying `no list names this host` about it would be
        plainly false to an operator looking at the file."""
        d = doc(splice=["b.example.com"])
        text = "\n".join(cmd_rules.render_query(
            cmd_rules.explain(d, "b.example.com"), d, "disk", "/p", "wl"))
        self.assertIn("admit nothing on their own", text)

    def test_the_apex_trap_is_preserved(self):
        """`*.example.com` does not authorise `example.com`. Three tracked files
        document that; a report that quietly widened it would tell an operator
        they have a destination they do not have."""
        self.assertFalse(
            cmd_rules.explain(doc(hosts=["*.example.com"]), "example.com")
            ["admitted"])


class EntryFieldTest(unittest.TestCase):
    def test_absent_is_any(self):
        self.assertEqual(cmd_rules._field(None), "any")

    def test_empty_is_not_rendered_as_any(self):
        """Absent means ANY, empty would mean NONE, and printing both as a
        blank hides exactly the widening trap VmPolicyEntry is built around."""
        self.assertEqual(cmd_rules._field([]), "(none)")


class TlsTreatmentTest(unittest.TestCase):
    def test_a_splice_pattern_on_an_unadmitted_host_says_refused(self):
        """The listener's parenthesisation: `if inspect and not (allowed and
        splices(host))`. THE ALLOWLIST DECISION COMES FIRST, so a name on the
        splice list and on no allowlist is refused, not spliced -- and a splice
        pattern can cover names `hosts` does not, which validation cannot catch.
        """
        view = cmd_rules.explain(doc(splice=["*.example.com"]),
                                 "api.example.com")
        treatment = cmd_rules.tls_treatment(view)
        self.assertTrue(treatment.startswith("refused"), treatment)
        self.assertIn("allowlist decision comes first", treatment)

    def test_a_splice_pattern_on_an_admitted_host_splices(self):
        view = cmd_rules.explain(
            doc(hosts=["*.example.com"], splice=["*.example.com"]),
            "api.example.com")
        self.assertTrue(cmd_rules.tls_treatment(view).startswith("spliced, by:"))

    def test_splice_mode_says_the_per_host_list_changes_nothing(self):
        view = cmd_rules.explain(doc(tls="splice", hosts=["a.example.com"]),
                                 "a.example.com")
        self.assertIn("changes nothing", cmd_rules.tls_treatment(view))

    def test_splice_mode_still_refuses_an_unadmitted_host(self):
        """Found in review. Under `tls = "splice"` the listener does not take
        the terminating branch at all -- it falls through to `if not allowed`
        and drops. Reporting an unadmitted host as "spliced" there described a
        code path the connection never reaches, which is the same class of
        error as the union reading."""
        view = cmd_rules.explain(doc(tls="splice", hosts=["a.example.com"]),
                                 "b.example.com")
        self.assertTrue(cmd_rules.tls_treatment(view).startswith("refused"))

    def test_an_unadmitted_host_reaches_no_treatment_in_either_mode(self):
        for mode in ("inspect", "splice"):
            with self.subTest(tls=mode):
                view = cmd_rules.explain(doc(tls=mode), "b.example.com")
                self.assertIn("refused", cmd_rules.tls_treatment(view))

    def test_the_default_is_terminated_and_parsed(self):
        view = cmd_rules.explain(doc(hosts=["a.example.com"]), "a.example.com")
        self.assertEqual(cmd_rules.tls_treatment(view), "terminated and parsed")


class EnumerationTest(unittest.TestCase):
    def test_literals_come_from_every_key(self):
        d = doc(hosts=["a.example.com"], internal=["b.example.com"],
                splice=["c.example.com"], http2=["d.example.com"],
                policy=[entry("e.example.com")])
        self.assertEqual(cmd_rules.literal_names(d),
                         ["a.example.com", "b.example.com", "c.example.com",
                          "d.example.com", "e.example.com"])

    def test_wildcards_are_not_enumerated_as_names(self):
        d = doc(hosts=["*.example.com", "a.example.com"])
        self.assertEqual(cmd_rules.literal_names(d), ["a.example.com"])
        self.assertEqual(cmd_rules.wildcard_patterns(d),
                         [("*.example.com", "hosts")])

    def test_a_character_class_is_a_wildcard(self):
        """fnmatch honours `[...]`, so a name carrying one names no host.
        Enumerating it as a literal would then report it as matching nothing."""
        self.assertEqual(cmd_rules.literal_names(doc(hosts=["a[bc].example.com"])),
                         [])

    def test_an_all_wildcard_document_says_so_rather_than_printing_nothing(self):
        """An empty report would read as `there are no rules`, which is the
        opposite of what an all-wildcard document means."""
        text = "\n".join(cmd_rules.render_enumeration(
            doc(hosts=["*.example.com"]), "disk", "/p", "wl"))
        self.assertIn("every pattern in this document is a wildcard", text)
        self.assertIn("cannot be enumerated", text)

    def test_the_enumeration_gives_each_literal_its_verdict(self):
        d = doc(hosts=["*.example.com", "files.example.com"],
                policy=[entry("api.example.com", methods=["GET"])])
        text = "\n".join(cmd_rules.render_enumeration(d, "disk", "/p", "wl"))
        self.assertIn("api.example.com", text)
        self.assertIn("1 policy entry", text)
        self.assertIn("allowlisted, any method and path", text)


class UnreadableEntriesTest(unittest.TestCase):
    """A `policy` element this reader cannot parse narrows the report, and a
    narrowed report is wrong in the PERMISSIVE direction: the host whose only
    governing entry was dropped reads as `any method, any path`."""

    BAD = doc(hosts=["a.example.com"],
              policy=[entry("api.example.com"), {"methods": ["GET"]}, "nope"])

    def test_they_are_counted(self):
        self.assertEqual(cmd_rules.unreadable_entries(self.BAD), 2)

    def test_a_clean_document_counts_none(self):
        self.assertEqual(
            cmd_rules.unreadable_entries(doc(policy=[entry("a.example.com")])), 0)

    def test_the_query_form_warns(self):
        text = "\n".join(cmd_rules.render_query(
            cmd_rules.explain(self.BAD, "a.example.com"), self.BAD, "disk",
            "/p", "wl"))
        self.assertIn("NARROWER than the file", text)

    def test_the_enumeration_warns_too(self):
        """Both forms, because the failure does not depend on which one is
        being read."""
        text = "\n".join(
            cmd_rules.render_enumeration(self.BAD, "disk", "/p", "wl"))
        self.assertIn("NARROWER than the file", text)


class DocumentSourceTest(unittest.TestCase):
    """Which file the report read, said out loud."""

    class _Config:
        def __init__(self, config):
            self.config = config

    NET = {"egress": "filtered", "hosts": ["a.example.com"]}

    def _config(self):
        return self._Config({"vm": {"network": dict(self.NET)}})

    def test_the_document_on_disk_wins(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "inspect.json"
            path.write_text(json.dumps(doc(hosts=["ondisk.example.com"])))
            with mock.patch.object(cmd_rules, "vm_inspect_policy_path",
                                   return_value=str(path)):
                d, origin, got = cmd_rules.load_document("wl", self._config())
        self.assertEqual(origin, "disk")
        self.assertEqual(d["hosts"], ["ondisk.example.com"])
        self.assertEqual(got, str(path))

    def test_a_missing_document_falls_back_to_the_toml(self):
        """A stopped VM has no document, and that is its ordinary state, not a
        fault -- `drift` makes the same distinction for the same reason."""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "absent.json"
            with mock.patch.object(cmd_rules, "vm_inspect_policy_path",
                                   return_value=str(path)):
                d, origin, got = cmd_rules.load_document("wl", self._config())
        self.assertEqual(origin, "config")
        self.assertIsNone(got)
        self.assertEqual(d["hosts"], ["a.example.com"])

    def test_a_malformed_document_is_an_error_not_a_re_render(self):
        """A document the listener could not parse is a document it did not
        load. Answering from the TOML instead would describe rules that are
        provably not in force."""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "inspect.json"
            path.write_text("{not json")
            with mock.patch.object(cmd_rules, "vm_inspect_policy_path",
                                   return_value=str(path)):
                with self.assertRaises(RuntimeError) as caught:
                    cmd_rules.load_document("wl", self._config())
        self.assertIn("not valid JSON", str(caught.exception))

    def test_an_unreadable_document_names_the_remedy(self):
        """write_policy() writes 0640 root:_wl-<name>, so an operator who is
        neither gets EACCES. A bare `Permission denied` sends them to look at
        the file rather than at their own uid; `egress` says the same thing
        about the record for the same reason."""
        with mock.patch.object(cmd_rules, "vm_inspect_policy_path",
                               return_value="/p/x.json"), \
             mock.patch.object(cmd_rules.Path, "read_text",
                               side_effect=PermissionError(13, "denied")):
            with self.assertRaises(RuntimeError) as caught:
                cmd_rules.load_document("wl", self._config())
        self.assertIn("Re-run as root", str(caught.exception))

    def test_the_rendered_case_names_the_workload_and_says_it_is_a_render(self):
        text = "\n".join(cmd_rules.render_query(
            cmd_rules.explain(doc(), "a.example.com"), doc(), "config", None,
            "myvm"))
        self.assertIn("has not started this boot", text)
        self.assertIn("myvm", text)

    def test_the_disk_case_points_at_drift_for_the_other_question(self):
        text = "\n".join(cmd_rules.render_query(
            cmd_rules.explain(doc(), "a.example.com"), doc(), "disk",
            "/p/x.json", "myvm"))
        self.assertIn("/p/x.json", text)
        self.assertIn("drift", text)


class CommandTest(unittest.TestCase):
    """The verb itself: refusal for a workload with no inspected egress, the
    two forms, and the JSON shape."""

    def _args(self, **kw):
        fields = {"workload": "wl", "host": None, "json": False}
        fields.update(kw)
        return mock.Mock(**fields)

    def _config(self, net=None):
        cfg = mock.Mock()
        cfg.config = {"vm": {"network": net if net is not None
                             else {"egress": "filtered",
                                   "hosts": ["a.example.com"]}}}
        return cfg

    def _run(self, args, net=None, uses_inspect=True):
        buf = io.StringIO()
        with mock.patch.object(cmd_rules, "load_config_or_exit",
                               return_value=self._config(net)), \
             mock.patch.object(cmd_rules, "vm_uses_inspect",
                               return_value=uses_inspect), \
             mock.patch.object(cmd_rules, "vm_inspect_policy_path",
                               return_value="/nonexistent/inspect.json"), \
             redirect_stdout(buf):
            code = cmd_rules.cmd_rules(args, mock.Mock())
        return code, buf.getvalue()

    def test_an_unfiltered_workload_is_refused_with_a_nonzero_code(self):
        """And the code has to be RETURNED nonzero, because `rules` reports
        failure the way `egress` does -- main() exits with what a handler
        returns, and a handler that printed a diagnostic and returned 0 was the
        rung 5 defect found on hardware."""
        code, _ = self._run(self._args(), uses_inspect=False)
        self.assertEqual(code, 1)

    def test_the_query_form_runs_when_a_host_is_given(self):
        code, out = self._run(self._args(host="a.example.com"))
        self.assertEqual(code, 0)
        self.assertIn("a.example.com", out)
        self.assertIn("allowlist", out)

    def test_the_enumeration_runs_when_no_host_is_given(self):
        code, out = self._run(self._args())
        self.assertEqual(code, 0)
        self.assertIn("literal name", out)

    def test_json_query_carries_the_governing_entries(self):
        code, out = self._run(
            self._args(host="api.example.com", json=True),
            net={"egress": "filtered", "hosts": ["*.example.com"],
                 "policy": [{"host": "api.example.com", "methods": ["GET"]}]})
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["origin"], "config")
        self.assertEqual(payload["query"]["governing"],
                         [{"host": "api.example.com", "methods": ["GET"],
                           "paths": None}])

    def test_json_carries_the_unreadable_count(self):
        code, out = self._run(self._args(json=True))
        self.assertEqual(json.loads(out)["unreadable_policy_elements"], 0)

    def test_json_enumeration_carries_literals_and_wildcards(self):
        code, out = self._run(
            self._args(json=True),
            net={"egress": "filtered",
                 "hosts": ["*.example.com", "a.example.com"]})
        payload = json.loads(out)
        self.assertEqual([v["host"] for v in payload["literals"]],
                         ["a.example.com"])
        self.assertEqual(payload["wildcards"],
                         [{"pattern": "*.example.com", "key": "hosts"}])


class UnknownTlsModeTest(unittest.TestCase):
    """A `tls` value this report does not know is not described as `inspect`.

    The terminating sentence is the fall-through arm, so an unrecognised mode
    inherits it silently. VM_TLS_UNBUILT is kept in vm.py precisely because a
    third mode is expected, and the day it lands this report would start
    describing its connections as `terminated and parsed` without a diff.
    """

    def test_an_unknown_mode_is_named_rather_than_described(self):
        view = cmd_rules.explain(doc(hosts=["a.com"], tls="future"), "a.com")
        self.assertIn("is not a mode this report knows",
                      cmd_rules.tls_treatment(view))

    def test_admission_still_comes_first(self):
        """An unadmitted host is refused whatever the mode says -- the listener
        answers the allowlist before it reaches any TLS treatment."""
        view = cmd_rules.explain(doc(tls="future"), "a.com")
        self.assertTrue(cmd_rules.tls_treatment(view).startswith("refused"))

    def test_the_known_modes_are_still_described(self):
        for mode, expected in (("inspect", "terminated and parsed"),
                               ("splice", "spliced")):
            view = cmd_rules.explain(doc(hosts=["a.com"], tls=mode), "a.com")
            self.assertTrue(cmd_rules.tls_treatment(view).startswith(expected),
                            f"{mode}: {cmd_rules.tls_treatment(view)}")


if __name__ == "__main__":
    unittest.main()
