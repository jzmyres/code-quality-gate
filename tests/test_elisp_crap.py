"""End-to-end Emacs Lisp complexity, Edebug scoring and ratchet tests."""
from __future__ import annotations

import json
import os
import shlex
import tomllib

from support import FixtureCase, baseline_text, output
from test_elisp_tests import MODULE, SUITE, config
from test_trust import TrustCase


COMPLEXITY_SOURCE = """\
;;; complexity.el --- rule fixture -*- lexical-binding: t -*-
(require 'cl-lib)
(defun branches (x)
  (if x 1 2) (when x 1) (unless x 1) (while nil x)
  (dolist (v nil) v) (dotimes (v 0) v)
  (cl-dolist (v nil) v) (cl-dotimes (v 0) v)
  (cl-do ((v 0)) ((> v 0)) v) (cl-do* ((v 0)) ((> v 0)) v)
  (dolist-with-progress-reporter (v nil "fixture") v)
  (ignore-errors x) (bound-and-true-p x))
(defun operands (x) (and x x x) (or x x))
(defun clauses (x) (cond ((eq x 1) 1) ((eq x 2) 2) (t 3)))
(defun no-catchall (x) (cond ((eq x 1) 1) ((eq x 2) 2)))
(defun bindings (x)
  (if-let ((a x) (b x)) (+ a b))
  (if-let* ((a x) (b a)) (+ a b))
  (when-let ((a x) (b x)) (+ a b))
  (when-let* ((a x) (b a)) (+ a b))
  (and-let* ((a x) (b a)) (+ a b)))
(defun handlers (x)
  (condition-case err (if x 1 2) (error err) (quit err))
  (condition-case-unless-debug err x (error err)))
(defun case-pcase (x)
  (pcase x (`(if ,a ,b) (if x a b)) (_ 0)))
(defun case-exhaustive (x)
  (pcase-exhaustive x ('a 1) (_ 0)))
(defun case-cl (x) (cl-case x (a 1) (otherwise 0)))
(defun case-ecase (x) (cl-ecase x (a 1) (b 2)))
(defun case-type (x) (cl-typecase x (integer 1) (t 0)))
(defun loop-clauses (x)
  (cl-loop for v in x when v collect v while v until nil always v never nil thereis v))
(defun loop-if-unless (x)
  (cl-loop for v in x if v collect v)
  (cl-loop for v in x unless v collect v))
(defun quoted () (identity '(if x (when y (if z 1 2)) (cond (t (if a b c))))))
(defsubst inline-fn (x) (if x 1 2))
(defmacro macro-fn (x) `(if ,x 1 2))
(cl-defun extended-fn (&optional x) (if x 1 2))
(let () (defun nested-non-subject () (if t 1 2)))
"""

EXPECTED_COMPLEXITY = {
    "branches": 14,
    "operands": 4,
    "clauses": 3,
    "no-catchall": 3,
    "bindings": 11,
    "handlers": 5,
    "case-pcase": 3,
    "case-exhaustive": 2,
    "case-cl": 2,
    "case-ecase": 3,
    "case-type": 2,
    "loop-clauses": 8,
    "loop-if-unless": 5,
    "quoted": 1,
    "inline-fn": 2,
    "macro-fn": 2,
    "extended-fn": 2,
}


def crap_config(*, threshold: float = 6, requires: str = "legacy-tests") -> str:
    return (config().replace('checks = ["legacy-tests"]', 'checks = ["legacy-tests", "crap"]')
            + f'''\n[checks.crap]
adapter = "elisp_crap"
tier = 1
enforcement = "enforced"
requires = "{requires}"
threshold = {threshold}
baseline = "crap.toml"
''')


def simple_suite(body: str = "(should t)") -> str:
    return ("(require 'ert)\n(ert-deftest fixture () " + body + ")\n"
            "(ert-run-tests-batch-and-exit t)\n")


def uncovered_config() -> str:
    return crap_config() + '''\n[classes.extra]
code = true
description = "not instrumented"
checks = ["crap"]
[[rule]]
pattern = "other/*.el"
class = "extra"
reason = "additional source"
'''


def by_subject(check: dict) -> dict:
    return {item["subject"]: item for item in check["findings"]}


class ElispCrapTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        for path, contents in (("src/core.el", MODULE), ("tests/suite.el", SUITE)):
            self.add_file(path, contents)
        (self.repo / "a.py").unlink()
        self.write_config(crap_config())

    def run_crap(self, *args: str):
        result, document = self.run_json(*args)
        return result, document, self.check_by_id(document, "crap")

    def test_evidence_is_explicitly_removed_after_crap(self) -> None:
        self.add_file("crap.toml", baseline_text([], check="crap", metric_version="elisp-edebug/1"))
        _result, document = self.run_evidence_check()
        self.assertEqual(self.check_by_id(document, "legacy-tests")["outcome"], "pass")
        crap = self.check_by_id(document, "crap")
        self.assertEqual(crap["outcome"], "pass")
        self.assertTrue(crap["findings"])

    def test_complexity_table_and_subjects(self) -> None:
        self.add_file("src/core.el", COMPLEXITY_SOURCE)
        self.add_file("tests/suite.el", simple_suite())
        self.write_config(crap_config(threshold=10000))
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        findings = by_subject(check)
        self.assertEqual(set(findings), {f"src/core.el:{name}" for name in EXPECTED_COMPLEXITY})
        for name, expected in EXPECTED_COMPLEXITY.items():
            with self.subTest(name=name):
                self.assertEqual(findings[f"src/core.el:{name}"]["measurement"]["cc"], expected)
        self.assertEqual(check["metric_version"], "elisp-edebug/1")
        self.assertEqual(findings["src/core.el:branches"]["location"], "src/core.el:3")

    def test_policy_adds_a_branch_form_once_per_use(self) -> None:
        self.add_file("src/core.el", "(defun zero (x) (if x 1 2))\n"
                      "(defun once (x) (if x 1 2) (identity x))\n"
                      "(defun twice (x) (if x 1 2) (identity x) (identity x))\n")
        self.add_file("tests/suite.el", simple_suite())
        self.write_config(crap_config(threshold=100))
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual([item["measurement"]["cc"] for item in check["findings"]], [2, 2, 2])
        self.write_config(crap_config(threshold=100) + '''
[checks.crap.decision_rules]
branch = ["if", "when", "unless", "while", "dolist", "dotimes", "cl-dolist", "cl-dotimes",
          "cl-do", "cl-do*", "dolist-with-progress-reporter", "ignore-errors", "bound-and-true-p", "identity"]
''')
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        findings = by_subject(check)
        for name, expected in (("zero", 2), ("once", 3), ("twice", 4)):
            with self.subTest(name=name):
                self.assertEqual(findings[f"src/core.el:{name}"]["measurement"]["cc"], expected)

    def test_policy_replaces_each_family_and_auxiliary_symbols(self) -> None:
        self.add_file("src/core.el", "(defun fixture (x)\n"
                      " (if x 1 2) (and x x) (cond (x 1) (t 0))\n"
                      " (identity x) (list x x x) (progn (x 1) (otherwise 0))\n"
                      " (let ((a x) (b x)) x)\n"
                      " (custom-handler err x (error 0) (quit 0))\n"
                      " (cl-case x ((if x 1 2) (identity x)) (otherwise 0))\n"
                      " (custom-loop custom-key when))\n")
        self.add_file("tests/suite.el", simple_suite())
        self.write_config(crap_config(threshold=10000) + '''
[checks.crap.decision_rules]
branch = ["identity"]
operands = ["list"]
cond = ["progn"]
bindings = ["let"]
handlers = ["custom-handler"]
case = ["cl-case"]
loop = ["custom-loop"]
loop_clauses = ["custom-key"]
catch_all = ["otherwise"]
''')
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        # Base 1 + branch 1 + operands 2 + cond 1 + bindings 2 + handlers 2
        # + case 1 and its branch body 1 + loop 1 and its keyword 1.
        self.assertEqual(by_subject(check)["src/core.el:fixture"]["measurement"]["cc"], 13)

    def test_empty_rule_lists_disable_decisions_and_catchall_exemption(self) -> None:
        self.add_file("src/core.el", "(defun fixture (x)\n"
                      " (if x 1 2) (cl-loop for v in x when v collect v)\n"
                      " (cond (x 1) (t 0)) (pcase x (_ 0)))\n")
        self.add_file("tests/suite.el", simple_suite())
        self.write_config(crap_config(threshold=100) + '''
[checks.crap.decision_rules]
branch = []
loop_clauses = []
catch_all = []
''')
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(by_subject(check)["src/core.el:fixture"]["measurement"]["cc"], 5)

    def test_duplicate_rule_names_report_the_key_and_first_duplicate_index(self) -> None:
        for family in ("branch", "loop_clauses", "catch_all"):
            with self.subTest(family=family):
                self.write_config(crap_config() + '\n[checks.crap.decision_rules]\n'
                                  f'{family} = ["custom", "other", "custom", "other"]\n')
                result, document = self.run_json()
                self.assertEqual(result.returncode, 2, output(result))
                self.assertEqual(document["decision"], "error")
                self.assertIn(
                    f"{self.repo / 'quality-gate.toml'}: checks.crap.decision_rules.{family}[2]: "
                    "expected a unique symbol name, got 'custom'",
                    result.stderr,
                )

    def test_scores_and_lambda_attribution(self) -> None:
        body = "(if x (if (eq x 'yes) (+ 1 2) (+ 3 4)) (+ 5 6))"
        self.add_file("src/core.el", f"(defun reached (x) {body})\n"
                      f"(defun never (x) {body})\n(defun partial (x) {body})\n"
                      "(defun outer (x) (funcall (lambda (v) (+ v 1)) x))\n")
        self.add_file("tests/suite.el", simple_suite(
            "(progn (reached 'yes) (reached 'no) (reached nil) (partial 'yes) (outer 1))"))
        self.write_config(crap_config(threshold=100))
        result, document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        findings = by_subject(check)
        reached, never, partial = (
            findings[f"src/core.el:{name}"] for name in ("reached", "never", "partial")
        )
        self.assertEqual(reached["measurement"]["cc"], 3)
        self.assertEqual(reached["value"], 3)
        self.assertEqual(never["value"], 12)
        measurement = partial["measurement"]
        self.assertGreater(measurement["hits"], 0)
        self.assertLess(measurement["hits"], measurement["points"])
        self.assertEqual(partial["value"], 9 * (1 - measurement["hits"] / measurement["points"]) ** 3 + 3)
        entries = self.check_by_id(document, "legacy-tests")["definitions"]
        outer = findings["src/core.el:outer"]["measurement"]
        function = next(item for item in entries if item["symbol"] == "outer")
        self.assertGreater(outer["points"], function["stop_points"])
        self.assertEqual(outer["hits"], outer["points"])

    def test_adjacent_definitions_have_exclusive_end_positions(self) -> None:
        self.add_file("src/core.el", "(defun first () (+ 1 2))(defun second () (+ 3 4))\n")
        self.add_file("tests/suite.el", simple_suite("(should (= (second) 7))"))
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        findings = by_subject(check)
        self.assertEqual(findings["src/core.el:first"]["measurement"]["hits"], 0)
        second = findings["src/core.el:second"]["measurement"]
        self.assertEqual(second["hits"], second["points"])

    def test_attribution_never_crosses_files(self) -> None:
        (self.repo / "src/core.el").unlink()
        self.add_file("src/first.el", "(defun alpha () (+ 1 2))\n")
        self.add_file("src/second.el", "(defun bravo () (+ 3 4))\n")
        self.add_file("tests/suite.el", simple_suite("(should (= (bravo) 7))"))
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        findings = by_subject(check)
        self.assertEqual(findings["src/first.el:alpha"]["measurement"]["hits"], 0)
        second = findings["src/second.el:bravo"]["measurement"]
        self.assertEqual(second["hits"], second["points"])

    def test_attribution_matches_an_instrumented_alias_to_the_selected_file(self) -> None:
        text = crap_config().replace('pattern = "src/*.el"', 'pattern = "src/core.el"')
        self.write_config(text + '''\n[classes.alias]
code = true
description = "The same file selected only for tests"
checks = ["legacy-tests"]
[[rule]]
pattern = "src/alias.el"
class = "alias"
reason = "another path to the instrumented file"
''')
        alias = self.repo / "src/alias.el"
        for hard_link in (False, True):
            with self.subTest(hard_link=hard_link):
                if hard_link:
                    os.link(self.repo / "src/core.el", alias)
                else:
                    alias.symlink_to("core.el")
                try:
                    result, document, check = self.run_crap()
                    self.assertEqual(result.returncode, 0, output(result))
                    evidence = self.check_by_id(document, "legacy-tests")["definitions"]
                    self.assertEqual({item["file"] for item in evidence}, {"src/alias.el"})
                    used = by_subject(check)["src/core.el:sample-used"]["measurement"]
                    self.assertGreater(used["points"], 0)
                    self.assertGreater(used["hits"], 0)
                finally:
                    alias.unlink()

    def test_empty_and_docstring_only_definitions_are_unmeasured(self) -> None:
        self.add_file("src/core.el", '(defun empty ())\n(defun documented () "Only a docstring.")\n')
        self.add_file("tests/suite.el", simple_suite())
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(check["findings"], [])
        for name in ("empty", "documented"):
            self.assertIn(f"src/core.el:{name}: unmeasured", result.stderr)
        self.assertIn("no Edebug stop point in this definition", result.stderr)

    def set_debt_fixture(self) -> None:
        self.add_file("src/core.el", "(defun never (x) (if x (if x 1 2) 3))\n"
                      "(defun small () (+ 1 2))\n")
        self.add_file("tests/suite.el", simple_suite("(should (= (small) 3))"))

    def write_baseline(self, bound: float) -> None:
        self.add_file("crap.toml", baseline_text([
            {"subject": "src/core.el:never", "bound": bound, "reason": "legacy debt"},
            {"subject": "src/core.el:small", "bound": 5, "reason": "now resolved"},
            {"subject": "src/core.el:removed", "bound": 10, "reason": "removed"},
        ], check="crap", metric_version="elisp-edebug/1"))

    def test_ratchet_bounds_and_prune(self) -> None:
        self.set_debt_fixture()
        self.write_config(crap_config().replace("threshold = 6\n", ""))
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        findings = by_subject(check)
        self.assertIn("src/core.el:never", findings, output(result))
        self.assertEqual(findings["src/core.el:never"]["value"], 12)
        self.assertIn("value 12.0 exceeds threshold 6.0", result.stderr)
        for bound, code in ((11.99, 1), (12, 0), (15, 0)):
            with self.subTest(bound=bound):
                self.write_baseline(bound)
                result, _document, check = self.run_crap()
                self.assertEqual(result.returncode, code, output(result))
                self.assertEqual(check["satisfied"], code == 0)
                self.assertEqual(by_subject(check)["src/core.el:never"]["covered_by_baseline"], code == 0)
        result, document, check = self.run_crap("--prune", "crap")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(document["prune"]["performed"])
        self.assertIn("src/core.el:removed", check["resolved_baseline_entries"])
        entries = tomllib.loads(self.read_file("crap.toml"))["entry"]
        self.assertEqual([(item["subject"], item["bound"]) for item in entries], [("src/core.el:never", 12)])

    def test_threshold_must_be_finite(self) -> None:
        for value in ("nan", "inf", "-inf"):
            with self.subTest(value=value):
                self.write_config(crap_config().replace("threshold = 6", f"threshold = {value}"))
                result, document = self.run_json()
                self.assertEqual(result.returncode, 2, output(result))
                self.assertEqual(document["decision"], "error")
                self.assertIn("checks.crap.threshold", result.stderr)
                self.assertIn("finite", result.stderr)

    def test_requires_must_name_an_earlier_elisp_tests_check(self) -> None:
        later = '''\n[checks.later]\nadapter = "elisp_tests"\ntier = 1\n'''
        later += 'enforcement = "enforced"\nsuite = "tests/suite.el"\n'
        for required, suffix in (("missing", ""), ("smoke", ""), ("later", later)):
            with self.subTest(required=required):
                self.write_config(crap_config(requires=required) + suffix)
                result, document = self.run_json()
                self.assertEqual(result.returncode, 2, output(result))
                self.assertEqual(document["decision"], "error")
                self.assertIn("checks.crap.requires", result.stderr)
                self.assertIn(required, result.stderr)
                self.assertIn("elisp_tests check declared earlier", result.stderr)

    def test_failed_required_check_is_unsupported(self) -> None:
        self.add_file("tests/suite.el", simple_suite("(should nil)"))
        result, document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(self.check_by_id(document, "legacy-tests")["outcome"], "fail")
        self.assertEqual(check["outcome"], "unsupported")
        self.assertEqual(check["findings"], [])
        self.assertIn("coverage unreliable: legacy-tests did not pass", result.stderr)

    def test_no_selected_files_fails(self) -> None:
        text = crap_config().replace('checks = ["legacy-tests", "crap"]',
                                     'checks = ["legacy-tests"]')
        self.write_config(text + '''\n[classes.empty]
code = true
description = "empty selection"
checks = ["crap"]
''')
        result, document = self.run_json()
        check = self.check_by_id(document, "crap")
        self.assertIn("no files selected", result.stderr)
        self.assertIn("zero inputs is not a pass", check["reason"])
        self.assertEqual((result.returncode, check["outcome"]), (1, "fail"), output(result))
        self.add_file("tests/suite.el", simple_suite("(should nil)"))
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "unsupported")
        self.assertIn("coverage unreliable: legacy-tests did not pass", check["reason"])

    def test_missing_instrumentation_is_configuration_error(self) -> None:
        self.add_file("other/uncovered.el", "(defun other () 1)\n")
        self.write_config(uncovered_config())
        result, document = self.run_json()
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        for text in ("other/uncovered.el", "crap", "legacy-tests"):
            self.assertIn(text, result.stderr)

    def test_duplicate_identity_names_both_lines(self) -> None:
        self.add_file("src/core.el", "(defun same () (+ 1 2))\n\n(defun same () (+ 3 4))\n")
        self.add_file("tests/suite.el", simple_suite())
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        for text in ("duplicate function identity src/core.el:same", "src/core.el:1", "src/core.el:3"):
            self.assertIn(text, result.stderr)

    def test_reader_failure_names_file(self) -> None:
        cases = (
            ('(with-temp-file "src/core.el" (insert "(defun broken ("))', "End of file"),
            ('(delete-file "src/core.el")', "No such file"),
        )
        for action, error in cases:
            with self.subTest(error=error):
                self.add_file("src/core.el", MODULE)
                self.add_file("tests/suite.el", simple_suite(action))
                result, document, check = self.run_crap()
                self.assertEqual(result.returncode, 1, output(result))
                self.assertEqual(self.check_by_id(document, "legacy-tests")["outcome"], "pass")
                self.assertEqual(check["outcome"], "fail")
                self.assertIn("Cannot read src/core.el", result.stderr)
                self.assertIn(error, result.stderr)

    def test_complexity_child_failure_and_invalid_result(self) -> None:
        bad_helper = self.base / "bad-helper.el"
        bad_helper.write_text('''\
(defun qg-elisp-complexity-run (_root _files result)
  (with-temp-file result (insert "{\\"definitions\\":[{}]}")))
''', encoding="utf-8")
        wrapper = self.base / "emacs-wrapper"
        cases = (
            ("exec emacs -Q --batch --eval '(kill-emacs 3)'", "unsupported", "exit 3"),
            (f'exec emacs -Q --batch -l {shlex.quote(str(bad_helper))} --eval "$6"',
             "error", "expected valid complexity definitions"),
        )
        for command, outcome, reason in cases:
            with self.subTest(outcome=outcome):
                wrapper.write_text('#!/bin/sh\ncase "$4" in\n'
                                   f'*qg-elisp-complexity.el) {command};;\n'
                                   'esac\nexec emacs "$@"\n', encoding="utf-8")
                wrapper.chmod(0o755)
                text = crap_config().replace('suite = "tests/suite.el"',
                                             f'suite = "tests/suite.el"\nemacs = {json.dumps(str(wrapper))}')
                self.write_config(text)
                result, _document, check = self.run_crap()
                self.assertEqual(result.returncode, 1, output(result))
                self.assertEqual(check["outcome"], outcome)
                self.assertIn(reason, result.stderr)

    def test_symbol_names_are_preserved(self) -> None:
        self.add_file("src/core.el", "(defun foo:bar () (+ 1 2))\n"
                      "(defun foo\\ bar () (+ 1 2))\n(defun λ () (+ 1 2))\n"
                      "(defun ## () (+ 1 2))\n")
        self.add_file("tests/suite.el", simple_suite("(should (= (foo:bar) 3))"))
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(set(by_subject(check)), {
            "src/core.el:foo:bar", "src/core.el:foo bar", "src/core.el:λ", "src/core.el:",
        })

    def test_duplicate_complexity_definitions_are_an_error(self) -> None:
        report = ('{"definitions":[{"file":"src/core.el","name":"sample-used",'
                  '"line":2,"end_line":3,"start":1,"end":200,"cc":100}],"definitions":[]}')
        helper = self.base / "duplicate-helper.el"
        helper.write_text('(defun qg-elisp-complexity-run (_root _files result) '
                          f'(with-temp-file result (insert {json.dumps(report)})))\n', encoding="utf-8")
        wrapper = self.base / "emacs-wrapper"
        wrapper.write_text('#!/bin/sh\ncase "$4" in\n'
                           f'*qg-elisp-complexity.el) exec emacs -Q --batch -l {shlex.quote(str(helper))} '
                           '--eval "$6";;\nesac\nexec emacs "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
        self.write_config(crap_config().replace('suite = "tests/suite.el"',
                          f'suite = "tests/suite.el"\nemacs = {json.dumps(str(wrapper))}'))
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "error")
        self.assertIn("expected a complexity JSON result", check["reason"])
        self.assertIn("duplicate name 'definitions'", check["reason"])
        self.assertEqual(check["findings"], [])

    def test_suite_runs_only_once(self) -> None:
        counter = self.base / "suite-runs"
        expression = ('(with-temp-buffer (insert "run\\n") '
                      f'(append-to-file (point-min) (point-max) {json.dumps(str(counter))}))')
        self.add_file("tests/suite.el", simple_suite(expression))
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(counter.read_text(encoding="utf-8").splitlines(), ["run"])

    def test_changed_lines_cover_the_whole_definition(self) -> None:
        self.add_file("src/core.el", "(defun never (x)\n  (if x\n      (if x 1 2)\n    3))\n")
        self.add_file("tests/suite.el", simple_suite())
        self.add_file("crap.toml", baseline_text([
            {"subject": "src/core.el:never", "bound": 12, "reason": "legacy"},
        ], check="crap", metric_version="elisp-edebug/1"))
        self.commit_all()
        self.add_file("src/core.el", "(defun never (x)\n  (if x\n      (if x 9 2)\n    3))\n")
        result, _document, check = self.run_crap("--changed-from", "HEAD")
        self.assertEqual(result.returncode, 1, output(result))
        findings = by_subject(check)
        self.assertIn("src/core.el:never", findings, output(result))
        finding = findings["src/core.el:never"]
        self.assertEqual(finding["location"], "src/core.el:1")
        self.assertEqual(finding["locations"], [{"path": "src/core.el", "start_line": 1, "end_line": 4}])
        self.assertTrue(finding["on_changed_lines"])
        self.assertTrue(finding["blocking"])


class ElispCrapTrustTests(TrustCase):
    def test_prune_resolves_colon_names_only_in_selected_files(self) -> None:
        (self.repo / "a.py").unlink()
        self.add_file("src/core.el", MODULE)
        self.add_file("src/core.el:outside.el", "(defun outside () 1)\n")
        self.add_file("tests/suite.el", SUITE)
        text = crap_config().replace('pattern = "src/*.el"', 'pattern = "src/core.el"')
        text += '''\n[[rule]]
pattern = "src/core.el:outside.el"
class = "suite"
reason = "unselected file"
'''
        self.write_config(text)
        self.add_file("crap.toml", baseline_text([
            {"subject": "src/core.el:gone:member", "bound": 9, "reason": "removed"},
            {"subject": "src/core.el:outside.el:member", "bound": 9, "reason": "outside domain"},
        ], check="crap", metric_version="elisp-edebug/1"))
        revision = self.commit_revision()
        result, document = self.trust_json(revision, "--prune", "crap")
        self.assertEqual(result.returncode, 0, output(result))
        check = self.check_by_id(document, "crap")
        self.assertEqual(check["resolved_baseline_entries"], ["src/core.el:gone:member"])
        self.assertEqual(check["unmeasured_baseline_entries"], ["src/core.el:outside.el:member"])
        entries = tomllib.loads(self.read_file("crap.toml"))["entry"]
        self.assertEqual([item["subject"] for item in entries], ["src/core.el:outside.el:member"])
        self.assertTrue(document["prune"]["performed"])

    def test_trusted_policy_refuses_suite_symlink_outside_candidate(self) -> None:
        (self.repo / "a.py").unlink()
        self.add_file("src/core.el", MODULE)
        suite = self.add_file("tests/suite.el", SUITE)
        self.write_config(crap_config())
        revision = self.commit_revision()
        outside = self.base / "outside.el"
        outside.write_text(SUITE, encoding="utf-8")
        suite.unlink()
        suite.symlink_to(outside)
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn("checks.legacy-tests.suite", result.stderr)
        self.assertIn("repository-relative", result.stderr)
