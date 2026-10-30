"""Real Emacs fixture tests for the ERT and Edebug collector."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

from support import GATE, FixtureCase, baseline_text, output


MODULE = """\
;;; core.el --- fixture -*- lexical-binding: t -*-
(defun sample-used (number)
  (funcall (lambda (value) (+ value 1)) number))
(defun sample-unused (number)
  (+ number 2))
(provide 'core)
"""
SUITE = """\
(require 'ert)
(ert-deftest sample-one () (should (= (sample-used 1) 2)))
(ert-deftest sample-two () (should (= (sample-used 4) 5)))
(ert-run-tests-batch-and-exit t)
"""


def config(extra: str = "", *, extra_rules: str = "", instrument_suite: bool = False) -> str:
    suite_class = "module" if instrument_suite else "suite"
    return f'''\
schema = 2
[code]
patterns = ["*.el"]
shebangs = []
[levels]
required_tiers = [1]
[classes.module]
code = true
description = "Measured modules"
checks = ["legacy-tests"]
[classes.suite]
code = true
description = "Suite and supporting files"
checks = ["smoke"]
[classes.config]
code = false
description = "Configuration"
[classes.doc]
code = false
description = "Documentation"
[checks.legacy-tests]
adapter = "elisp_tests"
tier = 1
enforcement = "enforced"
suite = "tests/suite.el"
{extra}
[checks.smoke]
adapter = "command"
tier = 1
enforcement = "enforced"
run = ["python3", "-c", "print(1)"]
tests_pattern = '(\\d+)'
[[rule]]
pattern = "src/*.el"
class = "module"
reason = "measured modules"
[[rule]]
pattern = "tests/*.el"
class = "{suite_class}"
reason = "suite"
[[rule]]
pattern = "*.toml"
class = "config"
reason = "configuration"
[[rule]]
pattern = "*.md"
class = "doc"
reason = "documentation"
[[rule]]
pattern = ".gitignore"
class = "config"
reason = "ignore rules"
{extra_rules}
'''


def executed_entry(bound: int) -> dict[str, object]:
    return {
        "subject": "tests:legacy-tests:executed",
        "bound": bound,
        "reason": "floor",
    }


class ElispTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.add_file("src/core.el", MODULE)
        self.add_file("tests/suite.el", SUITE)
        self.write_config(config())

    def run_check(self):
        result, document = self.run_json()
        return result, self.check_by_id(document, "legacy-tests")

    def assert_outcome(self, expected: str, *needles: str):
        result, check = self.run_check()
        self.assertEqual(result.returncode, 0 if expected == "pass" else 1, output(result))
        self.assertEqual(check["outcome"], expected, output(result))
        for needle in needles:
            self.assertIn(needle, result.stderr)
        return result, check

    def test_pass_definitions_and_version(self) -> None:
        result, check = self.assert_outcome("pass")
        self.assertEqual(check["test_results"], {
            "selected": 2, "passed": 2, "failed": 0, "skipped": 0, "failures": [],
        })
        definitions = check["definitions"]
        functions = {item["symbol"]: item for item in definitions}
        used, unused = functions["sample-used"], functions["sample-unused"]
        self.assertGreater(used["stop_points"], 0)
        self.assertEqual(used["reached"], used["stop_points"])
        self.assertGreater(unused["stop_points"], 0)
        self.assertEqual(unused["reached"], 0)
        lambdas = [item for item in definitions if item["symbol"] not in {"sample-used", "sample-unused"}]
        self.assertEqual(len(lambdas), 1, definitions)
        self.assertGreater(lambdas[0]["position"], used["position"])
        self.assertLess(lambdas[0]["position"], unused["position"])
        self.assertTrue(all(item["file"] == "src/core.el" for item in definitions))
        version = subprocess.run(["emacs", "-Q", "--batch", "--eval", "(princ emacs-version)"],
                                 check=True, capture_output=True, text=True).stdout
        self.assertEqual(check["tool"], {"name": "Emacs", "version": version})
        self.assertNotIn("emacs_version", check)
        self.assertIn(f"Emacs {version}", result.stderr)

    def test_evidence_document_reaches_a_dependent_check(self) -> None:
        self.write_config(config() + '''
[checks.consumer]
adapter = "evidence_consumer"
tier = 1
enforcement = "enforced"
requires = "legacy-tests"
''')
        gate = self.fixture_gate()
        with (gate / "quality_gate/adapters.py").open("a", encoding="utf-8") as stream:
            stream.write('''
def _fixture_parse(raw, root, path, full_key):
    from types import SimpleNamespace
    return ParsedSpec(SimpleNamespace(requires=raw["requires"]), "fixture/1", (), requires=raw["requires"])

def _fixture_run(root, config, check, files, classes, *, prefix, prior):
    import json, time
    from .checks import _check_result
    evidence = prior[check.spec.requires].evidence_path
    document = json.loads(evidence.read_text(encoding="utf-8"))
    return _check_result(check, time.monotonic(), "pass", measurement={"evidence": document})

register_adapter(AdapterDescriptor("evidence_consumer", ("requires",), _fixture_parse, _fixture_run,
                                   requires_adapter="elisp_tests"))
''')
        self.fixture_runner = lambda: gate / "qg.py"
        result, document = self.run_json()
        self.assertEqual(result.returncode, 0, output(result))
        measured = self.check_by_id(document, "legacy-tests")
        evidence = self.check_by_id(document, "consumer")["measurement"]["evidence"]
        self.assertEqual(evidence["selected"], 2)
        self.assertTrue(evidence["definitions"])
        self.assertEqual(evidence["definitions"], measured["definitions"])
        self.assertEqual(evidence["emacs_version"], measured["tool"]["version"])

    def test_redefined_symbols_keep_each_definition_and_position(self) -> None:
        self.add_file("src/core.el", "(defun redefined () (+ 0 1))\n(defun redefined () (+ 1 1))\n")
        self.add_file("tests/suite.el", "(require 'ert)\n"
                      "(ert-deftest redefinition () (should (= (redefined) 2)))\n"
                      "(ert-run-tests-batch-and-exit t)\n")
        _result, check = self.assert_outcome("pass")
        definitions = sorted(check["definitions"], key=lambda item: item["position"])
        self.assertEqual([item["symbol"] for item in definitions], ["redefined", "redefined"])
        self.assertLess(definitions[0]["position"], definitions[1]["position"])
        self.assertEqual(definitions[0]["reached"], 0)
        self.assertGreater(definitions[1]["reached"], 0)

    def test_failure_names_test_and_ert_condition(self) -> None:
        self.add_file("tests/suite.el", "(require 'ert)\n(ert-deftest broken () (should (= 1 2)))\n"
                      "(ert-run-tests-batch-and-exit t)\n")
        _result, check = self.assert_outcome("fail", "broken", "ert-test-failed", "(= 1 2)")
        self.assertEqual(check["test_results"]["failed"], 1)
        failure = check["test_results"]["failures"][0]
        self.assertIn("broken", failure)
        self.assertIn(failure.removeprefix("broken: "), check["diagnostics"]["output_tail"])

    def test_no_tests_and_all_skipped_fail(self) -> None:
        suites = [
            ("(ert-run-tests-batch-and-exit \"no-such-test\")", "0 selected, 0 skipped"),
            ("(ert-deftest skip-one () (ert-skip \"fixture\"))\n"
             "(ert-run-tests-batch-and-exit t)", "1 selected, 1 skipped"),
        ]
        for suite, message in suites:
            with self.subTest(message=message):
                self.add_file("tests/suite.el", "(require 'ert)\n" + suite + "\n")
                self.assert_outcome("fail", "no test executed", message)

    def test_expected_failures_and_unexpected_passes_follow_ert(self) -> None:
        self.add_file("tests/suite.el", "(require 'ert)\n"
                      "(ert-deftest expected () :expected-result :failed (should nil))\n"
                      "(ert-deftest passing () (should t))\n"
                      "(ert-deftest skipped () (ert-skip \"fixture\"))\n"
                      "(ert-run-tests-batch-and-exit t)\n")
        _result, check = self.assert_outcome("pass")
        self.assertEqual(check["test_results"], {
            "selected": 3, "passed": 2, "failed": 0, "skipped": 1, "failures": [],
        })
        self.add_file("tests/suite.el", "(require 'ert)\n"
                      "(ert-deftest surprising () :expected-result :failed (should t))\n"
                      "(ert-run-tests-batch-and-exit t)\n")
        _result, check = self.assert_outcome("fail", "surprising", "passed")
        self.assertEqual(check["test_results"]["failed"], 1)

    def test_suite_contract_is_exactly_one_batch_call(self) -> None:
        for suite, message in (("(message \"no tests\")", "called 0 times"),
                               (SUITE + "(ert-run-tests-batch-and-exit t)", "more than once")):
            with self.subTest(message=message):
                self.add_file("tests/suite.el", suite)
                self.assert_outcome("fail", "suite", message)

    def test_module_and_suite_load_errors_name_the_file(self) -> None:
        self.add_file("src/core.el", '(error "bad module")\n')
        self.assert_outcome("fail", "src/core.el", "bad module")
        self.add_file("src/core.el", MODULE)
        self.add_file("tests/suite.el", '(error "bad suite")\n')
        self.assert_outcome("fail", "tests/suite.el", "bad suite")

    def test_missing_emacs_is_unsupported(self) -> None:
        self.write_config(config('emacs = "no-qg-such-emacs-command"'))
        self.assert_outcome("unsupported", "no-qg-such-emacs-command", "expected")

    def version_probe(self, version: str) -> tuple[Path, Path]:
        wrapper = self.base / "emacs"
        log = self.base / "emacs-calls"
        log.unlink(missing_ok=True)
        wrapper.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> ' + shlex.quote(str(log)) + '\n'
                           'case "$*" in\n'
                           '  "-Q --batch --eval (princ emacs-version)") printf "%s" '
                           + shlex.quote(version) + ';;\n'
                           '  *) echo "unexpected suite or measurement command" >&2; exit 99;;\n'
                           'esac\n', encoding="utf-8")
        wrapper.chmod(0o755)
        option = f'emacs = {json.dumps(str(wrapper))}'
        text = config(option).replace('checks = ["legacy-tests"]',
                                      'checks = ["legacy-tests", "crap", "compile", "checkdoc"]')
        text += '''
[checks.crap]
adapter = "elisp_crap"
tier = 1
enforcement = "enforced"
requires = "legacy-tests"
baseline = "crap.toml"
'''
        for name in ("compile", "checkdoc"):
            text += (f'\n[checks.{name}]\nadapter = "elisp_{name}"\ntier = 1\n'
                     f'enforcement = "enforced"\n{option}\n')
        self.write_config(text)
        self.add_file("crap.toml", baseline_text([], check="crap", metric_version="elisp-edebug/1"))
        return wrapper, log

    def test_old_emacs_is_unsupported_for_every_elisp_check_before_any_suite(self) -> None:
        _wrapper, log = self.version_probe("29.3")
        result, document = self.run_json()
        self.assertEqual(result.returncode, 1, output(result))
        for name in ("legacy-tests", "crap", "compile", "checkdoc"):
            with self.subTest(check=name):
                check = self.check_by_id(document, name)
                self.assertEqual(check["outcome"], "unsupported", output(result))
                self.assertEqual(check["reason"], "found Emacs 29.3; minimum required is Emacs 30.1")
                self.assertNotIn("test_results", check)
        self.assertEqual(log.read_text().splitlines(),
                         ["-Q --batch --eval (princ emacs-version)"] * 4)

    def test_oversized_emacs_versions_are_unsupported_for_every_elisp_check(self) -> None:
        # Exercise the integer limit, component bound, and total text bound separately.
        for version in ("999999999" * 5000 + ".1", "1234567890.1", "1." * 64 + "1", "garbage"):
            with self.subTest(version=version[:32]):
                wrapper, log = self.version_probe(version)
                result, document = self.run_json()
                self.assertEqual(result.returncode, 1, output(result))
                self.assertNotIn("Traceback", result.stderr)
                for name in ("legacy-tests", "crap", "compile", "checkdoc"):
                    with self.subTest(check=name):
                        check = self.check_by_id(document, name)
                        self.assertEqual(check["outcome"], "unsupported", output(result))
                        reason = check["reason"]
                        self.assertIn(str(wrapper), reason)
                        shown = version[:128] + ("..." if len(version) > 128 else "")
                        self.assertIn(repr(shown), reason)
                        self.assertLess(len(reason), len(str(wrapper)) + 256)
                        self.assertNotIn("test_results", check)
                self.assertEqual(log.read_text().splitlines(),
                                 ["-Q --batch --eval (princ emacs-version)"] * 4)

    def assert_probe_refused(self, wrapper: Path, log: Path, shown: str,
                            *, truncated: bool = False, exit_code: int = 0) -> None:
        result, document = self.run_json()
        self.assertEqual(log.read_text().splitlines(),
                         ["-Q --batch --eval (princ emacs-version)"] * 4)
        self.assertEqual(result.returncode, 1, output(result))
        for name in ("legacy-tests", "crap", "compile", "checkdoc"):
            check = self.check_by_id(document, name)
            reason = check["reason"]
            with self.subTest(check=name):
                self.assertIn(shown, reason)
                self.assertEqual(check["outcome"], "unsupported", output(result))
                self.assertIn(str(wrapper), reason)
                self.assertLess(len(reason), len(str(wrapper)) + 256)
                self.assertEqual(check["diagnostics"]["output_truncated"], truncated)
                self.assertEqual(check["diagnostics"]["exit_code"], exit_code)
                self.assertNotIn("test_results", check)

    def test_truncated_emacs_version_is_unsupported_before_any_measurement(self) -> None:
        version = "30.1" + " " * (1024 * 1024) + "suffix"
        # Also isolate the truncation flag when the captured prefix fits the version bound.
        for capture_limit in (None, 128):
            with self.subTest(capture_limit=capture_limit):
                wrapper, log = self.version_probe(version)
                if capture_limit is not None:
                    gate = self.fixture_gate()
                    runner = gate / "quality_gate/runner.py"
                    text = runner.read_text(encoding="utf-8")
                    runner.write_text(text.replace("capture_limit: int | None = CAPTURE_LIMIT",
                                                   f"capture_limit: int | None = {capture_limit}"),
                                      encoding="utf-8")
                    self.fixture_runner = lambda gate=gate: gate / "qg.py"
                shown = version[:128] + ("..." if capture_limit is None else "")
                self.assert_probe_refused(wrapper, log, repr(shown), truncated=True)

    def test_emacs_version_size_is_bounded_before_stripping_whitespace(self) -> None:
        for version in ("30.1" + " " * 125, " " * 125 + "30.1"):
            with self.subTest(version=version):
                wrapper, log = self.version_probe(version)
                self.assert_probe_refused(wrapper, log, repr(version[:128] + "..."))

    def test_failed_emacs_version_probe_has_a_bounded_reason_for_every_check(self) -> None:
        wrapper, log = self.version_probe("9" * 45000)
        text = wrapper.read_text(encoding="utf-8")
        wrapper.write_text(text.replace(";;", "; exit 7;;", 1), encoding="utf-8")
        self.assert_probe_refused(wrapper, log, "9" * 128 + "...", exit_code=7)

    def test_invalid_emacs_version_probe_is_unsupported(self) -> None:
        wrapper = self.base / "emacs"
        for command in ("printf garbage", "exit 7", "exit 0"):
            with self.subTest(command=command):
                wrapper.write_text(f"#!/bin/sh\n{command}\n", encoding="utf-8")
                wrapper.chmod(0o755)
                self.write_config(config(f'emacs = {json.dumps(str(wrapper))}'))
                self.assert_outcome("unsupported", "expected", "got", "version")

    def test_emacs_version_probe_has_the_check_budget(self) -> None:
        wrapper = self.base / "emacs"
        wrapper.write_text("#!/bin/sh\nexec sleep 20\n", encoding="utf-8")
        wrapper.chmod(0o755)
        self.write_config(config(f'emacs = {json.dumps(str(wrapper))}\nbudget_seconds = 1'))
        _result, check = self.assert_outcome("fail", "version", "budget")
        self.assertEqual(check["execution"], "budget")

    def test_emacs_minimum_compares_numeric_versions(self) -> None:
        wrapper = self.base / "emacs"
        for version, outcome in (("30.0", "unsupported"), ("30.1", "pass"),
                                 ("30.10", "pass"), ("31.0", "pass")):
            with self.subTest(version=version):
                wrapper.write_text('#!/bin/sh\nif [ "$4" = "(princ emacs-version)" ]; then\n'
                                   f'  printf "{version}"\nelse\n  exec emacs "$@"\nfi\n',
                                   encoding="utf-8")
                wrapper.chmod(0o755)
                self.write_config(config(f'emacs = {json.dumps(str(wrapper))}'))
                self.assert_outcome(outcome)

    def test_kill_emacs_and_malformed_result_are_unsupported(self) -> None:
        for suite in ("(require 'ert)\n(ert-deftest die () (kill-emacs 0))\n"
                      "(ert-run-tests-batch-and-exit t)\n",
                      SUITE + '(defun json-encode (_object) "broken json")\n'):
            with self.subTest(suite=suite):
                self.add_file("tests/suite.el", suite)
                self.assert_outcome("unsupported", "expected", "got")

    def test_invalid_json_measurements_are_unsupported(self) -> None:
        valid = {"emacs_version": "30.1", "selected": 1, "passed": 1, "failed": 0,
                 "skipped": 0, "failures": [], "definitions": []}
        documents = [
            [],
            {"missing": "keys"},
            {"error": ""},
            {"error": 1},
            {**valid, "emacs_version": ""},
            {**valid, "selected": True},
            {**valid, "passed": 0},
            {**valid, "failures": [{"name": "extra", "condition": "failure"}]},
            {**valid, "failures": "bad"},
            {**valid, "definitions": ["bad"]},
            {**valid, "definitions": [{"symbol": None, "file": "src/core.el", "position": 1,
                                        "stop_points": 1, "reached": 0}]},
            {**valid, "definitions": [{"symbol": "x", "file": "../outside.el", "position": 1,
                                        "stop_points": 1, "reached": 0}]},
            {**valid, "definitions": [{"symbol": "x", "file": "src/core.el", "position": 0,
                                        "stop_points": 1, "reached": 0}]},
            {**valid, "definitions": [{"symbol": "x", "file": "src/core.el", "position": 1,
                                        "stop_points": 1, "reached": 2}]},
            {**valid, "definitions": [{"symbol": "x", "file": "tests/suite.el", "position": 1,
                                        "stop_points": 1, "reached": 1}]},
        ]
        for document in documents:
            with self.subTest(document=document):
                encoded = json.dumps(json.dumps(document))
                self.add_file("tests/suite.el", SUITE + f"(defun json-encode (_object) {encoded})\n")
                self.assert_outcome("unsupported", "expected", "got")

    def test_budget_kills_emacs_and_its_process_group(self) -> None:
        marker = self.base / "emacs-pid"
        child_marker = self.base / "child-pid"
        self.add_file("tests/suite.el", "(require 'ert)\n"
                      f'(with-temp-file {json.dumps(str(marker))} (insert (number-to-string (emacs-pid))))\n'
                      f'(let ((p (start-process "qg-child" nil "sleep" "20"))) '
                      f'(with-temp-file {json.dumps(str(child_marker))} '
                      '(insert (number-to-string (process-id p)))))\n'
                      "(ert-deftest slow () (sleep-for 20))\n"
                      "(ert-run-tests-batch-and-exit t)\n")
        self.write_config(config("budget_seconds = 1"))
        _result, check = self.assert_outcome("fail", "budget")
        self.assertEqual(check["execution"], "budget")
        pid = int(marker.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        child_pid = int(child_marker.read_text(encoding="utf-8"))
        status = Path(f"/proc/{child_pid}/stat")
        if status.exists():
            self.assertEqual(status.read_text(encoding="utf-8").split()[2], "Z")

    def test_instrumented_suite_is_configuration_error(self) -> None:
        for hard_link in (False, True):
            with self.subTest(hard_link=hard_link):
                self.write_config(config(instrument_suite=not hard_link))
                if hard_link:
                    suite = self.repo / "tests/suite.el"
                    suite.unlink()
                    os.link(self.repo / "src/core.el", suite)
                result, document = self.run_json()
                self.assertEqual(result.returncode, 2, output(result))
                self.assertEqual(document["decision"], "error")
                self.assertIn("legacy-tests", result.stderr)
                self.assertIn("tests/suite.el", result.stderr)

    def test_empty_class_still_runs_the_suite(self) -> None:
        (self.repo / "src/core.el").unlink()
        text = config().replace('[[rule]]\npattern = "src/*.el"\nclass = "module"\n'
                                'reason = "measured modules"\n', "")
        self.write_config(text)
        self.add_file("tests/suite.el", "(require 'ert)\n(ert-deftest only () (should t))\n"
                      "(ert-run-tests-batch-and-exit t)\n")
        _result, check = self.assert_outcome("pass")
        self.assertEqual(check["test_results"]["selected"], 1)
        self.assertEqual(check["definitions"], [])

    def test_load_path_and_load_file_context(self) -> None:
        self.add_file("lib/dependency.el", "(defun dependency-function () t)\n(provide 'dependency)\n")
        self.add_file("src/core.el", '(require \'dependency)\n'
                      '(unless (equal (file-name-nondirectory load-file-name) "core.el") '
                      '(error "bad load context"))\n' + MODULE)
        rules = '[[rule]]\npattern = "lib/*.el"\nclass = "suite"\nreason = "dependency"\n'
        self.write_config(config(extra_rules=rules))
        self.assert_outcome("fail", "src/core.el", "dependency")
        self.write_config(config('load_path = ["lib"]', extra_rules=rules))
        _result, check = self.assert_outcome("pass")
        self.assertNotIn("dependency-function", [item["symbol"] for item in check["definitions"]])

    def test_load_path_order_and_quoted_file_names(self) -> None:
        (self.repo / "src/core.el").unlink()
        self.add_file('src/module "one".el', "(require 'choice)\n(defun chosen () (choice))\n")
        self.add_file("lib first/choice.el", "(defun choice () 'first)\n(provide 'choice)\n")
        self.add_file("lib second/choice.el", "(defun choice () 'second)\n(provide 'choice)\n")
        self.add_file('tests/suite "one".el', "(require 'ert)\n"
                      "(ert-deftest choice-test () (should (eq (chosen) 'first)))\n"
                      "(ert-run-tests-batch-and-exit t)\n")
        rules = '[[rule]]\npattern = "lib*/*.el"\nclass = "suite"\nreason = "libraries"\n'
        text = config('load_path = ["lib first", "lib second"]', extra_rules=rules)
        text = text.replace('suite = "tests/suite.el"', 'suite = ' + json.dumps('tests/suite "one".el'))
        self.write_config(text)
        _result, check = self.assert_outcome("pass")
        self.assertEqual(check["definitions"][0]["file"], 'src/module "one".el')

    def verify_ert(self, entries: list[dict[str, object]]):
        text = config().replace(
            'checks = ["legacy-tests"]',
            'checks = ["legacy-tests", "verification"]',
        ) + ('\n[checks.verification]\nadapter = "verification"\ntier = 1\n'
             'enforcement = "enforced"\nrequires = "legacy-tests"\nbaseline = "verification.toml"\n')
        self.write_config(text)
        self.add_file("verification.toml", baseline_text(
            entries, check="verification", metric_version="verification/1",
        ))
        result, document = self.run_json()
        return result, self.check_by_id(document, "verification")

    def finding(self, check: dict[str, object], subject: str) -> dict[str, object]:
        return next(item for item in check["findings"] if item["subject"] == subject)

    def test_verification_consumes_ert_counts(self) -> None:
        result, check = self.verify_ert([executed_entry(2)])
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(self.finding(check, "tests:legacy-tests:executed")["value"], 2)
        self.assertEqual(
            sorted(item["subject"] for item in check["findings"]),
            ["tests:legacy-tests:executed", "tests:legacy-tests:skipped"],
        )

    def test_verification_floor_fails_with_a_reduced_ert_count(self) -> None:
        self.add_file("tests/suite.el", "(require 'ert)\n"
                      "(ert-deftest only () (should t))\n"
                      "(ert-run-tests-batch-and-exit t)\n")
        result, check = self.verify_ert([executed_entry(2)])
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(self.finding(check, "tests:legacy-tests:executed")["value"], 1)
        self.assertIn("falls below baseline bound 2", result.stderr)

    def test_verification_counts_skipped_ert_tests(self) -> None:
        self.add_file("tests/suite.el", "(require 'ert)\n"
                      "(ert-deftest passing () (should t))\n"
                      "(ert-deftest skipped () (ert-skip \"fixture\"))\n"
                      "(ert-run-tests-batch-and-exit t)\n")
        result, check = self.verify_ert([executed_entry(1)])
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(self.finding(check, "tests:legacy-tests:executed")["value"], 1)
        self.assertEqual(self.finding(check, "tests:legacy-tests:skipped")["value"], 1)
        self.assertIn("tests:legacy-tests:skipped", result.stderr)
        self.assertIn("exceeds threshold 0", result.stderr)

    def test_invalid_suite_files_are_configuration_errors(self) -> None:
        os.mkfifo(self.repo / "tests/fifo.el")
        (self.repo / "outside.el").symlink_to(self.base / "outside-target.el")
        (self.base / "outside-target.el").write_text(SUITE, encoding="utf-8")
        (self.repo / "loop").symlink_to("loop")
        for path in ("tests/fifo.el", "outside.el", "loop"):
            with self.subTest(path=path):
                self.write_config(config().replace('suite = "tests/suite.el"', f'suite = "{path}"'))
                result, document = self.run_json()
                self.assertEqual(result.returncode, 2, output(result))
                self.assertEqual(document["decision"], "error")
                self.assertIn("checks.legacy-tests.suite", result.stderr)
                self.assertIn("expected", result.stderr)
                self.assertIn("got", result.stderr)

    def test_measuring_an_identical_helper_keeps_the_stage_separate(self) -> None:
        helper = (GATE / "quality_gate/elisp/qg-elisp-child.el").read_text(encoding="utf-8")
        self.add_file("src/core.el", helper)
        # The before hook needs the same dynamically bound vector as an Edebug entry.
        self.add_file("tests/suite.el", "(require 'ert)\n"
                      "(ert-deftest helper-test () (let ((qg-elisp-child--counts [0])) "
                      "(should (= (qg-elisp-child--before 0) 0))))\n"
                      "(ert-run-tests-batch-and-exit t)\n")
        _result, check = self.assert_outcome("pass")
        definitions = {item["symbol"]: item for item in check["definitions"]}
        self.assertIn("qg-elisp-child--before", definitions)
        self.assertGreater(definitions["qg-elisp-child--before"]["reached"], 0)

    def test_bad_configuration_names_check_key_and_expected_actual(self) -> None:
        cases = [
            (config("bogus = 1"), "bogus"),
            (config().replace('suite = "tests/suite.el"', ''), "suite"),
            (config().replace('suite = "tests/suite.el"', 'suite = 42'), "suite"),
            (config().replace('suite = "tests/suite.el"', 'suite = "missing.el"'), "suite"),
            (config().replace('suite = "tests/suite.el"', 'suite = "src"'), "suite"),
            (config().replace('suite = "tests/suite.el"', 'suite = "../outside.el"'), "suite"),
            (config('load_path = "lib"'), "load_path"),
            (config('load_path = [42]'), "load_path[0]"),
            (config('load_path = ["missing"]'), "load_path[0]"),
            (config('load_path = ["src/core.el"]'), "load_path[0]"),
            (config('load_path = ["../outside"]'), "load_path[0]"),
            (config('emacs = 1'), "emacs"),
            (config('emacs = ""'), "emacs"),
            (config('budget_seconds = "1"'), "budget_seconds"),
            (config('budget_seconds = 0'), "budget_seconds"),
        ]
        for text, key in cases:
            with self.subTest(key=key, text=text):
                self.write_config(text)
                result, document = self.run_json()
                self.assertEqual(result.returncode, 2, output(result))
                self.assertEqual(document["decision"], "error")
                self.assertIn("checks.legacy-tests", result.stderr)
                self.assertIn(key, result.stderr)
                self.assertIn("expected", result.stderr)
                self.assertIn("got", result.stderr)
