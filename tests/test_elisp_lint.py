"""Exercise compile and checkdoc through the real gate and a real Emacs."""
from __future__ import annotations

import json
import shlex
import shutil
import subprocess

import test_command_checks
from support import GATE, FixtureCase, output
from test_elisp_tests import REPORT_VERSION_MISMATCHES, assert_report_version_mismatch


MODULE = """\
;;; core.el --- Example module -*- lexical-binding: t -*-

;;; Commentary:
;; A documented fixture module.

;;; Code:

(defun core-value ()
  "Return a value."
  42)

(provide 'core)
;;; core.el ends here
"""


def config(adapters=("elisp_compile", "elisp_checkdoc"), options=None, extra_rules=""):
    options = options or {}
    checks = ", ".join(json.dumps(name) for name in ("smoke", *adapters))
    blocks = "\n".join(
        f'[checks.{name}]\nadapter = "{name}"\ntier = 1\nenforcement = "enforced"\n'
        f'{options.get(name, "")}\n'
        for name in adapters
    )
    return f'''\
schema = 2
[code]
patterns = ["*.el"]
shebangs = []
[classes.module]
code = true
description = "Modules"
checks = [{checks}]
[classes.support]
code = true
description = "Support"
checks = ["smoke"]
[classes.config]
code = false
description = "Configuration"
[classes.doc]
code = false
description = "Documentation"
[checks.smoke]
adapter = "command"
tier = 1
enforcement = "enforced"
run = ["python3", "-c", "print(1)"]
tests_pattern = '(\\d+)'
{blocks}
[[rule]]
pattern = "src/*.el"
class = "module"
reason = "modules"
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


class ElispLintTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.emacs = shutil.which("emacs")
        self.assertIsNotNone(self.emacs, "these tests require a real Emacs")
        (self.repo / "a.py").unlink()
        self.add_file("src/core.el", MODULE)
        self.write_config(config())

    def run_checks(self, expected=0):
        result, document = self.run_json()
        self.assertEqual(result.returncode, expected, output(result))
        return result, document

    def assert_check(self, document, name, outcome):
        check = self.check_by_id(document, name)
        self.assertEqual(check["outcome"], outcome, check)
        return check

    def test_clean_module_and_reported_version(self) -> None:
        result, document = self.run_checks()
        version = subprocess.run([self.emacs, "-Q", "--batch", "--eval", "(princ emacs-version)"],
                                 check=True, capture_output=True, text=True).stdout
        for adapter in ("elisp_compile", "elisp_checkdoc"):
            with self.subTest(adapter=adapter):
                check = self.assert_check(document, adapter, "pass")
                self.assertEqual(check["tool"], {"name": "Emacs", "version": version})
                self.assertNotIn("emacs_version", check)
                self.assertIn(f"{adapter}: passed (Emacs {version}", result.stderr)

    def test_free_variable_fails_compilation_but_not_checkdoc(self) -> None:
        self.add_file("src/core.el", MODULE.replace("  42)", "  core-missing-variable)"))
        result, document = self.run_checks(1)
        compile_check = self.assert_check(document, "elisp_compile", "fail")
        self.assert_check(document, "elisp_checkdoc", "pass")
        self.assertIn("src/core.el", result.stderr)
        self.assertIn("free variable", result.stderr)
        self.assertIn("core-missing-variable", compile_check["reason"])
        doc_check = self.check_by_id(document, "elisp_checkdoc")
        self.assertEqual(compile_check["tool"], doc_check["tool"])

    def test_each_file_compiles_in_its_own_emacs(self) -> None:
        self.add_file("src/core.el", ";;; core.el -*- lexical-binding: t -*-\n"
                      "(eval-and-compile (defmacro qg-test-macro (value) value))\n")
        self.add_file("src/second.el", ";;; second.el -*- lexical-binding: t -*-\n"
                      "(defun qg-test-use () (qg-test-macro 42))\n")
        self.write_config(config(("elisp_compile",)))
        result, document = self.run_checks(1)
        self.assert_check(document, "elisp_compile", "fail")
        self.assertIn("src/second.el", result.stderr)
        self.assertIn("qg-test-macro", result.stderr)
        report = self.base / "same-process.json"
        helper = GATE / "quality_gate/elisp/qg-elisp-lint.el"
        form = (f"(qg-elisp-lint-compile '(\"src/core.el\" \"src/second.el\") "
                f"{json.dumps(str(self.base))} {json.dumps(str(report))})")
        run = subprocess.run([self.emacs, "-Q", "--batch", "-l", str(helper), "--eval", form],
                             cwd=self.repo, capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 0, output(run))
        self.assertEqual(json.loads(report.read_text())["failed"], [], output(run))

    def test_compilation_leaves_no_elc_or_git_changes(self) -> None:
        self.write_config(config(("elisp_compile",)))
        self.commit_all()
        self.run_checks()
        self.assertEqual(list(self.repo.rglob("*.elc")), [])
        self.assertEqual(self.git("status", "--short").stdout, "")
        self.add_file("src/core.el", MODULE.replace("  42)", "  core-missing-variable)"))
        self.commit_all("warning fixture")
        self.run_checks(1)
        self.assertEqual(list(self.repo.rglob("*.elc")), [])
        self.assertEqual(self.git("status", "--short").stdout, "")

    def test_checkdoc_reports_each_file_line_and_message(self) -> None:
        self.write_config(config(("elisp_checkdoc",)))
        examples = [
            (MODULE.replace('  "Return a value."\n', ''), 9, "documentation string"),
            (MODULE.replace('"Return a value."', '"Return a value"'), 9, "sentence"),
        ]
        for text, line, message in examples:
            with self.subTest(message=message):
                self.add_file("src/core.el", text)
                result, document = self.run_checks(1)
                check = self.assert_check(document, "elisp_checkdoc", "fail")
                self.assertIn(f"src/core.el:{line}:", result.stderr)
                self.assertIn(message, result.stderr.lower())
                self.assertIn(f"src/core.el:{line}:", check["reason"])

    def test_checkdoc_reports_all_selected_files(self) -> None:
        self.write_config(config(("elisp_checkdoc",)))
        self.add_file("src/core.el", MODULE.replace('"Return a value."', '"Return a value"'))
        self.add_file("src/second.el", MODULE.replace("core.el", "second.el")
                      .replace('  "Return a value."\n', ""))
        result, document = self.run_checks(1)
        check = self.assert_check(document, "elisp_checkdoc", "fail")
        for name in ("src/core.el:9:", "src/second.el:9:"):
            self.assertIn(name, check["reason"])
            self.assertIn(name, result.stderr)

    def test_configured_wrapper_is_used_for_both_checks(self) -> None:
        log = self.base / "arguments"
        wrapper = self.base / "emacs-wrapper"
        wrapper.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> {shlex.quote(str(log))}\n'
                           f'exec {shlex.quote(self.emacs)} "$@"\n')
        wrapper.chmod(0o755)
        option = f"emacs = {json.dumps(str(wrapper))}"
        self.write_config(config(options={name: option for name in ("elisp_compile", "elisp_checkdoc")}))
        _result, document = self.run_checks()
        for adapter in ("elisp_compile", "elisp_checkdoc"):
            self.assertEqual(self.check_by_id(document, adapter)["diagnostics"]["argv"][0], str(wrapper))
        lines = log.read_text().splitlines()
        self.assertEqual(lines.count("-Q"), 4)
        self.assertEqual(lines.count("--batch"), 4)
        self.assertEqual(lines.count(str(GATE / "quality_gate/elisp/qg-elisp-lint.el")), 2)
        self.assertTrue(any("qg-elisp-lint-compile" in line for line in lines))
        self.assertTrue(any("qg-elisp-lint-checkdoc" in line for line in lines))

    def test_missing_binary_and_missing_report_are_unsupported(self) -> None:
        wrapper = self.base / "no-report"
        wrapper.write_text(f'#!/bin/sh\nif [ "$4" = "(princ emacs-version)" ]; then\n'
                           f'  exec {shlex.quote(self.emacs)} "$@"\nfi\n'
                           f'exec {shlex.quote(self.emacs)} -Q --batch '
                           "--eval '(kill-emacs 0)'\n")
        wrapper.chmod(0o755)
        for adapter in ("elisp_compile", "elisp_checkdoc"):
            for binary in ("no-such-qg-emacs-command", str(wrapper)):
                with self.subTest(adapter=adapter, binary=binary):
                    self.write_config(config((adapter,), {adapter: f'emacs = {json.dumps(binary)}'}))
                    result, document = self.run_checks(1)
                    check = self.assert_check(document, adapter, "unsupported")
                    self.assertIn("expected", check["reason"])
                    self.assertIn("got", check["reason"])
                    self.assertIn(binary if binary.startswith("no-") else "JSON lint report", result.stderr)

    def test_invalid_reports_and_nonzero_exit_are_unsupported(self) -> None:
        valid = {"emacs_version": "30.1", "files": ["src/core.el"], "failed": [], "issues": []}
        cases = [None, {}, {**valid, "emacs_version": ""}, {**valid, "files": ["other.el"]},
                 {**valid, "failed": "src/core.el"}, {**valid, "issues": "not a list"},
                 {**valid, "failed": ["other.el"]},
                 {**valid, "issues": [{"file": "src/core.el", "line": 0, "message": "bad"}]},
                 {**valid, "issues": [{"file": "other.el", "line": 1, "message": "bad"}]},
                 {**valid, "issues": [{"file": "src/core.el", "line": True, "message": "bad"}]},
                 {**valid, "issues": [{"file": "src/core.el", "line": 1, "message": ""}]},
                 {**valid, "issues": [{"file": "src/core.el"}]}]
        wrapper = self.base / "malformed-report"
        for adapter in ("elisp_compile", "elisp_checkdoc"):
            for document in cases:
                with self.subTest(adapter=adapter, document=document):
                    encoded = json.dumps(json.dumps(document))
                    form = f"(progn (require 'json) (defun json-encode (_value) {encoded}))"
                    wrapper.write_text(f'#!/bin/sh\nexec {shlex.quote(self.emacs)} -Q --batch '
                                       f'--eval {shlex.quote(form)} "$@"\n')
                    wrapper.chmod(0o755)
                    self.write_config(config((adapter,), {adapter: f'emacs = {json.dumps(str(wrapper))}'}))
                    result, returned = self.run_checks(1)
                    check = self.assert_check(returned, adapter, "unsupported")
                    self.assertIn("expected", check["reason"])
                    self.assertIn("got", check["reason"])
                    self.assertIn("src/core.el", result.stderr)
            wrapper.write_text('#!/bin/sh\nif [ "$4" = "(princ emacs-version)" ]; then\n'
                               f'  exec {shlex.quote(self.emacs)} "$@"\nfi\n'
                               f'{shlex.quote(self.emacs)} "$@"\nexit 7\n')
            wrapper.chmod(0o755)
            result, returned = self.run_checks(1)
            self.assert_check(returned, adapter, "unsupported")
            self.assertIn("expected child exit 0", result.stderr)
            self.assertIn("got exit 7", result.stderr)

    def test_compile_refuses_changing_emacs_versions(self) -> None:
        self.add_file("src/second.el", MODULE.replace("core.el", "second.el"))
        marker = self.base / "seen"
        wrapper = self.base / "changing-emacs"
        wrapper.write_text('#!/bin/sh\nif [ "$4" = "(princ emacs-version)" ]; then\n'
                           '  printf "31.1"\n  exit 0\nfi\n'
                           f'if [ -f {shlex.quote(str(marker))} ]; then\n'
                           '  version=31.2\nelse\n'
                           f'  touch {shlex.quote(str(marker))}\n  version=31.1\nfi\n'
                           f'exec {shlex.quote(self.emacs)} -Q --batch '
                           '--eval "(setq emacs-version \\\"$version\\\")" "$@"\n')
        wrapper.chmod(0o755)
        option = f'emacs = {json.dumps(str(wrapper))}'
        self.write_config(config(("elisp_compile",), {"elisp_compile": option}))
        result, document = self.run_checks(1)
        check = self.assert_check(document, "elisp_compile", "unsupported")
        self.assertIn("expected Emacs version 31.1 from preflight, got '31.2'", result.stderr)
        self.assertEqual(check["tool"], {"name": "Emacs", "version": "31.1"})

    def lint_report_version(self, version: object, *, exit_code: int = 0) -> None:
        document = {"emacs_version": version, "files": ["src/core.el"], "failed": [], "issues": []}
        self.lint_report(json.dumps(document), exit_code=exit_code)

    def lint_report(self, report: str, *, exit_code: int = 0) -> None:
        encoded = json.dumps(report)
        form = f"(progn (require 'json) (defun json-encode (_value) {encoded}))"
        wrapper = self.base / "report-emacs"
        wrapper.write_text('#!/bin/sh\nif [ "$4" = "(princ emacs-version)" ]; then\n'
                           '  printf "30.1"\n  exit 0\nfi\n'
                           f'{shlex.quote(self.emacs)} -Q --batch --eval {shlex.quote(form)} "$@"\n'
                           f'exit {exit_code}\n', encoding="utf-8")
        wrapper.chmod(0o755)
        option = f'emacs = {json.dumps(str(wrapper))}'
        self.write_config(config(options={name: option for name in ("elisp_compile", "elisp_checkdoc")}))

    def test_duplicate_failed_is_unsupported(self) -> None:
        self.lint_report('{"emacs_version":"30.1","files":["src/core.el"],'
                         '"failed":["src/core.el"],"failed":[],"issues":[]}')
        _result, document = self.run_checks(1)
        for adapter in ("elisp_compile", "elisp_checkdoc"):
            check = self.assert_check(document, adapter, "unsupported")
            self.assertIn("JSON lint report", check["reason"])
            self.assertIn("duplicate name 'failed'", check["reason"])

    def test_report_version_must_equal_preflight_before_use(self) -> None:
        for version in REPORT_VERSION_MISMATCHES:
            for exit_code in (0, 7):
                with self.subTest(version=str(version)[:32], exit_code=exit_code):
                    self.lint_report_version(version, exit_code=exit_code)
                    result, document = self.run_checks(1)
                    for adapter in ("elisp_compile", "elisp_checkdoc"):
                        check = self.assert_check(document, adapter, "unsupported")
                        assert_report_version_mismatch(self, check, version, limit=300)
                        self.assertEqual(check["tool"], {"name": "Emacs", "version": "30.1"})
                    self.assertLess(len(result.stderr), 4096)

    def test_report_matching_preflight_is_accepted(self) -> None:
        self.lint_report_version("30.1")
        _result, document = self.run_checks()
        for adapter in ("elisp_compile", "elisp_checkdoc"):
            check = self.assert_check(document, adapter, "pass")
            self.assertEqual(check["tool"], {"name": "Emacs", "version": "30.1"})

    def test_no_selected_files_fails(self) -> None:
        text = config(("elisp_compile",)).replace('checks = ["smoke", "elisp_compile"]', 'checks = ["smoke"]')
        self.write_config(text)
        result, document = self.run_checks(1)
        self.assert_check(document, "elisp_compile", "fail")
        self.assertIn("no files selected", result.stderr)

    def test_load_path_is_used_in_order_for_both_checks(self) -> None:
        self.add_file("lib/dependency.el", "(defun dependency-value () 42)\n(provide 'dependency)\n")
        module = MODULE.replace("(defun core-value", "(require 'dependency)\n\n(defun core-value")
        self.add_file("src/core.el", module.replace("  42)", "  (dependency-value))"))
        extra_rules = '''\
[[rule]]
pattern = "lib/*.el"
class = "support"
reason = "dependency"
'''
        option = 'load_path = ["lib", "src"]'
        self.write_config(config(options={name: option for name in ("elisp_compile", "elisp_checkdoc")},
                                 extra_rules=extra_rules))
        _result, document = self.run_checks()
        for adapter in ("elisp_compile", "elisp_checkdoc"):
            argv = self.check_by_id(document, adapter)["diagnostics"]["argv"]
            self.assertEqual(argv[3:7], ["-L", "lib", "-L", "src"])
        self.write_config(config(("elisp_compile",), extra_rules=extra_rules))
        result, document = self.run_checks(1)
        self.assert_check(document, "elisp_compile", "fail")
        self.assertIn("dependency", result.stderr)
        self.assertIn("src/core.el", result.stderr)

    def test_budget_terminates_emacs_and_its_children(self) -> None:
        for adapter in ("elisp_compile", "elisp_checkdoc"):
            with self.subTest(adapter=adapter):
                pidfile = self.base / f"{adapter}-pid"
                childfile = self.base / f"{adapter}-child"
                form = (f'(progn (with-temp-file {json.dumps(str(pidfile))} '
                        f'(insert (number-to-string (emacs-pid)))) '
                        f'(let ((p (start-process "sleeper" nil "sleep" "20"))) '
                        f'(with-temp-file {json.dumps(str(childfile))} '
                        '(insert (number-to-string (process-id p))))) (sleep-for 20))')
                wrapper = self.base / f"{adapter}-slow"
                wrapper.write_text('#!/bin/sh\nif [ "$4" = "(princ emacs-version)" ]; then\n'
                                   f'  exec {shlex.quote(self.emacs)} "$@"\nfi\n'
                                   f'exec {shlex.quote(self.emacs)} -Q --batch '
                                   f'--eval {shlex.quote(form)} "$@"\n')
                wrapper.chmod(0o755)
                option = f'emacs = {json.dumps(str(wrapper))}\nbudget_seconds = 1'
                self.write_config(config((adapter,), {adapter: option}))
                result, document = self.run_checks(1)
                check = self.assert_check(document, adapter, "fail")
                self.assertEqual(check["execution"], "budget")
                self.assertIn("budget", result.stderr)
                test_command_checks.CommandCheckTests.wait_for_process_death(self, int(pidfile.read_text()))
                test_command_checks.CommandCheckTests.wait_for_process_death(self, int(childfile.read_text()))

    def test_invalid_configuration_names_check_key_and_expected_actual(self) -> None:
        (self.repo / "escape").symlink_to(self.base, target_is_directory=True)
        cases = [("bogus = 1", "bogus"),
                 ('load_path = "src"', "load_path"),
                 ("load_path = [42]", "load_path[0]"),
                 ('load_path = ["missing"]', "load_path[0]"),
                 ('load_path = ["src/core.el"]', "load_path[0]"),
                 ('load_path = ["../outside"]', "load_path[0]"),
                 ('load_path = ["/tmp"]', "load_path[0]"),
                 ('load_path = ["escape"]', "load_path[0]"),
                 ('load_path = [""]', "load_path[0]"),
                 ("emacs = 1", "emacs"), ('emacs = ""', "emacs"),
                 ('emacs = "bad\\u0000name"', "emacs"),
                 ('budget_seconds = "1"', "budget_seconds"),
                 ("budget_seconds = true", "budget_seconds"), ("budget_seconds = 0", "budget_seconds")]
        for adapter in ("elisp_compile", "elisp_checkdoc"):
            for option, key in cases:
                with self.subTest(adapter=adapter, option=option):
                    self.write_config(config((adapter,), {adapter: option}))
                    result, document = self.run_json()
                    self.assertEqual(result.returncode, 2, output(result))
                    self.assertEqual(document["decision"], "error")
                    for expected in (f"checks.{adapter}", key, "expected", "got"):
                        self.assertIn(expected, result.stderr)
