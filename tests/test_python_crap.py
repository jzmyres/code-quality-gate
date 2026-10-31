"""Tests for the python_crap adapter, its CC table and its ratchet."""
from __future__ import annotations

import configparser
import json
import os
import shutil
import subprocess
import sys
import time
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from support import (
    PYTHON_COMMON_RULE_LINES,
    PYTHON_TEST_HEADER,
    FixtureCase,
    baseline_text,
    output,
)


def crap_config(
    *,
    baseline: str = "quality-gate-crap.toml",
    threshold: int | float | None = None,
    tests_pattern: str = r"^Ran (\d+) tests? in",
) -> str:
    lines = [
        "schema = 2",
        "",
        "[code]",
        'patterns = ["*.py"]',
        'shebangs = ["python*"]',
        "",
        "[levels]",
        "required_tiers = [1]",
        "",
        "[classes.python]",
        "code = true",
        'description = "Python source"',
        'checks = ["tests", "crap"]',
        "",
        "[classes.test]",
        "code = true",
        'description = "Python tests"',
        'checks = ["tests"]',
        "",
        "[classes.config]",
        "code = false",
        'description = "Configuration"',
        "",
        "[classes.doc]",
        "code = false",
        'description = "Documentation"',
        "",
        "[checks.tests]",
        'adapter = "python_tests"',
        "tier = 1",
        'enforcement = "enforced"',
        'run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]',
        f"tests_pattern = {json.dumps(tests_pattern)}",
        "",
        "[checks.crap]",
        'adapter = "python_crap"',
        "tier = 1",
        'enforcement = "enforced"',
        'requires = "tests"',
        f'baseline = "{baseline}"',
    ]
    if threshold is not None:
        lines.append(f"threshold = {threshold}")
    lines.extend(
        [
            "",
            "[[rule]]",
            'pattern = "tests/*.py"',
            'class = "test"',
            'reason = "tests"',
            "",
            "[[rule]]",
            'pattern = "pkg/*.py"',
            'class = "python"',
            'reason = "source"',
        ]
    )
    lines.extend(PYTHON_COMMON_RULE_LINES)
    return "\n".join(lines)


class PythonCrapTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.add_file("pkg/__init__.py", "")
        self.write_config(crap_config())

    def add_tests(self, body: str, name: str = "test_sample") -> None:
        self.add_file(
            f"tests/{name}.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n" + body,
        )

    def add_default_test(self) -> None:
        self.add_tests(
            "    def test_ok(self):\n        self.assertTrue(True)\n"
        )

    def run_crap(
        self, *, env: dict[str, str] | None = None
    ) -> tuple[object, dict[str, object], dict[str, object]]:
        result, document = self.run_json(
            env=env or self.default_tool_env()
        )
        return result, document, self.check_by_id(document, "crap")

    def findings(self, check: dict[str, object]) -> dict[str, dict[str, object]]:
        return {
            finding["subject"]: finding
            for finding in check["findings"]
        }

    def test_untested_cc3_fails(self) -> None:
        self.add_default_test()
        self.add_file(
            "pkg/new.py",
            "def three(value):\n"
            "    if value:\n"
            "        if value > 1:\n"
            "            return 1\n"
            "    return 2\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertIsNotNone(check["reason"])
        finding = self.findings(check)["pkg/new.py:three"]
        self.assertEqual(finding["value"], 12.0)
        self.assertEqual(finding["measurement"]["cc"], 3)
        self.assertEqual(finding["measurement"]["executed"], 0)
        self.assertIn("value 12.0 exceeds threshold 6.0", result.stderr)

    def test_imported_but_uncalled_function_scores_zero_coverage(self) -> None:
        # Importing runs the decorator and def lines; they must not count as exercising the body.
        self.add_tests(
            "    def test_import_only(self):\n"
            "        import pkg.new\n"
            "        self.assertTrue(pkg.new)\n"
        )
        self.add_file(
            "pkg/new.py",
            "import functools\n\n\n"
            "@functools.cache\n"
            "def three(value):\n"
            "    if value:\n"
            "        if value > 1:\n"
            "            return 1\n"
            "    return 2\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        finding = self.findings(check)["pkg/new.py:three"]
        self.assertEqual(finding["measurement"]["executed"], 0)
        self.assertEqual(finding["measurement"]["statements"], 4)
        self.assertEqual(finding["value"], 12.0)

    def test_fully_covered_cc6_passes(self) -> None:
        self.add_file(
            "pkg/six.py",
            "def six(value):\n"
            "    if value:\n        pass\n"
            "    if value:\n        pass\n"
            "    if value:\n        pass\n"
            "    if value:\n        pass\n"
            "    if value:\n        pass\n"
            "    return value\n",
        )
        self.add_tests(
            "    def test_six(self):\n"
            "        import pkg.six\n"
            "        self.assertEqual(pkg.six.six(True), True)\n"
        )
        result, document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        finding = self.findings(check)["pkg/six.py:six"]
        self.assertEqual(finding["value"], 6.0)
        self.assertEqual(finding["measurement"]["cc"], 6)
        self.assertEqual(
            finding["measurement"]["executed"],
            finding["measurement"]["statements"],
        )
        self.assertEqual(document["decision"], "accepted")

    def test_baseline_exactly_at_its_mark_passes(self) -> None:
        self.add_default_test()
        self.add_file(
            "pkg/untested.py",
            "def five(value):\n"
            "    if value:\n        pass\n"
            "    if value:\n        pass\n"
            "    if value:\n        pass\n"
            "    if value:\n        pass\n"
            "    return value\n",
        )
        self.add_file(
            "quality-gate-crap.toml",
            baseline_text(
                [
                    {
                        "subject": "pkg/untested.py:five",
                        "bound": 30,
                        "reason": "worklist",
                    }
                ],
                check="crap",
                metric_version="python-lines/1",
            ),
        )
        result, document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertTrue(check["satisfied"])
        finding = self.findings(check)["pkg/untested.py:five"]
        self.assertEqual(finding["value"], 30.0)
        self.assertEqual(finding["bound"], 30)
        self.assertEqual(finding["baseline_reason"], "worklist")
        self.assertTrue(finding["covered_by_baseline"])
        self.assertEqual(document["decision"], "accepted_with_exceptions")

    def test_baseline_one_tenth_above_fails(self) -> None:
        self.add_default_test()
        self.add_file(
            "pkg/untested.py",
            "def five(value):\n"
            "    if value:\n        pass\n"
            "    if value:\n        pass\n"
            "    if value:\n        pass\n"
            "    if value:\n        pass\n"
            "    return value\n",
        )
        self.add_file(
            "quality-gate-crap.toml",
            baseline_text(
                [
                    {
                        "subject": "pkg/untested.py:five",
                        "bound": 29.9,
                        "reason": "worklist",
                    }
                ],
                check="crap",
                metric_version="python-lines/1",
            ),
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertIn("value 30.0 exceeds threshold 6.0", result.stderr)
        self.assertIn("baseline bound 29.9", result.stderr)
        finding = self.findings(check)["pkg/untested.py:five"]
        self.assertEqual(finding["value"], 30.0)
        self.assertEqual(finding["bound"], 29.9)
        self.assertTrue(finding["blocking"])

    def test_never_imported_file_scores_at_zero_coverage(self) -> None:
        self.add_default_test()
        self.add_file(
            "pkg/untested.py",
            "def only():\n    return 1\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        finding = self.findings(check)["pkg/untested.py:only"]
        self.assertEqual(finding["value"], 2.0)
        self.assertEqual(finding["measurement"]["executed"], 0)
        self.assertGreater(finding["measurement"]["statements"], 0)

    def test_repository_coverage_configuration_is_ignored(self) -> None:
        self.write_config(
            crap_config()
            + '\n[[rule]]\npattern = ".coveragerc"\n'
            'class = "config"\nreason = "repository coverage configuration"\n'
        )
        self.add_file(
            ".coveragerc",
            "[run]\n"
            "branch = True\n"
            "source = nowhere\n"
            "omit = pkg/*\n"
            "[report]\n"
            "exclude_lines =\n"
            "    .*\n",
        )
        self.add_file(
            "pkg/covered.py",
            "def covered():\n    return 1\n",
        )
        self.add_tests(
            "    def test_covered(self):\n"
            "        import pkg.covered\n"
            "        self.assertEqual(pkg.covered.covered(), 1)\n"
        )
        result, _document, check = self.run_crap(
            env={
                **self.default_tool_env(),
                "COVERAGE_OMIT": "pkg/*",
                "COVERAGE_BRANCH": "1",
            }
        )
        self.assertEqual(result.returncode, 0, output(result))
        finding = self.findings(check)["pkg/covered.py:covered"]
        self.assertEqual(finding["value"], 1.0)
        self.assertEqual(
            finding["measurement"]["executed"],
            finding["measurement"]["statements"],
        )

    def test_pragma_line_appears_in_excluded_lines(self) -> None:
        self.add_file(
            "pkg/pragma.py",
            "def with_pragma():\n"
            "    value = 1\n"
            "    return value  # pragma: no cover\n",
        )
        self.add_tests(
            "    def test_pragma(self):\n"
            "        import pkg.pragma\n"
            "        self.assertEqual(pkg.pragma.with_pragma(), 1)\n"
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        finding = self.findings(check)["pkg/pragma.py:with_pragma"]
        self.assertIn(3, finding["measurement"]["excluded_lines"])

    def test_entry_outside_the_measured_files_is_unmeasured_and_kept(
        self,
    ) -> None:
        self.add_default_test()
        self.add_file(
            "quality-gate-crap.toml",
            baseline_text(
                [
                    {
                        "subject": "gone.py:removed",
                        "bound": 99,
                        "expires": "2999-01-01",
                        "reason": "the file is not selected any more",
                    }
                ],
                check="crap",
                metric_version="python-lines/1",
            ),
        )
        result, document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(check["satisfied"])
        self.assertEqual(check["resolved_baseline_entries"], [])
        self.assertEqual(
            check["unmeasured_baseline_entries"], ["gone.py:removed"]
        )
        self.assertIn("unmeasured gone.py:removed", result.stderr)
        result = self.run_qg(
            "check", "--prune", "crap", env=self.default_tool_env()
        )
        self.assertEqual(result.returncode, 0, output(result))
        loaded = tomllib.loads(self.read_file("quality-gate-crap.toml"))
        self.assertEqual(loaded["check"], "crap")
        self.assertEqual(loaded["metric_version"], "python-lines/1")
        entry = loaded["entry"][0]
        self.assertEqual(entry["subject"], "gone.py:removed")
        self.assertEqual(str(entry["expires"]), "2999-01-01")
        self.assertEqual(entry["bound"], 99)

    def test_no_files_selected_fails(self) -> None:
        self.add_default_test()
        self.write_config(
            crap_config()
            .replace(
                'checks = ["tests", "crap"]',
                'checks = ["tests"]',
            )
            .replace(
                "[classes.test]",
                '[classes.empty]\ncode = true\n'
                'description = "Empty"\nchecks = ["crap"]\n\n'
                "[classes.test]",
            )
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertIn("no files selected", result.stderr)
        self.assertIn("zero inputs is not a pass", result.stderr)

    def test_malformed_baseline_is_an_error(self) -> None:
        self.add_default_test()
        self.add_file("quality-gate-crap.toml", "[entry\n")
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "error")
        self.assertIn("invalid baseline", result.stderr)

    def test_failed_tests_make_crap_unsupported(self) -> None:
        self.write_config(crap_config())
        self.add_tests(
            "    def test_fails(self):\n        self.fail('deliberate')\n",
            name="test_failure",
        )
        self.add_file(
            "pkg/untested.py",
            "def only():\n    return 1\n",
        )
        result, document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(self.check_by_id(document, "tests")["outcome"], "fail")
        self.assertEqual(check["outcome"], "unsupported")
        self.assertIn(
            "coverage unreliable: tests did not pass", result.stderr
        )

    def test_a_syntax_error_is_an_execution_error(self) -> None:
        self.add_default_test()
        self.add_file("pkg/broken.py", "def broken(:\n")
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "error")
        self.assertEqual(check["execution"], "error")
        self.assertIn("cannot parse pkg/broken.py", result.stderr)
        self.assertIn("cannot parse", check["reason"])

    def test_duplicate_identity_fails(self) -> None:
        self.add_default_test()
        self.add_file(
            "pkg/dupes.py",
            "if True:\n"
            "    def same():\n        return 1\n"
            "else:\n"
            "    def same():\n        return 2\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertIn("duplicate function identity", result.stderr)
        self.assertIn("pkg/dupes.py:2", result.stderr)
        self.assertIn("pkg/dupes.py:5", result.stderr)

    def test_unmeasured_function_fails(self) -> None:
        self.add_default_test()
        self.add_file(
            "pkg/excluded.py",
            "def empty():  # pragma: no cover\n"
            "    pass  # pragma: no cover\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertIn("pkg/excluded.py:empty: unmeasured", result.stderr)

    def test_one_line_body_is_unmeasured(self) -> None:
        self.add_default_test()
        self.add_file(
            "pkg/one_line.py",
            "def one_line(value): return 1 if value else 2\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertIn("pkg/one_line.py:one_line: unmeasured", result.stderr)
        self.assertIn(
            "body shares the def line; put the body on its own line",
            result.stderr,
        )
        self.assertIn("pkg/one_line.py:1", result.stderr)

    def test_property_accessors_have_distinct_identities(self) -> None:
        self.add_file(
            "pkg/props.py",
            "class Thing:\n"
            "    def __init__(self):\n"
            "        self._value = 1\n"
            "\n"
            "    @property\n"
            "    def value(self):\n"
            "        return self._value\n"
            "\n"
            "    @value.setter\n"
            "    def value(self, new):\n"
            "        self._value = new\n"
            "\n"
            "    @value.deleter\n"
            "    def value(self):\n"
            "        del self._value\n",
        )
        self.add_tests(
            "    def test_props(self):\n"
            "        import pkg.props\n"
            "        thing = pkg.props.Thing()\n"
            "        thing.value = 2\n"
            "        self.assertEqual(thing.value, 2)\n"
            "        del thing.value\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        findings = self.findings(check)
        for subject in (
            "pkg/props.py:Thing.value",
            "pkg/props.py:Thing.value.setter",
            "pkg/props.py:Thing.value.deleter",
        ):
            self.assertIn(subject, findings)

    def test_overload_declarations_are_skipped(self) -> None:
        self.add_default_test()
        self.add_file(
            "pkg/overloaded.py",
            "from typing import overload\n"
            "\n"
            "\n"
            "@overload\n"
            "def convert(value: int) -> int: ...\n"
            "\n"
            "\n"
            "@overload\n"
            "def convert(value: str) -> str: ...\n"
            "\n"
            "\n"
            "def convert(value):\n"
            "    return value\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        findings = self.findings(check)
        self.assertIn("pkg/overloaded.py:convert", findings)
        self.assertNotIn("pkg/overloaded.py:convert.overload", findings)

    def test_module_and_class_body_code_is_a_subject(self) -> None:
        self.add_default_test()
        self.add_file(
            "pkg/module_code.py",
            "if True:\n"
            "    MODULE_VALUE = 1\n"
            "\n"
            "class Holder:\n"
            "    if True:\n"
            "        CLASS_VALUE = 2\n"
            "\n"
            "    def method(self):\n"
            "        return 1\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        finding = self.findings(check)["pkg/module_code.py:<module>"]
        self.assertEqual(finding["measurement"]["cc"], 3)
        self.assertEqual(finding["measurement"]["executed"], 0)
        self.assertEqual(finding["value"], 12.0)
        self.assertIn("pkg/module_code.py:<module>", result.stderr)

    def test_qg_python_child_process_is_measured(self) -> None:
        self.add_file(
            "pkg/worker.py",
            "def work():\n    return 1\n\n"
            "if __name__ == '__main__':\n    work()\n",
        )
        self.add_file(
            "tests/test_child.py",
            "import json\n"
            "import os\n"
            "import pathlib\n"
            "import subprocess\n"
            "import unittest\n"
            "\n"
            "class Child(unittest.TestCase):\n"
            "    def test_child(self):\n"
            "        prefix = json.loads(os.environ['QG_PYTHON'])\n"
            "        worker = pathlib.Path(__file__).resolve().parent.parent"
            " / 'pkg' / 'worker.py'\n"
            "        subprocess.run(\n"
            "            [*prefix, str(worker)],\n"
            "            check=True,\n"
            "            env=os.environ.copy(),\n"
            "        )\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        finding = self.findings(check)["pkg/worker.py:work"]
        self.assertGreater(finding["measurement"]["executed"], 0)
        self.assertEqual(finding["value"], 1.0)

    def test_module_lambda_body_decisions_are_measured(self) -> None:
        # Importing defines the lambda; its two decisions run only when it is called.
        self.add_tests(
            "    def test_import_only(self):\n"
            "        import pkg.lambdas\n"
            "        self.assertTrue(pkg.lambdas)\n"
        )
        self.add_file(
            "pkg/lambdas.py",
            "f = lambda x: 1 if x else (2 if x is None else 3)\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "fail")
        self.assertIn("pkg/lambdas.py:<lambda@1>", result.stderr)
        self.assertIn("unmeasured", result.stderr)

    def test_uncalled_multiline_module_lambda_scores_zero_coverage(self) -> None:
        self.add_tests(
            "    def test_import_only(self):\n"
            "        import pkg.lambdas\n"
            "        self.assertTrue(pkg.lambdas)\n"
        )
        self.add_file(
            "pkg/lambdas.py",
            "f = lambda x: (\n"
            "    1 if x else (2 if x is None else 3)\n"
            ")\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 1, output(result))
        finding = self.findings(check)["pkg/lambdas.py:<lambda@1>"]
        self.assertEqual(finding["measurement"]["cc"], 3)
        self.assertEqual(finding["measurement"]["executed"], 0)
        self.assertEqual(finding["value"], 12.0)

    def test_called_multiline_module_lambda_is_measured(self) -> None:
        self.add_tests(
            "    def test_call(self):\n"
            "        import pkg.lambdas\n"
            "        self.assertEqual(pkg.lambdas.f(True), 1)\n"
        )
        self.add_file(
            "pkg/lambdas.py",
            "f = lambda x: (\n"
            "    1 if x else (2 if x is None else 3)\n"
            ")\n",
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        finding = self.findings(check)["pkg/lambdas.py:<lambda@1>"]
        self.assertEqual(finding["measurement"]["cc"], 3)
        self.assertEqual(
            finding["measurement"]["executed"],
            finding["measurement"]["statements"],
        )
        self.assertEqual(finding["value"], 3.0)

    def test_a_custom_overload_named_decorator_does_not_hide_its_body(self) -> None:
        self.add_file(
            "pkg/custom.py",
            "def overload(function):\n"
            "    return function\n"
            "\n"
            "@overload\n"
            "def convert(value):\n"
            "    if value:\n"
            "        return 1\n"
            "    return 2\n",
        )
        self.add_tests(
            "    def test_custom(self):\n"
            "        import pkg.custom\n"
            "        self.assertEqual(pkg.custom.convert(True), 1)\n"
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        finding = self.findings(check)["pkg/custom.py:convert"]
        self.assertEqual(finding["measurement"]["cc"], 2)

    def test_typing_overload_with_a_runtime_body_is_measured(self) -> None:
        self.add_file(
            "pkg/runtime_overload.py",
            "from typing import overload\n"
            "\n"
            "\n"
            "@overload\n"
            "def convert(value):\n"
            "    return value\n",
        )
        self.add_tests(
            "    def test_runtime(self):\n"
            "        import pkg.runtime_overload\n"
            "        self.assertTrue(pkg.runtime_overload)\n"
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        finding = self.findings(check)["pkg/runtime_overload.py:convert"]
        self.assertEqual(finding["measurement"]["cc"], 1)
        self.assertEqual(finding["measurement"]["executed"], 0)

    def test_bare_accessor_decorator_is_not_an_accessor(self) -> None:
        self.add_file(
            "pkg/bare.py",
            "def setter(function):\n"
            "    return function\n"
            "\n"
            "@setter\n"
            "def decorated(value):\n"
            "    return value\n",
        )
        self.add_tests(
            "    def test_bare(self):\n"
            "        import pkg.bare\n"
            "        self.assertEqual(pkg.bare.decorated(1), 1)\n"
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("pkg/bare.py:decorated", self.findings(check))

    def test_definition_time_decisions_count_once_in_the_owner(self) -> None:
        self.add_file(
            "pkg/ownership.py",
            "def decorate(function):\n"
            "    return function\n"
            "\n"
            "@(decorate if True else decorate)\n"
            "def composed(value=1 if True else 2):\n"
            "    return value\n",
        )
        self.add_tests(
            "    def test_owned(self):\n"
            "        import pkg.ownership\n"
            "        self.assertEqual(pkg.ownership.composed(), 1)\n"
        )
        result, _document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        findings = self.findings(check)
        self.assertEqual(
            findings["pkg/ownership.py:composed"]["measurement"]["cc"], 1
        )
        self.assertEqual(
            findings["pkg/ownership.py:<module>"]["measurement"]["cc"], 3
        )

    def test_cc_table_counts_each_construct_once(self) -> None:
        self.add_file(
            "pkg/constructs.py",
            "def plain():\n"
            "    return 1\n"
            "\n"
            "def with_if(x):\n"
            "    if x:\n"
            "        return 1\n"
            "    return 2\n"
            "\n"
            "def with_elif(x):\n"
            "    if x == 1:\n"
            "        return 1\n"
            "    elif x == 2:\n"
            "        return 2\n"
            "    return 3\n"
            "\n"
            "def with_ifexp(x):\n"
            "    return 1 if x else 2\n"
            "\n"
            "def with_for(items):\n"
            "    total = 0\n"
            "    for item in items:\n"
            "        total += item\n"
            "    return total\n"
            "\n"
            "async def with_async_for(items):\n"
            "    async for item in items:\n"
            "        return item\n"
            "    return None\n"
            "\n"
            "def with_while(x):\n"
            "    while x:\n"
            "        x -= 1\n"
            "    return x\n"
            "\n"
            "def with_comprehension_for(items):\n"
            "    return [item for item in items]\n"
            "\n"
            "def with_comprehension_if(items):\n"
            "    return [item for item in items if item]\n"
            "\n"
            "def with_except():\n"
            "    try:\n"
            "        return 1\n"
            "    except ValueError:\n"
            "        return 2\n"
            "\n"
            "def with_except_star():\n"
            "    try:\n"
            "        return 1\n"
            "    except* ValueError:\n"
            "        pass\n"
            "\n"
            "def with_match(x):\n"
            "    match x:\n"
            "        case 1:\n"
            "            return 1\n"
            "        case _:\n"
            "            return 0\n"
            "\n"
            "def with_guarded_wildcard(x):\n"
            "    match x:\n"
            "        case _ if x:\n"
            "            return 1\n"
            "    return 0\n"
            "\n"
            "def with_match_capture(x):\n"
            "    match x:\n"
            "        case remaining:\n"
            "            return remaining\n"
            "\n"
            "def with_match_or_wildcard(x):\n"
            "    match x:\n"
            "        case 1 | _:\n"
            "            return 0\n"
            "\n"
            "def with_bool_and(a, b, c):\n"
            "    return a and b and c\n"
            "\n"
            "def with_bool_or(a, b):\n"
            "    return a or b\n"
            "\n"
            "def with_nested(x):\n"
            "    def inner(y):\n"
            "        if y:\n"
            "            return 1\n"
            "        return 2\n"
            "    return inner(x)\n"
            "\n"
            "def with_lambda(x):\n"
            "    return (lambda y: 1 if y else 2)(x)\n"
            "\n"
            "class Outer:\n"
            "    class Inner:\n"
            "        def method(self, x):\n"
            "            if x:\n"
            "                return 1\n"
            "            return 2\n",
        )
        self.add_tests(
            "    def test_constructs(self):\n"
            "        import pkg.constructs\n"
            "        self.assertEqual(pkg.constructs.plain(), 1)\n"
        )
        result, _document, check = self.run_crap()
        expected = {
            "pkg/constructs.py:plain": 1,
            "pkg/constructs.py:with_if": 2,
            "pkg/constructs.py:with_elif": 3,
            "pkg/constructs.py:with_ifexp": 2,
            "pkg/constructs.py:with_for": 2,
            "pkg/constructs.py:with_async_for": 2,
            "pkg/constructs.py:with_while": 2,
            "pkg/constructs.py:with_comprehension_for": 2,
            "pkg/constructs.py:with_comprehension_if": 3,
            "pkg/constructs.py:with_except": 2,
            "pkg/constructs.py:with_except_star": 2,
            "pkg/constructs.py:with_match": 2,
            "pkg/constructs.py:with_guarded_wildcard": 2,
            "pkg/constructs.py:with_match_capture": 1,
            "pkg/constructs.py:with_match_or_wildcard": 1,
            "pkg/constructs.py:with_bool_and": 3,
            "pkg/constructs.py:with_bool_or": 2,
            "pkg/constructs.py:with_nested": 2,
            "pkg/constructs.py:with_lambda": 2,
            "pkg/constructs.py:Outer.Inner.method": 2,
        }
        findings = self.findings(check)
        self.assertTrue(findings, result.stderr)
        for subject, cc in expected.items():
            with self.subTest(subject=subject):
                self.assertIn(subject, findings)
                self.assertEqual(findings[subject]["measurement"]["cc"], cc)
        self.assertNotIn("pkg/constructs.py:with_nested.inner", findings)


RISKY_SOURCE = (
    "def risky(value):\n"
    "    if value:\n"
    "        return 1\n"
    "    a = 1  # dead\n"
    "    b = a  # dead\n"
    "    c = b  # dead\n"
    "    d = c  # dead\n"
    "    if value:  # dead\n"
    "        return d  # dead\n"
    "    return 0  # dead\n"
)


class CoverageConfigurationAttackTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.add_file("pkg/__init__.py", "")
        self.add_file("pkg/risky.py", RISKY_SOURCE)
        self.write_config(crap_config(threshold=8))
        self.fixture_gate()

    def add_covering_test(self, tamper: bool) -> None:
        lines = [
            "",
            "class Sample(unittest.TestCase):",
            "    def test_risky(self):",
            "        import json",
            "        import os",
            "        import pkg.risky",
            "        self.assertEqual(pkg.risky.risky(True), 1)",
        ]
        if tamper:
            lines.extend(
                [
                    "        configuration = pathlib.Path(",
                    "            json.loads(os.environ['QG_PYTHON'])[8]",
                    "        )",
                    "        configuration.write_text(",
                    "            configuration.read_text() + '    dead\\n'",
                    "        )",
                ]
            )
        self.add_file(
            "tests/test_risky.py",
            PYTHON_TEST_HEADER + "\n".join(lines) + "\n",
        )

    def run_attack(
        self, *, tamper: bool
    ) -> tuple[object, dict[str, object]]:
        self.add_covering_test(tamper)
        self.commit_all()
        revision = self.git("rev-parse", "HEAD").stdout.strip()
        return self.run_json(
            "--policy-from", revision, env=self.default_tool_env()
        )

    def assert_risky_score(self, document: dict[str, object]) -> None:
        check = self.check_by_id(document, "crap")
        finding = next(
            item
            for item in check["findings"]
            if item["subject"] == "pkg/risky.py:risky"
        )
        self.assertAlmostEqual(finding["value"], 343 / 81 + 3, places=12)
        self.assertEqual(finding["measurement"]["excluded_lines"], [])

    def test_untouched_run_scores_exactly_as_before(self) -> None:
        result, document = self.run_attack(tamper=False)
        self.assertEqual(result.returncode, 0, output(result))
        self.assert_risky_score(document)

    def test_a_test_cannot_rewrite_the_coverage_configuration(self) -> None:
        result, document = self.run_attack(tamper=True)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("coverage.ini", result.stderr)
        self.assertIn(
            "differs from the gate-owned configuration", result.stderr
        )
        tests = self.check_by_id(document, "tests")
        self.assertEqual(tests["outcome"], "error")
        self.assertIn("coverage.ini", tests["reason"])
        crap = self.check_by_id(document, "crap")
        self.assertEqual(crap["outcome"], "unsupported")
        self.assertEqual(crap["findings"], [])

    def test_non_regular_coverage_configuration_is_refused_within_the_budget(self) -> None:
        self.write_config(crap_config(threshold=8).replace(
            '[checks.tests]\n', '[checks.tests]\nbudget_seconds = 1\n'
        ))
        replacements = {
            "FIFO": "os.mkfifo(configuration)",
            "symlink": "configuration.symlink_to('elsewhere')",
            "directory": "configuration.mkdir()",
            "socket": "sock = socket.socket(socket.AF_UNIX)\n        sock.bind(str(configuration))",
        }
        for kind, replace in replacements.items():
            with self.subTest(kind=kind):
                self.add_file(
                    "tests/test_risky.py",
                    PYTHON_TEST_HEADER
                    + "import json\nimport os\nimport socket\n"
                    + "class Sample(unittest.TestCase):\n"
                    + "    def test_replace(self):\n"
                    + "        configuration = pathlib.Path(json.loads(os.environ['QG_PYTHON'])[8])\n"
                    + "        configuration.unlink()\n"
                    + f"        {replace}\n",
                )
                self.commit_all(kind)
                revision = self.git("rev-parse", "HEAD").stdout.strip()
                started = time.monotonic()
                result = self.run_qg(
                    "check", "--json", "--policy-from", revision,
                    env=self.default_tool_env(), timeout=8,
                )
                elapsed = time.monotonic() - started
                document = self.parse_json(result)
                check = self.check_by_id(document, "tests")
                self.assertEqual(result.returncode, 2, output(result))
                self.assertEqual(document["decision"], "error")
                self.assertEqual(check["execution"], "error")
                self.assertIn("coverage.ini", check["reason"])
                self.assertIn("expected a regular file", check["reason"])
                self.assertIn(kind, check["reason"])
                self.assertIn(check["reason"], result.stderr)
                self.assertLess(check["duration_seconds"], 1.0)
                self.assertLess(elapsed, 8.0)

    def test_settings_stay_canonical_after_validation(self) -> None:
        self.add_covering_test(False)
        shadow = self.base / "shadow"
        shadow.mkdir()
        (shadow / "risky.py").write_text(RISKY_SOURCE, encoding="utf-8")
        coverage_file = self.gate / "quality_gate" / "coverage_tool.py"
        with coverage_file.open("a", encoding="utf-8") as stream:
            stream.write(
                "\n_original_coverage_config_problem = _coverage_config_problem\n"
                "def _change_config_after_validation(data_dir, settings):\n"
                "    problem = _original_coverage_config_problem(data_dir, settings)\n"
                "    if problem is None:\n"
                f"        root = Path({str(self.repo)!r})\n"
                "        path = coverage_config_path(data_dir)\n"
                "        with path.open('a', encoding='utf-8') as config:\n"
                "            config.write('    dead\\n[paths]\\nalias =\\n'\n"
                "                         + f'    {root.parent / \"shadow\"}\\n'\n"
                "                         + f'    {root / \"pkg\"}\\n')\n"
                "    return problem\n"
                "_coverage_config_problem = _change_config_after_validation\n"
            )
        self.commit_all()
        revision = self.git("rev-parse", "HEAD").stdout.strip()
        result = subprocess.run(
            [sys.executable, "-I", str(self.gate / "qg.py"), "--repo", str(self.repo),
             "check", "--json", "--policy-from", revision],
            cwd=self.repo, env=self.default_tool_env(), capture_output=True,
            text=True, timeout=30,
        )
        document = self.parse_json(result)
        self.assertEqual(result.returncode, 0, output(result))
        self.assert_risky_score(document)

    def test_settings_text_needs_no_coverage_installation(self) -> None:
        from quality_gate.coverage_tool import coverage_config_text

        with mock.patch("quality_gate.coverage_tool.import_coverage") as load:
            with mock.patch("quality_gate.coverage_tool.coverage_installation") as lookup:
                settings = coverage_config_text(self.repo)
        self.assertIsInstance(settings, str)
        self.assertIn(f"source =\n    {self.repo}\n", settings)
        load.assert_not_called()
        lookup.assert_not_called()

    def test_root_rule_matches_both_pinned_list_parsers(self) -> None:
        from quality_gate.coverage_tool import import_coverage

        coverage = import_coverage()
        whitespace = [chr(code) for code in range(sys.maxunicode + 1) if chr(code).isspace()]
        corpus = [f"/project{chr(code)}name" for code in range(128)]
        corpus.extend(f"{character}/project" for character in whitespace)
        corpus.extend(f"/project{character}" for character in whitespace)
        corpus.extend(f"/project{character}name" for character in whitespace)
        corpus.extend([
            "/plain-ASCII_123", "/project name", "/projet-été-日本語",
            "/project${UNDEFINED?}name", "/project${UNDEFINED}name",
            "/project${UNDEFINED-default}name", "/project$$name",
        ])
        with mock.patch.dict(os.environ, {}, clear=True):
            for source in corpus:
                with self.subTest(root=source):
                    self.assert_root_rule_matches_parsers(Path(source), coverage)

    def assert_root_rule_matches_parsers(self, root: Path, coverage: object) -> None:
        from quality_gate.coverage_tool import _analysis_list, coverage_config_text
        from quality_gate.policy import UsageError

        source = str(root)
        # Construct refused settings independently, keeping LF continuations parseable.
        settings = "[run]\nsource =\n    " + source.replace("\n", "\n    ") + "\n"
        collection = coverage.config.HandyConfigParser(our_file=True)
        collection.read_string(settings)
        analysis = configparser.ConfigParser(interpolation=None)
        analysis.read_string(settings)
        try:
            collection_sources = collection.getlist("run", "source")
        except coverage.CoverageException:
            collection_sources = []
        analysis_sources = _analysis_list(analysis.get("run", "source"))
        unchanged = collection_sources == analysis_sources == [source]
        try:
            actual_settings = coverage_config_text(root)
        except UsageError:
            accepted = False
        else:
            accepted = True
        self.assertEqual(accepted, unchanged, (collection_sources, analysis_sources))
        if accepted:
            collection.read_string(actual_settings)
            analysis.read_string(actual_settings)
            self.assertEqual(collection.getlist("run", "source"), [source])
            self.assertEqual(_analysis_list(analysis.get("run", "source")), [source])

    def test_coverage_verification_failure_after_tests_is_structured_unsupported(self) -> None:
        from quality_gate.coverage_tool import coverage_installation

        installation = coverage_installation()
        tools = self.base / "tools"
        disposable = tools / installation.name
        shutil.copytree(installation, disposable)
        self.add_covering_test(False)
        self.add_file(
            "tests/test_tamper.py",
            PYTHON_TEST_HEADER
            + f"pathlib.Path({str(disposable / 'tampered')!r}).touch()\n"
            + "class Sample(unittest.TestCase):\n"
            + "    def test_ok(self):\n        self.assertTrue(True)\n",
        )
        result, document = self.run_json(env={"QG_TOOLS_DIR": str(tools)})
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "unsupported")
        self.assertEqual(check["diagnostics"]["exit_code"], 0)
        self.assertIn("coverage combination failed", check["reason"])
        self.assertIn("payload digest mismatch", check["reason"])
        self.assertIn(str(disposable), check["reason"])
        self.assertIn(check["reason"], result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.check_by_id(document, "crap")["findings"], [])

    def assert_project_path_is_refused(self, character: str) -> None:
        self.add_file(
            "tests/test_started.py",
            PYTHON_TEST_HEADER + "pathlib.Path('coverage-started').touch()\n",
        )
        self.repo = self.repo.rename(self.base / f"project{character}name")
        result, document = self.run_json(env=self.default_tool_env())
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "error")
        self.assertEqual(check["execution"], "error")
        self.assertIn(repr(str(self.repo)), check["reason"])
        offending = "$" if "$" in character else character
        self.assertIn(f"character {offending!r}", check["reason"])
        self.assertIn("coverage's 'source' setting cannot represent it", check["reason"])
        self.assertIn(check["reason"], result.stderr)
        self.assertIsNone(check["diagnostics"]["argv"])
        self.assertFalse((self.repo / "coverage-started").exists())
        self.assertEqual(self.check_by_id(document, "crap")["findings"], [])

    def test_project_path_with_comma_is_refused_before_running(self) -> None:
        self.assert_project_path_is_refused(",")

    def test_project_path_with_substitution_is_refused_before_running(self) -> None:
        self.assert_project_path_is_refused("${UNDEFINED?}")

    def test_project_path_with_lf_is_refused_before_running(self) -> None:
        self.assert_project_path_is_refused("\n")

    def test_project_path_with_cr_is_refused_before_running(self) -> None:
        self.assert_project_path_is_refused("\r")

    def test_project_path_with_vertical_tab_is_refused_before_running(self) -> None:
        self.assert_project_path_is_refused("\v")

    def test_project_path_with_u2028_is_refused_before_running(self) -> None:
        self.assert_project_path_is_refused("\u2028")

    def test_project_path_with_other_splitlines_separators_is_refused(self) -> None:
        for character in ("\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2029"):
            with self.subTest(character=repr(character)):
                self.assert_project_path_is_refused(character)

    def test_project_path_with_spaces_is_one_source_entry(self) -> None:
        self.assert_project_path_is_one_source_entry("project name")

    def test_project_path_with_non_ascii_letters_is_one_source_entry(self) -> None:
        self.assert_project_path_is_one_source_entry("projet-été-日本語")

    def assert_project_path_is_one_source_entry(self, name: str) -> None:
        from quality_gate.coverage_tool import (
            coverage_config_data, import_coverage, write_coverage_config,
        )

        self.repo = self.repo.rename(self.base / name)
        data_dir = self.base / "coverage data"
        config_file = write_coverage_config(data_dir, self.repo)
        coverage = import_coverage()
        collection = coverage.Coverage(config_file=str(config_file))
        analysis = coverage.Coverage(
            config_file=coverage_config_data(
                config_file.read_text(encoding="utf-8"), data_dir / ".coverage"
            )
        )
        self.assertEqual(collection.get_option("run:source"), [str(self.repo)])
        self.assertEqual(analysis.get_option("run:source"), [str(self.repo)])
        result, document = self.run_attack(tamper=False)
        self.assertEqual(result.returncode, 0, output(result))
        self.assert_risky_score(document)


if __name__ == "__main__":
    unittest.main()
