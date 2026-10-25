"""Tests for the python_crap adapter, its CC table and its ratchet."""
from __future__ import annotations

import json
import unittest

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
        "schema = 1",
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
        'checks = ["crap"]',
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
                ]
            ),
        )
        result, document, check = self.run_crap()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        finding = self.findings(check)["pkg/untested.py:five"]
        self.assertEqual(finding["value"], 30.0)
        self.assertEqual(finding["bound"], 30)
        self.assertEqual(finding["baseline_reason"], "worklist")
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
                ]
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


if __name__ == "__main__":
    unittest.main()
