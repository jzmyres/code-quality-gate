"""Tests for the python_tests adapter and its QG_PYTHON contract."""
from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import (
    GATE,
    PYTHON_COMMON_RULE_LINES,
    PYTHON_TEST_HEADER,
    FixtureCase,
    output,
)

sys.path.insert(0, str(GATE))
covrun = importlib.import_module("quality_gate.covrun")
policy = importlib.import_module("quality_gate.policy")
python_tests = importlib.import_module("quality_gate.python_tests")


def tests_config(
    *,
    run: str = '["{python}", "-m", "unittest", "discover", "-s", "tests"]',
    tests_pattern: str = r"^Ran (\d+) tests? in",
    skipped_pattern: str | None = None,
    budget: int | None = None,
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
        f"run = {run}",
        f"tests_pattern = {json.dumps(tests_pattern)}",
    ]
    if skipped_pattern is not None:
        lines.append(f"skipped_pattern = {json.dumps(skipped_pattern)}")
    if budget is not None:
        lines.append(f"budget_seconds = {budget}")
    lines.extend(
        [
            "",
            "[[rule]]",
            'pattern = "tests/*.py"',
            'class = "test"',
            'reason = "tests"',
        ]
    )
    lines.extend(PYTHON_COMMON_RULE_LINES)
    return "\n".join(lines)


class PythonTestsTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.write_config(tests_config())

    def add_test(self, name: str, body: str) -> None:
        self.add_file(
            f"tests/{name}.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n" + body,
        )

    def run_tests(
        self, *, env: dict[str, str] | None = None
    ) -> tuple[object, dict[str, object]]:
        return self.run_json(env=env or self.default_tool_env())

    def failed_tests(
        self, *needles: str
    ) -> tuple[object, dict[str, object]]:
        result, document = self.run_tests()
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "fail")
        for needle in needles:
            self.assertIn(needle, result.stderr)
        return result, check

    def unsupported_tests(
        self,
        *needles: str,
        env: dict[str, str] | None = None,
    ) -> tuple[object, dict[str, object]]:
        result, document = self.run_tests(env=env)
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "unsupported")
        for needle in needles:
            self.assertIn(needle, result.stderr)
        return result, check

    def test_tests_pass_and_report_the_count(self) -> None:
        self.add_test(
            "test_sample",
            "    def test_one(self):\n        self.assertTrue(True)\n\n"
            "    def test_two(self):\n        self.assertTrue(True)\n",
        )
        result, document = self.run_tests()
        self.assertEqual(result.returncode, 0, output(result))
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(check["execution"], "completed")
        self.assertEqual(check["measurement"], {"tests": 2})
        self.assertEqual(check["metric_version"], "test-count/1")
        self.assertIn("passed (2 tests", result.stderr)

    def test_zero_tests_fails(self) -> None:
        self.add_file("tests/helper.py", "VALUE = 1\n")
        self.failed_tests(
            "no test executed: 0 ran, 0 skipped",
            "zero tests is not a pass",
        )

    def test_all_skipped_tests_fail_as_no_test_executed(self) -> None:
        self.write_config(
            tests_config(skipped_pattern=r"skipped=(\d+)")
        )
        self.add_test(
            "test_skipped",
            "    @unittest.skip('deliberate')\n"
            "    def test_skipped(self):\n"
            "        self.assertTrue(True)\n",
        )
        self.failed_tests(
            "no test executed: 1 ran, 1 skipped",
            "zero tests is not a pass",
        )

    def test_ambiguous_test_summary_is_unsupported(self) -> None:
        self.add_file(
            "tests/summary.py",
            "print('Ran 1 test in 0.1s')\n"
            "print('Ran 2 tests in 0.2s')\n",
        )
        self.write_config(
            tests_config(run='["{python}", "tests/summary.py"]')
        )
        self.unsupported_tests("ambiguous test summary")

    def test_ambiguous_test_summary_on_failure_is_unsupported(self) -> None:
        self.add_file(
            "tests/failing_summary.py",
            "import sys\n"
            "print('Ran 1 test in 0.1s')\n"
            "print('Ran 2 tests in 0.2s')\n"
            "sys.exit(1)\n",
        )
        self.write_config(
            tests_config(run='["{python}", "tests/failing_summary.py"]')
        )
        self.unsupported_tests("ambiguous test summary")

    def test_failing_test_fails(self) -> None:
        self.add_test(
            "test_failure",
            "    def test_fails(self):\n        self.fail('deliberate')\n",
        )
        self.failed_tests("command exited 1", "deliberate")

    def test_failed_command_without_summary_has_no_measurement(self) -> None:
        self.add_file(
            "tests/failing.py",
            "import sys\nprint('no summary')\nsys.exit(1)\n",
        )
        self.write_config(
            tests_config(run='["{python}", "tests/failing.py"]')
        )
        _result, check = self.failed_tests("command exited 1", "no summary")
        self.assertNotIn("measurement", check)

    def test_failed_command_with_zero_executed_tests_reports_counts(self) -> None:
        self.add_file(
            "tests/failing.py",
            "import sys\n"
            "print('Ran 1 test in 0.1s')\n"
            "print('skipped=1')\n"
            "sys.exit(1)\n",
        )
        self.write_config(
            tests_config(
                run='["{python}", "tests/failing.py"]',
                skipped_pattern=r"skipped=(\d+)",
            )
        )
        _result, check = self.failed_tests(
            "command exited 1 and no test executed: 1 ran, 1 skipped",
            "zero tests is not a pass",
        )
        self.assertEqual(check["measurement"], {"tests": 0})

    def test_timeout_reports_budget(self) -> None:
        self.write_config(tests_config(budget=1))
        self.add_test(
            "test_slow",
            "    def test_slow(self):\n        import time\n"
            "        time.sleep(10)\n",
        )
        result, document = self.run_tests()
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(check["execution"], "budget")
        self.assertEqual(check["budget_seconds"], 1)
        self.assertIn("exceeded its 1 second budget", result.stderr)

    def test_unmatched_tests_pattern_is_unsupported(self) -> None:
        self.write_config(tests_config(tests_pattern=r"NEVER (\d+)"))
        self.add_test(
            "test_sample",
            "    def test_one(self):\n        self.assertTrue(True)\n",
        )
        self.unsupported_tests("tests_pattern", "did not match")

    def test_missing_coverage_is_unsupported(self) -> None:
        self.add_test(
            "test_sample",
            "    def test_one(self):\n        self.assertTrue(True)\n",
        )
        self.unsupported_tests(
            "not installed",
            "tools fetch",
            env={"QG_TOOLS_DIR": str(self.base / "empty-tools")},
        )


class CovrunTests(unittest.TestCase):
    def test_usage_and_missing_coverage_are_reported(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(covrun._run([]), 2)
        self.assertIn("expected DATA_DIR", stderr.getvalue())

        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                code = covrun._run(
                    [
                        "covrun.py",
                        temporary,
                        temporary,
                        str(missing),
                        "-c",
                        "pass",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertIn("coverage is not installed", stderr.getvalue())

    def test_run_writes_the_config_and_starts_coverage(self) -> None:
        calls: list[list[str]] = []

        def fake_main(arguments: list[str]) -> int:
            calls.append(arguments)
            return 7

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            data_dir = base / "data"
            source_root = base / "root"
            source_root.mkdir()
            coverage_dir = base / "coverage"
            coverage_dir.mkdir()
            with mock.patch.dict(
                os.environ, {"COVERAGE_TEST_OVERRIDE": "1"}
            ), mock.patch.object(
                covrun, "_coverage_main", return_value=(fake_main, None)
            ), mock.patch.object(sys, "path", list(sys.path)):
                code = covrun._run(
                    [
                        "covrun.py",
                        str(data_dir),
                        str(source_root),
                        str(coverage_dir),
                        "-c",
                        "print(1)",
                    ]
                )
            self.assertEqual(code, 7)
            self.assertNotIn("COVERAGE_TEST_OVERRIDE", os.environ)
            config_file = data_dir / "coverage.ini"
            self.assertIn(
                f"source =\n    {source_root}",
                config_file.read_text(encoding="utf-8"),
            )
            self.assertEqual(calls[0][0], "run")
            self.assertIn("--parallel-mode", calls[0])
            self.assertIn(f"--rcfile={config_file}", calls[0])
            self.assertEqual(calls[0][-2:], ["-c", "print(1)"])


class TestSummaryTests(unittest.TestCase):
    def spec(
        self,
        tests_pattern: str = r"^Ran ([0-9]+) tests? in",
        skipped_pattern: str | None = r"skipped=([0-9]+)",
    ) -> policy.PythonTestsSpec:
        return policy.PythonTestsSpec(
            run=(),
            tests_pattern=tests_pattern,
            tests_pattern_re=re.compile(tests_pattern, re.MULTILINE),
            skipped_pattern=skipped_pattern,
            skipped_pattern_re=(
                re.compile(skipped_pattern, re.MULTILINE)
                if skipped_pattern is not None
                else None
            ),
            budget_seconds=600,
        )

    def test_count_subtracts_skipped_and_reports_summary_errors(self) -> None:
        count, error = python_tests.parse_test_count(
            self.spec(), "Ran 3 tests in 0.01s\nskipped=1"
        )
        self.assertEqual((count, error), (2, None))
        count, error = python_tests.parse_test_count(
            self.spec(), "no summary"
        )
        self.assertIsNone(count)
        self.assertIn("did not match", error)

    def test_non_integer_counts_are_rejected(self) -> None:
        ran, skipped, error = python_tests.parse_test_summary(
            self.spec(tests_pattern=r"^Ran ([A-Za-z]+) tests? in"),
            "Ran many tests in 0.01s",
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("tests_pattern", error)
        self.assertIn("not a test count", error)

        ran, skipped, error = python_tests.parse_test_summary(
            self.spec(skipped_pattern=r"skipped=([A-Za-z]+)"),
            "Ran 1 test in 0.01s\nskipped=many",
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("skipped_pattern", error)
        self.assertIn("not a test count", error)

    def test_more_skipped_than_ran_is_rejected(self) -> None:
        ran, skipped, error = python_tests.parse_test_summary(
            self.spec(), "Ran 1 test in 0.01s\nskipped=2"
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertEqual(error, "skipped 2 tests but only 1 ran")


if __name__ == "__main__":
    unittest.main()
