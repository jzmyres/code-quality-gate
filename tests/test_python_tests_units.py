"""Unit tests for the python_tests adapter helpers."""
from __future__ import annotations

import contextlib
import io
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from support import GATE

sys.path.insert(0, str(GATE))
from quality_gate import checks, coverage_tool, output_patterns, policy, python_tests
from quality_gate import regexrun, runner


class PythonTestsCheckHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        tests_pattern = r"^Ran ([0-9]+) tests? in"
        skipped_pattern = r"skipped=([0-9]+)"
        self.spec = python_tests.PythonTestsSpec(
            run=(),
            tests_pattern=tests_pattern,
            tests_pattern_re=re.compile(tests_pattern, re.MULTILINE),
            skipped_pattern=skipped_pattern,
            skipped_pattern_re=re.compile(skipped_pattern, re.MULTILINE),
            budget_seconds=600,
        )
        self.check = policy.CheckDef(
            id="tests",
            adapter="python_tests",
            tier=1,
            enforcement="enforced",
            metric_version="test-count/1",
            evidence=("tests",),
            spec=self.spec,
            threshold=None,
            baseline=None,
        )

    def counts(self, combined: str) -> tuple[object, object]:
        return python_tests._tests_counts(
            self.check,
            self.spec,
            0.0,
            "check: tests",
            combined,
            runner.Diagnostics(),
            time.monotonic() + 60,
        )

    def test_missing_or_unreadable_coverage_configuration_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            settings = coverage_tool.coverage_config_text(data_dir)
            missing = coverage_tool._coverage_config_problem(data_dir, settings)
            self.assertIn("coverage.ini", missing)
            self.assertIn("cannot be read", missing)
            coverage_tool.write_coverage_config(data_dir, data_dir)
            with mock.patch.object(coverage_tool.os, "open", side_effect=PermissionError("denied")):
                unreadable = coverage_tool._coverage_config_problem(data_dir, settings)
            self.assertIn("coverage.ini", unreadable)
            self.assertIn("denied", unreadable)

    def test_more_entries_than_the_limit_end_with_and_n_more(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            names = [f"left-{index:02d}" for index in range(11)]
            for name in names:
                (directory / name).write_text("", encoding="utf-8")
            walk = os.walk

            def reversed_walk(*args: object, **options: object):
                for current, directories, files in walk(*args, **options):
                    yield (
                        current,
                        sorted(directories, reverse=True),
                        sorted(files, reverse=True),
                    )

            with mock.patch.object(checks.os, "walk", side_effect=reversed_walk):
                paths = checks._temporary_paths(directory)
        self.assertEqual(paths, sorted(names))
        self.assertEqual(
            checks._temporary_reason(paths),
            "11 entries (11 paths) left in the suite's TMPDIR: "
            + ", ".join(sorted(names)[: checks.TEMPORARY_PATH_LIMIT])
            + ", and 1 more",
        )

    def test_temporary_cleanup_failure_is_reported_with_its_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "tmp"
            directory.mkdir()
            message = (
                f"cannot remove the temporary directory {directory}: denied"
            )
            with mock.patch.object(
                checks, "_remove_temporary_directory", return_value=message
            ):
                with self.assertRaises(policy.UsageError) as raised:
                    checks._finish_temporary(directory)
        self.assertIn(str(directory), str(raised.exception))

    def test_setup_returns_the_data_directory_and_prefix(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        evidence_dir = Path(temporary.name)
        with mock.patch.object(
            python_tests, "coverage_prefix", return_value=["prefix"]
        ) as prefix:
            setup = python_tests._tests_setup(
                Path("/repo"), self.check, self.spec, 0.0, "check: tests", evidence_dir
            )
        assert not isinstance(setup, checks.CheckResult)
        data_dir, python_prefix = setup
        self.assertTrue(data_dir.is_dir())
        self.assertEqual(data_dir, evidence_dir / "data")
        self.assertEqual(python_prefix, ["prefix"])
        prefix.assert_called_once_with(Path("/repo"), data_dir)

    def setup_failure(self, error: Exception) -> checks.CheckResult:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        with mock.patch.object(
            python_tests, "coverage_prefix", side_effect=error
        ), contextlib.redirect_stderr(io.StringIO()):
            setup = python_tests._tests_setup(
                Path("/repo"), self.check, self.spec, 0.0, "check: tests",
                Path(temporary.name),
            )
        assert isinstance(setup, checks.CheckResult)
        return setup

    def test_setup_reports_an_unsupported_coverage_install(self) -> None:
        setup = self.setup_failure(
            policy.UnsupportedError("coverage is not installed")
        )
        self.assertEqual(setup.outcome, "unsupported")
        self.assertEqual(setup.execution, "error")
        self.assertEqual(setup.reason, "coverage is not installed")
        self.assertEqual(
            setup.diagnostics.error, "coverage is not installed"
        )

    def test_setup_reports_an_oserror_as_an_error(self) -> None:
        setup = self.setup_failure(OSError("denied"))
        self.assertEqual(setup.outcome, "error")
        self.assertEqual(setup.execution, "error")
        self.assertEqual(
            setup.reason, "cannot create coverage data directory: denied"
        )

    def test_execution_failure_handles_each_unfinished_run(self) -> None:
        cases = (
            (
                runner.RunResult(
                    argv=(),
                    execution="error",
                    returncode=None,
                    error="cannot start",
                ),
                "error",
                "error",
                "cannot start",
            ),
            (
                runner.RunResult(
                    argv=(), execution="budget", returncode=-15
                ),
                "fail",
                "budget",
                "command exceeded its 600 second budget",
            ),
            (
                runner.RunResult(
                    argv=(), execution="signal", returncode=-15
                ),
                "fail",
                "signal",
                "command terminated by signal 15",
            ),
        )
        for run_result, outcome, execution, reason in cases:
            with self.subTest(execution=run_result.execution):
                with contextlib.redirect_stderr(io.StringIO()):
                    result = python_tests._tests_execution_failure(
                        self.check,
                        self.spec,
                        run_result,
                        runner.Diagnostics(),
                        "",
                        "check: tests",
                        0.0,
                    )
            assert result is not None
            self.assertEqual(result.outcome, outcome)
            self.assertEqual(result.execution, execution)
            self.assertTrue(result.reason.startswith(reason))
            if execution == "budget":
                self.assertIn("deadline:", result.reason)
                self.assertIn("elapsed:", result.reason)

    def test_execution_failure_ignores_a_completed_run(self) -> None:
        run_result = runner.RunResult(
            argv=(), execution="completed", returncode=1
        )
        self.assertIsNone(
            python_tests._tests_execution_failure(
                self.check,
                self.spec,
                run_result,
                runner.Diagnostics(),
                "",
                "check: tests",
                0.0,
            )
        )

    def test_counts_returns_a_matching_failure(self) -> None:
        with mock.patch.object(
            output_patterns, "_pattern_matches", return_value=(None, None)
        ), contextlib.redirect_stderr(io.StringIO()):
            counts, failure = self.counts("ignored")
        self.assertIsNone(counts)
        assert failure is not None
        self.assertEqual(failure.outcome, "error")
        self.assertEqual(failure.reason, "test summary matching failed")

    def test_counts_marks_an_invalid_summary_unsupported(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            counts, failure = self.counts(
                "Ran 1 test in 0.1s\nskipped=2"
            )
        self.assertIsNone(counts)
        assert failure is not None
        self.assertEqual(failure.outcome, "unsupported")
        self.assertEqual(failure.reason, "skipped 2 tests but only 1 ran")

    def test_counts_rejects_zero_executed_tests(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            counts, failure = self.counts(
                "Ran 1 test in 0.1s\nskipped=1"
            )
        self.assertIsNone(counts)
        assert failure is not None
        self.assertEqual(failure.outcome, "fail")
        self.assertEqual(failure.measurement, {"tests": 0})
        self.assertEqual(
            failure.reason,
            "no test executed: 1 ran, 1 skipped; "
            "zero tests is not a pass",
        )

    def test_counts_returns_the_executed_test_count(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            counts, failure = self.counts(
                "Ran 3 tests in 0.1s\nskipped=1"
            )
        self.assertEqual(counts, (3, 1, 2))
        self.assertIsNone(failure)

    def test_evidence_builds_the_pass_result(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        evidence_dir = Path(temporary.name)
        data_dir = evidence_dir / "data"
        data_dir.mkdir()
        coverage_tool.write_coverage_config(data_dir, data_dir)
        with mock.patch.object(
            python_tests, "_combine_tests_evidence", return_value=None
        ), contextlib.redirect_stdout(io.StringIO()) as stdout:
            result = python_tests._tests_evidence(
                self.check,
                self.spec,
                0.0,
                "check: tests",
                evidence_dir,
                data_dir,
                data_dir,
                3,
                1,
                2,
                runner.Diagnostics(),
            )
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.measurement, {"tests": 2})
        self.assertEqual(result.tests_ran, 3)
        self.assertEqual(result.tests_skipped, 1)
        self.assertEqual(
            result.evidence_path,
            evidence_dir / "combined" / ".coverage",
        )
        self.assertEqual(result.adapter_data["coverage_config"], data_dir / "coverage.ini")
        self.assertEqual(
            result.adapter_data["coverage_settings"], coverage_tool.coverage_config_text(data_dir)
        )
        self.assertIn("passed (2 tests", stdout.getvalue())


class TestSummaryTests(unittest.TestCase):
    def spec(
        self,
        tests_pattern: str = r"^Ran ([0-9]+) tests? in",
        skipped_pattern: str | None = r"skipped=([0-9]+)",
    ) -> python_tests.PythonTestsSpec:
        return python_tests.PythonTestsSpec(
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

    def summarize(
        self, spec: python_tests.PythonTestsSpec, output: str
    ) -> tuple[int | None, int | None, str | None]:
        patterns = {"tests": spec.tests_pattern}
        if spec.skipped_pattern is not None:
            patterns["skipped"] = spec.skipped_pattern
        matches = regexrun.evaluate({"text": output, "patterns": patterns})
        return output_patterns.summarize_matches(
            spec, matches["tests"], matches.get("skipped", [])
        )

    def test_summary_counts_skipped_and_reports_errors(self) -> None:
        ran, skipped, error = self.summarize(
            self.spec(), "Ran 3 tests in 0.01s\nskipped=1"
        )
        self.assertEqual((ran, skipped, error), (3, 1, None))
        ran, skipped, error = self.summarize(self.spec(), "no summary")
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("did not match", error)

    def test_non_integer_counts_are_rejected(self) -> None:
        ran, skipped, error = self.summarize(
            self.spec(tests_pattern=r"^Ran ([A-Za-z]+) tests? in"),
            "Ran many tests in 0.01s",
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("tests_pattern", error)
        self.assertIn("not a test count", error)

        ran, skipped, error = self.summarize(
            self.spec(skipped_pattern=r"skipped=([A-Za-z]+)"),
            "Ran 1 test in 0.01s\nskipped=many",
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("skipped_pattern", error)
        self.assertIn("not a test count", error)

    def test_ambiguous_skipped_summary_is_rejected(self) -> None:
        ran, skipped, error = self.summarize(
            self.spec(), "Ran 2 tests in 0.1s\nskipped=0\nskipped=1"
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("ambiguous skipped summary", error)

    def test_negative_counts_are_rejected(self) -> None:
        ran, skipped, error = self.summarize(
            self.spec(skipped_pattern=r"skipped=(-?[0-9]+)"),
            "Ran 2 tests in 0.1s\nskipped=-1",
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("not a test count", error)
        ran, skipped, error = self.summarize(
            self.spec(tests_pattern=r"^Ran (-?[0-9]+) tests? in"),
            "Ran -1 test in 0.1s",
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("not a test count", error)

    def test_an_absent_optional_capture_is_zero(self) -> None:
        ran, skipped, error = self.summarize(
            self.spec(skipped_pattern=r"skipped(?:=([0-9]+))?"),
            "Ran 1 test in 0.1s\nskipped",
        )
        self.assertEqual((ran, skipped, error), (1, 0, None))

    def test_more_skipped_than_ran_is_rejected(self) -> None:
        ran, skipped, error = self.summarize(
            self.spec(), "Ran 1 test in 0.01s\nskipped=2"
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertEqual(error, "skipped 2 tests but only 1 ran")


if __name__ == "__main__":
    unittest.main()
