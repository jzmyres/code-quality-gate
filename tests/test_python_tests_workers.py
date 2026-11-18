"""Tests for python_tests parallel workers and their small helpers."""
from __future__ import annotations

import contextlib
import io
import os
import re
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from support import PYTHON_TEST_HEADER, output
from test_python_tests import PythonTestsFixture, tests_config

from quality_gate import checks, coverage_tool, policy, python_tests


def spec(workers: int = 1) -> python_tests.PythonTestsSpec:
    pattern = r"^Ran (\d+) tests? in"
    skipped = r"skipped=(\d+)"
    return python_tests.PythonTestsSpec(
        run=("{python}", "-m", "unittest", "discover", "-s", "tests"),
        tests_pattern=pattern,
        tests_pattern_re=re.compile(pattern, re.MULTILINE),
        skipped_pattern=skipped,
        skipped_pattern_re=re.compile(skipped, re.MULTILINE),
        budget_seconds=60,
        workers=workers,
    )


def check(workers: int = 1) -> policy.CheckDef:
    return policy.CheckDef(
        id="tests",
        adapter="python_tests",
        tier=1,
        enforcement="enforced",
        metric_version="test-count/1",
        evidence=("tests",),
        spec=spec(workers),
        threshold=None,
        baseline=None,
    )


class WorkerTests(PythonTestsFixture):
    def setUp(self) -> None:
        super().setUp()
        try:
            coverage_tool.coverage_installation()
        except policy.UnsupportedError:
            self.skipTest("the coverage tool cache is unavailable")

    def test_workers_split_the_suite_and_report_each_failure(self) -> None:
        self.write_config(tests_config(workers=2))
        self.add_test(
            "test_split",
            "    def test_a_ok(self):\n        self.assertTrue(True)\n\n"
            "    def test_b_fails(self):\n        self.fail('from b')\n\n"
            "    def test_c_fails(self):\n        self.fail('from c')\n\n"
            "    def test_d_ok(self):\n        self.assertTrue(True)\n",
        )
        result, document = self.run_tests()
        self.assertEqual(result.returncode, 1, output(result))
        found = self.check_by_id(document, "tests")
        self.assertEqual(found["outcome"], "fail")
        self.assertEqual(found["measurement"], {"tests": 4})
        self.assertIn("4 tests ran", found["reason"])
        for needle in (
            "test_split.Sample.test_b_fails",
            "AssertionError: from b",
            "test_split.Sample.test_c_fails",
            "AssertionError: from c",
        ):
            self.assertIn(needle, found["reason"])

    def test_a_worker_without_a_summary_names_its_test(self) -> None:
        self.write_config(tests_config(workers=2))
        self.add_test(
            "test_crash_worker",
            "    def test_a_crash(self):\n        import os\n        os._exit(3)\n\n"
            "    def test_b_ok(self):\n        self.assertTrue(True)\n",
        )
        result, document = self.run_tests()
        self.assertEqual(result.returncode, 1, output(result))
        found = self.check_by_id(document, "tests")
        self.assertEqual(found["outcome"], "error")
        self.assertIn(
            "test_crash_worker.Sample.test_a_crash", found["reason"]
        )
        self.assertIn("without a test summary", found["reason"])

    def test_workers_above_one_needs_a_unittest_discover_run(self) -> None:
        self.write_config(tests_config(
            workers=2,
            run='["{python}", "-m", "unittest", "tests"]',
        ))
        result, document = self.run_json()
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        for needle in ("checks.tests.workers", "unittest", "workers"):
            self.assertIn(needle, result.stderr)

    def adapter_lines(
        self, workers: int, name: str
    ) -> tuple[set[int], int]:
        evidence = self.base / name
        evidence.mkdir()
        context = SimpleNamespace(
            root=self.repo,
            check=check(workers),
            prefix="check: tests",
            evidence_dir=evidence,
        )
        with mock.patch.dict(
            os.environ, self.default_tool_env()
        ), contextlib.redirect_stderr(io.StringIO()):
            result = python_tests._run_python_tests(context)
        self.assertEqual(result.outcome, "pass", result.reason)
        coverage = coverage_tool.import_coverage()
        data = coverage.CoverageData(
            str(evidence / "combined" / ".coverage")
        )
        data.read()
        return (
            set(data.lines(str(self.repo / "app.py")) or []),
            result.tests_ran or 0,
        )

    def test_workers_combine_coverage_like_one_process(self) -> None:
        self.add_file(
            "app.py",
            "def value(number):\n"
            "    if number:\n"
            "        return 1\n"
            "    return 2\n",
        )
        self.add_file(
            "tests/test_app.py",
            PYTHON_TEST_HEADER
            + "from app import value\n\nclass Sample(unittest.TestCase):\n"
            "    def test_a(self):\n        self.assertEqual(value(1), 1)\n\n"
            "    def test_b(self):\n        self.assertEqual(value(0), 2)\n\n"
            "    def test_c(self):\n        self.assertEqual(value(2), 1)\n\n"
            "    def test_d(self):\n        self.assertEqual(value(-1), 1)\n",
        )
        single = self.adapter_lines(1, "single")
        parallel = self.adapter_lines(2, "parallel")
        self.assertEqual(single[1], 4)
        self.assertEqual(parallel[1], 4)
        self.assertEqual(parallel[0], single[0])


class HelperTests(unittest.TestCase):
    def test_discover_option_reads_both_spellings(self) -> None:
        run = ("python", "-m", "unittest", "discover", "-s", "tests")
        self.assertEqual(
            python_tests._discover_option(
                run, ("-s", "--start-directory"), "."
            ),
            "tests",
        )
        self.assertEqual(
            python_tests._discover_option(
                ("x", "--start-directory=src"),
                ("-s", "--start-directory"),
                ".",
            ),
            "src",
        )
        self.assertEqual(
            python_tests._discover_option(run, ("-t", "--top"), "."),
            ".",
        )

    def test_ids_are_dealt_round_robin_in_id_order(self) -> None:
        self.assertEqual(
            python_tests._deal_ids(["c", "a", "b", "d"], 2),
            [["a", "c"], ["b", "d"]],
        )

    def test_each_discovered_id_must_run_exactly_once(self) -> None:
        self.assertIsNone(
            python_tests._one_run_each(["a", "b"], ["b", "a"])
        )
        repeated = python_tests._one_run_each(
            ["a", "a", "b"], ["a", "a", "b"]
        )
        self.assertIn("a", repeated or "")
        self.assertIn("exactly once", repeated or "")
        missing = python_tests._one_run_each(["a"], [])
        self.assertIn("ran 0 times", missing or "")

    def test_parse_reads_workers_and_rejects_other_runs(self) -> None:
        parsed = python_tests._parse_python_tests(
            {
                "run": [
                    "{python}", "-m", "unittest", "discover", "-s", "tests",
                ],
                "tests_pattern": r"^Ran (\d+) tests? in",
                "workers": 3,
            },
            Path("quality-gate.toml"),
            "checks.tests",
        )
        self.assertEqual(parsed.workers, 3)
        with self.assertRaisesRegex(
            policy.ConfigError, r"checks.tests.workers"
        ):
            python_tests._parse_python_tests(
                {
                    "run": ["{python}", "-m", "unittest", "tests"],
                    "tests_pattern": r"^Ran (\d+) tests? in",
                    "workers": 2,
                },
                Path("quality-gate.toml"),
                "checks.tests",
            )

    def test_parse_missing_run_names_the_check_key(self) -> None:
        with self.assertRaisesRegex(
            policy.ConfigError, r"checks\.tests\.run"
        ):
            python_tests._parse_python_tests(
                {"tests_pattern": r"^Ran (\d+) tests? in"},
                Path("quality-gate.toml"),
                "checks.tests",
            )

    def test_run_python_tests_dispatches_parallel_workers(self) -> None:
        with mock.patch.object(
            python_tests, "_run_parallel_python_tests",
            return_value="parallel",
        ) as parallel, mock.patch.object(
            python_tests, "_run_single_python_tests",
            return_value="single",
        ) as single:
            self.assertEqual(
                python_tests._run_python_tests(
                    SimpleNamespace(check=check(2))
                ),
                "parallel",
            )
            self.assertEqual(
                python_tests._run_python_tests(
                    SimpleNamespace(check=check(1))
                ),
                "single",
            )
        parallel.assert_called_once()
        single.assert_called_once()

    def test_run_python_tests_return_setup_failures(self) -> None:
        found = check()
        context = SimpleNamespace(
            root=Path("."), check=found, prefix="check: tests",
            evidence_dir=Path("."),
        )
        failure = mock.Mock(spec=checks.CheckResult)
        with mock.patch.object(
            python_tests, "_tests_setup", return_value=failure
        ):
            self.assertIs(
                python_tests._run_python_tests(context), failure
            )
            self.assertIs(
                python_tests._run_single_python_tests(context), failure
            )

    def test_run_parallel_python_tests_finishes_the_outcome(self) -> None:
        found = check(2)
        context = SimpleNamespace(
            root=Path("."), check=found, prefix="check: tests",
            evidence_dir=Path("."),
        )
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                python_tests, "_tests_setup",
                return_value=(Path(directory), ["python"]),
            ), mock.patch.object(
                python_tests, "_parallel_outcome",
                return_value=("result", "combined"),
            ), mock.patch.object(
                python_tests, "_test_environment", return_value={}
            ), mock.patch.object(
                checks, "_temporary_test_directory",
                return_value=Path(directory),
            ), mock.patch.object(
                checks, "_finish_temporary", return_value=[]
            ), mock.patch.object(
                checks, "_temporary_reason", return_value=None
            ), mock.patch.object(
                checks, "_finish_test_result", return_value="finished"
            ) as finish:
                self.assertEqual(
                    python_tests._run_parallel_python_tests(
                        context, found.spec
                    ),
                    "finished",
                )
        finish.assert_called_once_with(
            "result", None, "check: tests", "combined"
        )

    def test_valid_ids_needs_a_string_list(self) -> None:
        self.assertTrue(python_tests._valid_ids(["a"]))
        self.assertFalse(python_tests._valid_ids([1]))
        self.assertFalse(python_tests._valid_ids("a"))

    def test_read_discovered_reports_bad_documents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ids.json"
            path.write_text('["a"]', encoding="utf-8")
            self.assertEqual(
                python_tests._read_discovered(path), (["a"], None)
            )
            path.write_text("[1]", encoding="utf-8")
            ids, error = python_tests._read_discovered(path)
        self.assertIsNone(ids)
        self.assertIn("list of strings", error or "")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ids.json"
            path.write_text("not json", encoding="utf-8")
            ids, error = python_tests._read_discovered(path)
        self.assertIsNone(ids)
        self.assertIn("cannot read", error or "")

    def test_failure_end_and_condition_line(self) -> None:
        text = "FAIL: a (m.C.a)\n---\nAssertionError: bad\n\nRan 1 test\n"
        matches = list(python_tests._WORKER_FAILURE.finditer(text))
        self.assertEqual(
            python_tests._failure_end(text, matches, 0),
            text.find("\nRan "),
        )
        two = (
            "FAIL: a (m.C.a)\n---\nAssertionError: first\n\n"
            "FAIL: b (m.C.b)\n---\nAssertionError: second\n\nRan 2 tests\n"
        )
        matches = list(python_tests._WORKER_FAILURE.finditer(two))
        self.assertEqual(
            python_tests._failure_end(two, matches, 0),
            matches[1].start(),
        )
        self.assertEqual(
            python_tests._condition_line("---\nAssertionError: bad\n==="),
            "AssertionError: bad",
        )
        self.assertEqual(python_tests._condition_line("---\n==="), "no condition")

    def test_failure_reason_and_nonzero_worker(self) -> None:
        self.assertEqual(
            python_tests._failure_reason(
                2, [("a", "bad"), ("b", "worse")]
            ),
            "2 tests ran; a: bad; b: worse",
        )
        manifest = [{"index": 0}, {"index": 1}]
        self.assertIsNone(
            python_tests._nonzero_worker(manifest, {"0": 0, "1": 0})
        )
        self.assertEqual(
            python_tests._nonzero_worker(manifest, {"0": 0, "1": 3}),
            {"index": 1},
        )

    def test_coordinator_failure_reads_its_run(self) -> None:
        found = check(2)
        context = SimpleNamespace(check=found, prefix="check: tests")
        failed = python_tests.RunResult(
            argv=(), execution="error", returncode=None, error="boom"
        )
        result = python_tests._coordinator_failure(
            context, found.spec, 0.0, failed
        )
        self.assertEqual(result.outcome, "error")
        self.assertIn("boom", result.reason)
        nonzero = python_tests.RunResult(
            argv=(), execution="completed", returncode=2
        )
        result = python_tests._coordinator_failure(
            context, found.spec, 0.0, nonzero
        )
        self.assertIn("exited 2", result.reason)
        finished = python_tests.RunResult(
            argv=(), execution="completed", returncode=0
        )
        self.assertIsNone(
            python_tests._coordinator_failure(
                context, found.spec, 0.0, finished
            )
        )

    def run_batch(
        self, directory: Path, result: object, read: object
    ) -> tuple:
        found = check(2)
        context = SimpleNamespace(
            root=Path("."), check=found, prefix="check: tests"
        )
        with mock.patch.object(
            python_tests, "run", return_value=result
        ), mock.patch.object(
            python_tests, "_read_worker_results", return_value=read
        ):
            return python_tests._run_worker_batch(
                context, found.spec, ["a", "b"], ["python"],
                directory, {}, time.monotonic() + 60, time.monotonic(),
            )

    def test_run_worker_batch_uses_the_start_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = python_tests.RunResult(
                argv=(), execution="completed", returncode=0
            )
            self.run_batch(Path(directory), result, ({}, {}, None))
            source = (Path(directory) / "worker_0.py").read_text(
                encoding="utf-8"
            )
        self.assertIn("os.path.abspath('tests')", source)

    def test_run_worker_batch_reports_a_read_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = python_tests.RunResult(
                argv=(), execution="completed", returncode=0
            )
            failure, results, texts, _combined, _manifest = self.run_batch(
                Path(directory), result, (None, {}, "broken")
            )
        self.assertIn("broken", failure.reason or "")
        self.assertIsNone(results)
        self.assertEqual(texts, {})

    def test_run_worker_batch_reports_a_start_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = python_tests.RunResult(
                argv=(), execution="error", returncode=None, error="boom"
            )
            failure, results, texts, combined, manifest = self.run_batch(
                Path(directory), result, ({}, {}, None)
            )
        self.assertIsNotNone(failure)
        self.assertEqual(failure.outcome, "error")
        self.assertIsNone(results)
        self.assertEqual(texts, {})
        self.assertEqual(combined, "")
        self.assertIn("boom", failure.reason or "")
        self.assertTrue(manifest)

    def test_skipped_and_worker_counts(self) -> None:
        found = spec()
        self.assertEqual(
            python_tests._skipped_count(found, "skipped=2"), (2, None)
        )
        self.assertEqual(
            python_tests._skipped_count(
                replace(found, skipped_pattern=None, skipped_pattern_re=None),
                "anything",
            ),
            (0, None),
        )
        _skipped, problem = python_tests._skipped_count(
            found, "skipped=1\nskipped=2"
        )
        self.assertIn("ambiguous", problem or "")
        self.assertEqual(
            python_tests._worker_count(found, "Ran 3 tests in 0.1s\nskipped=1"),
            (3, 1, None),
        )
        self.assertEqual(
            python_tests._worker_count(found, "no summary")[2],
            "without a test summary",
        )

    def test_parallel_totals_sums_the_workers(self) -> None:
        found = spec(2)
        text = "test_a (m.C.test_a) ... ok\nRan 2 tests in 0.1s\n"
        ran, skipped, executed, failures, problems, combined = (
            python_tests._parallel_totals(
                found,
                [{"index": 0, "ids": ["m.C.test_a"]}],
                {"0": 0},
                {"0": text},
            )
        )
        self.assertEqual((ran, skipped), (2, 0))
        self.assertEqual(executed, ["m.C.test_a"])
        self.assertEqual(failures, [])
        self.assertEqual(problems, [])
        self.assertEqual(combined, text)

    def test_read_worker_results_reads_codes_and_texts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            results = path / "results.json"
            results.write_text('{"0": 0}', encoding="utf-8")
            (path / "out").write_text("out", encoding="utf-8")
            (path / "err").write_text("err", encoding="utf-8")
            codes, texts, error = python_tests._read_worker_results(
                results,
                [{
                    "index": 0,
                    "stdout": str(path / "out"),
                    "stderr": str(path / "err"),
                }],
            )
            self.assertEqual(codes, {"0": 0})
            self.assertEqual(texts, {"0": "outerr"})
            self.assertIsNone(error)
            results.write_text("not json", encoding="utf-8")
            _codes, _texts, error = python_tests._read_worker_results(
                results, []
            )
        self.assertIn("cannot read", error or "")

    def test_discovered_ids_reads_the_helper_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            (root / "tests/test_one.py").write_text(
                "import unittest\n"
                "class One(unittest.TestCase):\n"
                "    def test_one(self):\n"
                "        self.assertTrue(True)\n",
                encoding="utf-8",
            )
            work = root / "work"
            work.mkdir()
            ids, error = python_tests._discovered_ids(
                root,
                (
                    "{python}", "-m", "unittest", "discover", "-s", "tests",
                ),
                os.environ.copy(),
                time.monotonic() + 30,
                work,
            )
        self.assertIsNone(error)
        self.assertEqual(ids, ["test_one.One.test_one"])

    def test_worker_source_names_the_path_and_ids(self) -> None:
        source = python_tests._worker_source(
            "tests", ["test_one.One.test_one"]
        )
        self.assertIn("os.path.abspath('tests')", source)
        self.assertIn("['test_one.One.test_one']", source)
        compile(source, "worker.py", "exec")

    def test_worker_manifest_writes_each_nonempty_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            manifest = python_tests._worker_manifest(
                ["python"], path, "tests", [["a"], [], ["b"]]
            )
            self.assertEqual([item["index"] for item in manifest], [0, 2])
            self.assertEqual(
                manifest[0]["ids"], ["a"]
            )
            self.assertTrue((path / "worker_0.py").is_file())
            self.assertIn("worker_0.py", manifest[0]["command"])
            self.assertNotIn("a", manifest[0]["command"])

    def test_executed_ids_reads_verbose_results(self) -> None:
        text = (
            "test_a (m.C.test_a) ... ok\n"
            "test_b (m.C.test_b) ... FAIL\n"
            "FAIL: test_b (m.C.test_b)\n"
        )
        self.assertEqual(
            python_tests._executed_ids(text), ["m.C.test_a", "m.C.test_b"]
        )

    def test_worker_failures_reads_the_condition(self) -> None:
        text = (
            "test_a (m.C.test_a) ... FAIL\n\n"
            "======================================================================\n"
            "FAIL: test_a (m.C.test_a)\n"
            "----------------------------------------------------------------------\n"
            "Traceback (most recent call last):\n"
            "AssertionError: bad\n\n"
            "----------------------------------------------------------------------\n"
            "Ran 1 test in 0.1s\n"
        )
        self.assertEqual(
            python_tests._worker_failures(text),
            [("m.C.test_a", "AssertionError: bad")],
        )

    def test_parallel_texts_reads_both_streams(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "out").write_text("out", encoding="utf-8")
            (path / "err").write_text("err", encoding="utf-8")
            texts, error = python_tests._parallel_texts([{
                "index": 0,
                "stdout": str(path / "out"),
                "stderr": str(path / "err"),
            }])
        self.assertIsNone(error)
        self.assertEqual(texts, {"0": "outerr"})

    def test_parallel_summary_reports_a_failure(self) -> None:
        found = check(2)
        context = SimpleNamespace(check=found, prefix="check: tests")
        text = (
            "test_a (m.C.test_a) ... FAIL\n\n"
            "======================================================================\n"
            "FAIL: test_a (m.C.test_a)\n"
            "----------------------------------------------------------------------\n"
            "AssertionError: bad\n\n"
            "----------------------------------------------------------------------\n"
            "Ran 1 test in 0.1s\n"
        )
        result, _combined = python_tests._parallel_summary(
            context, found.spec, ["m.C.test_a"],
            [{"index": 0, "ids": ["m.C.test_a"]}],
            {"0": 1}, {"0": text}, time.monotonic(),
        )
        self.assertEqual(result.outcome, "fail")
        self.assertIn("AssertionError: bad", result.reason)

    def test_parallel_summary_keeps_a_clean_worker(self) -> None:
        found = check(1)
        context = SimpleNamespace(
            check=found, prefix="check: tests",
            evidence_dir=Path("."), root=Path("."),
        )
        with mock.patch.object(
            python_tests, "_tests_evidence", return_value="pass"
        ):
            result, _combined = python_tests._parallel_summary(
                context, found.spec, ["m.C.test_a"],
                [{"index": 0, "ids": ["m.C.test_a"]}],
                {"0": 0},
                {"0": "test_a (m.C.test_a) ... ok\nRan 1 test in 0.1s\n"},
                time.monotonic(),
            )
        self.assertEqual(result, "pass")

    def test_parallel_outcome_reports_no_discovered_test(self) -> None:
        found = check(2)
        with tempfile.TemporaryDirectory() as directory:
            context = SimpleNamespace(
                check=found, prefix="check: tests",
                evidence_dir=Path(directory), root=Path("."),
            )
            with mock.patch.object(
                python_tests, "_discovered_ids", return_value=([], None)
            ):
                result, combined = python_tests._parallel_outcome(
                    context, found.spec, ["python"], Path(directory) / "data",
                    {}, time.monotonic(),
                )
        self.assertEqual(result.outcome, "fail")
        self.assertIn("no test discovered", result.reason)
        self.assertEqual(combined, "")


if __name__ == "__main__":
    unittest.main()
