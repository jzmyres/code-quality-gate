"""Differential tests for the shared unittest runner."""
from __future__ import annotations

import contextlib
import importlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from support import GATE

sys.path.insert(0, str(GATE))
shards = importlib.import_module("quality_gate.test_shards")
python_tests = importlib.import_module("quality_gate.python_tests")
coverage_tool = importlib.import_module("quality_gate.coverage_tool")
runner = importlib.import_module("quality_gate.runner")

FIXTURE = Path(__file__).parent / "fixtures" / "shards" / "project.toml"
SCRIPT = GATE / "quality_gate" / "test_shards.py"
EXPECTED = {
    "unittest.loader._FailedTest.test_broken": "error",
    "test_output.OutputCase.test_failure": "failure",
    "test_output.OutputCase.test_noisy": "passed",
    "test_parameters.FixtureCase.test_module_state": "passed",
    **{f"test_parameters.ParameterCase.test_square.{n}": "passed" for n in (2, 3, 4)},
    "test_skips.SkipCase.test_skip": "skipped",
    "test_skips.SkipCase.test_runtime_skip": "skipped",
}


class ShardsTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        temporary = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.root = temporary / "fixture"
        tests = self.root / "tests"
        tests.mkdir(parents=True)
        modules = tomllib.loads(FIXTURE.read_text(encoding="utf-8"))
        for filename, source in modules.items():
            (tests / filename).write_text(source, encoding="utf-8")
        self.script = self.root / "code-quality-gate" / "quality_gate" / SCRIPT.name
        self.script.parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT, self.script)
        self.temporary = temporary

    def _covered_run(self, name, command, invocations):
        data_dir = self.temporary / name
        prefix = python_tests.coverage_prefix(self.root, data_dir)
        result = subprocess.run(
            [*prefix, *command], cwd=self.root,
            env=python_tests._test_environment(prefix), capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(len(coverage_tool.registered_datasets(data_dir)), invocations)
        combined = data_dir / "combined" / ".coverage"
        coverage_tool.combine_coverage(data_dir, combined, coverage_tool.coverage_config_text(self.root))
        data = coverage_tool.import_coverage().CoverageData(str(combined))
        data.read()
        lines = {
            Path(path).name: sorted(data.lines(path))
            for path in data.measured_files() if Path(path).parent == self.root / "tests"
        }
        return result, lines

    def _adapter_counts(self, result):
        spec = python_tests._parse_python_tests(
            {
                "run": ["{python}", str(self.script), "-s", "tests"],
                "tests_pattern": r"^Ran (\d+) tests? in",
                "skipped_pattern": r"skipped=(\d+)",
            },
            self.root / "quality-gate.toml", "checks.tests",
        )
        start = time.monotonic()
        ran, skipped, error, failure = python_tests._tests_summary(
            None, spec, start, "tests", result.stdout + result.stderr, runner.Diagnostics(), start + 10,
        )
        self.assertIsNone(error)
        self.assertIsNone(failure)
        return ran, skipped

    def test_shards_coverage_and_adapter_counts_equal_serial(self):
        serial, expected_lines = self._covered_run(
            "serial", ["-m", "unittest", "discover", "-s", "tests"], 1,
        )
        self.assertEqual(serial.returncode, 1, serial.stderr)
        self.assertEqual(set(expected_lines), {"test_broken.py", "test_output.py", "test_parameters.py",
                                               "test_skips.py"})
        for workers in (1, 2, 4):
            with self.subTest(workers=workers):
                result, lines = self._covered_run(
                    f"workers-{workers}", [str(self.script), "-s", "tests", "-j", str(workers)],
                    1 if workers == 1 else workers + 1,
                )
                report = result.stdout + result.stderr
                self.assertEqual(result.returncode, serial.returncode, report)
                self.assertEqual(lines, expected_lines)
                self.assertEqual(self._adapter_counts(result), (9, 2))
                self.assertIn("FAILED (failures=1, errors=1, skipped=2)", report)
                self.assertIn("ERROR: unittest.loader._FailedTest.test_broken", report)
                self.assertIn("ImportError: Failed to import test module: test_broken", report)
                self.assertIn("FAIL: test_output.OutputCase.test_failure", report)
                self.assertIn("AssertionError:", report)
                self.assertNotIn("999", report)

    def test_shards_outcomes_are_equal_per_id(self):
        self.enterContext(mock.patch.dict(sys.modules))
        self.enterContext(mock.patch.object(sys, "path", sys.path.copy()))
        environment = self.enterContext(mock.patch.dict(os.environ))
        environment.pop("QG_PYTHON", None)
        start = self.root / "tests"
        suite = unittest.TestLoader().discover(str(start))
        with open(os.devnull, "w", encoding="utf-8") as output, shards._quiet(output):
            serial = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        self.assertEqual(serial.testsRun, len(EXPECTED))
        self.assertEqual({test.id() for test, _ in serial.failures},
                         {key for key, value in EXPECTED.items() if value == "failure"})
        self.assertEqual({test.id() for test, _ in serial.errors},
                         {key for key, value in EXPECTED.items() if value == "error"})
        self.assertEqual({test.id() for test, _ in serial.skipped},
                         {key for key, value in EXPECTED.items() if value == "skipped"})
        for workers in (1, 2, 4):
            with (
                self.subTest(workers=workers),
                mock.patch.object(shards, "_summary", return_value=1) as summary,
            ):
                self.assertEqual(shards.main(["-s", str(start), "-j", str(workers)]), 1)
                ids, reports, _ = summary.call_args.args
                self.assertEqual(set(ids), set(EXPECTED))
                records = {
                    test_id: outcome
                    for report in reports for test_id, outcome, _ in report["records"]
                }
                self.assertEqual(records, EXPECTED)

    def test_shards_discovery_difference_names_position_and_ids(self):
        with self.assertRaisesRegex(shards.ShardError, r"worker 2.*position 2.*'case.b'.*'case.c'"):
            shards.validate_reports(
                ["case.a", "case.b"],
                [{"ids": ["case.a", "case.b"]}, {"ids": ["case.a", "case.c"]}],
            )
        self.assertIn("<end of discovery>", shards._discovery_difference(["case.a"], [], 1))

    def test_shards_main_refuses_a_mismatched_or_incomplete_report(self):
        tests = [unittest.FunctionTestCase(lambda: None)]
        expected = tests[0].id()
        for actual, diagnostic in ((["wrong.id"], "position 1"), ([expected], "missing")):
            with (
                self.subTest(actual=actual),
                mock.patch.object(shards, "_discover", return_value=tests),
                mock.patch.object(shards, "_parallel", return_value=[{"ids": actual, "records": []}]),
                contextlib.redirect_stderr(io.StringIO()) as error,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(shards.main(["-s", "tests", "-j", "2"]), 1)
                self.assertIn(diagnostic, error.getvalue())
                self.assertIn(expected, error.getvalue())
                self.assertEqual(output.getvalue(), "")

    def test_shards_missing_duplicate_and_unexpected_records_name_ids(self):
        ids = ["case.a", "case.b"]
        records = [[test_id, "passed", []] for test_id in ("case.a", "case.a", "case.c")]
        diagnostic = r"missing.*case.b.*unexpected.*case.c.*duplicated.*case.a"
        with self.assertRaisesRegex(shards.ShardError, diagnostic):
            shards.validate_reports(ids, [{"ids": ids, "records": records}])

    def test_shards_assign_shares_keeps_modules_and_classes_together(self):
        self.enterContext(mock.patch.dict(sys.modules))
        self.enterContext(mock.patch.object(sys, "path", sys.path.copy()))
        tests = shards._discover(str(self.root / "tests"), "test*.py")
        for workers in (2, 4):
            first = shards.assign_shares(tests, workers)
            second = shards.assign_shares(shards._discover(str(self.root / "tests"), "test*.py"), workers)
            self.assertEqual(first, second)
            self.assertEqual(sorted(pos for share in first for pos in share), list(range(len(tests))))
            for share in first:
                parameters = [pos for pos in share if type(tests[pos]).__module__ == "test_parameters"]
                self.assertIn(len(parameters), (0, 4))

    def test_shards_fixture_setup_and_subtest_outcomes(self):
        class Blocked(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                raise unittest.SkipTest("fixture skip")

            def runTest(self):
                self.fail("fixture setup skipped")

        class Subtests(unittest.TestCase):
            def runTest(self):
                with self.subTest(value=1):
                    self.fail("one")
                with self.subTest(value=2):
                    self.fail("two")

        tests = [Blocked(), Subtests()]
        ids = [test.id() for test in tests]
        report = shards._execute(tests, ids)
        shards.validate_reports(ids, [report])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = shards._summary(ids, [report], 0)
        self.assertEqual(status, 1)
        self.assertIn("Ran 1 test in 0.000s", output.getvalue())
        self.assertIn("FAILED (failures=2, skipped=1)", output.getvalue())

    def test_shards_success_and_refusals(self):
        self.enterContext(mock.patch.dict(sys.modules))
        self.enterContext(mock.patch.object(sys, "path", sys.path.copy()))
        with mock.patch.object(shards.os, "cpu_count", return_value=8):
            self.assertEqual(shards._options(["-s", "tests"]).workers, 8)
        argv = ["-s", str(self.root / "tests"), "-p", "test_skips.py", "-j", "1"]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(shards.main(argv), 0)
        self.assertIn("OK (skipped=2)", output.getvalue())
        with contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(shards.main(["-s", str(self.root / "missing")]), 1)
            with self.assertRaises(SystemExit) as raised:
                shards._options(["-s", "tests", "-j", "0"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn(f"discovery start {str(self.root / 'missing')!r}: expected", error.getvalue())
        self.assertIn("--workers: expected an integer >= 1, got 0", error.getvalue())

    def test_shards_worker_prefix_rejects_invalid_input(self):
        for value in ("none", "[]", '["python", 1]'):
            with mock.patch.dict(os.environ, {"QG_PYTHON": value}):
                with self.assertRaisesRegex(shards.ShardError, "QG_PYTHON: expected.*got"):
                    shards._worker_prefix()

    def test_shards_worker_reports_launch_exit_and_read_failures(self):
        log = self.temporary / "worker.log"
        path = self.temporary / "worker.json"
        with self.assertRaisesRegex(shards.ShardError, "absent-interpreter.*expected to start"):
            shards._spawn_worker(["absent-interpreter"], subprocess.DEVNULL, log)
        process = mock.Mock()
        process.wait.return_value = 7
        log.write_text("worker diagnostic", encoding="utf-8")
        with self.assertRaisesRegex(shards.ShardError, r"worker.json.*expected exit status 0, got 7"):
            shards._read_worker(process, path, log)
        process.wait.return_value = 0
        with self.assertRaisesRegex(shards.ShardError, r"expected a readable JSON report.*worker.json"):
            shards._read_worker(process, path, log)
        process.poll.return_value = None
        shards._stop_worker(process)
        process.kill.assert_called_once()
