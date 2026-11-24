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


class WorkerCountTests(unittest.TestCase):
    def setUp(self):
        self.cgroup_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.cgroup_membership = self.cgroup_root / "self-cgroup"
        self.cgroup_membership.write_text("0::/user.slice/gate.scope\n", encoding="utf-8")
        self.cpu_max = self.cgroup_root / "user.slice/gate.scope/cpu.max"
        self.cpu_max.parent.mkdir(parents=True)
        self.enterContext(mock.patch.object(shards.os, "sched_getaffinity", return_value=set(range(12))))

    def _workers(self, *args):
        return shards._options(
            ["-s", "tests", *args], cgroup_root=self.cgroup_root, cgroup_membership=self.cgroup_membership,
        ).workers

    def test_default_workers_respect_quota_and_affinity(self):
        for content, expected in (
            ("300000 100000", 3), ("150000 100000", 2), ("max 100000", 12),
            ("10000 100000", 1), ("1300000 100000", 12),
        ):
            with self.subTest(content=content):
                self.cpu_max.write_text(content + "\n", encoding="utf-8")
                self.assertEqual(self._workers(), expected)

    def test_default_workers_without_cgroup_v2(self):
        self.cgroup_membership.write_text("2:cpu:/user.slice/gate.scope\n", encoding="utf-8")
        self.cpu_max.write_text("300000 100000\n", encoding="utf-8")
        self.assertEqual(self._workers(), 12)

    def test_default_workers_without_cpu_max(self):
        self.assertEqual(self._workers(), 12)

    def test_default_workers_reject_invalid_cpu_max(self):
        for content in (b"invalid\n", b"300000 0\n", b"max nope\n", b"\xff 100000\n"):
            with self.subTest(content=content):
                self.cpu_max.write_bytes(content)
                with self.assertRaises(shards.ShardError) as raised:
                    self._workers()
                self.assertIn(str(self.cpu_max), str(raised.exception))
                self.assertIn(repr(content), str(raised.exception))

    def test_default_workers_reject_unreadable_cpu_max(self):
        self.cpu_max.write_text("300000 100000\n", encoding="utf-8")
        with mock.patch.object(Path, "read_bytes", side_effect=PermissionError("permission denied")):
            with self.assertRaises(shards.ShardError) as raised:
                self._workers()
        self.assertIn(str(self.cpu_max), str(raised.exception))
        self.assertIn("content unavailable", str(raised.exception))
        self.assertIn("permission denied", str(raised.exception))

    def test_explicit_workers_are_not_capped(self):
        self.cpu_max.write_text("300000 100000\n", encoding="utf-8")
        self.assertEqual(self._workers("-j", "8"), 8)


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
                reports, _ = summary.call_args.args
                ids = reports[0]["ids"]
                self.assertEqual(set(ids), set(EXPECTED))
                records = {
                    test_id: outcome
                    for report in reports for _, test_id, outcome, _ in report["records"]
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
        records = [[position, "case.a", "passed", []] for position in (0, 0, 2)]
        diagnostic = r"missing position 2.*case.b.*unexpected position 3.*duplicated position 1.*case.a"
        with self.assertRaisesRegex(shards.ShardError, diagnostic):
            shards.validate_reports(ids, [{"ids": ids, "records": records}])

    def test_shards_assign_shares_keeps_modules_and_classes_together(self):
        self.enterContext(mock.patch.dict(sys.modules))
        self.enterContext(mock.patch.object(sys, "path", sys.path.copy()))
        tests = shards._discover(str(self.root / "tests"), "test*.py")
        for workers in (2, 4):
            first = shards.assign_shares(tests, shards._test_ids(tests), workers)
            rediscovered = shards._discover(str(self.root / "tests"), "test*.py")
            second = shards.assign_shares(rediscovered, shards._test_ids(rediscovered), workers)
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
            status = shards._summary([report], 0)
        self.assertEqual(status, 1)
        self.assertIn("Ran 1 test in 0.000s", output.getvalue())
        self.assertIn("FAILED (failures=2, skipped=1)", output.getvalue())

    def test_shards_success_and_refusals(self):
        self.enterContext(mock.patch.dict(sys.modules))
        self.enterContext(mock.patch.object(sys, "path", sys.path.copy()))
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
            shards._spawn_worker(["absent-interpreter"], log)
        process = mock.Mock()
        process.wait.return_value = 7
        log.write_text("worker diagnostic", encoding="utf-8")
        with self.assertRaisesRegex(shards.ShardError, r"worker.json.*expected exit status 0, got 7"):
            shards._read_worker(process, path, ["case.a"], [0])
        process.wait.return_value = 0
        with self.assertRaisesRegex(shards.ShardError, r"expected a readable JSON report.*worker.json"):
            shards._read_worker(process, path, ["case.a"], [0])
        process.poll.return_value = None
        shards._stop_worker(process)
        process.kill.assert_called_once()

    def _run_fixture(self, pattern, workers=None):
        argv = [sys.executable, "-I", "-B", "-X", "faulthandler"]
        if workers is None:
            argv.extend(["-m", "unittest", "discover"])
        else:
            argv.extend([str(self.script), "-j", str(workers)])
        environment = os.environ.copy()
        environment.pop("QG_PYTHON", None)
        return subprocess.run(
            [*argv, "-s", "tests", "-p", pattern],
            cwd=self.root, env=environment, text=True, capture_output=True, timeout=15,
        )

    def test_shards_inherit_serial_warning_filters(self):
        self._assert_serial_success("review_warn.py", "Ran 1 test in")

    def test_shards_keep_all_instances_with_the_same_id(self):
        self._assert_serial_success("review_duplicate.py", "Ran 3 tests in")

    def _assert_serial_success(self, pattern, summary):
        for workers in (None, 1, 2):
            with self.subTest(workers=workers):
                result = self._run_fixture(pattern, workers)
                report = result.stdout + result.stderr
                self.assertEqual(result.returncode, 0, report)
                self.assertIn(summary, report)
                self.assertIn("OK", report)

    def test_shards_refuse_suites_with_custom_execution(self):
        suites = (("review_custom_run", "ResourceSuite"), ("review_custom_call", "CallableSuite"))
        for filename, name in suites:
            pattern = f"{filename}.py"
            serial = self._run_fixture(pattern)
            self.assertEqual(serial.returncode, 0, serial.stderr)
            for workers in (1, 2):
                with self.subTest(filename=filename, workers=workers):
                    result = self._run_fixture(pattern, workers)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn(f"suite {name} in module {filename}", result.stderr)
                    self.assertIn("expected standard unittest suite execution", result.stderr)
                    self.assertNotIn("Ran ", result.stdout)

    def test_shards_import_errors_do_not_merge_unrelated_shares(self):
        pattern = "review_group_*.py"
        serial, lines = self._covered_run("group-serial", ["-m", "unittest", "discover",
                                                         "-s", "tests", "-p", pattern], 1)
        parallel, parallel_lines = self._covered_run(
            "group-parallel", [str(self.script), "-s", "tests", "-p", pattern, "-j", "4"], 5,
        )
        self.assertEqual(lines, parallel_lines)
        for result in (serial, parallel):
            self.assertEqual(result.returncode, 1, result.stderr)
            report = result.stdout + result.stderr
            self.assertIn("Ran 4 tests in", report)
            self.assertIn("FAILED (errors=2)", report)

    def test_shards_crashes_report_outstanding_tests_and_tail(self):
        serial = self._run_fixture("review_crash.py")
        inline = self._run_fixture("review_crash.py", 1)
        self.assertLess(serial.returncode, 0, serial.stderr)
        self.assertEqual(inline.returncode, serial.returncode, inline.stderr)
        for result in (serial, inline):
            self.assertIn("Fatal Python error: Segmentation fault", result.stderr)
            self.assertIn("in test_b_crash", result.stderr)
        parallel = self._run_fixture("review_crash.py", 2)
        self.assertEqual(parallel.returncode, 1, parallel.stderr)
        self.assertIn(f"expected exit status 0, got {serial.returncode}", parallel.stderr)
        self.assertIn("position 2 ('review_crash.CrashCase.test_b_crash')", parallel.stderr)
        self.assertIn("position 3 ('review_crash.CrashCase.test_c_pending')", parallel.stderr)
        self.assertNotIn("test_a_completed", parallel.stderr)
        self.assertIn("fixture stdout 59", parallel.stderr)
        self.assertIn("fixture stderr before crash", parallel.stderr)
        self.assertIn("fixture Python stdout before crash", parallel.stderr)
        self.assertNotIn("fixture stdout 00", parallel.stderr)
        self.assertIn("Fatal Python error: Segmentation fault", parallel.stderr)

    def test_shards_missing_worker_record_includes_log(self):
        result = self._run_fixture("review_missing.py", 2)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("missing position 1 ('review_missing.MissingCase.test_unreported')", result.stderr)
        self.assertIn("fixture returned without reporting a test", result.stderr)

    def test_shards_empty_discovery_matches_serial(self):
        self.enterContext(mock.patch.object(sys, "path", sys.path.copy()))
        argv = ["-s", str(self.root / "tests"), "-p", "no_matches_*.py", "-j", "1"]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(shards.main(argv), 5)
        self.assertTrue(output.getvalue().rstrip().endswith("NO TESTS RAN"))
        for workers in (None, 1, 4):
            with self.subTest(workers=workers):
                result = self._run_fixture("no_matches_*.py", workers)
                report = result.stdout + result.stderr
                self.assertEqual(result.returncode, 5, report)
                self.assertIn("Ran 0 tests in", report)
                self.assertTrue(report.rstrip().endswith("NO TESTS RAN"), report)
