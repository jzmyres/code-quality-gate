"""Differential tests for the shared unittest runner."""
from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
import re
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
        self.parent_cpu_max = self.cpu_max.parent.parent / "cpu.max"
        self.enterContext(mock.patch.object(shards, "CGROUP_ROOT", self.cgroup_root, create=True))
        self.enterContext(mock.patch.object(shards, "CGROUP_MEMBERSHIP", self.cgroup_membership, create=True))
        self.enterContext(mock.patch.object(shards.os, "cpu_count", return_value=16))
        self.enterContext(mock.patch.object(shards.os, "sched_getaffinity", return_value=set(range(12))))

    def _workers(self, *args):
        return shards._options(["-s", "tests", *args]).workers

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

    def test_default_workers_inherit_parent_quota_without_child_quota(self):
        self.parent_cpu_max.write_text("300000 100000\n", encoding="utf-8")
        self.assertEqual(self._workers(), 3)

    def test_default_workers_use_tighter_of_parent_and_child_quotas(self):
        for parent, child in ((600000, 200000), (200000, 600000)):
            with self.subTest(parent=parent, child=child):
                self.parent_cpu_max.write_text(f"{parent} 100000\n", encoding="utf-8")
                self.cpu_max.write_text(f"{child} 100000\n", encoding="utf-8")
                self.assertEqual(self._workers(), 2)

    def test_default_workers_walk_to_cgroup_root(self):
        (self.cgroup_root / "cpu.max").write_text("100000 100000\n", encoding="utf-8")
        self.parent_cpu_max.write_text("max 100000\n", encoding="utf-8")
        self.cpu_max.write_text("200000 100000\n", encoding="utf-8")
        self.assertEqual(self._workers(), 1)

    def test_default_workers_reject_missing_cgroup_directory(self):
        self.cgroup_membership.write_text("0::/user.slice/missing.scope\n", encoding="utf-8")
        with self.assertRaises(shards.ShardError) as raised:
            self._workers()
        self.assertIn(str(self.cgroup_root / "user.slice/missing.scope"), str(raised.exception))

    def test_default_workers_reject_invalid_ancestor_cpu_max(self):
        self.cpu_max.write_text("100000 100000\n", encoding="utf-8")
        content = b"invalid\n"
        self.parent_cpu_max.write_bytes(content)
        with self.assertRaises(shards.ShardError) as raised:
            self._workers()
        self.assertIn(str(self.parent_cpu_max), str(raised.exception))
        self.assertIn(repr(content), str(raised.exception))

    def test_default_workers_reject_unreadable_ancestor_cpu_max(self):
        self.parent_cpu_max.mkdir()
        with self.assertRaises(shards.ShardError) as raised:
            self._workers()
        self.assertIn(str(self.parent_cpu_max), str(raised.exception))
        self.assertIn("content unavailable", str(raised.exception))

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
        ids = []
        start_test = unittest.TextTestResult.startTest

        def record_start(result, test):
            ids.append(test.id())
            start_test(result, test)

        with (
            open(os.devnull, "w", encoding="utf-8") as output,
            shards._quiet(output),
            mock.patch.object(unittest.TextTestResult, "startTest", record_start),
        ):
            serial = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        self.assertCountEqual(ids, list(EXPECTED))
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
                self.assertEqual(reports[0]["ids"], ids)
                records = [row[:3] for report in reports for row in report["records"]]
                self.assertEqual(sorted(records), [
                    [position, name, EXPECTED[name]] for position, name in enumerate(ids)
                ])

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
        records = [[position, "case.a", "passed", [], 0.0, None] for position in (0, 0, 2)]
        diagnostic = r"missing position 2.*case.b.*unexpected position 3.*duplicated position 1.*case.a"
        with self.assertRaisesRegex(shards.ShardError, diagnostic):
            shards.validate_reports(ids, [{"ids": ids, "records": records}])

    def test_shards_reject_starts_inconsistent_with_terminal_records(self):
        case = unittest.FunctionTestCase(lambda: None)
        ids = [case.id()]
        report = shards._execute([case], ids)
        for starts, defect in (([], "disagree with measured"), ([0, 0], "unexpected outstanding")):
            with self.subTest(starts=starts):
                with self.assertRaisesRegex(shards.ShardError, f"{defect}.*{re.escape(ids[0])}"):
                    shards._validate_records(ids, range(1), report["records"], [], started=starts)

    def test_affected_runner_records_discovery_failure_with_real_id(self):
        loader = shards.AffectedLoader()
        failed = unittest.loader._FailedTest("missing", ImportError("missing fixture"))
        regular = unittest.FunctionTestCase(lambda: None)
        loader.sourced_cases.add(id(regular))
        ids = [regular.id(), failed.id()]
        journal = io.StringIO()
        loader.errors.append("missing fixture")
        with contextlib.redirect_stdout(io.StringIO()):
            tests, recorded_ids, positions = shards._affected_schedule(
                [regular, failed], ids, loader, None, journal,
            )
            self.assertEqual(shards._affected_execution(tests, recorded_ids, positions, journal), 1)
        header, *events = [json.loads(line) for line in journal.getvalue().splitlines()]
        self.assertEqual(header["ids"], ids)
        self.assertEqual(header["discovery_failed"], [1])
        self.assertEqual(events[1][1][:3], [1, ids[1], "error"])

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

    def test_shards_store_null_fixture_durations_and_invoked_subtest_evidence(self):
        class Fixture(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                raise unittest.SkipTest("fixture prevents invocation")

            def runTest(self):
                self.fail("unreachable")

        class Mixed(unittest.TestCase):
            def runTest(self):
                with self.subTest(number=1):
                    pass
                with self.subTest(number=2):
                    self.skipTest("only this subtest")

        cases = [Fixture(), Mixed()]
        ids = [test.id() for test in cases]
        clock = mock.Mock(side_effect=(8.0, 8.375))
        with mock.patch.object(shards.time, "monotonic", clock):
            report = shards._execute(cases, ids)
        shards.validate_reports(ids, [report])
        self.assertEqual(clock.call_count, 2)
        fixture, invoked = report["records"]
        self.assertEqual(fixture[:5], [0, ids[0], "fixture skipped", [], None])
        self.assertEqual(invoked[:3], [1, ids[1], "passed"])
        self.assertEqual(invoked[4], 0.375)
        self.assertEqual([(name.removeprefix(ids[1]), outcome) for name, outcome, _ in invoked[3]], [
            (" (number=1)", "passed"), (" (number=2)", "skipped"),
        ])

    def test_result_report_includes_failures_and_fixture_events(self):
        (self.root / "tests" / "test_report.py").write_text(
            "import unittest\n"
            "class Blocked(unittest.TestCase):\n"
            "    @classmethod\n"
            "    def setUpClass(cls):\n"
            "        raise RuntimeError('fixture error')\n"
            "    def test_blocked(self):\n"
            "        self.fail('must not run')\n"
            "class Cases(unittest.TestCase):\n"
            "    def test_subtests(self):\n"
            "        with self.subTest(value=1):\n"
            "            self.fail('one')\n"
            "        with self.subTest(value=2):\n"
            "            self.fail('two')\n"
            "    @unittest.expectedFailure\n"
            "    def test_unexpected_success(self):\n"
            "        pass\n",
            encoding="utf-8",
        )
        path = self.temporary / "suite report.json"
        for workers in (1, 2):
            with self.subTest(workers=workers):
                result = self._run_fixture("test*.py", workers, "--result-report", str(path))
                self.assertEqual(result.returncode, 1, result.stderr)
                report = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(shards.failed_subjects(report["records"], report["fixtures"]), [
                    "setUpClass (test_report.Blocked)", "test_output.OutputCase.test_failure",
                    "test_report.Cases.test_subtests", "test_report.Cases.test_unexpected_success",
                    "unittest.loader._FailedTest.test_broken",
                ])
                self.assertEqual([row[1] for row in report["records"]], report["ids"])
                self.assertIn("failures=3, errors=2, skipped=2, unexpected successes=1", result.stdout)
                path.unlink()

    def _run_local_report_fixture(self, path):
        self.enterContext(mock.patch.dict(sys.modules))
        self.enterContext(mock.patch.object(sys, "path", sys.path.copy()))
        with (
            contextlib.redirect_stdout(io.StringIO()) as stdout,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            status = shards.main([
                "-s", str(self.root / "tests"), "-p", "test_skips.py", "-j", "1",
                "--result-report", str(path),
            ])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_result_report_includes_invoked_skips_on_pass(self):
        path = self.temporary / "passed.json"
        status, _, error = self._run_local_report_fixture(path)
        self.assertEqual(status, 0, error)
        report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual([row[2] for row in report["records"]], ["skipped", "skipped"])
        self.assertTrue(all(row[4] >= 0 for row in report["records"]))

    def test_result_report_write_error_names_path(self):
        path = self.temporary / "missing" / "failed.json"
        status, output, error = self._run_local_report_fixture(path)
        self.assertEqual(status, 1)
        self.assertIn(str(path), error)
        self.assertIn("cannot write", error)
        self.assertIn("OK (skipped=2)", output)

    def test_result_report_discovery_error_names_path(self):
        path = self.temporary / "failed.json"
        missing = self.root / "missing"
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(shards.main(["-s", str(missing), "-j", "1", "--result-report", str(path)]), 1)
        self.assertIn(
            f"discovery start {str(missing)!r}: expected an importable test directory", stderr.getvalue(),
        )
        self.assertIn(str(path), stderr.getvalue())
        self.assertFalse(path.exists())

    def test_no_result_report_option_leaves_output_and_status_unchanged(self):
        path = self.temporary / "failed.json"
        plain = self._run_fixture("test_output.py", 1)
        self.assertEqual(list(self.temporary.rglob("*.json")), [])
        reported = self._run_fixture("test_output.py", 1, "--result-report", str(path))
        self.assertEqual(reported.returncode, plain.returncode)
        self.assertEqual(reported.stderr, plain.stderr)
        self.assertEqual(
            re.sub(r" in \d+\.\d+s", "", reported.stdout),
            re.sub(r" in \d+\.\d+s", "", plain.stdout),
        )

    def test_shards_success_and_refusals(self):
        self.enterContext(mock.patch.dict(sys.modules))
        self.enterContext(mock.patch.object(sys, "path", sys.path.copy()))
        argv = ["-s", str(self.root / "tests"), "-p", "test_skips.py", "-j", "1"]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(shards.main(argv), 0)
        self.assertIn("OK (skipped=2)", output.getvalue())
        with contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(shards.main(["-s", str(self.root / "missing"), "-j", "1"]), 1)
            with self.assertRaises(SystemExit) as raised:
                shards._options(["-s", "tests", "-j", "0"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn(
            f"discovery start {str(self.root / 'missing')!r}: expected an importable test directory",
            error.getvalue(),
        )
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

    def test_corrupt_worker_journal_preserves_exit_and_names_report(self):
        log = self.temporary / "worker.log"
        path = self.temporary / "worker.json"
        log.write_text("worker diagnostic", encoding="utf-8")
        journal = path.with_suffix(".jsonl")
        process = mock.Mock()
        for status, frame in (
            (-15, '["terminal", []]\n'),
            (0, '[]\n'),
            (0, '["started", 0]'),
            (0, '["extra", 0]\n'),
        ):
            with self.subTest(status=status, frame=frame):
                process.wait.return_value = status
                journal.write_text(frame, encoding="utf-8")
                with self.assertRaises(shards.ShardError) as caught:
                    shards._read_worker(process, path, ["case.a"], [0])
                self.assertIn("worker.json", str(caught.exception))
                self.assertIn("invalid worker journal", str(caught.exception))
                if status:
                    self.assertIn(f"got {status}", str(caught.exception))

    def _run_fixture(self, pattern, workers=None, *report_args):
        argv = [sys.executable, "-I", "-B", "-X", "faulthandler"]
        if workers is None:
            argv.extend(["-m", "unittest", "discover"])
        else:
            argv.extend([str(self.script), "-j", str(workers)])
        environment = os.environ.copy()
        environment.pop("QG_PYTHON", None)
        return subprocess.run(
            [*argv, "-s", "tests", "-p", pattern, *report_args],
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
