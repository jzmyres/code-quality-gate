"""Checks stop in-progress work when their shared deadline expires."""
from __future__ import annotations

import contextlib
import importlib
import io
import os
import re
import signal
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from support import GATE

sys.path.insert(0, str(GATE))
checks = importlib.import_module("quality_gate.checks")
policy = importlib.import_module("quality_gate.policy")
runner = importlib.import_module("quality_gate.runner")
ratchet = importlib.import_module("quality_gate.ratchet")
clones = importlib.import_module("quality_gate.clones")
python_crap = importlib.import_module("quality_gate.python_crap")
python_tests = importlib.import_module("quality_gate.python_tests")
coverage_tool = importlib.import_module("quality_gate.coverage_tool")
verification = importlib.import_module("quality_gate.verification")


class AnalysisDeadlineTests(unittest.TestCase):
    budget = 0.8

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.started = self.root / "started"
        self.finished = self.root / "finished"
        self.evidence = self.root / "coverage"
        self.config_file = self.root / "coverage.ini"
        self.evidence.touch()
        self.config_file.touch()
        self.config = SimpleNamespace(
            classes={
                "source": policy.ClassDef(
                    "source", True, "source", ("crap", "verification", "clones")
                )
            },
            max_bytes=1024,
        )

    def stall(self, *args: object, **kwargs: object) -> None:
        self.started.write_text(str(os.getpid()), encoding="utf-8")
        time.sleep(20)
        self.finished.touch()

    def adapter_spec(self, adapter: str) -> object:
        if adapter == "clones":
            return clones.CloneSpec(50)
        if adapter == "crap":
            return python_crap.PythonCrapSpec("tests")
        return verification.VerificationSpec("tests")

    def check_def(self, adapter: str) -> object:
        return policy.CheckDef(
            id=adapter, adapter="python_crap" if adapter == "crap" else adapter,
            tier=1, enforcement="enforced",
            metric_version="metric/1", evidence=(),
            spec=self.adapter_spec(adapter),
            threshold=6, baseline=self.root / "baseline",
        )

    def prior_tests(self) -> object:
        return checks.CheckResult(
            id="tests", kind="check", tier=1, enforcement="enforced",
            adapter="python_tests", evidence=("tests",), metric_version="test-count/1",
            outcome="pass", execution="completed", duration_seconds=0,
            budget_seconds=1, tests_ran=1, tests_skipped=0,
            evidence_path=self.evidence,
            adapter_data={"coverage_config": self.config_file, "coverage_settings": "canonical settings"},
        )

    def assert_timeout(self, result: object, step: str, elapsed: float) -> None:
        self.assertTrue(self.started.is_file(), f"{step} never started")
        self.assertFalse(self.finished.exists(), f"{step} finished after its deadline")
        self.assertEqual(result.execution, "budget")
        self.assertEqual(result.outcome, "fail")
        self.assertFalse(result.is_satisfied())
        self.assertIn(step, result.reason)
        self.assertIn("timeout", result.reason)
        self.assertIn(f"deadline: {self.budget:g} seconds", result.reason)
        self.assertIn("elapsed:", result.reason)
        self.assertLess(elapsed, self.budget * 4)
        worker = int(self.started.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(worker, 0)

    def assert_process_stopped(self, pid: int) -> None:
        status = Path(f"/proc/{pid}/stat")
        if status.exists():
            self.assertEqual(status.read_text(encoding="utf-8").rpartition(")")[2].split()[0], "Z")
        else:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def long_running_command(self, marker: Path) -> list[str]:
        program = (
            "import os, subprocess, sys, time\n"
            "from pathlib import Path\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])\n"
            "Path(sys.argv[1]).write_text(f'{os.getpid()} {child.pid}')\n"
            "time.sleep(20)\n"
        )
        return [sys.executable, "-c", program, str(marker)]

    def assert_marker_processes_stopped(self, marker: Path) -> None:
        self.assertTrue(marker.exists(), "the subprocess did not start before cancellation")
        for text in marker.read_text(encoding="utf-8").split():
            self.assert_process_stopped(int(text))

    def run_adapter(self, adapter: str) -> tuple[object, float]:
        start = time.monotonic()
        with mock.patch.object(checks, "RATCHET_BUDGET_SECONDS", self.budget):
            with contextlib.redirect_stderr(io.StringIO()):
                result = checks.run_check(
                    self.root, self.config, self.check_def(adapter),
                    ["source.py"], {"source.py": "source"}, prefix="check",
                    prior={"tests": self.prior_tests()},
                )
        return result, time.monotonic() - start

    def test_coverage_steps_are_stopped_while_running(self) -> None:
        pattern = r"^Ran (\d+) tests? in"
        spec = python_tests.PythonTestsSpec(
            (sys.executable, "-c", "print('Ran 1 test in 0.1s')"),
            pattern, re.compile(pattern), None, None, self.budget,
        )
        check = replace(
            self.check_def("verification"), id="tests", adapter="python_tests",
            spec=spec, evidence=("tests",), threshold=None,
        )
        for step in ("coverage configuration validation", "coverage combination"):
            with self.subTest(step=step):
                self.started.unlink(missing_ok=True)
                validation = self.stall if step == "coverage configuration validation" else None
                start = time.monotonic()
                with mock.patch.object(python_tests, "coverage_prefix", return_value=[]):
                    with mock.patch.object(
                        coverage_tool, "_coverage_config_problem", side_effect=validation, return_value=None
                    ):
                        with mock.patch.object(python_tests, "combine_coverage", side_effect=self.stall):
                            with contextlib.redirect_stderr(io.StringIO()):
                                result = checks.run_check(
                                    self.root, self.config, check, [], {}, prefix="check"
                                )
                self.assert_timeout(result, step, time.monotonic() - start)
                self.assertEqual(result.diagnostics.exit_code, 0)
                self.assertIn("Ran 1 test", result.diagnostics.output_tail)

    def test_crap_analysis_is_stopped_while_running(self) -> None:
        with mock.patch.object(python_crap, "measure_crap", side_effect=self.stall):
            result, elapsed = self.run_adapter("crap")
        self.assert_timeout(result, "CRAP analysis", elapsed)

    def test_verification_analysis_is_stopped_while_running(self) -> None:
        with mock.patch.object(verification, "measure_verification", side_effect=self.stall):
            result, elapsed = self.run_adapter("verification")
        self.assert_timeout(result, "verification analysis", elapsed)

    def test_cancelled_worker_stops_its_subprocess_and_group(self) -> None:
        command = self.long_running_command(self.started)
        def work() -> None:
            runner.run(command, budget_seconds=20)

        with runner.check_deadline(time.monotonic(), self.budget):
            with self.assertRaisesRegex(runner.StepTimeout, "analysis"):
                runner.analysis_step("analysis", work)
        self.assert_marker_processes_stopped(self.started)

    def test_cancelled_worker_stops_processes_in_threads_and_nested_workers(self) -> None:
        thread_marker = self.root / "thread-pids"
        nested_marker = self.root / "nested-pids"

        def launch(marker: Path) -> None:
            runner.run(self.long_running_command(marker), budget_seconds=20)

        def work() -> None:
            thread = threading.Thread(target=launch, args=(thread_marker,), daemon=True)
            thread.start()
            runner.analysis_step("nested analysis", launch, nested_marker)

        with runner.check_deadline(time.monotonic(), self.budget):
            with self.assertRaisesRegex(runner.StepTimeout, "analysis"):
                runner.analysis_step("analysis", work)
        self.assert_marker_processes_stopped(thread_marker)
        self.assert_marker_processes_stopped(nested_marker)

    def test_surviving_group_member_is_reported_with_pid_and_command(self) -> None:
        command = self.long_running_command(self.started)
        original_killpg = os.killpg

        def deny_child(pid: int, number: int) -> None:
            if self.started.exists() and pid == int(self.started.read_text().split()[0]):
                if number in (signal.SIGTERM, signal.SIGKILL):
                    raise PermissionError("signal denied")
            original_killpg(pid, number)

        def work() -> None:
            runner.run(command, budget_seconds=20)

        try:
            with mock.patch.object(runner.os, "killpg", side_effect=deny_child):
                with runner.check_deadline(time.monotonic(), self.budget):
                    with self.assertRaises(runner.WorkerError) as caught:
                        runner.analysis_step("analysis", work)
            reason = str(caught.exception)
            pid, child_pid = (int(value) for value in self.started.read_text(encoding="utf-8").split())
            self.assertIn(str(pid), reason)
            self.assertIn(str(child_pid), reason)
            self.assertIn(sys.executable, reason)
            self.assertIn("import time; time.sleep(20)", reason)
            self.assertIn("signal denied", reason)
            self.assertIn("still running", reason)
        finally:
            if self.started.exists():
                pid = int(self.started.read_text(encoding="utf-8").split()[0])
                with contextlib.suppress(ProcessLookupError):
                    original_killpg(pid, signal.SIGKILL)

    def test_cancellation_during_subprocess_launch_stops_the_process(self) -> None:
        register = runner._register_session
        for after_registration in (False, True):
            with self.subTest(after_registration=after_registration):
                self.started.unlink(missing_ok=True)

                def delayed(
                    command: tuple[str, ...], kind: str, token: str,
                    after: bool = after_registration,
                ) -> None:
                    if kind != "process":
                        register(command, kind, token)
                        return
                    if after:
                        register(command, kind, token)
                    self.started.write_text(str(os.getpid()), encoding="utf-8")
                    time.sleep(5)
                    if not after:
                        register(command, kind, token)

                def work() -> None:
                    runner.run([sys.executable, "-c", "import time; time.sleep(20)"],
                               budget_seconds=20)

                with mock.patch.object(runner, "_register_session", side_effect=delayed):
                    with runner.check_deadline(time.monotonic(), 0.5):
                        with self.assertRaisesRegex(runner.StepTimeout, "analysis"):
                            runner.analysis_step("analysis", work)
                self.assert_marker_processes_stopped(self.started)

    def test_successful_and_missing_commands_in_a_worker(self) -> None:
        def work() -> tuple[object, object]:
            completed = runner.run([sys.executable, "-c", "print('ok')"], budget_seconds=5)
            missing = runner.run([str(self.root / "missing-command")], budget_seconds=5)
            return completed, missing

        with runner.check_deadline(time.monotonic(), 5):
            completed, missing = runner.analysis_step("analysis", work)
        self.assertEqual(completed.stdout_text, "ok\n")
        self.assertEqual(completed.execution, "completed")
        self.assertEqual(missing.execution, "error")
        self.assertIn("missing-command", missing.error)

    def test_baseline_loading_is_stopped_while_running(self) -> None:
        findings = [ratchet.Finding("tests:tests:executed", 1, "test summary")]
        with mock.patch.object(verification, "measure_verification", return_value=findings):
            with mock.patch.object(checks, "_baseline_entries", side_effect=self.stall):
                result, elapsed = self.run_adapter("verification")
        self.assert_timeout(result, "baseline loading", elapsed)

    def test_ratchet_evaluation_is_stopped_while_running(self) -> None:
        findings = [ratchet.Finding("tests:tests:executed", 1, "test summary")]
        with mock.patch.object(verification, "measure_verification", return_value=findings):
            with mock.patch.object(checks, "_baseline_entries", return_value=[]):
                with mock.patch.object(checks, "evaluate", side_effect=self.stall):
                    result, elapsed = self.run_adapter("verification")
        self.assert_timeout(result, "ratchet evaluation", elapsed)

    def test_clone_tool_preparation_is_stopped_while_running(self) -> None:
        with mock.patch.object(clones, "_jscpd_binary", side_effect=self.stall):
            result, elapsed = self.run_adapter("clones")
        self.assert_timeout(result, "clone tool preparation", elapsed)


if __name__ == "__main__":
    unittest.main()
