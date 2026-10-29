"""Checks stop in-progress work when their shared deadline expires."""
from __future__ import annotations

import contextlib
import importlib
import io
import os
import re
import sys
import tempfile
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
owners = importlib.import_module("quality_gate.owners")


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

    def owners_spec(self) -> object:
        rule = owners.OwnerRule(
            "single-owner", "one implementation", ("source.py",),
            (owners.Pattern("python-call", "peak"),), (),
        )
        return owners.OwnersSpec((rule,))

    def adapter_spec(self, adapter: str) -> object:
        if adapter == "clones":
            return policy.CloneSpec(50)
        if adapter == "crap":
            return policy.PythonCrapSpec("tests")
        if adapter == "verification":
            return policy.VerificationSpec("tests")
        return self.owners_spec()

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
            evidence_path=self.evidence, coverage_config=self.config_file,
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

    def run_adapter(self, adapter: str) -> tuple[object, float]:
        start = time.monotonic()
        with mock.patch.object(checks, "CLONE_BUDGET_SECONDS", self.budget):
            with contextlib.redirect_stderr(io.StringIO()):
                result = checks.run_check(
                    self.root, self.config, self.check_def(adapter),
                    ["source.py"], {"source.py": "source"}, prefix="check",
                    prior={"tests": self.prior_tests()},
                )
        return result, time.monotonic() - start

    def test_coverage_combination_is_stopped_while_running(self) -> None:
        pattern = r"^Ran (\d+) tests? in"
        spec = policy.PythonTestsSpec(
            (sys.executable, "-c", "print('Ran 1 test in 0.1s')"),
            pattern, re.compile(pattern), None, None, self.budget,
        )
        check = replace(
            self.check_def("verification"), id="tests", adapter="python_tests",
            spec=spec, evidence=("tests",), threshold=None,
        )
        start = time.monotonic()
        with mock.patch.object(checks, "coverage_prefix", return_value=[]):
            with mock.patch.object(checks, "combine_coverage", side_effect=self.stall):
                with contextlib.redirect_stderr(io.StringIO()):
                    result = checks.run_check(self.root, self.config, check, [], {}, prefix="check")
        self.assert_timeout(result, "coverage combination", time.monotonic() - start)
        self.assertEqual(result.diagnostics.exit_code, 0)
        self.assertIn("Ran 1 test", result.diagnostics.output_tail)

    def test_crap_analysis_is_stopped_while_running(self) -> None:
        with mock.patch.object(checks, "measure_crap", side_effect=self.stall):
            result, elapsed = self.run_adapter("crap")
        self.assert_timeout(result, "CRAP analysis", elapsed)

    def test_verification_analysis_is_stopped_while_running(self) -> None:
        with mock.patch.object(checks, "measure_verification", side_effect=self.stall):
            result, elapsed = self.run_adapter("verification")
        self.assert_timeout(result, "verification analysis", elapsed)

    def test_owners_analysis_is_stopped_while_running(self) -> None:
        with mock.patch.object(checks, "measure_owners", side_effect=self.stall):
            result, elapsed = self.run_adapter("owners")
        self.assert_timeout(result, "owners analysis", elapsed)

    def test_owners_baseline_loading_is_stopped_while_running(self) -> None:
        with mock.patch.object(checks, "measure_owners", return_value=[]):
            with mock.patch.object(checks, "_baseline_entries", side_effect=self.stall):
                result, elapsed = self.run_adapter("owners")
        self.assert_timeout(result, "baseline loading", elapsed)

    def test_normal_owners_run_passes(self) -> None:
        (self.root / "source.py").write_text("peak()\n", encoding="utf-8")
        result, _elapsed = self.run_adapter("owners")
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.execution, "completed")
        self.assertTrue(result.is_satisfied())
        self.assertEqual(result.findings, [])

    def test_baseline_loading_is_stopped_while_running(self) -> None:
        findings = [ratchet.Finding("tests:tests:executed", 1, "test summary")]
        with mock.patch.object(checks, "measure_verification", return_value=findings):
            with mock.patch.object(checks, "_baseline_entries", side_effect=self.stall):
                result, elapsed = self.run_adapter("verification")
        self.assert_timeout(result, "baseline loading", elapsed)

    def test_ratchet_evaluation_is_stopped_while_running(self) -> None:
        findings = [ratchet.Finding("tests:tests:executed", 1, "test summary")]
        with mock.patch.object(checks, "measure_verification", return_value=findings):
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
