"""Unit tests for gate identity failure reporting."""
from __future__ import annotations

import importlib
import sys
import unittest

from support import GATE

sys.path.insert(0, str(GATE))
gate_result = importlib.import_module("quality_gate.gate_result")
runner = importlib.import_module("quality_gate.runner")


class GitProblemTests(unittest.TestCase):
    def test_no_run_is_unknown(self) -> None:
        self.assertEqual(
            gate_result._git_problem(None, "git failed"),
            "unknown: cannot run git",
        )

    def test_unfinished_execution_names_it(self) -> None:
        result = runner.RunResult(("git",), "budget", None)
        self.assertEqual(
            gate_result._git_problem(result, "git failed"),
            "unknown: git budget",
        )

    def test_failed_run_reports_stderr(self) -> None:
        result = runner.RunResult(
            ("git",), "completed", 1, stderr=b"fatal: bad\n"
        )
        self.assertEqual(
            gate_result._git_problem(result, "git failed"),
            "unknown: fatal: bad",
        )

    def test_failed_run_without_stderr_uses_the_context(self) -> None:
        result = runner.RunResult(("git",), "completed", 1)
        self.assertEqual(
            gate_result._git_problem(result, "git failed"),
            "unknown: git failed",
        )

    def test_successful_run_has_no_problem(self) -> None:
        result = runner.RunResult(("git",), "completed", 0)
        self.assertIsNone(
            gate_result._git_problem(result, "git failed")
        )


if __name__ == "__main__":
    unittest.main()
