"""The mutation runner must fail closed on incomplete or unreliable evidence."""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import GATE

sys.path.insert(0, str(GATE / "tests"))
import mutate_gate as mutation


class MutationRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="mutation-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "sample").mkdir()
        (self.root / "sample" / "__init__.py").write_text("", encoding="utf-8")
        (self.root / "tests").mkdir()

    def source(self, code: str, module: str = "decision.py") -> None:
        (self.root / "sample" / module).write_text(code, encoding="utf-8")

    def write_tests(self, code: str) -> None:
        (self.root / "tests" / "test_sample.py").write_text(code, encoding="utf-8")

    def decision(
        self,
        name: str,
        function: str,
        target: str,
        *,
        operator: str = "comparison",
        module: str = "decision.py",
    ) -> mutation.Decision:
        return mutation.Decision(name, f"sample/{module}", function, operator, target, "fixture decision")

    def run_fixture(self, *decisions: mutation.Decision, timeout: float = 4) -> mutation.Report:
        with contextlib.redirect_stdout(io.StringIO()):
            return mutation.run_mutations(self.root, decisions, timeout=timeout, workers=1)

    def assert_unloaded(self) -> None:
        report = self.run_fixture(self.decision("unloaded", "decision", "1 < 2", module="unused.py"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "error")
        self.assertIn("not shown to be loaded", report.outcomes[0].detail)

    def test_tested_decision_is_killed_and_untested_decision_survives(self) -> None:
        source = "def tested(x):\n    return x >= 1\n\ndef untested(x):\n    return x >= 1\n"
        self.source(source)
        self.write_tests(
            "import unittest\nfrom sample.decision import tested\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_boundary(self):\n        self.assertTrue(tested(1))\n"
        )
        report = self.run_fixture(
            self.decision("tested", "tested", "x >= 1"), self.decision("untested", "untested", "x >= 1")
        )
        self.assertFalse(report.passed)
        self.assertEqual(report.errors, ())
        self.assertEqual(
            [(item.name, item.status) for item in report.outcomes],
            [("tested", "killed"), ("untested", "survived")],
        )
        self.assertIn("test_boundary", report.outcomes[0].detail)
        self.assertEqual((self.root / "sample" / "decision.py").read_text(encoding="utf-8"), source)

    def test_timed_out_mutant_fails_and_is_not_killed(self) -> None:
        self.source(
            "def decision():\n    if False:\n        while True:\n            pass\n    return True\n"
        )
        self.write_tests(
            "import unittest\nfrom sample.decision import decision\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_decision(self):\n        self.assertTrue(decision())\n"
        )
        report = self.run_fixture(self.decision("hang", "decision", "False", operator="negate"), timeout=2)
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "timed out")
        self.assertIn("exceeded", report.outcomes[0].detail)

    def test_timeout_is_reported_when_the_process_exits_during_group_kill(self) -> None:
        process = mock.Mock(pid=123)
        process.wait.side_effect = [subprocess.TimeoutExpired("suite", 1), 0]
        with (
            mock.patch.object(mutation.subprocess, "Popen", return_value=process),
            mock.patch.object(mutation.os, "killpg", side_effect=ProcessLookupError),
        ):
            status, _result, detail = mutation._run_suite(
                self.root, "tests", self.root, 1, self.root / "driver.py"
            )
        self.assertEqual(status, "timed out")
        self.assertIn("exceeded", detail)

    def test_import_error_is_not_counted_as_a_kill(self) -> None:
        self.source(
            "def decision():\n    if True:\n        return 'yes'\n"
            "    raise ImportError('broken mutant')\n"
            "VALUE = decision()\n"
        )
        self.write_tests(
            "import unittest\nfrom sample.decision import VALUE\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_value(self):\n        self.assertTrue(VALUE)\n"
        )
        report = self.run_fixture(self.decision("import_error", "decision", "True", operator="negate"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "error")
        self.assertIn("ImportError", report.outcomes[0].detail)

    def test_execution_error_is_not_counted_as_a_kill(self) -> None:
        self.source(
            "def decision():\n    if False:\n        raise RuntimeError('broken mutant')\n    return True\n"
        )
        self.write_tests(
            "import unittest\nfrom sample.decision import decision\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_value(self):\n        self.assertTrue(decision())\n"
        )
        report = self.run_fixture(self.decision("execution_error", "decision", "False", operator="negate"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "error")
        self.assertIn("RuntimeError", report.outcomes[0].detail)

    def test_aborted_suite_without_a_report_is_not_a_kill(self) -> None:
        self.source("import os\ndef decision():\n    if False:\n        os._exit(17)\n    return True\n")
        self.write_tests(
            "import unittest\nfrom sample.decision import decision\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_value(self):\n        self.assertTrue(decision())\n"
        )
        report = self.run_fixture(self.decision("aborted", "decision", "False", operator="negate"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "error")
        self.assertIn("suite report", report.outcomes[0].detail)
        self.assertIn("exit 17", report.outcomes[0].detail)

    def test_setup_assertion_failure_is_not_counted_as_a_kill(self) -> None:
        self.source("def decision():\n    return True\n")
        self.write_tests(
            "import unittest\nfrom sample.decision import decision\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def setUp(self):\n        self.assertTrue(decision())\n"
            "    def test_value(self):\n        self.assertTrue(True)\n"
        )
        report = self.run_fixture(
            self.decision("setup", "decision", "return True", operator="opposite_return")
        )
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "error")
        self.assertIn("setup", report.outcomes[0].detail)

    def test_subprocess_return_code_fixture_import_error_is_not_a_kill(self) -> None:
        self.source(
            "def decision():\n    if True:\n        return 'yes'\n"
            "    raise ImportError('broken child import')\nVALUE = decision()\n"
        )
        self.write_tests(
            "import pathlib, subprocess, sys, unittest\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_import(self):\n"
            "        root = str(pathlib.Path(__file__).resolve().parent.parent)\n"
            "        code = 'import sys; sys.path.insert(0, sys.argv[1]); import sample.decision'\n"
            "        result = subprocess.run([sys.executable, '-I', '-c', code, root], "
            "capture_output=True, text=True)\n"
            "        self.assertEqual(result.returncode, 0)\n"
        )
        report = self.run_fixture(self.decision("child_import_code", "decision", "True", operator="negate"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "error")
        self.assertIn("ImportError", report.outcomes[0].detail)

    def test_subprocess_return_code_fixture_execution_error_is_not_a_kill(self) -> None:
        self.source(
            "def decision():\n    if False:\n        raise RuntimeError('broken child execution')\n"
            "    return 'yes'\n"
        )
        self.write_tests(
            "import pathlib, subprocess, sys, unittest\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_run(self):\n"
            "        root = str(pathlib.Path(__file__).resolve().parent.parent)\n"
            "        code = (\n"
            "            'import sys; sys.path.insert(0, sys.argv[1]); '\n"
            "            'from sample.decision import decision; print(decision())'\n"
            "        )\n"
            "        result = subprocess.run([sys.executable, '-I', '-c', code, root], "
            "capture_output=True, text=True)\n"
            "        self.assertEqual(result.returncode, 0)\n"
        )
        report = self.run_fixture(
            self.decision("child_execution_code", "decision", "False", operator="negate")
        )
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "error")
        self.assertIn("RuntimeError", report.outcomes[0].detail)

    def test_subprocess_import_error_is_not_counted_as_a_kill(self) -> None:
        self.source(
            "def decision():\n    if True:\n        return 'yes'\n"
            "    raise ImportError('broken subprocess import')\nVALUE = decision()\n"
        )
        self.write_tests(
            "import pathlib, subprocess, sys, unittest\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_import(self):\n"
            "        root = str(pathlib.Path(__file__).resolve().parent.parent)\n"
            "        code = 'import sys; sys.path.insert(0, sys.argv[1]); import sample.decision'\n"
            "        result = subprocess.run([sys.executable, '-I', '-c', code, root], "
            "capture_output=True, text=True)\n"
            "        self.assertEqual(result.returncode, 0, result.stderr)\n"
        )
        report = self.run_fixture(self.decision("child_import", "decision", "True", operator="negate"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "error")
        self.assertIn("ImportError", report.outcomes[0].detail)

    def test_all_runs_use_the_frozen_source_snapshot(self) -> None:
        self.source("def decision(x):\n    return x >= 1\n")
        original = self.root / "sample" / "decision.py"
        self.write_tests(
            "import pathlib, unittest\nfrom sample.decision import decision\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_boundary(self):\n"
            f"        pathlib.Path({str(original)!r}).write_text('def decision(x):\\n    return False\\n')\n"
            "        self.assertTrue(decision(1))\n"
        )
        report = self.run_fixture(self.decision("snapshot", "decision", "x >= 1"))
        self.assertTrue(report.passed, str(report))
        self.assertEqual(report.outcomes[0].status, "killed")
        self.assertIn("return False", original.read_text(encoding="utf-8"))

    def test_no_mutation_names_the_declared_function(self) -> None:
        self.source("def decision():\n    return 1\n")
        report = self.run_fixture(self.decision("no_mutation", "decision", "return 1"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes, ())
        self.assertIn("no_mutation: decision", report.errors[0])
        self.assertIn("found 0", report.errors[0])

    def test_missing_declared_function_is_rejected(self) -> None:
        self.source("def exists():\n    return 1 < 2\n")
        report = self.run_fixture(self.decision("missing", "does_not_exist", "1 < 2"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes, ())
        self.assertIn("does_not_exist", report.errors[0])
        self.assertIn("does not exist", report.errors[0])

    def test_failed_unmutated_suite_stops_before_any_mutant(self) -> None:
        self.source("def decision():\n    return 1 < 2\n")
        self.write_tests(
            "import unittest\nclass TestFailure(unittest.TestCase):\n"
            "    def test_failure(self):\n        self.fail('baseline failure')\n"
        )
        with mock.patch.object(mutation, "_one", side_effect=AssertionError("mutant ran")):
            report = self.run_fixture(self.decision("decision", "decision", "1 < 2"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes, ())
        self.assertIn("unmutated suite failed", report.errors[0])
        self.assertIn("baseline failure", report.errors[0])

    def test_unloaded_mutant_is_an_error_even_if_suite_passes(self) -> None:
        self.source("def decision():\n    return 1 < 2\n", module="unused.py")
        self.write_tests(
            "import unittest\nclass TestPass(unittest.TestCase):\n"
            "    def test_pass(self):\n        self.assertTrue(True)\n"
        )
        self.assert_unloaded()

    def test_unloaded_mutant_is_not_killed_by_an_unrelated_test_failure(self) -> None:
        self.source("def decision():\n    return 1 < 2\n", module="unused.py")
        sentinel = self.root / "baseline-ran"
        self.write_tests(
            "import pathlib, unittest\nclass TestPassOnce(unittest.TestCase):\n"
            "    def test_once(self):\n"
            f"        sentinel = pathlib.Path({str(sentinel)!r})\n"
            "        self.assertFalse(sentinel.exists())\n"
            "        sentinel.write_text('baseline')\n"
        )
        self.assert_unloaded()

    def test_unmutated_suite_with_a_skipped_test_fails_closed(self) -> None:
        self.source("def decision():\n    return 1 < 2\n")
        self.write_tests(
            "import unittest\nclass TestSkip(unittest.TestCase):\n"
            "    @unittest.skip('fixture')\n"
            "    def test_skip(self):\n        pass\n"
        )
        report = self.run_fixture(self.decision("decision", "decision", "1 < 2"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes, ())
        self.assertIn("skipped", report.errors[0])

    def test_empty_decisions_fail_closed(self) -> None:
        report = self.run_fixture()
        self.assertFalse(report.passed)
        self.assertIn("zero mutants", report.errors[0])

    def test_ambiguous_target_fails_closed(self) -> None:
        self.source("def decision(x):\n    return (x < 1) or (x < 1)\n")
        report = self.run_fixture(self.decision("ambiguous", "decision", "x < 1"))
        self.assertFalse(report.passed)
        self.assertIn("found 2", report.errors[0])

    def test_opposite_verdict_and_removed_raise_are_specific(self) -> None:
        source = "def decision():\n    if True:\n        raise ValueError('failure')\n    return False\n"
        removed = mutation.mutate(
            source, self.decision("error", "decision", "raise ValueError('failure')", operator="remove_raise")
        )
        opposite = mutation.mutate(
            source, self.decision("verdict", "decision", "return False", operator="opposite_return")
        )
        self.assertIn("        pass\n", removed)
        self.assertIn("    return True\n", opposite)
        self.assertIn("    return False\n", removed)
        self.assertIn("raise ValueError('failure')", opposite)


if __name__ == "__main__":
    unittest.main()
