"""The mutation runner must fail closed on incomplete or unreliable evidence."""

from __future__ import annotations

import contextlib
import inspect
import io
import os
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

    def write_parent_child(self, child: str, assertion: str) -> None:
        self.write_tests(
            "import pathlib, subprocess, sys, unittest\n"
            "class ParentTests(unittest.TestCase):\n"
            "    def test_child(self):\n"
            "        root = str(pathlib.Path(__file__).resolve().parent.parent)\n"
            f"        code = {child!r}\n"
            "        result = subprocess.run([sys.executable, '-I', '-c', code, root], "
            "capture_output=True, text=True)\n"
            f"        {assertion}\n"
        )

    def write_child_test(self, body: str, assertion: str) -> None:
        child = (
            "import sys, unittest\nsys.path.insert(0, sys.argv[1])\n"
            "from sample.decision import decision\n"
            "class ChildTests(unittest.TestCase):\n"
            "    def test_value(self):\n"
            + "".join(f"        {line}\n" for line in body.splitlines())
            + "unittest.main(argv=[sys.argv[0]])\n"
        )
        self.write_parent_child(child, assertion)

    def write_parent_fixture(self, methods: str) -> None:
        self.write_tests(
            "import unittest\nfrom sample.decision import decision\n"
            "class ParentTests(unittest.TestCase):\n"
            + "".join(f"    {line}\n" for line in methods.splitlines())
        )

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

    def assert_child_assertion_kills(self, name: str, body: str) -> None:
        self.write_child_test(body, "self.assertEqual(result.returncode, 0)")
        report = self.run_fixture(self.decision(name, "decision", "return True", operator="opposite_return"))
        self.assertTrue(report.passed, str(report))
        self.assertEqual(report.outcomes[0].status, "killed")

    def run_targeted_fixture(self, name: str) -> mutation.Report:
        report = self.run_fixture(
            self.decision(name, "decision", "return True", operator="opposite_return")
        )
        self.assertTrue(report.passed, str(report))
        self.assertEqual(report.outcomes[0].status, "killed")
        self.assertIn("1 selected test", report.outcomes[0].detail)
        self.assertNotIn("full suite", report.outcomes[0].detail)
        return report

    def test_probe_attributes_a_child_process_hit_to_the_parent_test(self) -> None:
        self.source("def decision():\n    return True\n")
        self.write_child_test(
            "self.assertTrue(decision())", "self.assertEqual(result.returncode, 0)"
        )
        self.run_targeted_fixture("child_hit")

    def test_targeted_kill_skips_the_full_suite(self) -> None:
        counter = self.root / "full-suite-runs"
        self.source("def decision():\n    return True\n")
        self.write_tests(
            "import pathlib, unittest\nfrom sample.decision import decision\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_reach(self):\n        self.assertTrue(decision())\n"
            "    def test_other(self):\n"
            f"        path = pathlib.Path({str(counter)!r})\n"
            "        count = int(path.read_text()) if path.exists() else 0\n"
            "        path.write_text(str(count + 1))\n"
        )
        self.run_targeted_fixture("targeted")
        self.assertEqual(counter.read_text(encoding="utf-8"), "1")

    def test_selected_tests_passing_survives_without_the_full_suite(self) -> None:
        self.source(
            "VALUE = None\n"
            "def decision():\n"
            "    global VALUE\n"
            "    VALUE = 1 >= 1\n"
            "    return VALUE\n"
        )
        self.write_tests(
            "import unittest\nimport sample.decision as sample\n"
            "class TestSelection(unittest.TestCase):\n"
            "    def test_call(self):\n        sample.decision()\n"
            "    def test_other(self):\n        self.assertIs(sample.VALUE, True)\n"
        )
        report = self.run_fixture(self.decision("selection", "decision", "1 >= 1"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "survived")
        self.assertIn("1 selected test", report.outcomes[0].detail)
        self.assertIn("the selected tests passed", report.outcomes[0].detail)
        self.assertNotIn("full suite", report.outcomes[0].detail)

    def test_unreached_mutant_survives_without_a_suite_run(self) -> None:
        self.source("def decision():\n    return True\n")
        self.write_tests(
            "import unittest\nfrom sample.decision import decision\n"
            "class TestImport(unittest.TestCase):\n"
            "    def test_import(self):\n        self.assertIsNotNone(decision)\n"
        )
        decision = self.decision("unreached", "decision", "return True", operator="opposite_return")
        with mock.patch.object(mutation, "_run_suite", wraps=mutation._run_suite) as run:
            report = self.run_fixture(decision)
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "survived")
        self.assertEqual(report.outcomes[0].detail, "no test reached its target")
        self.assertEqual(run.call_count, 1)

    def test_order_dependent_reaching_test_is_unstable(self) -> None:
        self.source("def decision():\n    return True\n")
        self.write_tests(
            "import unittest\nfrom sample.decision import decision\n"
            "STATE = False\n"
            "class TestOrder(unittest.TestCase):\n"
            "    def test_first(self):\n"
            "        global STATE\n"
            "        STATE = True\n"
            "    def test_second(self):\n"
            "        self.assertTrue(STATE)\n"
            "        self.assertTrue(decision())\n"
        )
        report = self.run_fixture(
            self.decision("order", "decision", "return True", operator="opposite_return")
        )
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "unstable")
        self.assertIn("failed unmutated", report.outcomes[0].detail)

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
        self.assertEqual(report.outcomes[1].detail, "no test reached its target")
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

    def test_unexpected_success_is_a_suite_failure_not_an_exit_error(self) -> None:
        self.write_tests(
            "import unittest\nclass TestUnexpected(unittest.TestCase):\n"
            "    @unittest.expectedFailure\n"
            "    def test_value(self):\n        pass\n"
        )
        status, result, _detail = mutation._run_suite(
            self.root, "tests", self.root, 4, Path(mutation.__file__).resolve()
        )
        self.assertEqual(status, "failed")
        self.assertEqual(
            result["unexpected_successes"], ["test_sample.TestUnexpected.test_value"]
        )

    def test_mutant_module_import_failure_is_invalid(self) -> None:
        self.source(
            "def decision():\n    if True:\n        return 'yes'\n"
            "    raise ImportError('broken mutant')\nVALUE = decision()\n"
        )
        self.write_tests(
            "import unittest\nfrom sample.decision import VALUE\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_value(self):\n        self.assertTrue(VALUE)\n"
        )
        report = self.run_fixture(self.decision("invalid", "decision", "True", operator="negate"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes[0].status, "invalid")
        self.assertIn("ImportError", report.outcomes[0].detail)

    def test_reaching_test_error_is_a_kill(self) -> None:
        self.source("def decision():\n    return True\n")
        self.write_tests(
            "import unittest\nfrom sample.decision import decision\n"
            "class TestDecision(unittest.TestCase):\n"
            "    def test_error(self):\n"
            "        if not decision():\n"
            "            raise RuntimeError('mutant error')\n"
        )
        report = self.run_fixture(
            self.decision("error", "decision", "return True", operator="opposite_return")
        )
        self.assertTrue(report.passed, str(report))
        self.assertEqual(report.outcomes[0].status, "killed")
        self.assertIn("test_error", report.outcomes[0].detail)

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

    def test_reaching_assertions_are_kills_in_every_position(self) -> None:
        self.source("def decision():\n    return True\n")
        fixtures = {
            "test body": "def test_value(self):\n    self.assertTrue(decision())",
            "setUp": (
                "def setUp(self):\n    self.assertTrue(decision())\n"
                "def test_value(self):\n    pass"
            ),
            "tearDown": (
                "def test_value(self):\n    pass\n"
                "def tearDown(self):\n    self.assertTrue(decision())"
            ),
            "cleanup": (
                "def setUp(self):\n    self.addCleanup(self.cleanup)\n"
                "def cleanup(self):\n    self.assertTrue(decision())\n"
                "def test_value(self):\n    pass"
            ),
            "subtest": (
                "def test_value(self):\n    with self.subTest():\n        self.assertTrue(decision())"
            ),
        }
        for position, methods in fixtures.items():
            with self.subTest(position=position):
                self.write_parent_fixture(methods)
                report = self.run_fixture(
                    self.decision(position, "decision", "return True", operator="opposite_return")
                )
                self.assertTrue(report.passed, f"{position}: {report}")
                self.assertEqual(report.outcomes[0].status, "killed")
                self.assertIn("1 selected test", report.outcomes[0].detail)
                self.assertNotIn("full suite", report.outcomes[0].detail)
        with self.subTest(position="child process"):
            self.write_parent_child(
                "import sys\nsys.path.insert(0, sys.argv[1])\n"
                "from sample.decision import decision\nassert decision()\n",
                "self.assertEqual(result.returncode, 0, result.stderr)",
            )
            self.run_targeted_fixture("child process")

    def test_child_unittest_assertions_are_kills(self) -> None:
        self.source("def decision():\n    return True\n")
        for name, body in (
            ("test", "self.assertTrue(decision())"),
            ("subtest", "with self.subTest():\n    self.assertTrue(decision())"),
        ):
            with self.subTest(name=name):
                self.assert_child_assertion_kills(name, body)

    def test_parent_test_body_subtest_assertion_is_still_a_kill(self) -> None:
        self.source("def decision():\n    return True\n")
        self.write_parent_fixture(
            "def test_value(self):\n    with self.subTest():\n        self.assertTrue(decision())"
        )
        self.run_targeted_fixture("parent_body_subtest")

    def test_parent_test_body_assertion_after_doCleanups_is_still_a_kill(self) -> None:
        self.source("def decision():\n    return True\n")
        self.write_parent_fixture(
            "def setUp(self):\n    self.addCleanup(self.cleanup)\n"
            "def cleanup(self):\n    pass\n"
            "def test_value(self):\n    self.doCleanups()\n    self.assertTrue(decision())"
        )
        self.run_targeted_fixture("parent_doCleanups")

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

    def test_failed_probe_stops_before_any_mutant(self) -> None:
        self.source("def decision():\n    return 1 < 2\n")
        self.write_tests(
            "import unittest\nclass TestFailure(unittest.TestCase):\n"
            "    def test_failure(self):\n        self.fail('probe failure')\n"
        )
        with mock.patch.object(mutation, "_one", side_effect=AssertionError("mutant ran")):
            report = self.run_fixture(self.decision("decision", "decision", "1 < 2"))
        self.assertFalse(report.passed)
        self.assertEqual(report.outcomes, ())
        self.assertIn("probe suite failed", report.errors[0])

    def test_unmutated_suite_runs_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mutation-counter-") as directory:
            counter = Path(directory) / "runs"
            self.source("def decision():\n    return True\n")
            (self.root / "tests" / "test_counter.py").write_text(
                "import pathlib, unittest\n"
                "def setUpModule():\n"
                f"    with pathlib.Path({str(counter)!r}).open('a', encoding='utf-8') as file:\n"
                "        file.write('run\\n')\n"
                "class TestCounter(unittest.TestCase):\n"
                "    def test_other(self):\n        pass\n",
                encoding="utf-8",
            )
            self.write_tests(
                "import unittest\n"
                "from sample.decision import decision\n"
                "class TestDecision(unittest.TestCase):\n"
                "    def test_value(self):\n        self.assertTrue(decision())\n"
            )
            report = self.run_fixture(
                self.decision("once", "decision", "return True", operator="opposite_return")
            )
            self.assertTrue(report.passed, str(report))
            self.assertEqual(counter.read_text(encoding="utf-8").splitlines(), ["run"])

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

    def test_unattributed_hits_run_the_complete_suite(self) -> None:
        self.source("def decision():\n    return True\nVALUE = decision()\n")
        self.write_tests(
            "import unittest\nfrom sample.decision import VALUE\n"
            "class TestValue(unittest.TestCase):\n"
            "    def test_value(self):\n        self.assertTrue(VALUE)\n"
        )
        with mock.patch.dict(os.environ, {"QG_MUTATION_TEST": "outer.test"}):
            report = self.run_fixture(
                self.decision("unattributed", "decision", "return True", operator="opposite_return")
            )
        self.assertTrue(report.passed, str(report))
        self.assertEqual(report.outcomes[0].status, "killed")
        self.assertIn("full suite (unattributed hits)", report.outcomes[0].detail)
        self.assertIn("test_value", report.outcomes[0].detail)

    def test_default_worker_count_is_two(self) -> None:
        parameters = inspect.signature(mutation.run_mutations).parameters
        self.assertEqual(parameters["workers"].default, 2)

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
