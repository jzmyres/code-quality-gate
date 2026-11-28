"""Compare gate evidence with native unittest and ERT observations."""
from __future__ import annotations

import functools
import io
import itertools
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from support import BASE_CONFIG, GATE, PYTHON_COMMON_RULE_LINES, FixtureCase, output

from quality_gate import adapters, python_tests


SHARDS = GATE / "quality_gate" / "test_shards.py"
shards = python_tests.test_shards

PYTHON_POLICY = r"""
schema = 2
[code]
patterns = ["*.py"]
shebangs = []
[levels]
required_tiers = [1]
[classes.test]
code = true
description = "Unittest suite"
checks = ["tests"]
[classes.config]
code = false
description = "Configuration"
[classes.doc]
code = false
description = "Documentation"
[checks.tests]
adapter = "{adapter}"
tier = 1
enforcement = "enforced"
run = {run}
tests_pattern = '^Ran (\d+) tests? in'
{skipped_line}
[[rule]]
pattern = "tests/*.py"
class = "test"
reason = "unittest discovery"
"""

ERT_POLICY = BASE_CONFIG + """
[classes.elisp-module]
code = true
description = "Instrumented Elisp"
checks = ["legacy-tests"]
[classes.ert-suite]
code = true
description = "ERT suite"
checks = ["smoke"]
[checks.legacy-tests]
adapter = "elisp_tests"
tier = 1
enforcement = "enforced"
suite = "tests/suite.el"
[[rule]]
pattern = "src/*.el"
class = "elisp-module"
reason = "instrumented code"
[[rule]]
pattern = "tests/*.el"
class = "ert-suite"
reason = "ERT entry point"
"""

ERT_MODULE = "(defun fixture-increment (value) (1+ value))\n"

NATIVE_UNITTEST = """\
import json
import sys
import unittest

class NativeResult(unittest.TestResult):
    def __init__(self, cases):
        super().__init__()
        self.positions = {id(test): pos for pos, test in enumerate(cases)}
        self.results = {}

    def addSuccess(self, test):
        self.completed(test, "passed")

    def addSkip(self, test, reason):
        self.completed(test, "skipped")

    def completed(self, test, outcome):
        pos = self.positions[id(test)]
        self.results[pos] = (pos, test.id(), outcome)

def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item

suite = unittest.defaultTestLoader.discover("tests")
cases = list(flatten(suite))
result = NativeResult(cases)
suite(result)
print(json.dumps([result.results[pos] for pos in range(len(cases))]))
"""

PYTHON_CASES = """\
import unittest
from pathlib import Path

with Path("discovery.log").open("a", encoding="utf-8") as stream:
    print(__name__, file=stream)

class Repeated(unittest.TestCase):
    def setUp(self):
        with Path("calls.log").open("a", encoding="utf-8") as stream:
            print(self.id(), file=stream)

    def test_pass(self):
        pass

    def test_skip(self):
        self.skipTest("invoked")
"""

PYTHON_HOOK = """\

def load_tests(loader, suite, pattern):
    return unittest.TestSuite([Repeated("test_pass"), Repeated("test_skip"), Repeated("test_pass")])
"""

ERT_SUITE = """\
(require 'ert)
(require 'json)

(defun fixture-observe-ert (run selector listener &rest args)
  (let ((calls 0))
    (apply run selector
           (lambda (event &rest data)
             (when (eq event 'run-started)
               (write-region
                (concat (json-encode
                         (vconcat (mapcar (lambda (test) (symbol-name (ert-test-name test)))
                                          (ert--stats-tests (car data))))) "\n")
                nil NATIVE-LOG t 'silent))
             (when (eq event 'test-ended)
               (let* ((test (nth 1 data))
                      (result (nth 2 data)))
                 (write-region
                  (concat (json-encode
                           (list calls (symbol-name (ert-test-name test))
                                 (symbol-name (type-of result))
                                 (ert-test-result-duration result))) "\n")
                  nil NATIVE-LOG t 'silent)
                 (setq calls (1+ calls))))
             (apply listener event data))
           args)))

(advice-add 'ert-run-tests :around #'fixture-observe-ert)
(ert-deftest fixture-pass () (should (= (fixture-increment 1) 2)))
(ert-deftest fixture-expected () :expected-result :failed (should nil))
(ert-deftest fixture-skip () (ert-skip "measured skip"))
(ert-run-tests-batch-and-exit '(member fixture-pass fixture-skip fixture-expected))
"""


def python_policy(argv, *, adapter="python_tests", skipped_pattern=None):
    skipped_line = "" if skipped_pattern is None else f"skipped_pattern = {json.dumps(skipped_pattern)}"
    check = PYTHON_POLICY.format(adapter=adapter, run=json.dumps(argv), skipped_line=skipped_line)
    return "\n".join([check, *PYTHON_COMMON_RULE_LINES])


class TestEvidenceTests(FixtureCase):
    def assert_occurrences(self, expected, actual):
        differences = [
            f"occurrence {position}: expected {want!r}, got {got!r}"
            for position, (want, got) in enumerate(itertools.zip_longest(expected, actual))
            if want != got
        ]
        self.assertEqual(differences, [])

    def gate_rows(self, identifier, *args, status=0):
        ledger = self.base / "ledger.jsonl"
        env = {**self.default_tool_env(), "QG_AGENT": "0"}
        result, document = self.run_json("--only", identifier, "--ledger", str(ledger), *args, env=env)
        self.assertEqual(result.returncode, status, output(result))
        check = self.check_by_id(document, identifier)
        entry = self.check_by_id(json.loads(ledger.read_text(encoding="utf-8").splitlines()[-1]), identifier)
        self.assertEqual("test_results" in check, "test_results" in entry)
        self.assertEqual(check.get("test_results"), entry.get("test_results"))
        return check

    def setup_python(self):
        (self.repo / "a.py").unlink()
        self.add_file("tests/test_repeat.py", PYTHON_CASES + PYTHON_HOOK)
        self.add_file("tests/test_other.py", PYTHON_CASES)
        argv = ["{python}", str(SHARDS), "-s", "tests", "-j", "2"]
        self.write_config(python_policy(argv))
        self.commit_all()

    def native_unittest(self):
        self.add_file("native.py", NATIVE_UNITTEST)
        result = subprocess.run([sys.executable, "-B", "native.py"], cwd=self.repo, check=True,
                                capture_output=True, text=True)
        (self.repo / "native.py").unlink()
        expected = json.loads(result.stdout)
        self.assert_work(expected, discoveries=1)
        return expected

    def assert_work(self, expected, *, discoveries):
        for filename, lines in (
            ("calls.log", [row[1] for row in expected]),
            ("discovery.log", ["test_other", "test_repeat"] * discoveries),
        ):
            path = self.repo / filename
            self.assertCountEqual(path.read_text(encoding="utf-8").splitlines(), lines)
            path.unlink()

    def test_unittest_direct_ordinary_and_affected_report_native_occurrences(self):
        self.setup_python()
        expected = self.native_unittest()
        report_path = self.base / "result.json"
        for workers in ("1", "2"):
            with self.subTest(workers=workers):
                env = {key: value for key, value in os.environ.items() if key != "QG_PYTHON"}
                subprocess.run([sys.executable, "-I", "-B", str(SHARDS), "-s", "tests", "-j", workers,
                                "--result-report", str(report_path)], cwd=self.repo, env=env, check=True,
                               capture_output=True, text=True)
                report = json.loads(report_path.read_text(encoding="utf-8"))
                self.assert_occurrences(expected, [row[:3] for row in report["records"]])
                self.assertEqual(report["ids"], [row[1] for row in expected])
                self.assert_work(expected, discoveries=1 if workers == "1" else 3)
        for scope in ((), ("--base", "HEAD")):
            with self.subTest(scope=scope):
                check = self.gate_rows("tests", *scope)
                rows = check["test_results"]
                keys = ("position", "id", "outcome")
                self.assert_occurrences(expected, [[row[key] for key in keys] for row in rows])
                self.assertTrue(all(row["duration_seconds"] >= 0 for row in rows))
                self.assert_work(expected, discoveries=1 if scope else 3)

    def test_ert_matches_native_completions_from_the_child_run(self):
        self.assertIsNotNone(shutil.which("emacs"))
        self.add_file("src/core.el", ERT_MODULE)
        self.write_config(ERT_POLICY)
        native = self.base / "native.jsonl"
        self.add_file("tests/suite.el", ERT_SUITE.replace("NATIVE-LOG", json.dumps(str(native))))
        self.commit_all()
        for scope in ((), ("--base", "HEAD")):
            with self.subTest(scope=scope):
                if scope:
                    self.add_file("src/core.el", ERT_MODULE + "\n")
                check = self.gate_rows("legacy-tests", *scope)
                self.assert_native_ert_results(check, native)

    def assert_native_ert_results(self, check, native):
        selected, *expected = map(json.loads, native.read_text(encoding="utf-8").splitlines())
        native.unlink()
        self.assertEqual(selected, ["fixture-pass", "fixture-skip", "fixture-expected"])
        self.assert_occurrences(selected, [row[1] for row in expected])
        keys = ("position", "id", "outcome", "duration_seconds")
        rows = check["test_results"]
        self.assert_occurrences(expected, [[row[key] for key in keys] for row in rows])
        self.assertTrue(all(row["expected"] for row in rows))
        self.assertEqual(check["measurement"], {"tests": 2})

    def replace_python_report(self, run, defect, command, **kwargs):
        child = run(command, **kwargs)
        if "--result-report" not in command and "--affected" not in command:
            return child
        self.assertEqual(child.returncode, 0, child.combined_text)
        if "--affected" in command:
            self.replace_affected_journal(Path(command[-1]), defect)
            return child
        path = Path(command[-1])
        if defect == "absent":
            path.unlink()
        else:
            report = json.loads(path.read_text(encoding="utf-8"))
            self.corrupt_report(report["records"], defect)
            path.write_text(json.dumps(report), encoding="utf-8")
        return child

    def replace_affected_journal(self, plan, defect):
        journal = plan.with_suffix(".result.jsonl")
        frames = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(frames[-1], ["finished", None])
        if defect == "unfinished":
            frames.pop()
        else:
            records = [frame[1] for frame in frames[1:] if frame[0] == "terminal"]
            self.corrupt_report(records, defect)
        journal.write_text("".join(json.dumps(frame) + "\n" for frame in frames), encoding="utf-8")

    def test_completed_shard_command_requires_valid_evidence(self):
        self.setup_python()
        name = "test_other.Repeated.test_pass"
        for defect in ("absent", "missing", "duplicated", "wrong-id", "duration"):
            with self.subTest(defect=defect):
                run = python_tests.run
                with mock.patch.object(
                    python_tests, "run",
                    side_effect=functools.partial(self.replace_python_report, run, defect),
                ):
                    check = self.gate_rows("tests", status=1)
                self.assertIn("test-results.json", check["reason"])
                if defect != "absent":
                    self.assertIn(name, check["reason"])
                self.assertNotIn("test_results", check)
                (self.repo / "calls.log").unlink()
                (self.repo / "discovery.log").unlink()

    def test_exit_zero_with_native_failure_evidence_is_rejected(self):
        self.setup_python()
        failing = PYTHON_CASES.replace("        pass", "        self.fail('native')")
        self.add_file("tests/test_other.py", failing)
        run = python_tests.run

        def force_exit_zero(command, **kwargs):
            child = run(command, **kwargs)
            if "--result-report" in command:
                self.assertEqual(child.returncode, 1, child.combined_text)
                child.returncode = 0
            return child

        with mock.patch.object(python_tests, "run", side_effect=force_exit_zero):
            check = self.gate_rows("tests", status=1)
        name = "test_other.Repeated.test_pass"
        self.assertIn("command exited 0 with failing unittest evidence", check["reason"])
        self.assertEqual([finding["subject"] for finding in check["findings"]], [name])
        self.assertEqual(check["test_results"][0]["outcome"], "failure")

    def test_summary_coverage_and_temporary_failures_keep_valid_rows(self):
        self.setup_python()
        config = self.read_file("quality-gate.toml")
        self.write_config(config.replace("Ran ", "Unmatched "))
        check = self.gate_rows("tests", status=1)
        self.assertIn("did not match", check["reason"])
        self.assertEqual(len(check["test_results"]), 5)
        self.write_config(config)
        self.clear_work_logs()
        error = python_tests.GateError("broken")
        with mock.patch.object(python_tests, "combine_coverage", side_effect=error):
            check = self.gate_rows("tests", status=1)
        self.assertIn("coverage combination failed", check["reason"])
        self.assertEqual(len(check["test_results"]), 5)
        self.clear_work_logs()
        self.add_file("tests/test_other.py", PYTHON_CASES.replace(
            "        pass", "        import tempfile\n        tempfile.mkdtemp()",
        ))
        check = self.gate_rows("tests", status=1)
        self.assertIn("suite's TMPDIR", check["reason"])
        self.assertEqual(len(check["test_results"]), 5)

    def clear_work_logs(self):
        for filename in ("calls.log", "discovery.log"):
            (self.repo / filename).unlink()

    def test_opaque_commands_keep_only_their_configured_aggregate_counts(self):
        self.setup_python()
        argv = ["{python}", "-m", "unittest", "discover", "-s", "tests"]
        self.write_config(python_policy(argv, skipped_pattern=r"skipped=(\d+)"))
        check = self.gate_rows("tests")
        self.assertEqual(check["measurement"], {"tests": 3})
        self.assertNotIn("test_results", check)
        self.clear_work_logs()
        argv = [sys.executable, "-c", "print('Ran 5 tests in 1s')"]
        self.write_config(python_policy(argv, adapter="command"))
        check = self.gate_rows("tests")
        self.assertEqual(check["measurement"], {"tests": 5})
        self.assertNotIn("test_results", check)

    @staticmethod
    def corrupt_report(records, defect):
        if defect == "missing":
            del records[0]
        elif defect == "duplicated":
            records.insert(0, records[0])
        elif defect == "wrong-id":
            records[0][1] = "same.position.different.id"
        else:
            records[0][4] = None

    def test_exit_zero_affected_journal_requires_valid_completed_evidence(self):
        self.setup_python()
        run = adapters.run
        for defect, diagnosis in (
            ("unfinished", "did not finish"),
            ("wrong-id", "test_other.Repeated.test_pass"),
            ("duration", "invalid outcome or duration"),
        ):
            with self.subTest(defect=defect), mock.patch.object(
                adapters, "run", side_effect=functools.partial(self.replace_python_report, run, defect),
            ):
                check = self.gate_rows("tests", "--base", "HEAD", status=1)
                self.assertIn("discovery.result.jsonl", check["reason"])
                self.assertIn(diagnosis, check["reason"])
                self.assertNotIn("test_results", check)
                self.clear_work_logs()


class CallbackTimingTests(unittest.TestCase):
    def test_start_and_stop_boundaries_exclude_bookkeeping_and_event_collection(self):
        current_time = 0.0

        def advance(_result, _test):
            nonlocal current_time
            current_time += 10.0

        def emit(event, _value):
            nonlocal current_time
            if event == "started":
                current_time += 20.0

        def skip():
            nonlocal current_time
            current_time += 0.125
            raise unittest.SkipTest("invoked")

        test = unittest.FunctionTestCase(skip)
        native_events = shards.ShardResult.events

        def harvest(result, test):
            advance(result, test)
            yield from native_events(result, test)

        with (
            mock.patch.object(shards, "time", SimpleNamespace(monotonic=lambda: current_time)),
            mock.patch.object(unittest.TextTestResult, "startTest", advance),
            mock.patch.object(shards.ShardResult, "events", harvest),
        ):
            result = shards.ShardResult(io.StringIO(), True, 0, ids=[test.id()], observe=emit)
            result.scheduled_test = test
            result.position = 0
            test(result)
        self.assertEqual(python_tests._result_rows(result.records), [
            {"position": 0, "id": test.id(), "outcome": "skipped", "duration_seconds": 0.125}
        ])
