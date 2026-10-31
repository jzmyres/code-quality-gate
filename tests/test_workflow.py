"""CI timeouts follow measured step durations and the applicable job workload."""

import re
import unittest
from pathlib import Path
from unittest.mock import patch


def blocks(text: str, pattern: str) -> list[tuple[str, str]]:
    """Split only the fixed indentation used by check.yml, without a YAML dependency."""
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    ends = [match.start() for match in matches[1:]] + [len(text)]
    return [(match[1], text[match.start():end]) for match, end in zip(matches, ends, strict=False)]


class WorkflowTimeoutTests(unittest.TestCase):
    def setUp(self) -> None:
        path = Path(__file__).resolve().parents[1] / ".github/workflows/check.yml"
        workflow = path.read_text(encoding="utf-8")
        self.jobs = blocks(workflow.split("jobs:\n", 1)[1], r"^  ([\w-]+):$")
        self.assertTrue(self.jobs, "expected workflow jobs, actual none")

    def step_bounds(self, job: str) -> list[tuple[str, str, int]]:
        bounds = []
        steps = job.split("    steps:\n", 1)[1]
        for position, (_first, step) in enumerate(blocks(steps, r"^      - (.*)$"), 1):
            timeout = re.search(r"^(?:      - |        )timeout-minutes: (.+)$", step, re.MULTILINE)
            if timeout is not None:
                name = re.search(r"^(?:      - |        )name: (.+)$", step, re.MULTILINE)
                label = name[1] if name else f"step {position}"
                bounds.append((label, step, int(timeout[1])))
        return bounds

    def test_step_timeouts_follow_measurements(self) -> None:
        for job_name, job in self.jobs:
            for name, step, actual in self.step_bounds(job):
                with self.subTest(job=job_name, step=name):
                    comments = "\n".join(re.findall(r"^        #.*$", step, re.MULTILINE))
                    measured = re.findall(r"\bMeasured (\d+) s\b", comments)
                    self.assertTrue(
                        measured, f"{name}: expected measurement in seconds, actual missing")
                    expected = ((3 * max(map(int, measured)) + 299) // 300) * 5
                    self.assertEqual(actual, expected,
                                     f"{name}: expected {expected} minutes, actual {actual}")

    def test_job_timeouts_sum_applicable_steps_and_setup(self) -> None:
        for job_name, job in self.jobs:
            header = job.split("    steps:\n", 1)[0]
            allowance = re.search(r"^    #.*setup allowance (\d+) minutes", header, re.MULTILINE)
            self.assertIsNotNone(
                allowance, f"{job_name}: expected setup allowance in minutes, actual missing")
            timeout = re.search(r"^    timeout-minutes: (.+)$", header, re.MULTILINE)
            self.assertIsNotNone(timeout, f"{job_name}: expected job timeout, actual missing")
            entries = blocks(header, r"^          - name: (.+)$")
            if entries:
                self.assertEqual(timeout[1], "${{ matrix.timeout }}", job_name)
            else:
                entries = [(job_name, header)]
            for name, entry in entries:
                with self.subTest(job=job_name, entry=name):
                    expected = int(allowance[1])
                    for _label, step, bound in self.step_bounds(job):
                        only = re.search(
                            r"^(?:      - |        )if: matrix\.name == '([^']+)'", step, re.MULTILINE)
                        if only is None or only[1] == name:
                            expected += bound
                    value = re.search(r"^            timeout: (.+)$", entry, re.MULTILINE) if (
                        timeout[1] == "${{ matrix.timeout }}") else timeout
                    self.assertIsNotNone(value, f"{job_name}/{name}: expected timeout, actual missing")
                    actual = int(value[1])
                    self.assertEqual(actual, expected,
                                     f"{job_name}/{name}: expected {expected} minutes, actual {actual}")


class WorkflowBoundaryTests(unittest.TestCase):
    def check_workflow(self, step: str, job_timeout: int, method: str) -> unittest.TestResult:
        workflow = (
            "jobs:\n"
            "  example:\n"
            "    # setup allowance 10 minutes\n"
            f"    timeout-minutes: {job_timeout}\n"
            "    steps:\n"
            "      - name: Previous step\n"
            "        # Measured 60 s\n"
            "        timeout-minutes: 5\n"
            "        run: echo previous\n"
            "      - run: echo untimed\n"
            f"{step}"
        )
        result = unittest.TestResult()
        with patch.object(Path, "read_text", return_value=workflow):
            WorkflowTimeoutTests(method).run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.skipped, [])
        return result

    def test_unnamed_timeout_requires_measurement(self) -> None:
        result = self.check_workflow(
            "      - run: sleep 900\n"
            "        timeout-minutes: 1\n",
            15, "test_step_timeouts_follow_measurements")
        self.assertEqual(len(result.failures), 1)
        failed_test, traceback = result.failures[0]
        failure = f"{failed_test}\n{traceback}"
        self.assertIn("job='example'", failure)
        self.assertIn("step='step 3'", failure)
        self.assertIn("expected measurement in seconds, actual missing", failure)

    def test_timeout_uses_largest_measurement_in_any_order(self) -> None:
        for earlier, later in ((592, 641), (641, 592)):
            for actual in (30, 35):
                with self.subTest(earlier=earlier, later=later, actual=actual):
                    result = self.check_workflow(
                        "      - name: Run the gate\n"
                        f"        # Measured {earlier} s\n"
                        f"        # Measured {later} s\n"
                        f"        timeout-minutes: {actual}\n",
                        actual + 15, "test_step_timeouts_follow_measurements")
                    if actual == 30:
                        self.assertEqual(len(result.failures), 1)
                        self.assertIn("Run the gate: expected 35 minutes, actual 30",
                                      result.failures[0][1])
                    else:
                        self.assertEqual(result.failures, [])

    def test_unnamed_measured_timeout_counts_in_job_sum(self) -> None:
        for first in ("run: sleep 60", "id: unnamed", "uses: example/action@v1",
                      "if: matrix.name == 'example'", "timeout-minutes: 5"):
            with self.subTest(first=first):
                step = f"      - {first}\n        # Measured 60 s\n"
                if first != "timeout-minutes: 5":
                    step += "        timeout-minutes: 5\n"
                for method in ("test_step_timeouts_follow_measurements",
                               "test_job_timeouts_sum_applicable_steps_and_setup"):
                    result = self.check_workflow(step, 20, method)
                    self.assertEqual(result.failures, [])
