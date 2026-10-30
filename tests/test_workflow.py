"""CI timeouts follow measured step durations and the applicable job workload."""

import re
import unittest
from pathlib import Path


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

    def step_bounds(self, job: str) -> list[tuple[str, int]]:
        bounds = []
        for _name, step in blocks(job, r"^      - (?:name|uses): (.+)$"):
            timeout = re.search(r"^        timeout-minutes: (.+)$", step, re.MULTILINE)
            if timeout is not None:
                bounds.append((step, int(timeout[1])))
        return bounds

    def test_step_timeouts_follow_measurements(self) -> None:
        for job_name, job in self.jobs:
            for step, actual in self.step_bounds(job):
                name = step.splitlines()[0].strip().removeprefix("- name: ")
                with self.subTest(job=job_name, step=name):
                    comments = "\n".join(re.findall(r"^        #.*$", step, re.MULTILINE))
                    measured = re.search(r"\bMeasured (\d+) s\b", comments)
                    self.assertIsNotNone(
                        measured, f"{name}: expected measurement in seconds, actual missing")
                    expected = ((3 * int(measured[1]) + 299) // 300) * 5
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
                    for step, bound in self.step_bounds(job):
                        only = re.search(r"^        if: matrix\.name == '([^']+)'", step, re.MULTILINE)
                        if only is None or only[1] == name:
                            expected += bound
                    value = re.search(r"^            timeout: (.+)$", entry, re.MULTILINE) if (
                        timeout[1] == "${{ matrix.timeout }}") else timeout
                    self.assertIsNotNone(value, f"{job_name}/{name}: expected timeout, actual missing")
                    actual = int(value[1])
                    self.assertEqual(actual, expected,
                                     f"{job_name}/{name}: expected {expected} minutes, actual {actual}")
