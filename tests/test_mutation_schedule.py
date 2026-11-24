"""Mutation testing of this repository runs on demand."""
from __future__ import annotations

import re
import unittest

from support import GATE

from quality_gate import policy


class MutationScheduleTests(unittest.TestCase):
    def test_mutation_on_demand_policy_has_no_mutation_adapter(self) -> None:
        config = policy.load_config(GATE)
        self.assertEqual(
            [check.id for check in config.checks.values() if check.adapter == "python_mutation"],
            [],
        )

    def test_mutation_on_demand_workflow_jobs_require_manual_dispatch(self) -> None:
        """Match job headers and inline or block run steps by workflow indentation."""
        workflow = (GATE / ".github" / "workflows" / "check.yml").read_text(encoding="utf-8")
        _, _, jobs = workflow.partition("\njobs:\n")
        mutation_jobs = []
        for job in re.split(r"(?m)(?=^  [\w-]+: *$)", jobs):
            run_steps = re.findall(r"(?m)^        run:([^\n]*(?:\n {10,}[^\n]*)*)", job)
            if any(re.search(r"\bmake[ \t]+mutation\b", step) for step in run_steps):
                mutation_jobs.append(job)
        self.assertTrue(mutation_jobs, "Expected a CI job that runs make mutation")
        for job in mutation_jobs:
            with self.subTest(job=job.splitlines()[0].strip()):
                self.assertEqual(
                    re.findall(r"(?m)^    if: *(.*)$", job),
                    ["github.event_name == 'workflow_dispatch'"],
                )
