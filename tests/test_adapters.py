"""One adapter descriptor drives parsing, running, display, direction and verification."""
from __future__ import annotations

import dataclasses
import importlib
import sys
import tempfile
import unittest
from pathlib import Path

from support import GATE, baseline_text

sys.path.insert(0, str(GATE))
adapters = importlib.import_module("quality_gate.adapters")
checks = importlib.import_module("quality_gate.checks")
policy = importlib.import_module("quality_gate.policy")
ratchet = importlib.import_module("quality_gate.ratchet")


@dataclasses.dataclass(frozen=True)
class StubSpec:
    count: int


def parse_stub(
    raw: dict[str, object], root: Path, path: Path, full_key: str
) -> adapters.ParsedSpec:
    count = policy._integer(raw, "count", path, f"{full_key}.count")
    return adapters.ParsedSpec(
        StubSpec(count), "stub/1", ("tests",), threshold=0
    )


def run_stub(
    root: Path,
    config: object,
    check: policy.CheckDef,
    files: list[str],
    classes: dict[str, str],
    *,
    prefix: str,
    prior: dict[str, object],
) -> checks.CheckResult:
    count = check.spec.count
    return checks.CheckResult(
        id=check.id,
        kind="check",
        tier=check.tier,
        enforcement=check.enforcement,
        adapter=check.adapter,
        evidence=check.evidence,
        metric_version=check.metric_version,
        outcome="pass",
        execution="completed",
        duration_seconds=0.0,
        budget_seconds=600,
        threshold=check.threshold,
        baseline_path=check.baseline,
        test_results=checks.TestResults(count, count, 0),
    )


STUB = adapters.AdapterDescriptor(
    "stub",
    ("count",),
    parse_stub,
    run_stub,
    display=lambda value: f"{value:.2f}",
    directions={"floor": "min"},
    produces_tests=True,
    budget=lambda spec: 3,
)

STUB_CONFIG = """\
schema = 2

[code]
patterns = ["*.py"]
shebangs = []

[classes.python]
code = true
description = "Python source"
checks = ["stub"]

[checks.stub]
adapter = "stub"
tier = 1
enforcement = "enforced"
count = 4
"""

VERIFICATION_CONFIG = """\
schema = 2

[code]
patterns = ["*.py"]
shebangs = []

[classes.python]
code = true
description = "Python source"
checks = ["stub", "verification"]

[checks.stub]
adapter = "stub"
tier = 1
enforcement = "enforced"
count = 4

[checks.verification]
adapter = "verification"
tier = 1
enforcement = "enforced"
baseline = "verification.toml"
"""


class StubAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        adapters.register_adapter(STUB)
        self.addCleanup(adapters.remove_adapter, "stub")
        temporary = tempfile.TemporaryDirectory(prefix="qg-stub-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "a.py").write_text("VALUE = 1\n", encoding="utf-8")

    def config(self, text: str) -> policy.Config:
        (self.root / "quality-gate.toml").write_text(text, encoding="utf-8")
        return policy.load_config(self.root)

    def test_stub_is_parsed_run_and_displayed_through_the_registry(self) -> None:
        config = self.config(STUB_CONFIG)
        check = config.checks["stub"]
        self.assertEqual(check.spec, StubSpec(4))
        self.assertEqual(check.threshold, 0)

        result = checks.run_check(
            self.root,
            config,
            check,
            ["a.py"],
            {"a.py": "python"},
            prefix="check: stub",
        )
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.test_results, checks.TestResults(4, 4, 0))
        self.assertEqual(ratchet._display_number(2.5, "stub"), "2.50")

    def test_verification_uses_every_adapter_that_produces_tests(self) -> None:
        config = self.config(VERIFICATION_CONFIG)
        (self.root / "verification.toml").write_text(
            baseline_text(
                [{
                    "subject": "tests:stub:executed",
                    "bound": 4,
                    "reason": "stub floor",
                }],
                check="verification",
                metric_version="verification/1",
            ),
            encoding="utf-8",
        )
        files = ["a.py"]
        classes = {"a.py": "python"}
        stub = checks.run_check(
            self.root, config, config.checks["stub"], files, classes,
            prefix="check: stub",
        )
        verification = checks.run_check(
            self.root, config, config.checks["verification"], files, classes,
            prefix="check: verification", prior={"stub": stub},
        )
        self.assertEqual(verification.outcome, "pass", verification.reason)
        self.assertTrue(verification.is_satisfied())
        self.assertIn(
            "tests:stub:executed",
            [finding.subject for finding in verification.findings],
        )

    def test_direction_uses_the_finding_kind_not_its_subject(self) -> None:
        entry = ratchet.BaselineEntry("tests:tests:executed", 4, "floor")
        maximum = ratchet.Finding(
            "tests:tests:executed", 5, "test summary", kind="metric"
        )
        result = ratchet.evaluate(
            [maximum],
            [entry],
            threshold=0,
            enforcement="enforced",
            prefix="check: verification",
            adapter="verification",
            domain=ratchet.Domain.all(),
        )
        self.assertEqual(result.findings[0].direction, "max")
        self.assertTrue(result.findings[0].blocking)

        minimum = ratchet.Finding(
            "not-a-test-subject", 5, "test summary", kind="executed"
        )
        result = ratchet.evaluate(
            [minimum],
            [ratchet.BaselineEntry("not-a-test-subject", 4, "floor")],
            threshold=0,
            enforcement="enforced",
            prefix="check: verification",
            adapter="verification",
            domain=ratchet.Domain.all(),
        )
        self.assertEqual(result.findings[0].direction, "min")
        self.assertFalse(result.findings[0].blocking)

    def test_descriptor_directions_apply_to_registered_kinds(self) -> None:
        entry = ratchet.BaselineEntry("subject", 4, "floor")
        result = ratchet.evaluate(
            [ratchet.Finding("subject", 5, "file:1", kind="floor")],
            [entry],
            threshold=0,
            enforcement="enforced",
            prefix="check: stub",
            adapter=STUB,
            domain=ratchet.Domain.all(),
        )
        self.assertEqual(result.findings[0].direction, "min")
        self.assertFalse(result.findings[0].blocking)


if __name__ == "__main__":
    unittest.main()
