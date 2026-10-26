"""Tests for the verification-loss adapter and its ratcheted metrics."""
from __future__ import annotations

import json
import unittest

from support import (
    PYTHON_COMMON_RULE_LINES,
    PYTHON_TEST_HEADER,
    FixtureCase,
    baseline_text,
    output,
)
from test_trust import TrustCase

BASELINE = "quality-gate-verification.toml"
METRIC_VERSION = "verification/1"
ADOPTION_REASON = "measured at adoption (M2c, 2026-10-25)"
NO_COVER = "# pragma: " "no cover"


def noqa_source(count: int) -> str:
    return "".join(
        f"VALUE_{index} = {index}  # noqa: E501\n"
        for index in range(count)
    )


class FindingMixin:
    def finding(
        self, check: dict[str, object], subject: str
    ) -> dict[str, object]:
        for item in check["findings"]:
            if item["subject"] == subject:
                return item
        self.fail(f"no finding {subject!r} in {check['findings']!r}")


def verification_config(
    *,
    baseline: str = BASELINE,
    requires: str | None = "tests",
) -> str:
    lines = [
        "schema = 2",
        "",
        "[code]",
        'patterns = ["*.py"]',
        'shebangs = ["python*"]',
        "",
        "[levels]",
        "required_tiers = [1]",
        "",
        "[classes.python]",
        "code = true",
        'description = "Python source"',
        'checks = ["tests", "verification"]',
        "",
        "[classes.test]",
        "code = true",
        'description = "Python tests"',
        'checks = ["tests", "verification"]',
        "",
        "[classes.config]",
        "code = false",
        'description = "Configuration"',
        "",
        "[classes.doc]",
        "code = false",
        'description = "Documentation"',
        "",
        "[checks.tests]",
        'adapter = "python_tests"',
        "tier = 1",
        'enforcement = "enforced"',
        'run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]',
        f"tests_pattern = {json.dumps(r'^Ran (\d+) tests? in')}",
        f"skipped_pattern = {json.dumps(r'skipped=(\d+)')}",
        "",
        "[checks.verification]",
        'adapter = "verification"',
        "tier = 1",
        'enforcement = "enforced"',
    ]
    if requires is not None:
        lines.append(f"requires = {json.dumps(requires)}")
    lines.append(f'baseline = "{baseline}"')
    lines.extend(
        [
            "",
            "[[rule]]",
            'pattern = "tests/*.py"',
            'class = "test"',
            'reason = "tests"',
            "",
            "[[rule]]",
            'pattern = "pkg/*.py"',
            'class = "python"',
            'reason = "source"',
        ]
    )
    lines.extend(PYTHON_COMMON_RULE_LINES)
    return "\n".join(lines)


def verification_baseline(entries: list[dict[str, object]]) -> str:
    return baseline_text(
        entries, check="verification", metric_version=METRIC_VERSION
    )


def executed_entry(bound: int) -> dict[str, object]:
    return {
        "subject": "tests:tests:executed",
        "bound": bound,
        "reason": ADOPTION_REASON,
    }


def skipped_entry(bound: int) -> dict[str, object]:
    return {
        "subject": "tests:tests:skipped",
        "bound": bound,
        "reason": ADOPTION_REASON,
    }


def exclusion_entry(
    relative: str, metric: str, bound: int
) -> dict[str, object]:
    return {
        "subject": f"exclusions:{relative}:{metric}",
        "bound": bound,
        "reason": ADOPTION_REASON,
    }


class VerificationTests(FindingMixin, FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.add_file("pkg/__init__.py", "")
        self.add_file("pkg/mod.py", "VALUE = 1\n")
        self.write_config(verification_config())

    def add_tests(self, count: int) -> None:
        body = "".join(
            f"    def test_{index}(self):\n"
            "        self.assertTrue(True)\n\n"
            for index in range(count)
        )
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER
            + "\nclass Sample(unittest.TestCase):\n"
            + body,
        )

    def write_verification_baseline(
        self, entries: list[dict[str, object]]
    ) -> None:
        self.add_file(BASELINE, verification_baseline(entries))

    def empty_verification_baseline(self) -> None:
        self.add_file(
            BASELINE,
            f'check = "verification"\nmetric_version = "{METRIC_VERSION}"\n',
        )

    def run_verification(
        self, *args: str
    ) -> tuple[object, dict[str, object], dict[str, object]]:
        result, document = self.run_json(
            *args, env=self.default_tool_env()
        )
        return result, document, self.check_by_id(document, "verification")

    def failed_verification(
        self, *args: str
    ) -> tuple[object, dict[str, object], dict[str, object]]:
        result, document, check = self.run_verification(*args)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(check["outcome"], "fail")
        return result, document, check

    def test_deleted_test_lowers_executed_below_its_floor(self) -> None:
        self.add_tests(2)
        self.write_verification_baseline([executed_entry(2)])
        result, _document, check = self.run_verification()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")

        self.add_tests(1)
        result, _document, check = self.failed_verification()
        finding = self.finding(check, "tests:tests:executed")
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["bound"], 2)
        self.assertIn("falls below baseline bound 2", result.stderr)

    def test_added_skip_raises_skipped_above_its_ceiling(self) -> None:
        self.add_tests(2)
        self.write_verification_baseline([executed_entry(1)])
        body = (
            "    @unittest.skip('deliberate')\n"
            "    def test_0(self):\n"
            "        self.assertTrue(True)\n\n"
            "    def test_1(self):\n"
            "        self.assertTrue(True)\n"
        )
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER
            + "\nclass Sample(unittest.TestCase):\n"
            + body,
        )
        result, _document, check = self.failed_verification()
        finding = self.finding(check, "tests:tests:skipped")
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["bound"], None)
        self.assertIn("exceeds threshold 0", result.stderr)
        executed = self.finding(check, "tests:tests:executed")
        self.assertEqual(executed["value"], 1)
        self.assertTrue(executed["covered_by_baseline"])

    def test_added_no_cover_pragma_fails(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/mod.py",
            f"VALUE = 1\nOTHER = 2  {NO_COVER}\n",
        )
        result, _document, check = self.failed_verification()
        finding = self.finding(
            check, "exclusions:pkg/mod.py:no-cover"
        )
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["bound"], None)
        self.assertIn("exclusions:pkg/mod.py:no-cover", result.stderr)

    def test_added_noqa_comment_fails(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/mod.py",
            "import os  # noqa: F401\nVALUE = 1\n",
        )
        result, _document, check = self.failed_verification()
        finding = self.finding(check, "exclusions:pkg/mod.py:noqa")
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["bound"], None)
        self.assertIn("exclusions:pkg/mod.py:noqa", result.stderr)

    def test_prune_raises_the_executed_floor(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_tests(2)
        result, document, check = self.run_verification(
            "--prune", "verification"
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        self.assertTrue(document["prune"]["performed"])
        text = self.read_file(BASELINE)
        self.assertIn('subject = "tests:tests:executed"', text)
        self.assertIn("bound = 2", text)

    def test_prune_lowers_the_noqa_ceiling(self) -> None:
        self.add_tests(1)
        self.add_file(
            "pkg/mod.py",
            "VALUE = 1  # noqa: E501\nOTHER = 2  # noqa: E501\n",
        )
        self.write_verification_baseline(
            [
                executed_entry(1),
                exclusion_entry("pkg/mod.py", "noqa", 2),
            ]
        )
        self.add_file(
            "pkg/mod.py",
            "VALUE = 1  # noqa: E501\nOTHER = 2\n",
        )
        result, document, check = self.run_verification(
            "--prune", "verification"
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(check["satisfied"], output(result))
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        self.assertTrue(document["prune"]["performed"])
        text = self.read_file(BASELINE)
        self.assertIn('subject = "exclusions:pkg/mod.py:noqa"', text)
        self.assertIn("bound = 1", text)

    def test_min_metric_without_a_baseline_entry_is_unmeasured(self) -> None:
        self.add_tests(1)
        self.empty_verification_baseline()
        result, _document, check = self.failed_verification()
        self.assertEqual(
            check["unmeasured_baseline_entries"],
            ["tests:tests:executed"],
        )
        finding = self.finding(check, "tests:tests:executed")
        self.assertEqual(
            finding["error"],
            "unmeasured: no baseline entry for a min metric",
        )
        self.assertIn("unmeasured: no baseline entry", result.stderr)


class VerificationTrustTests(FindingMixin, TrustCase):
    def prepare(
        self,
        *,
        tests: int,
        noqa: int,
        floor: int,
        ceiling: int,
    ) -> str:
        (self.repo / "a.py").unlink()
        self.add_file("pkg/__init__.py", "")
        self.add_file("pkg/mod.py", noqa_source(noqa))
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER
            + "\nclass Sample(unittest.TestCase):\n"
            + "".join(
                f"    def test_{index}(self):\n"
                "        self.assertTrue(True)\n\n"
                for index in range(tests)
            ),
        )
        self.write_config(verification_config())
        self.add_file(
            BASELINE,
            verification_baseline(
                [
                    executed_entry(floor),
                    exclusion_entry("pkg/mod.py", "noqa", ceiling),
                ]
            ),
        )
        return self.commit_revision()

    def candidate(
        self, revision: str, floor: int, ceiling: int
    ) -> dict[str, object]:
        self.add_file(
            BASELINE,
            verification_baseline(
                [
                    executed_entry(floor),
                    exclusion_entry("pkg/mod.py", "noqa", ceiling),
                ]
            ),
        )
        result, document = self.trust_json(
            revision, env=self.default_tool_env()
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        return document

    def bounds(
        self,
        document: dict[str, object],
        executed: tuple[int, int],
        noqa: tuple[int, int],
    ) -> None:
        check = self.check_by_id(document, "verification")
        executed_finding = self.finding(
            check, "tests:tests:executed"
        )
        noqa_finding = self.finding(
            check, "exclusions:pkg/mod.py:noqa"
        )
        self.assertEqual(
            (executed_finding["value"], executed_finding["bound"]),
            executed,
        )
        self.assertEqual(
            (noqa_finding["value"], noqa_finding["bound"]), noqa
        )

    def test_candidate_lowered_floor_and_raised_ceiling_are_ignored(
        self,
    ) -> None:
        revision = self.prepare(
            tests=2, noqa=2, floor=2, ceiling=2
        )
        self.add_file("pkg/mod.py", noqa_source(3))
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER
            + "\nclass Sample(unittest.TestCase):\n"
            "    def test_0(self):\n"
            "        self.assertTrue(True)\n",
        )
        document = self.candidate(revision, 1, 5)
        entry = self.protected(document, BASELINE)
        self.assertEqual(entry["status"], "ignored")
        self.assertEqual(
            set(entry["ignored_entries"]),
            {
                "tests:tests:executed",
                "exclusions:pkg/mod.py:noqa",
            },
        )
        self.bounds(document, (1, 2), (3, 2))

    def test_candidate_removed_floor_keeps_the_trusted_entry(self) -> None:
        revision = self.prepare(tests=2, noqa=2, floor=2, ceiling=2)
        self.add_file(
            BASELINE,
            verification_baseline(
                [exclusion_entry("pkg/mod.py", "noqa", 2)]
            ),
        )
        result, document = self.trust_json(
            revision, env=self.default_tool_env()
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        check = self.check_by_id(document, "verification")
        self.assertTrue(check["satisfied"])
        entry = self.protected(document, BASELINE)
        self.assertEqual(entry["status"], "ignored")
        self.assertEqual(
            entry["ignored_entries"], ["tests:tests:executed"]
        )
        finding = self.finding(check, "tests:tests:executed")
        self.assertEqual(finding["bound"], 2)
        self.assertNotIn("error", finding)

    def test_candidate_raised_floor_and_lowered_ceiling_are_applied(
        self,
    ) -> None:
        revision = self.prepare(
            tests=1, noqa=3, floor=1, ceiling=5
        )
        self.add_file("pkg/mod.py", noqa_source(4))
        document = self.candidate(revision, 2, 3)
        entry = self.protected(document, BASELINE)
        self.assertEqual(entry["status"], "tightened")
        self.bounds(document, (1, 2), (4, 3))


if __name__ == "__main__":
    unittest.main()
