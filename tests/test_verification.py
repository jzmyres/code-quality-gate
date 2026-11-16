"""Tests for the verification-loss adapter and its ratcheted metrics."""
from __future__ import annotations

import json
import os
import re
import sys
import unittest
from pathlib import Path

from support import (
    PYTHON_COMMON_RULE_LINES,
    PYTHON_TEST_HEADER,
    FixtureCase,
    baseline_text,
    output,
)
from test_trust import TrustCase

from quality_gate.policy import load_config
from quality_gate.verification import measure_exclusions

BASELINE = "quality-gate-verification.toml"
METRIC_VERSION = "verification/1"
ADOPTION_REASON = "measured at adoption (M2c, 2026-10-25)"


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


def verification_with_crap_config() -> str:
    text = verification_config()
    text = text.replace(
        'checks = ["tests", "verification"]',
        'checks = ["tests", "crap", "verification"]',
        1,
    )
    block = (
        "[checks.crap]\n"
        'adapter = "python_crap"\n'
        "tier = 1\n"
        'enforcement = "enforced"\n'
        'requires = "tests"\n'
        'baseline = "quality-gate-crap.toml"\n'
        "\n"
    )
    return text.replace("[checks.verification]", block + "[checks.verification]", 1)


def crap_check_block(identifier: str, baseline: str) -> str:
    return (
        f"[checks.{identifier}]\n"
        'adapter = "python_crap"\n'
        "tier = 1\n"
        'enforcement = "enforced"\n'
        'requires = "tests"\n'
        f'baseline = "{baseline}"\n'
        "\n"
    )


def verification_with_crap_after_config() -> str:
    """A verification policy whose python_crap check is declared after it."""
    text = verification_config().replace(
        'checks = ["tests", "verification"]',
        'checks = ["tests", "crap", "verification"]',
        1,
    )
    return text.replace(
        "[[rule]]",
        crap_check_block("crap", "quality-gate-crap.toml") + "[[rule]]",
        1,
    )


def verification_with_later_tests_and_crap_config() -> str:
    """A policy whose verification is followed by a test and a CRAP check."""
    text = verification_config(requires=None).replace(
        'checks = ["tests", "verification"]',
        'checks = ["tests", "tests2", "crap", "verification"]',
        1,
    )
    tests2 = (
        "[checks.tests2]\n"
        'adapter = "python_tests"\n'
        "tier = 1\n"
        'enforcement = "enforced"\n'
        'run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]\n'
        f"tests_pattern = {json.dumps(r'^Ran (\d+) tests? in')}\n"
        f"skipped_pattern = {json.dumps(r'skipped=(\d+)')}\n\n"
    )
    crap = crap_check_block("crap", "quality-gate-crap.toml").replace(
        'requires = "tests"', 'requires = "tests2"'
    )
    return text.replace("[[rule]]", tests2 + crap + "[[rule]]", 1)


def verification_with_two_crap_config() -> str:
    text = verification_with_crap_config().replace(
        'checks = ["tests", "crap", "verification"]',
        'checks = ["tests", "crap", "crap2", "verification"]',
        1,
    )
    return text.replace(
        "[checks.verification]",
        crap_check_block("crap2", "quality-gate-crap2.toml")
        + "[checks.verification]",
        1,
    )


def with_crap_only_class(text: str) -> str:
    classes = (
        "[classes.crap-only]\n"
        "code = true\n"
        'description = "Measured only by CRAP"\n'
        'checks = ["tests", "crap"]\n'
        "\n"
    )
    rule = (
        "[[rule]]\n"
        'pattern = "lib/*.py"\n'
        'class = "crap-only"\n'
        'reason = "only CRAP measures it"\n'
        "\n"
    )
    text = text.replace("[classes.config]", classes + "[classes.config]", 1)
    return text.replace("[[rule]]", rule + "[[rule]]", 1)


def with_pyw_pattern(text: str) -> str:
    text = text.replace(
        'patterns = ["*.py"]', 'patterns = ["*.py", "*.pyw"]', 1
    )
    rule = (
        "[[rule]]\n"
        'pattern = "*.pyw"\n'
        'class = "python"\n'
        'reason = "windowed Python program"\n'
        "\n"
    )
    return text.replace("[[rule]]", rule + "[[rule]]", 1)


def rewriting_config(rewrite: str) -> str:
    """A verification policy with a command check that runs before the tests."""
    text = verification_config()
    block = (
        "[checks.rewrite]\n"
        'adapter = "command"\n'
        "tier = 1\n"
        'enforcement = "enforced"\n'
        f"run = {json.dumps([sys.executable, '-c', rewrite])}\n"
        f"tests_pattern = {json.dumps(r'(\d+)')}\n"
        "\n"
    )
    text = text.replace("[checks.tests]", block + "[checks.tests]")
    return text.replace(
        'checks = ["tests", "verification"]',
        'checks = ["rewrite", "tests", "verification"]',
    )


def verification_baseline(entries: list[dict[str, object]]) -> str:
    return baseline_text(
        entries, check="verification", metric_version=METRIC_VERSION
    )


def multi_verification_config() -> str:
    extra = (
        '[checks.second]\nadapter = "verification"\ntier = 1\n'
        'enforcement = "enforced"\nrequires = "tests"\n'
        'baseline = "second.toml"\n\n'
    )
    return verification_config().replace(
        'checks = ["tests", "verification"]',
        'checks = ["tests", "verification", "second"]',
    ).replace("[[rule]]", extra + "[[rule]]", 1)


def second_baseline(bound: int) -> str:
    return baseline_text(
        [executed_entry(bound)], check="second", metric_version=METRIC_VERSION
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


def prepare_multiple_prune(case: FixtureCase) -> None:
    (case.repo / "a.py").unlink()
    case.write_config(multi_verification_config())
    case.add_file("pkg/mod.py", "VALUE = 1\n")
    case.add_file(
        "tests/test_sample.py",
        PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n"
        "    def test_one(self): self.assertTrue(True)\n"
        "    def test_two(self): self.assertTrue(True)\n",
    )
    case.add_file(BASELINE, verification_baseline([executed_entry(1)]))
    case.add_file("second.toml", second_baseline(1))


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

    def enable_crap(self, config: str | None = None) -> None:
        self.write_config(
            verification_with_crap_config() if config is None else config
        )
        self.add_file(
            "quality-gate-crap.toml",
            baseline_text([], check="crap", metric_version="python-lines/1"),
        )

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

    def command_producer(self, summary: str, *, requires: str | None = None) -> None:
        self.add_tests(1)
        text = verification_config(requires=requires).replace(
            'adapter = "python_tests"', 'adapter = "command"'
        ).replace(
            'run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]',
            f"run = {json.dumps([sys.executable, '-c', f'print({summary!r})'])}",
        )
        self.write_config(text)

    def test_command_producer_feeds_implicit_verification_counts_and_floor(self) -> None:
        self.command_producer("Ran 3 tests in 0.1s\nskipped=1")
        self.write_verification_baseline([executed_entry(2), skipped_entry(1)])
        result, document, check = self.run_verification()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.check_by_id(document, "tests")["outcome"], "pass")
        self.assertEqual(self.finding(check, "tests:tests:executed")["value"], 2)
        self.assertEqual(self.finding(check, "tests:tests:skipped")["value"], 1)

        self.command_producer("Ran 2 tests in 0.1s\nskipped=1")
        result, document, check = self.failed_verification()
        self.assertEqual(self.check_by_id(document, "tests")["outcome"], "pass")
        finding = self.finding(check, "tests:tests:executed")
        self.assertEqual((finding["value"], finding["bound"]), (1, 2))
        self.assertIn("tests:tests:executed: value 1 falls below baseline bound 2", result.stderr)

    def test_verification_requires_accepts_command_producer(self) -> None:
        self.command_producer("Ran 1 test in 0.1s", requires="tests")
        self.write_verification_baseline([executed_entry(1)])
        result, _document, check = self.run_verification()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.finding(check, "tests:tests:executed")["value"], 1)
        self.assertEqual(self.finding(check, "tests:tests:skipped")["value"], 0)

    def test_unmatched_command_summary_leaves_verification_unmeasured(self) -> None:
        self.command_producer("no test summary")
        self.write_verification_baseline([executed_entry(1)])
        result, document, check = self.run_verification()
        self.assertEqual(result.returncode, 1, output(result))
        producer = self.check_by_id(document, "tests")
        self.assertEqual(producer["outcome"], "unsupported")
        self.assertIn("tests_pattern", producer["reason"])
        self.assertIn("did not match", producer["reason"])
        self.assertNotIn("measurement", producer)
        self.assertEqual(check["outcome"], "unsupported")
        self.assertEqual(check["findings"], [])
        self.assertNotIn("measurement", check)
        self.assertIn("test counts unreliable: tests did not pass", check["reason"])

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

    def test_verification_ceiling_accepts_the_bound_and_rejects_an_increase(self) -> None:
        self.add_tests(1)
        self.add_file("pkg/mod.py", noqa_source(1))
        self.write_verification_baseline([executed_entry(1), exclusion_entry("pkg/mod.py", "noqa", 1)])
        result, document, check = self.run_verification()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        self.assertTrue(self.finding(check, "exclusions:pkg/mod.py:noqa")["covered_by_baseline"])

        self.add_file("pkg/mod.py", noqa_source(2))
        result, _document, check = self.failed_verification()
        finding = self.finding(check, "exclusions:pkg/mod.py:noqa")
        self.assertEqual((finding["value"], finding["bound"]), (2, 1))
        self.assertIn("baseline bound 1", result.stderr)

    def test_added_no_cover_pragma_fails(self) -> None:
        self.enable_crap()
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/mod.py",
            "VALUE = 1\nOTHER = 2  # pragma: no cover\n",
        )
        result, _document, check = self.failed_verification()
        finding = self.finding(
            check, "exclusions:pkg/mod.py:no-cover"
        )
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["bound"], None)
        self.assertIn("exclusions:pkg/mod.py:no-cover", result.stderr)

    def test_no_cover_counts_only_files_a_crap_check_measures(self) -> None:
        self.enable_crap()
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/mod.py",
            "VALUE = 1\n"
            "COMMENT = 2  # pragma: no cover\n"
            "TEXT = 'pragma: no cover'\n",
        )
        self.add_file(
            "tests/test_sample.py",
            self.read_file("tests/test_sample.py").replace(
                "class Sample",
                "MARKER = '# pragma: no cover'\n"
                "TEXT = 'pragma: no cover'\n\n"
                "class Sample",
            ),
        )
        result, _document, check = self.failed_verification()
        self.assertIn("exclusions:pkg/mod.py:no-cover", result.stderr)
        self.assertEqual(
            self.finding(check, "exclusions:pkg/mod.py:no-cover")["value"], 1
        )
        self.assertFalse(
            [
                item
                for item in check["findings"]
                if item["subject"] == "exclusions:tests/test_sample.py:no-cover"
            ]
        )

    def test_a_production_string_with_the_pragma_is_counted(self) -> None:
        self.enable_crap()
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/mod.py",
            "VALUE = 1\n"
            'MARKER = "# pragma: no cover"\n',
        )
        result, _document, check = self.failed_verification()
        self.assertIn("exclusions:pkg/mod.py:no-cover", result.stderr)
        self.assertEqual(
            self.finding(check, "exclusions:pkg/mod.py:no-cover")["value"], 1
        )

    def test_the_exclusion_pattern_does_not_match_its_own_definition(self) -> None:
        from quality_gate import coverage_tool

        definition = next(
            line
            for line in Path(coverage_tool.__file__).read_text(
                encoding="utf-8"
            ).splitlines()
            if line.startswith("PRAGMA_NO_COVER =")
        )
        self.assertIsNone(re.search(coverage_tool.PRAGMA_NO_COVER, definition))

    def test_the_exclusion_pattern_stays_on_one_line(self) -> None:
        from quality_gate.coverage_tool import PRAGMA_NO_COVER

        source = 'VALUE = """#\npragma: no cover"""\n'
        self.assertIsNone(re.search(PRAGMA_NO_COVER, source))
        self.assertIsNotNone(
            re.search(PRAGMA_NO_COVER, "VALUE = 1  # pragma: no cover\n")
        )

    def test_a_multiline_string_does_not_cross_the_exclusion_pattern(self) -> None:
        self.enable_crap()
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/blocks.py",
            "def with_block():\n"
            "    value = 1\n"
            '    text = """#\npragma: no cover"""\n'
            "    return value + len(text)\n",
        )
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n"
            "    def test_block(self):\n"
            "        import pkg.blocks\n"
            "        self.assertTrue(pkg.blocks.with_block())\n",
        )
        result, document, check = self.run_verification()
        excluded = sorted({
            line
            for finding in self.check_by_id(document, "crap")["findings"]
            for line in finding.get("measurement", {}).get("excluded_lines", [])
        })
        finding = self.finding(check, "exclusions:pkg/blocks.py:no-cover")
        self.assertEqual(finding["value"], len(excluded))
        if excluded:
            self.assertEqual(result.returncode, 1, output(result))
            self.assertIn("exclusions:pkg/blocks.py:no-cover", result.stderr)
        else:
            self.assertEqual(result.returncode, 0, output(result))

    def test_a_crap_only_file_counts_its_no_cover_lines(self) -> None:
        self.enable_crap(with_crap_only_class(verification_with_crap_config()))
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "lib/hidden.py",
            "def hidden():\n"
            "    value = 1  # noqa: E501\n"
            "    return value  # pragma: no cover\n",
        )
        result, _document, check = self.failed_verification()
        finding = self.finding(check, "exclusions:lib/hidden.py:no-cover")
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["bound"], None)
        self.assertIn("exclusions:lib/hidden.py:no-cover", result.stderr)
        self.assertFalse(
            [
                item
                for item in check["findings"]
                if item["subject"] == "exclusions:lib/hidden.py:noqa"
            ]
        )

    def test_a_pyw_file_counts_its_no_cover_lines(self) -> None:
        self.enable_crap(with_pyw_pattern(verification_with_crap_config()))
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/windowed.pyw",
            "def windowed():\n"
            "    value = 1  # noqa: E501\n"
            "    return value  # pragma: no cover\n",
        )
        result, _document, check = self.failed_verification()
        finding = self.finding(check, "exclusions:pkg/windowed.pyw:no-cover")
        self.assertEqual(finding["value"], 1)
        self.assertIn("exclusions:pkg/windowed.pyw:no-cover", result.stderr)
        self.assertFalse(
            [
                item
                for item in check["findings"]
                if item["subject"] == "exclusions:pkg/windowed.pyw:noqa"
            ]
        )

    def test_a_crap_check_declared_after_verification_is_refused(self) -> None:
        self.add_file(
            "quality-gate-crap.toml",
            baseline_text([], check="crap", metric_version="python-lines/1"),
        )
        self.write_verification_baseline([])
        for config in (
            verification_with_crap_after_config(),
            verification_with_later_tests_and_crap_config(),
        ):
            with self.subTest(config=config):
                self.write_config(config)
                result = self.run_qg("check")
                text = output(result)
                self.assertEqual(result.returncode, 2, text)
                self.assertIn("crap", text)
                self.assertIn("verification", text)
                self.assertIn(
                    "verification counts the exclusions of every CRAP check, "
                    "so it must come after them",
                    text,
                )

    def test_a_crap_check_declared_before_verification_loads(self) -> None:
        self.enable_crap()
        self.write_verification_baseline([])
        config = load_config(self.repo)
        self.assertEqual(
            list(config.checks), ["tests", "crap", "verification"]
        )

    def test_a_crap_check_without_a_measurement_leaves_no_cover_unmeasured(
        self,
    ) -> None:
        self.enable_crap()
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/broken.py",
            "def same():\n    return 1\n\n\ndef same():\n    return 2\n",
        )
        result, _document, check = self.run_verification()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "error")
        self.assertIn("crap reported no measurement", check["reason"])

    def test_two_crap_checks_count_an_excluded_line_once(self) -> None:
        self.enable_crap(verification_with_two_crap_config())
        self.add_file(
            "quality-gate-crap2.toml",
            baseline_text([], check="crap2", metric_version="python-lines/1"),
        )
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/mod.py",
            "def covered():\n"
            "    value = 1\n"
            "    return value  # pragma: no cover\n",
        )
        result, document, check = self.failed_verification()
        for identifier in ("crap", "crap2"):
            with self.subTest(identifier=identifier):
                crap = self.check_by_id(document, identifier)
                self.assertEqual(crap["outcome"], "pass")
                self.assertEqual(
                    self.finding(crap, "pkg/mod.py:covered")["measurement"][
                        "excluded_lines"
                    ],
                    [3],
                )
        finding = self.finding(check, "exclusions:pkg/mod.py:no-cover")
        self.assertEqual(finding["value"], 1)
        self.assertIn("exclusions:pkg/mod.py:no-cover", result.stderr)

    def test_only_verification_runs_the_crap_prerequisite(self) -> None:
        self.enable_crap()
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file("pkg/mod.py", "VALUE = 1\nMARKER = '# pragma: no cover'\n")
        result, document, check = self.run_verification(
            "--only", "verification"
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(self.check_by_id(document, "crap")["outcome"], "pass")
        identifiers = [item["id"] for item in document["checks"]]
        self.assertEqual(
            [
                identifier
                for identifier in identifiers
                if identifier in ("tests", "crap", "verification")
            ],
            ["tests", "crap", "verification"],
        )
        finding = self.finding(check, "exclusions:pkg/mod.py:no-cover")
        self.assertEqual(finding["value"], 1)
        self.assertIn("exclusions:pkg/mod.py:no-cover", result.stderr)

    def test_without_a_crap_check_nothing_is_coverage_measured(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file("pkg/mod.py", "VALUE = 1\nMARKER = '# pragma: no cover'\n")
        result, _document, check = self.run_verification()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(
            [
                item
                for item in check["findings"]
                if item["subject"].endswith(":no-cover")
            ]
        )

    def test_measure_exclusions_numbers_lines_at_newline_only(self) -> None:
        source = '"""doc\u2028more"""\nVALUE = 1  # noqa: E501\n'
        findings = {
            finding.subject.rsplit(":", 1)[-1]: finding
            for finding in measure_exclusions("pkg/mod.py", source)
        }
        finding = findings["noqa"]
        self.assertEqual(finding.value, 1)
        self.assertEqual(
            [
                (location.start_line, location.end_line)
                for location in finding.locations
            ],
            [(2, 2)],
        )

    def add_rule(
        self,
        *patterns: str,
        class_name: str = "python",
        shebangs: str = '["python*"]',
    ) -> None:
        self.write_config(
            verification_config().replace(
                'shebangs = ["python*"]', f"shebangs = {shebangs}"
            )
            + "".join(
                f'\n[[rule]]\npattern = "{pattern}"\n'
                f'class = "{class_name}"\nreason = "selected program"\n'
                for pattern in patterns
            )
        )

    def test_a_python_program_without_the_suffix_is_scanned(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "program",
            "#!/usr/bin/env python3\nimport os  # noqa: F401\nVALUE = 1\n",
        )
        self.add_rule("program")
        result, _document, check = self.failed_verification()
        finding = self.finding(check, "exclusions:program:noqa")
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["bound"], None)
        self.assertIn("exclusions:program:noqa", result.stderr)

    def test_a_versioned_python_interpreter_is_scanned(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "direct",
            "#!/usr/bin/python3.12\nimport os  # noqa: F401\nVALUE = 1\n",
        )
        self.add_file(
            "through-env",
            "#!/usr/bin/env python3.13\nimport os  # noqa: F401\nVALUE = 1\n",
        )
        self.add_rule("direct", "through-env")
        result, _document, check = self.failed_verification()
        for relative in ("direct", "through-env"):
            with self.subTest(relative=relative):
                finding = self.finding(check, f"exclusions:{relative}:noqa")
                self.assertEqual(finding["value"], 1)
                self.assertEqual(finding["bound"], None)
                self.assertIn(f"exclusions:{relative}:noqa", result.stderr)

    def test_a_selected_shell_script_is_not_scanned(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "harness.sh",
            "#!/bin/sh\n# noqa: E501\nVALUE=1\n",
        )
        self.add_rule("harness.sh")
        result, _document, check = self.run_verification()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(
            [
                item["subject"]
                for item in check["findings"]
                if "harness.sh" in item["subject"]
            ],
            output(result),
        )

    def test_a_config_interpreter_is_not_a_python_program(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "configure",
            "#!/usr/bin/env python3-config\nimport os  # noqa: F401\nVALUE = 1\n",
        )
        self.add_file(
            "windowed",
            "#!/usr/bin/env pythonw\nimport os  # noqa: F401\nVALUE = 1\n",
        )
        self.add_rule("configure", "windowed")
        result, _document, check = self.run_verification()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse(
            [
                item["subject"]
                for item in check["findings"]
                if "configure" in item["subject"] or "windowed" in item["subject"]
            ],
            output(result),
        )

    def test_an_unreadable_selected_program_is_an_error_naming_it(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root reads any file, so a mode cannot make one unreadable")
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        program = self.add_file(
            "program",
            "#!/usr/bin/env python3.12\nVALUE = 1  # noqa: E501\n",
        )
        program.chmod(0o000)
        self.addCleanup(program.chmod, 0o644)
        self.add_rule("program", shebangs="[]")
        result, _document, check = self.run_verification()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "error")
        self.assertIn("cannot read shebang of program", check["reason"])
        self.assertIn("cannot read shebang of program", result.stderr)

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

    def test_added_ruff_file_noqa_fails_with_and_without_codes(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        for directive in (
            "# ruff: noqa",
            "# ruff: noqa: E501",
            "#\u00a0ruff:\u00a0noqa:\u00a0E501",
        ):
            with self.subTest(directive=directive):
                self.add_file("pkg/mod.py", f"{directive}\nVALUE = 1\n")
                result, _document, check = self.failed_verification()
                finding = self.finding(check, "exclusions:pkg/mod.py:file-suppression")
                self.assertEqual(finding["value"], 1)
                self.assertEqual(finding["bound"], None)
                self.assertEqual(self.finding(check, "exclusions:pkg/mod.py:noqa")["value"], 0)
                self.assertIn("pkg/mod.py:1", result.stderr)
                self.assertIn(directive, result.stderr)

    def test_replacing_inline_noqa_with_file_noqa_fails_and_refuses_prune(self) -> None:
        self.add_tests(1)
        self.add_file("pkg/mod.py", noqa_source(2))
        self.write_verification_baseline([
            executed_entry(1), exclusion_entry("pkg/mod.py", "noqa", 2)
        ])
        result, _document, _check = self.run_verification()
        self.assertEqual(result.returncode, 0, output(result))

        original_baseline = self.read_file(BASELINE)
        self.add_file("pkg/mod.py", "# ruff: noqa\nVALUE_0 = 0\nVALUE_1 = 1\n")
        result, document, check = self.failed_verification("--prune", "verification")
        self.assertEqual(self.finding(check, "exclusions:pkg/mod.py:file-suppression")["value"], 1)
        self.assertIn("exclusions:pkg/mod.py:noqa", check["resolved_baseline_entries"])
        self.assertFalse(document["prune"]["performed"])
        self.assertEqual(self.read_file(BASELINE), original_baseline)
        self.assertIn("# ruff: noqa", result.stderr)

    def test_file_suppression_syntax_and_multiple_directives(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/mod.py",
            "# note # ruff: NoQa: E501 # ruff: noqa: F401\n"
            "# flake8 : NOQA: E501\n"
            "# FLAKE8=NoQA # ruff: noqa: F401\n"
            "# ruff: file-ignore[F401, E501]\n"
            "# RUFF: noqa\n"
            "# ruff: noquality\n"
            "# ruff: noqa:\n"
            "# ruff: file-ignore[]\n"
            "VALUE = 1  # ruff: noqa\n"
            "if True:\n"
            "    # ruff: file-ignore[F401]\n"
            "    pass\n",
        )
        result, _document, check = self.failed_verification()
        finding = self.finding(check, "exclusions:pkg/mod.py:file-suppression")
        self.assertEqual(finding["value"], 5)
        self.assertEqual(
            [location["start_line"] for location in finding["locations"]],
            [1, 2, 3, 3, 4],
        )
        self.assertIn("# ruff: NoQa", result.stderr)

    def test_file_directive_in_string_is_not_a_suppression(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/mod.py",
            'A = "# ruff: noqa"\n'
            "B = '# flake8: noqa'\n"
            'C = """\n# ruff: noqa: E501\n# ruff: file-ignore[F401]\n"""\n'
            "D = '# isort: skip_file'\n",
        )
        result, _document, check = self.run_verification()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.finding(check, "exclusions:pkg/mod.py:file-suppression")["value"], 0)
        self.assertEqual(self.finding(check, "exclusions:pkg/mod.py:noqa")["value"], 0)

    def test_isort_file_skips_count_on_comment_tokens(self) -> None:
        self.add_tests(1)
        self.write_verification_baseline([executed_entry(1)])
        self.add_file(
            "pkg/mod.py",
            "# isort: skip_file\n"
            "# ruff: isort: skip_file\n"
            "VALUE = 1  # isort:skip_file\n",
        )
        result, _document, check = self.failed_verification()
        finding = self.finding(check, "exclusions:pkg/mod.py:file-suppression")
        self.assertEqual(finding["value"], 3)
        self.assertIn("pkg/mod.py:1", result.stderr)
        self.assertIn("isort: skip_file", result.stderr)
        self.assertEqual(self.finding(check, "exclusions:pkg/mod.py:noqa")["value"], 0)

    def test_baselined_file_suppression_passes_and_removal_resolves(self) -> None:
        self.add_tests(1)
        self.add_file("pkg/mod.py", "# ruff: noqa\nVALUE = 1\n")
        self.write_verification_baseline([
            executed_entry(1), exclusion_entry("pkg/mod.py", "file-suppression", 1)
        ])
        result, document, check = self.run_verification()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        finding = self.finding(check, "exclusions:pkg/mod.py:file-suppression")
        self.assertTrue(finding["covered_by_baseline"])
        self.assertEqual(finding["baseline_reason"], ADOPTION_REASON)

        self.add_file("pkg/mod.py", "VALUE = 1\n")
        result, document, check = self.run_verification("--prune", "verification")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("exclusions:pkg/mod.py:file-suppression", check["resolved_baseline_entries"])
        self.assertTrue(document["prune"]["performed"])
        self.assertNotIn('subject = "exclusions:pkg/mod.py:file-suppression"', self.read_file(BASELINE))

    def test_file_suppression_requires_a_nonempty_baseline_reason(self) -> None:
        self.add_tests(1)
        self.add_file("pkg/mod.py", "# flake8: noqa\nVALUE = 1\n")
        entry = exclusion_entry("pkg/mod.py", "file-suppression", 1)
        entry["reason"] = ""
        self.write_verification_baseline([executed_entry(1), entry])
        result, _document, check = self.failed_verification()
        self.assertEqual(
            self.finding(check, "exclusions:pkg/mod.py:file-suppression")["error"],
            "empty baseline reason",
        )
        self.assertIn("empty reason", result.stderr)

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

    def test_no_test_producer_leaves_the_counts_unmeasured(self) -> None:
        text = """\
schema = 2

[code]
patterns = ["*.py"]
shebangs = []

[levels]
required_tiers = [1]

[classes.python]
code = true
description = "Python source"
checks = ["verification"]

[classes.config]
code = false
description = "Configuration"

[classes.doc]
code = false
description = "Documentation"

[checks.verification]
adapter = "verification"
tier = 1
enforcement = "enforced"
baseline = "quality-gate-verification.toml"

[[rule]]
pattern = "pkg/*.py"
class = "python"
reason = "source"
"""
        self.write_config(text + "\n".join(PYTHON_COMMON_RULE_LINES))
        self.empty_verification_baseline()
        result, _document, check = self.run_verification()
        self.assertEqual(check["outcome"], "unsupported")
        self.assertIn("no test adapter check to measure", check["reason"])
        self.assertIn("no test adapter check to measure", result.stderr)


class MultiplePruneTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        prepare_multiple_prune(self)

    def assert_both_bounds(self, bound: int) -> None:
        self.assertIn(f"bound = {bound}", self.read_file(BASELINE))
        self.assertIn(f"bound = {bound}", self.read_file("second.toml"))

    def test_repeated_prune_tightens_both_baselines(self) -> None:
        result, document = self.run_json(
            "--prune", "verification", "--prune", "second", env=self.default_tool_env()
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assert_both_bounds(2)
        self.assertEqual(document["prune"]["requested"], ["verification", "second"])
        self.assertTrue(document["prune"]["performed"])

    def test_prune_all_tightens_every_baseline(self) -> None:
        result, document = self.run_json("--prune", "all", env=self.default_tool_env())
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["prune"]["requested"], ["all"])
        self.assertTrue(document["prune"]["performed"])
        self.assert_both_bounds(2)

    def test_failing_check_refuses_all_requested_prunes(self) -> None:
        self.add_file("second.toml", second_baseline(3))
        before = [self.read_file(BASELINE), self.read_file("second.toml")]
        result, document = self.run_json("--prune", "all", env=self.default_tool_env())
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertFalse(document["prune"]["performed"])
        self.assertIn("second: prune refused", result.stderr)
        self.assertEqual([self.read_file(BASELINE), self.read_file("second.toml")], before)

    def test_invalid_later_request_writes_nothing(self) -> None:
        before = self.read_file(BASELINE)
        result, document = self.run_json(
            "--prune", "verification", "--prune", "missing", env=self.default_tool_env()
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("unknown check 'missing'", result.stderr)
        self.assertEqual(document["prune"]["requested"], ["verification", "missing"])
        self.assertEqual(self.read_file(BASELINE), before)

    def test_repeated_prune_refuses_a_failing_check_before_either_write(self) -> None:
        self.add_file("second.toml", second_baseline(3))
        before = [self.read_file(BASELINE), self.read_file("second.toml")]
        result, document = self.run_json(
            "--prune", "verification", "--prune", "second", env=self.default_tool_env()
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertFalse(document["prune"]["performed"])
        self.assertEqual([self.read_file(BASELINE), self.read_file("second.toml")], before)

    def test_all_refuses_a_failing_check_without_a_baseline(self) -> None:
        self.write_config(multi_verification_config().replace(
            "[checks.tests]", "[checks.fails]\nadapter = \"command\"\ntier = 1\n"
            "enforcement = \"enforced\"\nrun = [\"python3\", \"-c\", \"exit(1)\"]\n\n"
            "[checks.tests]", 1,
        ))
        before = self.read_file(BASELINE)
        result, document = self.run_json("--prune", "all", env=self.default_tool_env())
        self.assertEqual(result.returncode, 1, output(result))
        self.assertFalse(document["prune"]["performed"])
        self.assertIn("fails: prune refused", result.stderr)
        self.assertEqual(self.read_file(BASELINE), before)

    def test_repeated_ids_and_all_write_each_baseline_once(self) -> None:
        result, document = self.run_json(
            "--prune", "verification", "--prune", "all", "--prune", "second",
            env=self.default_tool_env(),
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(document["prune"]["performed"])
        self.assertEqual(result.stderr.count("baseline updated at"), 2)
        self.assert_both_bounds(2)


class VerificationTrustTests(FindingMixin, TrustCase):
    def test_candidate_cannot_authorize_a_file_suppression(self) -> None:
        revision = self.prepare(tests=1, noqa=2, floor=1, ceiling=2)
        self.add_file("pkg/mod.py", "# ruff: noqa\nVALUE_0 = 0\nVALUE_1 = 1\n")
        self.add_file(BASELINE, verification_baseline([
            executed_entry(1),
            exclusion_entry("pkg/mod.py", "noqa", 2),
            exclusion_entry("pkg/mod.py", "file-suppression", 1),
        ]))
        result, document = self.trust_json(revision, env=self.default_tool_env())
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "blocked")
        entry = self.protected(document, BASELINE)
        self.assertEqual(entry["status"], "blocked")
        self.assertEqual(
            entry["ignored_entries"],
            ["exclusions:pkg/mod.py:file-suppression"],
        )
        self.assertIn(
            f"check: blocked: protected input changed without "
            f"--allow-protected: {BASELINE}",
            result.stderr,
        )
        check = self.check_by_id(document, "verification")
        finding = self.finding(check, "exclusions:pkg/mod.py:file-suppression")
        self.assertEqual((finding["value"], finding["bound"]), (1, None))
        self.assertTrue(finding["blocking"])
        self.assertIn("exclusions:pkg/mod.py:noqa", check["resolved_baseline_entries"])

    def test_candidate_test_cannot_lower_merged_verification_floor(self) -> None:
        forged = verification_baseline([executed_entry(1)])
        revision = self.prepare(tests=2, noqa=0, floor=2, ceiling=0)
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n"
            "    def test_attack(self):\n"
            + self.merge_attack("verification", forged),
        )
        check = self.attacked_check(revision, "verification")
        finding = self.finding(check, "tests:tests:executed")
        self.assertEqual((finding["value"], finding["bound"]), (1, 2))
        self.assertTrue(finding["blocking"])

    def test_normal_trust_run_records_effective_baseline(self) -> None:
        revision = self.prepare(tests=2, noqa=0, floor=2, ceiling=0)
        result, document = self.trust_json(revision, env=self.default_tool_env())
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted")
        self.assertTrue(self.check_by_id(document, "verification")["satisfied"])
        identity = document["trust"]["identity_before"]
        self.assertEqual(identity, document["trust"]["identity_after"])
        self.assertIn("baseline " + BASELINE, identity["effective_inputs"])

    def test_authorized_baseline_rewrite_and_restore_keeps_snapshot(self) -> None:
        trusted = verification_baseline([
            executed_entry(2), exclusion_entry("pkg/mod.py", "noqa", 0)
        ])
        forged = verification_baseline([executed_entry(1)])
        restore = (
            f"import pathlib; pathlib.Path({BASELINE!r}).write_text({trusted!r})"
        )
        config = verification_config() + (
            '\n[checks.restore]\nadapter = "command"\ntier = 1\n'
            'enforcement = "enforced"\n'
            f'run = [{json.dumps(sys.executable)}, "-c", {json.dumps(restore)}]\n'
        )
        revision = self.prepare(
            tests=2, noqa=0, floor=2, ceiling=0, config=config
        )
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n"
            "    def test_attack(self):\n"
            f"        pathlib.Path({BASELINE!r}).write_text({forged!r})\n"
            "        self.assertTrue(True)\n",
        )
        result, document = self.trust_json(
            revision, "--allow-protected", BASELINE, env=self.default_tool_env()
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        check = self.check_by_id(document, "verification")
        self.assertEqual(self.finding(check, "tests:tests:executed")["bound"], 2)
        self.assertEqual(
            document["trust"]["identity_before"],
            document["trust"]["identity_after"],
        )

    def test_authorized_policy_new_baseline_is_snapshotted(self) -> None:
        revision = self.prepare(tests=2, noqa=0, floor=2, ceiling=0)
        new_baseline = "new-verification.toml"
        trusted = verification_baseline([executed_entry(2)])
        forged = verification_baseline([executed_entry(1)])
        self.write_config(verification_config(baseline=new_baseline))
        self.add_file(new_baseline, trusted)
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n"
            "    def test_attack(self):\n"
            f"        pathlib.Path({new_baseline!r}).write_text({forged!r})\n"
            "        self.assertTrue(True)\n",
        )
        result, document = self.trust_json(
            revision, "--allow-protected", "quality-gate.toml",
            env=self.default_tool_env(),
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn(new_baseline, document["error"])
        check = self.check_by_id(document, "verification")
        finding = self.finding(check, "tests:tests:executed")
        self.assertEqual((finding["value"], finding["bound"]), (1, 2))
        self.assertIn(
            "baseline " + new_baseline,
            document["trust"]["identity_before"]["effective_inputs"],
        )

    def test_authorized_policy_refuses_a_new_baseline_fifo(self) -> None:
        revision = self.prepare(tests=1, noqa=0, floor=1, ceiling=0)
        self.write_config(verification_config(baseline="new-verification.toml"))
        os.mkfifo(self.repo / "new-verification.toml")
        result = self.run_qg(
            "check", "--policy-from", revision,
            "--allow-protected", "quality-gate.toml", timeout=5,
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("new-verification.toml", result.stderr)
        self.assertIn("checks.verification.baseline", result.stderr)
        self.assertIn("does not exist", result.stderr)

    def test_malformed_authorized_baseline_is_refused_before_checks(self) -> None:
        marker = self.base / "ran"
        rewrite = f"import pathlib; pathlib.Path({str(marker)!r}).touch(); print(1)"
        revision = self.prepare(
            tests=1, noqa=0, floor=1, ceiling=0,
            config=rewriting_config(rewrite),
        )
        self.add_file(BASELINE, "not valid TOML [\n")
        result = self.run_qg(
            "check", "--policy-from", revision, "--allow-protected", BASELINE,
            env=self.default_tool_env(),
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("valid effective baseline", result.stderr)
        self.assertFalse(marker.exists())

    def prepare(
        self,
        *,
        tests: int,
        noqa: int,
        floor: int,
        ceiling: int,
        config: str | None = None,
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
        self.write_config(
            verification_config() if config is None else config
        )
        self.add_file(
            BASELINE,
            verification_baseline(
                [
                    executed_entry(floor),
                    exclusion_entry("pkg/mod.py", "noqa", ceiling),
                ]
            ),
        )
        return str(self.trusted_directory(self.commit_revision()))

    def candidate(
        self,
        revision: str,
        floor: int,
        ceiling: int,
        decision: str = "rejected",
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
        self.assertEqual(document["decision"], decision)
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

    def test_candidate_lowered_floor_and_raised_ceiling_are_blocked(
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
        document = self.candidate(revision, 1, 5, decision="blocked")
        entry = self.protected(document, BASELINE)
        self.assertEqual(entry["status"], "blocked")
        self.assertEqual(
            set(entry["ignored_entries"]),
            {
                "tests:tests:executed",
                "exclusions:pkg/mod.py:noqa",
            },
        )
        self.bounds(document, (1, 2), (3, 2))

    def test_candidate_lowered_floor_with_an_earlier_expiry_is_blocked(
        self,
    ) -> None:
        revision = self.prepare(tests=2, noqa=2, floor=2, ceiling=2)
        self.add_file(
            BASELINE,
            verification_baseline(
                [
                    {**executed_entry(0), "expires": "2099-12-31"},
                    exclusion_entry("pkg/mod.py", "noqa", 2),
                ]
            ),
        )
        _result, document = self.blocked_run(
            revision, self.default_tool_env()
        )
        self.assertEqual(
            self.protected(document, BASELINE)["ignored_entries"],
            ["tests:tests:executed"],
        )
        self.bounds(document, (2, 2), (2, 2))

    def test_candidate_removed_floor_keeps_the_trusted_entry_and_blocks(self) -> None:
        revision = self.prepare(tests=2, noqa=2, floor=2, ceiling=2)
        self.add_file(
            BASELINE,
            verification_baseline(
                [exclusion_entry("pkg/mod.py", "noqa", 2)]
            ),
        )
        _result, document = self.blocked_run(
            revision, self.default_tool_env()
        )
        check = self.check_by_id(document, "verification")
        self.assertTrue(check["satisfied"])
        entry = self.protected(document, BASELINE)
        self.assertEqual(entry["status"], "blocked")
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
