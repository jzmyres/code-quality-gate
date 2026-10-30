"""Tests for the verification-loss adapter and its ratcheted metrics."""
from __future__ import annotations

import json
import os
import sys
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


class MultiplePruneTrustTests(TrustCase):
    def setUp(self) -> None:
        super().setUp()
        prepare_multiple_prune(self)

    def test_trusted_prune_all_records_each_exact_write(self) -> None:
        revision = self.commit_revision()
        result, document = self.trust_json(revision, "--prune", "all", env=self.default_tool_env())
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(document["prune"]["performed"])
        for path in (BASELINE, "second.toml"):
            self.assertIn("bound = 2", self.read_file(path))
            before = document["trust"]["identity_before"]["protected"][path]
            after = document["trust"]["identity_after"]["protected"][path]
            self.assertNotEqual(before["candidate_sha256"], after["candidate_sha256"])

    def test_changed_protected_input_prevents_all_writes(self) -> None:
        writer = (
            "import pathlib; "
            "pathlib.Path('second.toml').write_text('altered'); print(1)"
        )
        self.write_config(multi_verification_config().replace(
            "[checks.tests]", "[checks.rewrite]\nadapter = \"command\"\ntier = 1\n"
            "enforcement = \"enforced\"\nrun = " + json.dumps([sys.executable, "-c", writer])
            + "\n\n[checks.tests]", 1,
        ))
        revision = self.commit_revision()
        before = self.read_file(BASELINE)
        result, document = self.trust_json(revision, "--prune", "all", env=self.default_tool_env())
        self.assertEqual(result.returncode, 2, output(result))
        self.assertFalse(document["prune"]["performed"])
        self.assertIn("second.toml", document["error"])
        self.assertEqual(self.read_file(BASELINE), before)
        self.assertEqual(self.read_file("second.toml"), "altered")


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
        self.assertEqual(document["decision"], "rejected")
        entry = self.protected(document, BASELINE)
        self.assertIn("exclusions:pkg/mod.py:file-suppression", entry["ignored_entries"])
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
        self.assertIn("FIFO", result.stderr)

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

    def test_check_rewriting_an_authorized_floor_then_prune_fails(self) -> None:
        weakened = verification_baseline([executed_entry(1)])
        rewrite = (
            "import pathlib; "
            f"pathlib.Path({BASELINE!r}).write_text({weakened!r}); "
            "print(1)"
        )
        revision = self.prepare(
            tests=1,
            noqa=0,
            floor=2,
            ceiling=0,
            config=rewriting_config(rewrite),
        )
        result, document = self.trust_json(
            revision,
            "--allow-protected",
            BASELINE,
            "--prune",
            "verification",
            env=self.default_tool_env(),
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn(BASELINE, document["error"])
        self.assertIn("changed during the run", document["error"])
        self.assertFalse(document["prune"]["performed"])
        self.assertEqual(self.read_file(BASELINE), weakened)
        check = self.check_by_id(document, "verification")
        self.assertEqual(self.finding(check, "tests:tests:executed")["bound"], 2)


if __name__ == "__main__":
    unittest.main()
