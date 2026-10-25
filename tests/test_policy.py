"""Tests for the policy schema and inventory obligations."""
from __future__ import annotations

import unittest

from support import BASE_CONFIG, FixtureCase, output


class PolicyTests(FixtureCase):
    def config_error(self, text: str, *needles: str) -> str:
        self.write_config(text)
        result = self.run_qg("inventory")
        message = output(result)
        self.assertEqual(result.returncode, 2, message)
        for needle in needles:
            self.assertIn(needle, message)
        return message

    def inventory_failure(self, text: str, *needles: str) -> str:
        self.write_config(text)
        result = self.run_qg("inventory")
        message = output(result)
        self.assertEqual(result.returncode, 1, message)
        for needle in needles:
            self.assertIn(needle, message)
        return message

    def test_schema_is_required(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("schema = 1\n", ""),
            "schema",
            "missing",
        )

    def test_schema_must_be_one(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("schema = 1", "schema = 2"),
            "schema",
            "expected 1",
            "2",
        )

    def test_schema_boolean_is_not_one(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("schema = 1", "schema = true"),
            "schema",
            "expected 1",
        )

    def test_schema_float_is_not_one(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("schema = 1", "schema = 1.0"),
            "schema",
            "expected 1",
        )

    def test_unknown_top_level_key_names_the_allowed_keys(self) -> None:
        message = self.config_error(
            BASE_CONFIG + "\n[clones]\nclasses = []\n",
            "clones",
            "allowed keys",
        )
        self.assertIn("schema", message)
        self.assertIn("checks", message)

    def test_unknown_class_key(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'description = "Python source"',
                'description = "Python source"\nextra = true',
            ),
            "classes.python.extra",
            "allowed keys",
        )

    def test_unknown_code_key(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'shebangs = ["sh", "bash", "python*"]',
                'shebangs = ["sh", "bash", "python*"]\nextra = true',
            ),
            "code.extra",
            "allowed keys",
        )

    def test_unknown_rule_key(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'reason = "Python source"',
                'reason = "Python source"\nextra = true',
            ),
            "rule[0].extra",
            "allowed keys",
        )

    def test_unknown_check_key(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "pass"]',
                'run = ["python3", "-c", "pass"]\nextra = true',
            ),
            "checks.smoke.extra",
            "allowed keys",
        )

    def test_code_class_must_list_a_check(self) -> None:
        self.inventory_failure(
            BASE_CONFIG.replace('checks = ["smoke"]\n', ""),
            "classes.python",
            "lists no check",
        )

    def test_class_must_not_name_an_unknown_check(self) -> None:
        self.inventory_failure(
            BASE_CONFIG.replace(
                'checks = ["smoke"]', 'checks = ["mystery"]'
            ),
            "classes.python",
            "unknown check 'mystery'",
        )

    def test_required_tiers_must_contain_one(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("required_tiers = [1]", "required_tiers = [2]"),
            "levels.required_tiers",
            "containing 1",
        )

    def test_missing_required_tier_without_not_applicable(self) -> None:
        self.inventory_failure(
            BASE_CONFIG.replace(
                "required_tiers = [1]", "required_tiers = [1, 2]"
            ),
            "classes.python",
            "required tier 2",
            "not_applicable",
        )

    def test_missing_required_tier_with_not_applicable(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                "required_tiers = [1]", "required_tiers = [1, 2]"
            )
            + '\n[[not_applicable]]\nclass = "python"\ntier = 2\n'
            'reason = "tier 2 has no adapter yet"\n'
        )
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 0, output(result))

    def test_not_applicable_reason_must_be_non_empty(self) -> None:
        self.config_error(
            BASE_CONFIG
            + '\n[[not_applicable]]\nclass = "python"\ntier = 2\n'
            'reason = "   "\n',
            "not_applicable[0].reason",
            "non-empty",
        )

    def test_not_applicable_class_must_exist(self) -> None:
        self.config_error(
            BASE_CONFIG
            + '\n[[not_applicable]]\nclass = "mystery"\ntier = 2\n'
            'reason = "not a class"\n',
            "not_applicable[0].class",
            "unknown class 'mystery'",
        )

    def test_check_adapter_must_be_known(self) -> None:
        self.config_error(
            BASE_CONFIG.replace('adapter = "command"', 'adapter = "mystery"'),
            "checks.smoke.adapter",
            "one of command, clones",
        )

    def test_check_enforcement_must_be_enforced_or_advisory(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'enforcement = "enforced"', 'enforcement = "optional"'
            ),
            "checks.smoke.enforcement",
            "enforced, advisory",
        )

    def test_check_tier_must_be_between_one_and_four(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("tier = 1", "tier = 0"),
            "checks.smoke.tier",
            ">= 1",
        )

    def test_completed_check_needs_an_argument_list(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "pass"]', "run = []"
            ),
            "checks.smoke.run",
            "non-empty",
        )

    def test_must_match_must_be_a_valid_regular_expression(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "pass"]',
                'run = ["python3", "-c", "pass"]\nmust_match = "[unclosed"',
            ),
            "checks.smoke.must_match",
            "valid regular expression",
        )

    def test_budget_seconds_must_be_positive(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "pass"]',
                'run = ["python3", "-c", "pass"]\nbudget_seconds = 0',
            ),
            "checks.smoke.budget_seconds",
            ">= 1",
        )

    def test_classes_checks_must_be_a_string_list(self) -> None:
        self.config_error(
            BASE_CONFIG.replace('checks = ["smoke"]', "checks = [1]"),
            "classes.python.checks[0]",
            "a string",
        )

    def test_python_tests_needs_a_tests_pattern(self) -> None:
        self.config_error(
            BASE_CONFIG
            + '\n[checks.tests]\nadapter = "python_tests"\ntier = 1\n'
            'enforcement = "enforced"\n'
            'run = ["{python}", "-m", "unittest"]\n',
            "checks.tests.tests_pattern",
            "missing",
        )

    def test_python_tests_pattern_needs_one_capture_group(self) -> None:
        self.config_error(
            BASE_CONFIG
            + '\n[checks.tests]\nadapter = "python_tests"\ntier = 1\n'
            'enforcement = "enforced"\n'
            'run = ["{python}", "-m", "unittest"]\n'
            'tests_pattern = "Ran \\\\d+ tests"\n',
            "checks.tests.tests_pattern",
            "one capture group",
            "0 capture groups",
        )

    def test_python_crap_requires_a_known_check(self) -> None:
        self.config_error(
            BASE_CONFIG
            + '\n[checks.crap]\nadapter = "python_crap"\ntier = 1\n'
            'enforcement = "enforced"\nrequires = "missing"\n'
            'baseline = "crap.toml"\n',
            "checks.crap.requires",
            "unknown check 'missing'",
        )

    def test_python_crap_requires_a_python_tests_check(self) -> None:
        self.config_error(
            BASE_CONFIG
            + '\n[checks.crap]\nadapter = "python_crap"\ntier = 1\n'
            'enforcement = "enforced"\nrequires = "smoke"\n'
            'baseline = "crap.toml"\n',
            "checks.crap.requires",
            "is a command check",
        )

    def test_python_crap_requires_an_earlier_check(self) -> None:
        self.config_error(
            BASE_CONFIG
            + '\n[checks.crap]\nadapter = "python_crap"\ntier = 1\n'
            'enforcement = "enforced"\nrequires = "tests"\n'
            'baseline = "crap.toml"\n'
            '\n[checks.tests]\nadapter = "python_tests"\ntier = 1\n'
            'enforcement = "enforced"\n'
            'run = ["{python}", "-m", "unittest"]\n'
            'tests_pattern = "Ran (\\\\d+) tests"\n',
            "checks.crap.requires",
            "'tests'",
            "declared earlier",
        )

    def test_python_crap_threshold_must_be_finite(self) -> None:
        for value in ("inf", "nan"):
            with self.subTest(value=value):
                self.config_error(
                    BASE_CONFIG
                    + '\n[checks.tests]\nadapter = "python_tests"\n'
                    'tier = 1\nenforcement = "enforced"\n'
                    'run = ["{python}", "-m", "unittest"]\n'
                    'tests_pattern = "Ran (\\\\d+) tests"\n'
                    '\n[checks.crap]\nadapter = "python_crap"\n'
                    'tier = 1\nenforcement = "enforced"\n'
                    'requires = "tests"\nbaseline = "crap.toml"\n'
                    f"threshold = {value}\n",
                    "checks.crap.threshold",
                    "finite",
                )


if __name__ == "__main__":
    unittest.main()
