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
            BASE_CONFIG.replace("schema = 2\n", ""),
            "schema",
            "missing",
        )

    def test_schema_must_be_two(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("schema = 2", "schema = 1"),
            "schema",
            "expected 2",
            "1",
        )

    def test_schema_boolean_is_not_two(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("schema = 2", "schema = true"),
            "schema",
            "expected 2",
        )

    def test_schema_float_is_not_two(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("schema = 2", "schema = 2.0"),
            "schema",
            "expected 2",
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
                'run = ["python3", "-c", "print(1)"]',
                'run = ["python3", "-c", "print(1)"]\nextra = true',
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
        self.write_config(
            BASE_CONFIG.replace(
                "required_tiers = [1]", "required_tiers = [1, 2]"
            )
        )
        result, document = self.run_json()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        obligation = next(
            item
            for item in document["obligations"]
            if item["class"] == "python" and item["tier"] == 2
        )
        self.assertEqual(obligation["status"], "unsatisfied")
        self.assertEqual(obligation["required"], ["properties", "fuzzing"])

    def test_missing_required_tier_with_not_applicable(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                "required_tiers = [1]", "required_tiers = [1, 2]"
            )
            + '\n[[not_applicable]]\nclass = "python"\ntier = 2\n'
            'reason = "tier 2 has no adapter yet"\n'
        )
        result, document = self.run_json()
        self.assertEqual(result.returncode, 0, output(result))
        obligation = next(
            item
            for item in document["obligations"]
            if item["class"] == "python" and item["tier"] == 2
        )
        self.assertEqual(obligation["status"], "exempted")
        self.assertEqual(obligation["reason"], "tier 2 has no adapter yet")

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
                'run = ["python3", "-c", "print(1)"]', "run = []"
            ),
            "checks.smoke.run",
            "non-empty",
        )

    def test_must_match_must_be_a_valid_regular_expression(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "print(1)"]',
                'run = ["python3", "-c", "print(1)"]\nmust_match = "[unclosed"',
            ),
            "checks.smoke.must_match",
            "valid regular expression",
        )

    def test_budget_seconds_must_be_positive(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "print(1)"]',
                'run = ["python3", "-c", "print(1)"]\nbudget_seconds = 0',
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


    def test_elisp_decision_rules_refuse_invalid_entries(self) -> None:
        prefix = (BASE_CONFIG + '\n[checks.crap]\nadapter = "elisp_crap"\n'
                  'tier = 1\nenforcement = "enforced"\nrequires = "smoke"\n'
                  'baseline = "crap.toml"\n')
        cases = (
            ('decision_rules = "bad-table"', "decision_rules", "bad-table"),
            ('decision_rules = { mystery = ["x"] }', "decision_rules.mystery", "mystery"),
            ('decision_rules = { branch = "bad-list" }', "decision_rules.branch", "bad-list"),
            ('decision_rules = { branch = [42] }', "decision_rules.branch[0]", "42"),
            ('decision_rules = { branch = [""] }', "decision_rules.branch[0]", "''"),
            ('decision_rules = { branch = ["bad name"] }', "decision_rules.branch[0]", "bad name"),
            ('decision_rules = { branch = ["bad\\u0000name"] }', "decision_rules.branch[0]", "bad"),
            ('decision_rules = { branch = ["custom", "custom"] }', "decision_rules.branch[1]", "custom"),
            ('decision_rules = { branch = ["and"] }', "decision_rules.operands[0]", "and"),
        )
        for rules, key, entry in cases:
            with self.subTest(rules=rules):
                self.config_error(prefix + rules + "\n", f"checks.crap.{key}", entry)

    def test_baseline_check_header_must_match_the_policy(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[checks.orphan]\nadapter = "clones"\ntier = 1\n'
            'enforcement = "enforced"\nbaseline = "orphan.toml"\n'
        )
        self.add_file(
            "orphan.toml",
            'check = "other"\nmetric_version = '
            '"jscpd-clone-occurrences/1"\n',
        )
        message = self.config_error(
            self.read_file("quality-gate.toml"),
            "orphan.toml",
            "check",
            "other",
        )
        self.assertIn("orphan", message)

    def test_baseline_metric_version_must_match_the_policy(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[checks.orphan]\nadapter = "clones"\ntier = 1\n'
            'enforcement = "enforced"\nbaseline = "orphan.toml"\n'
        )
        self.add_file(
            "orphan.toml",
            'check = "orphan"\nmetric_version = "jscpd-clone-occurrences/2"\n',
        )
        self.config_error(
            self.read_file("quality-gate.toml"),
            "orphan.toml",
            "metric_version",
            "jscpd-clone-occurrences/1",
        )

    def test_two_checks_may_not_share_a_baseline_path(self) -> None:
        self.config_error(
            BASE_CONFIG
            + '\n[checks.one]\nadapter = "clones"\ntier = 1\n'
            'enforcement = "enforced"\nbaseline = "shared.toml"\n'
            '\n[checks.two]\nadapter = "clones"\ntier = 1\n'
            'enforcement = "enforced"\nbaseline = "./shared.toml"\n',
            "checks.two.baseline",
            "shared.toml",
            "checks.one",
        )

    def test_check_direction_defaults_to_max_and_accepts_min(self) -> None:
        self.write_config(BASE_CONFIG)
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 0, output(result))
        self.write_config(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "print(1)"]',
                'run = ["python3", "-c", "print(1)"]\n'
                'direction = "min"',
            )
        )
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 0, output(result))

    def test_check_direction_must_be_max_or_min(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "print(1)"]',
                'run = ["python3", "-c", "print(1)"]\n'
                'direction = "sideways"',
            ),
            "checks.smoke.direction",
            "one of max, min",
            "sideways",
        )

    def test_verification_requires_refuses_command_without_tests_pattern(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("tests_pattern = '(\\d+)'\n", "")
            + '\n[checks.verification]\nadapter = "verification"\n'
            'tier = 1\nenforcement = "enforced"\nrequires = "smoke"\n'
            'baseline = "verification.toml"\n',
            "checks.verification.requires",
            "'smoke' is a command check",
            "produces no tests",
            "no tests_pattern",
            "an earlier check that produces tests",
        )

    def test_verification_requires_refuses_adapter_without_test_evidence(self) -> None:
        self.config_error(
            BASE_CONFIG
            + '\n[checks.duplicates]\nadapter = "clones"\n'
            'tier = 1\nenforcement = "enforced"\nbaseline = "clones.toml"\n'
            '\n[checks.verification]\nadapter = "verification"\n'
            'tier = 1\nenforcement = "enforced"\nrequires = "duplicates"\n'
            'baseline = "verification.toml"\n',
            "checks.verification.requires",
            "'duplicates' is a clones check that produces no tests",
        )

    def test_command_argument_with_nul_is_a_configuration_error(self) -> None:
        self.config_error(
            BASE_CONFIG.replace(
                'run = ["python3", "-c", "print(1)"]',
                'run = ["python3", "-c", "print(1)\\u0000"]',
            ),
            "checks.smoke.run[2]",
            "NUL",
        )


if __name__ == "__main__":
    unittest.main()
