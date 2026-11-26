"""Tests for the policy schema and inventory obligations."""
from __future__ import annotations

import importlib
import json
import sys
import unittest
from pathlib import Path

from support import BASE_CONFIG, GATE, FixtureCase, output, with_clones

sys.path.insert(0, str(GATE))
policy = importlib.import_module("quality_gate.policy")
shards = importlib.import_module("quality_gate.test_shards")

MODULE_CHECK = """\
[checks.module-contracts]
adapter = "module_contracts"
tier = 1
enforcement = "enforced"
"""
MODULE_POLICY = BASE_CONFIG + MODULE_CHECK + """
[modules.fixture]
files = ["*"]
entry_points = []
allowed_dependencies = []
"""


class PolicyTests(FixtureCase):
    def test_check_requires_modules_and_resolves_dependency_names(self) -> None:
        for text, key, detail in (
            (BASE_CONFIG + MODULE_CHECK, "[modules]", "missing"),
            (MODULE_POLICY.replace("allowed_dependencies = []", 'allowed_dependencies = ["unknown"]'),
             "modules.fixture.allowed_dependencies[0]", "unknown module 'unknown'"),
        ):
            with self.subTest(key=key):
                self.write_config(text)
                result = self.run_qg_process("check")
                self.assertEqual(result.returncode, 2, output(result))
                self.assertIn(f"{self.config_path}: {key}", result.stderr)
                self.assertIn(detail, result.stderr)

    def test_module_tables_and_fields(self) -> None:
        for text, key in (
            ("modules = false\n" + BASE_CONFIG, "[modules]"),
            (BASE_CONFIG + "\n[modules]\nfixture = 1\n", "modules.fixture"),
            (MODULE_POLICY.replace('files = ["*"]\n', ""), "modules.fixture.files"),
            (MODULE_POLICY.replace("entry_points = []\n", ""), "modules.fixture.entry_points"),
            (MODULE_POLICY.replace("allowed_dependencies = []\n", ""),
             "modules.fixture.allowed_dependencies"),
            (MODULE_POLICY.replace("entry_points = []", "extra = []"), "modules.fixture.extra"),
            (MODULE_POLICY.replace('files = ["*"]', "files = []"), "modules.fixture.files"),
        ):
            with self.subTest(text=text):
                self.config_error(text, f"{self.config_path}: {key}")

    def test_module_arrays_and_items(self) -> None:
        for field, original, repeat in (
            ("files", '["*"]', "*"),
            ("entry_points", "[]", "a.py"),
            ("allowed_dependencies", "[]", "fixture"),
        ):
            for value, suffix in (("true", ""), ("[true]", "[0]"), (json.dumps([repeat, repeat]), "[1]")):
                with self.subTest(field=field, value=value):
                    text = MODULE_POLICY.replace(f"{field} = {original}", f"{field} = {value}")
                    self.config_error(text, f"{self.config_path}: modules.fixture.{field}{suffix}")

    def test_module_paths_are_canonical(self) -> None:
        for field, original in (("files", '["*"]'), ("entry_points", "[]")):
            for path in ("", "/a", "a/", "a//b", "./a", "a/../b", "a/./b", "a\x00b"):
                with self.subTest(field=field, path=path):
                    text = MODULE_POLICY.replace(f"{field} = {original}", f"{field} = {json.dumps([path])}")
                    self.config_error(
                        text, f"modules.fixture.{field}[0]", "canonical repository-relative path",
                    )

    def test_module_contracts_check_id_is_reserved(self) -> None:
        self.config_error(
            BASE_CONFIG.replace("[checks.smoke]", "[checks.module-contracts]"),
            "checks.module-contracts",
        )

    def test_module_contracts_rejects_another_adapter_or_advisory_enforcement(self) -> None:
        for original, replacement, field in (
            ('adapter = "module_contracts"', 'adapter = "command"', "adapter"),
            ('enforcement = "enforced"', 'enforcement = "advisory"', "enforcement"),
        ):
            with self.subTest(field=field):
                config = BASE_CONFIG + MODULE_CHECK.replace(original, replacement)
                self.config_error(config, f"checks.module-contracts.{field}")

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

    def test_module_dirs_are_optional(self) -> None:
        self.assertIsNone(policy.load_config(self.repo).module_dirs)
        self.write_config('module_dirs = ["src", "tools/scripts"]\n' + BASE_CONFIG)
        self.assertEqual(
            policy.load_config(self.repo).module_dirs, ("src", "tools/scripts")
        )

    def test_module_dirs_require_a_list_of_relative_directory_paths(self) -> None:
        for value, key in (
            ('"src"', "module_dirs"),
            ('[""]', "module_dirs[0]"),
            ('["."]', "module_dirs[0]"),
            ('["/src"]', "module_dirs[0]"),
            ('["src/../other"]', "module_dirs[0]"),
            ('["src/"]', "module_dirs[0]"),
            ('["src\\u0000"]', "module_dirs[0]"),
        ):
            with self.subTest(value=value):
                self.config_error(f"module_dirs = {value}\n" + BASE_CONFIG, key, "expected")

    def test_module_dirs_wrong_types_name_the_offending_value(self) -> None:
        for value, key, actual in (
            ('{directory = "lib"}', "module_dirs", "{'directory': 'lib'}"),
            ('[["lib"]]', "module_dirs[0]", "['lib']"),
            ('["lib", 17]', "module_dirs[1]", "17"),
        ):
            with self.subTest(value=value):
                self.config_error(f"module_dirs = {value}\n" + BASE_CONFIG, key, actual)

    def test_duplicate_module_directory_names_the_value_and_index(self) -> None:
        self.config_error(
            'module_dirs = ["lib", "lib"]\n' + BASE_CONFIG,
            "module_dirs[1]",
            "duplicate 'lib'",
        )

    def test_python_import_roots_default_to_the_repository_root(self) -> None:
        self.assertEqual(policy.load_config(self.repo).python_import_roots, (".",))
        self.write_config('python_import_roots = ["src", ".", "vendor/lib"]\n' + BASE_CONFIG)
        self.assertEqual(policy.load_config(self.repo).python_import_roots, ("src", ".", "vendor/lib"))

    def test_python_import_roots_are_unique_canonical_paths(self) -> None:
        for value, key in (
            ('"src"', "python_import_roots"),
            ('[]', "python_import_roots"),
            ('[1]', "python_import_roots[0]"),
            ('[""]', "python_import_roots[0]"),
            ('["/src"]', "python_import_roots[0]"),
            ('["src/../lib"]', "python_import_roots[0]"),
            ('["src/*"]', "python_import_roots[0]"),
            ('["src", "src"]', "python_import_roots[1]"),
        ):
            with self.subTest(value=value):
                self.config_error(f"python_import_roots = {value}\n" + BASE_CONFIG, key, "expected")

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

    def test_not_applicable_entries_are_validated_in_order(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                "[code]",
                'not_applicable = [{ class = "missing", tier = 2, '
                'reason = "r" }, 0]\n\n[code]',
                1,
            )
        )
        with self.assertRaises(policy.ConfigError) as raised:
            policy.load_config(self.repo)
        self.assertEqual(
            str(raised.exception),
            f"{self.config_path}: not_applicable[0].class: expected a "
            "configured class (config, doc, python), got unknown class "
            "'missing'",
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

    def test_owners_adapter_is_unknown(self) -> None:
        self.config_error(
            BASE_CONFIG.replace('adapter = "command"', 'adapter = "owners"'),
            "checks.smoke.adapter",
            "one of command, clones",
            "got str 'owners'",
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

    def test_python_tests_rejects_workers_as_an_unknown_key(self) -> None:
        self.config_error(
            BASE_CONFIG
            + '\n[checks.tests]\nadapter = "python_tests"\ntier = 1\n'
            'enforcement = "enforced"\n'
            'run = ["{python}", "-m", "unittest", "discover"]\n'
            "tests_pattern = 'Ran (\\d+) tests'\n"
            "workers = 2\n",
            "checks.tests.workers",
            "allowed keys",
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


    def test_scalar_reader_messages_match_the_pre_table_readers(self) -> None:
        path = Path("/policy.toml")
        cases = (
            (policy._integer, {}, {},
             "/policy.toml: value: expected an integer, got missing"),
            (policy._integer, {"value": "x"}, {},
             "/policy.toml: value: expected an integer, got str 'x'"),
            (policy._integer, {"value": True}, {},
             "/policy.toml: value: expected an integer, got bool True"),
            (policy._integer, {"value": 1.5}, {},
             "/policy.toml: value: expected an integer, got float 1.5"),
            (policy._integer, {"value": float("inf")}, {},
             "/policy.toml: value: expected an integer, got float inf"),
            (policy._integer, {"value": 0}, {"minimum": 1},
             "/policy.toml: value: expected an integer >= 1, got 0"),
            (policy._integer, {"value": 5}, {"maximum": 4},
             "/policy.toml: value: expected an integer <= 4, got 5"),
            (policy._number, {}, {},
             "/policy.toml: value: expected a number, got missing"),
            (policy._number, {"value": "x"}, {},
             "/policy.toml: value: expected a finite number, got str 'x'"),
            (policy._number, {"value": True}, {},
             "/policy.toml: value: expected a finite number, got bool True"),
            (policy._number, {"value": float("inf")}, {},
             "/policy.toml: value: expected a finite number, got float inf"),
            (policy._number, {"value": float("nan")}, {},
             "/policy.toml: value: expected a finite number, got float nan"),
            (policy._number, {"value": 0.5}, {"minimum": 1},
             "/policy.toml: value: expected a finite number >= 1, got 0.5"),
            (policy._integer_list, {}, {},
             "/policy.toml: value: expected a list of integers, got missing"),
            (policy._integer_list, {"value": "x"}, {},
             "/policy.toml: value: expected a list of integers, got str 'x'"),
            (policy._integer_list, {"value": [1.5]}, {},
             "/policy.toml: value[0]: expected an integer, got float 1.5"),
            (policy._integer_list, {"value": [float("inf")]}, {},
             "/policy.toml: value[0]: expected an integer, got float inf"),
            (policy._integer_list, {"value": [0]}, {},
             "/policy.toml: value[0]: expected an integer from 1 to 4, got 0"),
            (policy._integer_list, {"value": [5]}, {},
             "/policy.toml: value[0]: expected an integer from 1 to 4, got 5"),
            (policy._string, {}, {},
             "/policy.toml: value: expected a non-empty string, got missing"),
            (policy._string, {"value": 1}, {},
             "/policy.toml: value: expected a string, got int 1"),
            (policy._string, {"value": ""}, {},
             "/policy.toml: value: expected a non-empty string, got str ''"),
            (policy._string, {"value": "   "}, {},
             "/policy.toml: value: expected a non-empty string, got str '   '"),
            (policy._string, {"value": float("inf")}, {},
             "/policy.toml: value: expected a string, got float inf"),
            (policy._string_list, {}, {},
             "/policy.toml: value: expected a list of strings, got missing"),
            (policy._string_list, {"value": "x"}, {},
             "/policy.toml: value: expected a list of strings, got str 'x'"),
            (policy._string_list, {"value": [1]}, {},
             "/policy.toml: value[0]: expected a string, got int 1"),
            (policy._string_list, {"value": [float("inf")]}, {},
             "/policy.toml: value[0]: expected a string, got float inf"),
            (policy._read_value, {}, {"rule": policy._TABLE},
             "/policy.toml: value: expected a table, got missing"),
            (policy._read_value, {"value": 1}, {"rule": policy._TABLE},
             "/policy.toml: value: expected a table, got int 1"),
            (policy._read_value, {}, {"rule": policy._BOOLEAN},
             "/policy.toml: value: expected a boolean, got missing"),
            (policy._read_value, {"value": 1}, {"rule": policy._BOOLEAN},
             "/policy.toml: value: expected a boolean, got int 1"),
            (policy._read_value, {"value": float("inf")},
             {"rule": policy._BOOLEAN},
             "/policy.toml: value: expected a boolean, got float inf"),
        )
        for reader, parent, options, expected in cases:
            with self.subTest(reader=reader.__name__, parent=parent):
                with self.assertRaises(policy.ConfigError) as raised:
                    reader(parent, "value", path, "value", **options)
                self.assertEqual(str(raised.exception), expected)
        self.assertEqual(
            policy._string_list({"value": []}, "value", path, "value"), ()
        )
        self.assertEqual(
            policy._integer_list({"value": []}, "value", path, "value"), ()
        )

    def test_readers_accept_subclasses_as_before(self) -> None:
        class IntSubclass(int):
            pass

        class FloatSubclass(float):
            pass

        class StringSubclass(str):
            pass

        class ListSubclass(list):
            pass

        class DictSubclass(dict):
            pass

        path = Path("/policy.toml")
        integer = IntSubclass(2)
        self.assertIs(
            policy._integer({"value": integer}, "value", path, "value"),
            integer,
        )
        number = FloatSubclass(2.5)
        converted = policy._number({"value": number}, "value", path, "value")
        self.assertEqual(converted, 2.5)
        self.assertIs(type(converted), float)
        string = StringSubclass("text")
        self.assertIs(
            policy._string({"value": string}, "value", path, "value"),
            string,
        )
        members = [StringSubclass("a"), StringSubclass("b")]
        strings = policy._string_list(
            {"value": ListSubclass(members)}, "value", path, "value"
        )
        self.assertEqual(strings, ("a", "b"))
        self.assertIs(strings[0], members[0])
        self.assertIs(strings[1], members[1])
        integers = [IntSubclass(1), IntSubclass(4)]
        integer_list = policy._integer_list(
            {"value": ListSubclass(integers)}, "value", path, "value"
        )
        self.assertEqual(integer_list, (1, 4))
        self.assertIs(integer_list[0], integers[0])
        self.assertIs(integer_list[1], integers[1])
        table = DictSubclass({"key": "value"})
        self.assertIs(
            policy._read_value(
                {"value": table}, "value", path, "value", policy._TABLE
            ),
            table,
        )

    def test_the_default_converter_returns_its_value(self) -> None:
        value = object()
        self.assertIs(policy._identity(value), value)

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
        self.add_file(
            "shared.toml",
            'check = "one"\nmetric_version = "jscpd-clone-occurrences/1"\n',
        )
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

    def test_baseline_key_naming_a_missing_file_is_a_configuration_error(
        self,
    ) -> None:
        message = self.config_error(
            with_clones(),
            "checks.clones.baseline",
            "quality-gate-clones.toml",
            "does not exist",
        )
        self.assertIn("existing baseline file", message)

    def test_baseline_key_naming_a_directory_is_a_configuration_error(
        self,
    ) -> None:
        (self.repo / "quality-gate-clones.toml").mkdir()
        message = self.config_error(
            with_clones(),
            "checks.clones.baseline",
            "quality-gate-clones.toml",
            "does not exist",
        )
        self.assertIn("existing baseline file", message)

    def test_a_missing_baseline_header_file_raises_naming_its_path(self) -> None:
        path = self.repo / "missing-header.toml"
        with self.assertRaises(policy.ConfigError) as raised:
            policy._baseline_header(path)
        self.assertIn(str(path), str(raised.exception))

    def test_baseline_key_naming_an_existing_file_loads(self) -> None:
        self.add_file(
            "quality-gate-clones.toml",
            'check = "clones"\n'
            'metric_version = "jscpd-clone-occurrences/1"\n',
        )
        self.write_config(with_clones())
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 0, output(result))

    def test_this_repository_policy_loads(self) -> None:
        config = policy.load_config(GATE)
        for identifier in ("clones", "source-chars", "elisp-crap"):
            with self.subTest(check=identifier):
                self.assertIsNone(config.checks[identifier].baseline)

    def assert_default_shard_workers(self, config: policy.Config) -> None:
        parser = shards.build_parser()
        for identifier, check in config.checks.items():
            run = getattr(check.spec, "run", ())
            for position, arg in enumerate(run):
                if Path(arg).parts[-2:] == ("quality_gate", "test_shards.py"):
                    options = parser.parse_args(run[position + 1:])
                    self.assertEqual(options.workers, parser.get_default("workers"), identifier)
                    break

    def test_this_repository_policy_uses_default_shard_workers(self) -> None:
        self.assert_default_shard_workers(policy.load_config(GATE))

    def test_shard_worker_policy_rejects_fixed_counts(self) -> None:
        config = BASE_CONFIG.replace('"smoke"', '"tests"').replace(
            '[checks.smoke]\nadapter = "command"', '[checks.tests]\nadapter = "python_tests"',
        )
        run = ["{python}", "-I", "quality_gate/test_shards.py", "-s", "tests"]
        original_run = '["python3", "-c", "print(1)"]'
        self.write_config(config.replace(original_run, json.dumps(run)))
        self.assert_default_shard_workers(policy.load_config(self.repo))
        for args in (("-j", "4"), ("-j4",), ("--workers", "4"), ("--workers=4",)):
            with self.subTest(args=args):
                self.write_config(config.replace(original_run, json.dumps([*run, *args])))
                fixture = policy.load_config(self.repo)
                with self.assertRaises(AssertionError):
                    self.assert_default_shard_workers(fixture)

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

    def test_verification_requires_messages_match_72eb80c(self) -> None:
        cases = (
            (
                BASE_CONFIG
                + '\n[checks.verification]\nadapter = "verification"\n'
                'tier = 1\nenforcement = "enforced"\nrequires = "missing"\n'
                'baseline = "verification.toml"\n',
                "unknown check 'missing'",
            ),
            (
                BASE_CONFIG.replace("tests_pattern = '(\\d+)'\n", "")
                + '\n[checks.verification]\nadapter = "verification"\n'
                'tier = 1\nenforcement = "enforced"\nrequires = "smoke"\n'
                'baseline = "verification.toml"\n',
                "'smoke' is a command check that produces no tests "
                "(no tests_pattern)",
            ),
        )
        for config, actual in cases:
            with self.subTest(actual=actual):
                self.write_config(config)
                with self.assertRaises(policy.ConfigError) as raised:
                    policy.load_config(self.repo)
                self.assertEqual(
                    str(raised.exception),
                    f"{self.config_path}: checks.verification.requires: "
                    "expected the id of an earlier check that produces tests, "
                    f"got {actual}",
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
