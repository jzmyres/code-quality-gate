"""Tests for inventory classification and configuration errors."""
from __future__ import annotations

import unittest

from support import BASE_CONFIG, FixtureCase, output


class InventoryTests(FixtureCase):
    def test_valid_inventory_passes(self) -> None:
        self.add_file("b.py", "print('b')\n")
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 0, text)
        self.assertIn("inventory: 5 files match 4 rules", result.stdout)

    def test_list_class_prints_one_file_per_line(self) -> None:
        self.add_file("b.py", "print('b')\n")
        result = self.run_qg("inventory", "--list", "python")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(result.stdout, "a.py\nb.py\n")

    def test_list_unknown_class_exits_2(self) -> None:
        result = self.run_qg("inventory", "--list", "mystery")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("unknown class 'mystery'", text)

    def test_list_known_but_empty_class_prints_nothing(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                "[classes.python]",
                '[classes.empty]\ncode = true\ndescription = "Empty"\n\n'
                "[classes.python]",
            )
        )
        result = self.run_qg("inventory", "--list", "empty")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(result.stdout, "")

    def test_unclassified_file_fails(self) -> None:
        self.add_file("mystery.txt", "x\n")
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("mystery.txt", text)
        self.assertIn("unclassified", text)

    def test_file_matching_two_rules_fails(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[[rule]]\npattern = "*.py"\nclass = "python"\n'
            'reason = "too broad"\n'
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("a.py", text)
        self.assertIn("matches 2 rules", text)

    def test_rule_matching_no_file_fails(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[[rule]]\npattern = "missing/*.zzz"\nclass = "config"\n'
            'reason = "matches nothing"\n'
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("missing/*.zzz", text)
        self.assertIn("matches no file", text)

    def test_empty_reason_fails(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'reason = "Python source"', 'reason = "   "'
            )
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("empty reason", text)

    def test_unknown_rule_class_fails(self) -> None:
        self.write_config(
            BASE_CONFIG.replace('class = "python"', 'class = "mystery"')
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("unknown class 'mystery'", text)

    def test_code_file_by_pattern_in_non_code_class_fails(self) -> None:
        self.write_config(
            BASE_CONFIG.replace('class = "python"', 'class = "doc"', 1)
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("a.py", text)
        self.assertIn("code file classified as 'doc'", text)

    def test_code_file_by_shebang_in_non_code_class_fails(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[[rule]]\npattern = "script*"\nclass = "doc"\n'
            'reason = "shebang scripts"\n'
        )
        self.add_file(
            "script-env",
            "#!/usr/bin/env -S python3 -u\nprint('x')\n",
        )
        self.add_file(
            "script-assignment",
            "#!/usr/bin/env VAR=1 bash\necho hi\n",
        )
        self.add_file("script-direct", "#!/bin/sh -e\necho hi\n")
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        for name in ("script-env", "script-assignment", "script-direct"):
            self.assertIn(name, text)
        self.assertIn("code file classified as 'doc'", text)

    def test_non_code_shebang_in_non_code_class_passes(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[[rule]]\npattern = "tool"\nclass = "doc"\n'
            'reason = "a perl script"\n'
        )
        self.add_file("tool", "#!/usr/bin/env perl\nprint 1;\n")
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("inventory: 5 files match 5 rules", result.stdout)

    def test_code_file_by_shebang_in_code_class_passes(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[[rule]]\npattern = "script*"\nclass = "python"\n'
            'reason = "code scripts"\n'
        )
        self.add_file("script", "#!/usr/bin/env python3\nprint('x')\n")
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("inventory: 5 files match 5 rules", result.stdout)

    def test_unreadable_shebang_fails(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[[rule]]\npattern = "script"\nclass = "doc"\n'
            'reason = "dangling link"\n'
        )
        (self.repo / "script").symlink_to(self.base / "missing")
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("cannot read shebang", text)

    def test_every_violation_is_printed(self) -> None:
        self.add_file("mystery.txt", "x\n")
        self.write_config(
            BASE_CONFIG.replace(
                'reason = "Python source"', 'reason = "   "'
            )
            + '\n[[rule]]\npattern = "*.py"\nclass = "python"\n'
            'reason = "too broad"\n'
            + '\n[[rule]]\npattern = "missing/*.zzz"\nclass = "config"\n'
            'reason = "matches nothing"\n'
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("mystery.txt", text)
        self.assertIn("matches 2 rules", text)
        self.assertIn("empty reason", text)
        self.assertIn("matches no file", text)

    def test_enumeration_failure_fails_inventory(self) -> None:
        env = self.fake_git_failing_ls_files()
        result = self.run_qg("inventory", env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("file enumeration failed", text)
        self.assertIn("simulated enumeration failure", text)

    def test_repo_must_be_top_level_of_work_tree(self) -> None:
        subdirectory = self.repo / "sub"
        subdirectory.mkdir()
        result = self.run_qg("inventory", repo=subdirectory)
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("expected the top level of a git work tree", text)

    def test_repo_must_be_a_git_work_tree(self) -> None:
        plain = self.base / "plain"
        plain.mkdir()
        result = self.run_qg("inventory", repo=plain)
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("expected the top level of a git work tree", text)

    def test_default_repo_is_the_current_directory(self) -> None:
        result = self.run_qg("inventory", include_repo=False, cwd=self.repo)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("inventory: 4 files match 4 rules", result.stdout)

    def test_missing_config_exits_2(self) -> None:
        self.config_path.unlink()
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("quality-gate.toml", text)
        self.assertIn("expected", text)
        self.assertIn("missing", text)

    def test_invalid_toml_exits_2(self) -> None:
        self.write_config("[code\n")
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("quality-gate.toml", text)
        self.assertIn("valid TOML", text)

    def test_missing_code_section_exits_2(self) -> None:
        self.write_config(
            '[classes.python]\ncode = true\ndescription = "Python"\n'
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("code:", text)
        self.assertIn("expected a table", text)

    def test_patterns_wrong_type_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'patterns = ["*.py", "*.sh", "*.el"]',
                'patterns = "*.py"',
            )
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("code.patterns", text)
        self.assertIn("list of strings", text)

    def test_pattern_item_wrong_type_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'patterns = ["*.py", "*.sh", "*.el"]',
                "patterns = [1]",
            )
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("code.patterns[0]", text)
        self.assertIn("expected a string", text)

    def test_missing_shebangs_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'shebangs = ["sh", "bash", "python*"]\n', ""
            )
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("code.shebangs", text)
        self.assertIn("missing", text)

    def test_missing_classes_section_exits_2(self) -> None:
        self.write_config(
            '[code]\npatterns = ["*.py"]\nshebangs = ["python*"]\n'
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("classes:", text)
        self.assertIn("expected a table", text)

    def test_class_missing_code_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'code = true\ndescription = "Python source"',
                'description = "Python source"',
            )
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("classes.python.code", text)
        self.assertIn("missing", text)

    def test_class_code_wrong_type_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'code = true\ndescription = "Python source"',
                'code = "yes"\ndescription = "Python source"',
            )
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("classes.python.code", text)
        self.assertIn("expected a boolean", text)

    def test_class_description_empty_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'description = "Python source"', 'description = ""'
            )
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("classes.python.description", text)
        self.assertIn("non-empty string", text)

    def test_rule_missing_pattern_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'pattern = "*.py"\nclass = "python"\nreason = "Python source"',
                'class = "python"\nreason = "Python source"',
            )
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("rule[0].pattern", text)
        self.assertIn("missing", text)

    def test_rule_missing_class_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'class = "python"\nreason = "Python source"',
                'reason = "Python source"',
            )
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("rule[0].class", text)
        self.assertIn("missing", text)

    def test_rule_reason_wrong_type_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'reason = "Python source"', "reason = 1"
            )
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("rule[0].reason", text)
        self.assertIn("expected a string", text)

    def test_rule_wrong_type_exits_2(self) -> None:
        config = BASE_CONFIG.split("[[rule]]", 1)[0]
        self.write_config('rule = "not a table"\n' + config)
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("rule:", text)
        self.assertIn("array of tables", text)

    def test_hygiene_max_bytes_wrong_type_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                "[classes.python]",
                '[hygiene]\nmax_bytes = "big"\n\n[classes.python]',
            )
        )
        result = self.run_qg("hygiene")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("hygiene.max_bytes", text)
        self.assertIn("expected an integer", text)

    def test_hygiene_max_bytes_negative_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                "[classes.python]",
                "[hygiene]\nmax_bytes = -1\n\n[classes.python]",
            )
        )
        result = self.run_qg("hygiene")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("hygiene.max_bytes", text)
        self.assertIn(">= 0", text)

    def test_other_invalid_config_values_exit_2(self) -> None:
        cases = [
            (
                "code section is not a table",
                'code = "x"\n',
                "code:",
            ),
            (
                "patterns missing",
                BASE_CONFIG.replace(
                    'patterns = ["*.py", "*.sh", "*.el"]\n', ""
                ),
                "code.patterns",
            ),
            (
                "shebang item is not a string",
                BASE_CONFIG.replace(
                    'shebangs = ["sh", "bash", "python*"]',
                    "shebangs = [1]",
                ),
                "code.shebangs[0]",
            ),
            (
                "classes is not a table",
                'classes = "x"\n[code]\npatterns = []\nshebangs = []\n',
                "classes:",
            ),
            (
                "class entry is not a table",
                'classes = { python = "x" }\n'
                "[code]\npatterns = []\nshebangs = []\n",
                "classes.python",
            ),
            (
                "class description is not a string",
                BASE_CONFIG.replace(
                    'description = "Python source"', "description = 1"
                ),
                "classes.python.description",
            ),
            (
                "hygiene is not a table",
                'hygiene = "x"\n' + BASE_CONFIG,
                "hygiene:",
            ),
            (
                "clones is not a table",
                'clones = "x"\n' + BASE_CONFIG,
                "clones:",
            ),
            (
                "clones min_tokens is not an integer",
                BASE_CONFIG
                + '\n[clones]\nclasses = ["python"]\nmin_tokens = "x"\n'
                'baseline = "quality-gate-clones.toml"\n',
                "clones.min_tokens",
            ),
            (
                "clones baseline is not a string",
                BASE_CONFIG
                + '\n[clones]\nclasses = ["python"]\nbaseline = 1\n',
                "clones.baseline",
            ),
            (
                "clones classes item is not a string",
                BASE_CONFIG
                + "\n[clones]\nclasses = [1]\n"
                'baseline = "quality-gate-clones.toml"\n',
                "clones.classes[0]",
            ),
            (
                "class description missing",
                BASE_CONFIG.replace(
                    'description = "Python source"\n', ""
                ),
                "classes.python.description",
            ),
            (
                "rule entry is not a table",
                'rule = [1]\n' + BASE_CONFIG.split("[[rule]]", 1)[0],
                "rule[0]",
            ),
            (
                "rule pattern is not a string",
                BASE_CONFIG.replace('pattern = "*.py"', "pattern = 1"),
                "rule[0].pattern",
            ),
            (
                "rule class is not a string",
                BASE_CONFIG.replace('class = "python"', "class = 1"),
                "rule[0].class",
            ),
            (
                "rule reason missing",
                BASE_CONFIG.replace(
                    'reason = "Python source"\n', ""
                ),
                "rule[0].reason",
            ),
            (
                "clones classes missing",
                BASE_CONFIG
                + "\n[clones]\nmin_tokens = 50\n"
                'baseline = "quality-gate-clones.toml"\n',
                "clones.classes",
            ),
            (
                "clones baseline empty",
                BASE_CONFIG
                + '\n[clones]\nclasses = ["python"]\nmin_tokens = 50\n'
                'baseline = ""\n',
                "clones.baseline",
            ),
        ]
        for name, config, key in cases:
            with self.subTest(name=name):
                self.write_config(config)
                result = self.run_qg("inventory")
                text = output(result)
                self.assertEqual(result.returncode, 2, text)
                self.assertIn(key, text)
                self.assertIn("expected", text)

    def test_clones_unknown_class_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[clones]\nclasses = ["mystery"]\nmin_tokens = 50\n'
            'baseline = "quality-gate-clones.toml"\n'
        )
        result = self.run_qg("clones")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("clones.classes", text)
        self.assertIn("unknown class 'mystery'", text)

    def test_clones_min_tokens_zero_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[clones]\nclasses = ["python"]\nmin_tokens = 0\n'
            'baseline = "quality-gate-clones.toml"\n'
        )
        result = self.run_qg("clones")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("clones.min_tokens", text)
        self.assertIn(">= 1", text)

    def test_clones_missing_baseline_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[clones]\nclasses = ["python"]\nmin_tokens = 50\n'
        )
        result = self.run_qg("clones")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("clones.baseline", text)
        self.assertIn("missing", text)

    def test_clones_classes_wrong_type_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[clones]\nclasses = "python"\nmin_tokens = 50\n'
            'baseline = "quality-gate-clones.toml"\n'
        )
        result = self.run_qg("clones")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("clones.classes", text)
        self.assertIn("list of strings", text)

    def test_no_command_exits_2(self) -> None:
        result = self.run_qg(include_repo=False)
        self.assertEqual(result.returncode, 2, output(result))

    def test_unknown_command_exits_2(self) -> None:
        result = self.run_qg("frobnicate")
        self.assertEqual(result.returncode, 2, output(result))


if __name__ == "__main__":
    unittest.main()
