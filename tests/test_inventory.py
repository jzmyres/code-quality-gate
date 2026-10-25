"""Tests for inventory classification and configuration errors."""
from __future__ import annotations

import importlib
import os
import socket
import subprocess
import sys
import unittest

from support import BASE_CONFIG, GATE, FixtureCase, output

sys.path.insert(0, str(GATE))
files = importlib.import_module("quality_gate.files")


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
                '[classes.empty]\ncode = true\ndescription = "Empty"\n'
                'checks = ["smoke"]\n\n'
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

    def test_a_rule_with_an_empty_pattern_fails(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[[rule]]\npattern = ""\nclass = "config"\n'
            'reason = "an empty pattern"\n'
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("empty pattern", text)

    def test_shebang_detection_is_skipped_without_patterns(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                'shebangs = ["sh", "bash", "python*"]', "shebangs = []"
            )
            + '\n[[rule]]\npattern = "script"\nclass = "doc"\n'
            'reason = "a shell script"\n'
        )
        self.add_file("script", "#!/bin/sh\necho hi\n")
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 0, output(result))

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

    def test_symlink_is_recorded_and_never_followed(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[[rule]]\npattern = "script*"\nclass = "doc"\n'
            'reason = "links"\n'
        )
        target = self.base / "outside-script"
        target.write_text("#!/bin/sh\necho outside\n", encoding="utf-8")
        (self.repo / "script-external").symlink_to(target)
        (self.repo / "script-dangling").symlink_to(self.base / "missing")
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 0, output(result))
        entries = files.enumerate_entries(self.repo)
        links = {entry.path for entry in entries if entry.path.startswith("script-")}
        self.assertEqual(links, {"script-external", "script-dangling"})
        self.assertTrue((self.repo / "script-external").is_symlink())

    def test_a_fifo_is_rejected(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[[rule]]\npattern = "pipe"\nclass = "doc"\n'
            'reason = "a fifo"\n'
        )
        self.add_file("pipe", "regular\n")
        self.git("add", "pipe")
        (self.repo / "pipe").unlink()
        os.mkfifo(self.repo / "pipe")
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("pipe", text)
        self.assertIn("unsupported file type FIFO", text)

    def test_a_socket_is_rejected(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[[rule]]\npattern = "sock"\nclass = "doc"\n'
            'reason = "a socket"\n'
        )
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        self.add_file("sock", "regular\n")
        self.git("add", "sock")
        (self.repo / "sock").unlink()
        server.bind(str(self.repo / "sock"))
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("sock", text)
        self.assertIn("unsupported file type socket", text)

    def test_an_untracked_metadata_shaped_name_is_its_own_file(self) -> None:
        name = "160000 " + "1" * 40 + " 0\tREADME.md"
        self.add_file(name, "x\n")
        entries = files.enumerate_entries(self.repo)
        paths = [entry.path for entry in entries]
        self.assertIn(name, paths)
        self.assertEqual(paths.count("README.md"), 1)
        for entry in entries:
            if entry.path == name:
                self.assertFalse(entry.gitlink)

    def test_a_deleted_worktree_file_is_reported(self) -> None:
        self.add_file("gone.py", "print('x')\n")
        self.git("add", "gone.py")
        (self.repo / "gone.py").unlink()
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("gone.py: cannot inspect", text)

    def test_shebang_reads_are_bounded(self) -> None:
        path = self.repo / "long-shebang"
        path.write_text(
            "#!/usr/bin/env python3\n" + "x" * 100000 + "\n",
            encoding="utf-8",
        )
        line = files._shebang_line(path)
        self.assertTrue(line.startswith("#!/usr/bin/env python3"))
        self.assertLessEqual(len(line.encode("utf-8")), files.SHEBANG_LIMIT)

    def test_gitlink_is_never_opened_and_needs_one_rule(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                "[classes.doc]",
                '[classes.gate]\ncode = false\n'
                'description = "Pinned submodule"\n\n'
                "[classes.doc]",
            )
            + '\n[[rule]]\npattern = "code-quality-gate"\n'
            'class = "gate"\nreason = "the pinned gate"\n'
        )
        self.git(
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,1111111111111111111111111111111111111111,"
            "code-quality-gate",
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 0, text)
        self.assertIn("inventory: 5 files match 5 rules", result.stdout)

    def test_gate_submodule_passes_the_quick_start_inventory(self) -> None:
        source = self.base / "gate-source"
        source.mkdir()
        env = self.env()
        subprocess.run(
            ["git", "init", "-q", "-b", "main"],
            cwd=source,
            env=env,
            check=True,
        )
        (source / "qg.py").write_text("# gate\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "qg.py"], cwd=source, env=env, check=True
        )
        subprocess.run(
            ["git", "commit", "-q", "-m", "gate"],
            cwd=source,
            env=env,
            check=True,
        )
        self.git(
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(source),
            "code-quality-gate",
        )
        self.write_config(
            BASE_CONFIG.replace(
                "[classes.doc]",
                '[classes.gate]\ncode = false\n'
                'description = "Pinned submodule"\n\n'
                "[classes.doc]",
            )
            + '\n[[rule]]\npattern = ".gitmodules"\n'
            'class = "config"\nreason = "submodule declarations"\n'
            '\n[[rule]]\npattern = "code-quality-gate"\n'
            'class = "gate"\nreason = "the pinned gate"\n'
        )
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 0, output(result))
        hygiene = self.run_qg("hygiene")
        self.assertEqual(hygiene.returncode, 0, output(hygiene))

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
            'schema = 2\n[classes.python]\ncode = true\n'
            'description = "Python"\nchecks = ["smoke"]\n'
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
            'schema = 2\n[code]\npatterns = ["*.py"]\n'
            'shebangs = ["python*"]\n'
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
                'schema = 2\ncode = "x"\n',
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
                'schema = 2\nclasses = "x"\n'
                "[code]\npatterns = []\nshebangs = []\n",
                "classes:",
            ),
            (
                "class entry is not a table",
                'schema = 2\nclasses = { python = "x" }\n'
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
        ]
        for name, config, key in cases:
            with self.subTest(name=name):
                self.write_config(config)
                result = self.run_qg("inventory")
                text = output(result)
                self.assertEqual(result.returncode, 2, text)
                self.assertIn(key, text)
                self.assertIn("expected", text)

    def test_check_tier_out_of_range_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[checks.bad]\nadapter = "command"\ntier = 5\n'
            'enforcement = "enforced"\nrun = ["true"]\n'
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("checks.bad.tier", text)
        self.assertIn("<= 4", text)

    def test_check_min_tokens_zero_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[checks.bad]\nadapter = "clones"\ntier = 1\n'
            'enforcement = "enforced"\nmin_tokens = 0\n'
            'baseline = "quality-gate-clones.toml"\n'
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("checks.bad.min_tokens", text)
        self.assertIn(">= 1", text)

    def test_check_missing_baseline_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[checks.bad]\nadapter = "clones"\ntier = 1\n'
            'enforcement = "enforced"\nmin_tokens = 50\n'
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("checks.bad.baseline", text)
        self.assertIn("missing", text)

    def test_check_unknown_key_exits_2(self) -> None:
        self.write_config(
            BASE_CONFIG
            + '\n[checks.bad]\nadapter = "command"\ntier = 1\n'
            'enforcement = "enforced"\nrun = ["true"]\nextra = 1\n'
        )
        result = self.run_qg("inventory")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("checks.bad.extra", text)
        self.assertIn("allowed keys", text)

    def test_no_command_exits_2(self) -> None:
        result = self.run_qg(include_repo=False)
        self.assertEqual(result.returncode, 2, output(result))

    def test_unknown_command_exits_2(self) -> None:
        result = self.run_qg("frobnicate")
        self.assertEqual(result.returncode, 2, output(result))


if __name__ == "__main__":
    unittest.main()
