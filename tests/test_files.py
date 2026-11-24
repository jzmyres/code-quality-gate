"""Tests for interpreter detection and module directories in inventory."""
from __future__ import annotations

import importlib
import unittest

from support import BASE_CONFIG, FixtureCase, output

files = importlib.import_module("quality_gate.files")
policy = importlib.import_module("quality_gate.policy")


class ShebangParserTests(unittest.TestCase):
    def test_env_options_before_bash(self) -> None:
        for arguments in (
            "-S bash",
            "--split-string bash",
            "-u NAME bash",
            "--unset=NAME bash",
            "-i bash",
            "--ignore-environment bash",
            "- bash",
            "-C /some/dir bash",
            "--chdir=/some/dir bash",
            "NAME=VALUE bash",
            "-- bash",
            "-- NAME=VALUE bash",
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(
                    files._shebang_interpreter(f"#!/usr/bin/env {arguments}"),
                    "bash",
                )

    def test_env_parses_options_in_the_split_string(self) -> None:
        for arguments in (
            "-S -u NAME bash",
            "--split-string -C /some/dir bash",
            "-S -C 'some dir' bash",
            '-S --chdir="some dir" bash',
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(
                    files._shebang_interpreter(f"#!/usr/bin/env {arguments}"),
                    "bash",
                )

    def test_env_splits_whitespace_inside_an_argument(self) -> None:
        self.assertEqual(files._env_interpreter(["-S", "-u\tNAME  bash"]), "bash")
        self.assertEqual(files._env_interpreter(["--split-string", "-C 'some dir' bash"]), "bash")

    def test_env_option_terminator_allows_a_command_starting_with_dash(self) -> None:
        self.assertEqual(files._shebang_interpreter("#!/usr/bin/env -- -bash"), "-bash")

    def test_env_returns_no_interpreter_when_an_option_has_no_argument(self) -> None:
        self.assertIsNone(files._shebang_interpreter("#!/usr/bin/env -u"))


class ShebangInventoryTests(FixtureCase):
    def test_env_shebang_overrides_python_suffix(self) -> None:
        self.add_file("a.py", "#!/usr/bin/env -S -u NAME bash\ntrue\n")
        config = policy.load_config(self.repo)
        _, classes, violations = files.validate_inventory(self.repo, config)
        self.assertEqual(violations, [])
        self.assertEqual(classes.languages["a.py"], "bash")

    def test_env_unknown_option_fails_inventory(self) -> None:
        self.add_file("a.py", "#!/usr/bin/env -S --unknown=NAME bash\ntrue\n")
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("a.py: unsupported shebang env option '--unknown=NAME'", result.stderr)


class ModuleDirectoryInventoryTests(FixtureCase):
    def test_code_outside_modules_names_each_file_and_all_declared_modules(self) -> None:
        self.write_config('module_dirs = ["src", "tools"]\n' + BASE_CONFIG)
        self.add_file("src/README.md", "# Source\n")
        self.add_file("tools/README.md", "# Tools\n")
        self.add_file("tools-extra/run.py", "print('outside')\n")
        self.git("add", "src", "tools", "tools-extra")
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(
            result.stderr,
            "inventory: a.py: code file outside declared module directories ('src', 'tools')\n"
            "inventory: tools-extra/run.py: code file outside declared module directories ('src', 'tools')\n",
        )

    def test_code_in_nested_module_passes_with_non_code_at_root(self) -> None:
        self.write_config('module_dirs = ["src/core", "src"]\n' + BASE_CONFIG)
        self.add_file("src/core/a.py", self.read_file("a.py"))
        (self.repo / "a.py").unlink()
        self.add_file("tools.lock.toml", "")
        self.git("add", "src")
        result = self.run_qg("inventory", "--list", "python")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(result.stdout, "src/core/a.py\n")

    def test_unused_module_requires_a_tracked_file(self) -> None:
        self.write_config('module_dirs = ["src", "lib"]\n' + BASE_CONFIG)
        self.add_file("src/a.py", self.read_file("a.py"))
        (self.repo / "a.py").unlink()
        self.add_file("lib/README.md", "# Untracked\n")
        self.add_file("library/README.md", "# Tracked\n")
        self.git("add", "src", "library")
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(
            result.stderr,
            "inventory: module_dirs: unused module directory 'lib' (contains no tracked file)\n",
        )

    def test_omitting_module_dirs_preserves_inventory(self) -> None:
        self.write_config('module_dirs = []\n' + BASE_CONFIG)
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("a.py: code file outside declared module directories (none)", result.stderr)
        self.write_config()
        result = self.run_qg("inventory")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(result.stdout, "inventory: 4 files match 4 rules\n")
        self.assertEqual(result.stderr, "")

    def test_unclassified_shebang_code_outside_module_also_fails_placement(self) -> None:
        self.write_config('module_dirs = ["src"]\n' + BASE_CONFIG)
        self.add_file("scripts/run", "#!/bin/sh\ntrue\n")
        config = policy.load_config(self.repo)
        entries = [files.GitFile("scripts/run", None)]
        validator = files._InventoryValidator(
            self.repo, config, entries, [], [0] * len(config.rules), {}, set()
        )
        validator._classify_files()
        validator._check_module_placement({"scripts/run"}, ("src",))
        self.assertEqual(
            validator.violations,
            [
                "scripts/run: unclassified (no rule matches)",
                "scripts/run: code file outside declared module directories ('src')",
            ],
        )
