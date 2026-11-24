"""Tests for interpreter detection in the inventory."""
from __future__ import annotations

import importlib
import unittest

from support import FixtureCase, output

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
            "-S -u NAME bash",
            "--split-string -C /some/dir bash",
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(
                    files._shebang_interpreter(f"#!/usr/bin/env {arguments}"),
                    "bash",
                )

    def test_env_splits_whitespace_inside_an_argument(self) -> None:
        self.assertEqual(files._env_interpreter(["-S", "-u\tNAME  bash"]), "bash")

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
