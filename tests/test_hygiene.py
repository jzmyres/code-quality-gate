"""Tests for the hygiene command."""
from __future__ import annotations

import unittest

from support import BASE_CONFIG, FixtureCase, output


class HygieneTests(FixtureCase):
    def test_clean_repository_passes(self) -> None:
        result = self.run_qg("hygiene")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("hygiene: 4 files within 10485760 bytes", result.stdout)

    def test_tracked_file_matching_ignore_rules_fails(self) -> None:
        self.add_file(".gitignore", "secret.log\n")
        self.add_file("secret.log", "secret\n")
        self.git("add", "-f", "secret.log")
        result = self.run_qg("hygiene")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("tracked file matches ignore rules", text)
        self.assertIn("secret.log", text)

    def test_untracked_ignored_file_does_not_fail(self) -> None:
        self.add_file(".gitignore", "secret.log\n")
        self.add_file("secret.log", "secret\n")
        result = self.run_qg("hygiene")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("hygiene: 4 files within 10485760 bytes", result.stdout)

    def test_file_exceeding_max_bytes_fails(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                "[classes.python]",
                "[hygiene]\nmax_bytes = 5000\n\n[classes.python]",
            )
        )
        self.add_file("big.txt", "x" * 5001)
        result = self.run_qg("hygiene")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("big.txt", text)
        self.assertIn("5001 bytes exceeds max_bytes 5000", text)

    def test_size_measurement_failure_fails(self) -> None:
        (self.repo / "broken").symlink_to(self.base / "missing")
        result = self.run_qg("hygiene")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("cannot measure size", text)
        self.assertIn("broken", text)

    def test_ignored_enumeration_failure_fails_hygiene(self) -> None:
        env = self.fake_git_failing_ls_files()
        result = self.run_qg("hygiene", env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("hygiene:", text)
        self.assertIn("ignored-file enumeration failed", text)
        self.assertIn("simulated enumeration failure", text)

    def test_file_enumeration_failure_fails_hygiene(self) -> None:
        env = self.fake_git_failing_file_enumeration()
        result = self.run_qg("hygiene", env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("hygiene:", text)
        self.assertIn("file enumeration failed", text)
        self.assertIn("simulated file enumeration failure", text)

    def test_default_max_bytes_is_used(self) -> None:
        result = self.run_qg("hygiene")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("10485760", result.stdout)


if __name__ == "__main__":
    unittest.main()
