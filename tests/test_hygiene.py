"""Tests for the hygiene command."""
from __future__ import annotations

import importlib
import os
import stat
import sys
import unittest

from support import BASE_CONFIG, GATE, FixtureCase, output

sys.path.insert(0, str(GATE))
files = importlib.import_module("quality_gate.files")


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

    def test_a_fifo_is_rejected(self) -> None:
        self.add_file("pipe", "regular\n")
        self.git("add", "pipe")
        (self.repo / "pipe").unlink()
        os.mkfifo(self.repo / "pipe")
        result = self.run_qg("hygiene")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("pipe", text)
        self.assertIn("unsupported file type FIFO", text)

    def test_a_deletion_is_not_measured(self) -> None:
        for staged in (False, True):
            with self.subTest(staged=staged):
                self.add_file("gone.md", "# gone\n")
                self.git("add", "gone.md")
                (self.repo / "gone.md").unlink()
                if staged:
                    self.git("add", "-u", "gone.md")
                result = self.run_qg("hygiene")
                text = output(result)
                self.assertEqual(result.returncode, 0, text)
                self.assertNotIn("gone.md", text)
                self.assertIn(
                    "hygiene: 4 files within 10485760 bytes", result.stdout
                )

    def test_a_missing_worktree_entry_fails_size_measurement(self) -> None:
        violations = files._size_violations(
            self.repo, [files.GitFile("missing.txt", None)], 10485760
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("missing.txt: cannot measure size", violations[0])

    def test_symlink_size_is_not_followed(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                "[classes.python]",
                "[hygiene]\nmax_bytes = 5000\n\n[classes.python]",
            )
        )
        target = self.base / "big-outside"
        target.write_text("x" * 6000, encoding="utf-8")
        (self.repo / "link.txt").symlink_to(target)
        result = self.run_qg("hygiene")
        self.assertEqual(result.returncode, 0, output(result))


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


class FileTypeTests(unittest.TestCase):
    def test_type_names_cover_regular_symlink_and_special_files(self) -> None:
        self.assertIsNone(files._type_name(stat.S_IFREG))
        self.assertIsNone(files._type_name(stat.S_IFLNK))
        self.assertEqual(files._type_name(stat.S_IFIFO), "FIFO")
        self.assertEqual(files._type_name(stat.S_IFSOCK), "socket")
        self.assertEqual(files._type_name(stat.S_IFCHR), "character device")
        self.assertEqual(files._type_name(stat.S_IFBLK), "block device")


if __name__ == "__main__":
    unittest.main()
