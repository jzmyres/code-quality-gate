"""Tests for the removed-token symmetry adapter and its advisory check."""
from __future__ import annotations

import unittest
from typing import Any

from support import (
    BASE_CONFIG,
    FixtureCase,
    _add_check_to_class,
    baseline_text,
    output,
)


BASELINE = "quality-gate-removal-symmetry.toml"
METRIC_VERSION = "removal-symmetry/1"


def removal_config(
    *,
    enforcement: str = "advisory",
    include_untracked: bool = True,
    extra: str = "",
) -> str:
    text = _add_check_to_class(BASE_CONFIG, "python", "removal-symmetry")
    return text + (
        "\n[checks.removal-symmetry]\n"
        'adapter = "removal_symmetry"\n'
        "tier = 1\n"
        f'enforcement = "{enforcement}"\n'
        'scope = "changed"\n'
        'base = "HEAD^"\n'
        f"include_untracked = {str(include_untracked).lower()}\n"
        "min_token_chars = 16\n"
        'token_kinds = ["definition", "string"]\n'
        'scan_classes = ["python", "doc", "config"]\n'
        'exclude_paths = ["plans/**"]\n'
        f'baseline = "{BASELINE}"\n'
        f"{extra}"
    )


def removal_baseline(entries: list[dict[str, Any]]) -> str:
    return baseline_text(
        entries, check="removal-symmetry", metric_version=METRIC_VERSION
    )


def token_entry(subject: str, bound: int = 1) -> dict[str, Any]:
    return {
        "subject": subject,
        "bound": bound,
        "reason": "the fixture intentionally keeps the old token",
    }


class RemovalSymmetryCheckTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_config(removal_config())

    def run_removal_check(self) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        result, document = self.run_json()
        return result, document, self.check_by_id(document, "removal-symmetry")

    def finding(
        self, check: dict[str, Any], subject: str
    ) -> dict[str, Any]:
        return next(
            item for item in check["findings"] if item["subject"] == subject
        )

    def install_removed_definition(self, name: str, reference: str) -> None:
        self.add_file("pkg/mod.py", f"def {name}():\n    return 1\n")
        self.add_file(
            "tests/test_mod.py", f"def test_it():\n    {reference}\n"
        )
        self.commit_all()
        self.remove_product()

    def remove_product(self) -> None:
        self.add_file("pkg/mod.py", "VALUE = 1\n")
        self.commit_all()

    def findings_after_removal(self) -> dict[str, Any]:
        result, _document, check = self.run_removal_check()
        self.assertEqual(result.returncode, 0, output(result))
        return check

    def test_removed_definition_still_referenced_in_a_test_is_reported(self) -> None:
        self.install_removed_definition(
            "old_helper", "assert old_helper(1) == 1"
        )

        result, document, check = self.run_removal_check()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        self.assertEqual(check["outcome"], "fail")
        self.assertTrue(check["satisfied"])
        finding = self.finding(check, "old_helper@tests/test_mod.py")
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["location"], "tests/test_mod.py:2")
        self.assertFalse(finding["covered_by_baseline"])

    def test_removed_long_string_in_a_doc_is_reported_and_a_short_token_is_not(self) -> None:
        long_token = "allow this window with a warning"
        short_token = "tiny key"
        self.add_file(
            "pkg/mod.py",
            f'PROMPT = "{long_token}"\nSHORT = "{short_token}"\n',
        )
        self.add_file(
            "README.md", f"# fixture\n\n{long_token}\n\n{short_token}\n"
        )
        self.commit_all()
        self.remove_product()

        check = self.findings_after_removal()
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            [f"{long_token}@README.md"],
        )
        self.assertNotIn(short_token, str(check["findings"]))

    def test_excluded_paths_are_not_scanned(self) -> None:
        token = "obsolete message text"
        self.add_file("pkg/mod.py", f'MESSAGE = "{token}"\n')
        self.add_file("README.md", f"# fixture\n\n{token}\n")
        self.add_file("plans/notes.md", f"# old plan\n\n{token}\n")
        self.commit_all()
        self.remove_product()

        check = self.findings_after_removal()
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            [f"{token}@README.md"],
        )

    def test_untracked_files_are_not_searched_when_disabled(self) -> None:
        self.write_config(removal_config(include_untracked=False))
        token = "untracked message text"
        self.add_file("pkg/mod.py", f'MESSAGE = "{token}"\n')
        self.commit_all()
        self.remove_product()
        self.add_file("tests/test_mod.py", f'COPY = "{token}"\n')

        check = self.findings_after_removal()
        self.assertEqual(check["findings"], [])

    def test_baseline_entry_accepts_exactly_its_subject(self) -> None:
        self.write_config(removal_config(enforcement="enforced"))
        self.add_file(
            "pkg/mod.py",
            "def old_one():\n    return 1\n"
            "\n"
            "def old_two():\n    return 2\n",
        )
        self.add_file(
            "tests/test_mod.py",
            "def test_it():\n"
            "    assert old_one() == 1\n"
            "    assert old_two() == 2\n",
        )
        self.commit_all()
        self.remove_product()
        self.add_file(
            BASELINE,
            removal_baseline([token_entry("old_one@tests/test_mod.py")]),
        )

        result, document, check = self.run_removal_check()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        covered = self.finding(check, "old_one@tests/test_mod.py")
        self.assertTrue(covered["covered_by_baseline"])
        self.assertFalse(covered["blocking"])
        uncovered = self.finding(check, "old_two@tests/test_mod.py")
        self.assertFalse(uncovered["covered_by_baseline"])
        self.assertTrue(uncovered["blocking"])

    def test_advisory_findings_are_reported_and_exit_zero(self) -> None:
        self.install_removed_definition("stale_function", "stale_function()")

        result, document, check = self.run_removal_check()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["enforcement"], "advisory")
        self.assertEqual(check["outcome"], "fail")
        self.assertTrue(check["satisfied"])
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        self.finding(check, "stale_function@tests/test_mod.py")


if __name__ == "__main__":
    unittest.main()
