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
ELISP_RULE = (
    "\n[[rule]]\n"
    'pattern = "*.el"\n'
    'class = "python"\n'
    'reason = "Elisp source"\n'
)


def removal_config(
    *,
    enforcement: str = "advisory",
    search_untracked: bool = True,
    base: str = "HEAD^",
    scope: str | None = "changed",
    scan_classes: str = '["python", "doc", "config"]',
    extra: str = "",
) -> str:
    text = _add_check_to_class(BASE_CONFIG, "python", "removal-symmetry")
    scope_line = "" if scope is None else f'scope = "{scope}"\n'
    return text + (
        "\n[checks.removal-symmetry]\n"
        'adapter = "removal_symmetry"\n'
        "tier = 1\n"
        f'enforcement = "{enforcement}"\n'
        f"{scope_line}"
        f'base = "{base}"\n'
        f"search_untracked = {str(search_untracked).lower()}\n"
        "min_token_chars = 16\n"
        'token_kinds = ["definition", "string"]\n'
        f"scan_classes = {scan_classes}\n"
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
        self.add_file(BASELINE, removal_baseline([]))
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
        self.write_config(removal_config(search_untracked=False))
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

    def test_scope_all_parses_removals_outside_the_listed_classes(self) -> None:
        self.write_config(removal_config(scope="all", scan_classes='["doc"]'))
        token = "scope all removed token"
        self.add_file("README.md", f'# fixture\n\nPROMPT = "{token}"\n')
        self.add_file("docs/other.md", f"# other\n\n{token}\n")
        self.commit_all()
        self.add_file("README.md", "# fixture\n")
        self.commit_all()

        check = self.findings_after_removal()
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            [f"{token}@docs/other.md"],
        )

    def test_a_deleted_file_still_contributes_its_removals(self) -> None:
        self.write_config(removal_config(scope=None))
        self.add_file("pkg/gone.py", "def deleted_helper():\n    return 1\n")
        self.add_file(
            "tests/test_mod.py",
            "def test_it():\n    assert deleted_helper() == 1\n",
        )
        self.commit_all()
        (self.repo / "pkg/gone.py").unlink()
        self.commit_all()

        check = self.findings_after_removal()
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            ["deleted_helper@tests/test_mod.py"],
        )

    def test_an_edited_definition_line_is_not_reported(self) -> None:
        self.add_file(
            "pkg/mod.py", "def kept_helper(value):\n    return value\n"
        )
        self.add_file(
            "tests/test_mod.py",
            "def test_it():\n    assert kept_helper(1) == 1\n",
        )
        self.commit_all()
        self.add_file(
            "pkg/mod.py",
            "def kept_helper(value, extra):\n    return value\n",
        )
        self.commit_all()

        self.assertEqual(self.findings_after_removal()["findings"], [])

    def test_an_added_annotation_is_not_reported(self) -> None:
        self.add_file("pkg/mod.py", "VALUE = 1\n")
        self.commit_all()
        self.add_file("pkg/mod.py", "VALUE: int = 1\n")
        self.commit_all()

        self.assertEqual(self.findings_after_removal()["findings"], [])

    def test_a_function_moved_to_another_file_is_not_reported(self) -> None:
        self.add_file("pkg/mod.py", "def moved_helper():\n    return 1\n")
        self.add_file(
            "tests/test_mod.py", "def test_it():\n    moved_helper()\n"
        )
        self.commit_all()
        self.add_file("pkg/mod.py", "VALUE = 1\n")
        self.add_file("pkg/other.py", "def moved_helper():\n    return 1\n")
        self.commit_all()

        self.assertEqual(self.findings_after_removal()["findings"], [])

    def test_an_elisp_definition_is_reported(self) -> None:
        self.write_config(removal_config(extra=ELISP_RULE))
        self.add_file("pkg/mod.el", "(defun old-helper ()\n  nil)\n")
        self.add_file("README.md", "# fixture\n\nold-helper\n")
        self.commit_all()
        self.add_file("pkg/mod.el", "(defun new-helper ()\n  nil)\n")
        self.commit_all()

        check = self.findings_after_removal()
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            ["old-helper@README.md"],
        )

    def test_a_definition_matches_only_on_identifier_boundaries(self) -> None:
        self.add_file("pkg/mod.py", "def mark():\n    return 1\n")
        self.add_file("README.md", "# fixture\n\nmarker\n")
        self.commit_all()
        self.remove_product()

        self.assertEqual(self.findings_after_removal()["findings"], [])

    def test_scan_classes_limit_the_search_domain(self) -> None:
        self.write_config(removal_config(scan_classes='["python"]'))
        token = "only in documentation text"
        self.add_file("pkg/mod.py", f'MESSAGE = "{token}"\n')
        self.add_file("README.md", f"# fixture\n\n{token}\n")
        self.commit_all()
        self.remove_product()

        self.assertEqual(self.findings_after_removal()["findings"], [])

    def test_the_baseline_file_is_not_searched(self) -> None:
        self.add_file("pkg/mod.py", "def ghost_token():\n    return 1\n")
        self.commit_all()
        self.remove_product()
        self.add_file(
            BASELINE,
            removal_baseline([token_entry("ghost_token@tests/test_mod.py")]),
        )

        self.assertEqual(self.findings_after_removal()["findings"], [])

    def test_excluded_paths_contribute_no_removals(self) -> None:
        token = "planned obsolete text"
        self.add_file("plans/gone.py", f'MESSAGE = "{token}"\n')
        self.add_file("README.md", f"# fixture\n\n{token}\n")
        self.commit_all()
        self.add_file("plans/gone.py", "VALUE = 1\n")
        self.commit_all()

        self.assertEqual(self.findings_after_removal()["findings"], [])

    def test_a_token_exactly_at_min_token_chars_is_a_finding(self) -> None:
        token = "1234567890123456"
        self.add_file("pkg/mod.py", f'MESSAGE = "{token}"\n')
        self.add_file("README.md", f"# fixture\n\n{token}\n")
        self.commit_all()
        self.remove_product()

        check = self.findings_after_removal()
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            [f"{token}@README.md"],
        )

    def test_an_invalid_base_is_a_configuration_error(self) -> None:
        self.write_config(removal_config(base="not-a-revision"))

        result, document, check = self.run_removal_check()
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn("not-a-revision", document["error"])
        self.assertEqual(check["outcome"], "error")

    def test_diff_mnemonic_prefix_does_not_hide_a_finding(self) -> None:
        self.git("config", "diff.mnemonicPrefix", "true")
        self.install_removed_definition("mnemonic_helper", "mnemonic_helper()")

        check = self.findings_after_removal()
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            ["mnemonic_helper@tests/test_mod.py"],
        )

    def test_a_non_ascii_path_still_gives_its_finding(self) -> None:
        self.add_file("pkg/café.py", "def nonascii_helper():\n    return 1\n")
        self.add_file(
            "tests/test_mod.py", "def test_it():\n    nonascii_helper()\n"
        )
        self.commit_all()
        self.add_file("pkg/café.py", "VALUE = 1\n")
        self.commit_all()

        check = self.findings_after_removal()
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            ["nonascii_helper@tests/test_mod.py"],
        )

    def test_an_undecodable_scanned_file_is_reported_not_measured(self) -> None:
        self.add_file("pkg/mod.py", "def binary_helper():\n    return 1\n")
        self.add_file(
            "tests/test_mod.py", "def test_it():\n    binary_helper()\n"
        )
        self.add_file("docs/binary.md", b"# fixture\n\xff\n")
        self.commit_all()
        self.remove_product()

        check = self.findings_after_removal()
        subjects = [item["subject"] for item in check["findings"]]
        self.assertIn("binary_helper@tests/test_mod.py", subjects)
        self.assertIn("docs/binary.md:not-measured", subjects)

    def test_an_escaped_quote_matches_its_unescaped_form(self) -> None:
        self.add_file(
            "pkg/mod.py", 'MESSAGE = "say \\"hello\\" to the window"\n'
        )
        self.add_file(
            "README.md", '# fixture\n\nsay "hello" to the window\n'
        )
        self.commit_all()
        self.remove_product()

        check = self.findings_after_removal()
        self.assertEqual(
            [item["subject"] for item in check["findings"]],
            ['say "hello" to the window@README.md'],
        )

    def test_a_still_quoted_path_is_a_configuration_error(self) -> None:
        self.add_file('pkg/odd"name.py', "VALUE = 1\n")
        self.commit_all()
        self.add_file('pkg/odd"name.py', "VALUE = 2\n")
        self.commit_all()

        result, document, check = self.run_removal_check()
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn('pkg/odd\\"name.py', document["error"])
        self.assertEqual(check["outcome"], "error")


if __name__ == "__main__":
    unittest.main()
