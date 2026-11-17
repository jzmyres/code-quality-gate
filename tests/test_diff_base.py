"""One gate run resolves QG_DIFF_BASE once and shares that commit."""
from __future__ import annotations

import unittest
from typing import Any
from unittest import mock

from support import (
    BASE_CONFIG,
    FixtureCase,
    _add_check_to_class,
    baseline_text,
    output,
)

from quality_gate import files


SOURCE_BASELINE = "quality-gate-source-chars.toml"

SOURCE_CHECK = (
    "\n[checks.source-chars]\n"
    'adapter = "source_chars"\n'
    "tier = 1\n"
    'enforcement = "enforced"\n'
    'scope = "changed"\n'
    'base = "HEAD"\n'
    f'baseline = "{SOURCE_BASELINE}"\n'
)

SHAPE_CHECKS = (
    "\n[checks.tests]\n"
    'adapter = "python_tests"\n'
    "tier = 1\n"
    'enforcement = "enforced"\n'
    'run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]\n'
    'tests_pattern = "^Ran (\\\\d+) tests? in"\n'
    "\n[checks.crap]\n"
    'adapter = "python_crap"\n'
    "tier = 1\n"
    'enforcement = "enforced"\n'
    'requires = "tests"\n'
    "threshold = 6\n"
    "\n[checks.shape]\n"
    'adapter = "python_shape"\n'
    "tier = 1\n"
    'enforcement = "enforced"\n'
    'scope = "changed"\n'
    'base = "HEAD"\n'
    'crap_check = "crap"\n'
)

BASE_FILES = {
    "pkg/mod.py": "def gone_helper():\n    return 1\n",
    "tests/test_mod.py": "def test_it():\n    gone_helper()\n",
}


def combined_config() -> str:
    text = BASE_CONFIG
    for identifier in ("source-chars", "shape"):
        text = _add_check_to_class(text, "python", identifier)
    return text + SOURCE_CHECK + SHAPE_CHECKS


class OneResolutionTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_config(combined_config())
        self.add_file(
            SOURCE_BASELINE,
            baseline_text(
                [], check="source-chars", metric_version="source-chars/1"
            ),
        )
        for relative, content in BASE_FILES.items():
            self.add_file(relative, content)
        self.commit_all("base")
        self.base_commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.add_file(
            "pkg/mod.py", "VALUE = 1  # \u202e hidden\n"
        )
        self.commit_all("change")

    def run_all(self, env: dict[str, str] | None = None) -> Any:
        return self.run_json(
            "--only", "source-chars", "shape", env=env
        )

    def measurements(self, document: dict[str, Any]) -> list[dict[str, str]]:
        return [
            self.check_by_id(document, identifier)["measurement"]["base"]
            for identifier in ("source-chars", "shape")
        ]

    def test_a_run_with_both_diffing_adapters_resolves_the_variable_once(self) -> None:
        original = files._verified_commit
        with mock.patch.object(
            files, "_verified_commit", wraps=original
        ) as checked:
            result, document = self.run_all(env={"QG_DIFF_BASE": self.base_commit})
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(checked.call_count, 1)
        self.assertEqual(
            {item["commit"] for item in self.measurements(document)},
            {self.base_commit},
        )

    def test_an_existing_tree_is_not_a_base_commit(self) -> None:
        tree = self.git("rev-parse", "HEAD^{tree}").stdout.strip()
        result, document = self.run_all(env={"QG_DIFF_BASE": tree})
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn(
            f"{files.DIFF_BASE_ENV} {tree!r}: expected an existing commit",
            document["error"],
        )

    def test_an_existing_blob_is_not_a_base_commit(self) -> None:
        blob = self.git("rev-parse", "HEAD:pkg/mod.py").stdout.strip()
        result, document = self.run_all(env={"QG_DIFF_BASE": blob})
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn(
            f"{files.DIFF_BASE_ENV} {blob!r}: expected an existing commit",
            document["error"],
        )

    def test_a_branch_that_moves_after_resolution_keeps_one_commit(self) -> None:
        self.git("branch", "moving", self.base_commit)
        original = files._verified_commit

        def verify_then_move(root: Any, value: str) -> Any:
            commit, problem = original(root, value)
            if value == "moving":
                self.git("branch", "-f", "moving", "HEAD")
            return commit, problem

        with mock.patch.object(
            files, "_verified_commit", side_effect=verify_then_move
        ):
            result, document = self.run_all(env={"QG_DIFF_BASE": "moving"})
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(
            self.measurements(document),
            [{"commit": self.base_commit, "source": "QG_DIFF_BASE"}] * 2,
        )


if __name__ == "__main__":
    unittest.main()
