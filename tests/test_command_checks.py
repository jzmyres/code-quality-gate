"""Tests for command checks, tool tokens and termination reporting."""
from __future__ import annotations

import json
import unittest

from support import (
    BASE_CONFIG,
    FixtureCase,
    _add_check_to_class,
    output,
)


def with_command(
    run: str,
    *,
    identifier: str = "lint",
    budget: int | None = None,
    must_match: str | None = None,
    enforcement: str = "enforced",
    classes: tuple[str, ...] = ("python",),
) -> str:
    text = BASE_CONFIG
    for name in classes:
        text = _add_check_to_class(text, name, identifier)
    lines = [
        "",
        f"[checks.{identifier}]",
        'adapter = "command"',
        "tier = 1",
        f'enforcement = "{enforcement}"',
        f"run = {run}",
    ]
    if budget is not None:
        lines.append(f"budget_seconds = {budget}")
    if must_match is not None:
        lines.append(f"must_match = {json.dumps(must_match)}")
    return text + "\n".join(lines) + "\n"


class CommandCheckTests(FixtureCase):
    def failed_lint(
        self, *, env: dict[str, str] | None = None
    ) -> tuple[object, dict[str, object]]:
        result, document = self.run_json(env=env)
        self.assertEqual(result.returncode, 1, output(result))
        return result, self.check_by_id(document, "lint")

    def test_command_check_passes(self) -> None:
        self.write_config(
            with_command('["python3", "-c", "print(\'ok\')"]')
        )
        result = self.run_qg("check")
        text = output(result)
        self.assertEqual(result.returncode, 0, text)
        self.assertIn("check: lint (command)", text)
        self.assertIn("check: lint: passed", text)
        self.assertIn("check: passed", text)

    def test_command_check_failure_exits_one(self) -> None:
        self.write_config(
            with_command(
                '["python3", "-c", "import sys; sys.exit(3)"]'
            )
        )
        result = self.run_qg("check")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("check: lint: command exited 3", text)
        self.assertIn("check: failed (lint)", text)

    def test_command_timeout_reports_budget_termination(self) -> None:
        self.write_config(
            with_command(
                '["python3", "-c", "import time; time.sleep(10)"]',
                budget=1,
            )
        )
        result, check = self.failed_lint()
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(check["termination"], "budget")
        self.assertEqual(check["budget_seconds"], 1)
        self.assertGreaterEqual(check["duration_seconds"], 0)
        self.assertIn("exceeded its 1 second budget", result.stderr)

    def test_must_match_passes_on_combined_output(self) -> None:
        self.write_config(
            with_command(
                '["python3", "-c", "import sys; '
                "print('needle', file=sys.stderr)\"]",
                must_match="needle",
            )
        )
        result = self.run_qg("check")
        self.assertEqual(result.returncode, 0, output(result))

    def test_missing_must_match_fails(self) -> None:
        self.write_config(
            with_command(
                '["python3", "-c", "print(\'haystack\')"]',
                must_match="needle",
            )
        )
        result = self.run_qg("check")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("did not match must_match", text)
        self.assertIn("needle", text)

    def test_command_with_no_files_selected_fails(self) -> None:
        self.write_config(
            with_command(
                '["python3", "-c", "print(\'x\')", "{files}"]',
                classes=("empty",),
            )
        )
        result, check = self.failed_lint()
        self.assertEqual(check["outcome"], "fail")
        self.assertIn("no files selected", result.stderr)

    def test_unknown_tool_is_unsupported(self) -> None:
        self.write_config(with_command('["{tool:mystery}"]'))
        result, check = self.failed_lint()
        self.assertEqual(check["outcome"], "unsupported")
        self.assertIn("unknown tool 'mystery'", result.stderr)
        self.assertIn("tools fetch", result.stderr)

    def test_unfetched_tool_is_unsupported(self) -> None:
        self.write_config(with_command('["{tool:ruff}", "--version"]'))
        result, check = self.failed_lint(
            env={"QG_TOOLS_DIR": str(self.base / "empty-tools")}
        )
        self.assertEqual(check["outcome"], "unsupported")
        self.assertIn("not installed", result.stderr)
        self.assertIn("tools fetch", result.stderr)

    def test_real_ruff_runs_when_it_is_installed(self) -> None:
        binary = self.ruff_binary()
        if not binary.is_file():
            self.skipTest(
                "ruff is not installed; run python3 -I qg.py tools fetch"
            )
        self.write_config(with_command('["{tool:ruff}", "--version"]'))
        result, document = self.run_json(env=self.default_tool_env())
        self.assertEqual(result.returncode, 0, output(result))
        check = self.check_by_id(document, "lint")
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(check["termination"], "exit")


if __name__ == "__main__":
    unittest.main()
