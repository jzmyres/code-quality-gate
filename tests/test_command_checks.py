"""Tests for command checks, tool tokens and execution reporting."""
from __future__ import annotations

import json
import os
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
    tests_pattern: str | None = None,
    skipped_pattern: str | None = None,
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
    if tests_pattern is not None:
        lines.append(f"tests_pattern = {json.dumps(tests_pattern)}")
    if skipped_pattern is not None:
        lines.append(f"skipped_pattern = {json.dumps(skipped_pattern)}")
    return text + "\n".join(lines) + "\n"


class CommandCheckTests(FixtureCase):
    def failed_lint(
        self, *, env: dict[str, str] | None = None
    ) -> tuple[object, dict[str, object]]:
        result, document = self.run_json(env=env)
        self.assertEqual(result.returncode, 1, output(result))
        return result, self.check_by_id(document, "lint")

    def require_real_ruff(self) -> None:
        if not self.ruff_binary().is_file():
            self.skipTest(
                "ruff is not installed; run python3 -I qg.py tools fetch"
            )

    def assert_lint_outcome(
        self, document: dict[str, object], outcome: str
    ) -> None:
        check = self.check_by_id(document, "lint")
        self.assertEqual(check["outcome"], outcome)

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

    def test_command_timeout_reports_budget_execution(self) -> None:
        self.write_config(
            with_command(
                '["python3", "-c", "import time; time.sleep(10)"]',
                budget=1,
            )
        )
        result, check = self.failed_lint()
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(check["execution"], "budget")
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
        self.require_real_ruff()
        self.write_config(with_command('["{tool:ruff}", "--version"]'))
        result, document = self.run_json(env=self.default_tool_env())
        self.assertEqual(result.returncode, 0, output(result))
        self.assert_lint_outcome(document, "pass")
        check = self.check_by_id(document, "lint")
        self.assertEqual(check["execution"], "completed")

    def test_real_ruff_rejects_then_accepts_a_fixture(self) -> None:
        self.require_real_ruff()
        self.write_config(
            with_command(
                '["{tool:ruff}", "check", "--no-cache", "{files}"]'
            )
        )
        self.add_file("-x.py", "import os\n")
        self.add_file("space name.py", "import sys\n")
        result, document = self.run_json(env=self.default_tool_env())
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assert_lint_outcome(document, "fail")
        self.assertIn("F401", text)
        self.assertIn("-x.py", text)
        self.assertIn("space name.py", text)
        self.add_file("-x.py", "print('fixed')\n")
        self.add_file("space name.py", "print('fixed')\n")
        result, document = self.run_json(env=self.default_tool_env())
        self.assertEqual(result.returncode, 0, output(result))
        self.assert_lint_outcome(document, "pass")


    def test_command_tests_pattern_counts_executed_tests(self) -> None:
        run = json.dumps(
            ["python3", "-c", "print('Ran 2 tests in 0.10s')"]
        )
        self.write_config(
            with_command(run, tests_pattern="^Ran (\\d+) tests? in")
        )
        result, document = self.run_json()
        self.assertEqual(result.returncode, 0, output(result))
        check = self.check_by_id(document, "lint")
        self.assertEqual(check["evidence"], ["tests"])
        self.assertEqual(check["measurement"], {"tests": 2})
        obligation = document["obligations"][0]
        self.assertIn("lint", obligation["checks"])

    def test_command_with_zero_executed_tests_fails(self) -> None:
        run = json.dumps(
            [
                "python3",
                "-c",
                "print('Ran 1 test in 0.10s'); print('skipped=1')",
            ]
        )
        self.write_config(
            with_command(
                run,
                tests_pattern="^Ran (\\d+) tests? in",
                skipped_pattern="skipped=(\\d+)",
            )
        )
        result, check = self.failed_lint()
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(check["measurement"], {"tests": 0})
        self.assertIn("no test executed: 1 ran, 1 skipped", result.stderr)

    def test_failing_command_diagnostics_name_argv_and_exit(self) -> None:
        run = json.dumps(
            ["python3", "-c", "import sys; print('bad output'); sys.exit(7)"]
        )
        self.write_config(with_command(run))
        result, check = self.failed_lint()
        diagnostics = check["diagnostics"]
        self.assertEqual(diagnostics["exit_code"], 7)
        self.assertIsNone(diagnostics["signal"])
        self.assertIn("bad output", diagnostics["output_tail"])
        self.assertIn("-c", diagnostics["argv"])
        self.assertIn("bad output", diagnostics["argv"][-1])
        self.assertGreater(diagnostics["output_bytes"], 0)

    def test_missing_executable_is_an_execution_error(self) -> None:
        self.write_config(
            with_command('["/nonexistent/qg-command"]')
        )
        result, check = self.failed_lint()
        self.assertEqual(check["outcome"], "error")
        self.assertEqual(check["execution"], "error")
        self.assertIn("cannot run command", result.stderr)
        self.assertIn("cannot run command", check["diagnostics"]["error"])

    def test_signal_is_reported_as_signal(self) -> None:
        run = json.dumps(
            [
                "python3",
                "-c",
                "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
            ]
        )
        self.write_config(with_command(run))
        result, check = self.failed_lint()
        self.assertEqual(check["execution"], "signal")
        self.assertIsNone(check["diagnostics"]["exit_code"])
        self.assertEqual(check["diagnostics"]["signal"], 15)

    def test_budget_kills_the_whole_process_group(self) -> None:
        pid_file = self.base / "child.pid"
        script = (
            "import pathlib, subprocess, sys, time\n"
            "child = subprocess.Popen([\n"
            "    sys.executable, '-c',\n"
            "    'import signal, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "time.sleep(60)',\n"
            "])\n"
            f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))\n"
            "time.sleep(60)\n"
        )
        script_file = self.base / "spawn.py"
        script_file.write_text(script, encoding="utf-8")
        self.write_config(
            with_command(json.dumps(["python3", str(script_file)]), budget=1)
        )
        result, check = self.failed_lint()
        self.assertEqual(check["execution"], "budget")
        self.assertIn("exceeded its 1 second budget", result.stderr)
        child_pid = int(pid_file.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_output_over_one_mib_is_capped_and_counted(self) -> None:
        run = json.dumps(
            [
                "python3",
                "-c",
                "import sys; sys.stdout.write('x' * (1024 * 1024 + 100))",
            ]
        )
        self.write_config(with_command(run))
        result, document = self.run_json()
        self.assertEqual(result.returncode, 0, output(result))
        check = self.check_by_id(document, "lint")
        diagnostics = check["diagnostics"]
        self.assertGreater(diagnostics["output_bytes"], 1024 * 1024)
        self.assertTrue(diagnostics["output_truncated"])
        self.assertLessEqual(len(diagnostics["output_tail"].encode()), 4096)

if __name__ == "__main__":
    unittest.main()
