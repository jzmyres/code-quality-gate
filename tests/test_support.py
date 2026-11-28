"""Tests for the fixture's in-process gate command."""
from __future__ import annotations

import json
import math
import os
import re
import signal
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase, output

sys.path.insert(0, str(GATE))
from quality_gate import cli, tools


class InProcessRunQGTests(FixtureCase):
    def capture_state(self) -> tuple[object, ...]:
        return (
            os.environ.copy(),
            Path.cwd(),
            sys.stdout,
            sys.stderr,
            tools._LOCK_OVERRIDE,
            signal.getsignal(signal.SIGALRM),
        )

    def assert_state_restored(self, before: tuple[object, ...]) -> None:
        self.assertEqual(os.environ, before[0])
        self.assertEqual(Path.cwd(), before[1])
        self.assertIs(sys.stdout, before[2])
        self.assertIs(sys.stderr, before[3])
        self.assertIs(tools._LOCK_OVERRIDE, before[4])
        self.assertIs(signal.getsignal(signal.SIGALRM), before[5])

    def test_a_call_restores_the_process_state_it_changes(self) -> None:
        self.fixture_gate()
        before = self.capture_state()
        result = self.run_qg("check")
        self.assertEqual(result.returncode, 0, output(result))
        self.assert_state_restored(before)

    def test_an_unexpected_exception_restores_the_state_and_fails(self) -> None:
        self.fixture_gate()
        before = self.capture_state()
        with mock.patch.object(
            cli, "main", side_effect=RuntimeError("injected failure")
        ):
            result = self.run_qg("check")
        self.assertEqual(result.returncode, 1)
        self.assertIn("RuntimeError: injected failure", result.stderr)
        self.assert_state_restored(before)

    def test_in_process_and_process_runs_agree(self) -> None:
        """Compare in-process execution with a plain process.

        Normalize only the elapsed seconds in each check line because timings
        differ between runs. When the gate measures itself, covrun.py lies
        inside the measured source. Using the coverage wrapper for this
        comparison would add an already-imported warning on stderr.
        """
        failing = BASE_CONFIG.replace(
            'run = ["python3", "-c", "print(1)"]',
            'run = ["python3", "-c", "import sys; sys.exit(1)"]',
        )
        elapsed = re.compile(r", \d+\.\d+s\)")

        def comparable(result: subprocess.CompletedProcess[str]) -> tuple[int, str, str]:
            return (
                result.returncode,
                elapsed.sub(", Ns)", result.stdout),
                elapsed.sub(", Ns)", result.stderr),
            )

        for name, text in (("passing", BASE_CONFIG), ("failing", failing)):
            with self.subTest(check=name):
                self.write_config(text)
                in_process = self.run_qg("check")
                with mock.patch.dict(os.environ):
                    os.environ.pop("QG_PYTHON", None)
                    process = self.run_qg_process("check")
                self.assertEqual(comparable(in_process), comparable(process))


    def test_check_ledger_agrees_between_entry_points(self) -> None:
        failing = BASE_CONFIG.replace(
            'run = ["python3", "-c", "print(1)"]',
            'run = ["python3", "-c", "raise SystemExit(1)"]',
        )
        elapsed = re.compile(r", \d+\.\d+s\)")
        ledger_path = self.base / "evidence.jsonl"

        def read_ledger(result: subprocess.CompletedProcess[str], mode: str) -> tuple[str, dict]:
            for stream in (result.stdout, result.stderr):
                self.assertNotIn("qg-ledger: ", stream, mode)
                self.assertNotIn('"run_id":', stream, mode)
            lines = ledger_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1, f"{mode}: expected one ledger record")
            ledger_path.unlink()
            ledger = json.loads(lines[0])
            run_id = ledger.pop("run_id")
            self.assertTrue(run_id, mode)
            self.assertTrue(ledger["checks"], mode)
            for row in ledger["checks"]:
                seconds = row.pop("duration_seconds")
                self.assertTrue(
                    0 <= seconds < math.inf, f"{mode}, {row['id']}: invalid duration {seconds!r}",
                )
            return run_id, ledger

        def comparable(result: subprocess.CompletedProcess[str]) -> tuple[int, list[str]]:
            streams = [elapsed.sub(", Ns)", stream) for stream in (result.stdout, result.stderr)]
            return result.returncode, streams

        self.commit_all()
        for name, text, status in (("passing", BASE_CONFIG, 0), ("failing", failing, 1)):
            with self.subTest(check=name):
                self.write_config(text)
                git_dir = self.repo / ".git"
                entries = sorted(path.relative_to(git_dir) for path in git_dir.rglob("*"))
                default = self.run_qg("check")
                with mock.patch.dict(os.environ):
                    os.environ.pop("QG_PYTHON", None)
                    plain = self.run_qg_process("check")
                self.assertEqual(default.returncode, status, default.stderr)
                self.assertEqual(comparable(default), comparable(plain))
                self.assertEqual(sorted(path.relative_to(git_dir) for path in git_dir.rglob("*")), entries)
                self.assertFalse((git_dir / "qg-ledger.jsonl").exists())
                self.assertFalse(ledger_path.exists())

                in_process = self.run_qg("check", "--ledger", str(ledger_path))
                in_process_id, in_process_ledger = read_ledger(in_process, "in process")
                with mock.patch.dict(os.environ):
                    os.environ.pop("QG_PYTHON", None)
                    process = self.run_qg_process("check", "--ledger", str(ledger_path))
                self.assertEqual(in_process.returncode, status, in_process.stderr)
                self.assertEqual(in_process_ledger["exit_status"], status)
                self.assertEqual(comparable(in_process), comparable(process))
                self.assertEqual(comparable(default), comparable(in_process))
                process_id, process_ledger = read_ledger(process, "subprocess")
                self.assertNotEqual(in_process_id, process_id)
                self.assertEqual(in_process_ledger, process_ledger)


if __name__ == "__main__":
    unittest.main()
