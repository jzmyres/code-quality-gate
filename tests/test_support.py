"""Tests for the fixture's in-process gate command."""
from __future__ import annotations

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
        failing = BASE_CONFIG.replace(
            'run = ["python3", "-c", "print(1)"]',
            'run = ["python3", "-c", "import sys; sys.exit(1)"]',
        )
        # Each check line reports its own elapsed seconds ("(exit 0, 0.02s)"), which differ between any
        # two runs, so only that field is normalized before the outputs are compared.
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
                # The subject is the in-process call against a plain process, not the coverage wrapper:
                # when the gate measures itself, QG_PYTHON's covrun.py lies inside the measured source
                # and coverage warns on stderr that it was already imported.
                with mock.patch.dict(os.environ):
                    os.environ.pop("QG_PYTHON", None)
                    process = self.run_qg_process("check")
                self.assertEqual(comparable(in_process), comparable(process))


if __name__ == "__main__":
    unittest.main()
