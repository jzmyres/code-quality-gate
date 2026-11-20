"""Tests for the runner's process-record reads, kept in one small file."""
from __future__ import annotations

import importlib
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from support import GATE
from test_runner import _detached_child_program, _kill_and_reap, _run_detached

sys.path.insert(0, str(GATE))
runner = importlib.import_module("quality_gate.runner")


class ProcRecordTests(unittest.TestCase):
    def test_fields_of_a_missing_process_is_none(self) -> None:
        self.assertIsNone(runner._fields_of("missing-process"))

    def test_fields_of_an_unreadable_stat_is_an_error_naming_the_pid(self) -> None:
        with mock.patch.object(
            runner, "_proc_fields",
            side_effect=PermissionError("denied"),
        ), self.assertRaisesRegex(
            OSError, r"pid 123.*PermissionError: denied"
        ):
            runner._fields_of("123")

    def test_a_non_utf8_process_name_does_not_break_a_run(self) -> None:
        program = (
            "import os, time\n"
            "descriptor = os.open('/proc/self/comm', os.O_WRONLY)\n"
            "os.write(descriptor, b'\\xff\\xfeodd')\n"
            "os.close(descriptor)\n"
            "time.sleep(30)\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", program], start_new_session=True
        )
        self.addCleanup(_kill_and_reap, process)
        stat = Path(f"/proc/{process.pid}/stat")
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if b"\xff\xfeodd" in stat.read_bytes():
                break
            time.sleep(0.01)
        else:
            self.fail("child did not take its process name")
        result = runner.run(["true"], budget_seconds=5)
        self.assertEqual(result.execution, "completed", result)

    def test_a_vanished_process_record_is_gone(self) -> None:
        with mock.patch(
            "builtins.open", side_effect=ProcessLookupError
        ):
            self.assertIsNone(
                runner._proc_fields("/proc/123/stat")
            )

    def test_an_unreadable_process_record_propagates_the_read_error(self) -> None:
        error = PermissionError("denied")
        with (
            mock.patch("builtins.open", side_effect=error),
            self.assertRaises(PermissionError) as raised,
        ):
            runner._proc_fields("/proc/123/stat")
        self.assertIs(raised.exception, error)

    def test_proc_fields_returns_the_fields_after_any_name_bytes(self) -> None:
        cases = [
            (b"10 (simple) S 1 2 3", ["S", "1", "2", "3"]),
            (b"11 (na)me\xff\xfe) R 4 5 6", ["R", "4", "5", "6"]),
            (b"12 (a)b) Z 7 8 9", ["Z", "7", "8", "9"]),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stat"
            for record, expected in cases:
                with self.subTest(record=record):
                    path.write_bytes(record)
                    self.assertEqual(
                        runner._proc_fields(str(path)), expected
                    )

    def test_an_unreadable_descendant_stat_is_an_error_naming_the_pid(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"
            program = _detached_child_program(pid_file)
            real_fields = runner._proc_fields

            def fields(path: str) -> list[str] | None:
                if pid_file.exists():
                    pid = pid_file.read_text(encoding="utf-8")
                    if path == f"/proc/{pid}/stat":
                        raise PermissionError("denied")
                return real_fields(path)

            result, pid = _run_detached(
                program, pid_file,
                mock.patch.object(
                    runner, "_proc_fields", side_effect=fields
                ),
            )
        self.assertEqual(result.execution, "error", result)
        self.assertIn(str(pid), result.error or "")
        self.assertIn("PermissionError", result.error or "")


if __name__ == "__main__":
    unittest.main()
