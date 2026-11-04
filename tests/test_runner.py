"""Unit tests for the bounded runner's pipe, reaping and group helpers."""
from __future__ import annotations

import importlib
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from support import GATE

sys.path.insert(0, str(GATE))
runner = importlib.import_module("quality_gate.runner")


class _FakeProcess:
    pid = 4242

    def __init__(self, waits: list[object]) -> None:
        self.waits = iter(waits)

    def wait(self, timeout: float) -> int:
        outcome = next(self.waits)
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, int)
        return outcome


def _timeout() -> subprocess.TimeoutExpired:
    return subprocess.TimeoutExpired(["child"], 1.0)


class ReadChunkTests(unittest.TestCase):
    def test_reads_available_bytes(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"hello")
            self.assertEqual(runner._read_chunk(read_fd), b"hello")
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_empty_nonblocking_pipe_has_no_chunk(self) -> None:
        read_fd, write_fd = os.pipe()
        os.set_blocking(read_fd, False)
        try:
            self.assertIsNone(runner._read_chunk(read_fd))
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_bad_descriptor_is_end_of_file(self) -> None:
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            self.assertEqual(runner._read_chunk(read_fd), b"")
        finally:
            os.close(write_fd)

    def test_a_ready_stream_yields_after_one_chunk(self) -> None:
        key = SimpleNamespace(fd=12, data="stdout")
        with mock.patch.object(runner, "_read_chunk", side_effect=[b"x"] * 100 + [None]) as read:
            runner._read_ready([(key, 1)], mock.Mock(), {"stdout": mock.Mock()}, runner._Capture(20))
        self.assertEqual(read.call_count, 1)

    def test_continuous_output_cannot_postpone_the_deadline_or_kill(self) -> None:
        program = (
            "import os, signal\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "data = b'x' * 65536\n"
            "while True:\n"
            "    os.write(1, data)\n"
        )
        start = time.monotonic()
        result = runner.run([sys.executable, "-c", program], budget_seconds=0.4)
        self.assertEqual(result.execution, "budget")
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertGreater(result.output_bytes, runner.CAPTURE_LIMIT)
        self.assertTrue(result.output_truncated)
        self.assertLess(time.monotonic() - start, 8.0)


class ReapTests(unittest.TestCase):
    def test_reap_returns_when_the_child_exits(self) -> None:
        process = _FakeProcess([0])
        with mock.patch.object(runner, "_signal_group") as signal_group:
            runner._reap(process)
        signal_group.assert_not_called()

    def test_reap_kills_and_waits_after_the_grace(self) -> None:
        process = _FakeProcess([_timeout(), 0])
        with mock.patch.object(runner, "_signal_group") as signal_group:
            runner._reap(process)
        signal_group.assert_called_once_with(process.pid, signal.SIGKILL)

    def test_reap_stops_after_a_second_timeout(self) -> None:
        process = _FakeProcess([_timeout(), _timeout()])
        with mock.patch.object(runner, "_signal_group") as signal_group:
            runner._reap(process)
        signal_group.assert_called_once_with(process.pid, signal.SIGKILL)


class RunInterruptTests(unittest.TestCase):
    @staticmethod
    def _raise_timeout(_signum: int, _frame: object) -> None:
        raise TimeoutError("test timer")

    def test_an_interrupt_kills_the_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pid"
            program = f"echo $$ > {pid_file}; sleep 30 & wait"
            previous = signal.signal(signal.SIGALRM, self._raise_timeout)
            self.addCleanup(signal.signal, signal.SIGALRM, previous)
            self.addCleanup(signal.setitimer, signal.ITIMER_REAL, 0.0)
            signal.setitimer(signal.ITIMER_REAL, 1.0)
            with self.assertRaises(TimeoutError):
                runner.run(["sh", "-c", program], budget_seconds=60)
            self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
            pid = int(pid_file.read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.killpg(pid, 0)


if __name__ == "__main__":
    unittest.main()
