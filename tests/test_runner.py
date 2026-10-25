"""Unit tests for the bounded runner's pipe and reaping helpers."""
from __future__ import annotations

import importlib
import os
import signal
import subprocess
import sys
import unittest
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


if __name__ == "__main__":
    unittest.main()
