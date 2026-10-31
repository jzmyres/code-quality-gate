"""Unit tests for the bounded runner's pipe and reaping helpers."""
from __future__ import annotations

import contextlib
import importlib
import io
import json
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
coverage_tool = importlib.import_module("quality_gate.coverage_tool")
verification = importlib.import_module("quality_gate.verification")


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
        with runner.check_deadline(start, 0.4):
            result = runner.run([sys.executable, "-c", program], budget_seconds=0.4)
        self.assertEqual(result.execution, "budget")
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertGreater(result.output_bytes, runner.CAPTURE_LIMIT)
        self.assertTrue(result.output_truncated)
        self.assertLess(time.monotonic() - start, 2.0)


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


class AnalysisWorkerTests(unittest.TestCase):
    def test_worker_registry_refuses_duplicate_names_and_non_json_constants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            registry = runner._WorkerRegistry(str(path))
            for text in ('{"cancelled":[123],"cancelled":[],"entries":{}}',
                         '{"cancelled":[],"entries":NaN}',
                         '{"cancelled":[],"entries":Infinity}',
                         '{"cancelled":[],"entries":-Infinity}'):
                with self.subTest(text=text):
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        with runner._registry_data(registry):
                            self.fail("invalid registry was accepted")
                    self.assertEqual(path.read_text(encoding="utf-8"), text)

    def test_process_registration_and_cancellation_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(json.dumps({"cancelled": [], "entries": {}}), encoding="utf-8")
            registry = runner._WorkerRegistry(str(path), (123,))
            context = runner._worker_registry.set(registry)
            try:
                with mock.patch.object(runner.os, "setsid") as setsid:
                    runner._register_session(("example", "argument"), "process", "token")
                    data = json.loads(path.read_text(encoding="utf-8"))
                    entry = data["entries"][str(os.getpid())]
                    self.assertEqual(entry["command"], ["example", "argument"])
                    self.assertEqual(entry["ancestors"], [123])
                    setsid.assert_called_once()
                    data["cancelled"].append(123)
                    path.write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaisesRegex(runner.WorkerError, "cancelled"):
                        runner._register_session(("example",), "process", "next")
                    setsid.assert_called_once()
            finally:
                runner._worker_registry.reset(context)

    def test_unreadable_process_status_is_not_treated_as_stopped(self) -> None:
        with mock.patch("builtins.open", side_effect=PermissionError("denied")):
            self.assertTrue(runner._proc_group_member("/proc/123/stat", 123))
        self.assertFalse(runner._proc_group_member("/proc/no-such-pid/stat", 123))

    def test_large_result_and_output_are_returned(self) -> None:
        def work() -> bytes:
            print("worker output")
            print("worker warning", file=sys.stderr)
            return b"x" * (256 * 1024)

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with runner.check_deadline(time.monotonic(), 5):
                result = runner.analysis_step("large result", work)
        self.assertEqual(result, b"x" * (256 * 1024))
        self.assertEqual(stdout.getvalue(), "worker output\n")
        self.assertEqual(stderr.getvalue(), "worker warning\n")

    def test_worker_exception_and_unserializable_result_are_reported(self) -> None:
        def fails() -> None:
            raise ValueError("analysis failed")

        with self.assertRaisesRegex(ValueError, "analysis failed"):
            runner._decode_worker(runner._worker_payload(fails, ()), "analysis")
        with self.assertRaisesRegex(runner.WorkerError, "cannot return worker result"):
            runner._decode_worker(runner._worker_payload(lambda: fails, ()), "analysis")

    def test_worker_exit_without_a_result_is_an_error(self) -> None:
        with runner.check_deadline(time.monotonic(), 5):
            with self.assertRaisesRegex(runner.WorkerError, "analysis worker exited"):
                runner.analysis_step("analysis", os._exit, 1)

    def test_worker_creation_failures_name_the_step(self) -> None:
        for operation in ("pipe", "fork"):
            with self.subTest(operation=operation):
                with mock.patch.object(runner.os, operation, side_effect=OSError("denied")):
                    with self.assertRaisesRegex(runner.WorkerError, "cannot start analysis worker"):
                        runner.analysis_step("analysis", lambda: None, deadline=time.monotonic() + 5)

    def test_worker_measurement_accepts_an_opaque_snapshot(self) -> None:
        merged = []
        measurement = runner.WorkerMeasurement(
            start=os.getpid,
            snapshot=lambda pid: {"worker": pid, "snapshot": os.getpid()},
            merge=lambda snapshot: merged.append((os.getpid(), snapshot)),
        )
        with mock.patch.object(runner, "_worker_measurement", measurement):
            with runner.check_deadline(time.monotonic(), 5):
                result = runner.analysis_step("measured analysis", os.getpid)
        self.assertNotEqual(result, os.getpid())
        self.assertEqual(merged, [(os.getpid(), {"worker": result, "snapshot": result})])

    def test_no_measurement_hook_does_no_measurement_work(self) -> None:
        with mock.patch.object(runner, "_worker_measurement", None):
            with mock.patch.object(coverage_tool, "_current_coverage") as current:
                payload = runner._worker_payload(lambda: 42, ())
                self.assertEqual(runner._decode_worker(payload, "analysis"), 42)
        current.assert_not_called()

    def test_worker_execution_is_included_in_active_coverage(self) -> None:
        coverage = coverage_tool.import_coverage()
        for branch in (False, True):
            with self.subTest(branch=branch):
                collector = coverage.Coverage(
                    data_file=None, config_file=False, source=[str(GATE)], branch=branch
                )
                collector.start()
                coverage_tool.install_worker_measurement()
                try:
                    with runner.check_deadline(time.monotonic(), 5):
                        runner.analysis_step(
                            "verification analysis", verification.measure_exclusions,
                            "source.py", "VALUE = 1  # noqa: E501\n",
                        )
                finally:
                    collector.stop()
                filename = str(GATE / "quality_gate" / "verification.py")
                data = collector.get_data()
                self.assertIn(136, data.lines(filename) or [])
                self.assertEqual(data.has_arcs(), branch)


if __name__ == "__main__":
    unittest.main()
