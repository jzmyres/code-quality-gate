"""Unit tests for the bounded runner's pipe, reaping and group helpers."""
from __future__ import annotations

import contextlib
import importlib
import io
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from support import GATE

sys.path.insert(0, str(GATE))
runner = importlib.import_module("quality_gate.runner")


ORPHAN_PROGRAM = """
import os
import time
from pathlib import Path


def start_grandchildren(release_reader, pid_writer):
    pids = []
    for _ in range(24):
        pid = os.fork()
        if pid == 0:
            os.close(pid_writer)
            os.setsid()
            os.read(release_reader, 1)
            os._exit(0)
        pids.append(pid)
    os.write(pid_writer, " ".join(map(str, pids)).encode())
    os._exit(0)


def process_fields(pid):
    try:
        record = Path(f"/proc/{pid}/stat").read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return [b"X", b""]
    return record.rpartition(b")")[2].split()


gate_pid = str(os.getppid()).encode()
pid_reader, pid_writer = os.pipe()
release_reader, release_writer = os.pipe()
middle = os.fork()
if middle == 0:
    os.close(pid_reader)
    os.close(release_writer)
    start_grandchildren(release_reader, pid_writer)
os.close(pid_writer)
os.close(release_reader)
try:
    assert os.waitpid(middle, 0) == (middle, 0)
    with os.fdopen(pid_reader) as stream:
        pids = [int(pid) for pid in stream.read().split()]
    assert len(pids) == 24
    assert all(process_fields(pid)[1] == gate_pid for pid in pids)
finally:
    os.close(release_writer)

deadline = time.monotonic() + 3
while any(process_fields(pid)[0] not in (b"X", b"Z") for pid in pids):
    assert time.monotonic() < deadline, "grandchildren did not exit"
    time.sleep(0.01)

deadline = time.monotonic() + 1
while True:
    zombies = [pid for pid in pids if process_fields(pid)[:2] == [b"Z", gate_pid]]
    if not zombies or time.monotonic() >= deadline:
        break
    time.sleep(0.02)
print(len(zombies), *zombies)
"""


class _FakeProcess:
    pid = 4242

    def __init__(self, waits: list[object]) -> None:
        self.waits = iter(waits)

    def poll(self) -> None:
        return None

    def wait(self, timeout: float) -> int:
        outcome = next(self.waits)
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, int)
        return outcome


def _timeout() -> subprocess.TimeoutExpired:
    return subprocess.TimeoutExpired(["child"], 1.0)


def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    process.wait()


def _detached_child_program(pid_file: Path) -> str:
    return (
        "import subprocess\n"
        "import sys\n"
        "child = subprocess.Popen(\n"
        "    [sys.executable, '-c', 'import time; time.sleep(30)'],\n"
        "    start_new_session=True,\n"
        "    stdin=subprocess.DEVNULL,\n"
        "    stdout=subprocess.DEVNULL,\n"
        "    stderr=subprocess.DEVNULL,\n"
        ")\n"
        f"open({str(pid_file)!r}, 'w', encoding='utf-8').write("
        "str(child.pid))\n"
    )

def _run_detached(
    program: str, pid_file: Path, patch: Any,
) -> tuple[runner.RunResult, int]:
    with patch:
        result = runner.run(
            [sys.executable, "-c", program], budget_seconds=5
        )
    pid = int(pid_file.read_text(encoding="utf-8"))
    runner._kill_adopted({pid})
    return result, pid


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
        result = runner.run(
            [sys.executable, "-c", program],
            budget_seconds=0.4,
            grace_seconds=0.2,
        )
        self.assertEqual(result.execution, "budget")
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertGreater(result.output_bytes, runner.CAPTURE_LIMIT)
        self.assertTrue(result.output_truncated)
        self.assertLess(time.monotonic() - start, 8.0)

    def test_reap_scans_follow_the_poll_interval_during_continuous_output(self) -> None:
        now = 0.0
        ticks = iter((0.03125, 0.0625, 0.125, 0.15625, 0.25, 0.28125, 0.3125, 0.34375, 0.375))
        scan_times = []
        key = SimpleNamespace(fd=12, data="stdout")

        def select(_timeout):
            nonlocal now
            now = next(ticks)
            return [(key, 1)]

        selector = mock.Mock()
        selector.select.side_effect = select
        selector.get_map.side_effect = lambda: {} if now == 0.375 else {key.fd: key}
        process = mock.Mock(pid=4242)
        process.stdout.fileno.return_value = key.fd
        process.stderr.fileno.return_value = 13
        process.poll.return_value = 0
        process.wait.return_value = 0

        def listdir(path: str) -> list[str]:
            if path == "/proc" and selector.register.called and not selector.close.called:
                scan_times.append(now)
            return []

        runner_os = SimpleNamespace(getpid=os.getpid, listdir=listdir, set_blocking=mock.Mock())
        with (
            mock.patch.object(runner, "os", runner_os),
            mock.patch.object(runner.selectors, "DefaultSelector", return_value=selector),
            mock.patch.object(runner, "time", SimpleNamespace(monotonic=lambda: now)),
            mock.patch.object(runner, "_subreaper_failure", return_value=None),
            mock.patch.object(runner, "_spawn", return_value=(process, None)),
            mock.patch.object(runner, "_group_alive", return_value=False),
            mock.patch.object(runner, "_signal_group"),
            mock.patch.object(runner, "_read_chunk", return_value=b"x"),
        ):
            result = runner.run(
                ["stream"], budget_seconds=0.25, grace_seconds=0.5, capture_limit=20,
            )
        self.assertEqual(result.execution, "budget")
        self.assertEqual(result.output_bytes, 9)
        self.assertEqual(result.stdout, b"x" * 9)
        self.assertIn(scan_times, ([], [0.0, 0.125, 0.25, 0.3125]))


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


class GroupAliveTests(unittest.TestCase):
    @staticmethod
    def _state(pid: int) -> str:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        return stat.rpartition(")")[2].split()[0]

    def test_a_zombie_group_is_not_alive(self) -> None:
        process = subprocess.Popen(["sh", "-c", "exit 0"], start_new_session=True)
        self.addCleanup(_kill_and_reap, process)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self._state(process.pid) == "Z":
                break
            time.sleep(0.01)
        else:
            self.fail("child did not become a zombie")
        os.killpg(process.pid, 0)
        self.assertFalse(runner._group_alive(process.pid))

    def test_a_running_child_group_is_alive(self) -> None:
        process = subprocess.Popen(["sleep", "30"], start_new_session=True)
        self.addCleanup(_kill_and_reap, process)
        self.assertTrue(runner._group_alive(process.pid))

    def test_an_unreaped_orphan_does_not_hold_the_run_open(self) -> None:
        program = (
            "import ctypes\n"
            "import sys\n"
            "import time\n"
            f"sys.path.insert(0, {str(GATE)!r})\n"
            "from quality_gate import runner\n"
            "ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)\n"
            "started = time.monotonic()\n"
            "result = runner.run(['sh', '-c', 'sleep 0.2 & exit 0'], budget_seconds=30)\n"
            "print(result.execution)\n"
            "print(time.monotonic() - started)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", program],
            capture_output=True,
            text=True,
            timeout=40,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        execution, duration = completed.stdout.splitlines()
        self.assertEqual(execution, "completed")
        self.assertLess(float(duration), 5.0)

    def test_reaps_exited_adopted_children_during_run(self) -> None:
        result = runner.run([sys.executable, "-I", "-c", ORPHAN_PROGRAM], budget_seconds=8)
        self.assertEqual((result.execution, result.returncode), ("completed", 0), result)
        count, *pids = result.stdout_text.split()
        self.assertEqual(int(count), len(pids), result.stdout_text)
        self.assertEqual(int(count), 0, f"Retained zombie PIDs: {', '.join(pids)}")


class ChildProcessTests(unittest.TestCase):
    """The subreaper's reads of /proc and its cleanup decisions."""

    def test_kill_and_reap_reaps_a_child_without_its_own_group(self) -> None:
        process = subprocess.Popen(["sleep", "30"])
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        self.assertIsNone(process.poll())
        self.assertNotEqual(process.pid, os.getpgid(process.pid))

        start = time.monotonic()
        _kill_and_reap(process)
        self.assertLess(time.monotonic() - start, 1.0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def test_child_pid_names_only_a_direct_child(self) -> None:
        process = subprocess.Popen(["sleep", "30"])
        self.addCleanup(_kill_and_reap, process)
        self.assertEqual(
            runner._child_pid(str(process.pid), os.getpid()), process.pid
        )
        self.assertIsNone(runner._child_pid(str(process.pid), 0))
        self.assertIsNone(runner._child_pid("missing-process", os.getpid()))

    def test_children_lists_the_direct_children(self) -> None:
        process = subprocess.Popen(["sleep", "30"])
        self.addCleanup(_kill_and_reap, process)
        self.assertIn(process.pid, runner._children(os.getpid()))

    def test_children_of_an_unreadable_proc_is_an_error(self) -> None:
        with mock.patch.object(
            runner.os, "listdir", side_effect=OSError("denied")
        ), self.assertRaises(OSError):
            runner._children(os.getpid())

    def test_reaps_later_adopted_children_after_an_unreadable_record(self) -> None:
        known, unreadable, first, second = ("9000001", "9000002", "9000003", "9000004")
        gate_pid = str(os.getpid())
        direct = ""
        draining = False
        original_spawn = runner._spawn
        original_close = runner._close
        original_fields = runner._proc_fields

        def spawn(*args):
            nonlocal direct, draining
            process, failure = original_spawn(*args)
            if process is not None:
                direct = str(process.pid)
                draining = True
            return process, failure

        def close(*args):
            nonlocal draining
            draining = False
            original_close(*args)

        def listing(path):
            if draining and path == "/proc":
                return [direct, known, unreadable, first, second]
            return [*os.listdir(path), known] if path == "/proc" else os.listdir(path)

        def fields(path):
            name = Path(path).parent.name
            if name == unreadable:
                raise PermissionError("synthetic unreadable process record")
            if name in (direct, known, first, second):
                return ["Z", gate_pid]
            return original_fields(path)

        runner_os = mock.Mock(wraps=os)
        runner_os.WNOHANG = os.WNOHANG
        runner_os.listdir.side_effect = listing
        runner_os.waitpid.side_effect = ChildProcessError
        with (
            mock.patch.object(runner, "os", runner_os),
            mock.patch.object(runner, "_spawn", side_effect=spawn),
            mock.patch.object(runner, "_close", side_effect=close),
            mock.patch.object(runner, "_proc_fields", side_effect=fields),
        ):
            result = runner.run([sys.executable, "-I", "-c", "pass"], budget_seconds=5)
        self.assertEqual((result.execution, result.returncode), ("completed", 0), result)
        expected = {(int(pid), os.WNOHANG) for pid in (first, second)}
        observed = {call.args for call in runner_os.waitpid.call_args_list}
        missing = expected - observed
        self.assertFalse(missing, f"Missing waitpid(pid, WNOHANG) calls: {sorted(missing)}")
        self.assertEqual(observed, expected)

    def test_an_unreadable_process_table_with_a_detached_child_is_an_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"
            program = _detached_child_program(pid_file)
            real_listdir = os.listdir

            def listing(path: str) -> list[str]:
                if path == "/proc" and pid_file.exists():
                    raise PermissionError("process table hidden")
                return real_listdir(path)

            result, _pid = _run_detached(
                program, pid_file,
                mock.patch.object(
                    runner.os, "listdir", side_effect=listing
                ),
            )
        self.assertEqual(result.execution, "error", result)
        self.assertIn("process table", result.error or "")
        self.assertIn("PermissionError", result.error or "")

    def test_kill_adopted_stops_and_reaps_a_child(self) -> None:
        process = subprocess.Popen(["sleep", "30"])
        self.addCleanup(_kill_and_reap, process)
        runner._kill_adopted({process.pid})
        try:
            process.wait(timeout=5.0)
        except ChildProcessError:
            pass
        deadline = time.monotonic() + 5.0
        while (
            Path(f"/proc/{process.pid}").exists()
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        self.assertFalse(Path(f"/proc/{process.pid}").exists())

    def test_stop_adopted_checks_remaining_at_the_deadline(self) -> None:
        clock = mock.Mock()
        clock.monotonic.side_effect = [0.0, 2.0]
        with mock.patch.object(
            runner, "_children", return_value={99}
        ), mock.patch.object(
            runner, "_kill_adopted"
        ) as kill, mock.patch.object(
            runner, "time", clock
        ), mock.patch.object(
            runner, "_stop_remaining", return_value=None
        ) as remaining:
            self.assertIsNone(runner._stop_adopted(set()))
        kill.assert_called_once_with({99})
        remaining.assert_called_once_with(set())

    def test_stop_remaining_names_a_child_or_an_unreadable_table(self) -> None:
        with mock.patch.object(runner, "_children", return_value={99}):
            self.assertEqual(
                runner._stop_remaining(set()), runner.DESCENDANT_ERROR
            )
        with mock.patch.object(runner, "_children", return_value=set()):
            self.assertIsNone(runner._stop_remaining(set()))
        with mock.patch.object(
            runner, "_children", side_effect=PermissionError("denied")
        ):
            reason = runner._stop_remaining(set())
        self.assertIn("process table", reason or "")
        self.assertIn("PermissionError", reason or "")

    def test_cleanup_error_names_the_failed_cleanup(self) -> None:
        self.assertIsNone(runner._cleanup_error(True, None))
        self.assertEqual(runner._cleanup_error(False, None), runner.CLEANUP_ERROR)
        self.assertEqual(
            runner._cleanup_error(True, runner.DESCENDANT_ERROR),
            runner.DESCENDANT_ERROR,
        )

    def test_execution_fields_maps_each_outcome(self) -> None:
        self.assertEqual(
            runner._execution_fields("completed", 0, None),
            ("completed", None, False),
        )
        self.assertEqual(
            runner._execution_fields("budget", None, None),
            ("budget", None, True),
        )
        self.assertEqual(
            runner._execution_fields("completed", -9, None),
            ("signal", None, False),
        )
        self.assertEqual(
            runner._execution_fields("completed", 0, "broken"),
            ("error", "broken", True),
        )

    def test_an_interrupted_cleanup_notes_each_failure(self) -> None:
        process = SimpleNamespace(pid=4242)
        error = TimeoutError("test timer")
        captured = io.StringIO()
        with mock.patch.object(
            runner, "_kill_and_wait", return_value=False
        ), mock.patch.object(
            runner, "_stop_adopted", return_value=runner.DESCENDANT_ERROR
        ), contextlib.redirect_stderr(captured):
            runner._finish_interrupted(error, process, set())
        notes = getattr(error, "__notes__", [])
        self.assertTrue(any(
            runner.CLEANUP_ERROR in note for note in notes
        ), notes)
        self.assertTrue(any(
            runner.DESCENDANT_ERROR in note for note in notes
        ), notes)
        self.assertIn(runner.CLEANUP_ERROR, captured.getvalue())

    def test_a_command_that_cannot_start_is_an_error(self) -> None:
        result = runner.run(["/no/such/command"], budget_seconds=1)
        self.assertEqual(result.execution, "error")
        self.assertIn("cannot run command", result.error or "")


class ProcGroupMemberTests(unittest.TestCase):
    group = 77

    def test_a_stat_entry_is_a_member_of_its_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = [
                ("state S", "123 (sh) S 1 77 0 -1 4194560 0", True),
                ("state Z", "123 (sh) Z 1 77 0 -1 4194560 0", False),
                ("state X", "123 (sh) X 1 77 0 -1 4194560 0", False),
                ("another group", "123 (sh) S 1 78 0 -1 4194560 0", False),
                ("short line", "123 (sh) S 1", True),
            ]
            for name, line, expected in cases:
                with self.subTest(case=name):
                    path = root / "stat"
                    path.write_text(line, encoding="utf-8")
                    self.assertIs(runner._proc_group_member(str(path), self.group), expected)
            with self.subTest(case="missing file"):
                missing = root / "missing"
                self.assertFalse(runner._proc_group_member(str(missing), self.group))
            with self.subTest(case="directory"):
                entry = root / "entry"
                entry.mkdir()
                self.assertTrue(runner._proc_group_member(str(entry), self.group))


def _zombie(pid: int) -> bool:
    """Whether PID is an unreaped zombie this process still owns."""
    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return False
    return state.rpartition(")")[2].split()[0] == "Z"


def _interrupt(pid_file: Path, program: str) -> TimeoutError:
    """Run PROGRAM until PID_FILE exists, then interrupt it and disarm again."""

    def interrupt_after_pid(_signum: int, _frame: object) -> None:
        if not pid_file.exists():
            signal.setitimer(signal.ITIMER_REAL, 0.01)
            return
        raise TimeoutError("test timer")

    previous = signal.signal(signal.SIGALRM, interrupt_after_pid)
    try:
        signal.setitimer(signal.ITIMER_REAL, 1.0)
        runner.run(["sh", "-c", program], budget_seconds=60)
    except TimeoutError as error:
        return error
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous)
    raise AssertionError("the interrupt did not end the run")


class RunInterruptTests(unittest.TestCase):
    def test_an_interrupt_kills_the_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pid"
            program = (
                f"sleep 30 & echo $$ > {pid_file}.tmp; "
                f"mv {pid_file}.tmp {pid_file}; wait"
            )
            _interrupt(pid_file, program)
            self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
            pid = int(pid_file.read_text(encoding="utf-8"))
            self.assertFalse(runner._group_alive(pid))


class InterruptCleanupTests(unittest.TestCase):
    """An interrupt returns within the cleanup deadline, whatever liveness says."""

    def _interrupted(self, patch: Any) -> tuple[float, int]:
        """Interrupt one real child under PATCH, and return its time and pid."""
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pid"
            program = (
                f"echo $$ > {pid_file}.tmp; mv {pid_file}.tmp {pid_file}; "
                "sleep 30"
            )
            with patch:
                start = time.monotonic()
                _interrupt(pid_file, program)
                elapsed = time.monotonic() - start
            pid = int(pid_file.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 5.0
            while _zombie(pid) and time.monotonic() < deadline:
                time.sleep(0.01)
        return elapsed, pid

    def _assert_bounded_and_reaped(self, patch: Any) -> None:
        elapsed, pid = self._interrupted(patch)
        self.assertLess(elapsed, runner.CLEANUP_SECONDS + 3.0)
        self.assertFalse(_zombie(pid))
        self.assertFalse(runner._group_alive(pid))

    def test_an_unreadable_process_table_still_returns(self) -> None:
        self._assert_bounded_and_reaped(mock.patch.object(
            runner, "_proc_group_running",
            side_effect=OSError("denied"),
        ))

    def test_a_platform_without_a_subreaper_is_an_error_naming_it(self) -> None:
        with mock.patch.object(runner.sys, "platform", "darwin"):
            result = runner.run(
                [sys.executable, "-c", "print(1)"], budget_seconds=1
            )
        self.assertEqual(result.execution, "error")
        self.assertIn("PR_SET_CHILD_SUBREAPER", result.error or "")
        self.assertIn("darwin", result.error or "")


class UnconfirmedCleanupTests(unittest.TestCase):
    def test_an_interrupted_group_that_never_reads_as_gone_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "pid"
            program = (
                f"echo $$ > {pid_file}.tmp; mv {pid_file}.tmp {pid_file}; "
                "sleep 30"
            )
            captured = io.StringIO()
            with mock.patch.object(
                runner, "_group_alive", return_value=True
            ), contextlib.redirect_stderr(captured):
                error = _interrupt(pid_file, program)
            pid = int(pid_file.read_text(encoding="utf-8"))
        self.assertIn(f"process group {pid}", captured.getvalue())
        self.assertIn(runner.CLEANUP_ERROR, captured.getvalue())
        notes = getattr(error, "__notes__", [])
        self.assertTrue(
            any(
                f"process group {pid}" in note
                and runner.CLEANUP_ERROR in note
                for note in notes
            ),
            notes,
        )

    def test_a_group_that_survives_sigkill_reports_unconfirmed_cleanup(self) -> None:
        program = "import time; time.sleep(30)"
        real_reap = runner._reap
        signals_before_reap: list[signal.Signals] = []

        def reap(process: subprocess.Popen[bytes]) -> bool:
            signals_before_reap[:] = [
                call.args[1] for call in signal_group.call_args_list if call.args[0] == process.pid
            ]
            return real_reap(process)

        with (
            mock.patch.object(runner, "_group_alive", return_value=True),
            mock.patch.object(runner, "_signal_group", wraps=runner._signal_group)
            as signal_group,
            mock.patch.object(runner, "_reap", side_effect=reap),
        ):
            start = time.monotonic()
            result = runner.run(
                [sys.executable, "-c", program],
                budget_seconds=0.2,
                grace_seconds=0.2,
            )
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, runner.CLEANUP_SECONDS + 8.0)
        self.assertEqual(result.execution, "error")
        self.assertTrue(result.timed_out)
        self.assertEqual(result.error, runner.CLEANUP_ERROR)
        self.assertIn(signal.SIGTERM, signals_before_reap)
        after_sigterm = signals_before_reap.index(signal.SIGTERM) + 1
        self.assertIn(
            signal.SIGKILL, signals_before_reap[after_sigterm:],
            "Expected the drain to request SIGKILL after SIGTERM before _reap",
        )


if __name__ == "__main__":
    unittest.main()
