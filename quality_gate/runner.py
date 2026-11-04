"""The one bounded subprocess runner.

Every subprocess the gate starts (repository helpers, command checks and
test runs) goes through 'run': the child starts in its own process group, the whole group is
terminated at the budget (SIGTERM, then SIGKILL after a grace period) and
reaped, and output is captured up to a fixed byte limit.  Bytes beyond the
limit are counted and discarded; a rolling tail of all output is kept for
diagnostics.

The run has one wall-clock limit: 'checks._run_policy_checks' arms it with
SIGALRM and the handler raises 'RunTimeout'.  A context variable keeps the
current check, its deadline and its step, so the timeout can name the check and
the step that was running and a subprocess can share the check's budget.
"""
from __future__ import annotations

import contextlib
import contextvars
import os
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from .policy import UsageError

CAPTURE_LIMIT = 1024 * 1024
TAIL_LIMIT = 4096
GRACE_SECONDS = 5.0
_PIPE_READ = 65536


@dataclass
class CheckDeadline:
    check: str
    started: float
    seconds: float
    step: str = "check setup"

    @property
    def deadline(self) -> float:
        return self.started + self.seconds


_check_deadline: contextvars.ContextVar[CheckDeadline | None] = (
    contextvars.ContextVar("check_deadline", default=None)
)


class RunTimeout(UsageError):
    """The run exceeded the wall-clock limit of its checks' budgets."""

    def __init__(self, limit: float, allowance: float) -> None:
        scope = _check_deadline.get()
        check = scope.check if scope is not None else "unknown"
        step = scope.step if scope is not None else "unknown"
        super().__init__(
            f"the run exceeded its {limit:g} s limit "
            f"(its checks' budgets plus {allowance:g} s) during {check}: {step}"
        )


@contextlib.contextmanager
def check_deadline(check: str, started: float, seconds: float):
    """Set the current check, its deadline and the starting step name."""
    scope = CheckDeadline(check, started, seconds)
    token = _check_deadline.set(scope)
    try:
        yield scope
    finally:
        _check_deadline.reset(token)


def remaining_budget(seconds: float) -> float:
    """The smaller of SECONDS and the current check's remaining time."""
    scope = _check_deadline.get()
    if scope is None:
        return seconds
    return max(0.0, min(seconds, scope.deadline - time.monotonic()))


def mark_step(step: str) -> None:
    scope = _check_deadline.get()
    if scope is not None:
        scope.step = step


@dataclass
class Diagnostics:
    """Execution facts a JSON consumer can use without parsing stderr."""

    argv: list[str] | None = None
    exit_code: int | None = None
    signal: int | None = None
    output_bytes: int = 0
    output_tail: str = ""
    output_truncated: bool = False
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "argv": self.argv,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "output_bytes": self.output_bytes,
            "output_tail": self.output_tail,
            "output_truncated": self.output_truncated,
        }
        if self.error is not None:
            document["error"] = self.error
        return document


@dataclass
class RunResult:
    """The outcome of one bounded run."""

    argv: tuple[str, ...]
    execution: str
    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    output_bytes: int = 0
    output_tail: bytes = b""
    output_truncated: bool = False
    duration_seconds: float = 0.0
    error: str | None = None
    timed_out: bool = False

    @staticmethod
    def _text(data: bytes) -> str:
        return data.decode("utf-8", "replace")

    @property
    def stdout_text(self) -> str:
        return self._text(self.stdout)

    @property
    def stderr_text(self) -> str:
        return self._text(self.stderr)

    @property
    def combined(self) -> bytes:
        first = self.stdout
        second = self.stderr
        if first and second and not first.endswith(b"\n"):
            first += b"\n"
        return first + second

    @property
    def combined_text(self) -> str:
        return self._text(self.combined)

    def diagnostics(self) -> Diagnostics:
        exit_code = self.returncode
        signal_number = None
        if exit_code is not None and exit_code < 0:
            signal_number = -exit_code
            exit_code = None
        return Diagnostics(
            argv=list(self.argv),
            exit_code=exit_code,
            signal=signal_number,
            output_bytes=self.output_bytes,
            output_tail=self._text(self.output_tail[-TAIL_LIMIT:]),
            output_truncated=self.output_truncated,
            error=self.error,
        )


def _empty(
    argv: tuple[str, ...], *, execution: str, error: str, started: float
) -> RunResult:
    return RunResult(
        argv=argv,
        execution=execution,
        returncode=None,
        error=error,
        duration_seconds=time.monotonic() - started,
    )


def _signal_group(pid: int, number: int) -> None:
    try:
        os.killpg(pid, number)
    except OSError:
        pass


def _proc_group_member(path: str, group: int) -> bool:
    try:
        with open(path, encoding="utf-8") as stream:
            fields = stream.read().rpartition(")")[2].split()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return len(fields) < 3 or (fields[2] == str(group) and fields[0] not in ("Z", "X"))


def _proc_group_running(pid: int) -> bool:
    try:
        with os.scandir("/proc") as entries:
            return any(
                _proc_group_member(f"{entry.path}/stat", pid)
                for entry in entries if entry.name.isdigit()
            )
    except OSError:
        return True


def _group_alive(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return _proc_group_running(pid) if sys.platform.startswith("linux") else True


@dataclass
class _Capture:
    limit: int
    buffers: dict[str, bytearray] = field(
        default_factory=lambda: {"stdout": bytearray(), "stderr": bytearray()}
    )
    total: int = 0
    captured: int = 0
    tail: bytearray = field(default_factory=bytearray)

    def add(self, name: str, chunk: bytes) -> None:
        self.total += len(chunk)
        room = self.limit - self.captured
        if room > 0:
            take = min(room, len(chunk))
            self.buffers[name].extend(chunk[:take])
            self.captured += take
        self.tail.extend(chunk)
        if len(self.tail) > TAIL_LIMIT:
            del self.tail[: len(self.tail) - TAIL_LIMIT]

    @property
    def truncated(self) -> bool:
        return self.total > self.captured


@dataclass
class _DrainState:
    deadline: float
    grace_seconds: float
    execution: str = "completed"
    terminated_at: float | None = None
    killed: bool = False
    hard_deadline: float | None = None

    def advance(self, now: float, pid: int) -> None:
        if self.terminated_at is None and now >= self.deadline:
            self.execution = "budget"
            _signal_group(pid, signal.SIGTERM)
            self.terminated_at = now
        if self._grace_expired(now):
            _signal_group(pid, signal.SIGKILL)
            self.killed = True
            self.hard_deadline = now + 1.0

    def _grace_expired(self, now: float) -> bool:
        return (
            self.terminated_at is not None
            and not self.killed
            and now >= self.terminated_at + self.grace_seconds
        )

    def past_hard_deadline(self, now: float) -> bool:
        return (
            self.hard_deadline is not None
            and now >= self.hard_deadline
        )

    def timeout(self, now: float) -> float:
        if self.terminated_at is None:
            return max(0.0, min(0.1, self.deadline - now))
        if self.killed:
            return 0.05
        return max(
            0.0,
            min(0.05, self.terminated_at + self.grace_seconds - now),
        )


def _read_chunk(fd: int) -> bytes | None:
    try:
        return os.read(fd, _PIPE_READ)
    except BlockingIOError:
        return None
    except OSError:
        return b""


def _read_ready(
    events: list[tuple[Any, int]],
    selector: selectors.BaseSelector,
    streams: dict[str, Any],
    capture: _Capture,
) -> None:
    for key, _mask in events:
        fd = key.fd
        name = key.data
        stream = streams[name]
        chunk = _read_chunk(fd)
        if chunk:
            capture.add(name, chunk)
        elif chunk == b"":
            selector.unregister(fd)
            stream.close()


def _process_finished(process: subprocess.Popen[bytes]) -> bool:
    return process.poll() is not None and not _group_alive(process.pid)


def _finished(process: subprocess.Popen[bytes], selector: selectors.BaseSelector) -> bool:
    return not selector.get_map() and _process_finished(process)


def _drain(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    streams: dict[str, Any],
    capture: _Capture,
    deadline: float,
    grace_seconds: float,
) -> str:
    state = _DrainState(deadline, grace_seconds)
    while True:
        now = time.monotonic()
        state.advance(now, process.pid)
        if _finished(process, selector):
            break
        if state.past_hard_deadline(now):
            break
        events = selector.select(state.timeout(now))
        _read_ready(events, selector, streams, capture)
    return state.execution


def _close(selector: selectors.BaseSelector, streams: dict[str, Any]) -> None:
    selector.close()
    for stream in streams.values():
        with contextlib.suppress(OSError):
            stream.close()


def _kill_and_wait(process: subprocess.Popen[bytes]) -> None:
    _signal_group(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        pass


def _reap(process: subprocess.Popen[bytes]) -> None:
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        _kill_and_wait(process)


def _was_signalled(execution: str, returncode: int | None) -> bool:
    return (
        execution != "budget"
        and returncode is not None
        and returncode < 0
    )


def _run_budget(
    budget_seconds: float, grace_seconds: float
) -> tuple[float, float]:
    if _check_deadline.get() is None:
        return budget_seconds, grace_seconds
    return remaining_budget(budget_seconds), 0.0


def _popen(
    command: tuple[str, ...],
    cwd: os.PathLike[str] | str | None,
    env: dict[str, str] | None,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


def _spawn(
    argv: tuple[str, ...],
    cwd: os.PathLike[str] | str | None,
    env: dict[str, str] | None,
    started: float,
) -> tuple[subprocess.Popen[bytes] | None, RunResult | None]:
    try:
        return _popen(argv, cwd, env), None
    except (OSError, subprocess.SubprocessError) as error:
        return None, _empty(
            argv,
            execution="error",
            error=f"cannot run command: {error}",
            started=started,
        )


def _capture_process(
    process: subprocess.Popen[bytes], deadline: float,
    grace_seconds: float, capture_limit: int | None,
) -> tuple[str, _Capture]:
    assert process.stdout is not None and process.stderr is not None
    limit = 2**63 if capture_limit is None else max(0, capture_limit)
    capture = _Capture(limit=limit)
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    selector = selectors.DefaultSelector()
    for name, stream in streams.items():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream.fileno(), selectors.EVENT_READ, name)
    try:
        execution = _drain(process, selector, streams, capture, deadline, grace_seconds)
    finally:
        _close(selector, streams)
    return execution, capture


def run(
    argv: list[str] | tuple[str, ...],
    *,
    cwd: os.PathLike[str] | str | None = None,
    env: dict[str, str] | None = None,
    budget_seconds: float,
    capture_limit: int | None = CAPTURE_LIMIT,
    grace_seconds: float = GRACE_SECONDS,
) -> RunResult:
    """Run ARGV in its own process group within BUDGET_SECONDS."""
    budget_seconds, grace_seconds = _run_budget(budget_seconds, grace_seconds)
    argv_tuple = tuple(argv)
    started = time.monotonic()
    deadline = started + max(0.0, budget_seconds)
    process, failure = _spawn(argv_tuple, cwd, env, started)
    if failure is not None:
        return failure
    assert process is not None
    try:
        execution, capture = _capture_process(
            process, deadline, grace_seconds, capture_limit
        )
        _reap(process)
        returncode = process.poll()
        if _was_signalled(execution, returncode):
            execution = "signal"
        return RunResult(
            argv=argv_tuple,
            execution=execution,
            returncode=returncode,
            stdout=bytes(capture.buffers["stdout"]),
            stderr=bytes(capture.buffers["stderr"]),
            output_bytes=capture.total,
            output_tail=bytes(capture.tail),
            output_truncated=capture.truncated,
            duration_seconds=time.monotonic() - started,
            timed_out=execution == "budget",
        )
    except BaseException:
        _kill_and_wait(process)
        raise
