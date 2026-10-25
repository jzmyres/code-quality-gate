"""The one bounded subprocess runner.

Every subprocess the gate starts (git helpers, command checks, jscpd and
test runs) goes through `run`: the child starts in its own process group, the whole group is
terminated at the budget (SIGTERM, then SIGKILL after a grace period) and
reaped, and output is captured up to a fixed byte limit.  Bytes beyond the
limit are counted and discarded; a rolling tail of all output is kept for
diagnostics.
"""
from __future__ import annotations

import contextlib
import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any


CAPTURE_LIMIT = 1024 * 1024
TAIL_LIMIT = 4096
GRACE_SECONDS = 5.0
_PIPE_READ = 65536


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


def _group_alive(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except OSError:
        return False
    return True


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
        while (chunk := _read_chunk(fd)) is not None:
            if chunk:
                capture.add(name, chunk)
                continue
            selector.unregister(fd)
            stream.close()
            break


def _finished(
    process: subprocess.Popen[bytes], selector: selectors.BaseSelector
) -> bool:
    if selector.get_map() or process.poll() is None:
        return False
    return not _group_alive(process.pid)


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
    argv_tuple = tuple(argv)
    started = time.monotonic()
    deadline = started + max(0.0, budget_seconds)
    try:
        process = subprocess.Popen(
            argv_tuple,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        return _empty(
            argv_tuple,
            execution="error",
            error=f"cannot run command: {error}",
            started=started,
        )

    assert process.stdout is not None
    assert process.stderr is not None
    limit = 2**63 if capture_limit is None else max(0, capture_limit)
    capture = _Capture(limit=limit)
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    selector = selectors.DefaultSelector()
    for name, stream in streams.items():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream.fileno(), selectors.EVENT_READ, name)
    try:
        execution = _drain(
            process, selector, streams, capture, deadline, grace_seconds
        )
    finally:
        _close(selector, streams)
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
