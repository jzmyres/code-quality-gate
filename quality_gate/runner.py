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
import ctypes
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
CLEANUP_SECONDS = 1.0
CLEANUP_ERROR = (
    f"cleanup did not confirm the process group gone within {CLEANUP_SECONDS:g} s"
)
DESCENDANT_ERROR = (
    "cleanup did not confirm the adopted descendants gone within "
    f"{CLEANUP_SECONDS:g} s"
)
_PR_SET_CHILD_SUBREAPER = 36
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


@dataclass(frozen=True)
class ExecutionOutcome:
    """One value of RunResult.execution and what it means to a caller."""

    name: str
    completed: bool = False
    error: bool = False
    budget: bool = False
    signal: bool = False


# The one termination-outcome table: every adapter reads a run's execution
# through it instead of comparing the names itself.
EXECUTION_OUTCOMES = {
    "completed": ExecutionOutcome("completed", completed=True),
    "error": ExecutionOutcome("error", error=True),
    "budget": ExecutionOutcome("budget", budget=True),
    "signal": ExecutionOutcome("signal", signal=True),
}


def execution_outcome(execution: str) -> ExecutionOutcome:
    """The table's record for EXECUTION, or an unknown one with no flags."""
    outcome = EXECUTION_OUTCOMES.get(execution)
    if outcome is None:
        return ExecutionOutcome(execution)
    return outcome


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


def _proc_fields(path: str) -> list[str] | None:
    """The fields after a process's name in /proc/PID/stat, or None if gone."""
    try:
        with open(path, encoding="utf-8") as stream:
            return stream.read().rpartition(")")[2].split()
    except FileNotFoundError:
        return None


def _proc_group_member(path: str, group: int) -> bool:
    try:
        fields = _proc_fields(path)
    except OSError:
        return True
    if fields is None:
        return False
    return len(fields) < 3 or (
        fields[2] == str(group) and fields[0] not in ("Z", "X")
    )


def _fields_of(name: str) -> list[str] | None:
    """One process's /proc fields, or None when it is gone or unreadable."""
    try:
        return _proc_fields(f"/proc/{name}/stat")
    except OSError:
        return None


def _child_pid(name: str, pid: int) -> int | None:
    """The pid NAME names, when its parent is PID."""
    fields = _fields_of(name)
    if fields is None or len(fields) < 2:
        return None
    return int(name) if fields[1] == str(pid) else None


def _enumeration_error(error: OSError) -> str:
    return (
        f"cannot enumerate the process table: "
        f"{type(error).__name__}: {error}"
    )


def _children(pid: int) -> set[int]:
    """The pids whose parent is PID, read from /proc.

    An unreadable or absent process table raises OSError: treating it as an
    empty set would confirm a cleanup that was never seen.
    """
    names = [name for name in os.listdir("/proc") if name.isdigit()]
    found: set[int] = set()
    for name in names:
        child = _child_pid(name, pid)
        if child is not None:
            found.add(child)
    return found


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
    """Whether the group may still hold a live member; cannot tell means yes."""
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    if not sys.platform.startswith("linux"):
        return True
    try:
        return _proc_group_running(pid)
    except OSError:
        return True


def _subreaper_failure() -> str | None:
    """Why this process cannot adopt orphaned descendants, or None."""
    if not sys.platform.startswith("linux"):
        return f"PR_SET_CHILD_SUBREAPER is unavailable on {sys.platform}"
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
    except (OSError, AttributeError) as error:
        return f"prctl(PR_SET_CHILD_SUBREAPER) is unavailable: {error}"
    if result != 0:
        return (
            "prctl(PR_SET_CHILD_SUBREAPER) failed: "
            f"{os.strerror(ctypes.get_errno())}"
        )
    return None


def _kill_adopted(adopted: set[int]) -> None:
    """Stop and non-blockingly reap the children this process adopted."""
    for pid in adopted:
        _signal_group(pid, signal.SIGKILL)
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)
    for pid in adopted:
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass


def _stop_remaining(known: set[int]) -> str | None:
    """Tell whether an adopted child remains, or why that cannot be seen."""
    try:
        remaining = _children(os.getpid()) - known
    except OSError as error:
        return _enumeration_error(error)
    if remaining:
        return DESCENDANT_ERROR
    return None


def _stop_adopted(known: set[int]) -> str | None:
    """Kill and reap every adopted child, or return why absence is unconfirmed."""
    deadline = time.monotonic() + CLEANUP_SECONDS
    while True:
        try:
            adopted = _children(os.getpid()) - known
        except OSError as error:
            return _enumeration_error(error)
        if not adopted:
            return None
        _kill_adopted(adopted)
        if time.monotonic() < deadline:
            time.sleep(0.01)
            continue
        return _stop_remaining(known)


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


def _kill_and_wait(process: subprocess.Popen[bytes]) -> bool:
    """Kill the group, and tell whether its absence was confirmed by the deadline.

    The leader is polled every turn: an unreaped zombie of the leader is what
    keeps the group looking alive where 'killpg' cannot tell, so reaping it is
    part of showing the group gone.
    """
    deadline = time.monotonic() + CLEANUP_SECONDS
    gone = False
    while not gone:
        _signal_group(process.pid, signal.SIGKILL)
        process.poll()
        gone = not _group_alive(process.pid)
        if gone or time.monotonic() >= deadline:
            break
        time.sleep(0.01)
    try:
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        pass
    return gone


def _reap(process: subprocess.Popen[bytes]) -> bool:
    """Wait for the leader, and tell whether the group was confirmed gone."""
    try:
        process.wait(timeout=CLEANUP_SECONDS)
    except subprocess.TimeoutExpired:
        return _kill_and_wait(process)
    if not _group_alive(process.pid):
        return True
    return _kill_and_wait(process)


def _was_signalled(execution: str, returncode: int | None) -> bool:
    return (
        execution != "budget"
        and returncode is not None
        and returncode < 0
    )


def _cleanup_error(group_gone: bool, adopted_error: str | None) -> str | None:
    """The cleanup failure that wins over the drained execution, if any."""
    if group_gone and adopted_error is None:
        return None
    return CLEANUP_ERROR if not group_gone else adopted_error


def _finish_interrupted(
    error: BaseException, process: subprocess.Popen[bytes], known: set[int],
) -> None:
    """Kill what an interrupted run left, and note any unconfirmed cleanup."""
    if not _kill_and_wait(process):
        note = f"process group {process.pid}: {CLEANUP_ERROR}"
        error.add_note(note)
        print(note, file=sys.stderr, flush=True)
    adopted_error = _stop_adopted(known)
    if adopted_error is not None:
        error.add_note(adopted_error)
        print(adopted_error, file=sys.stderr, flush=True)


def _execution_fields(
    execution: str, returncode: int | None, cleanup_error: str | None,
) -> tuple[str, str | None, bool]:
    """The run's outcome split into execution, error and timeout flag."""
    if cleanup_error is not None:
        return "error", cleanup_error, True
    if _was_signalled(execution, returncode):
        return "signal", None, False
    return execution, None, execution == "budget"


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
    argv_tuple = tuple(argv)
    started = time.monotonic()
    subreaper_failure = _subreaper_failure()
    if subreaper_failure is not None:
        return _empty(
            argv_tuple,
            execution="error",
            error=(
                "cannot make the check a child subreaper: "
                f"{subreaper_failure}"
            ),
            started=started,
        )
    try:
        known = _children(os.getpid())
    except OSError as error:
        return _empty(
            argv_tuple,
            execution="error",
            error=_enumeration_error(error),
            started=started,
        )
    budget_seconds, grace_seconds = _run_budget(budget_seconds, grace_seconds)
    deadline = started + max(0.0, budget_seconds)
    process, failure = _spawn(argv_tuple, cwd, env, started)
    if failure is not None:
        return failure
    assert process is not None
    try:
        execution, capture = _capture_process(
            process, deadline, grace_seconds, capture_limit
        )
        group_gone = _reap(process)
        adopted_error = _stop_adopted(known)
        returncode = process.poll()
        # Cleanup that could not show the group or its adopted descendants gone
        # wins over the drained execution: the run must never report a silent
        # success in that case.
        execution, error, timed_out = _execution_fields(
            execution, returncode, _cleanup_error(group_gone, adopted_error)
        )
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
            error=error,
            timed_out=timed_out,
        )
    except BaseException as error:
        _finish_interrupted(error, process, known)
        raise
