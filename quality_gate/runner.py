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
import contextvars
import fcntl
import io
import json
import os
import pickle
import selectors
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable

from .json_input import load_json

CAPTURE_LIMIT = 1024 * 1024
TAIL_LIMIT = 4096
GRACE_SECONDS = 5.0
_PIPE_READ = 65536
_STOP_WAIT = 1.0


class StepTimeout(Exception):
    """An in-process step exceeded the check deadline."""


class WorkerError(Exception):
    """A supervised analysis worker failed without returning a result."""


@dataclass
class CheckDeadline:
    started: float
    seconds: float
    step: str = "check setup"
    diagnostics: Any = None

    @property
    def deadline(self) -> float:
        return self.started + self.seconds


_check_deadline: contextvars.ContextVar[CheckDeadline | None] = (
    contextvars.ContextVar("check_deadline", default=None)
)


@dataclass(frozen=True)
class _WorkerRegistry:
    path: str
    ancestors: tuple[int, ...] = ()


_worker_registry: contextvars.ContextVar[_WorkerRegistry | None] = (
    contextvars.ContextVar("worker_registry", default=None)
)
_worker_process_registry: _WorkerRegistry | None = None


def _current_registry() -> _WorkerRegistry | None:
    return _worker_registry.get() or _worker_process_registry


@contextlib.contextmanager
def _registry_data(registry: _WorkerRegistry):
    with open(registry.path, "r+", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            data = load_json(stream.read())
            yield data
            stream.seek(0)
            json.dump(data, stream)
            stream.truncate()
            stream.flush()
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def _register_session(command: tuple[str, ...], kind: str, token: str) -> None:
    global _worker_process_registry
    registry = _current_registry()
    assert registry is not None
    pid = os.getpid()
    ancestors = (*registry.ancestors, pid) if kind == "worker" else registry.ancestors
    with _registry_data(registry) as data:
        if any(parent in data["cancelled"] for parent in ancestors):
            raise WorkerError("worker was cancelled before starting a process")
        data["entries"][str(pid)] = {
            "ancestors": ancestors, "command": command, "kind": kind, "token": token,
        }
        # Cancellation holds the same lock, so it sees either the worker's group
        # or the registered new group, including while a subprocess is launching.
        os.setsid()
    if kind == "worker":
        _worker_process_registry = _WorkerRegistry(registry.path, ancestors)
        _worker_registry.set(_worker_process_registry)


def _forget_process(pid: int) -> None:
    registry = _current_registry()
    if registry is not None:
        with _registry_data(registry) as data:
            data["entries"].pop(str(pid), None)


def _forget_token(token: str) -> None:
    registry = _current_registry()
    assert registry is not None
    with _registry_data(registry) as data:
        entries = data["entries"]
        for pid, entry in list(entries.items()):
            if entry["token"] == token:
                del entries[pid]


@contextlib.contextmanager
def check_deadline(started: float, seconds: float):
    scope = CheckDeadline(started, seconds)
    token = _check_deadline.set(scope)
    try:
        yield scope
    finally:
        _check_deadline.reset(token)


def remaining_budget(seconds: float) -> float:
    scope = _check_deadline.get()
    if scope is None:
        return seconds
    return max(0.0, min(seconds, scope.deadline - time.monotonic()))


def check_time() -> None:
    scope = _check_deadline.get()
    if scope is not None and time.monotonic() >= scope.deadline:
        raise StepTimeout(scope.step)


def record_diagnostics(diagnostics: Any) -> None:
    scope = _check_deadline.get()
    if scope is not None:
        scope.diagnostics = diagnostics


def mark_step(step: str) -> None:
    scope = _check_deadline.get()
    if scope is not None:
        scope.step = step


def _current_coverage() -> Any:
    module = sys.modules.get("coverage")
    return module.Coverage.current() if module is not None else None


def _start_worker_coverage() -> Any:
    current = _current_coverage()
    if current is None:
        return None
    # A fork has its own memory. Record its real execution separately, then
    # send it back to the already-active collector in the parent.
    module = sys.modules["coverage"]
    child = module.Coverage(
        data_file=None,
        config_file=False,
        source=current.get_option("run:source"),
        branch=current.get_option("run:branch"),
        include=current.get_option("run:include"),
        omit=current.get_option("run:omit"),
    )
    child.start()
    return child


def _finish_worker_coverage(child: Any) -> tuple[bool, dict[str, Any]] | None:
    if child is None:
        return None
    child.stop()
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="No data was collected.*")
        data = child.get_data()
    return _coverage_snapshot(data)


def _coverage_snapshot(data: Any) -> tuple[bool, dict[str, Any]] | None:
    arcs = data.has_arcs()
    recorded = {
        name: (data.arcs(name) if arcs else data.lines(name))
        for name in data.measured_files()
    }
    recorded = {name: lines for name, lines in recorded.items() if lines}
    return (arcs, recorded) if recorded else None


def _merge_worker_coverage(snapshot: tuple[bool, dict[str, Any]] | None) -> None:
    if snapshot is None:
        return
    current = _current_coverage()
    if current is None:
        return
    arcs, recorded = snapshot
    if arcs:
        current.get_data().add_arcs(recorded)
    else:
        current.get_data().add_lines(recorded)


def _worker_payload(function: Callable[..., Any], args: tuple[Any, ...]) -> bytes:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        coverage = _start_worker_coverage()
        try:
            success, result = True, function(*args)
        except BaseException as error:
            success, result = False, error
        snapshot = _finish_worker_coverage(coverage)
    response = (
        success, result, stdout.getvalue(), stderr.getvalue(), snapshot
    )
    try:
        return pickle.dumps(response, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception as error:
        failure = WorkerError(f"cannot return worker result: {error}")
        return pickle.dumps(
            (False, failure, stdout.getvalue(), stderr.getvalue(), snapshot)
        )


def _worker(
    write_fd: int, step: str, function: Callable[..., Any], args: tuple[Any, ...]
) -> None:
    try:
        _register_session(("analysis worker", step), "worker", "")
        payload = memoryview(_worker_payload(function, args))
        while payload:
            payload = payload[os.write(write_fd, payload):]
    finally:
        os._exit(0)


def _stop_error(pid: int, entry: dict[str, Any], detail: str) -> str:
    return f"cannot stop pid {pid} command {shlex.join(entry['command'])}: {detail}"


def _kill_registered(pid: int, entry: dict[str, Any]) -> str | None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return None
    except OSError as error:
        return _stop_error(pid, entry, str(error))
    return None


def _registered(data: dict[str, Any], worker: int, kind: str) -> dict[int, dict[str, Any]]:
    return {
        int(pid): entry for pid, entry in data["entries"].items()
        if worker in entry["ancestors"] and entry["kind"] == kind
    }


def _cancel_processes(worker: int) -> tuple[dict[int, dict[str, Any]], list[str]]:
    registry = _current_registry()
    assert registry is not None
    with _registry_data(registry) as data:
        data["cancelled"].append(worker)
        processes = _registered(data, worker, "process")
        failures = [_kill_registered(pid, entry) for pid, entry in processes.items()]
    return processes, [failure for failure in failures if failure is not None]


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


def _proc_member_command(pid: int, fallback: list[str]) -> list[str]:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as stream:
            command = [os.fsdecode(item) for item in stream.read().split(b"\0") if item]
    except OSError:
        return fallback
    return command or fallback


def _live_member(path: str, pid: int, group: int, fallback: list[str]) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as stream:
            fields = stream.read().rpartition(")")[2].split()
    except OSError:
        return None
    if len(fields) < 3 or fields[2] != str(group) or fields[0] in ("Z", "X"):
        return None
    return {"command": _proc_member_command(pid, fallback)}


def _live_group_members(group: int, entry: dict[str, Any]) -> dict[int, dict[str, Any]]:
    try:
        with os.scandir("/proc") as paths:
            members = {}
            for path in paths:
                if path.name.isdigit():
                    pid = int(path.name)
                    member = _live_member(f"{path.path}/stat", pid, group, entry["command"])
                    if member is not None:
                        members[pid] = member
            return members
    except OSError:
        return {}


def _pending_errors(groups: dict[int, dict[str, Any]]) -> list[str]:
    failures = []
    for group, entry in groups.items():
        members = _live_group_members(group, entry) if sys.platform.startswith("linux") else {}
        failures.extend(
            _stop_error(pid, member, "still running")
            for pid, member in (members or {group: entry}).items()
        )
    return failures


def _group_running(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return _proc_group_running(pid) if sys.platform.startswith("linux") else True


def _running_groups(processes: dict[int, dict[str, Any]]) -> dict[int, dict[str, Any]]:
    return {pid: entry for pid, entry in processes.items() if _group_running(pid)}


def _wait_for_groups(processes: dict[int, dict[str, Any]]) -> dict[int, dict[str, Any]]:
    deadline = time.monotonic() + _STOP_WAIT
    while processes:
        processes = _running_groups(processes)
        if not processes or time.monotonic() >= deadline:
            break
        for pid, entry in processes.items():
            _kill_registered(pid, entry)
        time.sleep(0.01)
    return processes


def _kill_worker_pid(pid: int, entry: dict[str, Any]) -> str | None:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return None
    except OSError as error:
        return _stop_error(pid, entry, str(error))
    return None


def _reaped(pid: int) -> bool:
    try:
        finished, _status = os.waitpid(pid, os.WNOHANG)
        return bool(finished)
    except ChildProcessError:
        return True


def _workers_to_stop(data: dict[str, Any], worker: int, step: str) -> tuple[dict[int, Any], bool]:
    workers = _registered(data, worker, "worker")
    reaped = _reaped(worker)
    if reaped and not _group_running(worker):
        workers.pop(worker, None)
        data["entries"].pop(str(worker), None)
    elif worker not in workers:
        workers[worker] = {"command": ("analysis worker", step)}
    return workers, reaped


def _worker_signals(pid: int, entry: dict[str, Any], worker: int, reaped: bool) -> list[str | None]:
    failures = [_kill_registered(pid, entry)]
    if pid != worker or not reaped:
        failures.append(_kill_worker_pid(pid, entry))
    return failures


def _signal_workers(workers: dict[int, Any], worker: int, reaped: bool) -> list[str]:
    return [
        failure for pid, entry in workers.items()
        for failure in _worker_signals(pid, entry, worker, reaped) if failure is not None
    ]


def _kill_workers(worker: int, step: str) -> tuple[dict[int, dict[str, Any]], list[str]]:
    registry = _current_registry()
    assert registry is not None
    with _registry_data(registry) as data:
        workers, reaped = _workers_to_stop(data, worker, step)
        failures = _signal_workers(workers, worker, reaped)
    return workers, failures


def _wait_for_worker(pid: int, step: str) -> str | None:
    deadline = time.monotonic() + _STOP_WAIT
    while not _reaped(pid):
        if time.monotonic() >= deadline:
            return _stop_error(pid, {"command": ("analysis worker", step)}, "still running")
        time.sleep(0.01)
    return None


def _stop_worker(pid: int, step: str) -> None:
    processes, failures = _cancel_processes(pid)
    pending = _wait_for_groups(processes)
    workers, worker_failures = _kill_workers(pid, step)
    failures.extend(worker_failures)
    worker_failure = _wait_for_worker(pid, step)
    if worker_failure is not None:
        failures.append(worker_failure)
    pending_workers = _wait_for_groups(workers)
    pending = _wait_for_groups(pending)
    failures.extend(_pending_errors(pending))
    failures.extend(_pending_errors(pending_workers))
    if failures:
        raise WorkerError("; ".join(failures))
    _forget_stopped(processes | workers)


def _forget_stopped(stopped: dict[int, dict[str, Any]]) -> None:
    registry = _current_registry()
    assert registry is not None
    with _registry_data(registry) as data:
        entries = data["entries"]
        for pid, entry in stopped.items():
            if entries.get(str(pid)) == entry:
                del entries[str(pid)]


def _read_worker(read_fd: int, deadline: float, step: str) -> bytes:
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(read_fd, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StepTimeout(step)
            if not selector.select(remaining):
                continue
            chunk = os.read(read_fd, _PIPE_READ)
            if not chunk:
                break
            data.extend(chunk)
    return bytes(data)


def _decode_worker(data: bytes, step: str) -> Any:
    try:
        success, result, stdout, stderr, snapshot = pickle.loads(data)
    except Exception as error:
        raise WorkerError(f"{step} worker returned invalid data: {error}") from error
    _merge_worker_coverage(snapshot)
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    if not success:
        raise result
    return result


def _worker_result(read_fd: int, pid: int, deadline: float, step: str) -> Any:
    data = _read_worker(read_fd, deadline, step)
    registry = _current_registry()
    assert registry is not None
    with _registry_data(registry) as state:
        _pid, status = os.waitpid(pid, 0)
        state["entries"].pop(str(pid), None)
    if status != 0 or not data:
        raise WorkerError(f"{step} worker exited without a result")
    return _decode_worker(data, step)


def _step_deadline(step: str, deadline: float | None) -> float | None:
    scope = _check_deadline.get()
    if scope is not None:
        scope.step = step
        return min(deadline, scope.deadline) if deadline is not None else scope.deadline
    return deadline


def _worker_pipe(step: str) -> tuple[int, int]:
    try:
        return os.pipe()
    except OSError as error:
        raise WorkerError(f"cannot start {step} worker: {error}") from error


def _start_worker(step: str, function: Callable[..., Any], args: tuple[Any, ...]) -> tuple[int, int]:
    read_fd, write_fd = _worker_pipe(step)
    try:
        pid = os.fork()
    except OSError as error:
        os.close(read_fd)
        os.close(write_fd)
        raise WorkerError(f"cannot start {step} worker: {error}") from error
    if pid == 0:
        os.close(read_fd)
        _worker(write_fd, step, function, args)
    os.close(write_fd)
    return read_fd, pid


def _supervise_registered(
    step: str, function: Callable[..., Any], args: tuple[Any, ...], deadline: float
) -> Any:
    read_fd, pid = _start_worker(step, function, args)
    try:
        return _worker_result(read_fd, pid, deadline, step)
    except BaseException:
        _stop_worker(pid, step)
        raise
    finally:
        os.close(read_fd)


def _supervise(step: str, function: Callable[..., Any], args: tuple[Any, ...], deadline: float) -> Any:
    if _current_registry() is not None:
        return _supervise_registered(step, function, args, deadline)
    with tempfile.TemporaryDirectory(prefix="qg-workers-") as directory:
        path = os.path.join(directory, "registry.json")
        with open(path, "w", encoding="utf-8") as stream:
            json.dump({"cancelled": [], "entries": {}}, stream)
        token = _worker_registry.set(_WorkerRegistry(path))
        try:
            return _supervise_registered(step, function, args, deadline)
        finally:
            _worker_registry.reset(token)


def analysis_step(
    step: str, function: Callable[..., Any], *args: Any, deadline: float | None = None
) -> Any:
    """Run a synchronous step in a killable worker under the remaining deadline."""
    deadline = _step_deadline(step, deadline)
    if deadline is None:
        return function(*args)
    if time.monotonic() >= deadline:
        raise StepTimeout(step)
    return _supervise(step, function, args, deadline)


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
        chunk = _read_chunk(fd)
        if chunk:
            capture.add(name, chunk)
        elif chunk == b"":
            selector.unregister(fd)
            stream.close()


def _process_finished(process: subprocess.Popen[bytes]) -> bool:
    return process.poll() is not None and not _group_alive(process.pid)


def _tracked_finished(process: subprocess.Popen[bytes]) -> bool:
    if sys.platform.startswith("linux"):
        # Keep the leader unreaped until the group has stopped, so its pid
        # cannot identify another process while the registry still refers to that group.
        return not _group_running(process.pid) and process.poll() is not None
    return _process_finished(process)


def _finished(process: subprocess.Popen[bytes], selector: selectors.BaseSelector) -> bool:
    if selector.get_map():
        return False
    registry = _current_registry()
    if registry is None:
        return _process_finished(process)
    with _registry_data(registry) as data:
        finished = _tracked_finished(process)
        if finished:
            data["entries"].pop(str(process.pid), None)
        return finished


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
    if _check_deadline.get() is not None:
        check_time()
        return remaining_budget(budget_seconds), 0.0
    return budget_seconds, grace_seconds


def _popen(
    command: tuple[str, ...],
    cwd: os.PathLike[str] | str | None,
    env: dict[str, str] | None,
    token: str | None,
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=token is None,
        preexec_fn=(
            lambda: _register_session(command, "process", token or "")
        ) if token is not None else None,
    )


def _spawn(
    argv: tuple[str, ...],
    cwd: os.PathLike[str] | str | None,
    env: dict[str, str] | None,
    started: float,
) -> tuple[subprocess.Popen[bytes] | None, RunResult | None]:
    token = uuid.uuid4().hex if _current_registry() is not None else None
    try:
        return _popen(argv, cwd, env, token), None
    except (OSError, subprocess.SubprocessError) as error:
        if token is not None:
            _forget_token(token)
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


def _ensure_process_stopped(process: subprocess.Popen[bytes], command: tuple[str, ...]) -> None:
    if _group_running(process.pid):
        raise WorkerError(_stop_error(process.pid, {"command": command}, "still running"))
    _forget_process(process.pid)


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
    budget_seconds, grace_seconds = _run_budget(
        budget_seconds, grace_seconds
    )
    argv_tuple = tuple(argv)
    started = time.monotonic()
    deadline = started + max(0.0, budget_seconds)
    process, failure = _spawn(argv_tuple, cwd, env, started)
    if failure is not None:
        return failure
    assert process is not None
    execution, capture = _capture_process(process, deadline, grace_seconds, capture_limit)
    _reap(process)
    _ensure_process_stopped(process, argv_tuple)
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
