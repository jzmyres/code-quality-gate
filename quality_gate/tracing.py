"""Recorded file reads for result reuse.

One recorder collects the inputs of a check: files opened for reading or
executed, paths looked up and not found, files stat'ed and directories
listed.  Subprocesses are wrapped in the pinned tracer; the gate's own reads
are observed with an audit hook.  The trace travels through a file the
tracer opens and the gate makes unreadable to traced processes before they
run.
"""
from __future__ import annotations

import ast
import contextlib
import contextvars
import errno
import hashlib
import os
import re
import shutil
import signal
import stat
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Iterator

from .exec_inputs import interpreter
from .trace_guard import protect_tracer

TRACE_SYSCALLS = (
    "%file,getdents,getdents64,close,fstat,clone,clone3,fork,vfork"
)
_WRAPPER = ': > "$1"\nread _ < "$2"\nshift 2\nexec "$@"'
_LINE = re.compile(
    r"^(?:\[pid\s+(\d+)\]\s*)?(?:(\d+)\s+)?([a-z0-9_]+)\((.*)\)\s+=\s+(.*)$"
)
_STRING = re.compile(r'"((?:\\.|[^"\\])*)"')
_DELETED_FD = re.compile(r"\b(\d+)<(/[^>]* \(deleted\))>")
_PSEUDO = ("/proc", "/dev", "/sys")
DIRECTORY_PRESENT = "directory"


class TraceUnavailable(Exception):
    """The tracer could not be used for a check that needs it."""


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root + os.sep)


def _excluded(path: str, extra: tuple[str, ...]) -> bool:
    if any(_within(path, root) for root in (*_PSEUDO, *extra)):
        return True
    return False


def _file_hash(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _directory_hash(path: str) -> str:
    digest = hashlib.sha256()
    for name in sorted(os.listdir(path)):
        digest.update(os.fsencode(name) + b"\0")
    return digest.hexdigest()


def _hash_path(path: str) -> str | None:
    if os.path.isdir(path):
        return DIRECTORY_PRESENT
    if os.path.isfile(path):
        return _file_hash(path)
    return None


def _hash_directory(path: str) -> str | None:
    return _directory_hash(path) if os.path.isdir(path) else None


def _inode(path: str) -> tuple[int, int] | None:
    try:
        info = _original_stat(path)
    except OSError:
        return None
    return info.st_dev, info.st_ino


_FILE_TYPES = (
    (stat.S_IFREG, "file"),
    (stat.S_IFDIR, "directory"),
    (stat.S_IFLNK, "symlink"),
    (stat.S_IFIFO, "fifo"),
    (stat.S_IFSOCK, "socket"),
    (stat.S_IFCHR, "character"),
    (stat.S_IFBLK, "block"),
)


def _file_type(mode: int) -> str:
    kind = stat.S_IFMT(mode)
    return next((name for value, name in _FILE_TYPES if value == kind), "other")


def _observed_metadata(info: os.stat_result) -> dict[str, Any]:
    """The metadata a stat, lstat or access call could observe."""
    return {
        "type": _file_type(info.st_mode),
        "mode": stat.S_IMODE(info.st_mode),
        "size": info.st_size,
        "uid": info.st_uid,
        "gid": info.st_gid,
    }


_MISSING = object()
State = tuple[Any, ...]


def _replace_input(old: Any, value: str | None) -> bool:
    if value == DIRECTORY_PRESENT and old not in (_MISSING, None, DIRECTORY_PRESENT):
        return False
    return old is _MISSING or old is None or value is not None


def _changed_presence(old: Any, value: str | None) -> bool:
    return old is None or value is None


def _input_changed(old: Any, value: str | None) -> bool:
    if old is _MISSING or old == value:
        return False
    if _changed_presence(old, value):
        return True
    return old != DIRECTORY_PRESENT and value != DIRECTORY_PRESENT


@dataclass
class Recorder:
    """The inputs one check has read so far."""

    cwd: Path
    temporary: Path
    tracer: tuple[str, ...] = ()
    extra_excluded: tuple[str, ...] = ()
    inputs: dict[str, str | None] = field(default_factory=dict)
    created: set[str] = field(default_factory=set)
    written: set[str] = field(default_factory=set)
    read_inodes: set[tuple[int, int]] = field(default_factory=set)
    written_inodes: set[tuple[int, int]] = field(default_factory=set)
    temporary_paths: set[str] = field(default_factory=set)
    symlinks: dict[str, str] = field(default_factory=dict)
    non_symlinks: set[str] = field(default_factory=set)
    metadata: dict[str, dict[str, Any]] = field(default_factory=dict)
    reliable: bool = True
    environment: dict[str, str] | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _keep(self, path: str) -> bool:
        roots = (str(self.temporary), *self.extra_excluded, *self.temporary_paths)
        return bool(path) and not _excluded(path, roots)

    def _set(self, path: str, value: str | None) -> None:
        if not self._keep(path) or path in self.created:
            return
        with self._lock:
            old = self.inputs.get(path, _MISSING)
            if _input_changed(old, value):
                self.reliable = False
            if _replace_input(old, value):
                self.inputs[path] = value

    def _mark_existing_write(self, path: str) -> None:
        inode = _inode(path)
        if path in self.inputs or path in self.symlinks or inode in self.read_inodes:
            self.reliable = False
        if inode is None:
            self.reliable = False
        else:
            self.written_inodes.add(inode)
        self.written.add(path)

    def mark_write(self, path: str, created: bool) -> None:
        if not self._keep(path):
            return
        if created:
            self.mark_created(path)
        elif path not in self.created:
            self._mark_existing_write(path)

    def _remember_non_symlink(self, path: str) -> None:
        if path in self.symlinks:
            self.reliable = False
        self.non_symlinks.add(path)

    def _remember_symlink(self, path: str, digest: str) -> None:
        old = self.symlinks.get(path)
        if path in self.non_symlinks or (old is not None and old != digest):
            self.reliable = False
        self.symlinks[path] = digest

    def _record_lstat_type(self, path: str, is_link: bool) -> None:
        if is_link:
            self._remember_symlink(path, hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest())
        else:
            self._remember_non_symlink(path)

    def _remember_metadata(self, path: str, info: os.stat_result) -> None:
        if stat.S_ISDIR(info.st_mode):
            return
        value = _observed_metadata(info)
        old = self.metadata.get(path)
        if old is not None and old != value:
            self.reliable = False
        self.metadata[path] = value

    def _record_lstat_checked(self, path: str, is_link: bool) -> None:
        try:
            info = _original_lstat(path)
        except OSError:
            self.reliable = False
            return
        if stat.S_ISLNK(info.st_mode) != is_link:
            self.reliable = False
            return
        self._record_lstat_type(path, is_link)
        self._remember_metadata(path, info)

    def record_lstat(self, path: str, is_link: bool) -> None:
        if self._keep(path) and path not in self.created:
            self._record_lstat_checked(path, is_link)

    def record_stat(self, path: str) -> None:
        if not self._keep(path) or path in self.created:
            return
        try:
            info = _original_lstat(path)
        except OSError:
            self.reliable = False
            return
        self._remember_metadata(path, info)

    def mark_created(self, path: str) -> None:
        if self._keep(path):
            with self._lock:
                self.created.add(path)

    def _track_read(self, path: str) -> bool:
        inode = _inode(path)
        if path in self.written or inode in self.written_inodes:
            self.reliable = False
            return False
        if inode is not None:
            self.read_inodes.add(inode)
        return True

    def _compute_hash(self, path: str, compute: Any) -> str | None:
        token = _audit_busy.set(True)
        try:
            return compute(path)
        except OSError:
            return None
        finally:
            _audit_busy.reset(token)

    def _can_read(self, path: str) -> bool:
        return self._keep(path) and path not in self.created and self._track_read(path)

    def _store_hash(self, path: str, value: str | None) -> None:
        if value is None:
            self.reliable = False
        else:
            self._set(path, value)

    def _add_hash(self, path: str, compute: Any) -> None:
        if self._can_read(path):
            self._store_hash(path, self._compute_hash(path, compute))

    def add_path(self, path: str) -> None:
        self._add_hash(path, _hash_path)

    def add_directory(self, path: str) -> None:
        self._add_hash(path, _hash_directory)

    def add_absent(self, path: str) -> None:
        self._set(path, None)

    def snapshot(self) -> dict[str, str | None]:
        with self._lock:
            return dict(sorted(self.inputs.items()))

    def state(self) -> State:
        with self._lock:
            return (dict(sorted(self.inputs.items())), tuple(sorted(self.created)),
                    self.reliable, tuple(sorted(self.temporary_paths)), dict(self.symlinks),
                    tuple(sorted(self.written)), tuple(sorted(self.read_inodes)),
                    tuple(sorted(self.written_inodes)), tuple(sorted(self.non_symlinks)),
                    dict(sorted(self.metadata.items())))


_active: contextvars.ContextVar[Recorder | None] = contextvars.ContextVar(
    "quality_gate_recorder", default=None
)
_hook_installed = False
_audit_busy: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "quality_gate_audit_busy", default=False
)


_child_fds: set[int] = set()


def register_child_fd(fd: int) -> None:
    _child_fds.add(fd)


def unregister_child_fd(fd: int) -> None:
    _child_fds.discard(fd)


def _close_fd(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def close_in_child() -> None:
    """Close descriptors the gate must not give to a forked child."""
    for fd in tuple(_child_fds):
        _close_fd(fd)
    _child_fds.clear()


def current() -> Recorder | None:
    return _active.get()


def snapshot() -> State | None:
    recorder = current()
    return recorder.state() if recorder is not None else None


def _merge_inodes(recorder: Recorder, reads: Any, writes: Any) -> None:
    if recorder.read_inodes.intersection(writes) or recorder.written_inodes.intersection(reads):
        recorder.reliable = False
    recorder.read_inodes.update(reads)
    recorder.written_inodes.update(writes)


def _merge_links(recorder: Recorder, symlinks: dict[str, str], non_symlinks: Any) -> None:
    for path, digest in symlinks.items():
        recorder._remember_symlink(path, digest)
    for path in non_symlinks:
        recorder._remember_non_symlink(path)


def _merge_metadata(recorder: Recorder, metadata: Any) -> None:
    for path, value in metadata.items():
        old = recorder.metadata.get(path)
        if old is not None and old != value:
            recorder.reliable = False
        recorder.metadata[path] = value


def _merge_state(recorder: Recorder, state: State) -> None:
    (inputs, created, reliable, temporary_paths, symlinks, written, reads, writes,
     non_symlinks, metadata) = state
    _merge_links(recorder, symlinks, non_symlinks)
    _merge_metadata(recorder, metadata)
    _merge_inodes(recorder, reads, writes)
    recorder.written.update(written)
    recorder.temporary_paths.update(temporary_paths)
    recorder.reliable = recorder.reliable and reliable
    for path in created:
        recorder.mark_created(path)
    for path, value in inputs.items():
        recorder._set(path, value)


def merge_snapshot(state: State | None) -> None:
    recorder = current()
    if recorder is not None and state is not None:
        _merge_state(recorder, state)


def _audit_path(value: Any) -> str | None:
    try:
        if isinstance(value, int):
            return None
        return os.path.abspath(os.fsdecode(os.fspath(value)))
    except (TypeError, ValueError):
        return None


def _audit_absent(recorder: Recorder, path: str) -> None:
    resolved = _resolve(recorder, recorder.cwd, None, path)
    if resolved is not None:
        recorder.add_absent(resolved)


def _audit_present(recorder: Recorder, path: str) -> None:
    resolved = _resolve(recorder, recorder.cwd, None, path)
    if resolved is not None:
        recorder.add_path(resolved)


def _audited_stat(path: str) -> str:
    try:
        _original_stat(path)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "error"
    return "present"


def _audit_read(recorder: Recorder, path: str) -> None:
    if not recorder._keep(path):
        return
    status = _audited_stat(path)
    if status == "missing":
        _audit_absent(recorder, path)
    elif status == "error":
        recorder.reliable = False
    else:
        _audit_present(recorder, path)


def _audit_flags(recorder: Recorder, path: str, flags: int) -> None:
    access = flags & os.O_ACCMODE
    if access in (os.O_WRONLY, os.O_RDWR):
        created = bool(flags & os.O_CREAT) and not os.path.lexists(path)
        recorder.mark_write(path, created)
    if access in (os.O_RDONLY, os.O_RDWR):
        _audit_read(recorder, path)


def _audit_mode(recorder: Recorder, path: str, mode: Any) -> None:
    text = mode if isinstance(mode, str) else ""
    if any(character in text for character in "wax"):
        recorder.mark_write(path, not os.path.lexists(path))
    if "r" in text or "+" in text:
        _audit_read(recorder, path)


def _audit_open(path: str | None, mode: Any, flags: Any) -> None:
    recorder = current()
    if recorder is None or path is None:
        return
    if isinstance(flags, int):
        _audit_flags(recorder, path, flags)
    else:
        _audit_mode(recorder, path, mode)


def _register_temporary(value: Any) -> None:
    path = _audit_path(value)
    if path is not None:
        current().temporary_paths.add(path)  # type: ignore[union-attr]


def _audit_temporary(args: tuple[Any, ...]) -> None:
    if args:
        _register_temporary(args[0])


def _audit_directory(args: tuple[Any, ...]) -> None:
    recorder = current()
    path = _audit_path(args[0]) if args else None
    if recorder is not None and path is not None and recorder._keep(path):
        resolved = _resolve(recorder, recorder.cwd, None, path)
        if resolved is not None:
            recorder.add_directory(resolved)


def _audit_open_event(args: tuple[Any, ...]) -> None:
    _audit_open(_audit_path(args[0]), args[1], args[2])


_AUDIT_EVENTS = {
    "tempfile.mkdtemp": _audit_temporary,
    "tempfile.mkstemp": _audit_temporary,
    "os.listdir": _audit_directory,
    "os.scandir": _audit_directory,
    "open": _audit_open_event,
}


def _audit_event(event: str, args: tuple[Any, ...]) -> None:
    handler = _AUDIT_EVENTS.get(event)
    if handler is not None:
        handler(args)


def _safe_audit(recorder: Recorder, event: str, args: tuple[Any, ...]) -> None:
    try:
        _audit_event(event, args)
    except Exception:
        recorder.reliable = False


def _audit(event: str, args: tuple[Any, ...]) -> None:
    recorder = current()
    if recorder is None or _audit_busy.get():
        return
    token = _audit_busy.set(True)
    try:
        _safe_audit(recorder, event, args)
    finally:
        _audit_busy.reset(token)


_original_stat = os.stat
_original_lstat = os.lstat


def _fd_location(descriptor: int) -> str | None:
    try:
        return os.readlink(f"/proc/self/fd/{descriptor}")
    except OSError:
        return None


def _stat_follow(function: Any, kwargs: dict[str, Any]) -> bool:
    return function is not _original_lstat and kwargs.get("follow_symlinks") is not False


def _stat_base(raw: str, kwargs: dict[str, Any]) -> str | None:
    descriptor = kwargs.get("dir_fd")
    if descriptor is None or os.path.isabs(raw):
        return ""
    return _fd_location(descriptor)


def _stat_location(
    recorder: Recorder, path: Any, kwargs: dict[str, Any], follow: bool,
) -> str | None:
    if isinstance(path, int):
        return _fd_location(path)
    raw = os.fsdecode(os.fspath(path))
    base = _stat_base(raw, kwargs)
    if base is None:
        return None
    return _resolve(recorder, recorder.cwd, base or None, raw, follow=follow)


def _record_missing_error(recorder: Recorder, name: str, error: OSError) -> None:
    if error.errno in (errno.ENOENT, errno.ENOTDIR):
        recorder.add_absent(name)


def _record_stat_error(recorder: Recorder, name: str | None, error: OSError) -> None:
    if name:
        _record_missing_error(recorder, name, error)


def _record_stat_type(recorder: Recorder, name: str, follow: bool, result: Any) -> None:
    if follow:
        recorder.record_stat(name)
    else:
        recorder.record_lstat(name, stat.S_ISLNK(result.st_mode))


def _stat_and_record(
    recorder: Recorder, function: Any, path: Any, args: Any, kwargs: Any,
) -> Any:
    follow = _stat_follow(function, kwargs)
    name = _stat_location(recorder, path, kwargs, follow)
    try:
        result = function(path, *args, **kwargs)
    except OSError as error:
        _record_stat_error(recorder, name, error)
        raise
    if name:
        recorder.add_path(name)
        _record_stat_type(recorder, name, follow, result)
    return result


def _traced_stat(function: Any, path: Any, *args: Any, **kwargs: Any) -> Any:
    recorder = current()
    if recorder is None or _audit_busy.get():
        return function(path, *args, **kwargs)
    token = _audit_busy.set(True)
    try:
        return _stat_and_record(recorder, function, path, args, kwargs)
    finally:
        _audit_busy.reset(token)


def _stat(path: Any, *args: Any, **kwargs: Any) -> Any:
    return _traced_stat(_original_stat, path, *args, **kwargs)


def _lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
    return _traced_stat(_original_lstat, path, *args, **kwargs)


def _install_hook() -> None:
    global _hook_installed
    if not _hook_installed:
        sys.addaudithook(_audit)
        os.stat = _stat
        os.lstat = _lstat
        _hook_installed = True


@contextlib.contextmanager
def collecting(
    cwd: Path,
    temporary: Path,
    tracer: tuple[str, ...],
    extra_excluded: tuple[str, ...] = (),
) -> Iterator[Recorder]:
    _install_hook()
    recorder = Recorder(cwd, temporary, tracer, extra_excluded)
    token = _active.set(recorder)
    try:
        yield recorder
    finally:
        _active.reset(token)


def _parse_string(text: str) -> str | None:
    match = _STRING.search(text)
    if match is None:
        return None
    try:
        value = ast.literal_eval('b"' + match.group(1) + '"')
        return os.fsdecode(value) if isinstance(value, bytes) else None
    except (SyntaxError, ValueError):
        return None


_MAX_LINKS = 40


@dataclass
class _Walk:
    parts: list[str]
    resolved: list[str]
    follow: bool
    links: int = 0


def _absolute(cwd: Path, base: str | None, raw: str) -> str:
    if raw.startswith("/"):
        return raw
    return os.path.join(base if base is not None else str(cwd), raw)


def _component(recorder: Recorder, candidate: str) -> tuple[str, Any]:
    try:
        return "ok", _original_lstat(candidate)
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ENOTDIR):
            return "missing", None
        recorder.reliable = False
        return "error", None


def _symlink_target(recorder: Recorder, path: str) -> str | None:
    try:
        target = os.readlink(path)
    except OSError:
        recorder.reliable = False
        return None
    if recorder._keep(path):
        recorder._remember_symlink(
            path, hashlib.sha256(os.fsencode(target)).hexdigest()
        )
        recorder.add_path(path)
    return target


def _is_followed(walk: _Walk, info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) and (walk.follow or bool(walk.parts))


def _expand_link(walk: _Walk, recorder: Recorder, candidate: str) -> tuple[bool, str | None]:
    walk.links += 1
    if walk.links > _MAX_LINKS:
        recorder.reliable = False
        return True, None
    target = _symlink_target(recorder, candidate)
    if target is None:
        return True, None
    if target.startswith("/"):
        walk.resolved.clear()
    walk.parts[0:0] = target.split("/")
    return False, None


def _skip_component(walk: _Walk, part: str) -> bool:
    if part == "..":
        if walk.resolved:
            walk.resolved.pop()
        return True
    return part in ("", ".")


def _walk_component(walk: _Walk, recorder: Recorder) -> tuple[bool, str | None]:
    if not walk.parts:
        return True, "/" + "/".join(walk.resolved)
    part = walk.parts.pop(0)
    if _skip_component(walk, part):
        return False, None
    candidate = "/" + "/".join([*walk.resolved, part])
    status, info = _component(recorder, candidate)
    if status != "ok":
        if status == "missing":
            return True, candidate
        return True, None
    if _is_followed(walk, info):
        return _expand_link(walk, recorder, candidate)
    walk.resolved.append(part)
    return False, None


def _resolve(
    recorder: Recorder, cwd: Path, base: str | None, raw: str, *, follow: bool = True,
) -> str | None:
    walk = _Walk(_absolute(cwd, base, raw).split("/"), [], follow)
    while True:
        done, value = _walk_component(walk, recorder)
        if done:
            return value


def _first_int(text: str) -> int | None:
    match = re.match(r"\s*(-?\d+)", text)
    return int(match.group(1)) if match is not None else None


def _result(text: str) -> tuple[int | None, str | None]:
    if text.startswith("-1"):
        error = re.search(r"\b([A-Z][A-Z0-9]+)\b", text[2:])
        return None, error.group(1) if error is not None else "error"
    return _first_int(text), None


def _descriptor_base(
    cwd: Path, fds: dict[tuple[int, int], str], pid: int, first: str,
) -> str | None:
    annotated = re.search(r"<(/[^>]*)>", first)
    if annotated:
        return annotated.group(1)
    if first.strip() == "AT_FDCWD":
        return str(cwd)
    descriptor = _first_int(first)
    return fds.get((pid, descriptor)) if descriptor is not None else None


def _located_path(
    recorder: Recorder, cwd: Path, fds: dict[tuple[int, int], str], pid: int,
    args: str, *, follow: bool = True,
) -> str | None:
    parts = args.split(",", 1)
    if len(parts) != 2:
        return None
    first, rest = parts
    raw = _parse_string(rest)
    if raw is None:
        return None
    base = _descriptor_base(cwd, fds, pid, first)
    if base is None and not raw.startswith("/"):
        return None
    return _resolve(recorder, cwd, base, raw, follow=follow)


def _record_presence(
    recorder: Recorder, path: str, error: str | None
) -> None:
    if error in ("ENOENT", "ENOTDIR"):
        recorder.add_absent(path)
    elif error is None:
        recorder.add_path(path)


def _non_file_stat(args: str, error: str | None) -> bool:
    if error is not None or _parse_string(args) != "":
        return False
    return re.search(r"S_IF(?:REG|DIR|LNK)", args) is None


def _unresolved_input(recorder: Recorder, args: str, error: str | None) -> None:
    if error not in (None, "ENOENT", "ENOTDIR") or _non_file_stat(args, error):
        return
    recorder.reliable = False


def _created_by_open(recorder: Recorder, path: str, args: str) -> bool:
    absent = path in recorder.inputs and recorder.inputs[path] is None
    return "O_CREAT" in args and ("O_EXCL" in args or absent)


def _open_reads(args: str) -> bool:
    return "O_WRONLY" not in args and "O_PATH" not in args


def _record_access(recorder: Recorder, path: str, args: str) -> None:
    if "O_WRONLY" in args or "O_RDWR" in args:
        recorder.mark_write(path, _created_by_open(recorder, path, args))
    if _open_reads(args):
        recorder.add_path(path)


def _record_stat(
    recorder: Recorder,
    cwd: Path,
    fds: dict[tuple[int, int], str],
    pid: int,
    args: str,
    error: str | None,
) -> None:
    follow = "AT_SYMLINK_NOFOLLOW" not in args
    path = _located_path(recorder, cwd, fds, pid, args, follow=follow)
    if path is None:
        _unresolved_input(recorder, args, error)
        return
    _record_presence(recorder, path, error)
    if error is not None:
        return
    if follow:
        recorder.record_stat(path)
    else:
        recorder.record_lstat(path, "S_IFLNK" in args)


def _record_direct(
    recorder: Recorder, cwd: Path, args: str, error: str | None
) -> None:
    raw = _parse_string(args)
    if raw is None:
        _unresolved_input(recorder, args, error)
        return
    path = _resolve(recorder, cwd, None, raw)
    if path is None:
        return
    _record_presence(recorder, path, error)
    if error is None:
        recorder.record_stat(path)


def _handle_close(
    recorder: Recorder,
    cwd: Path,
    fds: dict[tuple[int, int], str],
    pid: int,
    args: str,
    value: int | None,
    error: str | None,
) -> None:
    fds.pop((pid, _first_int(args) or -1), None)


def _open_missing(recorder: Recorder, path: str, args: str, error: str) -> None:
    if error == "ENOTDIR" and "O_DIRECTORY" in args and os.path.lexists(path):
        if os.path.isdir(path):
            recorder.reliable = False
        else:
            recorder.add_path(path)
    else:
        recorder.add_absent(path)


def _handle_open(
    recorder: Recorder,
    cwd: Path,
    fds: dict[tuple[int, int], str],
    pid: int,
    args: str,
    value: int | None,
    error: str | None,
    *,
    prefix: str,
) -> None:
    args = prefix + args
    path = _located_path(recorder, cwd, fds, pid, args, follow="O_NOFOLLOW" not in args)
    if path is None:
        _unresolved_input(recorder, args, error)
        return
    if error in ("ENOENT", "ENOTDIR"):
        _open_missing(recorder, path, args, error)
        return
    if value is None:
        return
    fds[(pid, value)] = path
    _record_access(recorder, path, args)


def _handle_stat(
    recorder: Recorder,
    cwd: Path,
    fds: dict[tuple[int, int], str],
    pid: int,
    args: str,
    value: int | None,
    error: str | None,
) -> None:
    _record_direct(recorder, cwd, args, error)


def _direct_lstat_path(recorder: Recorder, cwd: Path, args: str) -> str | None:
    raw = _parse_string(args)
    if raw is None:
        return None
    return _resolve(recorder, cwd, None, raw, follow=False)


def _record_lstat_result(recorder: Recorder, path: str, args: str, error: str | None) -> None:
    _record_presence(recorder, path, error)
    if error is None:
        recorder.record_lstat(path, "S_IFLNK" in args)


def _handle_lstat(
    recorder: Recorder, cwd: Path, fds: dict[tuple[int, int], str], pid: int,
    args: str, value: int | None, error: str | None,
) -> None:
    path = _direct_lstat_path(recorder, cwd, args)
    if path is None:
        recorder.reliable = False
        return
    _record_lstat_result(recorder, path, args, error)


def _handle_fstatat(
    recorder: Recorder,
    cwd: Path,
    fds: dict[tuple[int, int], str],
    pid: int,
    args: str,
    value: int | None,
    error: str | None,
) -> None:
    _record_stat(recorder, cwd, fds, pid, args, error)


def _handle_getdents(
    recorder: Recorder,
    cwd: Path,
    fds: dict[tuple[int, int], str],
    pid: int,
    args: str,
    value: int | None,
    error: str | None,
) -> None:
    if value is None:
        return
    fd = _first_int(args)
    annotated = re.match(r"\s*\d+<(/[^>]*)>", args)
    path = annotated.group(1) if annotated else fds.get((pid, fd))
    if path is not None:
        recorder.add_directory(path)
    else:
        recorder.reliable = False


def _handle_fstat(
    recorder: Recorder,
    cwd: Path,
    fds: dict[tuple[int, int], str],
    pid: int,
    args: str,
    value: int | None,
    error: str | None,
) -> None:
    annotated = re.match(r"\s*\d+<(/[^>]*)>", args)
    fd = _first_int(args)
    path = annotated.group(1) if annotated else fds.get((pid, fd))
    if path is not None:
        _record_lstat_result(recorder, path, args, error)
    elif error is None and any(kind in args for kind in ("S_IFREG", "S_IFDIR", "S_IFLNK")):
        recorder.reliable = False


def _link_path(
    recorder: Recorder, cwd: Path, fds: Any, pid: int, args: str, direct: bool,
) -> str | None:
    raw = _parse_string(args) if direct else None
    if raw is None:
        return _located_path(recorder, cwd, fds, pid, args, follow=False)
    return _resolve(recorder, cwd, None, raw, follow=False)


def _reported_link(args: str) -> str | None:
    first = _STRING.search(args)
    return _parse_string(args[first.end():]) if first else None


def _link_matches(target: str, reported: str | None, value: int | None) -> bool:
    return value is not None and reported is not None and target[:value] == reported


def _link_hash(path: str, args: str, value: int | None) -> str | None:
    try:
        target = os.readlink(path)
    except OSError:
        return None
    if not _link_matches(target, _reported_link(args), value):
        return None
    return hashlib.sha256(os.fsencode(target)).hexdigest()


def _record_link_result(recorder: Recorder, path: str, args: str, value: int | None) -> None:
    digest = _link_hash(path, args, value)
    if digest is None:
        recorder.reliable = False
    else:
        recorder._remember_symlink(path, digest)


def _record_readlink_error(recorder: Recorder, path: str, error: str) -> None:
    if error in ("ENOENT", "ENOTDIR"):
        recorder.add_absent(path)
    elif error == "EINVAL":
        recorder.add_path(path)
        recorder.record_lstat(path, False)
    else:
        recorder.reliable = False


def _handle_readlink(
    recorder: Recorder, cwd: Path, fds: dict[tuple[int, int], str], pid: int,
    args: str, value: int | None, error: str | None, *, direct: bool,
) -> None:
    path = _link_path(recorder, cwd, fds, pid, args, direct)
    if path is None:
        _unresolved_input(recorder, args, error)
        return
    if not recorder._keep(path):
        return
    if error is None:
        _record_link_result(recorder, path, args, value)
    else:
        _record_readlink_error(recorder, path, error)


def _next_interpreter(path: str, seen: set[str]) -> str | None:
    target = interpreter(path)
    if target is None:
        return None
    if target in seen or not os.path.isabs(target):
        raise ValueError("invalid interpreter chain")
    seen.add(target)
    return target


def _interpreter_chain(path: str) -> Iterator[str]:
    seen = {path}
    for _ in range(8):
        target = _next_interpreter(path, seen)
        if target is None:
            return
        yield target
        path = target
    raise ValueError("interpreter chain is too long")


def _record_interpreters(recorder: Recorder, path: str) -> None:
    try:
        for target in _interpreter_chain(path):
            recorder.add_path(target)
    except (OSError, ValueError, OverflowError):
        recorder.reliable = False


def _handle_exec(
    recorder: Recorder, cwd: Path, fds: dict[tuple[int, int], str], pid: int,
    args: str, value: int | None, error: str | None, *, direct: bool,
) -> None:
    raw = _parse_string(args) if direct else None
    if raw is None:
        path = _located_path(recorder, cwd, fds, pid, args)
    else:
        path = _resolve(recorder, cwd, None, raw)
    if path is None:
        recorder.reliable = False
        return
    _record_presence(recorder, path, error)
    if error is None:
        _record_interpreters(recorder, path)


def _handle_statfs(
    recorder: Recorder, cwd: Path, fds: Any, pid: int,
    args: str, value: int | None, error: str | None,
) -> None:
    if error in ("ENOENT", "ENOTDIR"):
        _record_direct(recorder, cwd, args, error)
    else:
        recorder.reliable = False


_SYSCALL_HANDLERS = {
    "close": _handle_close,
    "open": partial(_handle_open, prefix="AT_FDCWD, "),
    "openat": partial(_handle_open, prefix=""),
    "openat2": partial(_handle_open, prefix=""),
    "stat": _handle_stat,
    "statfs": _handle_statfs,
    "lstat": _handle_lstat,
    "newfstatat": _handle_fstatat,
    "statx": _handle_fstatat,
    "fstat": _handle_fstat,
    "getdents": _handle_getdents,
    "getdents64": _handle_getdents,
    "execve": partial(_handle_exec, direct=True),
    "execveat": partial(_handle_exec, direct=False),
    "readlink": partial(_handle_readlink, direct=True),
    "readlinkat": partial(_handle_readlink, direct=False),
    "access": _handle_stat,
    "faccessat": _handle_fstatat,
    "faccessat2": _handle_fstatat,
}


_NON_INPUT_CALLS = {"getcwd", "chdir", "fchdir", "clone", "clone3", "fork", "vfork"}


def _unknown_syscall(recorder: Recorder, cwd: Path, name: str, args: str) -> None:
    if name in _NON_INPUT_CALLS:
        return
    raw = _parse_string(args)
    path = _resolve(recorder, cwd, None, raw) if raw is not None else None
    if path is None or recorder._keep(path):
        recorder.reliable = False


def _trace_pid(bracket: str | None, prefix: str | None) -> int:
    return int(bracket or prefix or 0)


def _record_line(recorder: Recorder, cwd: Path, fds: Any, line: str) -> None:
    match = _LINE.match(line.rstrip("\n"))
    if match is None:
        return
    bracket, prefix, name, args, tail = match.groups()
    handler = _SYSCALL_HANDLERS.get(name)
    if handler is None:
        _unknown_syscall(recorder, cwd, name, args)
        return
    value, error = _result(tail)
    handler(recorder, cwd, fds, _trace_pid(bracket, prefix), args, value, error)


def _resume_line(recorder: Recorder, pending: Any, resumed: Any) -> str | None:
    pid, name, rest = resumed.groups()
    prefix = pending.pop((pid, name), None)
    if prefix is None:
        recorder.reliable = False
        return None
    return prefix + rest


def _line_part(recorder: Recorder, pending: Any, line: str) -> str | None:
    unfinished = re.match(r"^(\d+)\s+(\w+)\((.*) <unfinished \.\.\.>$", line)
    if unfinished:
        pid, name, args = unfinished.groups()
        pending[(pid, name)] = f"{pid} {name}({args}"
        return None
    resumed = re.match(r"^(\d+)\s+<\.\.\. (\w+) resumed>(.*)$", line)
    return _resume_line(recorder, pending, resumed) if resumed else line


def _completed_lines(recorder: Recorder, text: str) -> Iterator[str]:
    pending: dict[tuple[str, str], str] = {}
    for line in text.splitlines():
        completed = _line_part(recorder, pending, line)
        if completed is not None:
            yield completed
    if pending:
        recorder.reliable = False


def _inherit_fds(fds: Any, parent: int, child: int) -> None:
    fds.update({(child, fd): path for (owner, fd), path in fds.items() if owner == parent})


def _chdir_path(recorder: Recorder, current: Path, args: str) -> Path | None:
    raw = _parse_string(args)
    if raw is None:
        return None
    path = _resolve(recorder, current, None, raw)
    return Path(path) if path is not None else None


def _fchdir_path(recorder: Recorder, args: str) -> Path | None:
    annotated = re.search(r"<(/[^>]*)>", args)
    if annotated:
        return Path(annotated.group(1))
    recorder.reliable = False
    return None


def _changed_directory(recorder: Recorder, current: Path, args: str, name: str) -> Path | None:
    if name == "chdir":
        return _chdir_path(recorder, current, args)
    return _fchdir_path(recorder, args)


def _advance_directory(recorder: Recorder, directories: Any, pid: int,
                       current: Path, name: str, args: str, error: str | None) -> None:
    if error is not None:
        return
    directory = _changed_directory(recorder, current, args, name)
    if directory is not None:
        directories[pid] = directory


def _advance_trace(recorder: Recorder, directories: Any, fds: Any, pid: int,
                   current: Path, name: str, args: str, tail: str) -> None:
    value, error = _result(tail)
    if name in ("chdir", "fchdir"):
        _advance_directory(recorder, directories, pid, current, name, args, error)
    elif name in ("clone", "clone3", "fork", "vfork") and value:
        directories[value] = current
        _inherit_fds(fds, pid, value)


def _trace_directory(recorder: Recorder, cwd: Path, directories: Any, pid: int, args: str) -> Path:
    annotated = re.search(r"AT_FDCWD<(/[^>]*)>", args)
    if annotated:
        path = annotated.group(1)
        if path.endswith(" (deleted)") and str(directories.get(pid, cwd)) != path:
            recorder.reliable = False
        directories[pid] = Path(path)
    return directories.get(pid, cwd)


def _check_deleted_descriptors(recorder: Recorder, fds: Any, pid: int, text: str) -> None:
    for descriptor, path in _DELETED_FD.findall(text):
        if fds.get((pid, int(descriptor))) != path:
            recorder.reliable = False


def _invalid_trace_line(recorder: Recorder, line: str) -> None:
    if re.match(r"^\d+\s+\w+\(", line):
        recorder.reliable = False


def _trace_entry(recorder: Recorder, cwd: Path, fds: Any, directories: Any, line: str) -> None:
    match = _LINE.match(line)
    if match is None:
        _invalid_trace_line(recorder, line)
        return
    bracket, prefix, name, args, tail = match.groups()
    pid = _trace_pid(bracket, prefix)
    current = _trace_directory(recorder, cwd, directories, pid, args)
    _check_deleted_descriptors(recorder, fds, pid, args)
    _record_line(recorder, current, fds, line)
    _check_deleted_descriptors(recorder, fds, pid, tail)
    _advance_trace(recorder, directories, fds, pid, current, name, args, tail)


def _parse_trace_text(recorder: Recorder, cwd: Path, text: str) -> None:
    fds: dict[tuple[int, int], str] = {}
    directories: dict[int, Path] = {}
    for line in _completed_lines(recorder, text):
        _trace_entry(recorder, cwd, fds, directories, line)


def _read_trace(recorder: Recorder, cwd: Path, fd: int) -> None:
    with os.fdopen(os.dup(fd), "r", encoding="utf-8", errors="replace") as stream:
        _parse_trace_text(recorder, cwd, stream.read())


@dataclass
class Prepared:
    """One subprocess invocation wrapped in the tracer."""

    argv: list[str]
    recorder: Recorder
    cwd: Path
    directory: Path
    trace: Path
    ready: Path
    gate: Path
    stop: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    pid: int = 0
    trace_fd: int | None = None
    error: str | None = None

    def _wait_ready(self, deadline: float) -> bool:
        while not self.ready.exists():
            if self.stop.is_set() or time.monotonic() > deadline:
                return False
            time.sleep(0.001)
        return True

    def _open_gate(self, deadline: float) -> int | None:
        while not self.stop.is_set():
            try:
                return os.open(self.gate, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as error:
                if not (
                    error.errno == errno.ENXIO
                    and time.monotonic() < deadline
                ):
                    return None
                time.sleep(0.001)
        return None

    def _protect_trace(self) -> None:
        self.trace_fd = os.open(self.trace, os.O_RDONLY | os.O_CLOEXEC)
        self.trace.unlink()
        protect_tracer(self.pid)

    def _release_child(self, deadline: float) -> None:
        if not self._wait_ready(deadline):
            raise OSError("tracer did not become ready")
        self._protect_trace()
        fd = self._open_gate(deadline)
        if fd is None:
            raise OSError("tracer did not open its startup channel")
        try:
            os.write(fd, b"\n")
        finally:
            os.close(fd)

    def _terminate_tracer(self) -> None:
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except OSError:
            pass

    def _release(self) -> None:
        try:
            self._release_child(time.monotonic() + 30.0)
        except (OSError, ValueError, StopIteration) as error:
            self.error = str(error)
            self._terminate_tracer()

    def start(self, pid: int) -> None:
        self.pid = pid
        self.thread = threading.Thread(target=self._release, daemon=True)
        self.thread.start()

    def finish(self) -> None:
        from .runner import analysis_step

        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=2.0)
        try:
            if self.error is not None:
                raise TraceUnavailable(f"reuse: cannot protect tracer output: {self.error}")
            if self.trace_fd is None:
                raise TraceUnavailable("reuse: tracer produced no protected output")
            analysis_step("trace analysis", _read_trace, self.recorder, self.cwd, self.trace_fd)
        finally:
            if self.trace_fd is not None:
                os.close(self.trace_fd)
                self.trace_fd = None
            shutil.rmtree(self.directory, ignore_errors=True)

    def abandon(self) -> None:
        self.stop.set()
        shutil.rmtree(self.directory, ignore_errors=True)


def prepare(argv: tuple[str, ...], cwd: os.PathLike[str] | str | None) -> Prepared | None:
    recorder = current()
    if recorder is None:
        return None
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=recorder.temporary))
    trace = directory / "trace"
    ready = directory / "ready"
    gate = directory / "go"
    try:
        trace.touch()
        os.chmod(trace, 0o666)
        os.mkfifo(gate, 0o600)
    except OSError as error:
        shutil.rmtree(directory, ignore_errors=True)
        raise TraceUnavailable(f"reuse: cannot create tracer channel: {error}") from error
    workdir = Path(cwd) if cwd is not None else recorder.cwd
    command = [
        *recorder.tracer,
        "-f",
        "-qq",
        "--always-show-pid",
        "-yy",
        "-s",
        "4096",
        "-e",
        f"trace={TRACE_SYSCALLS}",
        "-o",
        str(trace),
        "/bin/sh",
        "-c",
        _WRAPPER,
        "sh",
        str(ready),
        str(gate),
        *argv,
    ]
    prepared = Prepared(
        command, recorder, workdir, directory, trace, ready, gate
    )
    return prepared
